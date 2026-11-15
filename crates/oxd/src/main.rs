//! `oxd`: the Netoxide daemon.
//!
//! It owns the config. Every change goes through it as a candidate and a
//! commit, and it is the only thing that loads rules into the kernel.
//!
//! The API is HTTP and JSON. On the Unix socket the caller is whoever the
//! kernel says opened it, and is an admin. On the HTTPS listener the caller
//! is the owner of an access token and has that token's role.
//!
//! Stopping the daemon leaves the loaded ruleset in place. The box keeps
//! forwarding with the last commit.

mod api;
mod dhcp;
mod limit;
mod net;
mod services;
mod setup;
mod tls;
mod web;
mod wg;

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ipnet::IpNet;
use ox_nft::list_command;
use ox_store::{Applier, Baseline, Engine, NullApplier, Target};
use serde_json::Value;

/// Puts a target into effect on this machine: the ruleset into the kernel
/// through libnftables, and the service config into a supervised dnsmasq.
struct SystemApplier {
    dnsmasq: services::Dnsmasq,
    /// The last target that was applied in full, for undoing a half-applied one.
    current: Option<Target>,
    /// Interfaces the config names that this machine does not have.
    missing: Vec<String>,
    /// What Netoxide put on the machine itself. Only these are ever taken
    /// off again. Kept on disk so a restart remembers them.
    managed: Managed,
    managed_path: PathBuf,
    /// Where the DHCP clients keep their leases.
    state_dir: PathBuf,
    /// The interfaces asking the network for an address.
    dhcp: BTreeMap<String, dhcp::Client>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
struct Managed {
    addresses: BTreeSet<(String, IpNet)>,
    /// Default routes: the interface and the router.
    routes: BTreeSet<(String, IpAddr)>,
    /// WireGuard interfaces Netoxide created.
    tunnels: BTreeSet<String>,
    /// Routes through tunnels: the interface and the network.
    tunnel_routes: BTreeSet<(String, IpNet)>,
    /// VLAN interfaces Netoxide created: the name, the port and the number.
    vlans: BTreeSet<(String, String, u16)>,
}

fn block_on<T>(work: impl Future<Output = T>) -> T {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(work))
}

impl SystemApplier {
    fn new(state_dir: &Path, dnsmasq: services::Dnsmasq) -> SystemApplier {
        let managed_path = state_dir.join("managed.json");
        let managed = std::fs::read(&managed_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        SystemApplier {
            dnsmasq,
            current: None,
            missing: vec![],
            managed,
            managed_path,
            state_dir: state_dir.to_path_buf(),
            dhcp: BTreeMap::new(),
        }
    }

    fn save_managed(&self) {
        let text = serde_json::to_vec(&self.managed).unwrap_or_default();
        let tmp = self.managed_path.with_extension("tmp");
        let saved =
            std::fs::write(&tmp, text).and_then(|()| std::fs::rename(&tmp, &self.managed_path));
        if let Err(e) = saved {
            eprintln!("oxd: cannot record what was put on the interfaces: {e}");
        }
    }

    /// Puts the target's addresses, routes and DHCP clients in place.
    /// Drops deleted VLAN interfaces from the record, with what was on them.
    fn forget_vlans(&mut self, names: &[String]) {
        self.managed.vlans.retain(|v| !names.contains(&v.0));
        self.managed.addresses.retain(|(i, _)| !names.contains(i));
        self.managed.routes.retain(|(i, _)| !names.contains(i));
        self.save_managed();
    }

    fn bring_up(&mut self, target: &Target) -> Result<(), String> {
        // Tunnels first: their interfaces must exist to be given addresses.
        let created = block_on(wg::configure(&target.wireguard, &self.state_dir))?;
        self.managed.tunnels.extend(created);
        self.save_managed();
        // VLANs next, for the same reason.
        // One of ours whose port or number changed is made again.
        let changed: Vec<String> = self
            .managed
            .vlans
            .iter()
            .filter(|v| !target.vlans.contains(v) && target.vlans.iter().any(|t| t.0 == v.0))
            .map(|v| v.0.clone())
            .collect();
        if !changed.is_empty() {
            block_on(net::delete_links(&changed));
            self.forget_vlans(&changed);
        }
        let created = block_on(net::ensure_vlans(&target.vlans))?;
        self.managed.vlans.extend(
            target
                .vlans
                .iter()
                .filter(|v| created.contains(&v.0))
                .cloned(),
        );
        self.save_managed();
        let ensured = block_on(net::ensure_addresses(&target.addresses))?;
        self.missing = ensured.missing;
        self.managed.addresses.extend(ensured.added);
        self.managed.routes.extend(target.gateways.iter().cloned());
        self.save_managed();
        block_on(net::set_default_routes(&target.gateways))?;
        // Addresses brought the tunnels up, so routes can now leave by them.
        let wanted = wg::routes(&target.wireguard);
        let stale: Vec<(String, IpNet)> = self
            .managed
            .tunnel_routes
            .iter()
            .filter(|r| !wanted.contains(r))
            .cloned()
            .collect();
        self.managed.tunnel_routes.extend(wanted.iter().cloned());
        self.save_managed();
        block_on(wg::set_routes(&wanted, &stale))?;
        self.managed.tunnel_routes.retain(|r| wanted.contains(r));
        self.save_managed();
        for name in &target.dhcp_clients {
            if !self.dhcp.contains_key(name) {
                let _in_runtime = tokio::runtime::Handle::current().enter();
                self.dhcp
                    .insert(name.clone(), dhcp::Client::start(name, &self.state_dir));
            }
        }
        Ok(())
    }

    /// Takes off what Netoxide put on the machine that `keep` does not ask
    /// for: addresses, default routes and DHCP clients with their leases.
    fn take_down_all_but(&mut self, keep: Option<&Target>) {
        let empty = Target::default();
        let keep = keep.unwrap_or(&empty);
        let gone: Vec<String> = self
            .dhcp
            .keys()
            .filter(|name| !keep.dhcp_clients.contains(name))
            .cloned()
            .collect();
        for name in gone {
            if let Some(client) = self.dhcp.remove(&name) {
                block_on(client.stop());
            }
        }
        // A lease from an earlier run of the daemon, on an interface that
        // no longer asks for one.
        for name in dhcp::remembered(&self.state_dir) {
            if !keep.dhcp_clients.contains(&name) {
                block_on(dhcp::forget(&self.state_dir, &name));
            }
        }
        // Tunnels this config does not have. Their addresses and routes go
        // with the interface.
        let tunnels: Vec<String> = self
            .managed
            .tunnels
            .iter()
            .filter(|name| !keep.wireguard.contains_key(*name))
            .cloned()
            .collect();
        if !tunnels.is_empty() {
            block_on(wg::delete(&tunnels));
            self.managed.tunnels.retain(|t| !tunnels.contains(t));
            self.managed
                .tunnel_routes
                .retain(|(t, _)| !tunnels.contains(t));
            self.managed.addresses.retain(|(t, _)| !tunnels.contains(t));
            self.save_managed();
        }
        // VLANs this config does not have, likewise.
        let vlans: Vec<String> = self
            .managed
            .vlans
            .iter()
            .filter(|v| !keep.vlans.contains(v))
            .map(|v| v.0.clone())
            .collect();
        if !vlans.is_empty() {
            block_on(net::delete_links(&vlans));
            self.forget_vlans(&vlans);
        }
        let routes: Vec<(String, IpAddr)> = self
            .managed
            .routes
            .iter()
            .filter(|r| !keep.gateways.contains(r))
            .cloned()
            .collect();
        let addresses: Vec<(String, IpNet)> = self
            .managed
            .addresses
            .iter()
            .filter(|a| !keep.addresses.contains(a))
            .cloned()
            .collect();
        if routes.is_empty() && addresses.is_empty() {
            return;
        }
        block_on(net::remove_default_routes(&routes));
        for problem in block_on(net::remove_addresses(&addresses)) {
            eprintln!("oxd: {problem}");
        }
        self.managed.routes.retain(|r| !routes.contains(r));
        self.managed.addresses.retain(|a| !addresses.contains(a));
        self.save_managed();
    }
}

fn load(ruleset: &Value) -> Result<(), String> {
    ox_libnft::run_json(&ruleset.to_string())
        .map(|_| ())
        .map_err(|e| e.to_string())
}

impl Applier for SystemApplier {
    fn apply(&mut self, target: &Target) -> Result<(), String> {
        let conf = target.services.get(ox_services::DNSMASQ);
        // Check the service config before anything changes.
        self.dnsmasq.check(conf)?;
        load(&target.ruleset)?;
        // Addresses and forwarding come after the rules, so nothing is
        // routed before the firewall is in place, and before the services,
        // which listen on those addresses.
        let rest = (|| {
            self.bring_up(target)?;
            if target.forwarding {
                net::enable_forwarding(&target.uplinks)?;
            }
            self.dnsmasq.apply(conf)
        })();
        if let Err(e) = rest {
            // The firewall changed and the service did not follow. Go back,
            // so the box is never half in one config and half in another.
            let (ruleset, old) = match &self.current {
                Some(t) => (
                    t.ruleset.clone(),
                    t.services.get(ox_services::DNSMASQ).cloned(),
                ),
                None => (ox_nft::render_empty(), None),
            };
            let undone = load(&ruleset).and_then(|()| self.dnsmasq.apply(old.as_ref()));
            let previous = self.current.clone();
            self.take_down_all_but(previous.as_ref());
            if let Some(previous) = &previous {
                // Put back what the failed target replaced on its way: a
                // default route, a VLAN made again with another number, the
                // peers and routes of a tunnel. Everything here is safe to
                // repeat, so the whole of the previous config is brought up.
                if let Err(again) = self.bring_up(previous) {
                    eprintln!("oxd: could not put the previous interfaces back: {again}");
                }
            }
            return Err(match undone {
                Ok(()) => e,
                Err(u) => format!("{e}. Going back also failed: {u}"),
            });
        }
        // What the previous config had and this one does not.
        self.take_down_all_but(Some(target));
        self.current = Some(target.clone());
        Ok(())
    }
    fn dump(&mut self) -> Result<Value, String> {
        let out = ox_libnft::run_json(&list_command().to_string()).map_err(|e| e.to_string())?;
        serde_json::from_str(&out).map_err(|e| format!("nftables printed invalid JSON: {e}"))
    }
    fn name(&self) -> &'static str {
        "kernel"
    }
    fn tick(&mut self) {
        self.dnsmasq.tick();
    }
    fn services(&mut self) -> Vec<(String, String)> {
        self.dnsmasq
            .state()
            .map(|s| (ox_services::DNSMASQ.to_string(), s))
            .into_iter()
            .chain(
                self.dhcp
                    .iter()
                    .map(|(name, client)| (format!("address on {name}"), client.state())),
            )
            .chain(self.missing.iter().map(|name| {
                (
                    format!("interface {name}"),
                    "not on this machine; its addresses were not set".to_string(),
                )
            }))
            .collect()
    }
}

/// Tells systemd the rules are loaded and the API is up, so units ordered
/// after this one (the network coming up) wait for the firewall. Does
/// nothing when not started by systemd.
fn notify_ready() {
    use std::os::{linux::net::SocketAddrExt, unix::net};
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let bytes = path.as_encoded_bytes();
    let addr = match bytes.strip_prefix(b"@") {
        Some(name) => net::SocketAddr::from_abstract_name(name),
        None => net::SocketAddr::from_pathname(&path),
    };
    let sent = addr.and_then(|addr| net::UnixDatagram::unbound()?.send_to_addr(b"READY=1", &addr));
    if let Err(e) = sent {
        eprintln!("oxd: could not tell systemd the daemon is ready: {e}");
    }
}

pub type Shared = Arc<Mutex<Engine<Box<dyn Applier>>>>;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct Args {
    state_dir: PathBuf,
    socket: PathBuf,
    dry_run: bool,
    lockdown: bool,
    keep_privileges: bool,
    dnsmasq: String,
    /// Address for the HTTPS listener, such as 0.0.0.0:8443.
    listen: Option<std::net::SocketAddr>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    /// Loopback address for a plain HTTP listener, for a TLS proxy on this machine.
    listen_http: Option<std::net::SocketAddr>,
}

const USAGE: &str = "\
oxd: the Netoxide daemon

  --state-dir <dir>   where commits, candidates and the audit log live
                      (default /var/lib/netoxide)
  --socket <path>     Unix socket for the API (default /run/netoxide/oxd.sock)
  --version           print the version and exit
  --dry-run           keep state and serve the API, but load nothing into the kernel
                      and start no services
  --lockdown          until the first commit, drop forwarded and inbound traffic.
                      A remote session to this machine will be cut
  --dnsmasq <path>    the dnsmasq program to run for DNS and DHCP (default dnsmasq)
  --keep-service-privileges
                      do not switch services to an unprivileged user. Needed
                      inside a user namespace
  --listen <addr:port>
                      also serve the API and the web UI over HTTPS here.
                      Every request needs an access token (see `ox token`)
  --listen-http <127.0.0.1:port>
                      the same without TLS, on a loopback address only, for
                      a TLS proxy running on this machine
  --tls-cert <file>   certificate chain for --listen, in PEM
  --tls-key <file>    private key for --listen, in PEM. Without these two, a
                      self-signed certificate is made and kept in the state
                      directory
";

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        state_dir: "/var/lib/netoxide".into(),
        socket: "/run/netoxide/oxd.sock".into(),
        dry_run: false,
        lockdown: false,
        keep_privileges: false,
        dnsmasq: "dnsmasq".into(),
        listen: None,
        tls_cert: None,
        tls_key: None,
        listen_http: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--state-dir" => args.state_dir = it.next().ok_or("--state-dir needs a value")?.into(),
            "--socket" => args.socket = it.next().ok_or("--socket needs a value")?.into(),
            "--version" | "-V" => {
                println!("oxd {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--dry-run" => args.dry_run = true,
            "--lockdown" => args.lockdown = true,
            "--keep-service-privileges" => args.keep_privileges = true,
            "--dnsmasq" => args.dnsmasq = it.next().ok_or("--dnsmasq needs a value")?,
            "--listen" => {
                let v = it.next().ok_or("--listen needs an address and port")?;
                args.listen = Some(v.parse().map_err(|_| {
                    format!("'{v}' is not an address and port, such as 0.0.0.0:8443")
                })?);
            }
            "--listen-http" => {
                let v = it.next().ok_or("--listen-http needs an address and port")?;
                let addr: std::net::SocketAddr = v.parse().map_err(|_| {
                    format!("'{v}' is not an address and port, such as 127.0.0.1:8080")
                })?;
                // Tokens would cross the network in the clear on any other address.
                if !addr.ip().is_loopback() {
                    return Err(
                        "--listen-http only accepts a loopback address; use --listen for HTTPS"
                            .into(),
                    );
                }
                args.listen_http = Some(addr);
            }
            "--tls-cert" => {
                args.tls_cert = Some(it.next().ok_or("--tls-cert needs a file")?.into())
            }
            "--tls-key" => args.tls_key = Some(it.next().ok_or("--tls-key needs a file")?.into()),
            "-h" | "--help" => return Err(String::new()),
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    Ok(args)
}

async fn serve(args: Args) -> Result<(), String> {
    let applier: Box<dyn Applier> = if args.dry_run {
        Box::new(NullApplier::default())
    } else {
        Box::new(SystemApplier::new(
            &args.state_dir,
            services::Dnsmasq::new(
                args.state_dir.join("services"),
                args.dnsmasq.clone(),
                args.keep_privileges,
            ),
        ))
    };
    let baseline = if args.lockdown {
        Baseline::Lockdown
    } else {
        Baseline::Open
    };
    let engine = Engine::open_with(&args.state_dir, applier, baseline, now())
        .map_err(|e| format!("{}: {e}", args.state_dir.display()))?;
    let shared: Shared = Arc::new(Mutex::new(engine));
    let leases = args.state_dir.join("services").join("dnsmasq.leases");

    // A socket file left by a previous run would make bind fail.
    let _ = std::fs::remove_file(&args.socket);
    if let Some(dir) = args.socket.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let listener = tokio::net::UnixListener::bind(&args.socket)
        .map_err(|e| format!("{}: {e}", args.socket.display()))?;
    std::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| format!("{}: {e}", args.socket.display()))?;

    // The commit-confirm clock. A pending commit past its deadline is reverted here.
    let ticker = shared.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(1));
        loop {
            every.tick().await;
            match ticker.lock().unwrap_or_else(|e| e.into_inner()).tick(now()) {
                Ok(Some(c)) => eprintln!(
                    "oxd: commit #{} was not confirmed and has been reverted",
                    c.id
                ),
                Ok(None) => {}
                Err(e) => eprintln!("oxd: automatic revert failed: {e}"),
            }
        }
    });

    // A box with no config can be set up from a browser, with this code.
    let has_config = shared
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .running()
        .is_ok_and(|r| r.is_some());
    let setup_code = setup::open(&args.state_dir, has_config);

    notify_ready();
    eprintln!(
        "oxd: listening on {} ({})",
        args.socket.display(),
        if args.dry_run {
            "dry run, nothing is loaded"
        } else {
            "applying to the kernel"
        }
    );
    if args.tls_cert.is_some() != args.tls_key.is_some() {
        return Err("--tls-cert and --tls-key go together".into());
    }
    if let Some(addr) = args.listen {
        let tls::Loaded {
            config,
            note,
            fingerprint,
        } = tls::config(
            &args.state_dir,
            args.tls_cert.as_deref(),
            args.tls_key.as_deref(),
        )
        .await?;
        let _ = api::HTTPS.set(serde_json::json!({
            "listen": addr.to_string(),
            "fingerprint": fingerprint,
        }));
        // No connect info here, so every request must carry a token.
        let app = api::router(shared.clone(), leases.clone(), args.state_dir.clone());
        eprintln!("oxd: HTTPS on {addr} ({note}); every request needs an access token");
        eprintln!("oxd: certificate fingerprint {fingerprint}");
        tokio::spawn(async move {
            // A caller has 10 seconds to finish the TLS handshake, which the
            // library sets. This adds a cap on how many connections are open
            // at once, and closes the ones that go quiet.
            let acceptor = axum_server::tls_rustls::RustlsAcceptor::new(config).acceptor(
                limit::Limit::new(MAX_CONNECTIONS, MAX_PER_ADDRESS, idle_timeout()),
            );
            // The server library leaves both of these off. Without them a
            // caller could hold a place for ever by sending a byte of a
            // request now and then.
            let patience = idle_timeout().min(std::time::Duration::from_secs(30));
            let mut server = axum_server::bind(addr)
                .acceptor(acceptor)
                .first_request_timeout(patience);
            server.http_builder().http1().header_read_timeout(patience);
            if let Err(e) = server
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
            {
                eprintln!("oxd: the HTTPS listener stopped: {e}");
            }
        });
    }
    if let Some(code) = &setup_code {
        if args.listen.is_some() || args.listen_http.is_some() {
            eprintln!(
                "oxd: this box has no config. Open its web interface from the inside network and enter the setup code {code}"
            );
        } else {
            eprintln!(
                "oxd: this box has no config. Run `ox init` here, or start the daemon with --listen to set it up from a browser"
            );
        }
    }
    if let Some(addr) = args.listen_http {
        let plain = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("{addr}: {e}"))?;
        let app = api::router(shared.clone(), leases.clone(), args.state_dir.clone());
        eprintln!("oxd: HTTP on {addr}, loopback only; every request needs an access token");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(
                plain,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            {
                eprintln!("oxd: the HTTP listener stopped: {e}");
            }
        });
    }
    let socket = args.socket.clone();
    axum::serve(
        listener,
        api::router(shared, leases, args.state_dir.clone())
            .into_make_service_with_connect_info::<api::Peer>(),
    )
    .with_graceful_shutdown(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    })
    .await
    .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(socket);
    eprintln!("oxd: stopped; the loaded ruleset stays in place");
    Ok(())
}

/// How many connections the HTTPS listener holds at once, and how many of
/// them one address may have. A browser opens about six and `ox` one.
const MAX_CONNECTIONS: usize = 256;
const MAX_PER_ADDRESS: usize = 32;

/// How long a connection to the HTTPS listener may go with no bytes either
/// way before it is closed. The longest quiet stretch in normal use is a
/// commit that restarts services while the caller waits for the answer.
fn idle_timeout() -> std::time::Duration {
    // Tests set this to see a quiet connection closed without waiting minutes.
    let secs = std::env::var("OXD_IDLE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|s| (1..=3600).contains(s))
        .unwrap_or(120);
    std::time::Duration::from_secs(secs)
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) if e.is_empty() => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("oxd: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("oxd: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(serve(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("oxd: {e}");
            ExitCode::FAILURE
        }
    }
}

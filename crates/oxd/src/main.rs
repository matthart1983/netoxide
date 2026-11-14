//! `oxd`: the Netoxide daemon.
//!
//! It owns the config. Every change goes through it as a candidate and a
//! commit, and it is the only thing that loads rules into the kernel.
//!
//! The API is HTTP and JSON on a Unix socket. Access is whoever can open the
//! socket file; there is no TLS, login or role check yet. The caller's name
//! comes from the `x-ox-user` header and is recorded as given.
//!
//! Stopping the daemon leaves the loaded ruleset in place. The box keeps
//! forwarding with the last commit.

mod api;
mod services;
mod tls;
mod web;

use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ox_nft::list_command;
use ox_store::{Applier, Baseline, Engine, NullApplier, Target};
use serde_json::Value;

/// Puts a target into effect on this machine: the ruleset into the kernel
/// through libnftables, and the service config into a supervised dnsmasq.
struct SystemApplier {
    dnsmasq: services::Dnsmasq,
    /// The last target that was applied in full, for undoing a half-applied one.
    current: Option<Target>,
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
        if let Err(e) = self.dnsmasq.apply(conf) {
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
            return Err(match undone {
                Ok(()) => e,
                Err(u) => format!("{e}. Going back also failed: {u}"),
            });
        }
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
            .collect()
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
}

const USAGE: &str = "\
oxd: the Netoxide daemon

  --state-dir <dir>   where commits, candidates and the audit log live
                      (default /var/lib/netoxide)
  --socket <path>     Unix socket for the API (default /run/netoxide/oxd.sock)
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
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--state-dir" => args.state_dir = it.next().ok_or("--state-dir needs a value")?.into(),
            "--socket" => args.socket = it.next().ok_or("--socket needs a value")?.into(),
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
        Box::new(SystemApplier {
            dnsmasq: services::Dnsmasq::new(
                args.state_dir.join("services"),
                args.dnsmasq.clone(),
                args.keep_privileges,
            ),
            current: None,
        })
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
            match ticker.lock().unwrap().tick(now()) {
                Ok(Some(c)) => eprintln!(
                    "oxd: commit #{} was not confirmed and has been reverted",
                    c.id
                ),
                Ok(None) => {}
                Err(e) => eprintln!("oxd: automatic revert failed: {e}"),
            }
        }
    });

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
        let (config, note) = tls::config(
            &args.state_dir,
            args.tls_cert.as_deref(),
            args.tls_key.as_deref(),
        )
        .await?;
        // No connect info here, so every request must carry a token.
        let app = api::router(shared.clone(), leases.clone());
        eprintln!("oxd: HTTPS on {addr} ({note}); every request needs an access token");
        tokio::spawn(async move {
            if let Err(e) = axum_server::bind_rustls(addr, config)
                .serve(app.into_make_service())
                .await
            {
                eprintln!("oxd: the HTTPS listener stopped: {e}");
            }
        });
    }
    let socket = args.socket.clone();
    axum::serve(
        listener,
        api::router(shared, leases).into_make_service_with_connect_info::<api::Peer>(),
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

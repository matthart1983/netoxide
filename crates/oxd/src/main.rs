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

use std::{
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::ExitCode,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ox_nft::list_command;
use ox_store::{Applier, Engine, NullApplier};
use serde_json::Value;

/// Loads rulesets into the kernel through libnftables.
struct KernelApplier;

impl Applier for KernelApplier {
    fn apply(&mut self, ruleset: &Value) -> Result<(), String> {
        ox_libnft::run_json(&ruleset.to_string())
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    fn dump(&mut self) -> Result<Value, String> {
        let out = ox_libnft::run_json(&list_command().to_string()).map_err(|e| e.to_string())?;
        serde_json::from_str(&out).map_err(|e| format!("nftables printed invalid JSON: {e}"))
    }
    fn name(&self) -> &'static str {
        "kernel"
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
}

const USAGE: &str = "\
oxd: the Netoxide daemon

  --state-dir <dir>   where commits, candidates and the audit log live
                      (default /var/lib/netoxide)
  --socket <path>     Unix socket for the API (default /run/netoxide/oxd.sock)
  --dry-run           keep state and serve the API, but load nothing into the kernel
";

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        state_dir: "/var/lib/netoxide".into(),
        socket: "/run/netoxide/oxd.sock".into(),
        dry_run: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--state-dir" => args.state_dir = it.next().ok_or("--state-dir needs a value")?.into(),
            "--socket" => args.socket = it.next().ok_or("--socket needs a value")?.into(),
            "--dry-run" => args.dry_run = true,
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
        Box::new(KernelApplier)
    };
    let engine = Engine::open(&args.state_dir, applier, now())
        .map_err(|e| format!("{}: {e}", args.state_dir.display()))?;
    let shared: Shared = Arc::new(Mutex::new(engine));

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
    let socket = args.socket.clone();
    axum::serve(listener, api::router(shared))
        .with_graceful_shutdown(async {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
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

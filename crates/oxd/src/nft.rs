//! Loads and reads the kernel's ruleset by running the `nft` program.
//!
//! `nft` is started with a fixed argument list and no shell. The ruleset
//! goes to it as JSON on standard input, never on the command line. `nft`
//! applies a file as one netlink transaction: every command in it takes
//! effect or none does.
//!
//! The daemon used to call libnftables in process. That library is
//! GPL-2.0-only, and running the program keeps the two apart. It also
//! leaves the workspace with no `unsafe` code at all.

use std::{
    fmt,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

/// Where distributions install `nft`. The daemon does not search `PATH`, so
/// a directory someone can write to cannot stand in for it.
const PLACES: [&str; 4] = [
    "/usr/sbin/nft",
    "/usr/bin/nft",
    "/sbin/nft",
    "/usr/local/sbin/nft",
];

/// How long one run may take before it is stopped. A load is normally over
/// in well under a second.
const LIMIT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NftError {
    /// The `nft` program is not installed where the daemon looks.
    Missing,
    /// It could not be started or did not finish.
    Failed(String),
    /// nftables refused the ruleset. Nothing in it was applied.
    Refused(String),
}

impl fmt::Display for NftError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NftError::Missing => write!(
                f,
                "the nft program is not installed (looked in {}); install the nftables package",
                PLACES.join(", ")
            ),
            NftError::Failed(why) => write!(f, "nft could not be run: {why}"),
            NftError::Refused(msg) => write!(f, "nftables refused the ruleset: {}", msg.trim()),
        }
    }
}

impl std::error::Error for NftError {}

fn program() -> Option<&'static str> {
    PLACES.into_iter().find(|p| Path::new(p).is_file())
}

/// True when the `nft` program is where the daemon looks for it.
pub fn installed() -> bool {
    program().is_some()
}

/// Runs a libnftables JSON document and returns what nftables printed.
///
/// The document is one transaction. On `Err`, the kernel ruleset is unchanged.
pub fn run_json(json: &str) -> Result<String, NftError> {
    let program = program().ok_or(NftError::Missing)?;
    let failed = |e: std::io::Error| NftError::Failed(e.to_string());
    let mut child = Command::new(program)
        // JSON in and out, read from standard input.
        .args(["--json", "--file", "-"])
        // Nothing of the daemon's environment is nft's business.
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(failed)?;

    // Each pipe gets its own thread, so a large ruleset going in and a
    // large listing coming out cannot wait on each other.
    let mut stdin = child.stdin.take().expect("stdin was piped");
    let input = json.to_string();
    let writer = std::thread::spawn(move || stdin.write_all(input.as_bytes()));
    let mut stdout = child.stdout.take().expect("stdout was piped");
    let out = std::thread::spawn(move || {
        let mut text = String::new();
        stdout.read_to_string(&mut text).map(|_| text)
    });
    let mut stderr = child.stderr.take().expect("stderr was piped");
    let err = std::thread::spawn(move || {
        let mut text = String::new();
        stderr.read_to_string(&mut text).map(|_| text)
    });

    let started = Instant::now();
    let status = loop {
        match child.try_wait().map_err(failed)? {
            Some(status) => break status,
            None if started.elapsed() > LIMIT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(NftError::Failed(format!(
                    "it did not finish within {} seconds and was stopped",
                    LIMIT.as_secs()
                )));
            }
            None => std::thread::sleep(Duration::from_millis(2)),
        }
    };
    // A program that refused its input may have closed the pipe early, so a
    // failed write is only an error if the run otherwise succeeded.
    let wrote = writer.join().unwrap_or(Ok(()));
    let output = out.join().ok().and_then(Result::ok).unwrap_or_default();
    let error = err.join().ok().and_then(Result::ok).unwrap_or_default();
    if !status.success() {
        return Err(NftError::Refused(if error.trim().is_empty() {
            format!("nft stopped with {status}")
        } else {
            error
        }));
    }
    wrote.map_err(failed)?;
    Ok(output)
}

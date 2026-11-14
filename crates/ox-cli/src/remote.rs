//! `ox remote`: the boxes this machine can manage over HTTPS.

use std::io::{BufRead, IsTerminal, Write};

use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
use ox_client::{Client, Remote, Trust, fingerprint_text, parse_fingerprint, parse_url, remotes};

use crate::{RemoteCmd, Result};

/// Reads a line from the terminal without showing it.
fn read_secret(prompt: &str) -> Result<String> {
    let stdin = std::io::stdin();
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let before = tcgetattr(&stdin).ok();
    if let Some(mut hidden) = before.clone() {
        hidden.local_flags.remove(LocalFlags::ECHO);
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, &hidden);
    }
    let mut line = String::new();
    let read = stdin.lock().read_line(&mut line);
    if let Some(before) = before {
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, &before);
        eprintln!();
    }
    read?;
    Ok(line.trim().to_string())
}

fn ask(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

pub fn run(cmd: &RemoteCmd) -> Result<()> {
    let file = remotes::path()?;
    match cmd {
        RemoteCmd::List => {
            let all = remotes::load(&file)?;
            if all.is_empty() {
                out!("no boxes saved; add one with `ox remote add <name> <url>`");
            }
            for (name, saved) in &all {
                out!(
                    "{:<16} {}  {}",
                    name,
                    saved.url,
                    match &saved.fingerprint {
                        Some(fp) => format!("certificate {fp}"),
                        None => "certificate checked by this machine's authorities".into(),
                    }
                );
            }
        }
        RemoteCmd::Remove { name } => {
            let mut all = remotes::load(&file)?;
            if all.remove(name).is_none() {
                return Err(format!("no box is saved as '{name}'").into());
            }
            remotes::save(&file, &all)?;
            out!(
                "forgot {name}. Its access token still works on the box until it is revoked there"
            );
        }
        RemoteCmd::Add {
            name,
            url,
            fingerprint,
            token_file,
        } => {
            if !ox_schema::is_name(name) {
                return Err(format!(
                    "'{name}' is not a name for a box; use lowercase letters, digits and hyphens"
                )
                .into());
            }
            let (host, port) = parse_url(url)?;
            let seen = ox_client::probe(&host, port)?;
            let shown = fingerprint_text(&seen.fingerprint);
            let trust = match fingerprint {
                Some(given) => {
                    if parse_fingerprint(given)? != seen.fingerprint {
                        return Err(format!(
                            "the box at {url} shows the certificate {shown}, which is not the fingerprint you gave. Nothing was saved and no token was sent"
                        )
                        .into());
                    }
                    Trust::Pin(seen.fingerprint)
                }
                None if seen.trusted => {
                    out!(
                        "The certificate of {host} is vouched for by this machine's certificate authorities."
                    );
                    Trust::Roots
                }
                None => {
                    out!("The box at {url} made its own certificate:\n");
                    out!("  {shown}\n");
                    out!("Run `ox status` on the box and compare the certificate line.");
                    if !std::io::stdin().is_terminal() {
                        return Err(
                            "pass --fingerprint with the value from the box to save it without being asked".into(),
                        );
                    }
                    if !matches!(ask("Is it the same? [y/N] ")?.as_str(), "y" | "Y" | "yes") {
                        return Err("nothing was saved".into());
                    }
                    Trust::Pin(seen.fingerprint)
                }
            };
            let token = match token_file {
                Some(path) => std::fs::read_to_string(path)
                    .map_err(|e| format!("{}: {e}", path.display()))?
                    .trim()
                    .to_string(),
                None => match std::env::var("OX_TOKEN").ok().filter(|t| !t.is_empty()) {
                    Some(token) => token,
                    None if std::io::stdin().is_terminal() => {
                        read_secret("Access token (made on the box with `ox token create`): ")?
                    }
                    None => {
                        return Err("give the access token with --token-file or in OX_TOKEN".into());
                    }
                },
            };
            let saved = remotes::Saved::new(&host, port, &trust, &token);
            // Checks the address, the certificate and the token in one go.
            let remote: Remote = saved.remote()?;
            let me = Client::https(remote).json("GET", "/v1/whoami", None)?;
            let mut all = remotes::load(&file)?;
            let replaced = all.insert(name.clone(), saved).is_some();
            remotes::save(&file, &all)?;
            out!(
                "{} {name}: you are {} with the role {}",
                if replaced { "replaced" } else { "saved" },
                me["name"].as_str().unwrap_or("?"),
                me["role"].as_str().unwrap_or("?"),
            );
            out!("Use it with: ox --remote {name} status");
            out!(
                "The token is kept in {}, readable only by you",
                file.display()
            );
        }
    }
    Ok(())
}

//! First-run setup from a browser.
//!
//! A box with no config has no tokens, so nobody could sign in to the web
//! UI to set it up. This opens one narrow door for that moment only:
//!
//! - The daemon makes a setup code, prints it where only someone on the
//!   box can read it (the console, the journal, `ox status`), and keeps it
//!   in the state directory.
//! - Whoever has the code may list the machine's ports, preview a starter
//!   config and apply it. Applying returns an admin access token.
//! - The door only opens to callers on a private or local address, shuts
//!   after ten wrong codes, and shuts for good once a config is running.

use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{
        OnceLock,
        atomic::{AtomicU32, Ordering},
    },
};

use axum::{
    Json, Router,
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use ox_setup::{Answers, Port, Serve};
use serde::Deserialize;
use serde_json::json;

use crate::{
    Shared,
    api::{ApiError, HTTPS},
    now,
};

/// How many wrong codes are accepted before setup shuts until a restart.
const MAX_TRIES: u32 = 10;

/// How long a setup's first commit waits to be kept.
const KEEP_SECS: u64 = 300;

struct Door {
    code: String,
    wrong: AtomicU32,
}

static DOOR: OnceLock<Door> = OnceLock::new();

/// Letters and digits that are hard to mistake for one another.
const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";

fn new_code() -> std::io::Result<String> {
    use std::io::Read;
    let mut bytes = [0u8; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut code: String = bytes
        .iter()
        .map(|b| ALPHABET[usize::from(*b) % ALPHABET.len()] as char)
        .collect();
    code.insert(4, '-');
    Ok(code)
}

/// Letters and digits only, in capitals, so a code can be typed loosely.
fn plain(code: &str) -> String {
    code.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Opens setup for a box that has no running config, and returns the code.
/// The same code is used again after a restart, until a config runs.
pub fn open(state_dir: &Path, has_config: bool) -> Option<String> {
    let file = state_dir.join("setup-code");
    if has_config {
        let _ = std::fs::remove_file(&file);
        return None;
    }
    let code = match std::fs::read_to_string(&file) {
        Ok(text) if plain(&text).len() == 8 => text.trim().to_string(),
        _ => {
            use std::{io::Write, os::unix::fs::OpenOptionsExt};
            let code = new_code().ok()?;
            let _ = std::fs::remove_file(&file);
            let written = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&file)
                .and_then(|mut f| f.write_all(code.as_bytes()));
            if let Err(e) = written {
                eprintln!("oxd: cannot keep the setup code ({}): {e}", file.display());
            }
            code
        }
    };
    let _ = DOOR.set(Door {
        code: code.clone(),
        wrong: AtomicU32::new(0),
    });
    Some(code)
}

/// The code, for someone already on the box, while setup is still open.
pub fn code_for_local(has_config: bool) -> Option<&'static str> {
    if has_config {
        return None;
    }
    DOOR.get().map(|d| d.code.as_str())
}

/// Addresses that are on the same site as the box, never across the internet.
fn is_nearby(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn refuse(status: StatusCode, why: &str) -> ApiError {
    ApiError::new(status, why)
}

/// True while a box could be set up from the browser.
fn available(s: &Shared) -> bool {
    DOOR.get()
        .is_some_and(|d| d.wrong.load(Ordering::Relaxed) < MAX_TRIES)
        && s.lock()
            .unwrap_or_else(|e| e.into_inner())
            .running()
            .is_ok_and(|r| r.is_none())
}

/// Checks the caller may use setup: nearby, with the right code.
fn admit(s: &Shared, from: Option<SocketAddr>, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(door) = DOOR.get() else {
        return Err(refuse(
            StatusCode::CONFLICT,
            "this box is already set up; sign in with an access token",
        ));
    };
    if !from.is_some_and(|a| is_nearby(a.ip())) {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "setup only answers a device on the same network as the box",
        ));
    }
    if door.wrong.load(Ordering::Relaxed) >= MAX_TRIES {
        return Err(refuse(
            StatusCode::FORBIDDEN,
            "too many wrong setup codes. Restart the daemon on the box to try again, or set it up there with `ox init`",
        ));
    }
    if !available(s) {
        return Err(refuse(
            StatusCode::CONFLICT,
            "this box is already set up; sign in with an access token",
        ));
    }
    let given = headers
        .get("x-setup-code")
        .and_then(|v| v.to_str().ok())
        .map(plain)
        .unwrap_or_default();
    if given != plain(&door.code) {
        let left = MAX_TRIES.saturating_sub(door.wrong.fetch_add(1, Ordering::Relaxed) + 1);
        return Err(refuse(
            StatusCode::UNAUTHORIZED,
            &format!(
                "that is not the setup code. It is shown on the box by `ox status` and in the daemon's log. {left} tries left"
            ),
        ));
    }
    Ok(())
}

/// Where a request came from, when the listener records it.
struct From_(Option<SocketAddr>);

impl<S: Sync> axum::extract::FromRequestParts<S> for From_ {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<From_, Self::Rejection> {
        Ok(From_(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0),
        ))
    }
}

/// Whether the browser should offer setup. Says nothing else.
async fn state(State(s): State<Shared>) -> Response {
    Json(json!({ "needed": available(&s) })).into_response()
}

/// The machine's ports, for choosing which faces the internet.
async fn ports(
    State(s): State<Shared>,
    from: From_,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    admit(&s, from.0, &headers)?;
    let found = ox_setup::detect().map_err(|e| {
        refuse(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("cannot list this machine's ports: {e}"),
        )
    })?;
    let rows: Vec<_> = found
        .iter()
        .map(|d| {
            json!({
                "name": d.name,
                "up": d.up,
                "addresses": d.addrs.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "internet": d.default_route,
            })
        })
        .collect();
    Ok(Json(json!({ "ports": rows, "hostname": hostname() })).into_response())
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| ox_schema::is_hostname(h))
        .unwrap_or_else(|| "netoxide".into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inside {
    port: String,
    /// The box's address there, with its prefix length. Left out, the
    /// address the port already has is kept.
    #[serde(default)]
    address: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Choice {
    /// The port that faces the internet.
    internet: String,
    inside: Vec<Inside>,
    #[serde(default)]
    name: Option<String>,
}

/// Turns the answers into a complete starter config.
fn build(choice: &Choice) -> Result<ox_schema::Config, String> {
    let found = ox_setup::detect().map_err(|e| format!("cannot list this machine's ports: {e}"))?;
    let detected = |name: &str| found.iter().find(|d| d.name == name);
    let wan = detected(&choice.internet)
        .ok_or_else(|| format!("this machine has no port called {}", choice.internet))?;
    // An internet port with no IPv4 address of its own asks the provider's
    // network for one, as a port behind a modem does.
    let wan_v4: Vec<_> = wan
        .addrs
        .iter()
        .filter(|a| a.addr().is_ipv4())
        .copied()
        .collect();
    let wan_dhcp = wan_v4.is_empty() || wan.gateway.is_none();
    let mut lans = vec![];
    for (i, inside) in choice.inside.iter().enumerate() {
        let port = detected(&inside.port)
            .ok_or_else(|| format!("this machine has no port called {}", inside.port))?;
        let addrs = match inside
            .address
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            Some(text) => vec![text.parse().map_err(|_| {
                format!("'{text}' is not an address with a prefix length, such as 192.168.10.1/24")
            })?],
            None if !port.addrs.is_empty() => port.addrs.clone(),
            None => vec![
                format!("192.168.{}.1/24", 10 + i)
                    .parse()
                    .map_err(|_| "too many inside ports".to_string())?,
            ],
        };
        lans.push(Port {
            name: inside.port.clone(),
            addrs,
        });
    }
    let answers = Answers {
        hostname: choice
            .name
            .as_deref()
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(String::from)
            .unwrap_or_else(hostname),
        wan: Port {
            name: wan.name.clone(),
            addrs: if wan_dhcp {
                wan.addrs
                    .iter()
                    .filter(|a| !a.addr().is_ipv4())
                    .copied()
                    .collect()
            } else {
                wan.addrs.clone()
            },
        },
        lans,
        serve: Some(Serve::default()),
        wan_dhcp,
        gateway: if wan_dhcp {
            vec![]
        } else {
            wan.gateway.map(IpAddr::V4).into_iter().collect()
        },
    };
    let mut config = ox_setup::starter(&answers)?;
    // Keep this page reachable from inside once the rules are loaded.
    if let Some(port) = HTTPS
        .get()
        .and_then(|h| h["listen"].as_str())
        .and_then(|l| l.parse::<SocketAddr>().ok())
        .map(|a| a.port())
    {
        ox_setup::allow_admin(&mut config, port)?;
    }
    Ok(config)
}

/// What the chosen setup would do, in sentences. Changes nothing.
async fn preview(
    State(s): State<Shared>,
    from: From_,
    headers: HeaderMap,
    Json(choice): Json<Choice>,
) -> Result<Response, ApiError> {
    admit(&s, from.0, &headers)?;
    let config = build(&choice).map_err(|e| refuse(StatusCode::UNPROCESSABLE_ENTITY, &e))?;
    Ok(Json(json!({ "describe": ox_setup::describe(&config) })).into_response())
}

/// Applies the chosen setup with an undo timer and hands back an admin
/// token. If the caller is cut off, the box goes back to having no config
/// and setup opens again with the same code.
async fn apply(
    State(s): State<Shared>,
    from: From_,
    headers: HeaderMap,
    Json(choice): Json<Choice>,
) -> Result<Response, ApiError> {
    admit(&s, from.0, &headers)?;
    let config = build(&choice).map_err(|e| refuse(StatusCode::UNPROCESSABLE_ENTITY, &e))?;
    let who = "first-run setup";
    let mut e = s.lock().unwrap_or_else(|e| e.into_inner());
    e.put_candidate("setup", &config.to_toml(), who, now())?;
    // A token from an earlier try that was not kept is replaced.
    if e.tokens()?.iter().any(|t| t.name == "setup") {
        e.revoke_token("setup", who, now())?;
    }
    let token = e.create_token("setup", "admin", None, who, now())?;
    let commit = e.commit_candidate("setup", who, "first-run setup", Some(KEEP_SECS), now())?;
    Ok(
        Json(json!({ "token": token, "commit": commit.id, "keep_secs": KEEP_SECS }))
            .into_response(),
    )
}

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/v1/setup", get(state))
        .route("/v1/setup/ports", get(ports))
        .route("/v1/setup/preview", post(preview))
        .route("/v1/setup/apply", post(apply))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_typed_loosely_and_differ() {
        let (a, b) = (new_code().unwrap(), new_code().unwrap());
        assert_eq!(a.len(), 9);
        assert_eq!(a.as_bytes()[4], b'-');
        assert_ne!(a, b);
        assert_eq!(plain("abcd-ef23"), "ABCDEF23");
        assert_eq!(plain(" ABCD EF23\n"), "ABCDEF23");
        assert!(a.bytes().all(|c| c == b'-' || ALPHABET.contains(&c)));
    }

    #[test]
    fn setup_answers_only_nearby_callers() {
        for near in [
            "127.0.0.1",
            "192.168.1.9",
            "10.0.0.1",
            "172.16.4.4",
            "169.254.1.1",
            "::1",
            "fe80::1",
            "fd00::5",
            "::ffff:192.168.1.9",
        ] {
            assert!(is_nearby(near.parse().unwrap()), "{near}");
        }
        for far in [
            "8.8.8.8",
            "203.0.113.9",
            "172.32.0.1",
            "2001:db8::1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_nearby(far.parse().unwrap()), "{far}");
        }
    }
}

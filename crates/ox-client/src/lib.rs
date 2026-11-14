//! A small HTTP/1.1 client for the daemon.
//!
//! On the box it talks to the daemon's Unix socket. From another machine it
//! talks to the HTTPS listener with an access token. One request per
//! connection, with `Connection: close`.

pub mod remotes;
mod tls;

use std::{
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::Value;

pub use tls::{Probe, Trust, fingerprint_text, parse_fingerprint, probe};

/// A daemon on another machine, and how to know it is the right one.
#[derive(Debug, Clone)]
pub struct Remote {
    /// A name or an address, without brackets.
    pub host: String,
    pub port: u16,
    pub trust: Trust,
    pub token: String,
}

impl Remote {
    /// The address as it goes in a URL.
    pub fn authority(&self) -> String {
        authority(&self.host, self.port)
    }
}

pub fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The port `oxd --listen` is shown with in the docs, used when a URL names none.
pub const DEFAULT_PORT: u16 = 8443;

/// Reads `https://host:port`, `host:port` or `host`. Plain `http://` is
/// refused, because the access token would cross the network in the clear.
pub fn parse_url(url: &str) -> Result<(String, u16), String> {
    let bad =
        || format!("'{url}' is not an address for a box; use https://<name or address>:<port>");
    if url.starts_with("http://") {
        return Err(format!(
            "'{url}' is plain HTTP, which would send the access token unencrypted; use https://"
        ));
    }
    let rest = url.strip_prefix("https://").unwrap_or(url);
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', ' ']) {
        return Err(bad());
    }
    let (host, port) = if let Some(inner) = rest.strip_prefix('[') {
        // An IPv6 address in brackets, with or without a port.
        let (host, after) = inner.split_once(']').ok_or_else(bad)?;
        match after {
            "" => (host, None),
            p => (host, Some(p.strip_prefix(':').ok_or_else(bad)?)),
        }
    } else if rest.matches(':').count() > 1 {
        // A bare IPv6 address.
        (rest, None)
    } else {
        match rest.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (rest, None),
        }
    };
    let port = match port {
        None => DEFAULT_PORT,
        Some(p) => p.parse().ok().filter(|p| *p != 0).ok_or_else(bad)?,
    };
    if host.is_empty() {
        return Err(bad());
    }
    Ok((host.to_string(), port))
}

enum Via {
    Unix(PathBuf),
    Https(Remote),
}

pub struct Client {
    via: Via,
}

trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}

/// How long to wait for a box to accept a connection, and for an answer. A
/// commit that restarts services can take a while to answer.
const CONNECT: Duration = Duration::from_secs(10);
const ANSWER: Duration = Duration::from_secs(120);

fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot look up {host}: {e}"))?;
    let mut last = format!("{host} has no address");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(ANSWER));
                let _ = stream.set_write_timeout(Some(ANSWER));
                return Ok(stream);
            }
            Err(e) => last = format!("cannot reach {addr}: {e}"),
        }
    }
    Err(last)
}

impl Client {
    /// A client for the daemon on this machine.
    pub fn new(socket: &Path) -> Client {
        Client {
            via: Via::Unix(socket.to_path_buf()),
        }
    }

    /// A client for a daemon on another machine.
    pub fn https(remote: Remote) -> Client {
        Client {
            via: Via::Https(remote),
        }
    }

    /// Whether this client talks to another machine.
    pub fn is_remote(&self) -> bool {
        matches!(self.via, Via::Https(_))
    }

    /// Where the daemon is, for messages.
    pub fn target(&self) -> String {
        match &self.via {
            Via::Unix(path) => path.display().to_string(),
            Via::Https(r) => format!("https://{}", r.authority()),
        }
    }

    fn open(&self) -> Result<(Box<dyn Stream>, String, String), String> {
        match &self.via {
            Via::Unix(socket) => {
                let stream = UnixStream::connect(socket).map_err(|e| {
                    format!(
                        "cannot reach oxd at {}: {e}. Is the daemon running? Set --socket or OX_SOCKET if it listens elsewhere, or --remote for a box on the network",
                        socket.display()
                    )
                })?;
                Ok((Box::new(stream), "oxd".into(), String::new()))
            }
            Via::Https(r) => {
                let tcp = connect_tcp(&r.host, r.port)?;
                let stream = tls::wrap(tcp, &r.host, &r.trust)?;
                let auth = format!("Authorization: Bearer {}\r\n", r.token);
                Ok((Box::new(stream), r.authority(), auth))
            }
        }
    }

    /// Sends a request and returns the body of a 2xx response. Any other
    /// status becomes an error carrying the daemon's message.
    pub fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<(&str, &str)>,
    ) -> Result<String, String> {
        let (mut stream, host, auth) = self.open()?;
        let (content_type, payload) = body.unwrap_or(("text/plain", ""));
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{auth}\
             Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{payload}",
            payload.len()
        );
        let explain = |e: std::io::Error| tls::explain(&e, &self.target());
        stream.write_all(request.as_bytes()).map_err(explain)?;
        stream.flush().map_err(explain)?;
        let raw = read_response(&mut *stream).map_err(explain)?;
        let text = String::from_utf8_lossy(&raw);

        let (head, body) = text
            .split_once("\r\n\r\n")
            .ok_or("oxd sent a response without headers")?;
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or("oxd sent a response without a status")?;
        if head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
        {
            return Err("oxd sent a chunked response, which this client does not read".into());
        }
        if (200..300).contains(&status) {
            return Ok(body.to_string());
        }
        let message = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| v["error"].as_str().map(String::from))
            .unwrap_or_else(|| format!("oxd answered {status}"));
        Err(message)
    }

    pub fn get(&self, path: &str) -> Result<String, String> {
        self.send("GET", path, None)
    }

    pub fn json(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
        let payload = body.map(Value::to_string);
        let text = self.send(
            method,
            path,
            payload.as_deref().map(|p| ("application/json", p)),
        )?;
        serde_json::from_str(&text).map_err(|e| format!("oxd sent invalid JSON: {e}"))
    }
}

/// The largest answer this client will hold. The audit log of a busy box is
/// the biggest thing the daemon sends.
const MAX_RESPONSE: usize = 256 * 1024 * 1024;

/// Reads one response: the headers, then as many bytes as `Content-Length`
/// says, or everything until the daemon closes the connection.
fn read_response(stream: &mut dyn Read) -> std::io::Result<Vec<u8>> {
    let mut raw = vec![];
    let mut buf = [0u8; 16 * 1024];
    let mut want: Option<usize> = None;
    loop {
        if want.is_none()
            && let Some(end) = raw.windows(4).position(|w| w == b"\r\n\r\n")
        {
            let head = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok());
            // Without a length, the end of the connection is the end.
            want = Some(length.map_or(usize::MAX, |n| (end + 4).saturating_add(n)));
        }
        if want.is_some_and(|n| raw.len() >= n) {
            raw.truncate(want.unwrap_or(raw.len()));
            return Ok(raw);
        }
        if raw.len() > MAX_RESPONSE {
            return Err(std::io::Error::other("the answer is too large"));
        }
        match stream.read(&mut buf) {
            Ok(0) => return Ok(raw),
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            // A TLS peer that closes without saying so first has still sent
            // everything when no length was promised.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && want == Some(usize::MAX) => {
                return Ok(raw);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_parse() {
        let ok = |url: &str, host: &str, port: u16| {
            assert_eq!(parse_url(url), Ok((host.to_string(), port)), "{url}");
        };
        ok("https://fw.example.net:9443", "fw.example.net", 9443);
        ok("https://fw.example.net", "fw.example.net", DEFAULT_PORT);
        ok("https://fw.example.net/", "fw.example.net", DEFAULT_PORT);
        ok("fw.example.net:9443", "fw.example.net", 9443);
        ok("192.0.2.1", "192.0.2.1", DEFAULT_PORT);
        ok("https://192.0.2.1:8443", "192.0.2.1", 8443);
        ok("https://[2001:db8::1]:9443", "2001:db8::1", 9443);
        ok("[2001:db8::1]", "2001:db8::1", DEFAULT_PORT);
        ok("2001:db8::1", "2001:db8::1", DEFAULT_PORT);
        for bad in [
            "",
            "https://",
            "http://fw.example.net",
            "https://fw/path",
            "https://user@fw",
            "fw:0",
            "fw:port",
            "https://[2001:db8::1",
            "https://[2001:db8::1]9443",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
        assert!(parse_url("http://fw").unwrap_err().contains("unencrypted"));
        assert_eq!(authority("2001:db8::1", 8443), "[2001:db8::1]:8443");
        assert_eq!(authority("fw", 8443), "fw:8443");
    }

    #[test]
    fn a_response_ends_where_its_length_says() {
        let mut with = &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA"[..];
        assert!(read_response(&mut with).unwrap().ends_with(b"\r\n\r\nok"));
        let mut without = &b"HTTP/1.1 200 OK\r\n\r\nall of it"[..];
        assert!(read_response(&mut without).unwrap().ends_with(b"all of it"));
        let mut empty = &b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"[..];
        assert!(read_response(&mut empty).unwrap().ends_with(b"\r\n\r\n"));
    }
}

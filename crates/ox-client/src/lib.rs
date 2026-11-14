//! A small HTTP/1.1 client for the daemon's Unix socket.
//!
//! One request per connection, with `Connection: close`, so the response is
//! everything the daemon writes before it closes the socket.

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

use serde_json::Value;

pub struct Client {
    socket: PathBuf,
}

impl Client {
    pub fn new(socket: &Path) -> Client {
        Client {
            socket: socket.to_path_buf(),
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
        let mut stream = UnixStream::connect(&self.socket).map_err(|e| {
            format!(
                "cannot reach oxd at {}: {e}. Is the daemon running? Set --socket or OX_SOCKET if it listens elsewhere",
                self.socket.display()
            )
        })?;
        let (content_type, payload) = body.unwrap_or(("text/plain", ""));
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: oxd\r\nConnection: close\r\n\
             Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{payload}",
            payload.len()
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| e.to_string())?;
        let mut raw = vec![];
        stream.read_to_end(&mut raw).map_err(|e| e.to_string())?;
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

//! WireGuard tunnels.
//!
//! A tunnel is an interface in a zone, so the same policies decide what
//! crosses it. The config holds each peer's public key and never a private
//! one: the box makes its own private key and keeps it out of the config,
//! the commits and the audit log.

use std::net::SocketAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{IfaceAddr, Net};

/// One WireGuard interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireGuard {
    /// The zone the tunnel is in. Policies from and to it decide what the
    /// peers may reach.
    pub zone: String,
    /// Addresses of the box inside the tunnel, each with its prefix length.
    #[serde(default)]
    pub addresses: Vec<IfaceAddr>,
    /// The UDP port peers connect to. Leave it out on a box that only
    /// connects out to its peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(default, rename = "peer", skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<WgPeer>,
}

/// A device or site on the other end of a tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WgPeer {
    pub name: String,
    /// The peer's public key, as WireGuard prints it (44 characters).
    pub public_key: String,
    /// The addresses this peer may send from, and that are routed to it:
    /// one address for a laptop, whole networks for another site.
    pub allowed: Vec<Net>,
    /// Where to reach the peer, as address and port. Leave it out for a
    /// peer that connects to this box.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub endpoint: Option<SocketAddr>,
    /// Send a packet this often, in seconds, to keep a path through
    /// someone else's NAT open. 25 is the usual value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<u16>,
}

/// Decodes a WireGuard key: standard base64 of exactly 32 bytes.
pub fn decode_key(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    };
    let mut out = [0u8; 33];
    for (i, quad) in bytes.chunks(4).enumerate() {
        let last = i == 10;
        let mut n = 0u32;
        for (j, c) in quad.iter().enumerate() {
            n = n << 6 | if last && j == 3 { 0 } else { value(*c)? };
        }
        out[i * 3..i * 3 + 3].copy_from_slice(&n.to_be_bytes()[1..]);
    }
    // The last group holds two bytes; the bits past them must be zero, so
    // that every key has one spelling.
    if out[32] != 0 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    Some(key)
}

/// Encodes 32 bytes the way WireGuard prints keys.
pub fn encode_key(key: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut padded = [0u8; 33];
    padded[..32].copy_from_slice(key);
    let mut out = String::with_capacity(44);
    for chunk in padded.chunks(3) {
        let n = u32::from(chunk[0]) << 16 | u32::from(chunk[1]) << 8 | u32::from(chunk[2]);
        for shift in [18, 12, 6, 0] {
            out.push(ALPHABET[(n >> shift & 63) as usize] as char);
        }
    }
    out.truncate(43);
    out.push('=');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_and_bad_ones_are_refused() {
        // A key from the WireGuard documentation.
        let text = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
        let key = decode_key(text).unwrap();
        assert_eq!(key[0], 0xc5);
        assert_eq!(encode_key(&key), text);
        let mut all = [0u8; 32];
        for (i, b) in all.iter_mut().enumerate() {
            *b = (i * 37 + 11) as u8;
        }
        assert_eq!(decode_key(&encode_key(&all)), Some(all));

        for bad in [
            "",
            "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg", // no padding
            "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dh=", // stray low bits
            "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8D\n=", // not base64
            "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg==", // too long
        ] {
            assert_eq!(decode_key(bad), None, "{bad:?}");
        }
    }
}

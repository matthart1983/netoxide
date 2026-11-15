//! WireGuard tunnels: the kernel's own implementation, set up over netlink.
//!
//! No `wg` program is run. The interface is created over rtnetlink and
//! configured over the kernel's WireGuard generic-netlink family, which is
//! the same interface `wg` uses.
//!
//! The box's private key for each tunnel lives in the state directory,
//! readable by root only. It is made on first use and never leaves: it is
//! not in the config, the commits, the audit log or any API answer.

use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use futures_util::stream::{StreamExt, TryStreamExt};
use ipnet::IpNet;
use netlink_packet_core::{NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
use netlink_packet_generic::GenlMessage;
use netlink_packet_wireguard::{
    WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute,
    WireguardCmd, WireguardMessage, WireguardPeer, WireguardPeerAttribute, WireguardPeerFlags,
};
use ox_schema::{WireGuard, decode_key, encode_key};
use rtnetlink::{LinkUnspec, LinkWireguard, RouteMessageBuilder, packet_route::route::RouteScope};
use x25519_dalek::{PublicKey, StaticSecret};

/// "File exists".
const EEXIST: i32 = -17;

fn key_path(dir: &Path, iface: &str) -> PathBuf {
    dir.join("wireguard").join(format!("{iface}.key"))
}

/// A new key pair: `(private, public)`, as WireGuard prints keys.
pub fn new_keypair() -> Result<(String, String), String> {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("cannot read random bytes for a key: {e}"))?;
    let secret = StaticSecret::from(bytes);
    let public = PublicKey::from(&secret);
    Ok((
        encode_key(&secret.to_bytes()),
        encode_key(public.as_bytes()),
    ))
}

/// The box's private key for a tunnel, made and stored on first use.
fn private_key(dir: &Path, iface: &str) -> Result<[u8; 32], String> {
    let path = key_path(dir, iface);
    if let Ok(text) = std::fs::read_to_string(&path) {
        return decode_key(text.trim())
            .ok_or_else(|| format!("{} does not hold a WireGuard key", path.display()));
    }
    let (private, _) = new_keypair()?;
    store_key(&path, &private)?;
    decode_key(&private).ok_or_else(|| "made an invalid key".to_string())
}

/// Writes a private key file, replacing one that is there.
fn store_key(path: &Path, private: &str) -> Result<(), String> {
    let parent = path.parent().expect("the key path has a directory");
    std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    // Never on disk with wider permissions, and whole or not at all.
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .and_then(|mut f| {
            f.write_all(private.as_bytes())?;
            f.sync_all()
        })
        .and_then(|()| std::fs::rename(&tmp, path))
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn is_iface(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !matches!(name, "." | "..")
}

/// Every tunnel's private key on this box, by interface, for a backup.
pub fn export_keys(dir: &Path) -> std::collections::BTreeMap<String, String> {
    let mut keys = std::collections::BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(dir.join("wireguard")) else {
        return keys;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(iface) = name.to_str().and_then(|n| n.strip_suffix(".key")) else {
            continue;
        };
        if let Ok(text) = std::fs::read_to_string(entry.path())
            && decode_key(text.trim()).is_some()
        {
            keys.insert(iface.to_string(), text.trim().to_string());
        }
    }
    keys
}

/// Puts a private key from a backup in place for a tunnel. The tunnel
/// uses it from the next commit that configures it.
pub fn import_key(dir: &Path, iface: &str, private: &str) -> Result<(), String> {
    if !is_iface(iface) {
        return Err(format!("'{iface}' is not an interface name"));
    }
    if decode_key(private.trim()).is_none() {
        return Err(format!("the key for {iface} is not a WireGuard key"));
    }
    store_key(&key_path(dir, iface), private.trim())
}

/// The box's public key for a tunnel. Makes the key pair if there is none,
/// so two sites can swap public keys before either commits a tunnel.
pub fn public_key(dir: &Path, iface: &str) -> Result<String, String> {
    let secret = StaticSecret::from(private_key(dir, iface)?);
    Ok(encode_key(PublicKey::from(&secret).as_bytes()))
}

fn allowed_ip(net: &IpNet) -> WireguardAllowedIp {
    WireguardAllowedIp(vec![
        WireguardAllowedIpAttr::Family(if net.addr().is_ipv4() {
            WireguardAddressFamily::Ipv4
        } else {
            WireguardAddressFamily::Ipv6
        }),
        WireguardAllowedIpAttr::IpAddr(net.network()),
        WireguardAllowedIpAttr::Cidr(net.prefix_len()),
    ])
}

/// Sends one WireGuard message and collects what comes back.
async fn talk(message: WireguardMessage, flags: u16) -> Result<Vec<WireguardMessage>, String> {
    let (connection, mut handle, _) =
        genetlink::new_connection().map_err(|e| format!("cannot open a netlink socket: {e}"))?;
    let task = tokio::spawn(connection);
    let mut request = NetlinkMessage::from(GenlMessage::from_payload(message));
    request.header.flags = NLM_F_REQUEST | flags;
    let result = async {
        let mut answers = handle
            .request(request)
            .await
            .map_err(|e| format!("the kernel's WireGuard is not available: {e}"))?;
        let mut out = vec![];
        while let Some(answer) = answers.next().await {
            match answer.map_err(|e| e.to_string())?.payload {
                NetlinkPayload::InnerMessage(m) => out.push(m.payload),
                NetlinkPayload::Error(e) if e.code.is_some() => {
                    return Err(e.to_io().to_string());
                }
                _ => {}
            }
        }
        Ok(out)
    }
    .await;
    task.abort();
    result
}

/// Creates each tunnel's interface if it is not there and gives it its key,
/// port and peers. Peers the config no longer has are removed. A peer that
/// stays is updated in place and keeps its session, so a commit that does
/// not touch a tunnel does not interrupt it. Returns the interfaces that
/// were created.
pub async fn configure(
    wanted: &BTreeMap<String, WireGuard>,
    dir: &Path,
) -> Result<Vec<String>, String> {
    let mut created = vec![];
    if wanted.is_empty() {
        return Ok(created);
    }
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|e| format!("cannot open a netlink socket: {e}"))?;
    let task = tokio::spawn(connection);
    let mut result = Ok(());
    for (name, wg) in wanted {
        match handle
            .link()
            .add(LinkWireguard::new(name).build())
            .execute()
            .await
        {
            Ok(()) => created.push(name.clone()),
            Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == EEXIST => {}
            Err(e) => {
                result = Err(format!(
                    "cannot create the WireGuard interface {name}: {e}. Is the kernel's wireguard module available?"
                ));
                break;
            }
        }
        let wanted_keys: Vec<&str> = wg.peers.iter().map(|p| p.public_key.as_str()).collect();
        let gone = peers(name)
            .await
            .into_iter()
            .filter(|p| !wanted_keys.contains(&p.public_key.as_str()))
            .filter_map(|p| {
                Some(WireguardPeer(vec![
                    WireguardPeerAttribute::PublicKey(decode_key(&p.public_key)?),
                    WireguardPeerAttribute::Flags(WireguardPeerFlags::RemoveMe),
                ]))
            });
        let peers = wg
            .peers
            .iter()
            .filter_map(|p| {
                let mut attrs = vec![
                    WireguardPeerAttribute::PublicKey(decode_key(&p.public_key)?),
                    WireguardPeerAttribute::Flags(WireguardPeerFlags::ReplaceAllowedIps),
                    WireguardPeerAttribute::PersistentKeepalive(p.keepalive.unwrap_or(0)),
                    WireguardPeerAttribute::AllowedIps(
                        p.allowed.iter().map(|n| allowed_ip(&n.0)).collect(),
                    ),
                ];
                if let Some(endpoint) = p.endpoint {
                    attrs.push(WireguardPeerAttribute::Endpoint(endpoint));
                }
                Some(WireguardPeer(attrs))
            })
            .chain(gone)
            .collect();
        let key = match private_key(dir, name) {
            Ok(key) => key,
            Err(e) => {
                result = Err(e);
                break;
            }
        };
        let set = WireguardMessage {
            cmd: WireguardCmd::SetDevice,
            attributes: vec![
                WireguardAttribute::IfName(name.clone()),
                WireguardAttribute::PrivateKey(key),
                WireguardAttribute::Peers(peers),
            ],
        };
        let mut set = set;
        // Without a port in the config the kernel keeps the one it chose.
        // Asking for "any port" again would pick a new one on every commit.
        if let Some(port) = wg.listen_port {
            set.attributes.push(WireguardAttribute::ListenPort(port));
        }
        if let Err(e) = talk(set, NLM_F_ACK).await {
            result = Err(format!("cannot configure the tunnel {name}: {e}"));
            break;
        }
    }
    task.abort();
    result.map(|()| created)
}

/// The routes a set of tunnels needs: each peer's allowed networks, except
/// those the tunnel's own addresses already cover.
pub fn routes(wanted: &BTreeMap<String, WireGuard>) -> Vec<(String, IpNet)> {
    let mut out = vec![];
    for (name, wg) in wanted {
        for peer in &wg.peers {
            for net in &peer.allowed {
                let net = net.0.trunc();
                let covered = wg.addresses.iter().any(|a| {
                    a.0.trunc().contains(&net.network()) && a.0.prefix_len() <= net.prefix_len()
                });
                // A default route through a tunnel would capture the
                // tunnel's own packets. That needs policy routing, which
                // is not built.
                if !covered && net.prefix_len() > 0 && !out.contains(&(name.clone(), net)) {
                    out.push((name.clone(), net));
                }
            }
        }
    }
    out
}

fn route_to(index: u32, net: &IpNet) -> rtnetlink::packet_route::route::RouteMessage {
    match net {
        IpNet::V4(n) => RouteMessageBuilder::<Ipv4Addr>::new()
            .destination_prefix(n.network(), n.prefix_len())
            .output_interface(index)
            .scope(RouteScope::Link)
            .build(),
        IpNet::V6(n) => RouteMessageBuilder::<Ipv6Addr>::new()
            .destination_prefix(n.network(), n.prefix_len())
            .output_interface(index)
            .build(),
    }
}

async fn index_of(handle: &rtnetlink::Handle, name: &str) -> Option<u32> {
    let link = handle
        .link()
        .get()
        .match_name(name.to_string())
        .execute()
        .try_next()
        .await;
    link.ok().flatten().map(|l| l.header.index)
}

/// Adds or removes routes through tunnel interfaces. The interfaces must
/// be up for an add. A route that is already gone counts as removed.
pub async fn set_routes(add: &[(String, IpNet)], remove: &[(String, IpNet)]) -> Result<(), String> {
    if add.is_empty() && remove.is_empty() {
        return Ok(());
    }
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|e| format!("cannot open a netlink socket: {e}"))?;
    let task = tokio::spawn(connection);
    let mut result = Ok(());
    for (name, net) in remove {
        if let Some(index) = index_of(&handle, name).await {
            let _ = handle.route().del(route_to(index, net)).execute().await;
        }
    }
    for (name, net) in add {
        let Some(index) = index_of(&handle, name).await else {
            continue;
        };
        // The link has to be up before a route can leave by it.
        let up = handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await;
        let added = match up {
            Ok(()) => {
                handle
                    .route()
                    .add(route_to(index, net))
                    .replace()
                    .execute()
                    .await
            }
            Err(e) => Err(e),
        };
        if let Err(e) = added {
            result = Err(format!("cannot route {net} through {name}: {e}"));
            break;
        }
    }
    task.abort();
    result
}

/// Deletes tunnel interfaces. Their addresses and routes go with them.
pub async fn delete(names: &[String]) {
    if names.is_empty() {
        return;
    }
    let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
        return;
    };
    let task = tokio::spawn(connection);
    for name in names {
        if let Some(index) = index_of(&handle, name).await {
            let _ = handle.link().del(index).execute().await;
        }
    }
    task.abort();
}

/// What the kernel reports for one peer.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct PeerState {
    pub public_key: String,
    /// Where the peer was last heard from.
    pub endpoint: Option<String>,
    /// Unix time of the last completed handshake. `None` when there has
    /// been none.
    pub last_handshake: Option<i64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// The peers of one tunnel as the kernel holds them. Empty when the
/// interface does not exist.
pub async fn peers(iface: &str) -> Vec<PeerState> {
    let get = WireguardMessage {
        cmd: WireguardCmd::GetDevice,
        attributes: vec![WireguardAttribute::IfName(iface.to_string())],
    };
    let mut out = vec![];
    for message in talk(get, NLM_F_DUMP).await.unwrap_or_default() {
        for attr in message.attributes {
            let WireguardAttribute::Peers(list) = attr else {
                continue;
            };
            for WireguardPeer(attrs) in list {
                let mut peer = PeerState::default();
                for a in attrs {
                    match a {
                        WireguardPeerAttribute::PublicKey(k) => peer.public_key = encode_key(&k),
                        WireguardPeerAttribute::Endpoint(e) => peer.endpoint = Some(e.to_string()),
                        WireguardPeerAttribute::LastHandshake(t) => {
                            peer.last_handshake = Some(t.seconds).filter(|s| *s > 0);
                        }
                        WireguardPeerAttribute::RxBytes(n) => peer.rx_bytes = n,
                        WireguardPeerAttribute::TxBytes(n) => peer.tx_bytes = n,
                        _ => {}
                    }
                }
                // A long peer list arrives in parts; later parts repeat
                // the key of the peer they continue.
                if !out
                    .iter()
                    .any(|p: &PeerState| p.public_key == peer.public_key)
                {
                    out.push(peer);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_pair_is_two_valid_keys_and_differs_each_time() {
        let (private, public) = new_keypair().unwrap();
        assert!(decode_key(&private).is_some() && decode_key(&public).is_some());
        assert_ne!(private, public);
        assert_ne!(new_keypair().unwrap().0, private);
        // The public key is the one the private key gives, by RFC 7748's
        // test vector for the base point.
        let secret: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let public = PublicKey::from(&StaticSecret::from(secret));
        assert_eq!(
            public.as_bytes()[..4],
            [0x85, 0x20, 0xf0, 0x09],
            "RFC 7748 section 6.1"
        );
    }

    #[test]
    fn the_private_key_is_made_once_and_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("oxd-wg-key-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = public_key(&dir, "wg0").unwrap();
        assert_eq!(
            public_key(&dir, "wg0").unwrap(),
            first,
            "the same key every time"
        );
        assert_ne!(
            public_key(&dir, "wg1").unwrap(),
            first,
            "one key per tunnel"
        );
        let mode = std::fs::metadata(key_path(&dir, "wg0"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn routes_cover_what_the_tunnel_address_does_not() {
        let wg: WireGuard = toml::from_str(
            r#"
            zone = "vpn"
            addresses = ["10.90.0.1/24"]
            [[peer]]
            name = "laptop"
            public_key = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
            allowed = ["10.90.0.2/32"]
            [[peer]]
            name = "branch"
            public_key = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
            allowed = ["10.90.0.3/32", "192.168.77.0/24", "fd00:77::/64"]
            "#,
        )
        .unwrap();
        let wanted = BTreeMap::from([("wg0".to_string(), wg)]);
        let nets: Vec<String> = routes(&wanted).iter().map(|(_, n)| n.to_string()).collect();
        assert_eq!(nets, ["192.168.77.0/24", "fd00:77::/64"]);
    }
}

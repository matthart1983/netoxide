//! Brings the machine's interfaces in line with the config, over netlink.
//!
//! This only ever adds. It puts the config's addresses on their interfaces,
//! brings those links up, and turns on packet forwarding. It never removes
//! an address or turns forwarding off, because something else on the machine
//! may rely on them, and a firewall that takes the address it is managed
//! through off its interface has locked its operator out.

use std::collections::BTreeMap;

use futures_util::stream::TryStreamExt;
use ipnet::IpNet;
use rtnetlink::LinkUnspec;

/// "File exists": the address is already on the interface.
const EEXIST: i32 = -17;

/// Adds each address to its interface and brings the link up. Returns the
/// interfaces the config names that this machine does not have.
pub async fn ensure_addresses(wanted: &[(String, IpNet)]) -> Result<Vec<String>, String> {
    let mut by_iface: BTreeMap<&str, Vec<&IpNet>> = BTreeMap::new();
    for (name, addr) in wanted {
        by_iface.entry(name).or_default().push(addr);
    }
    if by_iface.is_empty() {
        return Ok(vec![]);
    }
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|e| format!("cannot open a netlink socket: {e}"))?;
    let task = tokio::spawn(connection);

    let mut missing = vec![];
    for (name, addrs) in by_iface {
        let link = handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute()
            .try_next()
            .await;
        let index = match link {
            Ok(Some(link)) => link.header.index,
            // The kernel answers "no such device" as an error, not an empty list.
            Ok(None) | Err(rtnetlink::Error::NetlinkError(_)) => {
                missing.push(name.to_string());
                continue;
            }
            Err(e) => return Err(format!("cannot look up interface {name}: {e}")),
        };
        for addr in addrs {
            match handle
                .address()
                .add(index, addr.addr(), addr.prefix_len())
                .execute()
                .await
            {
                Ok(()) => {}
                Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == EEXIST => {}
                Err(e) => return Err(format!("cannot put {addr} on {name}: {e}")),
            }
        }
        handle
            .link()
            .set(LinkUnspec::new_with_index(index).up().build())
            .execute()
            .await
            .map_err(|e| format!("cannot bring {name} up: {e}"))?;
    }
    task.abort();
    Ok(missing)
}

/// Lets the kernel route packets between interfaces, for IPv4 and IPv6.
pub fn enable_forwarding(uplinks: &[String]) -> Result<(), String> {
    for path in [
        "/proc/sys/net/ipv4/ip_forward",
        "/proc/sys/net/ipv6/conf/all/forwarding",
    ] {
        // A machine without IPv6 has no such file, which is fine.
        if std::path::Path::new(path).exists() {
            std::fs::write(path, "1")
                .map_err(|e| format!("cannot turn on forwarding ({path}): {e}"))?;
        }
    }
    // With forwarding on, Linux stops listening to the provider's router
    // advertisements unless told otherwise, and the box would lose its own
    // IPv6 address and route on the internet side.
    for name in uplinks {
        let path = format!("/proc/sys/net/ipv6/conf/{name}/accept_ra");
        if std::path::Path::new(&path).exists() {
            let _ = std::fs::write(&path, "2");
        }
    }
    Ok(())
}

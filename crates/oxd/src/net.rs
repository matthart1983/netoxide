//! Brings the machine's interfaces in line with the config, over netlink.
//!
//! It puts the config's addresses on their interfaces, brings those links
//! up, and turns on packet forwarding. It reports which addresses it added,
//! so the daemon can take exactly those off again when a later config drops
//! them or a commit fails half way. An address that was already there when
//! Netoxide first saw the interface is never removed, and forwarding is
//! never turned off, because something else on the machine may rely on them.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use futures_util::stream::TryStreamExt;
use ipnet::IpNet;
use rtnetlink::{LinkUnspec, RouteMessageBuilder};

/// "File exists": the address is already on the interface.
const EEXIST: i32 = -17;

/// "Cannot assign requested address": the address is not on the interface.
const EADDRNOTAVAIL: i32 = -99;

/// What `ensure_addresses` did.
#[derive(Default)]
pub struct Ensured {
    /// Interfaces the config names that this machine does not have.
    pub missing: Vec<String>,
    /// Addresses that were not there before and are now.
    pub added: Vec<(String, IpNet)>,
}

/// Adds each address to its interface and brings the link up.
pub async fn ensure_addresses(wanted: &[(String, IpNet)]) -> Result<Ensured, String> {
    let mut by_iface: BTreeMap<&str, Vec<&IpNet>> = BTreeMap::new();
    for (name, addr) in wanted {
        by_iface.entry(name).or_default().push(addr);
    }
    let mut done = Ensured::default();
    if by_iface.is_empty() {
        return Ok(done);
    }
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|e| format!("cannot open a netlink socket: {e}"))?;
    let task = tokio::spawn(connection);

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
                done.missing.push(name.to_string());
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
                Ok(()) => done.added.push((name.to_string(), *addr)),
                Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == EEXIST => {}
                Err(e) => {
                    task.abort();
                    return Err(format!("cannot put {addr} on {name}: {e}"));
                }
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
    Ok(done)
}

/// Creates the VLAN interfaces that are not there yet and brings their
/// ports up. Returns the ones it created. An interface that already has
/// the name is left as it is: something else made it, so it is not ours to
/// change or to remove later.
pub async fn ensure_vlans(wanted: &[(String, String, u16)]) -> Result<Vec<String>, String> {
    let mut created = vec![];
    if wanted.is_empty() {
        return Ok(created);
    }
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|e| format!("cannot open a netlink socket: {e}"))?;
    let task = tokio::spawn(connection);
    let mut result = Ok(());
    for (name, parent, id) in wanted {
        if index_of(&handle, name).await.is_some() {
            continue;
        }
        let Some(port) = index_of(&handle, parent).await else {
            result = Err(format!(
                "{name} is VLAN {id} on {parent}, and this machine has no interface called {parent}"
            ));
            break;
        };
        if let Err(e) = handle
            .link()
            .add(rtnetlink::LinkVlan::new(name, port, *id).build())
            .execute()
            .await
        {
            result = Err(format!(
                "cannot create {name} as VLAN {id} on {parent}: {e}"
            ));
            break;
        }
        created.push(name.clone());
        // Tagged traffic only flows while the port itself is up.
        if let Err(e) = handle
            .link()
            .set(LinkUnspec::new_with_index(port).up().build())
            .execute()
            .await
        {
            result = Err(format!("cannot bring {parent} up for {name}: {e}"));
            break;
        }
    }
    task.abort();
    // What was created before a failure is still reported through the
    // error path's caller, which removes it.
    match result {
        Ok(()) => Ok(created),
        Err(e) => {
            delete_links(&created).await;
            Err(e)
        }
    }
}

/// Deletes interfaces by name. One that is already gone counts as deleted.
pub async fn delete_links(names: &[String]) {
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

/// Takes addresses off their interfaces. One that is already gone, or whose
/// interface is gone, counts as removed. Returns what could not be removed.
pub async fn remove_addresses(unwanted: &[(String, IpNet)]) -> Vec<String> {
    let mut failed = vec![];
    if unwanted.is_empty() {
        return failed;
    }
    let (connection, handle, _) = match rtnetlink::new_connection() {
        Ok(c) => c,
        Err(e) => return vec![format!("cannot open a netlink socket: {e}")],
    };
    let task = tokio::spawn(connection);
    for (name, addr) in unwanted {
        let link = handle
            .link()
            .get()
            .match_name(name.clone())
            .execute()
            .try_next()
            .await;
        let Ok(Some(link)) = link else {
            continue;
        };
        let mut found = handle
            .address()
            .get()
            .set_link_index_filter(link.header.index)
            .set_address_filter(addr.addr())
            .set_prefix_length_filter(addr.prefix_len())
            .execute();
        while let Ok(Some(message)) = found.try_next().await {
            match handle.address().del(message).execute().await {
                Ok(()) => {}
                Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == EADDRNOTAVAIL => {}
                Err(e) => failed.push(format!("cannot take {addr} off {name}: {e}")),
            }
        }
    }
    task.abort();
    failed
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

fn default_route(index: u32, gateway: IpAddr) -> rtnetlink::packet_route::route::RouteMessage {
    match gateway {
        IpAddr::V4(g) => RouteMessageBuilder::<Ipv4Addr>::new()
            .output_interface(index)
            .gateway(g)
            .build(),
        IpAddr::V6(g) => RouteMessageBuilder::<Ipv6Addr>::new()
            .output_interface(index)
            .gateway(g)
            .build(),
    }
}

/// Points the default route at each router, replacing one that is there.
/// An interface this machine does not have is skipped: `ensure_addresses`
/// has already reported it.
pub async fn set_default_routes(wanted: &[(String, IpAddr)]) -> Result<(), String> {
    if wanted.is_empty() {
        return Ok(());
    }
    let (connection, handle, _) =
        rtnetlink::new_connection().map_err(|e| format!("cannot open a netlink socket: {e}"))?;
    let task = tokio::spawn(connection);
    let mut result = Ok(());
    for (name, gateway) in wanted {
        let Some(index) = index_of(&handle, name).await else {
            continue;
        };
        if let Err(e) = handle
            .route()
            .add(default_route(index, *gateway))
            .replace()
            .execute()
            .await
        {
            result = Err(format!(
                "cannot set the default route through {gateway} on {name}: {e}"
            ));
            break;
        }
    }
    task.abort();
    result
}

/// Removes default routes Netoxide set. One that is already gone counts as removed.
pub async fn remove_default_routes(unwanted: &[(String, IpAddr)]) {
    if unwanted.is_empty() {
        return;
    }
    let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
        return;
    };
    let task = tokio::spawn(connection);
    for (name, gateway) in unwanted {
        if let Some(index) = index_of(&handle, name).await {
            let _ = handle
                .route()
                .del(default_route(index, *gateway))
                .execute()
                .await;
        }
    }
    task.abort();
}

//! Finds the network interfaces of this machine, their addresses, and which
//! one carries the default route.

use std::{collections::BTreeMap, io, net::IpAddr};

use ipnet::IpNet;
use nix::{ifaddrs::getifaddrs, net::if_::InterfaceFlags};

/// One interface as found on the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    pub name: String,
    /// True when the link is up and has carrier.
    pub up: bool,
    /// Addresses with prefix lengths. Link-local IPv6 addresses are left out.
    pub addrs: Vec<IpNet>,
    /// True when a default route leaves by this interface.
    pub default_route: bool,
    /// The IPv4 router that default route goes through, if it has one.
    pub gateway: Option<std::net::Ipv4Addr>,
}

/// The IPv4 default route's router for each interface, from /proc/net/route.
fn default_gateways(v4: &str) -> BTreeMap<String, std::net::Ipv4Addr> {
    let mut out = BTreeMap::new();
    for line in v4.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() > 3
            && f[1] == "00000000"
            && let Ok(raw) = u32::from_str_radix(f[2], 16)
            && raw != 0
        {
            // The file holds the address in network byte order, printed as
            // a host-order number.
            out.entry(f[0].to_string())
                .or_insert_with(|| std::net::Ipv4Addr::from(raw.to_ne_bytes()));
        }
    }
    out
}

/// Interfaces with a default route, from the kernel's route tables.
fn default_routes(v4: &str, v6: &str) -> Vec<String> {
    let mut out = vec![];
    // /proc/net/route: Iface Destination Gateway Flags ... with hex fields.
    for line in v4.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() > 3
            && f[1] == "00000000"
            && u32::from_str_radix(f[3], 16).is_ok_and(|x| x & 2 != 0)
        {
            out.push(f[0].to_string());
        }
    }
    // /proc/net/ipv6_route: destination, prefix length, ..., interface.
    for line in v6.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() == 10 && f[0].chars().all(|c| c == '0') && f[1] == "00" && f[9] != "lo" {
            out.push(f[9].to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

fn prefix_len(mask: IpAddr) -> u8 {
    match mask {
        IpAddr::V4(m) => u32::from(m).count_ones() as u8,
        IpAddr::V6(m) => u128::from(m).count_ones() as u8,
    }
}

/// Lists the machine's interfaces, without loopback, in name order.
pub fn detect() -> io::Result<Vec<Detected>> {
    let routes = default_routes(
        &std::fs::read_to_string("/proc/net/route").unwrap_or_default(),
        &std::fs::read_to_string("/proc/net/ipv6_route").unwrap_or_default(),
    );
    let gateways =
        default_gateways(&std::fs::read_to_string("/proc/net/route").unwrap_or_default());
    let mut found: BTreeMap<String, Detected> = BTreeMap::new();
    for ifa in getifaddrs().map_err(io::Error::from)? {
        if ifa.flags.contains(InterfaceFlags::IFF_LOOPBACK) {
            continue;
        }
        let entry = found
            .entry(ifa.interface_name.clone())
            .or_insert_with(|| Detected {
                name: ifa.interface_name.clone(),
                up: false,
                addrs: vec![],
                default_route: routes.contains(&ifa.interface_name),
                gateway: gateways.get(&ifa.interface_name).copied(),
            });
        entry.up |= ifa
            .flags
            .contains(InterfaceFlags::IFF_UP | InterfaceFlags::IFF_RUNNING);
        let ip = |s: &nix::sys::socket::SockaddrStorage| -> Option<IpAddr> {
            s.as_sockaddr_in()
                .map(|a| IpAddr::V4(a.ip()))
                .or_else(|| s.as_sockaddr_in6().map(|a| IpAddr::V6(a.ip())))
        };
        let (Some(addr), Some(mask)) = (
            ifa.address.as_ref().and_then(ip),
            ifa.netmask.as_ref().and_then(ip),
        ) else {
            continue;
        };
        // fe80::/10 exists on every interface and says nothing about the network.
        let link_local = matches!(addr, IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80);
        if let (false, Ok(net)) = (link_local, IpNet::new(addr, prefix_len(mask)))
            && !entry.addrs.contains(&net)
        {
            entry.addrs.push(net);
        }
    }
    Ok(found.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_routes_are_read_for_both_families() {
        let v4 = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n\
                  wan0\t00000000\t0100A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                  wan0\t0000A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n\
                  lan0\t00000A0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        let v6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 wan6\n\
                  20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 lan0\n\
                  00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n";
        assert_eq!(default_routes(v4, v6), ["wan0", "wan6"]);
        assert!(default_routes("", "").is_empty());
        assert_eq!(
            default_gateways(v4).get("wan0"),
            Some(&"192.168.0.1".parse().unwrap())
        );
        assert!(!default_gateways(v4).contains_key("lan0"));
    }

    #[test]
    fn masks_become_prefix_lengths() {
        assert_eq!(prefix_len("255.255.255.0".parse().unwrap()), 24);
        assert_eq!(prefix_len("255.255.255.255".parse().unwrap()), 32);
        assert_eq!(prefix_len("ffff:ffff:ffff:ffff::".parse().unwrap()), 64);
    }

    #[test]
    fn this_machine_can_be_read() {
        let found = detect().unwrap();
        assert!(found.iter().all(|d| d.name != "lo"));
        assert!(
            found
                .iter()
                .flat_map(|d| &d.addrs)
                .all(|a| !a.to_string().starts_with("fe80")),
            "link-local addresses are left out"
        );
    }
}

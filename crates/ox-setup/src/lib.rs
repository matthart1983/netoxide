//! The easy path: a guided setup and plain-language actions.
//!
//! Everything here writes ordinary Netoxide config. There is no second,
//! simpler format: `starter` returns the same [`Config`] a user could write
//! by hand, and the actions edit one in place. The advanced tools read and
//! change the result like any other config.

mod detect;
mod simple;

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
};

use ipnet::IpNet;
use ox_explain::{Packet, Verdict, explain};
use ox_nft::{L4, compile};
use ox_schema::{
    Action, AddrRef, Config, DhcpPool, Dns, Forward, IfaceAddr, Interface, Nat, Net, Outbound,
    Policy, PortSpec, Proto, Rule, SCHEMA_VERSION, SELF_ZONE, ServiceRef, Translate, WgPeer,
    WireGuard, Zone, is_name,
};

pub use detect::{Detected, detect};
#[cfg(test)]
mod network_tests {
    use super::*;

    const HOME: &str = include_str!("../../../examples/home.toml");

    fn guest() -> NetworkRequest {
        NetworkRequest {
            name: "Guest Wi-Fi".into(),
            port: "eth1".into(),
            vlan: 20,
            address: None,
            internet: true,
        }
    }

    #[test]
    fn a_guest_network_is_one_step_and_kept_apart() {
        let old = Config::from_toml(HOME).unwrap();
        let mut config = old.clone();
        let done = add_network(&mut config, &guest()).unwrap();
        let all = done.join("\n");
        assert!(
            all.contains("VLAN 20 on eth1, where the box is 192.168.20.1/24"),
            "{all}"
        );
        assert!(all.contains("192.168.20.100 to 192.168.20.199"), "{all}");
        assert!(
            all.contains("answers DNS") && all.contains("Guest Wi-Fi can reach Internet"),
            "{all}"
        );
        assert!(all.contains("cannot reach your other networks"), "{all}");

        // It is ordinary config, valid after a trip through text.
        let config = Config::from_toml(&config.to_toml()).unwrap();
        let iface = &config.interfaces["eth1.20"];
        assert_eq!(iface.zone, "guest-wi-fi");
        assert_eq!(
            iface.vlan.as_ref().map(|v| (v.parent.as_str(), v.id)),
            Some(("eth1", 20))
        );

        // In the grid it reaches the internet and nothing else, and nothing reaches it.
        let g = grid(&config);
        let at = |from: &str, to: &str| {
            let i = |z: &str| g.networks.iter().position(|n| n.zone == z).unwrap();
            g.cells[i(from)][i(to)].clone()
        };
        assert_eq!(at("guest-wi-fi", "wan"), Cell::Allowed);
        assert_eq!(at("guest-wi-fi", "lan"), Cell::Blocked);
        assert_eq!(at("lan", "guest-wi-fi"), Cell::Blocked);
        assert_eq!(at("wan", "guest-wi-fi"), Cell::Blocked);
        let lines = headline(&old, &config);
        assert!(
            lines.contains(&"A new network: Guest Wi-Fi".to_string()),
            "{lines:?}"
        );
        assert!(
            lines.contains(&"Guest Wi-Fi can reach Internet".to_string()),
            "{lines:?}"
        );

        // A guest may use the box for DNS and an address, and not manage it.
        let ruleset = compile(&config).unwrap();
        let verdict = |dst: &str, l4: L4, dport: u16| {
            explain(
                &ruleset,
                &Packet {
                    src: "192.168.20.50".parse().unwrap(),
                    dst: dst.parse().unwrap(),
                    l4,
                    dport: Some(dport),
                    iif: "eth1.20".into(),
                    box_addrs: vec![],
                },
            )
            .unwrap()
            .verdict
        };
        assert_eq!(verdict("192.168.20.1", L4::Udp, 53), Verdict::Accept);
        assert_eq!(verdict("192.168.20.1", L4::Tcp, 22), Verdict::Drop);
        assert_eq!(verdict("192.168.10.5", L4::Tcp, 445), Verdict::Drop);
        assert_eq!(verdict("1.1.1.1", L4::Tcp, 443), Verdict::Accept);
    }

    #[test]
    fn a_network_without_internet_and_the_ways_it_is_refused() {
        let mut config = Config::from_toml(HOME).unwrap();
        let cameras = NetworkRequest {
            name: "Cameras".into(),
            vlan: 30,
            address: Some("10.30.0.1/24".parse().unwrap()),
            internet: false,
            ..guest()
        };
        let done = add_network(&mut config, &cameras).unwrap().join("\n");
        assert!(done.contains("Cameras cannot reach the internet"), "{done}");
        assert!(!config.to_toml().contains("n-cameras-out"));

        let refused = |req: NetworkRequest, want: &str| {
            let mut c = config.clone();
            let e = add_network(&mut c, &req).unwrap_err();
            assert!(e.contains(want), "wanted '{want}' in: {e}");
            assert_eq!(c, config, "a refused request changes nothing");
        };
        refused(cameras.clone(), "already a network called 'cameras'");
        refused(
            NetworkRequest {
                name: "More".into(),
                ..cameras.clone()
            },
            "eth1.30 already exists",
        );
        refused(
            NetworkRequest {
                port: "eth0".into(),
                ..guest()
            },
            "faces the internet",
        );
        refused(
            NetworkRequest {
                port: "eth9".into(),
                ..guest()
            },
            "the inside ports are eth1",
        );
        refused(
            NetworkRequest {
                port: "eth1.30".into(),
                ..guest()
            },
            "itself a VLAN",
        );
        refused(
            NetworkRequest {
                name: "  ".into(),
                ..guest()
            },
            "give the network a name",
        );
        refused(
            NetworkRequest {
                address: Some("192.168.10.129/25".parse().unwrap()),
                ..guest()
            },
            "overlaps",
        );
        refused(
            NetworkRequest {
                vlan: 4095,
                ..guest()
            },
            "1 to 4094",
        );
        // A name that starts with a digit still makes a valid zone.
        let mut c = config.clone();
        add_network(
            &mut c,
            &NetworkRequest {
                name: "5G lab".into(),
                vlan: 40,
                ..guest()
            },
        )
        .unwrap();
        assert!(c.zones.contains_key("net-5g-lab"));
    }
}

pub use simple::{
    Cell, Grid, LetIn, Network, grid, headline, interface_for, plain_changes, set_access,
};

/// Lets the inside network reach the box's web interface on `port`, by
/// adding it to the starter's management rule.
pub fn allow_admin(config: &mut Config, port: u16) -> Result<(), String> {
    let spec: PortSpec = format!("tcp/{port}").parse()?;
    config.services.insert("admin".into(), vec![spec]);
    let rule = config
        .policies
        .iter_mut()
        .filter(|p| p.to == SELF_ZONE)
        .flat_map(|p| p.rules.iter_mut())
        .find(|r| r.id == "r-manage")
        .ok_or("the starter config has no management rule to add the web interface to")?;
    rule.service.push(ServiceRef::Named("admin".into()));
    rule.name = "Manage the box from inside: web interface, SSH and ping".into();
    Ok(())
}

/// One port of the box, as chosen in the guided setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub name: String,
    /// Addresses of the box on this port, with prefix lengths.
    pub addrs: Vec<IpNet>,
}

/// The answers the guided setup needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answers {
    pub hostname: String,
    /// The port that faces the internet.
    pub wan: Port,
    /// The ports that face the inside network.
    pub lans: Vec<Port>,
    /// Hand out addresses and answer DNS for the inside network.
    pub serve: Option<Serve>,
    /// The provider assigns the box's IPv4 address on the internet port
    /// (DHCP). Any IPv4 address in `wan` is then left out of the config.
    pub wan_dhcp: bool,
    /// The provider's routers, for an internet port with fixed addresses.
    pub gateway: Vec<IpAddr>,
}

/// How the box serves DNS and DHCP to the inside network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Serve {
    /// The resolvers to forward DNS queries to.
    pub upstream: Vec<IpAddr>,
    /// The domain for local names, such as `home.arpa`.
    pub domain: Option<String>,
}

impl Default for Serve {
    fn default() -> Serve {
        Serve {
            upstream: vec![
                "1.1.1.1".parse().expect("valid"),
                "9.9.9.9".parse().expect("valid"),
            ],
            domain: Some("home.arpa".into()),
        }
    }
}

/// A pool of addresses to hand out on a network, away from the box's own
/// address. `None` when the network is too small to be worth a pool.
fn pool(own: ipnet::Ipv4Net) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let size = 1u32.checked_shl(32 - u32::from(own.prefix_len()))?;
    if size < 16 {
        return None;
    }
    let net = u32::from(own.network());
    let me = u32::from(own.addr());
    // On a /24 or larger: .100 to .199. On a smaller one: its upper half.
    let (mut first, mut last) = if size >= 256 {
        (net + 100, net + 199)
    } else {
        (net + size / 2, net + size - 2)
    };
    if (first..=last).contains(&me) {
        if me - first < last - me {
            first = me + 1;
        } else {
            last = me - 1;
        }
    }
    Some((Ipv4Addr::from(first), Ipv4Addr::from(last)))
}

fn rule(id: &str, name: &str, source: Vec<AddrRef>, service: &[&str], reason: &str) -> Rule {
    Rule {
        id: id.into(),
        name: name.into(),
        action: Action::Accept,
        source,
        destination: vec![AddrRef::Any],
        service: service
            .iter()
            .map(|s| s.parse().expect("built-in service"))
            .collect(),
        log: false,
        enabled: true,
        reason: Some(reason.into()),
    }
}

/// Builds a complete starter config for a home or small-office router:
/// the inside network may go out, it is hidden behind the box's address,
/// the box can be managed from inside only, and everything inbound from the
/// internet is dropped.
pub fn starter(a: &Answers) -> Result<Config, String> {
    if a.lans.is_empty() {
        return Err("choose at least one port for the inside network".into());
    }
    if a.lans.iter().any(|l| l.name == a.wan.name) {
        return Err(format!(
            "{} cannot face both the internet and the inside network",
            a.wan.name
        ));
    }
    for lan in &a.lans {
        if lan.addrs.is_empty() {
            return Err(format!(
                "{} has no address; give the box an address on the inside network, such as 192.168.10.1/24",
                lan.name
            ));
        }
    }
    let iface = |p: &Port, zone: &str, default_route: bool| Interface {
        zone: zone.into(),
        addresses: p.addrs.iter().map(|n| IfaceAddr(*n)).collect(),
        default_route,
        gateway: vec![],
        dhcp_client: false,
        vlan: None,
    };
    let mut wan = iface(&a.wan, "wan", true);
    if a.wan_dhcp {
        wan.addresses.retain(|n| !n.0.addr().is_ipv4());
        wan.dhcp_client = true;
    }
    wan.gateway = a
        .gateway
        .iter()
        .copied()
        .filter(|g| !(a.wan_dhcp && g.is_ipv4()))
        .collect();
    let mut config = Config {
        schema: SCHEMA_VERSION,
        hostname: a.hostname.clone(),
        ipv6_autoconfig: vec![],
        zones: [
            (
                "wan".to_string(),
                Zone {
                    description: Some("Internet".into()),
                },
            ),
            (
                "lan".to_string(),
                Zone {
                    description: Some("Inside network".into()),
                },
            ),
        ]
        .into(),
        interfaces: [(a.wan.name.clone(), wan)].into(),
        addresses: Default::default(),
        services: [
            ("ssh", vec!["tcp/22"]),
            ("ping", vec!["icmp", "icmpv6"]),
            ("dhcpv6-client", vec!["udp/546"]),
        ]
        .into_iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                v.into_iter()
                    .map(|s| s.parse().expect("built-in"))
                    .collect(),
            )
        })
        .collect(),
        policies: vec![],
        nat: Nat::default(),
        dns: None,
        dhcp: Default::default(),
        wireguard: Default::default(),
    };
    for lan in &a.lans {
        config
            .interfaces
            .insert(lan.name.clone(), iface(lan, "lan", false));
    }
    let inside: Vec<IpNet> = a
        .lans
        .iter()
        .flat_map(|l| l.addrs.iter().map(IpNet::trunc))
        .collect();
    config
        .addresses
        .insert("inside".into(), inside.iter().map(|n| Net(*n)).collect());

    config.policies = vec![
        Policy {
            from: "lan".into(),
            to: "wan".into(),
            log_default: true,
            rules: vec![rule(
                "r-inside-out",
                "Inside network to the internet",
                vec![AddrRef::Any],
                &["any"],
                "starter config: everything inside may reach the internet",
            )],
        },
        Policy {
            from: "lan".into(),
            to: SELF_ZONE.into(),
            log_default: true,
            rules: vec![rule(
                "r-manage",
                "Manage and ping the box from inside",
                vec![AddrRef::Any],
                &["ssh", "ping"],
                "starter config: SSH and ping to the box from the inside network only",
            )],
        },
        Policy {
            from: "wan".into(),
            to: SELF_ZONE.into(),
            log_default: true,
            rules: vec![rule(
                "r-dhcpv6",
                "IPv6 address assignment from the provider",
                vec![AddrRef::Net(Net("fe80::/10".parse().expect("valid")))],
                &["dhcpv6-client"],
                "starter config: DHCPv6 replies come from the provider's link-local address",
            )],
        },
    ];
    if a.wan_dhcp {
        config.services.insert(
            "dhcp-client".into(),
            vec!["udp/68".parse().expect("built-in")],
        );
        // The answer to the box's own request. It comes from whatever
        // address the provider's server has, so the source is open.
        config.policies[2].rules.push(rule(
            "r-dhcp-client",
            "IPv4 address assignment from the provider",
            vec![AddrRef::Any],
            &["dhcp-client"],
            "starter config: the provider's answer to the box asking for its address",
        ));
    }
    // Private IPv4 addresses are not routable on the internet, so hide them.
    let v4: Vec<AddrRef> = inside
        .iter()
        .filter(|n| n.addr().is_ipv4())
        .map(|n| AddrRef::Net(Net(*n)))
        .collect();
    if !v4.is_empty() {
        config.nat.outbound.push(Outbound {
            id: "n-inside-out".into(),
            name: "Hide the inside network behind the box".into(),
            from: "lan".into(),
            to: "wan".into(),
            source: v4,
            translate: Translate::Masquerade,
        });
    }
    if let Some(serve) = &a.serve {
        for (name, ports) in [("dns", vec!["udp/53", "tcp/53"]), ("dhcp", vec!["udp/67"])] {
            config.services.insert(
                name.to_string(),
                ports
                    .into_iter()
                    .map(|p| p.parse().expect("built-in"))
                    .collect(),
            );
        }
        // The services need a visible rule like everything else.
        config.policies[1].rules.push(rule(
            "r-services",
            "Use the box for DNS and for getting an address",
            vec![AddrRef::Any],
            &["dns", "dhcp"],
            "starter config: the box answers DNS and hands out addresses inside",
        ));
        config.dns = Some(Dns {
            zones: vec!["lan".into()],
            upstream: serve.upstream.clone(),
            dnssec: true,
            domain: serve.domain.clone(),
            hosts: vec![],
        });
        for lan in &a.lans {
            let own = lan.addrs.iter().find_map(|n| match n {
                IpNet::V4(n) => Some(*n),
                IpNet::V6(_) => None,
            });
            if lan
                .addrs
                .iter()
                .any(|n| n.addr().is_ipv6() && n.prefix_len() == 64)
            {
                config.ipv6_autoconfig.push(lan.name.clone());
            }
            if let Some((first, last)) = own.and_then(pool) {
                config.dhcp.insert(
                    lan.name.clone(),
                    DhcpPool {
                        first,
                        last,
                        lease: Default::default(),
                        dns: vec![],
                        statics: vec![],
                    },
                );
            }
        }
    }
    check(&config)?;
    Ok(config)
}

fn check(config: &Config) -> Result<(), String> {
    let problems = config.validate();
    if !problems.is_empty() {
        return Err(problems
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; "));
    }
    compile(config).map(|_| ()).map_err(|e| e.to_string())
}

/// A new network of its own, such as one for guests or cameras.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRequest {
    /// What to call it, such as "Guest Wi-Fi".
    pub name: String,
    /// The port that carries it, such as `eth1`.
    pub port: String,
    /// Its VLAN number on that port, 1 to 4094. The switch or access point
    /// on the port must use the same number for this network.
    pub vlan: u16,
    /// The box's address on it. Left out, a free 192.168.x.1/24 is chosen.
    pub address: Option<IpNet>,
    /// Whether devices on it may reach the internet.
    pub internet: bool,
}

/// Adds a network as a VLAN in a zone of its own, with addresses handed
/// out and DNS if the box serves them, and internet access if asked for.
/// It can reach none of the other networks until that is allowed.
pub fn add_network(config: &mut Config, req: &NetworkRequest) -> Result<Vec<String>, String> {
    // Built on a copy, so a request that is refused part way changes nothing.
    let mut next = config.clone();
    let done = build_network(&mut next, req)?;
    *config = next;
    Ok(done)
}

fn build_network(config: &mut Config, req: &NetworkRequest) -> Result<Vec<String>, String> {
    if !(1..=4094).contains(&req.vlan) {
        return Err(format!(
            "VLAN {} does not exist; the numbers are 1 to 4094",
            req.vlan
        ));
    }
    let title = req.name.trim();
    if title.is_empty() || title.len() > 40 || title.chars().any(char::is_control) {
        return Err("give the network a name of up to 40 characters, such as Guest Wi-Fi".into());
    }
    let mut zone: String = title
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    while zone.contains("--") {
        zone = zone.replace("--", "-");
    }
    let zone = zone.trim_matches('-').to_string();
    let zone = if zone.starts_with(|c: char| c.is_ascii_lowercase()) {
        zone
    } else {
        format!("net-{zone}")
    };
    if !is_name(&zone) || zone == SELF_ZONE {
        return Err(format!(
            "'{title}' cannot be made into a network name; use letters and digits"
        ));
    }
    if config.zones.contains_key(&zone) {
        return Err(format!("there is already a network called '{zone}'"));
    }
    let port = req.port.trim();
    match config.interfaces.get(port) {
        Some(i) if i.vlan.is_some() => {
            return Err(format!(
                "{port} is itself a VLAN; put the new network on the physical port"
            ));
        }
        Some(i) if i.default_route => {
            return Err(format!(
                "{port} faces the internet; put the new network on an inside port"
            ));
        }
        Some(_) => {}
        None => {
            return Err(format!(
                "this box has no port called {port} in its config; the inside ports are {}",
                config
                    .interfaces
                    .iter()
                    .filter(|(_, i)| !i.default_route && i.vlan.is_none())
                    .map(|(n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    let iface = format!("{port}.{}", req.vlan);
    if iface.len() > 15 {
        return Err(format!("{iface} is too long for an interface name"));
    }
    if config.interfaces.contains_key(&iface) {
        return Err(format!(
            "{iface} already exists; choose another VLAN number"
        ));
    }
    let taken = |net: &IpNet| {
        config
            .interfaces
            .values()
            .flat_map(|i| i.addresses.iter())
            .chain(config.wireguard.values().flat_map(|w| w.addresses.iter()))
            .any(|a| a.0.contains(&net.network()) || net.contains(&a.0.network()))
    };
    let address = match req.address {
        Some(a) if taken(&a.trunc()) => {
            return Err(format!("{a} overlaps a network the box already has"));
        }
        Some(a) => a,
        // Prefer the VLAN number as the third number, which is easy to remember.
        None => std::iter::once(u32::from(req.vlan))
            .chain(20..255)
            .filter(|n| (1..255).contains(n))
            .filter_map(|n| format!("192.168.{n}.1/24").parse::<IpNet>().ok())
            .find(|n| !taken(&n.trunc()))
            .ok_or("no free 192.168.x.0/24 network is left; give an address")?,
    };
    let internet = config
        .interfaces
        .values()
        .find(|i| i.default_route)
        .map(|i| i.zone.clone());

    config.zones.insert(
        zone.clone(),
        Zone {
            description: Some(title.to_string()),
        },
    );
    config.interfaces.insert(
        iface.clone(),
        Interface {
            zone: zone.clone(),
            addresses: vec![IfaceAddr(address)],
            default_route: false,
            gateway: vec![],
            dhcp_client: false,
            vlan: Some(ox_schema::Vlan {
                parent: port.to_string(),
                id: req.vlan,
            }),
        },
    );
    let mut done = vec![format!(
        "{title} is a new network: VLAN {} on {port}, where the box is {address}",
        req.vlan
    )];

    // Addresses and names, if the box already serves them to another network.
    let mut served = vec![];
    let own_v4 = match address {
        IpNet::V4(n) => Some(n),
        IpNet::V6(_) => None,
    };
    if !config.dhcp.is_empty()
        && let Some((first, last)) = own_v4.and_then(pool)
    {
        config.dhcp.insert(
            iface.clone(),
            DhcpPool {
                first,
                last,
                lease: Default::default(),
                dns: vec![],
                statics: vec![],
            },
        );
        config
            .services
            .entry("dhcp".into())
            .or_insert_with(|| vec!["udp/67".parse().expect("built-in")]);
        served.push("dhcp");
        done.push(format!(
            "devices on it get an address from {first} to {last}"
        ));
    }
    if let Some(dns) = &mut config.dns {
        dns.zones.push(zone.clone());
        config.services.entry("dns".into()).or_insert_with(|| {
            ["udp/53", "tcp/53"]
                .iter()
                .map(|p| p.parse().expect("built-in"))
                .collect()
        });
        served.insert(0, "dns");
        done.push("the box answers DNS for it".into());
    }
    if !served.is_empty() {
        config.policies.push(Policy {
            from: zone.clone(),
            to: SELF_ZONE.into(),
            log_default: true,
            rules: vec![rule(
                &format!("r-{zone}-services"),
                &format!("{title}: use the box for DNS and for getting an address"),
                vec![AddrRef::Any],
                &served,
                "added with the network",
            )],
        });
    }
    match (&internet, req.internet) {
        (Some(wan), true) => done.extend(set_access(config, &zone, wan, true)?),
        (None, true) => {
            return Err("this box has no internet port in its config, so the network cannot be given internet access".into());
        }
        (_, false) => done.push(format!("{title} cannot reach the internet")),
    }
    done.push(format!(
        "{title} cannot reach your other networks, and they cannot reach it, until you allow it"
    ));
    check(config)?;
    Ok(done)
}

/// What a config does, in sentences a new user can read.
pub fn describe(config: &Config) -> Vec<String> {
    let mut out = vec![];
    for (name, i) in &config.interfaces {
        let addrs = if i.addresses.is_empty() {
            "no fixed address".to_string()
        } else {
            i.addresses
                .iter()
                .map(|a| a.0.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push(format!("{name} is in zone {} ({addrs})", i.zone));
        if let Some(v) = &i.vlan {
            out.push(format!(
                "{name} is VLAN {} on {}, made by the box",
                v.id, v.parent
            ));
        }
        if i.dhcp_client {
            out.push(format!(
                "{name}: the box asks the network there for its IPv4 address and router"
            ));
        }
        for g in &i.gateway {
            out.push(format!("{name}: the default route goes through {g}"));
        }
    }
    for p in &config.policies {
        let to = if p.to == SELF_ZONE {
            "the box itself".to_string()
        } else {
            p.to.clone()
        };
        for r in p.rules.iter().filter(|r| r.enabled) {
            // "any" reads badly in a sentence, so say what it means.
            let list = |items: Vec<String>, all: &str| {
                if items == ["any"] {
                    all.to_string()
                } else {
                    items.join(", ")
                }
            };
            let what = list(
                r.service.iter().map(ServiceRef::to_string).collect(),
                "everything",
            );
            let who = list(r.source.iter().map(AddrRef::to_string).collect(), "anyone");
            let whom = list(
                r.destination.iter().map(AddrRef::to_string).collect(),
                "anywhere",
            );
            let verb = match r.action {
                Action::Accept => "allowed",
                Action::Drop => "dropped",
                Action::Reject => "rejected",
            };
            out.push(format!(
                "{} → {to}: {what} from {who} to {whom} is {verb} ({})",
                p.from, r.id
            ));
        }
        out.push(format!("{} → {to}: everything else is dropped", p.from));
    }
    for (name, w) in &config.wireguard {
        out.push(format!(
            "{name} is a WireGuard tunnel in zone {}{}, with {}",
            w.zone,
            w.listen_port
                .map(|p| format!(", listening on udp/{p}"))
                .unwrap_or_default(),
            match w.peers.len() {
                0 => "no peers yet".to_string(),
                1 => format!("one peer ({})", w.peers[0].name),
                n => format!("{n} peers"),
            }
        ));
    }
    for f in &config.nat.forward {
        out.push(format!(
            "{} {} from {} is forwarded to {}{} ({})",
            f.address
                .map_or("the box's own address,".to_string(), |a| a.to_string()),
            f.service,
            f.from,
            f.to,
            f.to_port.map(|p| format!(" port {p}")).unwrap_or_default(),
            f.id
        ));
    }
    for o in &config.nat.outbound {
        out.push(format!(
            "traffic from {} leaving by {} appears to come from {} ({})",
            o.source
                .iter()
                .map(AddrRef::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            o.to,
            match o.translate {
                Translate::Masquerade => "the box's own address".to_string(),
                Translate::Address(a) => a.to_string(),
            },
            o.id
        ));
    }
    if let Some(dns) = &config.dns {
        out.push(format!(
            "the box answers DNS for {}, forwarding to {}{}",
            dns.zones.join(", "),
            dns.upstream
                .iter()
                .map(IpAddr::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            if dns.dnssec {
                ", with DNSSEC checking"
            } else {
                ""
            }
        ));
        if let Some(d) = &dns.domain {
            out.push(format!("local names end in .{d}"));
        }
    }
    for name in &config.ipv6_autoconfig {
        out.push(format!(
            "devices on {name} give themselves an IPv6 address from the network the box announces"
        ));
    }
    for (name, p) in &config.dhcp {
        out.push(format!(
            "devices on {name} get an address from {} to {}, kept for {}",
            p.first, p.last, p.lease
        ));
    }
    let zones: Vec<&String> = config.zones.keys().collect();
    for from in &zones {
        for to in zones.iter().map(|z| z.as_str()).chain([SELF_ZONE]) {
            if *from != to
                && !config
                    .policies
                    .iter()
                    .any(|p| &p.from == *from && p.to == to)
            {
                let to = if to == SELF_ZONE {
                    "the box itself"
                } else {
                    to
                };
                out.push(format!("{from} → {to}: no rules, so everything is dropped"));
            }
        }
    }
    out
}

/// Lowercase letters, digits and hyphens from free text, for use in an ID.
fn slug(text: &str, max: usize) -> String {
    let mut s = String::new();
    for c in text.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            s.push(c);
        } else if !s.ends_with('-') && !s.is_empty() {
            s.push('-');
        }
    }
    s.truncate(max);
    s.trim_end_matches('-').to_string()
}

/// An ID that is not used yet, built from a prefix and a name.
fn fresh_id(config: &Config, prefix: &str, name: &str) -> String {
    let used = |id: &str| {
        config.rules().any(|(_, r)| r.id == id)
            || config.nat.forward.iter().any(|f| f.id == id)
            || config.nat.outbound.iter().any(|o| o.id == id)
    };
    // An ID is at most 32 characters; leave room for a numeric suffix.
    let mut base = match slug(name, 28).as_str() {
        "" => prefix.to_string(),
        s => format!("{prefix}-{s}"),
    };
    base.truncate(28);
    let base = base.trim_end_matches('-').to_string();
    let mut id = base.clone();
    let mut n = 2;
    while used(&id) || !is_name(&id) {
        id = format!("{base}-{n}");
        n += 1;
    }
    id
}

/// A candidate name for a one-step action, such as `forward-home-assistant`.
pub fn candidate_name(prefix: &str, name: &str) -> String {
    format!("{prefix}-{}", slug(name, 20))
        .trim_end_matches('-')
        .to_string()
}

/// The zone whose interface network holds an address.
fn zone_of(config: &Config, ip: IpAddr) -> Option<&str> {
    config
        .interfaces
        .values()
        .find(|i| i.addresses.iter().any(|a| a.0.trunc().contains(&ip)))
        .map(|i| i.zone.as_str())
}

/// "Forward a port": what the user asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardRequest {
    pub name: String,
    /// The port people connect to from outside, such as `tcp/443`.
    pub service: PortSpec,
    /// The inside host that should receive the traffic.
    pub to: IpAddr,
    /// The port on the inside host, when it differs.
    pub to_port: Option<u16>,
    /// The outside address to forward. Defaults to the box's address on the
    /// internet-facing interface.
    pub address: Option<IpAddr>,
}

/// Adds a port forward and the filter rule it needs. Returns what was done,
/// in plain sentences. The config is unchanged on error.
pub fn add_forward(config: &mut Config, req: &ForwardRequest) -> Result<Vec<String>, String> {
    let PortSpec::Ports { proto, first, last } = req.service else {
        return Err("a forward needs a TCP or UDP port, such as tcp/443".into());
    };
    if first != last && req.to_port.is_some() {
        return Err("a port range keeps its port numbers; leave out the inside port".into());
    }
    let v4 = req.to.is_ipv4();
    let (wan_name, wan) = config
        .interfaces
        .iter()
        .find(|(_, i)| i.default_route && i.addresses.iter().any(|a| a.0.addr().is_ipv4() == v4))
        .or_else(|| config.interfaces.iter().find(|(_, i)| i.default_route))
        .ok_or("no interface carries the default route, so there is no outside to forward from")?;
    let from = wan.zone.clone();
    // With no fixed address on the outside port, the forward follows
    // whatever address the provider gives the box.
    let address = req.address.or_else(|| {
        wan.addresses
            .iter()
            .map(|a| a.0.addr())
            .find(|a| a.is_ipv4() == v4)
    });
    if address.is_some_and(|a| a.is_ipv4() != v4) {
        return Err(
            "the outside address and the inside host must both be IPv4 or both be IPv6".into(),
        );
    }
    let to_zone = zone_of(config, req.to)
        .ok_or_else(|| format!("{} is not on any network of this box", req.to))?
        .to_string();
    if to_zone == from {
        return Err(format!(
            "{} is on the outside network, not behind the box",
            req.to
        ));
    }

    let inside_first = req.to_port.unwrap_or(first);
    let inside = PortSpec::Ports {
        proto,
        first: inside_first,
        last: inside_first + (last - first),
    };
    let mut next = config.clone();
    let rule_id = fresh_id(&next, "r-fwd", &req.name);
    let nat_id = fresh_id(&next, "n-fwd", &req.name);
    let rule = Rule {
        id: rule_id.clone(),
        name: format!("{} (forwarded)", req.name),
        action: Action::Accept,
        source: vec![AddrRef::Any],
        destination: vec![AddrRef::Net(Net(IpNet::from(req.to)))],
        service: vec![ServiceRef::Port(inside)],
        log: false,
        enabled: true,
        reason: Some(format!("port forward {nat_id}")),
    };
    let pair = match next
        .policies
        .iter()
        .position(|p| p.from == from && p.to == to_zone)
    {
        Some(i) => i,
        None => {
            next.policies.push(Policy {
                from: from.clone(),
                to: to_zone.clone(),
                log_default: true,
                rules: vec![],
            });
            next.policies.len() - 1
        }
    };
    next.policies[pair].rules.push(rule);
    next.nat.forward.push(Forward {
        id: nat_id.clone(),
        name: req.name.clone(),
        from: from.clone(),
        address,
        service: req.service,
        to: req.to,
        to_port: req.to_port,
        rule: rule_id.clone(),
    });
    check(&next)?;

    // Prove it: a packet from outside must now be accepted by the new rule.
    // If an earlier rule decides first, move the new one to the top. With
    // no fixed outside address, a documentation address stands in for the
    // one the provider will assign.
    let probe_dst: IpAddr = address.unwrap_or(if v4 {
        "192.0.2.1".parse().expect("valid")
    } else {
        "2001:db8::1".parse().expect("valid")
    });
    let outside = address.map_or("the box's own address,".to_string(), |a| a.to_string());
    let probe = Packet {
        src: if v4 {
            "198.51.100.7".parse().expect("valid")
        } else {
            "2001:db8:ffff::7".parse().expect("valid")
        },
        dst: probe_dst,
        l4: if proto == Proto::Tcp {
            L4::Tcp
        } else {
            L4::Udp
        },
        dport: Some(first),
        iif: wan_name.clone(),
        box_addrs: vec![probe_dst],
    };
    let decided_by = |c: &Config| -> Result<(Verdict, Option<String>), String> {
        let rs = compile(c).map_err(|e| e.to_string())?;
        let e = explain(&rs, &probe).map_err(|e| e.to_string())?;
        Ok((e.verdict, e.rule.map(|r| r.id)))
    };
    let mut moved = None;
    if decided_by(&next)? != (Verdict::Accept, Some(rule_id.clone())) {
        let (_, earlier) = decided_by(&next)?;
        let rules = &mut next.policies[pair].rules;
        let r = rules.pop().expect("just pushed");
        rules.insert(0, r);
        check(&next)?;
        if decided_by(&next)? != (Verdict::Accept, Some(rule_id.clone())) {
            return Err(format!(
                "the forward was written but a packet from outside is still not accepted by {rule_id}; nothing was changed"
            ));
        }
        moved = earlier;
    }
    *config = next;
    let mut out = vec![
        format!(
            "{outside} {} from {from} is forwarded to {}{} ({nat_id})",
            req.service,
            req.to,
            req.to_port
                .map(|p| format!(" port {p}"))
                .unwrap_or_default()
        ),
        format!("rule {rule_id} in {from} → {to_zone} lets that traffic in"),
    ];
    if let Some(earlier) = moved {
        out.push(format!(
            "{rule_id} was placed first in {from} → {to_zone}, because rule {earlier} would have decided the traffic before it"
        ));
    }
    out.push(format!(
        "checked: a packet from outside to {outside} {} is accepted by {rule_id}",
        req.service
    ));
    Ok(out)
}

/// "Add a device to the VPN": what the user asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnPeerRequest {
    /// What the device is, such as "Ana's laptop".
    pub name: String,
    /// The device's WireGuard public key.
    pub public_key: String,
}

/// What a new VPN device needs to be told, besides its own private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VpnPeer {
    /// What was done, in plain sentences.
    pub done: Vec<String>,
    /// The tunnel interface on the box.
    pub tunnel: String,
    pub listen_port: u16,
    /// The device's address inside the tunnel.
    pub address: IpNet,
    /// The networks the device should send through the tunnel.
    pub routes: Vec<IpNet>,
    /// The box's address as a DNS server, when it answers DNS for the VPN.
    pub dns: Option<IpAddr>,
}

/// The device's own config file, in the format every WireGuard app reads.
/// `endpoint` is how the device finds the box from outside: a name or
/// address, with or without a port.
pub fn client_config(peer: &VpnPeer, private_key: &str, box_key: &str, endpoint: &str) -> String {
    let endpoint = if let Ok(v6) = endpoint.parse::<std::net::Ipv6Addr>() {
        format!("[{v6}]:{}", peer.listen_port)
    } else if endpoint.parse::<std::net::SocketAddr>().is_ok()
        || endpoint
            .rsplit_once(':')
            .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        // Already has a port.
        endpoint.to_string()
    } else {
        format!("{endpoint}:{}", peer.listen_port)
    };
    let routes: Vec<String> = peer.routes.iter().map(ToString::to_string).collect();
    let mut out = format!(
        "[Interface]\nPrivateKey = {private_key}\nAddress = {}\n",
        peer.address
    );
    if let Some(dns) = peer.dns {
        out.push_str(&format!("DNS = {dns}\n"));
    }
    out.push_str(&format!(
        "\n[Peer]\nPublicKey = {box_key}\nEndpoint = {endpoint}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
        routes.join(", ")
    ));
    out
}

/// A QR code of some text, as rows of `1` (dark) and `0` (light) with the
/// blank border a scanner needs. The WireGuard phone apps read a device's
/// config from one. `None` when the text is too long for a QR code.
pub fn qr_rows(text: &str) -> Option<Vec<String>> {
    const BORDER: usize = 4;
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let width = code.width();
    let colors = code.to_colors();
    let blank = "0".repeat(width + 2 * BORDER);
    let mut rows = vec![blank.clone(); BORDER];
    for line in colors.chunks(width) {
        let mut row = "0".repeat(BORDER);
        row.extend(line.iter().map(|c| match c {
            qrcode::Color::Dark => '1',
            qrcode::Color::Light => '0',
        }));
        row.push_str(&"0".repeat(BORDER));
        rows.push(row);
    }
    rows.extend(vec![blank; BORDER]);
    Some(rows)
}

/// A QR code drawn with block characters, two rows of the code per line of
/// text. Light squares are drawn and dark ones left empty, which reads
/// correctly on a terminal with a dark background.
pub fn qr_text(rows: &[String]) -> String {
    let dark = |row: Option<&String>, x: usize| row.is_some_and(|r| r.as_bytes()[x] == b'1');
    let mut out = String::new();
    for pair in rows.chunks(2) {
        for x in 0..pair[0].len() {
            out.push(match (dark(pair.first(), x), dark(pair.get(1), x)) {
                (false, false) => '█',
                (false, true) => '▀',
                (true, false) => '▄',
                (true, true) => ' ',
            });
        }
        out.push('\n');
    }
    out
}

const VPN_ZONE: &str = "vpn";
const VPN_PORT: u16 = 51820;

/// Adds a device to the box's VPN, and sets the VPN up if there is none:
/// a WireGuard tunnel in its own zone, the rule that lets devices connect
/// from the internet, and rules that let them reach the inside networks.
/// The config is unchanged on error.
pub fn add_vpn_peer(config: &mut Config, req: &VpnPeerRequest) -> Result<VpnPeer, String> {
    let peer_name = slug(&req.name, 32);
    if !is_name(&peer_name) {
        return Err("give the device a name that starts with a letter, such as \"laptop\"".into());
    }
    if ox_schema::decode_key(&req.public_key).is_none() {
        return Err("that is not a WireGuard public key: 44 characters ending in '='".into());
    }
    let mut next = config.clone();
    let mut done = vec![];

    let existing = next
        .wireguard
        .iter()
        .find(|(_, w)| w.zone == VPN_ZONE && w.listen_port.is_some())
        .map(|(name, _)| name.clone());
    let tunnel = match existing {
        Some(name) => name,
        None => {
            let (wan_name, wan) = next
                .interfaces
                .iter()
                .find(|(_, i)| i.default_route)
                .ok_or("no interface carries the default route, so devices outside could not reach the box")?;
            let (wan_name, wan_zone) = (wan_name.clone(), wan.zone.clone());
            let inside_zones: BTreeSet<String> = next
                .interfaces
                .values()
                .filter(|i| i.zone != wan_zone)
                .map(|i| i.zone.clone())
                .collect();
            // A network for the tunnel that nothing on the box uses yet.
            let used: Vec<IpNet> = next
                .interfaces
                .values()
                .flat_map(|i| i.addresses.iter().map(|a| a.0.trunc()))
                .collect();
            let own: IpNet = (90..=99)
                .map(|n| format!("10.{n}.0.1/24").parse::<IpNet>().expect("valid"))
                .find(|net| !used.iter().any(|u| u.contains(&net.network()) || net.contains(&u.network())))
                .ok_or("the networks 10.90.0.0/24 to 10.99.0.0/24 are all in use here; add the tunnel to the config by hand")?;
            let name = (0..10)
                .map(|n| format!("wg{n}"))
                .find(|n| !next.interfaces.contains_key(n) && !next.wireguard.contains_key(n))
                .ok_or("wg0 to wg9 are all taken")?;
            next.zones.entry(VPN_ZONE.into()).or_insert(Zone {
                description: Some("Devices connected over the VPN".into()),
            });
            next.wireguard.insert(
                name.clone(),
                WireGuard {
                    zone: VPN_ZONE.into(),
                    addresses: vec![IfaceAddr(own)],
                    listen_port: Some(VPN_PORT),
                    peers: vec![],
                },
            );
            next.services
                .entry("wireguard".into())
                .or_insert_with(|| vec![format!("udp/{VPN_PORT}").parse().expect("built-in")]);
            let policy = |next: &mut Config, from: &str, to: &str| -> usize {
                match next
                    .policies
                    .iter()
                    .position(|p| p.from == from && p.to == to)
                {
                    Some(i) => i,
                    None => {
                        next.policies.push(Policy {
                            from: from.into(),
                            to: to.into(),
                            log_default: true,
                            rules: vec![],
                        });
                        next.policies.len() - 1
                    }
                }
            };
            let i = policy(&mut next, &wan_zone, SELF_ZONE);
            let id = fresh_id(&next, "r", "vpn-connect");
            next.policies[i].rules.push(rule(
                &id,
                "Devices connect to the VPN",
                vec![AddrRef::Any],
                &["wireguard"],
                "VPN setup: WireGuard answers only peers whose key it knows",
            ));
            done.push(format!(
                "a VPN was set up: tunnel {name} with the box at {}, listening on udp/{VPN_PORT} on {wan_name} ({id})",
                own.addr()
            ));
            for zone in &inside_zones {
                let i = policy(&mut next, VPN_ZONE, zone);
                let id = fresh_id(&next, "r", &format!("vpn-to-{zone}"));
                next.policies[i].rules.push(rule(
                    &id,
                    &format!("VPN devices reach {zone}"),
                    vec![AddrRef::Any],
                    &["any"],
                    "VPN setup: a connected device is treated like one on the inside network",
                ));
                done.push(format!(
                    "devices on the VPN may reach everything in {zone} ({id})"
                ));
            }
            let serves_dns = next.dns.is_some();
            let i = policy(&mut next, VPN_ZONE, SELF_ZONE);
            let id = fresh_id(&next, "r", "vpn-to-box");
            let mut services = vec!["icmp", "icmpv6"];
            if serves_dns {
                services.extend(["udp/53", "tcp/53"]);
            }
            next.policies[i].rules.push(rule(
                &id,
                "VPN devices may ping the box and use its DNS",
                vec![AddrRef::Any],
                &services,
                "VPN setup",
            ));
            if let Some(dns) = &mut next.dns
                && !dns.zones.iter().any(|z| z == VPN_ZONE)
            {
                dns.zones.push(VPN_ZONE.into());
                done.push(
                    "the box answers DNS for VPN devices, so local names work for them".into(),
                );
            }
            name
        }
    };

    let wg = next.wireguard.get_mut(&tunnel).expect("found or just made");
    let own = wg
        .addresses
        .iter()
        .map(|a| a.0)
        .find(|a| a.addr().is_ipv4() && a.prefix_len() <= 30)
        .ok_or_else(|| {
            format!("{tunnel} has no IPv4 network to give the device an address from")
        })?;
    if wg.peers.iter().any(|p| p.name == peer_name) {
        return Err(format!("the VPN already has a device called '{peer_name}'"));
    }
    if wg.peers.iter().any(|p| p.public_key == req.public_key) {
        return Err("the VPN already has a device with that key".into());
    }
    let taken: Vec<IpAddr> = wg
        .peers
        .iter()
        .flat_map(|p| p.allowed.iter().map(|n| n.0.addr()))
        .chain([own.addr()])
        .collect();
    let address = own
        .hosts()
        .find(|h| !taken.contains(h))
        .ok_or_else(|| format!("{} has no free address left", own.trunc()))?;
    let address = IpNet::new(address, 32).expect("a host route");
    wg.peers.push(WgPeer {
        name: peer_name.clone(),
        public_key: req.public_key.clone(),
        allowed: vec![Net(address)],
        endpoint: None,
        keepalive: None,
    });
    let listen_port = wg.listen_port.unwrap_or(VPN_PORT);
    check(&next)?;

    // What the device should send through the tunnel: the tunnel's own
    // network and every network the VPN zone may reach.
    let reachable: BTreeSet<&str> = next
        .policies
        .iter()
        .filter(|p| p.from == VPN_ZONE && p.to != SELF_ZONE)
        .map(|p| p.to.as_str())
        .collect();
    let mut routes = vec![own.trunc()];
    for i in next
        .interfaces
        .values()
        .filter(|i| reachable.contains(i.zone.as_str()))
    {
        for a in &i.addresses {
            if a.0.addr().is_ipv4() && !routes.contains(&a.0.trunc()) {
                routes.push(a.0.trunc());
            }
        }
    }
    let dns = next
        .dns
        .as_ref()
        .filter(|d| d.zones.iter().any(|z| z == VPN_ZONE))
        .map(|_| own.addr());
    done.push(format!(
        "{peer_name} was added to the VPN with the address {}",
        address.addr()
    ));
    *config = next;
    Ok(VpnPeer {
        done,
        tunnel,
        listen_port,
        address,
        routes,
        dns,
    })
}

/// "Block a device": drops everything an inside address sends, to other
/// networks and to the box. Returns what was done.
pub fn block(config: &mut Config, who: Net, name: &str) -> Result<Vec<String>, String> {
    let zone = zone_of(config, who.0.addr())
        .ok_or_else(|| format!("{who} is not on any network of this box"))?
        .to_string();
    let mut next = config.clone();
    let mut out = vec![];
    let pairs: Vec<usize> = (0..next.policies.len())
        .filter(|i| next.policies[*i].from == zone)
        .collect();
    for i in pairs {
        let to = next.policies[i].to.clone();
        let id = fresh_id(
            &next,
            "r-block",
            &format!("{} {}", slug(name, 12), slug(&to, 7)),
        );
        next.policies[i].rules.insert(
            0,
            Rule {
                id: id.clone(),
                name: format!("Block {name}"),
                action: Action::Drop,
                source: vec![AddrRef::Net(who)],
                destination: vec![AddrRef::Any],
                service: vec![ServiceRef::Any],
                log: true,
                enabled: true,
                reason: Some(format!("blocked device {who}")),
            },
        );
        let to = if to == SELF_ZONE {
            "the box itself".to_string()
        } else {
            to
        };
        out.push(format!(
            "{id}: everything {who} sends to {to} is dropped and logged"
        ));
    }
    if out.is_empty() {
        return Err(format!(
            "zone {zone} has no rules, so everything {who} sends is already dropped"
        ));
    }
    check(&next)?;
    *config = next;
    out.push(format!(
        "connections {who} already has open keep working until they end; new ones are dropped"
    ));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn port(name: &str, addrs: &[&str]) -> Port {
        Port {
            name: name.into(),
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    fn home() -> Config {
        starter(&Answers {
            hostname: "home".into(),
            wan: port("eth0", &["203.0.113.10/24", "2001:db8:1::10/64"]),
            lans: vec![port("eth1", &["192.168.10.1/24", "2001:db8:2::1/64"])],
            serve: None,
            wan_dhcp: false,
            gateway: vec![],
        })
        .unwrap()
    }

    fn verdict(
        config: &Config,
        src: &str,
        dst: &str,
        l4: L4,
        dport: Option<u16>,
        iif: &str,
    ) -> (Verdict, Option<String>) {
        let rs = compile(config).unwrap();
        let p = Packet {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            l4,
            dport,
            iif: iif.into(),
            box_addrs: vec![],
        };
        let e = explain(&rs, &p).unwrap();
        (e.verdict, e.rule.map(|r| r.id))
    }

    #[test]
    fn the_starter_lets_inside_out_and_nothing_in() {
        let c = home();
        for (src, dst) in [
            ("192.168.10.50", "198.51.100.9"),
            ("2001:db8:2::50", "2001:db8:ffff::9"),
        ] {
            assert_eq!(
                verdict(&c, src, dst, L4::Tcp, Some(443), "eth1").0,
                Verdict::Accept,
                "{src} out"
            );
        }
        for (src, dst) in [
            ("198.51.100.7", "203.0.113.10"),
            ("2001:db8:ffff::7", "2001:db8:1::10"),
        ] {
            assert_eq!(
                verdict(&c, src, dst, L4::Tcp, Some(22), "eth0").0,
                Verdict::Drop,
                "ssh from outside"
            );
            assert_eq!(
                verdict(&c, src, dst, L4::Tcp, Some(443), "eth0").0,
                Verdict::Drop
            );
        }
        // The inside network cannot be reached from outside either.
        assert_eq!(
            verdict(
                &c,
                "198.51.100.7",
                "192.168.10.50",
                L4::Tcp,
                Some(80),
                "eth0"
            )
            .0,
            Verdict::Drop
        );
    }

    #[test]
    fn the_box_is_managed_from_inside_only() {
        let c = home();
        for (src, dst) in [
            ("192.168.10.50", "192.168.10.1"),
            ("2001:db8:2::50", "2001:db8:2::1"),
        ] {
            assert_eq!(
                verdict(&c, src, dst, L4::Tcp, Some(22), "eth1"),
                (Verdict::Accept, Some("r-manage".into()))
            );
        }
        assert_eq!(
            verdict(&c, "192.168.10.50", "192.168.10.1", L4::Icmp, None, "eth1").0,
            Verdict::Accept
        );
        assert_eq!(
            verdict(
                &c,
                "2001:db8:2::50",
                "2001:db8:2::1",
                L4::Icmpv6,
                None,
                "eth1"
            )
            .0,
            Verdict::Accept
        );
        // Other ports on the box are closed, even from inside.
        assert_eq!(
            verdict(
                &c,
                "192.168.10.50",
                "192.168.10.1",
                L4::Tcp,
                Some(8080),
                "eth1"
            )
            .0,
            Verdict::Drop
        );
    }

    #[test]
    fn private_ipv4_is_hidden_and_ipv6_is_not() {
        let c = home();
        assert_eq!(c.nat.outbound.len(), 1);
        assert_eq!(
            c.nat.outbound[0].source,
            vec!["192.168.10.0/24".parse().unwrap()]
        );
        // A setup with no IPv4 inside needs no NAT at all.
        let v6 = starter(&Answers {
            hostname: "v6".into(),
            wan: port("eth0", &["2001:db8:1::10/64"]),
            lans: vec![port("eth1", &["2001:db8:2::1/64"])],
            serve: None,
            wan_dhcp: false,
            gateway: vec![],
        })
        .unwrap();
        assert!(v6.nat.outbound.is_empty());
    }

    #[test]
    fn a_wan_without_a_fixed_address_still_works() {
        let c = starter(&Answers {
            hostname: "dhcp".into(),
            wan: port("eth0", &[]),
            lans: vec![
                port("eth1", &["192.168.10.1/24"]),
                port("eth2", &["192.168.20.1/24"]),
            ],
            serve: None,
            wan_dhcp: false,
            gateway: vec![],
        })
        .unwrap();
        assert_eq!(c.zone_interfaces("lan"), ["eth1", "eth2"]);
        assert_eq!(c.addresses["inside"].len(), 2);
    }

    fn served() -> Config {
        starter(&Answers {
            hostname: "home".into(),
            wan: port("eth0", &[]),
            lans: vec![port("eth1", &["192.168.10.1/24", "2001:db8:2::1/64"])],
            serve: Some(Serve::default()),
            wan_dhcp: false,
            gateway: vec![],
        })
        .unwrap()
    }

    #[test]
    fn the_starter_can_serve_dns_and_addresses_inside_only() {
        let c = served();
        let dns = c.dns.as_ref().unwrap();
        assert_eq!(dns.zones, ["lan"]);
        assert_eq!(dns.domain.as_deref(), Some("home.arpa"));
        let p = &c.dhcp["eth1"];
        assert_eq!(
            (p.first.to_string(), p.last.to_string()),
            ("192.168.10.100".into(), "192.168.10.199".into())
        );
        // The inside network may use the services, in both address families.
        for (src, me) in [
            ("192.168.10.50", "192.168.10.1"),
            ("2001:db8:2::50", "2001:db8:2::1"),
        ] {
            assert_eq!(
                verdict(&c, src, me, L4::Udp, Some(53), "eth1"),
                (Verdict::Accept, Some("r-services".into()))
            );
            assert_eq!(
                verdict(&c, src, me, L4::Tcp, Some(53), "eth1").0,
                Verdict::Accept
            );
        }
        assert_eq!(
            verdict(
                &c,
                "192.168.10.50",
                "192.168.10.1",
                L4::Udp,
                Some(67),
                "eth1"
            )
            .0,
            Verdict::Accept
        );
        let text = describe(&c).join("\n");
        assert!(
            text.contains(
                "the box answers DNS for lan, forwarding to 1.1.1.1, 9.9.9.9, with DNSSEC checking"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "devices on eth1 get an address from 192.168.10.100 to 192.168.10.199, kept for 12h"
            ),
            "{text}"
        );
    }

    #[test]
    fn pools_keep_clear_of_the_box_and_fit_the_network() {
        let p = |s: &str| pool(s.parse().unwrap()).map(|(a, b)| format!("{a}-{b}"));
        assert_eq!(
            p("192.168.10.1/24").as_deref(),
            Some("192.168.10.100-192.168.10.199")
        );
        assert_eq!(
            p("10.20.0.1/16").as_deref(),
            Some("10.20.0.100-10.20.0.199")
        );
        assert_eq!(
            p("192.168.10.150/24").as_deref(),
            Some("192.168.10.100-192.168.10.149")
        );
        assert_eq!(
            p("192.168.10.120/24").as_deref(),
            Some("192.168.10.121-192.168.10.199")
        );
        assert_eq!(
            p("192.168.10.1/26").as_deref(),
            Some("192.168.10.32-192.168.10.62")
        );
        assert_eq!(
            p("192.168.10.1/29"),
            None,
            "eight addresses are too few for a pool"
        );
        // Every pool this makes passes validation: inside the network, not the box.
        for net in [
            "192.168.10.1/24",
            "192.168.10.150/24",
            "192.168.10.33/26",
            "10.0.0.1/8",
            "172.16.5.129/25",
        ] {
            let c = starter(&Answers {
                hostname: "h".into(),
                wan: port("eth0", &[]),
                lans: vec![port("eth1", &[net])],
                serve: Some(Serve::default()),
                wan_dhcp: false,
                gateway: vec![],
            });
            assert!(c.is_ok(), "{net}: {c:?}");
        }
    }

    #[test]
    fn bad_answers_are_refused_in_plain_words() {
        let mut a = Answers {
            hostname: "x".into(),
            wan: port("eth0", &[]),
            lans: vec![],
            serve: None,
            wan_dhcp: false,
            gateway: vec![],
        };
        assert!(starter(&a).unwrap_err().contains("at least one port"));
        a.lans = vec![port("eth0", &["192.168.1.1/24"])];
        assert!(starter(&a).unwrap_err().contains("cannot face both"));
        a.lans = vec![port("eth1", &[])];
        assert!(starter(&a).unwrap_err().contains("192.168.10.1/24"));
    }

    #[test]
    fn describe_says_what_is_allowed_and_what_is_dropped() {
        let text = describe(&home()).join("\n");
        assert!(
            text.contains(
                "lan → wan: everything from anyone to anywhere is allowed (r-inside-out)"
            ),
            "{text}"
        );
        assert!(
            text.contains("wan → lan: no rules, so everything is dropped"),
            "{text}"
        );
        assert!(
            text.contains("appears to come from the box's own address"),
            "{text}"
        );
    }

    #[test]
    fn forwarding_a_port_adds_the_nat_and_the_rule_and_proves_it() {
        for (to, outside, address) in [
            ("192.168.10.20", "198.51.100.7", "203.0.113.10"),
            ("2001:db8:2::20", "2001:db8:ffff::7", "2001:db8:1::10"),
        ] {
            let mut c = home();
            let done = add_forward(
                &mut c,
                &ForwardRequest {
                    name: "Home Assistant".into(),
                    service: "tcp/443".parse().unwrap(),
                    to: to.parse().unwrap(),
                    to_port: Some(8123),
                    address: None,
                },
            )
            .unwrap();
            assert!(done.last().unwrap().starts_with("checked:"), "{done:?}");
            assert_eq!(c.nat.forward[0].id, "n-fwd-home-assistant");
            assert_eq!(c.nat.forward[0].rule, "r-fwd-home-assistant");
            assert_eq!(
                verdict(&c, outside, address, L4::Tcp, Some(443), "eth0"),
                (Verdict::Accept, Some("r-fwd-home-assistant".into()))
            );
            // Only that port, and only that host.
            assert_eq!(
                verdict(&c, outside, address, L4::Tcp, Some(22), "eth0").0,
                Verdict::Drop
            );
        }
    }

    #[test]
    fn a_forward_goes_ahead_of_a_rule_that_would_block_it() {
        let mut c = home();
        c.policies.push(Policy {
            from: "wan".into(),
            to: "lan".into(),
            log_default: true,
            rules: vec![Rule {
                id: "r-no".into(),
                name: "Nothing in".into(),
                action: Action::Drop,
                source: vec![AddrRef::Any],
                destination: vec![AddrRef::Any],
                service: vec![ServiceRef::Any],
                log: false,
                enabled: true,
                reason: None,
            }],
        });
        let done = add_forward(
            &mut c,
            &ForwardRequest {
                name: "Game".into(),
                service: "udp/27015-27020".parse().unwrap(),
                to: "192.168.10.30".parse().unwrap(),
                to_port: None,
                address: None,
            },
        )
        .unwrap();
        assert!(
            done.iter()
                .any(|l| l.contains("placed first") && l.contains("r-no")),
            "{done:?}"
        );
        assert_eq!(c.policies.last().unwrap().rules[0].id, "r-fwd-game");
    }

    #[test]
    fn forwards_that_cannot_work_are_refused_and_change_nothing() {
        let before = home();
        let req = |to: &str, service: &str| ForwardRequest {
            name: "x".into(),
            service: service.parse().unwrap(),
            to: to.parse().unwrap(),
            to_port: None,
            address: None,
        };
        for (r, needle) in [
            (req("10.9.9.9", "tcp/80"), "not on any network"),
            (req("203.0.113.50", "tcp/80"), "outside network"),
            (req("192.168.10.20", "icmp"), "TCP or UDP port"),
        ] {
            let mut c = before.clone();
            let err = add_forward(&mut c, &r).unwrap_err();
            assert!(err.contains(needle), "{err}");
            assert_eq!(c, before);
        }
    }

    #[test]
    fn a_forward_works_when_the_provider_assigns_the_outside_address() {
        // `served` has no fixed address on its internet port.
        let mut c = served();
        let done = add_forward(
            &mut c,
            &ForwardRequest {
                name: "Web".into(),
                service: "tcp/443".parse().unwrap(),
                to: "192.168.10.20".parse().unwrap(),
                to_port: None,
                address: None,
            },
        )
        .unwrap();
        assert_eq!(c.nat.forward[0].address, None);
        assert!(
            done[0].starts_with("the box's own address, tcp/443 from wan"),
            "{done:?}"
        );
        assert!(done.last().unwrap().starts_with("checked:"), "{done:?}");

        // Whatever address the box turns out to have, the forward applies
        // to it and to nothing else.
        let rs = compile(&c).unwrap();
        let to = |dst: &str, mine: bool| {
            let dst: IpAddr = dst.parse().unwrap();
            let p = Packet {
                src: "198.51.100.7".parse().unwrap(),
                dst,
                l4: L4::Tcp,
                dport: Some(443),
                iif: "eth0".into(),
                box_addrs: if mine { vec![dst] } else { vec![] },
            };
            explain(&rs, &p).unwrap()
        };
        assert_eq!(to("100.64.3.9", true).verdict, Verdict::Accept);
        let other = to("100.64.3.9", false);
        assert_eq!(other.verdict, Verdict::Drop);
        assert!(
            other.to_string().contains("does not apply"),
            "the explanation says why the forward was not used: {other}"
        );
    }

    const KEY_A: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const KEY_B: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

    #[test]
    fn adding_a_vpn_device_sets_the_vpn_up_and_proves_the_rules() {
        let mut c = served();
        let before = c.clone();
        let laptop = add_vpn_peer(
            &mut c,
            &VpnPeerRequest {
                name: "Ana's laptop".into(),
                public_key: KEY_A.into(),
            },
        )
        .unwrap();
        assert_eq!(laptop.tunnel, "wg0");
        assert_eq!(laptop.address.to_string(), "10.90.0.2/32");
        assert_eq!(laptop.dns, Some("10.90.0.1".parse().unwrap()));
        let routes: Vec<String> = laptop.routes.iter().map(ToString::to_string).collect();
        assert_eq!(routes, ["10.90.0.0/24", "192.168.10.0/24"]);
        assert!(
            laptop.done[0].starts_with("a VPN was set up"),
            "{:?}",
            laptop.done
        );
        assert!(c.validate().is_empty(), "{:?}", c.validate());

        // The rules it wrote do what it said: a device on the VPN reaches
        // the inside network and the box's DNS, the internet reaches the
        // tunnel port and nothing else, and the VPN cannot go out by wan.
        let rs = compile(&c).unwrap();
        let verdict = |src: &str, dst: &str, l4, dport, iif: &str| {
            let p = Packet {
                src: src.parse().unwrap(),
                dst: dst.parse().unwrap(),
                l4,
                dport,
                iif: iif.into(),
                box_addrs: vec!["100.64.3.9".parse().unwrap()],
            };
            explain(&rs, &p).unwrap().verdict
        };
        assert_eq!(
            verdict("10.90.0.2", "192.168.10.20", L4::Tcp, Some(445), "wg0"),
            Verdict::Accept
        );
        assert_eq!(
            verdict("10.90.0.2", "10.90.0.1", L4::Udp, Some(53), "wg0"),
            Verdict::Accept
        );
        assert_eq!(
            verdict("10.90.0.2", "10.90.0.1", L4::Tcp, Some(22), "wg0"),
            Verdict::Drop
        );
        assert_eq!(
            verdict("10.90.0.2", "198.51.100.9", L4::Tcp, Some(443), "wg0"),
            Verdict::Drop
        );
        assert_eq!(
            verdict("198.51.100.7", "100.64.3.9", L4::Udp, Some(51820), "eth0"),
            Verdict::Accept
        );
        assert_eq!(
            verdict("198.51.100.7", "100.64.3.9", L4::Udp, Some(51821), "eth0"),
            Verdict::Drop
        );
        // An inside device can answer the laptop: the way back is known.
        assert_eq!(
            verdict("192.168.10.20", "10.90.0.2", L4::Icmp, None, "eth1"),
            Verdict::Drop,
            "inside may not start connections to VPN devices; only replies pass"
        );

        // A second device joins the same VPN and gets the next address.
        let phone = add_vpn_peer(
            &mut c,
            &VpnPeerRequest {
                name: "phone".into(),
                public_key: KEY_B.into(),
            },
        )
        .unwrap();
        assert_eq!(phone.address.to_string(), "10.90.0.3/32");
        assert_eq!(phone.done.len(), 1, "no second setup: {:?}", phone.done);
        assert_eq!(c.wireguard["wg0"].peers.len(), 2);

        // The same name or key again is refused and changes nothing.
        let two = c.clone();
        for (name, key, needle) in [
            (
                "phone",
                "0000000000000000000000000000000000000000000=",
                "already has a device called",
            ),
            ("tablet", KEY_B, "already has a device with that key"),
            ("tablet", "not a key", "not a WireGuard public key"),
            ("9", KEY_A, "give the device a name"),
        ] {
            let err = add_vpn_peer(
                &mut c,
                &VpnPeerRequest {
                    name: name.into(),
                    public_key: key.into(),
                },
            )
            .unwrap_err();
            assert!(err.contains(needle), "{name}: {err}");
            assert_eq!(c, two);
        }
        assert_ne!(c, before);
    }

    #[test]
    fn the_device_config_names_the_box_however_the_endpoint_is_written() {
        let peer = VpnPeer {
            done: vec![],
            tunnel: "wg0".into(),
            listen_port: 51820,
            address: "10.90.0.2/32".parse().unwrap(),
            routes: vec![
                "10.90.0.0/24".parse().unwrap(),
                "192.168.10.0/24".parse().unwrap(),
            ],
            dns: None,
        };
        for (given, written) in [
            ("home.example.net", "home.example.net:51820"),
            ("home.example.net:4500", "home.example.net:4500"),
            ("203.0.113.10", "203.0.113.10:51820"),
            ("2001:db8::5", "[2001:db8::5]:51820"),
            ("[2001:db8::5]:4500", "[2001:db8::5]:4500"),
        ] {
            let text = client_config(&peer, "PRIVATE", "PUBLIC", given);
            assert!(
                text.contains(&format!("Endpoint = {written}\n")),
                "{given}: {text}"
            );
            assert!(text.contains("AllowedIPs = 10.90.0.0/24, 192.168.10.0/24\n"));
            assert!(!text.contains("DNS ="));
        }
    }

    #[test]
    fn blocking_a_device_drops_what_it_sends_in_both_families() {
        for (device, peer, dst, me) in [
            (
                "192.168.10.66",
                "192.168.10.50",
                "198.51.100.9",
                "192.168.10.1",
            ),
            (
                "2001:db8:2::66",
                "2001:db8:2::50",
                "2001:db8:ffff::9",
                "2001:db8:2::1",
            ),
        ] {
            let mut c = home();
            let done = block(&mut c, device.parse().unwrap(), "Smart TV").unwrap();
            assert_eq!(done.len(), 3, "{done:?}");
            assert_eq!(
                verdict(&c, device, dst, L4::Tcp, Some(443), "eth1").0,
                Verdict::Drop
            );
            assert_eq!(
                verdict(&c, device, me, L4::Tcp, Some(22), "eth1").0,
                Verdict::Drop
            );
            // Its neighbours are untouched.
            assert_eq!(
                verdict(&c, peer, dst, L4::Tcp, Some(443), "eth1").0,
                Verdict::Accept
            );
        }
        let mut c = home();
        let err = block(&mut c, "10.9.9.9".parse().unwrap(), "x").unwrap_err();
        assert!(err.contains("not on any network"));
    }

    #[test]
    fn a_device_config_fits_a_qr_code() {
        let config = "[Interface]\nPrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\nAddress = 10.90.0.2/32, fd90::2/128\nDNS = 10.90.0.1\n\n[Peer]\nPublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=\nEndpoint = home.example.net:51820\nAllowedIPs = 192.168.10.0/24, 2001:db8:2::/64\nPersistentKeepalive = 25\n";
        let rows = qr_rows(config).expect("fits");
        // Square, with a blank border of four on every side.
        assert!(rows.len() > 40 && rows.iter().all(|r| r.len() == rows.len()));
        assert!(rows[..4].iter().all(|r| !r.contains('1')));
        assert!(
            rows.iter()
                .all(|r| r.starts_with("0000") && r.ends_with("0000"))
        );
        // The finder pattern's top edge: seven dark squares at the corner.
        assert_eq!(&rows[4][4..11], "1111111");
        // The same text gives the same code, and other text another.
        assert_eq!(qr_rows(config), Some(rows.clone()));
        assert_ne!(qr_rows("other"), Some(rows.clone()));
        let drawn = qr_text(&rows);
        assert_eq!(drawn.lines().count(), rows.len().div_ceil(2));
        assert!(drawn.lines().all(|l| l.chars().count() == rows.len()));
        // Far too much for one code.
        assert!(qr_rows(&"x".repeat(10_000)).is_none());

        // An independent reader gets the config back from the picture, at
        // four pixels a square as the web UI draws it.
        const SCALE: usize = 4;
        let side = rows.len() * SCALE;
        let mut picture = rqrr::PreparedImage::prepare_from_greyscale(side, side, |x, y| {
            if rows[y / SCALE].as_bytes()[x / SCALE] == b'1' {
                0
            } else {
                255
            }
        });
        let grids = picture.detect_grids();
        assert_eq!(grids.len(), 1, "one code in the picture");
        let (_, read) = grids[0].decode().expect("the code reads");
        assert_eq!(read, config);
    }
}

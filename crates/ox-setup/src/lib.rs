//! The easy path: a guided setup and plain-language actions.
//!
//! Everything here writes ordinary Netoxide config. There is no second,
//! simpler format: `starter` returns the same [`Config`] a user could write
//! by hand, and the actions edit one in place. The advanced tools read and
//! change the result like any other config.

mod detect;

use std::net::IpAddr;

use ipnet::IpNet;
use ox_explain::{Packet, Verdict, explain};
use ox_nft::{L4, compile};
use ox_schema::{
    Action, AddrRef, Config, Forward, IfaceAddr, Interface, Nat, Net, Outbound, Policy, PortSpec,
    Proto, Rule, SCHEMA_VERSION, SELF_ZONE, ServiceRef, Translate, Zone, is_name,
};

pub use detect::{Detected, detect};

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
    };
    let mut config = Config {
        schema: SCHEMA_VERSION,
        hostname: a.hostname.clone(),
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
        interfaces: [(a.wan.name.clone(), iface(&a.wan, "wan", true))].into(),
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
    for f in &config.nat.forward {
        out.push(format!(
            "{} {} from {} is forwarded to {}{} ({})",
            f.address,
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
    let address = match req.address {
        Some(a) => a,
        None => wan
            .addresses
            .iter()
            .map(|a| a.0.addr())
            .find(|a| a.is_ipv4() == v4)
            .ok_or_else(|| {
                format!(
                    "{wan_name} has no fixed {} address in the config; say which outside address to forward with --address",
                    if v4 { "IPv4" } else { "IPv6" }
                )
            })?,
    };
    if address.is_ipv4() != v4 {
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
    // If an earlier rule decides first, move the new one to the top.
    let probe = Packet {
        src: if v4 {
            "198.51.100.7".parse().expect("valid")
        } else {
            "2001:db8:ffff::7".parse().expect("valid")
        },
        dst: address,
        l4: if proto == Proto::Tcp {
            L4::Tcp
        } else {
            L4::Udp
        },
        dport: Some(first),
        iif: wan_name.clone(),
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
            "{address} {} from {from} is forwarded to {}{} ({nat_id})",
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
        "checked: a packet from outside to {address} {} is accepted by {rule_id}",
        req.service
    ));
    Ok(out)
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
        })
        .unwrap();
        assert_eq!(c.zone_interfaces("lan"), ["eth1", "eth2"]);
        assert_eq!(c.addresses["inside"].len(), 2);
    }

    #[test]
    fn bad_answers_are_refused_in_plain_words() {
        let mut a = Answers {
            hostname: "x".into(),
            wan: port("eth0", &[]),
            lans: vec![],
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
}

//! Translates a pfSense `config.xml` backup into a Netoxide config and a
//! report.
//!
//! The importer never guesses. Every item of the backup lands in one of
//! three lists: translated one to one, changed (it works but differs, and
//! the report says how), or unsupported (it was left out, with the manual
//! step). A rule the importer cannot translate exactly is left out.
//!
//! pfSense writes rules per ingress interface. Netoxide writes them per zone
//! pair. Each pfSense interface becomes a zone, and a rule becomes one rule
//! in every zone pair its destination can reach, in the original order.
//!
//! [`Imported::verify`] replays packets through a model of the pfSense
//! ruleset and through the translated config, and reports any whose verdict
//! differs.
//!
//! Only pfSense backups are read. OPNsense uses a different layout.

mod pf;

use std::collections::BTreeMap;

use ipnet::IpNet;
use ox_explain::{Packet, Verdict, explain};
use ox_nft::compile;
use ox_schema::{
    Action, AddrRef, Config, Forward, IfaceAddr, Interface, Nat, Net, Outbound, Policy, PortSpec,
    Proto, Rule, SCHEMA_VERSION, SELF_ZONE, ServiceRef, Translate, Zone,
};

use pf::{Model, PfProto, Side};
pub use pf::{PfVerdict, probes};

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("not valid XML: {0}")]
    Xml(#[from] roxmltree::Error),
    #[error("this is an OPNsense backup; only pfSense backups are read so far")]
    Opnsense,
    #[error("this is not a pfSense backup: the root element is <{0}>")]
    NotPfsense(String),
    #[error(
        "the backup has no interfaces with an address, so there is nothing to build zones from"
    )]
    NoInterfaces,
    #[error(
        "importer bug: the translated config does not validate. Please report this with the backup.\n{0}"
    )]
    Invalid(String),
}

/// A pfSense item that works after import but differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changed {
    pub from: String,
    pub to: String,
}

/// A pfSense item that was left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported {
    pub item: String,
    pub step: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    /// Such as `pfSense config version 23.3`.
    pub source: String,
    pub translated: Vec<String>,
    pub changed: Vec<Changed>,
    pub unsupported: Vec<Unsupported>,
}

impl Report {
    pub fn total(&self) -> usize {
        self.translated.len() + self.changed.len() + self.unsupported.len()
    }

    fn changed(&mut self, from: impl Into<String>, to: impl Into<String>) {
        self.changed.push(Changed {
            from: from.into(),
            to: to.into(),
        });
    }

    fn unsupported(&mut self, item: impl Into<String>, step: impl Into<String>) {
        self.unsupported.push(Unsupported {
            item: item.into(),
            step: step.into(),
        });
    }
}

impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let total = self.total().max(1);
        writeln!(f, "{} · {} items", self.source, self.total())?;
        writeln!(
            f,
            "  {} translated one to one ({:.1}%)",
            self.translated.len(),
            100.0 * self.translated.len() as f64 / total as f64
        )?;
        writeln!(f, "  {} changed: works, but differs", self.changed.len())?;
        writeln!(
            f,
            "  {} unsupported: manual step needed",
            self.unsupported.len()
        )?;
        if !self.changed.is_empty() {
            writeln!(f, "\nchanged")?;
            for c in &self.changed {
                writeln!(f, "  {}\n    → {}", c.from, c.to)?;
            }
        }
        if !self.unsupported.is_empty() {
            writeln!(f, "\nunsupported")?;
            for u in &self.unsupported {
                writeln!(f, "  {}\n    manual step: {}", u.item, u.step)?;
            }
        }
        Ok(())
    }
}

/// A packet the two rulesets disagree on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    pub packet: Packet,
    pub pfsense: PfVerdict,
    pub netoxide: Verdict,
    /// The Netoxide rule that decided, or `default drop`.
    pub by: String,
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}  pfSense {} · Netoxide {} by {}",
            self.packet,
            self.pfsense,
            self.netoxide.as_str(),
            self.by
        )
    }
}

pub struct Imported {
    pub config: Config,
    pub report: Report,
    model: Model,
}

impl Imported {
    /// Replays packets through the pfSense model and the translated config.
    /// Returns the ones that get a different verdict. Packets that arrive on
    /// an interface the backup does not have are skipped.
    pub fn verify(&self, packets: &[Packet]) -> Vec<Mismatch> {
        let ruleset = compile(&self.config).expect("an imported config compiles");
        let mut out = vec![];
        for p in packets {
            let Some(old) = self.model.verdict(p) else {
                continue;
            };
            let Ok(new) = explain(&ruleset, p) else {
                continue;
            };
            let same = match &old {
                PfVerdict::Pass(_) => new.verdict == Verdict::Accept,
                PfVerdict::Block(_) | PfVerdict::DefaultBlock => new.verdict != Verdict::Accept,
                PfVerdict::Untranslated(_) => false,
            };
            if !same {
                out.push(Mismatch {
                    packet: p.clone(),
                    pfsense: old,
                    netoxide: new.verdict,
                    by: new.rule.map_or("default drop".to_string(), |r| r.id),
                });
            }
        }
        out
    }

    /// Packets that exercise every translated rule, for [`Imported::verify`].
    pub fn probes(&self) -> Vec<Packet> {
        probes(&self.model)
    }
}

/// Makes a pfSense name usable as a Netoxide name: lowercase letters, digits
/// and hyphens, starting with a letter, at most `max` long.
fn sanitize(raw: &str, max: usize) -> String {
    let mut s = String::new();
    for c in raw.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            s.push(c);
        } else if !s.ends_with('-') {
            s.push('-');
        }
    }
    let mut s = s.trim_matches('-').to_string();
    if !s.starts_with(|c: char| c.is_ascii_lowercase()) {
        s.insert(0, 'z');
    }
    s.truncate(max);
    s.trim_end_matches('-').to_string()
}

fn net_ref(n: &IpNet) -> AddrRef {
    AddrRef::Net(Net(n.trunc()))
}

/// The references to write for one side of a rule, limited to the rule's
/// address families. `None` means the side can match nothing.
fn side_refs(side: &Side, group: Option<&str>, v4: bool, v6: bool) -> Option<Vec<AddrRef>> {
    match side {
        Side::Any => Some(match (v4, v6) {
            (true, true) => vec![AddrRef::Any],
            (true, false) => vec![net_ref(&"0.0.0.0/0".parse().unwrap())],
            _ => vec![net_ref(&"::/0".parse().unwrap())],
        }),
        Side::Nets(nets) => {
            let kept: Vec<&IpNet> = nets
                .iter()
                .filter(|n| if n.addr().is_ipv4() { v4 } else { v6 })
                .collect();
            if kept.is_empty() {
                return None;
            }
            match group {
                Some(g) if kept.len() == nets.len() => Some(vec![AddrRef::Group(g.to_string())]),
                _ => Some(kept.into_iter().map(net_ref).collect()),
            }
        }
    }
}

fn families(refs: &[AddrRef], config_groups: &BTreeMap<String, Vec<Net>>) -> (bool, bool) {
    let mut out = (false, false);
    for r in refs {
        match r {
            AddrRef::Any => return (true, true),
            AddrRef::Net(n) => {
                if n.0.addr().is_ipv4() {
                    out.0 = true
                } else {
                    out.1 = true
                }
            }
            AddrRef::Group(g) => {
                for n in config_groups.get(g).into_iter().flatten() {
                    if n.0.addr().is_ipv4() {
                        out.0 = true
                    } else {
                        out.1 = true
                    }
                }
            }
        }
    }
    out
}

fn services(r: &pf::PRule) -> Vec<ServiceRef> {
    let ports = |proto: Proto| -> Vec<ServiceRef> {
        let ranges = if r.ports.is_empty() {
            vec![(1, 65535)]
        } else {
            r.ports.clone()
        };
        ranges
            .into_iter()
            .map(|(first, last)| ServiceRef::Port(PortSpec::Ports { proto, first, last }))
            .collect()
    };
    match r.proto {
        PfProto::Any => vec![ServiceRef::Any],
        PfProto::Tcp => ports(Proto::Tcp),
        PfProto::Udp => ports(Proto::Udp),
        PfProto::TcpUdp => [ports(Proto::Tcp), ports(Proto::Udp)].concat(),
        PfProto::Icmp => {
            let mut v = vec![];
            if r.v4 {
                v.push(ServiceRef::Port(PortSpec::Icmp));
            }
            if r.v6 {
                v.push(ServiceRef::Port(PortSpec::Icmpv6));
            }
            v
        }
    }
}

/// Reads a pfSense backup and translates it.
pub fn import_pfsense(xml: &str) -> Result<Imported, ImportError> {
    let doc = roxmltree::Document::parse(xml)?;
    let root = doc.root_element();
    match root.tag_name().name() {
        "pfsense" => {}
        "opnsense" => return Err(ImportError::Opnsense),
        other => return Err(ImportError::NotPfsense(other.to_string())),
    }
    let mut report = Report::default();
    let model = Model::parse(root, &mut report)?;
    report.source = format!("pfSense config version {}", model.version);

    let mut config = Config {
        schema: SCHEMA_VERSION,
        hostname: model.hostname.clone(),
        ipv6_autoconfig: vec![],
        zones: BTreeMap::new(),
        interfaces: BTreeMap::new(),
        addresses: BTreeMap::new(),
        services: BTreeMap::new(),
        policies: vec![],
        nat: Nat::default(),
        dns: None,
        dhcp: Default::default(),
        wireguard: Default::default(),
    };

    // Interfaces and zones.
    for i in &model.ifaces {
        config.zones.insert(
            i.zone.clone(),
            Zone {
                description: Some(format!("pfSense interface {} ({})", i.descr, i.key)),
            },
        );
        config.interfaces.insert(
            i.name.clone(),
            Interface {
                zone: i.zone.clone(),
                addresses: i
                    .v4
                    .iter()
                    .chain(i.v6.iter())
                    .map(|a| IfaceAddr(*a))
                    .collect(),
                default_route: i.gw4 || i.gw6,
                gateway: vec![],
                dhcp_client: false,
            },
        );
        report.translated.push(format!(
            "interface {} ({}) → zone {}",
            i.descr, i.name, i.zone
        ));
    }
    report.changed(
        format!(
            "Interface names {}",
            model
                .ifaces
                .iter()
                .map(|i| i.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        "kept as written; they are FreeBSD names, so rename them to the Linux names of the new box",
    );

    // Address groups.
    for (name, alias) in &model.aliases {
        if let pf::Alias::Nets { group, nets } = alias {
            config
                .addresses
                .insert(group.clone(), nets.iter().map(|n| Net(n.trunc())).collect());
            report
                .translated
                .push(format!("alias {name} → address group {group}"));
        }
    }

    // Filter rules, per ingress interface, in pfSense's evaluation order.
    let mut policies: Vec<Policy> = vec![];
    let mut emitted: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    let mut dropped: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for iface in &model.ifaces {
        for r in model.effective(&iface.key) {
            if r.untranslated.is_some() {
                continue;
            }
            let from = &iface.zone;
            for (to, dst) in model.buckets(r, &iface.key) {
                let pair = format!("{from} → {to}");
                let (Some(source), Some(destination)) = (
                    side_refs(&r.src, r.src_group.as_deref(), r.v4, r.v6),
                    side_refs(
                        &dst,
                        r.dst_group.as_deref().filter(|_| dst == r.dst),
                        r.v4,
                        r.v6,
                    ),
                ) else {
                    dropped.entry(r.n).or_default().push(pair);
                    continue;
                };
                let (s, d) = (
                    families(&source, &config.addresses),
                    families(&destination, &config.addresses),
                );
                if !((s.0 && d.0) || (s.1 && d.1)) {
                    dropped.entry(r.n).or_default().push(pair);
                    continue;
                }
                let many_ifaces = r.ifaces.len() > 1;
                let id = match (many_ifaces, model.buckets(r, &iface.key).len() > 1) {
                    (true, _) => format!("{}-{from}-{to}", r.id),
                    (false, true) => format!("{}-{to}", r.id),
                    (false, false) => r.id.clone(),
                };
                let rule = Rule {
                    id: id.clone(),
                    name: r.name.clone(),
                    action: r.action,
                    source,
                    destination,
                    service: services(r),
                    log: r.log,
                    enabled: !r.disabled,
                    reason: None,
                };
                match policies.iter_mut().find(|p| p.from == *from && p.to == to) {
                    Some(p) => p.rules.push(rule),
                    None => policies.push(Policy {
                        from: from.clone(),
                        to: to.clone(),
                        log_default: true,
                        rules: vec![rule],
                    }),
                }
                emitted
                    .entry(r.n)
                    .or_default()
                    .push(format!("{id} in {pair}"));
            }
        }
    }
    for r in &model.rules {
        let label = format!(
            "{} rule {} \"{}\"",
            if r.floating { "Floating" } else { "Filter" },
            r.n,
            r.name
        );
        if let Some(why) = &r.untranslated {
            let warn = if r.action == Action::Accept {
                "left out, so this traffic is dropped"
            } else {
                "left out; this was a block rule, so check that a later rule does not now allow the traffic"
            };
            report.unsupported(label, format!("{why}; {warn}"));
            continue;
        }
        let ids = emitted.get(&r.n).cloned().unwrap_or_default();
        let gone = dropped.get(&r.n).cloned().unwrap_or_default();
        match (ids.len(), gone.is_empty(), r.floating) {
            (0, _, _) => report.changed(
                label,
                "left out: its source and destination are on the same network or in different address families, so it could never match a routed packet",
            ),
            (1, true, false) => report.translated.push(format!("{label} → {}", ids[0])),
            _ => report.changed(label, format!("{} zone-pair rules: {}", ids.len(), ids.join(", "))),
        }
    }

    // The anti-lockout rule is implicit in pfSense. Here it is a rule you can see.
    if let Some(iface) = model.lockout() {
        let rule = Rule {
            id: "r-antilockout".into(),
            name: "Admin access to the firewall (pfSense anti-lockout)".into(),
            action: Action::Accept,
            source: vec![AddrRef::Any],
            // pfSense's rule covers the interface's own address only.
            destination: iface
                .v4
                .iter()
                .chain(iface.v6.iter())
                .map(|a| net_ref(&IpNet::from(a.addr())))
                .collect(),
            service: [443, 80, 22]
                .into_iter()
                .map(|p| {
                    ServiceRef::Port(PortSpec::Ports {
                        proto: Proto::Tcp,
                        first: p,
                        last: p,
                    })
                })
                .collect(),
            log: false,
            enabled: true,
            reason: None,
        };
        match policies
            .iter_mut()
            .find(|p| p.from == iface.zone && p.to == SELF_ZONE)
        {
            Some(p) => p.rules.insert(0, rule),
            None => policies.push(Policy {
                from: iface.zone.clone(),
                to: SELF_ZONE.into(),
                log_default: true,
                rules: vec![rule],
            }),
        }
        report.changed(
            format!("Implicit anti-lockout rule on {}", iface.descr),
            format!("explicit rule r-antilockout in {} → self; narrow its source once you have a management rule", iface.zone),
        );
    }

    // Port forwards.
    for f in &model.forwards {
        let label = format!("Port forward \"{}\"", f.name);
        if let Some(why) = &f.untranslated {
            report.unsupported(label, why.clone());
            continue;
        }
        let from = model
            .iface(&f.iface)
            .map(|i| i.zone.clone())
            .unwrap_or_default();
        let to = model.zone_of(f.target).unwrap_or_default();
        let rule_id = match &f.assoc {
            pf::Assoc::Pass => {
                let id = format!("r-fwd-{}", f.n);
                let rule = Rule {
                    id: id.clone(),
                    name: format!("{} (from port forward)", f.name),
                    action: Action::Accept,
                    source: vec![AddrRef::Any],
                    destination: vec![net_ref(&IpNet::from(f.target))],
                    service: vec![ServiceRef::Port(PortSpec::Ports {
                        proto: f.proto,
                        first: f.local_first,
                        last: f.local_first + (f.last - f.first),
                    })],
                    log: false,
                    enabled: true,
                    reason: None,
                };
                match policies.iter_mut().find(|p| p.from == from && p.to == to) {
                    Some(p) => p.rules.insert(0, rule),
                    None => policies.push(Policy {
                        from: from.clone(),
                        to: to.clone(),
                        log_default: true,
                        rules: vec![rule],
                    }),
                }
                report.changed(
                    format!("{label}, filter rule association \"Pass\""),
format!(
                        "NAT {} plus explicit rule {id} in {from} → {to}. Unlike pfSense, that rule also accepts packets sent straight to {}; review it",
                        f.id, f.target
                    ),
                );
                Some(id)
            }
            pf::Assoc::Rule(tag) => model
                .rules
                .iter()
                .find(|r| r.assoc.as_deref() == Some(tag) && r.untranslated.is_none())
                .and_then(|r| emitted.get(&r.n))
                .and_then(|ids| {
                    ids.iter()
                        .find(|i| i.ends_with(&format!(" in {from} → {to}")))
                })
                .and_then(|i| i.split(' ').next().map(String::from)),
            pf::Assoc::None => None,
        };
        let Some(rule) = rule_id else {
            report.unsupported(
                label,
                "it has no translated filter rule; add an accept rule for the internal host and name it in the forward",
            );
            continue;
        };
        config.nat.forward.push(Forward {
            id: f.id.clone(),
            name: f.name.clone(),
            from,
            address: Some(f.address),
            service: PortSpec::Ports {
                proto: f.proto,
                first: f.first,
                last: f.last,
            },
            to: f.target,
            to_port: (f.first == f.last && f.local_first != f.first).then_some(f.local_first),
            rule: rule.clone(),
        });
        if matches!(f.assoc, pf::Assoc::Rule(_)) {
            report
                .translated
                .push(format!("{label} → {} with filter rule {rule}", f.id));
        }
    }

    // Automatic outbound NAT is implicit in pfSense. Here it is written out.
    if model.outbound_auto {
        let mut made = vec![];
        for wan in model.ifaces.iter().filter(|i| i.gw4) {
            for lan in model.ifaces.iter().filter(|i| !i.gw4 && i.v4.is_some()) {
                let id = format!("n-out-{}-{}", lan.zone, wan.zone);
                config.nat.outbound.push(Outbound {
                    id: id.clone(),
                    name: format!("{} to {}", lan.descr, wan.descr),
                    from: lan.zone.clone(),
                    to: wan.zone.clone(),
                    source: vec![net_ref(&lan.v4.unwrap())],
                    translate: Translate::Masquerade,
                });
                made.push(id);
            }
        }
        if !made.is_empty() {
            report.changed(
                "Automatic outbound NAT",
                format!(
                    "{} explicit masquerade rules: {}",
                    made.len(),
                    made.join(", ")
                ),
            );
        }
    }

    config.policies = policies;
    let problems = config.validate();
    if !problems.is_empty() {
        return Err(ImportError::Invalid(
            problems
                .iter()
                .map(|p| format!("  {p}"))
                .collect::<Vec<_>>()
                .join("\n"),
        ));
    }
    compile(&config).map_err(|e| ImportError::Invalid(e.to_string()))?;
    Ok(Imported {
        config,
        report,
        model,
    })
}

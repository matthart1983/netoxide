//! Compiles a validated config into a [`Ruleset`], and renders that ruleset
//! as libnftables JSON.
//!
//! The ruleset is the single source for two consumers. `render` turns it
//! into what the kernel loads, and `ox-explain` evaluates packets against it.
//! Both read the same resolved addresses and ports, so an explanation cannot
//! drift from the rules that are loaded.
//!
//! Nothing here talks to the kernel. Applying the JSON is the daemon's job.

mod render;

use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use ox_schema::{Action, AddrRef, Config, PortSpec, Proto, ServiceRef, Translate};

pub use render::{Stats, list_command, render, render_empty};

/// Name of the nftables table Netoxide owns. Nothing else is touched.
pub const TABLE: &str = "netoxide";

/// The most nftables rules one chain may hold. Matching inside a rule uses
/// sets, so this bounds the rules a packet walks in order.
pub const MAX_CHAIN: usize = 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CompileError {
    #[error(
        "policy {from} → {to} compiles to {rules} nftables rules; the limit per chain is {MAX_CHAIN}. \
         Merge rules that share an action into one rule with more sources, destinations or services"
    )]
    ChainTooLong {
        from: String,
        to: String,
        rules: usize,
    },
}

/// A config with every reference resolved, ready to render or evaluate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    pub interfaces: Vec<Iface>,
    /// One chain per zone pair, in config order.
    pub chains: Vec<Chain>,
    pub forwards: Vec<Dnat>,
    pub outbound: Vec<Snat>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iface {
    pub name: String,
    pub zone: String,
    pub addrs: Vec<IpNet>,
    pub default_route: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub from: String,
    /// A zone, or `self`.
    pub to: String,
    pub log_default: bool,
    /// Enabled rules only, in order. First match wins.
    pub rules: Vec<CRule>,
}

impl Chain {
    /// The nftables chain name for this pair.
    pub fn name(&self) -> String {
        // Zone names cannot hold '_', so "__" keeps a-b → c apart from a → b-c.
        format!(
            "p_{}__{}",
            self.from.replace('-', "_"),
            self.to.replace('-', "_")
        )
    }

    /// How many nftables rules the chain renders to, without its final drop.
    pub fn nft_rules(&self) -> usize {
        self.rules.iter().map(|r| r.expansions().len()).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CRule {
    pub id: String,
    pub name: String,
    pub action: Action,
    pub log: bool,
    pub reason: Option<String>,
    pub src: AddrMatch,
    pub dst: AddrMatch,
    pub svc: SvcMatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// The transport protocols a packet can be described with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4 {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

impl L4 {
    pub fn as_str(self) -> &'static str {
        match self {
            L4::Tcp => "tcp",
            L4::Udp => "udp",
            L4::Icmp => "icmp",
            L4::Icmpv6 => "icmpv6",
        }
    }
}

/// Addresses a rule matches, with overlaps merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrMatch {
    Any,
    Nets { v4: Vec<Ipv4Net>, v6: Vec<Ipv6Net> },
}

impl AddrMatch {
    fn from_nets(nets: Option<Vec<IpNet>>) -> AddrMatch {
        let Some(nets) = nets else {
            return AddrMatch::Any;
        };
        let (mut v4, mut v6) = (vec![], vec![]);
        for n in nets {
            match n {
                IpNet::V4(n) => v4.push(n),
                IpNet::V6(n) => v6.push(n),
            }
        }
        // nftables refuses an interval set whose elements overlap.
        AddrMatch::Nets {
            v4: Ipv4Net::aggregate(&v4),
            v6: Ipv6Net::aggregate(&v6),
        }
    }

    pub fn matches(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (AddrMatch::Any, _) => true,
            (AddrMatch::Nets { v4, .. }, IpAddr::V4(a)) => v4.iter().any(|n| n.contains(&a)),
            (AddrMatch::Nets { v6, .. }, IpAddr::V6(a)) => v6.iter().any(|n| n.contains(&a)),
        }
    }

    fn allows(&self, family: Family) -> bool {
        match (self, family) {
            (AddrMatch::Any, _) => true,
            (AddrMatch::Nets { v4, .. }, Family::V4) => !v4.is_empty(),
            (AddrMatch::Nets { v6, .. }, Family::V6) => !v6.is_empty(),
        }
    }
}

/// Services a rule matches, with overlapping port ranges merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvcMatch {
    pub any: bool,
    /// Sorted, non-overlapping `(protocol, first, last)`.
    pub ports: Vec<(Proto, u16, u16)>,
    pub icmp: bool,
    pub icmpv6: bool,
}

impl SvcMatch {
    fn from_specs(specs: Option<Vec<PortSpec>>) -> SvcMatch {
        let mut m = SvcMatch {
            any: specs.is_none(),
            ports: vec![],
            icmp: false,
            icmpv6: false,
        };
        for s in specs.into_iter().flatten() {
            match s {
                PortSpec::Icmp => m.icmp = true,
                PortSpec::Icmpv6 => m.icmpv6 = true,
                PortSpec::Ports { proto, first, last } => m.ports.push((proto, first, last)),
            }
        }
        m.ports.sort();
        let mut merged: Vec<(Proto, u16, u16)> = vec![];
        for (proto, first, last) in m.ports.drain(..) {
            match merged.last_mut() {
                // Adjacent ranges merge too: 137 and 138 become 137-138.
                Some((p, _, end)) if *p == proto && first <= end.saturating_add(1) => {
                    *end = (*end).max(last);
                }
                _ => merged.push((proto, first, last)),
            }
        }
        m.ports = merged;
        m
    }

    pub fn matches(&self, l4: L4, dport: Option<u16>) -> bool {
        if self.any {
            return true;
        }
        let port_in = |want: Proto| {
            dport.is_some_and(|d| {
                self.ports
                    .iter()
                    .any(|(p, first, last)| *p == want && (*first..=*last).contains(&d))
            })
        };
        match l4 {
            L4::Tcp => port_in(Proto::Tcp),
            L4::Udp => port_in(Proto::Udp),
            L4::Icmp => self.icmp,
            L4::Icmpv6 => self.icmpv6,
        }
    }
}

/// Which part of a rule's service one nftables rule carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvcKind {
    All,
    Ports,
    Icmp,
    Icmpv6,
}

impl CRule {
    /// The nftables rules this rule becomes: one per address family and
    /// service kind that can match. A rule over IPv4 and IPv6 addresses needs
    /// two, because one nftables rule matches one family's address field.
    pub fn expansions(&self) -> Vec<(Option<Family>, SvcKind)> {
        let families: Vec<Option<Family>> =
            if self.src == AddrMatch::Any && self.dst == AddrMatch::Any {
                vec![None]
            } else {
                [Family::V4, Family::V6]
                    .into_iter()
                    .filter(|f| self.src.allows(*f) && self.dst.allows(*f))
                    .map(Some)
                    .collect()
            };
        let mut kinds = vec![];
        if self.svc.any {
            kinds.push(SvcKind::All);
        } else {
            if !self.svc.ports.is_empty() {
                kinds.push(SvcKind::Ports);
            }
            if self.svc.icmp {
                kinds.push(SvcKind::Icmp);
            }
            if self.svc.icmpv6 {
                kinds.push(SvcKind::Icmpv6);
            }
        }
        let mut out = vec![];
        for f in &families {
            for k in &kinds {
                let fits = !matches!(
                    (f, k),
                    (Some(Family::V6), SvcKind::Icmp) | (Some(Family::V4), SvcKind::Icmpv6)
                );
                if fits {
                    out.push((*f, *k));
                }
            }
        }
        out
    }

    /// True when this rule matches the packet. This is the same test the
    /// rendered nftables rules perform.
    pub fn matches(&self, src: IpAddr, dst: IpAddr, l4: L4, dport: Option<u16>) -> bool {
        self.src.matches(src) && self.dst.matches(dst) && self.svc.matches(l4, dport)
    }
}

/// A port forward with its zone resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnat {
    pub id: String,
    pub name: String,
    pub from: String,
    pub address: IpAddr,
    pub proto: Proto,
    pub first: u16,
    pub last: u16,
    pub to: IpAddr,
    pub to_port: Option<u16>,
    pub rule: String,
}

impl Dnat {
    pub fn matches(&self, zone: &str, dst: IpAddr, l4: L4, dport: Option<u16>) -> bool {
        let proto_ok = matches!(
            (self.proto, l4),
            (Proto::Tcp, L4::Tcp) | (Proto::Udp, L4::Udp)
        );
        self.from == zone
            && self.address == dst
            && proto_ok
            && dport.is_some_and(|d| (self.first..=self.last).contains(&d))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snat {
    pub id: String,
    pub name: String,
    pub from: String,
    pub to: String,
    pub src: AddrMatch,
    pub translate: Translate,
}

impl Snat {
    pub fn matches(&self, from: &str, to: &str, src: IpAddr) -> bool {
        let family_ok = match self.translate {
            Translate::Masquerade => true,
            Translate::Address(a) => a.is_ipv4() == src.is_ipv4(),
        };
        self.from == from && self.to == to && family_ok && self.src.matches(src)
    }
}

impl Ruleset {
    /// Interfaces in a zone, in name order.
    pub fn zone_interfaces(&self, zone: &str) -> Vec<&str> {
        self.interfaces
            .iter()
            .filter(|i| i.zone == zone)
            .map(|i| i.name.as_str())
            .collect()
    }

    pub fn chain(&self, from: &str, to: &str) -> Option<&Chain> {
        self.chains.iter().find(|c| c.from == from && c.to == to)
    }
}

impl Ruleset {
    /// One line of counts, as shown by `ox validate` and `ox plan`.
    pub fn summary(&self) -> String {
        let (_, s) = render(self);
        let config_rules: usize = self.chains.iter().map(|c| c.rules.len()).sum();
        format!(
            "{config_rules} rules in {} zone pairs → {} nftables rules, {} sets, {} verdict maps, longest chain {}",
            self.chains.len(),
            s.rules,
            s.sets,
            s.verdict_maps,
            s.longest_chain
        )
    }
}

/// Resolves a validated config into a ruleset.
pub fn compile(config: &Config) -> Result<Ruleset, CompileError> {
    let addrs = |refs: &[AddrRef]| AddrMatch::from_nets(config.resolve_addrs(refs));
    let services = |refs: &[ServiceRef]| SvcMatch::from_specs(config.resolve_services(refs));

    let mut chains = vec![];
    for p in &config.policies {
        let chain = Chain {
            from: p.from.clone(),
            to: p.to.clone(),
            log_default: p.log_default,
            rules: p
                .rules
                .iter()
                .filter(|r| r.enabled)
                .map(|r| CRule {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    action: r.action,
                    log: r.log,
                    reason: r.reason.clone(),
                    src: addrs(&r.source),
                    dst: addrs(&r.destination),
                    svc: services(&r.service),
                })
                .collect(),
        };
        let rules = chain.nft_rules();
        if rules > MAX_CHAIN {
            return Err(CompileError::ChainTooLong {
                from: chain.from,
                to: chain.to,
                rules,
            });
        }
        chains.push(chain);
    }

    Ok(Ruleset {
        interfaces: config
            .interfaces
            .iter()
            .map(|(name, i)| Iface {
                name: name.clone(),
                zone: i.zone.clone(),
                addrs: i.addresses.iter().map(|a| a.0).collect(),
                default_route: i.default_route,
            })
            .collect(),
        chains,
        forwards: config
            .nat
            .forward
            .iter()
            .filter_map(|f| match f.service {
                PortSpec::Ports { proto, first, last } => Some(Dnat {
                    id: f.id.clone(),
                    name: f.name.clone(),
                    from: f.from.clone(),
                    address: f.address,
                    proto,
                    first,
                    last,
                    to: f.to,
                    to_port: f.to_port,
                    rule: f.rule.clone(),
                }),
                // Validation refuses a forward on ICMP.
                _ => None,
            })
            .collect(),
        outbound: config
            .nat
            .outbound
            .iter()
            .map(|o| Snat {
                id: o.id.clone(),
                name: o.name.clone(),
                from: o.from.clone(),
                to: o.to.clone(),
                src: addrs(&o.source),
                translate: o.translate,
            })
            .collect(),
    })
}

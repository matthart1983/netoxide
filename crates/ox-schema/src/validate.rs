//! Checks that need the whole document: references, uniqueness and address
//! families. Parsing has already checked each value on its own.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::{
    Action, AddrRef, Config, PortSpec, SCHEMA_VERSION, SELF_ZONE, ServiceRef, Translate, is_name,
};

/// One thing wrong with a config, with where it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// Where in the document, such as `policy lan → dmz, rule r-0412`.
    pub at: String,
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.at, self.message)
    }
}

/// Linux limits interface names to 15 bytes.
const IFNAMSIZ: usize = 15;

/// Rule and NAT IDs: a letter, then letters, digits and hyphens, at most 32.
fn is_id(s: &str) -> bool {
    is_name(s)
}

impl Config {
    /// Returns every problem found. An empty list means the config is valid.
    pub fn validate(&self) -> Vec<Problem> {
        let mut out = Checker {
            config: self,
            problems: vec![],
        };
        out.run();
        out.problems
    }
}

struct Checker<'a> {
    config: &'a Config,
    problems: Vec<Problem>,
}

impl Checker<'_> {
    fn add(&mut self, at: impl Into<String>, message: impl Into<String>) {
        self.problems.push(Problem {
            at: at.into(),
            message: message.into(),
        });
    }

    fn run(&mut self) {
        let c = self.config;
        if c.schema != SCHEMA_VERSION {
            self.add(
                "schema",
                format!(
                    "this build reads schema {SCHEMA_VERSION}, the file says {}",
                    c.schema
                ),
            );
        }
        if c.hostname.is_empty() {
            self.add("hostname", "must not be empty");
        }
        self.zones_and_interfaces();
        self.objects();
        self.policies();
        self.nat();
    }

    fn zones_and_interfaces(&mut self) {
        let c = self.config;
        for name in c.zones.keys() {
            if !is_name(name) {
                self.add(
                    format!("zone {name}"),
                    "zone names are lowercase letters, digits and hyphens, starting with a letter",
                );
            }
            if name == SELF_ZONE || name == "any" {
                self.add(format!("zone {name}"), "this name is reserved");
            }
        }
        for (name, iface) in &c.interfaces {
            let at = format!("interface {name}");
            let ok_chars = name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'));
            if name.is_empty() || name.len() > IFNAMSIZ || !ok_chars {
                self.add(
                    &at,
                    format!("interface names are 1 to {IFNAMSIZ} letters, digits, '.', '-' or '_'"),
                );
            }
            if !c.zones.contains_key(&iface.zone) {
                self.add(&at, format!("zone '{}' is not defined", iface.zone));
            }
        }
        for family in ["IPv4", "IPv6"] {
            let with_default: Vec<&str> = c
                .interfaces
                .iter()
                .filter(|(_, i)| {
                    i.default_route
                        && i.addresses
                            .iter()
                            .any(|a| a.0.addr().is_ipv4() == (family == "IPv4"))
                })
                .map(|(n, _)| n.as_str())
                .collect();
            if with_default.len() > 1 {
                self.add(
                    "interfaces",
                    format!(
                        "{} all carry the {family} default route; schema 1 allows one",
                        with_default.join(", ")
                    ),
                );
            }
        }
    }

    fn objects(&mut self) {
        let c = self.config;
        for (name, nets) in &c.addresses {
            let at = format!("address group {name}");
            if !is_name(name) {
                self.add(&at, "group names are lowercase letters, digits and hyphens");
            }
            if nets.is_empty() {
                self.add(&at, "is empty, so a rule using it would match nothing");
            }
        }
        for (name, ports) in &c.services {
            let at = format!("service {name}");
            if !is_name(name) || name == "any" || name == "icmp" || name == "icmpv6" {
                self.add(&at, "is not a usable service name");
            }
            if ports.is_empty() {
                self.add(&at, "is empty, so a rule using it would match nothing");
            }
        }
    }

    fn check_addr_refs(&mut self, at: &str, field: &str, refs: &[AddrRef]) {
        if refs.is_empty() {
            self.add(
                at,
                format!("{field} is empty; write \"any\" to match everything"),
            );
        }
        if refs.len() > 1 && refs.contains(&AddrRef::Any) {
            self.add(at, format!("{field} mixes \"any\" with other entries"));
        }
        for r in refs {
            if let AddrRef::Group(g) = r
                && !self.config.addresses.contains_key(g)
            {
                self.add(
                    at,
                    format!("{field} names address group '@{g}', which is not defined"),
                );
            }
        }
    }

    fn check_service_refs(&mut self, at: &str, refs: &[ServiceRef]) {
        if refs.is_empty() {
            self.add(at, "service is empty; write \"any\" to match everything");
        }
        if refs.len() > 1 && refs.contains(&ServiceRef::Any) {
            self.add(at, "service mixes \"any\" with other entries");
        }
        for r in refs {
            if let ServiceRef::Named(n) = r
                && !self.config.services.contains_key(n)
            {
                self.add(at, format!("service '{n}' is not defined"));
            }
        }
    }

    /// The address families a side of a rule can match: (IPv4, IPv6).
    fn families(&self, refs: &[AddrRef]) -> (bool, bool) {
        match self.config.resolve_addrs(refs) {
            None => (true, true),
            Some(nets) => (
                nets.iter().any(|n| n.addr().is_ipv4()),
                nets.iter().any(|n| n.addr().is_ipv6()),
            ),
        }
    }

    fn policies(&mut self) {
        let c = self.config;
        let mut pairs = BTreeSet::new();
        let mut ids: BTreeMap<&str, String> = BTreeMap::new();
        for p in &c.policies {
            let pair = format!("policy {} → {}", p.from, p.to);
            if p.from == SELF_ZONE {
                self.add(
                    &pair,
                    "rules for traffic sent by the box itself are not in schema 1; it is allowed out",
                );
            } else if !c.zones.contains_key(&p.from) {
                self.add(&pair, format!("zone '{}' is not defined", p.from));
            } else if c.zone_interfaces(&p.from).is_empty() {
                self.add(&pair, format!("zone '{}' has no interfaces", p.from));
            }
            if p.to != SELF_ZONE {
                if !c.zones.contains_key(&p.to) {
                    self.add(&pair, format!("zone '{}' is not defined", p.to));
                } else if c.zone_interfaces(&p.to).is_empty() {
                    self.add(&pair, format!("zone '{}' has no interfaces", p.to));
                }
            }
            if !pairs.insert((&p.from, &p.to)) {
                self.add(
                    &pair,
                    "this zone pair appears twice; merge the rules into one policy",
                );
            }
            for r in &p.rules {
                let at = format!("{pair}, rule {}", r.id);
                if !is_id(&r.id) {
                    self.add(
                        &at,
                        "rule IDs are lowercase letters, digits and hyphens, starting with a letter",
                    );
                }
                if let Some(first) = ids.insert(&r.id, pair.clone()) {
                    self.add(&at, format!("this ID is already used in {first}"));
                }
                if r.name.is_empty() {
                    self.add(&at, "name must not be empty");
                }
                self.check_addr_refs(&at, "source", &r.source);
                self.check_addr_refs(&at, "destination", &r.destination);
                self.check_service_refs(&at, &r.service);

                let (s4, s6) = self.families(&r.source);
                let (d4, d6) = self.families(&r.destination);
                let (v4, v6) = (s4 && d4, s6 && d6);
                if !v4 && !v6 {
                    self.add(
                        &at,
                        "source and destination are different address families, so it can never match",
                    );
                }
                if let Some(specs) = c.resolve_services(&r.service) {
                    let only =
                        |want: PortSpec| !specs.is_empty() && specs.iter().all(|s| *s == want);
                    if only(PortSpec::Icmp) && !v4 {
                        self.add(
                            &at,
                            "matches icmp, but its addresses are IPv6 only; use icmpv6",
                        );
                    }
                    if only(PortSpec::Icmpv6) && !v6 {
                        self.add(
                            &at,
                            "matches icmpv6, but its addresses are IPv4 only; use icmp",
                        );
                    }
                }
            }
        }
    }

    fn nat(&mut self) {
        let c = self.config;
        let mut ids = BTreeSet::new();
        for f in &c.nat.forward {
            let at = format!("nat forward {}", f.id);
            if !is_id(&f.id) || !ids.insert(&f.id) {
                self.add(&at, "NAT IDs must be unique lowercase names");
            }
            if !c.zones.contains_key(&f.from) {
                self.add(&at, format!("zone '{}' is not defined", f.from));
            }
            if !matches!(f.service, PortSpec::Ports { .. }) {
                self.add(&at, "service must be a TCP or UDP port");
            }
            if let PortSpec::Ports { first, last, .. } = f.service
                && first != last
                && f.to_port.is_some()
            {
                self.add(
                    &at,
                    "to_port cannot be set when the service is a port range",
                );
            }
            if f.address.is_ipv4() != f.to.is_ipv4() {
                self.add(&at, "address and to are different address families");
            }
            // The forward must name a real accept rule in a policy from the same zone.
            match c.rules().find(|(_, r)| r.id == f.rule) {
                None => self.add(&at, format!("filter rule '{}' does not exist", f.rule)),
                Some((p, r)) => {
                    if p.from != f.from {
                        self.add(
                            &at,
                            format!(
                                "filter rule '{}' is in policy {} → {}, not a policy from '{}'",
                                f.rule, p.from, p.to, f.from
                            ),
                        );
                    }
                    if r.action != Action::Accept {
                        self.add(&at, format!("filter rule '{}' does not accept", f.rule));
                    }
                }
            }
        }
        for o in &c.nat.outbound {
            let at = format!("nat outbound {}", o.id);
            if !is_id(&o.id) || !ids.insert(&o.id) {
                self.add(&at, "NAT IDs must be unique lowercase names");
            }
            for z in [&o.from, &o.to] {
                if !c.zones.contains_key(z) {
                    self.add(&at, format!("zone '{z}' is not defined"));
                }
            }
            self.check_addr_refs(&at, "source", &o.source);
            if let Translate::Address(a) = o.translate {
                let (s4, s6) = self.families(&o.source);
                if (a.is_ipv4() && !s4) || (a.is_ipv6() && !s6) {
                    self.add(
                        &at,
                        "translate address and source are different address families",
                    );
                }
            }
        }
    }
}

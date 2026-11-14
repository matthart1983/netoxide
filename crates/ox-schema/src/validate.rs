//! Checks that need the whole document: references, uniqueness and address
//! families. Parsing has already checked each value on its own.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::{
    Action, AddrRef, Config, PortSpec, Proto, SCHEMA_VERSION, SELF_ZONE, ServiceRef, Translate,
    is_hostname, is_name,
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
        if !is_hostname(&c.hostname) {
            self.add(
                "hostname",
                "must be a host name: letters, digits and hyphens, with dots between parts",
            );
        }
        self.zones_and_interfaces();
        self.objects();
        self.policies();
        self.nat();
        self.services();
        self.wireguard();
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
            // The kernel keeps settings for every interface under these
            // names, so an interface cannot have them.
            if matches!(name.as_str(), "." | ".." | "all" | "default") {
                self.add(&at, "this name is reserved by the kernel");
            }
            if name.is_empty() || name.len() > IFNAMSIZ || !ok_chars {
                self.add(
                    &at,
                    format!("interface names are 1 to {IFNAMSIZ} letters, digits, '.', '-' or '_'"),
                );
            }
            if !c.zones.contains_key(&iface.zone) {
                self.add(&at, format!("zone '{}' is not defined", iface.zone));
            }
            self.uplink(&at, iface);
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

    fn wireguard(&mut self) {
        let c = self.config;
        for (name, wg) in &c.wireguard {
            let at = format!("wireguard {name}");
            let ok_chars = name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'));
            if name.is_empty()
                || name.len() > IFNAMSIZ
                || !ok_chars
                || matches!(name.as_str(), "." | ".." | "all" | "default")
            {
                self.add(
                    &at,
                    format!("interface names are 1 to {IFNAMSIZ} letters, digits, '.', '-' or '_'"),
                );
            }
            if c.interfaces.contains_key(name) {
                self.add(
                    &at,
                    "an interface with this name is already in [interfaces]",
                );
            }
            if !c.zones.contains_key(&wg.zone) {
                self.add(&at, format!("zone '{}' is not defined", wg.zone));
            }
            match wg.listen_port {
                Some(0) => self.add(&at, "listen_port 0 is not a port"),
                Some(port) => {
                    let open = c
                        .zones
                        .keys()
                        .any(|zone| self.box_accepts(zone, Proto::Udp, port));
                    if !open {
                        self.add(
                            &at,
                            format!(
                                "peers connect to udp/{port} on the box, but no rule to self accepts it; \
                                 add an accept rule for udp/{port} in the policy from the zone they arrive by"
                            ),
                        );
                    }
                }
                None => {
                    if !wg.peers.is_empty() && wg.peers.iter().all(|p| p.endpoint.is_none()) {
                        self.add(
                            &at,
                            "nothing could start this tunnel: set listen_port so peers can connect, \
                             or give a peer an endpoint to connect to",
                        );
                    }
                }
            }
            let (mut names, mut keys, mut nets) =
                (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
            for peer in &wg.peers {
                let at = format!("{at}, peer {}", peer.name);
                if !is_name(&peer.name) {
                    self.add(
                        &at,
                        "peer names are lowercase letters, digits and hyphens, starting with a letter",
                    );
                }
                if !names.insert(&peer.name) {
                    self.add(&at, "this name is used by another peer");
                }
                if crate::decode_key(&peer.public_key).is_none() {
                    self.add(
                        &at,
                        "public_key is not a WireGuard key: 44 characters ending in '='",
                    );
                } else if !keys.insert(&peer.public_key) {
                    self.add(&at, "this public key is used by another peer");
                }
                if peer.allowed.is_empty() {
                    self.add(
                        &at,
                        "allowed is empty, so nothing could be sent to or accepted from this peer",
                    );
                }
                for net in &peer.allowed {
                    if !nets.insert(net.0.trunc()) {
                        self.add(
                            &at,
                            format!("{} is also allowed for another peer; WireGuard sends each address to one peer", net.0),
                        );
                    }
                }
                if peer.endpoint.is_some_and(|e| e.port() == 0) {
                    self.add(&at, "endpoint needs a port");
                }
                if peer.keepalive == Some(0) {
                    self.add(&at, "keepalive 0 means off; leave it out");
                }
            }
        }
    }

    /// The settings that say how an interface reaches the internet.
    fn uplink(&mut self, at: &str, iface: &crate::Interface) {
        if (iface.dhcp_client || !iface.gateway.is_empty()) && !iface.default_route {
            self.add(
                at,
                "gateway and dhcp_client belong on the interface that carries the default route; \
                 set default_route = true",
            );
            return;
        }
        for v4 in [true, false] {
            let family = if v4 { "IPv4" } else { "IPv6" };
            let gateways: Vec<std::net::IpAddr> = iface
                .gateway
                .iter()
                .copied()
                .filter(|g| g.is_ipv4() == v4)
                .collect();
            if gateways.len() > 1 {
                self.add(
                    at,
                    format!("more than one {family} gateway; schema 1 allows one"),
                );
            }
            for g in gateways {
                let link_local =
                    matches!(g, std::net::IpAddr::V6(a) if a.segments()[0] & 0xffc0 == 0xfe80);
                let on_link = iface.addresses.iter().any(|a| a.0.contains(&g));
                if iface.addresses.iter().any(|a| a.0.addr() == g) {
                    self.add(at, format!("gateway {g} is the box's own address"));
                } else if !on_link && !link_local {
                    self.add(
                        at,
                        format!(
                            "gateway {g} is not in any network this interface has an address in"
                        ),
                    );
                }
            }
        }
        if !iface.dhcp_client {
            return;
        }
        if iface.addresses.iter().any(|a| a.0.addr().is_ipv4()) {
            self.add(
                at,
                "dhcp_client asks the network for the IPv4 address, so list no fixed IPv4 address here",
            );
        }
        if iface.gateway.iter().any(std::net::IpAddr::is_ipv4) {
            self.add(
                at,
                "dhcp_client gets the router from the network, so list no IPv4 gateway here",
            );
        }
        if !self.box_accepts(&iface.zone, Proto::Udp, 68) {
            self.add(
                at,
                format!(
                    "the box asks for its address here, but no rule in {} → self accepts the \
                     answer; add an accept rule there for udp/68",
                    iface.zone
                ),
            );
        }
        if self.self_accepts(&iface.zone, Proto::Udp, 67) == Some(false) {
            self.add(
                at,
                format!(
                    "the policy self → {} filters what the box sends there and does not accept \
                     its DHCP requests; add an accept rule there for udp/67",
                    iface.zone
                ),
            );
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
                // Traffic the box itself sends. It needs somewhere to go.
                if p.to == SELF_ZONE {
                    self.add(
                        &pair,
                        "the box talking to itself is always allowed and takes no rules",
                    );
                }
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
            if f.address.is_some_and(|a| a.is_ipv4() != f.to.is_ipv4()) {
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

    /// True when an enabled accept rule lets this port in from a zone to the box.
    fn box_accepts(&self, zone: &str, proto: Proto, port: u16) -> bool {
        self.config
            .policies
            .iter()
            .filter(|p| p.from == zone && p.to == SELF_ZONE)
            .flat_map(|p| &p.rules)
            .filter(|r| r.enabled && r.action == Action::Accept)
            .any(|r| match self.config.resolve_services(&r.service) {
                None => true,
                Some(specs) => specs.iter().any(|s| {
                    matches!(s, PortSpec::Ports { proto: p, first, last }
                        if *p == proto && (*first..=*last).contains(&port))
                }),
            })
    }

    /// Whether a policy for traffic the box sends to a zone accepts this
    /// port. `None` when there is no such policy, which means it is allowed.
    fn self_accepts(&self, to: &str, proto: Proto, port: u16) -> Option<bool> {
        let policy = self
            .config
            .policies
            .iter()
            .find(|p| p.from == SELF_ZONE && p.to == to)?;
        Some(
            policy
                .rules
                .iter()
                .filter(|r| r.enabled && r.action == Action::Accept)
                .any(|r| match self.config.resolve_services(&r.service) {
                    None => true,
                    Some(specs) => specs.iter().any(|s| {
                        matches!(s, PortSpec::Ports { proto: p, first, last }
                            if *p == proto && (*first..=*last).contains(&port))
                    }),
                }),
        )
    }

    fn services(&mut self) {
        let c = self.config;
        if let Some(dns) = &c.dns {
            if dns.zones.is_empty() {
                self.add("dns", "zones is empty, so nobody could use the resolver");
            }
            if dns.upstream.is_empty() {
                self.add(
                    "dns",
                    "upstream is empty; name at least one resolver to forward to, such as 1.1.1.1",
                );
            }
            if let Some(d) = &dns.domain
                && !is_hostname(d)
            {
                self.add("dns", format!("domain '{d}' is not a valid domain name"));
            }
            for zone in &dns.zones {
                let at = format!("dns, zone {zone}");
                if !c.zones.contains_key(zone) {
                    self.add(&at, "this zone is not defined");
                    continue;
                }
                let has_address = c
                    .interfaces
                    .values()
                    .any(|i| i.zone == *zone && !i.addresses.is_empty())
                    || c.wireguard
                        .values()
                        .any(|w| w.zone == *zone && !w.addresses.is_empty());
                if !has_address {
                    self.add(
                        &at,
                        "no interface in this zone has an address for clients to send queries to",
                    );
                }
                if !(self.box_accepts(zone, Proto::Udp, 53)
                    && self.box_accepts(zone, Proto::Tcp, 53))
                {
                    self.add(
                        &at,
                        format!(
                            "the resolver serves this zone, but no rule in {zone} → self accepts DNS; \
                             add an accept rule there for udp/53 and tcp/53"
                        ),
                    );
                }
            }
            // The resolver forwards to its upstreams by the default route. If
            // the box's own traffic to that zone is filtered, DNS must be let out.
            for zone in c
                .interfaces
                .values()
                .filter(|i| i.default_route)
                .map(|i| i.zone.as_str())
                .collect::<BTreeSet<_>>()
            {
                let out = |proto| self.self_accepts(zone, proto, 53);
                if out(Proto::Udp) == Some(false) || out(Proto::Tcp) == Some(false) {
                    self.add(
                        "dns",
                        format!(
                            "the resolver forwards queries out by zone {zone}, but the policy self → {zone} \
                             does not accept DNS; add an accept rule there for udp/53 and tcp/53"
                        ),
                    );
                }
            }
            let mut names = BTreeSet::new();
            for h in &dns.hosts {
                let at = format!("dns host {}", h.name);
                if !is_hostname(&h.name) {
                    self.add(
                        &at,
                        "names are letters, digits and hyphens, with dots between labels",
                    );
                }
                if !names.insert((h.name.to_ascii_lowercase(), h.address.is_ipv4())) {
                    self.add(&at, "this name is listed twice for the same address family");
                }
            }
        }

        let mut announced = BTreeSet::new();
        for name in &c.ipv6_autoconfig {
            let at = format!("ipv6_autoconfig {name}");
            if !announced.insert(name) {
                self.add(&at, "this interface is listed twice");
            }
            match c.interfaces.get(name) {
                None => self.add(&at, "this interface is not defined"),
                Some(i) => {
                    // Devices build their address from a 64-bit network.
                    let ok = i
                        .addresses
                        .iter()
                        .any(|a| a.0.addr().is_ipv6() && a.0.prefix_len() == 64);
                    if !ok {
                        self.add(
                            &at,
                            "the interface needs an IPv6 address with a /64 prefix to announce",
                        );
                    }
                }
            }
        }

        let mut macs = BTreeSet::new();
        for (name, pool) in &c.dhcp {
            let at = format!("dhcp {name}");
            let Some(iface) = c.interfaces.get(name) else {
                self.add(&at, "this interface is not defined");
                continue;
            };
            let Some(own) = iface
                .addresses
                .iter()
                .map(|a| a.0)
                .find(|a| a.addr().is_ipv4())
            else {
                self.add(&at, "the interface has no IPv4 address, so there is no network to hand addresses out on");
                continue;
            };
            let subnet = own.trunc();
            let usable = |ip: std::net::Ipv4Addr| {
                let ip = std::net::IpAddr::V4(ip);
                subnet.contains(&ip) && ip != subnet.network() && ip != subnet.broadcast()
            };
            if pool.first > pool.last {
                self.add(
                    &at,
                    format!(
                        "the pool runs backwards: {} is after {}",
                        pool.first, pool.last
                    ),
                );
            }
            for ip in [pool.first, pool.last] {
                if !usable(ip) {
                    self.add(&at, format!("{ip} is not a usable address on {subnet}"));
                }
            }
            if let std::net::IpAddr::V4(me) = own.addr()
                && (pool.first..=pool.last).contains(&me)
            {
                self.add(
                    &at,
                    format!("the pool includes {me}, the box's own address"),
                );
            }
            let served = c
                .dns
                .as_ref()
                .is_some_and(|d| d.zones.contains(&iface.zone));
            if pool.dns.is_empty() && !served {
                self.add(
                    &at,
                    format!(
                        "clients need a DNS server: add zone '{}' to [dns] zones, or list servers in dns",
                        iface.zone
                    ),
                );
            }
            if !self.box_accepts(&iface.zone, Proto::Udp, 67) {
                self.add(
                    &at,
                    format!(
                        "addresses are handed out here, but no rule in {} → self accepts DHCP; \
                         add an accept rule there for udp/67",
                        iface.zone
                    ),
                );
            }
            if self.self_accepts(&iface.zone, Proto::Udp, 68) == Some(false) {
                self.add(
                    &at,
                    format!(
                        "the policy self → {} filters what the box sends there and does not accept \
                         DHCP replies; add an accept rule there for udp/68",
                        iface.zone
                    ),
                );
            }
            let mut addrs = BTreeSet::new();
            for st in &pool.statics {
                let at = format!("{at}, static {}", st.mac);
                if !usable(st.address) {
                    self.add(
                        &at,
                        format!("{} is not a usable address on {subnet}", st.address),
                    );
                }
                if std::net::IpAddr::V4(st.address) == own.addr() {
                    self.add(&at, "this is the box's own address");
                }
                if !macs.insert(st.mac) {
                    self.add(&at, "this hardware address has more than one static lease");
                }
                if !addrs.insert(st.address) {
                    self.add(
                        &at,
                        format!("{} is given to more than one device", st.address),
                    );
                }
                if let Some(n) = &st.name
                    && (!is_hostname(n) || n.contains('.'))
                {
                    self.add(
                        &at,
                        format!("name '{n}' must be one label of letters, digits and hyphens"),
                    );
                }
            }
        }
    }
}

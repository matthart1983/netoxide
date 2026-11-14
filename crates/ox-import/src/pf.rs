//! A model of a pfSense backup: its interfaces, aliases, filter rules and
//! port forwards, and how pfSense itself would judge a packet.
//!
//! The model keeps rules the importer cannot translate, marked with the
//! reason, so `verdict` can say when one of them would have decided a packet.

use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnet::IpNet;
use ox_explain::Packet;
use ox_nft::L4;
use ox_schema::{Action, Proto, SELF_ZONE};
use roxmltree::Node;

use crate::{ImportError, Report, sanitize};

pub struct Iface {
    /// pfSense's key: `wan`, `lan`, `opt1`.
    pub key: String,
    /// The kernel interface name, such as `igb1`.
    pub name: String,
    pub descr: String,
    pub zone: String,
    /// Address with prefix length, such as 10.40.0.1/16.
    pub v4: Option<IpNet>,
    pub v6: Option<IpNet>,
    pub gw4: bool,
    pub gw6: bool,
}

impl Iface {
    fn addrs(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.v4.iter().chain(self.v6.iter()).copied()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Side {
    Any,
    Nets(Vec<IpNet>),
}

impl Side {
    fn matches(&self, ip: IpAddr) -> bool {
        match self {
            Side::Any => true,
            Side::Nets(nets) => nets.iter().any(|n| n.contains(&ip)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PfProto {
    Any,
    Tcp,
    Udp,
    TcpUdp,
    Icmp,
}

pub struct PRule {
    /// 1-based position in the backup's filter section.
    pub n: usize,
    pub id: String,
    pub name: String,
    pub ifaces: Vec<String>,
    pub floating: bool,
    pub action: Action,
    pub v4: bool,
    pub v6: bool,
    pub proto: PfProto,
    pub src: Side,
    pub dst: Side,
    /// The address group to write instead of the networks, when the side is one alias.
    pub src_group: Option<String>,
    pub dst_group: Option<String>,
    /// Destination port ranges. Empty means any port.
    pub ports: Vec<(u16, u16)>,
    pub log: bool,
    pub disabled: bool,
    pub assoc: Option<String>,
    /// Why the rule cannot be translated exactly.
    pub untranslated: Option<String>,
}

pub enum Alias {
    Nets { group: String, nets: Vec<IpNet> },
    Ports(Vec<(u16, u16)>),
    Unsupported(String),
}

pub enum Assoc {
    /// pfSense passes the forwarded traffic without a visible filter rule.
    Pass,
    /// Tag shared with a filter rule.
    Rule(String),
    None,
}

pub struct PForward {
    pub n: usize,
    pub id: String,
    pub name: String,
    pub iface: String,
    pub proto: Proto,
    pub address: IpAddr,
    pub first: u16,
    pub last: u16,
    pub target: IpAddr,
    pub local_first: u16,
    pub assoc: Assoc,
    pub untranslated: Option<String>,
}

pub struct Model {
    pub version: String,
    pub hostname: String,
    pub ifaces: Vec<Iface>,
    pub aliases: BTreeMap<String, Alias>,
    pub rules: Vec<PRule>,
    pub forwards: Vec<PForward>,
    pub outbound_auto: bool,
    antilockout: bool,
}

/// What pfSense would do with a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PfVerdict {
    Pass(String),
    Block(String),
    DefaultBlock,
    /// A rule the importer left out would have decided this packet.
    Untranslated(String),
}

impl fmt::Display for PfVerdict {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PfVerdict::Pass(by) => write!(f, "pass by {by}"),
            PfVerdict::Block(by) => write!(f, "block by {by}"),
            PfVerdict::DefaultBlock => f.write_str("block by default deny"),
            PfVerdict::Untranslated(by) => write!(f, "decided by {by}, which was not translated"),
        }
    }
}

fn child<'a>(node: Node<'a, 'a>, name: &str) -> Option<Node<'a, 'a>> {
    node.children()
        .find(|c| c.is_element() && c.tag_name().name() == name)
}

fn children<'a>(node: Node<'a, 'a>, name: &'a str) -> impl Iterator<Item = Node<'a, 'a>> {
    node.children()
        .filter(move |c| c.is_element() && c.tag_name().name() == name)
}

fn text<'a>(node: Node<'a, 'a>, name: &str) -> &'a str {
    child(node, name)
        .and_then(|c| c.text())
        .map_or("", str::trim)
}

fn host(ip: IpAddr) -> IpNet {
    IpNet::from(ip)
}

fn parse_net(s: &str) -> Option<IpNet> {
    s.parse::<IpNet>()
        .ok()
        .or_else(|| s.parse::<IpAddr>().ok().map(host))
}

/// `443`, `8000:8010` or `137-139`.
fn parse_ports(s: &str) -> Option<(u16, u16)> {
    let (a, b) = s.split_once([':', '-']).unwrap_or((s, s));
    let (a, b) = (a.parse().ok()?, b.parse().ok()?);
    (a > 0 && a <= b).then_some((a, b))
}

/// True when the two networks share any address.
fn overlaps(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

impl Model {
    pub fn parse(root: Node, report: &mut Report) -> Result<Model, ImportError> {
        let system = child(root, "system");
        let mut model = Model {
            version: text(root, "version").to_string(),
            hostname: system.map_or("", |s| text(s, "hostname")).to_string(),
            ifaces: vec![],
            aliases: BTreeMap::new(),
            rules: vec![],
            forwards: vec![],
            outbound_auto: false,
            antilockout: system
                .and_then(|s| child(s, "webgui"))
                .is_none_or(|w| child(w, "noantilockout").is_none()),
        };
        if model.hostname.is_empty() {
            model.hostname = "imported".into();
        }
        model.parse_ifaces(root, report);
        if model.ifaces.is_empty() {
            return Err(ImportError::NoInterfaces);
        }
        model.parse_aliases(root, report);
        model.parse_rules(root);
        model.parse_nat(root, report);
        model.other_sections(root, report);
        Ok(model)
    }

    fn parse_ifaces(&mut self, root: Node, report: &mut Report) {
        let Some(section) = child(root, "interfaces") else {
            return;
        };
        for node in section.children().filter(Node::is_element) {
            let key = node.tag_name().name().to_string();
            let name = text(node, "if").to_string();
            if name.is_empty() {
                continue;
            }
            let descr = match text(node, "descr") {
                "" => key.to_uppercase(),
                d => d.to_string(),
            };
            let addr = |ip: &str, len: &str| -> Option<IpNet> {
                IpNet::new(text(node, ip).parse().ok()?, text(node, len).parse().ok()?).ok()
            };
            let (v4, v6) = (addr("ipaddr", "subnet"), addr("ipaddrv6", "subnetv6"));
            let dynamic4 = !text(node, "ipaddr").is_empty() && v4.is_none();
            if dynamic4 {
                report.changed(
                    format!("Interface {descr} gets its IPv4 address by {}", text(node, "ipaddr")),
                    "its addresses are left empty; rules that name this interface's network or address were left out",
                );
            }
            let mut zone = sanitize(&descr, 10);
            if self.ifaces.iter().any(|i| i.zone == zone) || zone == SELF_ZONE || zone == "any" {
                zone = sanitize(
                    &format!("{}{}", &zone[..zone.len().min(8)], self.ifaces.len()),
                    10,
                );
            }
            // Schema 1 allows one default route per family: the first interface with a gateway.
            let gw4 = (!text(node, "gateway").is_empty() || dynamic4)
                && !self.ifaces.iter().any(|i| i.gw4);
            let gw6 = !text(node, "gatewayv6").is_empty() && !self.ifaces.iter().any(|i| i.gw6);
            self.ifaces.push(Iface {
                key,
                name,
                descr,
                zone,
                v4,
                v6,
                gw4,
                gw6,
            });
        }
    }

    fn parse_aliases(&mut self, root: Node, report: &mut Report) {
        let Some(section) = child(root, "aliases") else {
            return;
        };
        for node in children(section, "alias") {
            let name = text(node, "name").to_string();
            let tokens: Vec<&str> = text(node, "address").split_whitespace().collect();
            let alias = match text(node, "type") {
                "host" | "network" => {
                    let mut nets = vec![];
                    let mut bad = None;
                    for t in &tokens {
                        match (parse_net(t), self.aliases.get(*t)) {
                            (Some(n), _) => nets.push(n),
                            (None, Some(Alias::Nets { nets: inner, .. })) => {
                                nets.extend(inner.clone())
                            }
                            _ => {
                                bad = Some(format!(
                                    "it has the entry '{t}', which is not an address; groups resolved by DNS are not in schema 1"
                                ))
                            }
                        }
                    }
                    match bad {
                        Some(why) => Alias::Unsupported(why),
                        None if nets.is_empty() => Alias::Unsupported("it is empty".into()),
                        None => {
                            let mut group = sanitize(&name, 32);
                            let taken = |g: &str| {
                                self.aliases
                                    .values()
                                    .any(|a| matches!(a, Alias::Nets { group, .. } if group == g))
                            };
                            if taken(&group) {
                                group = sanitize(
                                    &format!(
                                        "{}-{}",
                                        &group[..group.len().min(28)],
                                        self.aliases.len()
                                    ),
                                    32,
                                );
                            }
                            Alias::Nets { group, nets }
                        }
                    }
                }
                "port" => match tokens
                    .iter()
                    .map(|t| parse_ports(t))
                    .collect::<Option<Vec<_>>>()
                {
                    Some(p) if !p.is_empty() => {
                        report.changed(
                            format!("Port alias {name}"),
                            "written out in each rule that uses it; schema 1 services carry a protocol",
                        );
                        Alias::Ports(p)
                    }
                    _ => Alias::Unsupported("it holds something other than port numbers".into()),
                },
                other => Alias::Unsupported(format!("alias type '{other}' is not in schema 1")),
            };
            if let Alias::Unsupported(why) = &alias {
                report.unsupported(
                    format!("Alias {name}"),
                    format!("{why}; rules that use it were left out"),
                );
            }
            self.aliases.insert(name, alias);
        }
    }

    pub fn iface(&self, key: &str) -> Option<&Iface> {
        self.ifaces.iter().find(|i| i.key == key)
    }

    /// One side of a rule: the addresses, the group to write for them, and
    /// why it cannot be translated, if it cannot.
    fn side(&self, node: Option<Node>) -> (Side, Option<String>, Option<String>) {
        let Some(node) = node else {
            return (Side::Any, None, None);
        };
        let fail = |why: String| (Side::Any, None, Some(why));
        if child(node, "not").is_some() {
            return fail(
                "it uses a negated match; write it as a drop rule followed by an accept rule"
                    .into(),
            );
        }
        if child(node, "any").is_some() {
            return (Side::Any, None, None);
        }
        let network = text(node, "network");
        if !network.is_empty() {
            let nets: Vec<IpNet> = if network == "(self)" {
                self.ifaces
                    .iter()
                    .flat_map(Iface::addrs)
                    .map(|a| host(a.addr()))
                    .collect()
            } else if let Some(i) = self.iface(network) {
                i.addrs().map(|a| a.trunc()).collect()
            } else if let Some(i) = network.strip_suffix("ip").and_then(|k| self.iface(k)) {
                i.addrs().map(|a| host(a.addr())).collect()
            } else {
                return fail(format!(
                    "it names the network '{network}', which is not a plain interface"
                ));
            };
            if nets.is_empty() {
                return fail(format!(
                    "it names '{network}', an interface with no static address"
                ));
            }
            return (Side::Nets(nets), None, None);
        }
        let address = text(node, "address");
        if address.is_empty() {
            return (Side::Any, None, None);
        }
        match (self.aliases.get(address), parse_net(address)) {
            (Some(Alias::Nets { group, nets }), _) => {
                (Side::Nets(nets.clone()), Some(group.clone()), None)
            }
            (Some(Alias::Unsupported(why)), _) => fail(format!("it uses alias {address}: {why}")),
            (Some(Alias::Ports(_)), _) => {
                fail(format!("it uses port alias {address} as an address"))
            }
            (None, Some(n)) => (Side::Nets(vec![n]), None, None),
            (None, None) => fail(format!(
                "its address '{address}' is not an address, a network or a known alias"
            )),
        }
    }

    fn ports(&self, node: Option<Node>) -> Result<Vec<(u16, u16)>, String> {
        let port = node.map_or("", |n| text(n, "port"));
        if port.is_empty() {
            return Ok(vec![]);
        }
        match (self.aliases.get(port), parse_ports(port)) {
            (Some(Alias::Ports(p)), _) => Ok(p.clone()),
            (_, Some(p)) => Ok(vec![p]),
            _ => Err(format!(
                "its port '{port}' is not a port, a range or a port alias"
            )),
        }
    }

    fn parse_rules(&mut self, root: Node) {
        let Some(section) = child(root, "filter") else {
            return;
        };
        for (i, node) in children(section, "rule").enumerate() {
            let n = i + 1;
            let mut why: Option<String> = None;
            let mut fail = |w: String| {
                why.get_or_insert(w);
            };
            let action = match text(node, "type") {
                "pass" => Action::Accept,
                "block" => Action::Drop,
                "reject" => Action::Reject,
                other => {
                    fail(format!("rule type '{other}' is not in schema 1"));
                    Action::Drop
                }
            };
            let floating = text(node, "floating") == "yes";
            let mut ifaces: Vec<String> = text(node, "interface")
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            if floating && ifaces.is_empty() {
                ifaces = self.ifaces.iter().map(|i| i.key.clone()).collect();
            }
            if let Some(k) = ifaces.iter().find(|k| self.iface(k).is_none()) {
                fail(format!(
                    "it is on '{k}', which is not a plain interface (a group, a VPN or a disabled port)"
                ));
            }
            if ifaces.is_empty() {
                fail("it names no interface".into());
            }
            if floating {
                if text(node, "quick") != "yes" {
                    fail("it is a floating rule without quick, where the last match wins; zone-pair rules are first match".into());
                }
                if text(node, "direction") != "in" {
                    fail("it is a floating rule that matches outbound packets; schema 1 rules match on the way in".into());
                }
            }
            let (v4, v6) = match text(node, "ipprotocol") {
                "inet6" => (false, true),
                "inet46" => (true, true),
                _ => (true, false),
            };
            let proto = match text(node, "protocol") {
                "" => PfProto::Any,
                "tcp" => PfProto::Tcp,
                "udp" => PfProto::Udp,
                "tcp/udp" => PfProto::TcpUdp,
                "icmp" | "ipv6-icmp" => PfProto::Icmp,
                other => {
                    fail(format!("protocol '{other}' is not in schema 1"));
                    PfProto::Any
                }
            };
            let (src_node, dst_node) = (child(node, "source"), child(node, "destination"));
            let (src, src_group, src_why) = self.side(src_node);
            let (dst, dst_group, dst_why) = self.side(dst_node);
            for w in [src_why, dst_why].into_iter().flatten() {
                fail(w);
            }
            if src_node.is_some_and(|s| !text(s, "port").is_empty()) {
                fail("it matches a source port, which schema 1 rules cannot".into());
            }
            let ports = if matches!(proto, PfProto::Tcp | PfProto::Udp | PfProto::TcpUdp) {
                self.ports(dst_node).unwrap_or_else(|w| {
                    fail(w);
                    vec![]
                })
            } else {
                vec![]
            };
            if !text(node, "sched").is_empty() {
                fail(format!(
                    "it runs on schedule '{}'; schedules are not in schema 1",
                    text(node, "sched")
                ));
            }
            if !text(node, "gateway").is_empty() {
                fail(format!(
                    "it routes by policy to gateway '{}'; policy routing is not in schema 1",
                    text(node, "gateway")
                ));
            }
            let name = match text(node, "descr") {
                "" => format!("pfSense rule {n}"),
                d => d.to_string(),
            };
            let assoc = text(node, "associated-rule-id");
            self.rules.push(PRule {
                n,
                id: format!("r-{n:04}"),
                name,
                ifaces,
                floating,
                action,
                v4,
                v6,
                proto,
                src,
                dst,
                src_group,
                dst_group,
                ports,
                log: child(node, "log").is_some(),
                disabled: child(node, "disabled").is_some(),
                assoc: (!assoc.is_empty()).then(|| assoc.to_string()),
                untranslated: why,
            });
        }
    }

    fn parse_nat(&mut self, root: Node, report: &mut Report) {
        let Some(nat) = child(root, "nat") else {
            self.outbound_auto = true;
            return;
        };
        for (i, node) in children(nat, "rule").enumerate() {
            let n = i + 1;
            let name = match text(node, "descr") {
                "" => format!("pfSense port forward {n}"),
                d => d.to_string(),
            };
            let dst = child(node, "destination");
            let iface = text(node, "interface").to_string();
            let mut why: Option<String> = None;
            let address = match self.side(dst) {
                (Side::Nets(nets), _, None)
                    if nets.iter().filter(|n| n.addr().is_ipv4()).count() == 1 =>
                {
                    nets.iter().find(|n| n.addr().is_ipv4()).map(|n| n.addr())
                }
                (_, _, Some(w)) => {
                    why = Some(w);
                    None
                }
                _ => {
                    why = Some("its destination is not one IPv4 address".into());
                    None
                }
            };
            let ports = self.ports(dst).ok().filter(|p| p.len() == 1).map(|p| p[0]);
            let target = match (
                text(node, "target").parse::<IpAddr>(),
                self.aliases.get(text(node, "target")),
            ) {
                (Ok(ip), _) => Some(ip),
                (_, Some(Alias::Nets { nets, .. }))
                    if nets.len() == 1 && nets[0].prefix_len() == nets[0].max_prefix_len() =>
                {
                    Some(nets[0].addr())
                }
                _ => None,
            };
            let local = text(node, "local-port");
            let local_first = parse_ports(local).map(|p| p.0).or(ports.map(|p| p.0));
            if self.iface(&iface).is_none() {
                why.get_or_insert(format!(
                    "it is on '{iface}', which is not a plain interface"
                ));
            }
            if ports.is_none() {
                why.get_or_insert("its destination port is not one port or one range".into());
            }
            if target.is_none() {
                why.get_or_insert(format!(
                    "its target '{}' is not one address",
                    text(node, "target")
                ));
            }
            let protos: Vec<Proto> = match text(node, "protocol") {
                "tcp" => vec![Proto::Tcp],
                "udp" => vec![Proto::Udp],
                "tcp/udp" => vec![Proto::Tcp, Proto::Udp],
                other => {
                    why.get_or_insert(format!(
                        "protocol '{other}' cannot be forwarded in schema 1"
                    ));
                    vec![Proto::Tcp]
                }
            };
            for proto in &protos {
                let suffix = if protos.len() > 1 {
                    format!("-{}", proto.as_str())
                } else {
                    String::new()
                };
                self.forwards.push(PForward {
                    n,
                    id: format!("n-{n:04}{suffix}"),
                    name: name.clone(),
                    iface: iface.clone(),
                    proto: *proto,
                    address: address.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    first: ports.map_or(0, |p| p.0),
                    last: ports.map_or(0, |p| p.1),
                    target: target.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                    local_first: local_first.unwrap_or(0),
                    assoc: match text(node, "associated-rule-id") {
                        "" => Assoc::None,
                        "pass" => Assoc::Pass,
                        tag => Assoc::Rule(tag.to_string()),
                    },
                    untranslated: why.clone(),
                });
            }
        }
        let outbound = child(nat, "outbound");
        let mode = outbound.map_or("automatic", |o| match text(o, "mode") {
            "" => "automatic",
            m => m,
        });
        self.outbound_auto = matches!(mode, "automatic" | "hybrid");
        if let Some(o) = outbound {
            for rule in children(o, "rule") {
                report.unsupported(
                    format!("Manual outbound NAT rule \"{}\"", text(rule, "descr")),
                    "write it as an outbound NAT entry by hand; manual outbound rules are not translated yet",
                );
            }
        }
        for (tag, what) in [("onetoone", "1:1 NAT"), ("npt", "NPt")] {
            for _ in children(nat, tag) {
                report.unsupported(
                    format!("{what} entry"),
                    format!("{what} is not in schema 1"),
                );
            }
        }
    }

    /// Parts of the backup that schema 1 has no place for.
    fn other_sections(&self, root: Node, report: &mut Report) {
        let section = |name: &str| child(root, name);
        if let Some(vpn) = section("openvpn") {
            for s in children(vpn, "openvpn-server") {
                report.unsupported(
                    format!("OpenVPN server \"{}\"", text(s, "description")),
                    "OpenVPN is not in Netoxide; move site links to WireGuard or IPsec and remote access to the WireGuard portal",
                );
            }
            for c in children(vpn, "openvpn-client") {
                report.unsupported(
                    format!("OpenVPN client \"{}\"", text(c, "description")),
                    "OpenVPN is not in Netoxide; move the link to WireGuard or IPsec",
                );
            }
        }
        if let Some(ipsec) = section("ipsec") {
            for p in children(ipsec, "phase1") {
                report.unsupported(
                    format!("IPsec tunnel \"{}\"", text(p, "descr")),
                    "VPN is not in schema 1 yet; keep the tunnel on the old box until it is",
                );
            }
        }
        if let Some(cp) = section("captiveportal") {
            for zone in cp.children().filter(Node::is_element) {
                report.unsupported(
                    format!("Captive portal zone \"{}\"", zone.tag_name().name()),
                    "not in 1.0; keep the old box for guest Wi-Fi or drop the portal",
                );
            }
        }
        if let Some(pkgs) = section("installedpackages") {
            for p in children(pkgs, "package") {
                report.unsupported(
                    format!("Package {}", text(p, "name")),
                    "packages do not exist in Netoxide; check whether a built-in feature covers what it did",
                );
            }
        }
        if let Some(routes) = section("staticroutes") {
            for r in children(routes, "route") {
                report.unsupported(
                    format!("Static route to {}", text(r, "network")),
                    "static routes are not in schema 1; rules for destinations behind it land in the default-route zone",
                );
            }
        }
        if let Some(gw) = section("gateways") {
            for g in children(gw, "gateway_group") {
                report.unsupported(
                    format!("Gateway group {}", text(g, "name")),
                    "multi-WAN failover is not in schema 1 yet",
                );
            }
        }
        if let Some(vips) = section("virtualip") {
            for v in children(vips, "vip") {
                report.unsupported(
                    format!("Virtual IP {}", text(v, "subnet")),
                    "virtual IPs and CARP are not in schema 1; HA comes later",
                );
            }
        }
        if let Some(s) = section("schedules") {
            for sched in children(s, "schedule") {
                report.unsupported(
                    format!("Schedule {}", text(sched, "name")),
                    "schedules are not in schema 1",
                );
            }
        }
        for (tag, what) in [("dhcpd", "DHCP server"), ("dhcpdv6", "DHCPv6 server")] {
            if let Some(d) = section(tag) {
                for i in d
                    .children()
                    .filter(|n| n.is_element() && child(*n, "enable").is_some())
                {
                    report.unsupported(
                        format!("{what} on {}", i.tag_name().name()),
                        "DHCP is not in schema 1 yet; keep serving leases from the old box or another server",
                    );
                }
            }
        }
        for (tag, what) in [("unbound", "DNS resolver"), ("dnsmasq", "DNS forwarder")] {
            if section(tag).is_some_and(|d| child(d, "enable").is_some()) {
                report.unsupported(
                    what,
                    "DNS is not in schema 1 yet; point clients at another resolver",
                );
            }
        }
    }

    /// The rules pfSense tries for packets arriving on an interface, in
    /// order: floating quick rules first, then the interface's own.
    pub fn effective(&self, key: &str) -> Vec<&PRule> {
        let on = |r: &&PRule| r.ifaces.iter().any(|k| k == key);
        self.rules
            .iter()
            .filter(|r| r.floating)
            .filter(on)
            .chain(self.rules.iter().filter(|r| !r.floating).filter(on))
            .collect()
    }

    fn default_zone(&self, v4: bool) -> Option<&str> {
        self.ifaces
            .iter()
            .find(|i| if v4 { i.gw4 } else { i.gw6 })
            .map(|i| i.zone.as_str())
    }

    /// The zone an address is routed to: a connected network, else the default route.
    pub fn zone_of(&self, ip: IpAddr) -> Option<String> {
        self.ifaces
            .iter()
            .find(|i| i.addrs().any(|a| a.trunc().contains(&ip)))
            .map(|i| i.zone.clone())
            .or_else(|| self.default_zone(ip.is_ipv4()).map(String::from))
    }

    fn is_box(&self, ip: IpAddr) -> bool {
        self.ifaces
            .iter()
            .any(|i| i.addrs().any(|a| a.addr() == ip))
    }

    /// The zone pairs a rule lands in when it is on interface `key`: each
    /// destination zone, with the part of the destination that lives there.
    pub fn buckets(&self, r: &PRule, key: &str) -> Vec<(String, Side)> {
        let Some(from) = self.iface(key).map(|i| i.zone.as_str()) else {
            return vec![];
        };
        let nets = match &r.dst {
            Side::Any => {
                let mut out: Vec<(String, Side)> = vec![];
                for i in &self.ifaces {
                    if i.zone != from && !out.iter().any(|(z, _)| *z == i.zone) {
                        out.push((i.zone.clone(), Side::Any));
                    }
                }
                out.push((SELF_ZONE.to_string(), Side::Any));
                return out;
            }
            Side::Nets(nets) => nets,
        };
        let mut out: Vec<(String, Vec<IpNet>)> = vec![];
        let mut put = |zone: &str, net: IpNet| {
            if zone == from {
                return;
            }
            match out.iter_mut().find(|(z, _)| z == zone) {
                Some((_, v)) => {
                    if !v.contains(&net) {
                        v.push(net);
                    }
                }
                None => out.push((zone.to_string(), vec![net])),
            }
        };
        for net in nets {
            let is_host = net.prefix_len() == net.max_prefix_len();
            let mut covered = false;
            for i in &self.ifaces {
                for a in i.addrs() {
                    // The box's own addresses inside the destination are traffic to the box.
                    if net.contains(&a.addr()) {
                        put(SELF_ZONE, host(a.addr()));
                    }
                    if is_host && net.addr() == a.addr() {
                        covered = true;
                        continue;
                    }
                    let subnet = a.trunc();
                    if overlaps(net, &subnet) {
                        put(&i.zone, *net);
                        covered |= subnet.contains(&net.network())
                            && subnet.prefix_len() <= net.prefix_len();
                    }
                }
            }
            // Whatever is not on a connected network leaves by the default route.
            if !covered && let Some(zone) = self.default_zone(net.addr().is_ipv4()) {
                put(zone, *net);
            }
        }
        out.into_iter().map(|(z, v)| (z, Side::Nets(v))).collect()
    }

    /// The interface pfSense's anti-lockout rule protects, if the rule is on.
    pub fn lockout(&self) -> Option<&Iface> {
        if !self.antilockout {
            return None;
        }
        self.iface("lan").or_else(|| self.iface("wan"))
    }

    fn rule_matches(r: &PRule, src: IpAddr, dst: IpAddr, l4: L4, dport: Option<u16>) -> bool {
        let family = if src.is_ipv4() { r.v4 } else { r.v6 };
        let proto = matches!(
            (r.proto, l4),
            (PfProto::Any, _)
                | (PfProto::Tcp | PfProto::TcpUdp, L4::Tcp)
                | (PfProto::Udp | PfProto::TcpUdp, L4::Udp)
                | (PfProto::Icmp, L4::Icmp | L4::Icmpv6)
        );
        let port = r.ports.is_empty()
            || dport.is_some_and(|d| r.ports.iter().any(|(a, b)| (*a..=*b).contains(&d)));
        family && proto && port && r.src.matches(src) && r.dst.matches(dst)
    }

    /// What pfSense would do with the first packet of a connection. `None`
    /// when the packet's interface is not in the backup.
    pub fn verdict(&self, p: &Packet) -> Option<PfVerdict> {
        let iface = self.ifaces.iter().find(|i| i.name == p.iif)?;
        let (mut dst, mut dport) = (p.dst, p.dport);
        // pf translates the destination before it filters.
        for f in self.forwards.iter().filter(|f| f.iface == iface.key) {
            let proto = matches!(
                (f.proto, p.l4),
                (Proto::Tcp, L4::Tcp) | (Proto::Udp, L4::Udp)
            );
            let Some(port) = dport.filter(|d| (f.first..=f.last).contains(d)) else {
                continue;
            };
            if proto && f.address == dst {
                if f.untranslated.is_some() {
                    return Some(PfVerdict::Untranslated(format!(
                        "port forward \"{}\"",
                        f.name
                    )));
                }
                dst = f.target;
                dport = Some(f.local_first + (port - f.first));
                if matches!(f.assoc, Assoc::Pass) {
                    return Some(PfVerdict::Pass(format!("port forward \"{}\"", f.name)));
                }
                break;
            }
        }
        if self.lockout().is_some_and(|l| l.key == iface.key)
            && p.l4 == L4::Tcp
            && dport.is_some_and(|d| [443, 80, 22].contains(&d))
            && iface.addrs().any(|a| a.addr() == dst)
        {
            return Some(PfVerdict::Pass("the anti-lockout rule".into()));
        }
        for r in self.effective(&iface.key) {
            if r.disabled || !Self::rule_matches(r, p.src, dst, p.l4, dport) {
                continue;
            }
            let by = format!("rule {} \"{}\"", r.n, r.name);
            return Some(match (&r.untranslated, r.action) {
                (Some(_), _) => PfVerdict::Untranslated(by),
                (None, Action::Accept) => PfVerdict::Pass(by),
                (None, _) => PfVerdict::Block(by),
            });
        }
        Some(PfVerdict::DefaultBlock)
    }
}

/// An address inside a network that is unlikely to be the box itself.
fn sample(net: &IpNet) -> IpAddr {
    if net.prefix_len() == net.max_prefix_len() {
        return net.addr();
    }
    let room = net.max_prefix_len() - net.prefix_len();
    let offset: u32 = if room >= 6 { 23 } else { 1 << (room - 1) };
    match net.network() {
        IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(u32::from(a) + offset)),
        IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(u128::from(a) + u128::from(offset))),
    }
}

/// Packets that reach every translatable rule and port forward of the
/// model: inside each rule's match, and just outside its ports.
pub fn probes(model: &Model) -> Vec<Packet> {
    let outside = |v4: bool, n: u8| -> IpAddr {
        if v4 {
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, n))
        } else {
            IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                0xffff,
                0,
                0,
                0,
                0,
                u16::from(n),
            ))
        }
    };
    let mut out: Vec<Packet> = vec![];
    let mut add = |src: IpAddr, dst: IpAddr, l4: L4, dport: Option<u16>, iif: &str| {
        // A packet between two hosts on the ingress network is never routed.
        let same_net = model
            .ifaces
            .iter()
            .any(|i| i.name == iif && i.addrs().any(|a| a.trunc().contains(&dst)));
        if src == dst || (same_net && !model.is_box(dst)) || model.zone_of(dst).is_none() {
            return;
        }
        let p = Packet {
            src,
            dst,
            l4,
            dport,
            iif: iif.to_string(),
            box_addrs: vec![],
        };
        if !out.contains(&p) {
            out.push(p);
        }
    };
    for iface in &model.ifaces {
        for r in model.effective(&iface.key) {
            if r.untranslated.is_some() {
                continue;
            }
            for v4 in [true, false] {
                if !(if v4 { r.v4 } else { r.v6 }) {
                    continue;
                }
                let fam = |n: &&IpNet| n.addr().is_ipv4() == v4;
                let own = if v4 { iface.v4 } else { iface.v6 };
                let srcs: Vec<IpAddr> = match &r.src {
                    Side::Nets(nets) => nets.iter().filter(fam).map(sample).collect(),
                    Side::Any => own
                        .iter()
                        .map(|a| sample(&a.trunc()))
                        .chain((if v4 { iface.gw4 } else { iface.gw6 }).then(|| outside(v4, 7)))
                        .collect(),
                };
                let dsts: Vec<IpAddr> = match &r.dst {
                    Side::Nets(nets) => nets.iter().filter(fam).map(sample).collect(),
                    Side::Any => model
                        .ifaces
                        .iter()
                        .filter_map(|i| if v4 { i.v4 } else { i.v6 })
                        .flat_map(|a| [sample(&a.trunc()), a.addr()])
                        .chain([outside(v4, 9)])
                        .collect(),
                };
                let icmp = if v4 { L4::Icmp } else { L4::Icmpv6 };
                let port = |d: u16| r.ports.first().map_or(d, |p| p.0);
                let beyond = r.ports.last().and_then(|p| p.1.checked_add(1));
                let mut l4s: Vec<(L4, Option<u16>)> = match r.proto {
                    PfProto::Tcp => vec![(L4::Tcp, Some(port(443)))],
                    PfProto::Udp => vec![(L4::Udp, Some(port(53)))],
                    PfProto::TcpUdp => vec![(L4::Tcp, Some(port(443))), (L4::Udp, Some(port(53)))],
                    PfProto::Icmp => vec![(icmp, None)],
                    PfProto::Any => vec![(L4::Tcp, Some(443)), (L4::Udp, Some(53)), (icmp, None)],
                };
                if let Some(b) = beyond {
                    let first = l4s[0].0;
                    l4s.push((first, Some(b)));
                }
                for s in &srcs {
                    for d in &dsts {
                        for (l4, dport) in &l4s {
                            add(*s, *d, *l4, *dport, &iface.name);
                        }
                    }
                }
            }
        }
        for f in model
            .forwards
            .iter()
            .filter(|f| f.iface == iface.key && f.untranslated.is_none())
        {
            let l4 = if f.proto == Proto::Tcp {
                L4::Tcp
            } else {
                L4::Udp
            };
            add(outside(true, 7), f.address, l4, Some(f.first), &iface.name);
            add(
                outside(true, 7),
                f.target,
                l4,
                Some(f.local_first),
                &iface.name,
            );
        }
    }
    out
}

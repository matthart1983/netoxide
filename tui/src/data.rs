//! Mock data for the Netoxide TUI prototype. It mirrors the design canvas so
//! the two can be compared screen for screen. Nothing here talks to a box.

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Accept,
    Drop,
    Reject,
}

impl Action {
    pub fn label(self) -> &'static str {
        match self {
            Action::Accept => "accept",
            Action::Drop => "drop",
            Action::Reject => "reject",
        }
    }
}

pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub src: &'static str,
    pub dst: &'static str,
    pub svc: &'static str,
    pub action: Action,
    pub log: bool,
    pub schedule: &'static str,
    pub hits: &'static str,
    pub hygiene: &'static str,
    pub pending: bool,
}

pub struct ZonePair {
    pub label: &'static str,
    pub total: u32,
    pub default_hits: &'static str,
    pub rules: Vec<Rule>,
}

#[allow(clippy::too_many_arguments)]
fn r(
    id: &'static str,
    name: &'static str,
    src: &'static str,
    dst: &'static str,
    svc: &'static str,
    action: Action,
    log: bool,
    schedule: &'static str,
    hits: &'static str,
    hygiene: &'static str,
) -> Rule {
    Rule {
        id,
        name,
        src,
        dst,
        svc,
        action,
        log,
        schedule,
        hits,
        hygiene,
        pending: false,
    }
}

/// Marks a rule as present only in the pending candidate.
fn pending(mut rule: Rule) -> Rule {
    rule.pending = true;
    rule
}

pub fn zone_pairs() -> Vec<ZonePair> {
    use Action::*;
    vec![
        ZonePair {
            label: "lan → dmz",
            total: 6,
            default_hits: "2,114",
            rules: vec![
                pending(r(
                    "r-0412",
                    "Drop SMB and NetBIOS",
                    "any",
                    "any",
                    "smb, netbios",
                    Drop,
                    true,
                    "always",
                    "—",
                    "",
                )),
                r(
                    "r-0388",
                    "Finance to file servers",
                    "@finance-pcs",
                    "@finance-file-servers",
                    "https",
                    Accept,
                    false,
                    "always",
                    "1,204",
                    "",
                ),
                r(
                    "r-0301",
                    "Staff to intranet",
                    "@staff",
                    "10.30.0.20",
                    "http, https",
                    Accept,
                    false,
                    "always",
                    "88,410",
                    "",
                ),
                r(
                    "r-0302",
                    "Staff to intranet (old)",
                    "10.20.0.0/16",
                    "10.30.0.20",
                    "https",
                    Accept,
                    false,
                    "always",
                    "0",
                    "shadowed by r-0301",
                ),
                r(
                    "r-0277",
                    "Backups to NAS",
                    "@backup-agents",
                    "@nas",
                    "tcp/873",
                    Accept,
                    true,
                    "nightly 01:00–05:00",
                    "31",
                    "",
                ),
                r(
                    "r-0150",
                    "Printer admin",
                    "@it-admins",
                    "@printers",
                    "https, tcp/9100",
                    Accept,
                    false,
                    "always",
                    "0",
                    "no hits in 90 d",
                ),
            ],
        },
        ZonePair {
            label: "lan → wan",
            total: 46,
            default_hits: "9,870",
            rules: vec![
                r(
                    "r-0102",
                    "Block known-bad destinations",
                    "any",
                    "@blocklist-ip",
                    "any",
                    Drop,
                    true,
                    "always",
                    "3,311",
                    "",
                ),
                r(
                    "r-0110",
                    "DNS only via resolver",
                    "any",
                    "!self",
                    "dns, dot",
                    Reject,
                    true,
                    "always",
                    "612",
                    "",
                ),
                r(
                    "r-0120",
                    "Web",
                    "@staff",
                    "any",
                    "http, https, quic",
                    Accept,
                    false,
                    "always",
                    "4.1 M",
                    "",
                ),
                r(
                    "r-0131",
                    "Accounting SaaS",
                    "@finance-pcs",
                    "@xero-ranges",
                    "https",
                    Accept,
                    false,
                    "Mon–Fri 07–19",
                    "22,019",
                    "wider than traffic",
                ),
            ],
        },
        ZonePair {
            label: "wan → dmz",
            total: 12,
            default_hits: "1.9 M",
            rules: vec![
                r(
                    "r-0200",
                    "Public web (port forward)",
                    "any",
                    "10.30.0.10",
                    "https",
                    Accept,
                    true,
                    "always",
                    "512,880",
                    "",
                ),
                r(
                    "r-0204",
                    "Mail relay",
                    "@mx-partners",
                    "10.30.0.11",
                    "smtp",
                    Accept,
                    true,
                    "always",
                    "9,402",
                    "",
                ),
                r(
                    "r-0210",
                    "Old FTP",
                    "any",
                    "10.30.0.12",
                    "ftp",
                    Accept,
                    true,
                    "always",
                    "0",
                    "no hits in 90 d",
                ),
            ],
        },
        ZonePair {
            label: "vpn → lan",
            total: 19,
            default_hits: "204",
            rules: vec![
                r(
                    "r-0501",
                    "Engineers to lab",
                    "group:engineering",
                    "@lab-nets",
                    "any",
                    Accept,
                    true,
                    "always",
                    "18,233",
                    "",
                ),
                r(
                    "r-0502",
                    "Finance to ERP",
                    "group:finance",
                    "@erp",
                    "https",
                    Accept,
                    true,
                    "always",
                    "6,091",
                    "",
                ),
                r(
                    "r-0510",
                    "Contractors to ticketing",
                    "group:contractors",
                    "10.20.9.4",
                    "https",
                    Accept,
                    true,
                    "Mon–Fri 08–18",
                    "1,120",
                    "",
                ),
            ],
        },
        ZonePair {
            label: "guest → wan",
            total: 4,
            default_hits: "77",
            rules: vec![
                r(
                    "r-0601",
                    "Guest web, shaped",
                    "zone:guest",
                    "any",
                    "http, https, quic",
                    Accept,
                    false,
                    "always",
                    "301,442",
                    "",
                ),
                r(
                    "r-0602",
                    "Guest SMTP block",
                    "zone:guest",
                    "any",
                    "smtp",
                    Drop,
                    true,
                    "always",
                    "14",
                    "",
                ),
            ],
        },
        ZonePair {
            label: "any → self",
            total: 9,
            default_hits: "48,301",
            rules: vec![
                r(
                    "r-0001",
                    "Management from admin VLAN",
                    "@it-admins",
                    "self",
                    "https, ssh-breakglass",
                    Accept,
                    true,
                    "always",
                    "2,940",
                    "",
                ),
                r(
                    "r-0002",
                    "DNS and DHCP from internal",
                    "zone:lan, zone:guest",
                    "self",
                    "dns, dhcp",
                    Accept,
                    false,
                    "always",
                    "1.2 M",
                    "",
                ),
                r(
                    "r-0003",
                    "WireGuard",
                    "any",
                    "self:wan0",
                    "udp/51820",
                    Accept,
                    false,
                    "always",
                    "88,104",
                    "",
                ),
            ],
        },
    ]
}

pub struct NatRule {
    pub id: &'static str,
    pub name: &'static str,
    pub matches: &'static str,
    pub to: &'static str,
    pub rule: &'static str,
    pub hairpin: &'static str,
    pub hits: &'static str,
}

pub struct NatTab {
    pub label: &'static str,
    pub blurb: &'static str,
    pub rows: Vec<NatRule>,
}

pub fn nat_tabs() -> Vec<NatTab> {
    let n = |id, name, matches, to, rule, hairpin, hits| NatRule {
        id,
        name,
        matches,
        to,
        rule,
        hairpin,
        hits,
    };
    vec![
        NatTab {
            label: "Port forwards",
            blurb: "Destination NAT to an internal host. Every forward names its filter rule; there is no hidden pass rule.",
            rows: vec![
                n(
                    "n-0010",
                    "Public web",
                    "wan0 203.0.113.10 tcp/443",
                    "10.30.0.10:443",
                    "r-0200",
                    "on",
                    "512,880",
                ),
                n(
                    "n-0011",
                    "Mail relay",
                    "wan0 203.0.113.10 tcp/25",
                    "10.30.0.11:25",
                    "r-0204",
                    "off",
                    "9,402",
                ),
                n(
                    "n-0012",
                    "Web, HTTP redirect",
                    "wan0 203.0.113.10 tcp/80",
                    "10.30.0.10:80",
                    "r-0201",
                    "on",
                    "41,230",
                ),
                n(
                    "n-0014",
                    "Lab SSH (expires 30 Nov)",
                    "wan0 203.0.113.10 tcp/2222",
                    "10.40.1.5:22",
                    "r-0215",
                    "off",
                    "41",
                ),
            ],
        },
        NatTab {
            label: "Outbound",
            blurb: "Source NAT per zone and egress. Inter-zone and site-VPN traffic is not translated unless a rule says so.",
            rows: vec![
                n(
                    "n-0100",
                    "Staff to internet",
                    "zone lan → wan0",
                    "wan0 address (masquerade)",
                    "any",
                    "—",
                    "6.2 M",
                ),
                n(
                    "n-0101",
                    "DMZ to internet",
                    "zone dmz → wan0",
                    "203.0.113.10 (static)",
                    "any",
                    "—",
                    "880,104",
                ),
                n(
                    "n-0102",
                    "Guest via 5G",
                    "zone guest → wan1",
                    "wan1 address (masquerade)",
                    "any",
                    "—",
                    "301,442",
                ),
                n(
                    "n-0103",
                    "Site VPN, no NAT",
                    "zone lan → wg-mel",
                    "no translation",
                    "any",
                    "—",
                    "77,019",
                ),
            ],
        },
        NatTab {
            label: "1:1",
            blurb: "A whole public address mapped to one internal host in both directions.",
            rows: vec![n(
                "n-0200",
                "Mail gateway",
                "203.0.113.12",
                "10.30.0.12",
                "r-0206",
                "on",
                "120,880",
            )],
        },
        NatTab {
            label: "NAT64",
            blurb: "IPv6-only VLANs reach IPv4 through 64:ff9b::/96, with DNS64 on the resolver for those zones.",
            rows: vec![n(
                "n-0300",
                "IPv6-only lab",
                "zone lab-v6 → 64:ff9b::/96",
                "wan0 IPv4 pool",
                "r-0701",
                "—",
                "18,442",
            )],
        },
    ]
}

pub struct Tunnel {
    pub name: &'static str,
    pub kind: &'static str,
    pub peer: &'static str,
    pub nets: &'static str,
    pub up: bool,
    pub why: &'static str,
    pub last: &'static str,
    pub bytes: &'static str,
}

pub fn tunnels() -> Vec<Tunnel> {
    let t = |name, kind, peer, nets, up, why, last, bytes| Tunnel {
        name,
        kind,
        peer,
        nets,
        up,
        why,
        last,
        bytes,
    };
    vec![
        t(
            "wg-mel",
            "WireGuard",
            "198.51.100.4:51820",
            "10.20.0.0/16 ↔ 10.60.0.0/16",
            true,
            "",
            "41 s ago",
            "18.2 / 9.1 GB",
        ),
        t(
            "wg-bne",
            "WireGuard",
            "198.51.100.22:51820",
            "10.20.0.0/16 ↔ 10.70.0.0/16",
            true,
            "",
            "1 min ago",
            "4.4 / 3.0 GB",
        ),
        t(
            "wg-per",
            "WireGuard",
            "198.51.100.31:51820",
            "10.20.0.0/16 ↔ 10.80.0.0/16",
            true,
            "",
            "22 s ago",
            "2.1 / 1.7 GB",
        ),
        t(
            "ipsec-aws",
            "IPsec IKEv2",
            "AWS VPN gateway (2)",
            "10.20.0.0/16 ↔ 172.31.0.0/16",
            true,
            "",
            "rekeyed 38 min ago",
            "61.0 / 12.4 GB",
        ),
        t(
            "ipsec-bank",
            "IPsec IKEv2",
            "192.0.2.200",
            "10.30.0.11/32 ↔ 192.0.2.64/27",
            true,
            "",
            "rekeyed 2 h ago",
            "0.3 / 0.2 GB",
        ),
        t(
            "wg-akl",
            "WireGuard",
            "198.51.100.40:51820",
            "10.20.0.0/16 ↔ 10.90.0.0/16",
            false,
            "no handshake for 3 h 12 min; peer not answering",
            "3 h ago",
            "0 / 0",
        ),
    ]
}

pub const VPN_USERS: &[(&str, &str, &str, &str)] = &[
    ("Priya Raman", "engineering", "10.99.0.14", "08:12"),
    ("Tom Achebe", "finance", "10.99.0.31", "08:40"),
    ("Lena Kovac", "engineering", "10.99.0.17", "09:05"),
    ("Sam Whitfield", "contractors", "10.99.1.4", "10:22"),
    ("Ana Ruiz", "it-admins", "10.99.0.2", "10:58"),
];

pub const VPN_GROUPS: &[(&str, &str)] = &[
    ("engineering", "r-0501 lab networks"),
    ("finance", "r-0502 ERP"),
    ("contractors", "r-0510 ticketing, business hours"),
    ("it-admins", "r-0001 management"),
];

/// (zone pair, mode, profile, suppressions, on failure)
pub const IPS_ZONES: &[(&str, &str, &str, &str, &str)] = &[
    (
        "wan → dmz",
        "block",
        "balanced",
        "3 rules",
        "fail open, alarm",
    ),
    (
        "wan → self",
        "block",
        "balanced",
        "none",
        "fail open, alarm",
    ),
    (
        "lan → wan",
        "alert",
        "policy (C2, tracking)",
        "11 rules",
        "—",
    ),
    ("guest → wan", "block", "strict", "none", "fail closed"),
    ("lan → dmz", "off", "—", "—", "—"),
];

/// (time, severity, signature, flow, zone pair, action)
pub const IPS_EVENTS: &[(&str, &str, &str, &str, &str, &str)] = &[
    (
        "11:48:02",
        "high",
        "Exploit attempt against VPN appliance web portal",
        "45.0.2.18 → 203.0.113.10:443",
        "wan → dmz",
        "blocked",
    ),
    (
        "11:41:37",
        "high",
        "Known malware command-and-control beacon",
        "10.20.6.51 → 185.0.4.9:8443",
        "lan → wan",
        "alerted",
    ),
    (
        "11:30:15",
        "medium",
        "Inbound scan for MSSQL",
        "91.0.3.77 → 203.0.113.10:1433",
        "wan → self",
        "blocked",
    ),
    (
        "11:22:09",
        "medium",
        "TLS certificate from known-bad issuer",
        "10.20.4.90 → 104.0.0.7:443",
        "lan → wan",
        "alerted",
    ),
    (
        "11:05:44",
        "low",
        "BitTorrent DHT traffic",
        "10.50.2.14 → many:6881",
        "guest → wan",
        "blocked",
    ),
    (
        "10:58:30",
        "low",
        "Outdated SSH client version",
        "10.40.1.5 → 10.30.0.12:22",
        "lab → dmz",
        "alerted",
    ),
];

/// (name, type, zone, ipv4, ipv6, link, rate)
pub const IFACES: &[(&str, &str, &str, &str, &str, &str, &str)] = &[
    (
        "wan0",
        "PPPoE over igc0",
        "wan",
        "203.0.113.10/32",
        "2001:db8:4a00::1 (PD /56)",
        "2.5G full",
        "412 / 96 Mb/s",
    ),
    (
        "wan1",
        "ethernet igc1 (5G)",
        "wan",
        "100.64.12.9/30 dhcp",
        "—",
        "1G full",
        "3 / 1 Mb/s",
    ),
    ("lag0", "LACP igc2 + igc3", "—", "—", "—", "2 × 2.5G", "—"),
    (
        "lan0.20",
        "VLAN 20 on lag0",
        "lan",
        "10.20.0.1/16",
        "2001:db8:4a00:1::1/64",
        "up",
        "88 / 390 Mb/s",
    ),
    (
        "lan0.30",
        "VLAN 30 on lag0",
        "dmz",
        "10.30.0.1/24",
        "2001:db8:4a00:2::1/64",
        "up",
        "210 / 31 Mb/s",
    ),
    (
        "lan0.40",
        "VLAN 40 on lag0",
        "lab-v6",
        "—",
        "2001:db8:4a00:3::1/64",
        "up",
        "4 / 9 Mb/s",
    ),
    (
        "lan0.50",
        "VLAN 50 on lag0",
        "guest",
        "10.50.0.1/22",
        "—",
        "up",
        "21 / 140 Mb/s",
    ),
    (
        "wg0",
        "WireGuard",
        "vpn",
        "10.99.0.1/23",
        "—",
        "42 peers",
        "30 / 44 Mb/s",
    ),
];

/// (gateway, state, tier, latency, loss, probe)
pub const GATEWAYS: &[(&str, &str, &str, &str, &str, &str)] = &[
    (
        "wan0 NBN fibre",
        "active",
        "1",
        "4 ms",
        "0.0%",
        "1.1.1.1, 9.9.9.9",
    ),
    (
        "wan1 5G backup",
        "standby, healthy",
        "2",
        "31 ms",
        "0.4%",
        "1.1.1.1, 9.9.9.9",
    ),
];

pub const POLICY_ROUTES: &[(&str, &str)] = &[
    ("zone guest, any destination", "wan1 first, then wan0"),
    (
        "@voip-handsets to SIP trunk",
        "wan0 only, CAKE priority tier",
    ),
    ("backups to offsite (r-0277)", "wan0, no failover"),
];

/// (date, trigger, load, loss, flows kept, pass)
pub const HA_TESTS: &[(&str, &str, &str, &str, &str, bool)] = &[
    (
        "1 Nov 2026",
        "scheduled: power cut on primary",
        "96,000 conns",
        "0.71 s",
        "99.3%",
        true,
    ),
    (
        "4 Oct 2026",
        "scheduled: WAN cable pulled",
        "71,500 conns",
        "0.58 s",
        "99.6%",
        true,
    ),
    (
        "6 Sep 2026",
        "upgrade to 1.0.3",
        "64,200 conns",
        "0.62 s",
        "99.5%",
        true,
    ),
    (
        "2 Aug 2026",
        "scheduled: power cut on primary",
        "88,000 conns",
        "1.40 s",
        "97.8%",
        false,
    ),
];

/// (kind, text) where kind is ' ', '+' or '-'
pub const DIFF: &[(char, &str)] = &[
    (' ', "[[zone_pair]]"),
    (' ', "from = \"lan\""),
    (' ', "to   = \"dmz\""),
    (' ', ""),
    ('+', "[[zone_pair.rule]]"),
    ('+', "id      = \"r-0412\""),
    ('+', "action  = \"drop\""),
    ('+', "service = [\"smb\", \"netbios\"]"),
    ('+', "log     = true"),
    ('+', "reason  = \"Retire SMBv1 shares, CHG-2207\""),
    ('+', ""),
    (' ', "[[zone_pair.rule]]"),
    (' ', "id      = \"r-0388\""),
    (' ', "action  = \"accept\""),
    ('-', "service = [\"smb\", \"netbios\", \"https\"]"),
    ('+', "service = [\"https\"]"),
    (' ', "dest    = \"@finance-file-servers\""),
];

pub const PLAN: &[&str] = &[
    "schema 1.0 validation passed",
    "compiled 96 rules → 9 sets, 3 verdict maps, longest chain 18",
    "one nftables transaction, atomic swap",
    "HA: commit to primary and backup in one transaction",
];

pub const IMPACT: &[(&str, &str)] = &[
    (
        "10.20.4.17 → 10.30.0.8 tcp/445",
        "1,204 flows · finance-pc pool",
    ),
    ("10.20.6.3 → 10.30.0.9 tcp/445", "88 flows · scanner-02"),
    ("10.20.8.40 → 10.30.0.8 udp/137", "412 flows · legacy-erp"),
];

/// (name, handle, role, sign-in, last active)
pub const ADMINS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "Ana Ruiz",
        "a.ruiz",
        "network admin",
        "OIDC + passkey",
        "now",
    ),
    (
        "Adaeze Okafor",
        "a.okafor",
        "security admin",
        "OIDC + passkey",
        "10:58",
    ),
    ("Jun Nguyen", "j.nguyen", "operator", "OIDC", "10:52"),
    (
        "Sanjay Patel",
        "s.patel",
        "network admin",
        "OIDC",
        "yesterday",
    ),
    (
        "External auditor",
        "ext-auditor",
        "auditor",
        "OIDC to 31 Dec",
        "3 Nov",
    ),
    (
        "Break-glass",
        "local-admin",
        "network admin",
        "local + TOTP",
        "never",
    ),
];

/// (token, scopes, owner, expires)
pub const TOKENS: &[(&str, &str, &str, &str)] = &[
    (
        "terraform-ci",
        "policy:write nat:write",
        "s.patel",
        "14 Feb 2027",
    ),
    (
        "siem-export",
        "logs:read audit:read",
        "a.okafor",
        "1 Jun 2027",
    ),
    ("monitoring", "metrics:read", "a.ruiz", "1 Jun 2027"),
];

/// (time, who, event, from, hash)
pub const AUDIT: &[(&str, &str, &str, &str, &str)] = &[
    (
        "11:50:12",
        "a.ruiz",
        "signed in",
        "10.99.0.2 (vpn)",
        "9f3c…a1e0",
    ),
    (
        "10:58:40",
        "a.okafor",
        "approved candidate block-legacy-smb",
        "10.20.1.44",
        "41d2…7b9c",
    ),
    (
        "10:52:03",
        "j.nguyen",
        "created candidate block-legacy-smb (+9 −1)",
        "10.20.3.18",
        "c07a…3f12",
    ),
    (
        "09:14:55",
        "terraform-ci",
        "ran plan on policy (no changes)",
        "10.20.8.5",
        "2be8…90d4",
    ),
    (
        "03:10:21",
        "system",
        "IPS rules updated, signature verified",
        "—",
        "77e1…c5aa",
    ),
    (
        "yest 16:22",
        "s.patel",
        "committed #2479, confirm 5m, confirmed after 2m 10s",
        "10.20.1.12",
        "e4f9…12bd",
    ),
];

/// (pair, tenant, template, policy, drift, HA, version, site VPN, support until)
#[allow(clippy::type_complexity)]
pub const FLEET: &[(&str, &str, &str, &str, bool, &str, &str, &str, &str)] = &[
    (
        "syd-br-014",
        "Harbour Dental",
        "branch-std v14",
        "#2479 matches",
        false,
        "a active",
        "1.0.4",
        "5/6 up",
        "30 Nov 2026",
    ),
    (
        "mel-site-03",
        "Kestrel Logistics",
        "site-std v9",
        "#2466 matches",
        false,
        "a active",
        "1.0.3",
        "8/8 up",
        "30 Jun 2027",
    ),
    (
        "akl-core-01",
        "Tasman Freight",
        "core-std v4",
        "#2481 matches",
        false,
        "a active",
        "1.0.4",
        "12/12 up",
        "31 Mar 2027",
    ),
    (
        "bne-br-022",
        "Northside Clinics",
        "branch-std v14",
        "#2402 matches",
        false,
        "a active",
        "1.0.3",
        "2/2 up",
        "30 Nov 2026",
    ),
    (
        "per-br-007",
        "Northside Clinics",
        "branch-std v14",
        "#2398 2 rules drift",
        true,
        "single",
        "1.0.3 LTS",
        "2/2 up",
        "30 Nov 2026",
    ),
    (
        "cbr-br-011",
        "Harbour Dental",
        "branch-std v14",
        "#2479 matches",
        false,
        "b active",
        "1.0.4",
        "3/3 up",
        "30 Nov 2026",
    ),
    (
        "hba-br-002",
        "Kestrel Logistics",
        "branch-std v13",
        "#2455 template behind",
        true,
        "a active",
        "1.0.3",
        "2/2 up",
        "30 Jun 2027",
    ),
];

pub const NEEDS_ACTION: &[(&str, &str)] = &[
    (
        "Local policy drift on per-br-007",
        "2 rules added on the box outside template branch-std v14",
    ),
    (
        "Site tunnel wg-akl down for 3 h",
        "syd-br-014 ↔ akl-core-01, peer not answering",
    ),
    (
        "2 candidates waiting for a second approver",
        "block-legacy-smb (Harbour Dental), new-voip-vlan (Kestrel)",
    ),
    (
        "syd-br-014 missed its failover target once",
        "1.40 s loss on 2 Aug during an IPS reload; 3 passes since",
    ),
    (
        "14 firewalls reach end of support on 30 Nov",
        "they keep forwarding and keep receiving security fixes",
    ),
];

/// The commit the mock box runs before the candidate is applied, and the one it becomes.
pub const BASE_COMMIT: &str = "#2479";
pub const NEXT_COMMIT: &str = "#2480";

// ───────────────────────────── Import report ─────────────────────────────

pub const IMPORT_FILE: &str = "config-fw-par-02.xml";
pub const IMPORT_SOURCE: &str = "pfSense 2.7.2 backup";
/// (count, label)
pub const IMPORT_TOTALS: &[(&str, &str)] = &[
    ("1,231", "translated one to one (95.9%)"),
    ("41", "changed: works, but differs"),
    ("12", "unsupported: manual step needed"),
];
/// (pfSense item, what it became)
pub const IMPORT_CHANGED: &[(&str, &str)] = &[
    (
        "Floating rule \"Block bogons\" on WAN",
        "3 zone-pair rules: wan → lan, wan → dmz, wan → self",
    ),
    (
        "Interface group \"LANS\" (igb1, igb2.20, igb2.30)",
        "Zone \"lans\" with the same three interfaces",
    ),
    (
        "Gateway group WAN_FAILOVER, probe every 500 ms",
        "Health probe every 1 s, the 1.0 minimum",
    ),
    (
        "Alias \"OFFICE_NETS\" with a hostname entry",
        "Address group resolved by Unbound, refreshed every 5 min",
    ),
];
/// (pfSense item, manual step)
pub const IMPORT_UNSUPPORTED: &[(&str, &str)] = &[
    (
        "Package pfBlockerNG-devel, 6 IP feeds",
        "move DNS lists to per-zone blocklists; IP feeds to an address set",
    ),
    (
        "OpenVPN server \"RoadWarrior\", remote access",
        "set up the WireGuard portal with OIDC login",
    ),
    (
        "Captive portal zone \"guest\"",
        "not in 1.0; keep the old box for guest Wi-Fi or drop the portal",
    ),
    (
        "Limiter \"VoIP_up\" with a custom FQ-CoDel quantum",
        "use a CAKE tier on the zone; quantum is not exposed",
    ),
];
/// (flow, pfSense verdict, Netoxide verdict, why)
pub const IMPORT_DIFFS: &[(&str, &str, &str, &str)] = &[
    (
        "10.40.2.5:51022 → 8.8.8.8:53 udp",
        "pass",
        "drop",
        "a floating \"quick\" rule matched first; the zone-pair rule follows the DNS redirect policy",
    ),
    (
        "10.40.9.12 → 192.168.1.1 icmp",
        "drop",
        "pass",
        "implicit anti-lockout rule on LAN became an explicit rule on lans → self",
    ),
    (
        "203.0.113.7:443 → 10.40.0.10:8443 tcp",
        "pass",
        "drop",
        "port forward used \"Filter rule association: Pass\"; now NAT plus a rule needing review",
    ),
];

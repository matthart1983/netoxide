//! Renders the config's DNS and DHCP settings for dnsmasq.
//!
//! dnsmasq is the first backend because one program covers both services
//! and it can be run and tested in a network namespace. The config does not
//! name it, so another backend can render the same settings later.
//!
//! This crate only produces text. Running dnsmasq is the daemon's job.

use std::{collections::BTreeSet, fmt::Write, net::IpAddr};

use ox_schema::Config;

/// The name the daemon files this service under.
pub const DNSMASQ: &str = "dnsmasq";

/// The root zone's DNSSEC trust anchors: KSK-2017 and KSK-2024, as published
/// by IANA at https://data.iana.org/root-anchors/root-anchors.xml.
const ROOT_ANCHORS: [&str; 2] = [
    "trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    "trust-anchor=.,38696,8,2,683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
];

/// The dnsmasq config for a validated Netoxide config, or `None` when it
/// asks for neither DNS nor DHCP.
///
/// Paths and process options are not in here. The daemon passes the lease
/// file and similar on the command line, so this text depends on the config
/// alone and two boxes with the same config render the same file.
pub fn dnsmasq_conf(config: &Config) -> Option<String> {
    if config.dns.is_none() && config.dhcp.is_empty() && config.ipv6_autoconfig.is_empty() {
        return None;
    }
    let mut out = String::new();
    let mut line = |text: &str| {
        out.push_str(text);
        out.push('\n');
    };
    line("# Written by oxd from the running Netoxide config. Changes here are overwritten.");
    // Nothing comes from the machine's own files: the config is the only input.
    line("no-resolv");
    line("no-hosts");
    line("no-poll");
    // Keep working when an interface appears after start.
    line("bind-dynamic");

    let dns_ifaces: BTreeSet<&str> = config
        .dns
        .iter()
        .flat_map(|d| &d.zones)
        .flat_map(|z| config.zone_interfaces(z))
        .collect();
    let all: BTreeSet<&str> = dns_ifaces
        .iter()
        .copied()
        .chain(config.dhcp.keys().map(String::as_str))
        .chain(config.ipv6_autoconfig.iter().map(String::as_str))
        .collect();
    for name in &all {
        line(&format!("interface={name}"));
    }
    let hands_out =
        |n: &str| config.dhcp.contains_key(n) || config.ipv6_autoconfig.iter().any(|i| i == n);
    for name in dns_ifaces.iter().filter(|n| !hands_out(n)) {
        line(&format!("no-dhcp-interface={name}"));
    }

    match &config.dns {
        None => line("port=0"),
        Some(dns) => {
            for up in &dns.upstream {
                line(&format!("server={up}"));
            }
            // Never forward bare names or private reverse lookups upstream.
            line("domain-needed");
            line("bogus-priv");
            if dns.dnssec {
                line("dnssec");
                line("dnssec-check-unsigned");
                for anchor in ROOT_ANCHORS {
                    line(anchor);
                }
            }
            if let Some(domain) = &dns.domain {
                line(&format!("domain={domain}"));
                line(&format!("local=/{domain}/"));
                line("expand-hosts");
            }
            for h in &dns.hosts {
                match &dns.domain {
                    Some(d) if !h.name.contains('.') => {
                        line(&format!(
                            "host-record={}.{d},{},{}",
                            h.name, h.name, h.address
                        ));
                    }
                    _ => line(&format!("host-record={},{}", h.name, h.address)),
                }
            }
        }
    }

    for (name, pool) in &config.dhcp {
        // Validation guarantees the interface and its IPv4 address exist.
        let Some(own) = config
            .interfaces
            .get(name)
            .and_then(|i| i.addresses.iter().map(|a| a.0).find(|a| a.addr().is_ipv4()))
        else {
            continue;
        };
        line(&format!(
            "dhcp-range=interface:{name},{},{},{},{}",
            pool.first,
            pool.last,
            own.netmask(),
            pool.lease.seconds()
        ));
        // dnsmasq tags each request with the interface it arrived on. Without
        // these options it hands out its own address as router and resolver.
        if !pool.dns.is_empty() {
            let servers: Vec<String> = pool.dns.iter().map(IpAddr::to_string).collect();
            line(&format!(
                "dhcp-option=tag:{name},option:dns-server,{}",
                servers.join(",")
            ));
        }
        for st in &pool.statics {
            let mut entry = format!("dhcp-host={},{}", st.mac, st.address);
            if let Some(n) = &st.name {
                let _ = write!(entry, ",{n}");
            }
            line(&entry);
        }
    }
    if !config.ipv6_autoconfig.is_empty() {
        // Announce the interface's own /64. Devices pick their address
        // themselves; the box hands out none and keeps no IPv6 leases.
        line("enable-ra");
        for name in &config.ipv6_autoconfig {
            line(&format!("dhcp-range=::,constructor:{name},ra-only,64,12h"));
        }
    }
    if !config.dhcp.is_empty() {
        // The box is the only DHCP server on its networks, so it may correct
        // clients that ask for an address from somewhere else.
        line("dhcp-authoritative");
    }
    Some(out)
}

/// One row of dnsmasq's lease file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRow {
    /// Unix time the lease ends.
    pub expires: u64,
    pub mac: String,
    pub address: String,
    /// The name the client gave, if any.
    pub name: Option<String>,
}

/// Parses dnsmasq's lease file: `expiry mac address name client-id` per line.
pub fn parse_leases(text: &str) -> Vec<LeaseRow> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            // IPv6 leases and the server DUID line have a different shape.
            if f.len() < 4 || f[1].matches(':').count() != 5 {
                return None;
            }
            Some(LeaseRow {
                expires: f[0].parse().ok()?,
                mac: f[1].to_string(),
                address: f[2].to_string(),
                name: (f[3] != "*").then(|| f[3].to_string()),
            })
        })
        .collect()
}

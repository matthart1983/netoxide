//! Config values that are written as one string, such as `"tcp/443"` or
//! `"@finance-pcs"`. Each parses on load, so a typo fails with the value named.

use std::{borrow::Cow, fmt, net::IpAddr, str::FromStr};

use ipnet::IpNet;
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

/// Gives a string-typed value its serde and JSON Schema impls from
/// `FromStr` and `Display`.
macro_rules! string_typed {
    ($ty:ident, $name:literal, $desc:literal) => {
        impl TryFrom<String> for $ty {
            type Error = String;
            fn try_from(s: String) -> Result<Self, String> {
                s.parse()
            }
        }
        impl From<$ty> for String {
            fn from(v: $ty) -> String {
                v.to_string()
            }
        }
        impl JsonSchema for $ty {
            fn schema_name() -> Cow<'static, str> {
                $name.into()
            }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({ "type": "string", "description": $desc })
            }
        }
    };
}

/// True for names the config lets users choose: zones, groups, services.
/// Lowercase letters, digits and hyphens, starting with a letter, at most 32.
pub fn is_name(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
        && s.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// A network or a single host. A bare address means the host itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Net(pub IpNet);

impl FromStr for Net {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if let Ok(net) = s.parse::<IpNet>() {
            // 10.20.4.17/16 is almost always a slip for 10.20.0.0/16 or a /32.
            if net.addr() != net.network() {
                return Err(format!(
                    "'{s}' has host bits set; write {} or {}",
                    net.trunc(),
                    net.addr()
                ));
            }
            return Ok(Net(net));
        }
        s.parse::<IpAddr>()
            .map(|a| Net(IpNet::from(a)))
            .map_err(|_| format!("'{s}' is not an address or a network in CIDR form"))
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0.prefix_len() == self.0.max_prefix_len() {
            write!(f, "{}", self.0.addr())
        } else {
            write!(f, "{}", self.0)
        }
    }
}
string_typed!(
    Net,
    "Net",
    "An IPv4 or IPv6 network in CIDR form, or a single address"
);

/// What a rule's `source` or `destination` entry names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum AddrRef {
    Any,
    /// `@name`: an entry in the top-level `addresses` table.
    Group(String),
    Net(Net),
}

impl FromStr for AddrRef {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if s == "any" {
            Ok(AddrRef::Any)
        } else if let Some(name) = s.strip_prefix('@') {
            if is_name(name) {
                Ok(AddrRef::Group(name.to_string()))
            } else {
                Err(format!("'{s}' is not a valid address group name"))
            }
        } else {
            s.parse().map(AddrRef::Net)
        }
    }
}

impl fmt::Display for AddrRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AddrRef::Any => f.write_str("any"),
            AddrRef::Group(g) => write!(f, "@{g}"),
            AddrRef::Net(n) => n.fmt(f),
        }
    }
}
string_typed!(
    AddrRef,
    "AddrRef",
    "\"any\", \"@group-name\", a network in CIDR form, or a single address"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// One protocol and port range, or ICMP for one address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum PortSpec {
    /// `tcp/443` or `udp/137-138`. `first <= last`.
    Ports {
        proto: Proto,
        first: u16,
        last: u16,
    },
    Icmp,
    Icmpv6,
}

impl FromStr for PortSpec {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "icmp" => return Ok(PortSpec::Icmp),
            "icmpv6" => return Ok(PortSpec::Icmpv6),
            _ => {}
        }
        let bad = || format!("'{s}' is not a service; write tcp/443, udp/137-138, icmp or icmpv6");
        let (proto, ports) = s.split_once('/').ok_or_else(bad)?;
        let proto = match proto {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            _ => return Err(bad()),
        };
        let (first, last) = match ports.split_once('-') {
            Some((a, b)) => (a.parse().map_err(|_| bad())?, b.parse().map_err(|_| bad())?),
            None => {
                let p: u16 = ports.parse().map_err(|_| bad())?;
                (p, p)
            }
        };
        if first == 0 || first > last {
            return Err(format!("'{s}' has an empty or zero port range"));
        }
        Ok(PortSpec::Ports { proto, first, last })
    }
}

impl fmt::Display for PortSpec {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PortSpec::Icmp => f.write_str("icmp"),
            PortSpec::Icmpv6 => f.write_str("icmpv6"),
            PortSpec::Ports { proto, first, last } if first == last => {
                write!(f, "{}/{first}", proto.as_str())
            }
            PortSpec::Ports { proto, first, last } => {
                write!(f, "{}/{first}-{last}", proto.as_str())
            }
        }
    }
}
string_typed!(
    PortSpec,
    "PortSpec",
    "\"tcp/443\", \"udp/137-138\", \"icmp\" or \"icmpv6\""
);

/// What a rule's `service` entry names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum ServiceRef {
    Any,
    /// An entry in the top-level `services` table.
    Named(String),
    Port(PortSpec),
}

impl FromStr for ServiceRef {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if s == "any" {
            return Ok(ServiceRef::Any);
        }
        if let Ok(p) = s.parse::<PortSpec>() {
            return Ok(ServiceRef::Port(p));
        }
        if is_name(s) {
            Ok(ServiceRef::Named(s.to_string()))
        } else {
            Err(format!(
                "'{s}' is not a service name, tcp/443, udp/137-138, icmp or icmpv6"
            ))
        }
    }
}

impl fmt::Display for ServiceRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ServiceRef::Any => f.write_str("any"),
            ServiceRef::Named(n) => f.write_str(n),
            ServiceRef::Port(p) => p.fmt(f),
        }
    }
}
string_typed!(
    ServiceRef,
    "ServiceRef",
    "\"any\", a name from the services table, or a port such as \"tcp/443\""
);

/// How outbound NAT rewrites the source address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Translate {
    /// Use the address of the interface the packet leaves by.
    Masquerade,
    Address(IpAddr),
}

impl FromStr for Translate {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if s == "masquerade" {
            Ok(Translate::Masquerade)
        } else {
            s.parse()
                .map(Translate::Address)
                .map_err(|_| format!("'{s}' is not \"masquerade\" or an address"))
        }
    }
}

impl fmt::Display for Translate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Translate::Masquerade => f.write_str("masquerade"),
            Translate::Address(a) => a.fmt(f),
        }
    }
}
string_typed!(Translate, "Translate", "\"masquerade\" or a source address");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nets_parse_for_both_families() {
        assert_eq!(
            "10.20.0.0/16".parse::<Net>().unwrap().to_string(),
            "10.20.0.0/16"
        );
        assert_eq!(
            "10.20.4.17".parse::<Net>().unwrap().to_string(),
            "10.20.4.17"
        );
        assert_eq!(
            "2001:db8:4a00:1::/64".parse::<Net>().unwrap().to_string(),
            "2001:db8:4a00:1::/64"
        );
        assert_eq!(
            "2001:db8::17".parse::<Net>().unwrap().to_string(),
            "2001:db8::17"
        );
    }

    #[test]
    fn host_bits_are_refused_with_both_fixes_named() {
        let e = "10.20.4.17/16".parse::<Net>().unwrap_err();
        assert!(
            e.contains("10.20.0.0/16") && e.contains("10.20.4.17"),
            "{e}"
        );
        assert!("2001:db8::1/64".parse::<Net>().is_err());
    }

    #[test]
    fn services_round_trip() {
        for s in ["tcp/443", "udp/137-138", "icmp", "icmpv6"] {
            assert_eq!(s.parse::<PortSpec>().unwrap().to_string(), s);
        }
        for s in ["tcp/0", "tcp/90-80", "sctp/1", "tcp/70000", "tcp/"] {
            assert!(s.parse::<PortSpec>().is_err(), "{s} should not parse");
        }
        assert_eq!(
            "smb".parse::<ServiceRef>().unwrap(),
            ServiceRef::Named("smb".into())
        );
        assert!("SMB".parse::<ServiceRef>().is_err());
    }

    #[test]
    fn address_refs_round_trip() {
        for s in ["any", "@finance-pcs", "10.0.0.0/8", "2001:db8::/32"] {
            assert_eq!(s.parse::<AddrRef>().unwrap().to_string(), s);
        }
        assert!("@Bad_Name".parse::<AddrRef>().is_err());
    }
}

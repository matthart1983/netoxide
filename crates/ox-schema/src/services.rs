//! Services the box provides to its networks: DNS and DHCP.
//!
//! The config says what to serve. It does not name the program that serves
//! it; that is the daemon's choice.

use std::{
    borrow::Cow,
    collections::BTreeMap,
    fmt,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

/// A DNS resolver for the box's networks. It forwards to `upstream` and
/// answers for the local names in `hosts` and for DHCP clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    /// The zones whose clients may use the resolver.
    pub zones: Vec<String>,
    /// The resolvers to forward to, such as `1.1.1.1`.
    #[schemars(with = "Vec<String>")]
    pub upstream: Vec<IpAddr>,
    /// Validate answers with DNSSEC. On by default.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub dnssec: bool,
    /// The domain for local names, such as `home.arpa`. A host called `nas`
    /// is then also `nas.home.arpa`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Local names with fixed addresses.
    #[serde(default, rename = "host", skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<DnsHost>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DnsHost {
    pub name: String,
    #[schemars(with = "String")]
    pub address: IpAddr,
}

/// An IPv4 address pool handed out on one interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DhcpPool {
    /// First address of the pool.
    #[schemars(with = "String")]
    pub first: Ipv4Addr,
    /// Last address of the pool.
    #[schemars(with = "String")]
    pub last: Ipv4Addr,
    /// How long a client keeps its address, such as `12h`. Defaults to 12h.
    #[serde(default, skip_serializing_if = "Lease::is_default")]
    pub lease: Lease,
    /// The DNS servers clients are told to use. Defaults to the box itself
    /// when its resolver serves this interface's zone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(with = "Vec<String>")]
    pub dns: Vec<IpAddr>,
    /// Devices that always get the same address.
    #[serde(default, rename = "static", skip_serializing_if = "Vec::is_empty")]
    pub statics: Vec<StaticLease>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StaticLease {
    pub mac: Mac,
    #[schemars(with = "String")]
    pub address: Ipv4Addr,
    /// The device's name. It becomes a local DNS name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// DHCP pools by interface name.
pub type Dhcp = BTreeMap<String, DhcpPool>;

fn yes() -> bool {
    true
}
fn is_true(b: &bool) -> bool {
    *b
}

/// True for a name usable in DNS: letters, digits and hyphens in each label.
pub fn is_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// A lease time, written as `30m`, `12h` or `7d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Lease(pub u32);

impl Lease {
    const DEFAULT: Lease = Lease(12 * 3600);

    fn is_default(&self) -> bool {
        *self == Lease::DEFAULT
    }

    pub fn seconds(self) -> u32 {
        self.0
    }
}

impl Default for Lease {
    fn default() -> Lease {
        Lease::DEFAULT
    }
}

impl FromStr for Lease {
    type Err = String;
    fn from_str(s: &str) -> Result<Lease, String> {
        let bad = || format!("'{s}' is not a lease time; write 30m, 12h or 7d");
        let (digits, scale) = match s.chars().last() {
            Some('m') => (&s[..s.len() - 1], 60),
            Some('h') => (&s[..s.len() - 1], 3600),
            Some('d') => (&s[..s.len() - 1], 86_400),
            _ => return Err(bad()),
        };
        let secs = digits
            .parse::<u32>()
            .ok()
            .and_then(|n| n.checked_mul(scale))
            .ok_or_else(bad)?;
        if !(120..=30 * 86_400).contains(&secs) {
            return Err(format!("lease '{s}' must be between 2 minutes and 30 days"));
        }
        Ok(Lease(secs))
    }
}

impl fmt::Display for Lease {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            s if s % 86_400 == 0 => write!(f, "{}d", s / 86_400),
            s if s % 3600 == 0 => write!(f, "{}h", s / 3600),
            s => write!(f, "{}m", s / 60),
        }
    }
}

impl TryFrom<String> for Lease {
    type Error = String;
    fn try_from(s: String) -> Result<Lease, String> {
        s.parse()
    }
}
impl From<Lease> for String {
    fn from(l: Lease) -> String {
        l.to_string()
    }
}
impl JsonSchema for Lease {
    fn schema_name() -> Cow<'static, str> {
        "Lease".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "string", "description": "A lease time such as 30m, 12h or 7d" })
    }
}

/// A hardware address, written as `aa:bb:cc:dd:ee:ff`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Mac(pub [u8; 6]);

impl FromStr for Mac {
    type Err = String;
    fn from_str(s: &str) -> Result<Mac, String> {
        let bad = || format!("'{s}' is not a hardware address; write aa:bb:cc:dd:ee:ff");
        let parts: Vec<&str> = s.split([':', '-']).collect();
        if parts.len() != 6 {
            return Err(bad());
        }
        let mut out = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            if p.len() != 2 {
                return Err(bad());
            }
            out[i] = u8::from_str_radix(p, 16).map_err(|_| bad())?;
        }
        Ok(Mac(out))
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let m = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

impl TryFrom<String> for Mac {
    type Error = String;
    fn try_from(s: String) -> Result<Mac, String> {
        s.parse()
    }
}
impl From<Mac> for String {
    fn from(m: Mac) -> String {
        m.to_string()
    }
}
impl JsonSchema for Mac {
    fn schema_name() -> Cow<'static, str> {
        "Mac".into()
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "string", "description": "A hardware address such as aa:bb:cc:dd:ee:ff" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leases_parse_and_print() {
        for (text, secs) in [("30m", 1800), ("12h", 43_200), ("7d", 604_800)] {
            let l: Lease = text.parse().unwrap();
            assert_eq!((l.seconds(), l.to_string().as_str()), (secs, text));
        }
        for bad in ["12", "1m", "40d", "h", "12 h", "-1h"] {
            assert!(bad.parse::<Lease>().is_err(), "{bad}");
        }
    }

    #[test]
    fn hardware_addresses_parse_in_both_common_forms() {
        let m: Mac = "AA:BB:cc:dd:ee:0f".parse().unwrap();
        assert_eq!(m.to_string(), "aa:bb:cc:dd:ee:0f");
        assert_eq!("aa-bb-cc-dd-ee-0f".parse::<Mac>().unwrap(), m);
        for bad in [
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:gg",
            "aabbccddeeff",
            "a:b:c:d:e:f",
        ] {
            assert!(bad.parse::<Mac>().is_err(), "{bad}");
        }
    }

    #[test]
    fn hostnames_are_checked() {
        for ok in ["nas", "nas.home.arpa", "printer-2"] {
            assert!(is_hostname(ok), "{ok}");
        }
        for bad in ["", "-nas", "nas-", "my nas", "a..b", "nas_1"] {
            assert!(!is_hostname(bad), "{bad}");
        }
    }
}

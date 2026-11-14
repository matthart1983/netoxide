//! The Netoxide config: one typed document that describes a box.
//!
//! This crate parses the document from TOML or JSON, validates it, and
//! publishes its JSON Schema. Every other part of Netoxide reads these types
//! and nothing else.
//!
//! Schema version 1 covers zones, interfaces, address groups, services,
//! zone-pair filter policies, NAT, a DNS resolver and IPv4 DHCP. VPN, routing
//! protocols and HA are not in it yet.

mod services;
mod strings;
mod validate;

use std::{collections::BTreeMap, net::IpAddr, path::Path};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use services::{Dhcp, DhcpPool, Dns, DnsHost, Lease, Mac, StaticLease, is_hostname};
pub use strings::{AddrRef, Net, PortSpec, Proto, ServiceRef, Translate, is_name};
pub use validate::Problem;

/// The schema version this build reads and writes.
pub const SCHEMA_VERSION: u32 = 1;

/// The zone name for traffic addressed to the box itself.
pub const SELF_ZONE: &str = "self";

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("{path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("{0}")]
    Toml(#[from] toml::de::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("{} problem(s) in the config:\n{}", .0.len(), .0.iter().map(|p| format!("  {p}")).collect::<Vec<_>>().join("\n"))]
    Invalid(Vec<Problem>),
}

/// The whole config for one box.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Schema version of this document. Must be 1.
    pub schema: u32,
    pub hostname: String,
    /// Interfaces where the box announces its IPv6 network, so devices there
    /// give themselves an address and learn the box as their router.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ipv6_autoconfig: Vec<String>,
    /// Zones group interfaces. Rules are written between zones.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub zones: BTreeMap<String, Zone>,
    /// Interfaces by kernel name, such as `lan0.20`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub interfaces: BTreeMap<String, Interface>,
    /// Named address groups, used in rules as `@name`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub addresses: BTreeMap<String, Vec<Net>>,
    /// Named services, used in rules by name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<String, Vec<PortSpec>>,
    /// One entry per zone pair. Rules in a pair are tried in order.
    #[serde(default, rename = "policy", skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<Policy>,
    #[serde(default, skip_serializing_if = "Nat::is_empty")]
    pub nat: Nat,
    /// A DNS resolver for the box's networks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,
    /// IPv4 address pools, by interface name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub dhcp: Dhcp,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub zone: String,
    /// Addresses of the box on this interface, each with its prefix length,
    /// such as `10.20.0.1/16`.
    #[serde(default)]
    pub addresses: Vec<IfaceAddr>,
    /// True when the default route leaves by this interface.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub default_route: bool,
    /// The routers the default route goes through, at most one for IPv4
    /// and one for IPv6, such as `["203.0.113.1"]`. Only on an interface
    /// with `default_route`. Leave it out when the address comes from the
    /// network, which then names the router itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateway: Vec<std::net::IpAddr>,
    /// Ask the network on this interface for the box's IPv4 address and
    /// router (DHCP), as an internet provider's modem expects. Only on an
    /// interface with `default_route` and no fixed IPv4 address.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dhcp_client: bool,
}

/// An interface address with its prefix length, such as `10.20.0.1/16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IfaceAddr(pub ipnet::IpNet);

impl JsonSchema for IfaceAddr {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "IfaceAddr".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "An interface address with its prefix length, such as 10.20.0.1/16"
        })
    }
}

/// The rules for traffic from one zone to another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub from: String,
    /// A zone name, or `self` for traffic addressed to the box.
    pub to: String,
    /// Log packets that match no rule and are dropped. On by default.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub log_default: bool,
    #[serde(default, rename = "rule", skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Stable ID, unique in the config. It appears in logs and in `ox explain`.
    pub id: String,
    pub name: String,
    pub action: Action,
    #[serde(default = "any_addr", skip_serializing_if = "is_any_addr")]
    pub source: Vec<AddrRef>,
    #[serde(default = "any_addr", skip_serializing_if = "is_any_addr")]
    pub destination: Vec<AddrRef>,
    #[serde(default = "any_service", skip_serializing_if = "is_any_service")]
    pub service: Vec<ServiceRef>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub log: bool,
    /// A disabled rule stays in the config and is left out of the ruleset.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub enabled: bool,
    /// Why the rule exists, such as a change ticket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Accept,
    /// Discard silently.
    Drop,
    /// Discard and tell the sender.
    Reject,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Accept => "accept",
            Action::Drop => "drop",
            Action::Reject => "reject",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Nat {
    /// Port forwards: destination NAT to an internal host.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forward: Vec<Forward>,
    /// Source NAT for traffic leaving by a zone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbound: Vec<Outbound>,
}

impl Nat {
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty() && self.outbound.is_empty()
    }
}

/// A port forward. It only rewrites the destination. The packet still has to
/// pass the filter rule named in `rule`, so there is no hidden pass rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Forward {
    pub id: String,
    pub name: String,
    /// The zone the packet arrives from.
    pub from: String,
    /// The address the packet is sent to, before translation.
    #[schemars(with = "String")]
    pub address: IpAddr,
    /// A TCP or UDP port or port range.
    pub service: PortSpec,
    /// The internal host that receives the packet.
    #[schemars(with = "String")]
    pub to: IpAddr,
    /// The port on the internal host. Defaults to the original port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_port: Option<u16>,
    /// ID of the accept rule that lets the translated packet through.
    pub rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Outbound {
    pub id: String,
    pub name: String,
    pub from: String,
    pub to: String,
    #[serde(default = "any_addr", skip_serializing_if = "is_any_addr")]
    pub source: Vec<AddrRef>,
    pub translate: Translate,
}

fn yes() -> bool {
    true
}
fn is_true(b: &bool) -> bool {
    *b
}
fn any_addr() -> Vec<AddrRef> {
    vec![AddrRef::Any]
}
fn is_any_addr(v: &[AddrRef]) -> bool {
    v == [AddrRef::Any]
}
fn any_service() -> Vec<ServiceRef> {
    vec![ServiceRef::Any]
}
fn is_any_service(v: &[ServiceRef]) -> bool {
    v == [ServiceRef::Any]
}

impl Config {
    /// Parses and validates a TOML document.
    pub fn from_toml(text: &str) -> Result<Config, LoadError> {
        let config: Config = toml::from_str(text)?;
        config.checked()
    }

    /// Parses and validates a JSON document.
    pub fn from_json(text: &str) -> Result<Config, LoadError> {
        let config: Config = serde_json::from_str(text)?;
        config.checked()
    }

    /// Loads a file. `.json` is read as JSON and anything else as TOML.
    pub fn load(path: &Path) -> Result<Config, LoadError> {
        let text = std::fs::read_to_string(path).map_err(|source| LoadError::Read {
            path: path.display().to_string(),
            source,
        })?;
        if path.extension().is_some_and(|e| e == "json") {
            Config::from_json(&text)
        } else {
            Config::from_toml(&text)
        }
    }

    fn checked(self) -> Result<Config, LoadError> {
        let problems = self.validate();
        if problems.is_empty() {
            Ok(self)
        } else {
            Err(LoadError::Invalid(problems))
        }
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).expect("a valid config always serialises")
    }

    /// The JSON Schema for this config version.
    pub fn json_schema() -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(Config)).expect("schema is plain JSON")
    }

    /// Every rule with the policy it belongs to, in config order.
    pub fn rules(&self) -> impl Iterator<Item = (&Policy, &Rule)> {
        self.policies
            .iter()
            .flat_map(|p| p.rules.iter().map(move |r| (p, r)))
    }

    /// Interfaces in a zone, in name order.
    pub fn zone_interfaces(&self, zone: &str) -> Vec<&str> {
        self.interfaces
            .iter()
            .filter(|(_, i)| i.zone == zone)
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// The networks an address reference stands for. `None` means any.
    /// Call only on a validated config: an unknown group is empty here.
    pub fn resolve_addrs(&self, refs: &[AddrRef]) -> Option<Vec<ipnet::IpNet>> {
        let mut nets = vec![];
        for r in refs {
            match r {
                AddrRef::Any => return None,
                AddrRef::Net(n) => nets.push(n.0),
                AddrRef::Group(g) => {
                    nets.extend(self.addresses.get(g).into_iter().flatten().map(|n| n.0));
                }
            }
        }
        Some(nets)
    }

    /// The ports a service reference stands for. `None` means any.
    pub fn resolve_services(&self, refs: &[ServiceRef]) -> Option<Vec<PortSpec>> {
        let mut specs = vec![];
        for r in refs {
            match r {
                ServiceRef::Any => return None,
                ServiceRef::Port(p) => specs.push(*p),
                ServiceRef::Named(n) => {
                    specs.extend(self.services.get(n).into_iter().flatten().copied());
                }
            }
        }
        Some(specs)
    }
}

//! Who may do what: roles, access tokens, and the four-eyes setting.

use std::{collections::BTreeSet, fs, io::Read, path::Path};

use ox_schema::Config;

use serde::{Deserialize, Serialize};

use crate::audit::sha256_hex;

/// What a caller wants to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Status, running config, candidates, plans, explain, leases, kernel.
    Read,
    ReadAudit,
    /// Save and delete candidates.
    Edit,
    Approve,
    /// Commit, confirm and revert.
    Commit,
    Rollback,
    /// Tokens, roles and settings. Whoever has this can give themselves
    /// anything, so it is full control.
    Manage,
}

impl Action {
    pub const ALL: [Action; 7] = [
        Action::Read,
        Action::ReadAudit,
        Action::Edit,
        Action::Approve,
        Action::Commit,
        Action::Rollback,
        Action::Manage,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::ReadAudit => "read-audit",
            Action::Edit => "edit",
            Action::Approve => "approve",
            Action::Commit => "commit",
            Action::Rollback => "rollback",
            Action::Manage => "manage",
        }
    }

    pub fn parse(s: &str) -> Option<Action> {
        Action::ALL.into_iter().find(|a| a.as_str() == s)
    }

    pub fn describe(self) -> &'static str {
        match self {
            Action::Read => "read the config and status",
            Action::ReadAudit => "read the audit log",
            Action::Edit => "save or delete candidates",
            Action::Approve => "approve candidates",
            Action::Commit => "commit, confirm or revert",
            Action::Rollback => "roll back",
            Action::Manage => "manage tokens, roles and settings",
        }
    }
}

/// A part of the config. A role can be held to some of them, and then it
/// may only save, approve or commit changes that stay inside those parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Section {
    /// Zones, address groups, named services, rules and NAT.
    Firewall,
    /// The hostname, interfaces and IPv6 announcements.
    Network,
    /// DNS and DHCP.
    Services,
    /// WireGuard tunnels and their peers.
    Vpn,
}

impl Section {
    pub const ALL: [Section; 4] = [
        Section::Firewall,
        Section::Network,
        Section::Services,
        Section::Vpn,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Section::Firewall => "firewall",
            Section::Network => "network",
            Section::Services => "services",
            Section::Vpn => "vpn",
        }
    }

    pub fn parse(s: &str) -> Option<Section> {
        Section::ALL.into_iter().find(|x| x.as_str() == s)
    }

    /// The section a top-level key of the config belongs to.
    pub fn of_key(key: &str) -> Option<Section> {
        Some(match key {
            "zones" | "addresses" | "services" | "policy" | "nat" => Section::Firewall,
            "schema" | "hostname" | "interfaces" | "ipv6_autoconfig" => Section::Network,
            "dns" | "dhcp" => Section::Services,
            "wireguard" => Section::Vpn,
            _ => return None,
        })
    }
}

/// The sections that differ between two configs. With no old config, every
/// section the new one fills in counts. A config that does not parse, or a
/// key this code does not know, counts as every section, so a mistake here
/// can only make a limited role more limited.
pub fn touched(old: Option<&str>, new: &str) -> BTreeSet<Section> {
    let all = || Section::ALL.into_iter().collect();
    let object = |text: &str| -> Option<serde_json::Map<String, serde_json::Value>> {
        let config = Config::from_toml(text).ok()?;
        match serde_json::to_value(&config).ok()? {
            serde_json::Value::Object(map) => Some(map),
            _ => None,
        }
    };
    let Some(new) = object(new) else { return all() };
    let old = match old {
        None => serde_json::Map::new(),
        Some(text) => match object(text) {
            Some(map) => map,
            None => return all(),
        },
    };
    let mut out = BTreeSet::new();
    // Rules are written between zones, so moving an interface or a tunnel
    // into another zone changes which rules its traffic gets. That is a
    // firewall change, whichever section the key sits in.
    if zones_of(&old) != zones_of(&new) {
        out.insert(Section::Firewall);
    }
    for key in old.keys().chain(new.keys()) {
        if old.get(key) == new.get(key) {
            continue;
        }
        // The schema version is in every config and says nothing about what changed.
        if key == "schema" && old.is_empty() {
            continue;
        }
        match Section::of_key(key) {
            Some(section) => out.insert(section),
            None => return all(),
        };
    }
    out
}

/// The zone of every interface and tunnel in a config.
fn zones_of(config: &serde_json::Map<String, serde_json::Value>) -> Vec<(String, String)> {
    ["interfaces", "wireguard"]
        .iter()
        .filter_map(|key| config.get(*key)?.as_object())
        .flatten()
        .map(|(name, value)| (name.clone(), value["zone"].to_string()))
        .collect()
}

/// A named set of actions, held to some sections of the config or to all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub name: String,
    pub can: BTreeSet<Action>,
    /// The sections changes must stay inside. `None` is no limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sections: Option<BTreeSet<Section>>,
    /// Built-in roles come with the daemon and cannot be deleted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub builtin: bool,
}

impl Role {
    fn fixed(name: &str, can: &[Action], sections: Option<&[Section]>) -> Role {
        Role {
            name: name.to_string(),
            can: can.iter().copied().collect(),
            sections: sections.map(|s| s.iter().copied().collect()),
            builtin: true,
        }
    }

    /// The roles every box has.
    pub fn builtins() -> Vec<Role> {
        use Action::*;
        let operate = [Read, ReadAudit, Edit, Approve, Commit];
        vec![
            Role::fixed("viewer", &[Read], None),
            Role::fixed("auditor", &[Read, ReadAudit], None),
            Role::fixed("operator", &operate, None),
            Role::fixed(
                "network-admin",
                &operate,
                Some(&[Section::Network, Section::Services, Section::Vpn]),
            ),
            Role::fixed("security-admin", &operate, Some(&[Section::Firewall])),
            Role::admin(),
        ]
    }

    pub fn admin() -> Role {
        Role::fixed("admin", &Action::ALL, None)
    }

    pub fn builtin(name: &str) -> Option<Role> {
        Role::builtins().into_iter().find(|r| r.name == name)
    }

    /// Whether this role may perform an action at all.
    pub fn may(&self, action: Action) -> bool {
        self.can.contains(&action)
    }

    /// The sections out of `touched` this role may not change.
    pub fn outside(&self, touched: &BTreeSet<Section>) -> Vec<Section> {
        match &self.sections {
            None => vec![],
            Some(mine) => touched.difference(mine).copied().collect(),
        }
    }

    /// A line for people: what the role can do and where.
    pub fn describe(&self) -> String {
        let can: Vec<&str> = self.can.iter().map(|a| a.as_str()).collect();
        match &self.sections {
            None => can.join(", "),
            Some(s) => format!(
                "{}; changes only in {}",
                can.join(", "),
                s.iter().map(|x| x.as_str()).collect::<Vec<_>>().join(", ")
            ),
        }
    }
}

/// A caller, after the daemon has worked out who it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub name: String,
    pub role: Role,
}

/// An access token as stored. The secret itself is never kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub name: String,
    /// The name of a role, built in or made on this box.
    pub role: String,
    /// SHA-256 of the secret.
    pub sha256: String,
    pub created: u64,
    /// Unix time after which the token stops working.
    pub expires: Option<u64>,
    pub created_by: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// A commit needs approval from someone other than the candidate's author.
    #[serde(default)]
    pub four_eyes: bool,
}

/// Approval state of a candidate, stored beside it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateMeta {
    /// Who saved the candidate last.
    pub author: String,
    pub saved_at: u64,
    /// SHA-256 of the candidate text the fields below refer to.
    pub sha256: String,
    pub approved_by: Option<String>,
    pub approved_at: Option<u64>,
}

/// 32 random bytes from the kernel, as a token secret.
pub(crate) fn new_secret() -> std::io::Result<String> {
    let mut bytes = [0u8; 32];
    fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(format!(
        "ox_{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ))
}

pub(crate) fn load<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T, String> {
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Finds the token a secret belongs to, if it is still valid and its role
/// still exists.
pub(crate) fn verify(tokens: &[Token], roles: &[Role], secret: &str, now: u64) -> Option<Identity> {
    let hash = sha256_hex(secret.as_bytes());
    let token = tokens
        .iter()
        .find(|t| t.sha256 == hash && t.expires.is_none_or(|e| now < e))?;
    let role = Role::builtin(&token.role)
        .or_else(|| roles.iter().find(|r| r.name == token.role).cloned())?;
    Some(Identity {
        name: format!("token:{}", token.name),
        role,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_allow_what_they_should() {
        use Action::*;
        let operate = vec![Read, ReadAudit, Edit, Approve, Commit];
        let table = [
            ("viewer", vec![Read]),
            ("auditor", vec![Read, ReadAudit]),
            ("operator", operate.clone()),
            ("network-admin", operate.clone()),
            ("security-admin", operate),
            ("admin", Action::ALL.to_vec()),
        ];
        assert_eq!(table.len(), Role::builtins().len());
        for (name, allowed) in table {
            let role = Role::builtin(name).unwrap();
            for action in Action::ALL {
                assert_eq!(
                    role.may(action),
                    allowed.contains(&action),
                    "{name} {action:?}"
                );
            }
        }
        assert!(Role::builtin("root").is_none());
        // Only the two split roles are held to sections.
        for role in Role::builtins() {
            let limited = matches!(role.name.as_str(), "network-admin" | "security-admin");
            assert_eq!(role.sections.is_some(), limited, "{}", role.name);
        }
    }

    const BASE: &str = include_str!("../../../examples/home.toml");

    fn set(sections: &[Section]) -> BTreeSet<Section> {
        sections.iter().copied().collect()
    }

    #[test]
    fn a_change_is_placed_in_its_section() {
        let swap = |from: &str, to: &str| {
            assert!(BASE.contains(from), "the example config lost '{from}'");
            let text = BASE.replacen(from, to, 1);
            assert!(Config::from_toml(&text).is_ok(), "'{to}' made it invalid");
            text
        };
        assert_eq!(touched(Some(BASE), BASE), set(&[]));
        // Layout and comments are not changes.
        let spaced = swap("[dns]", "# the resolver\n\n[dns]");
        assert_eq!(touched(Some(BASE), &spaced), set(&[]));

        let hostname = BASE.lines().find(|l| l.starts_with("hostname")).unwrap();
        let renamed = swap(hostname, "hostname = \"edge\"");
        assert_eq!(touched(Some(BASE), &renamed), set(&[Section::Network]));

        let service = swap("ssh = [\"tcp/22\"]", "ssh = [\"tcp/2222\"]");
        assert_eq!(touched(Some(BASE), &service), set(&[Section::Firewall]));

        let dns = swap("domain = \"home.arpa\"", "domain = \"lan.example\"");
        assert_eq!(touched(Some(BASE), &dns), set(&[Section::Services]));
        // Going back is a change too.
        assert_eq!(touched(Some(&dns), BASE), set(&[Section::Services]));

        let both = dns.replacen(hostname, "hostname = \"edge\"", 1);
        assert_eq!(
            touched(Some(BASE), &both),
            set(&[Section::Network, Section::Services])
        );
        // The first config touches what it fills in.        // The first config touches what it fills in.
        assert_eq!(
            touched(None, BASE),
            set(&[Section::Firewall, Section::Network, Section::Services])
        );
        // Text that is not a config counts as everything.
        assert_eq!(touched(Some(BASE), "nonsense"), set(&Section::ALL));
        assert_eq!(touched(Some("nonsense"), BASE), set(&Section::ALL));
    }

    /// Rules are written between zones, so which zone a port or a tunnel
    /// is in decides which rules its traffic gets.
    #[test]
    fn moving_a_port_or_a_tunnel_between_zones_is_a_firewall_change() {
        let port = "schema = 1\nhostname = \"t\"\n\n[zones.a]\n\n[zones.b]\n\n[interfaces.eth0]\nzone = \"a\"\naddresses = [\"192.0.2.1/24\", \"2001:db8::1/64\"]\n";
        let tunnel = format!(
            "{port}\n[wireguard.wg0]\nzone = \"a\"\naddresses = [\"10.9.0.1/24\", \"fd00:9::1/64\"]\n"
        );
        let valid = |text: String| {
            assert!(
                Config::from_toml(&text).is_ok(),
                "not a valid config:\n{text}"
            );
            text
        };
        let (port, tunnel) = (valid(port.to_string()), valid(tunnel));

        let moved = valid(port.replacen("zone = \"a\"", "zone = \"b\"", 1));
        assert_eq!(
            touched(Some(&port), &moved),
            set(&[Section::Firewall, Section::Network])
        );
        // A new address on a port that stays where it is: network only.
        let renumbered = valid(port.replace("192.0.2.1/24", "192.0.2.2/24"));
        assert_eq!(touched(Some(&port), &renumbered), set(&[Section::Network]));

        // A new tunnel joins a zone; so does one that moves.
        assert_eq!(
            touched(Some(&port), &tunnel),
            set(&[Section::Firewall, Section::Vpn])
        );
        let rezoned = valid(tunnel.replacen("wg0]\nzone = \"a\"", "wg0]\nzone = \"b\"", 1));
        assert_eq!(
            touched(Some(&tunnel), &rezoned),
            set(&[Section::Firewall, Section::Vpn])
        );
        let readdressed = valid(tunnel.replace("10.9.0.1/24", "10.9.1.1/24"));
        assert_eq!(touched(Some(&tunnel), &readdressed), set(&[Section::Vpn]));
        // Taking a port away changes what its zone holds.
        assert_eq!(
            touched(Some(&tunnel), &port),
            set(&[Section::Firewall, Section::Vpn])
        );
    }

    #[test]
    fn every_config_key_has_a_section() {
        let schema = serde_json::to_value(Config::json_schema()).unwrap();
        let keys = schema["properties"].as_object().unwrap();
        assert!(keys.len() >= 12);
        for key in keys.keys() {
            assert!(
                Section::of_key(key).is_some(),
                "config key '{key}' has no section; add it to Section::of_key"
            );
        }
    }

    #[test]
    fn a_limited_role_names_what_is_outside_it() {
        let role = Role::builtin("network-admin").unwrap();
        assert!(
            role.outside(&set(&[Section::Vpn, Section::Network]))
                .is_empty()
        );
        assert_eq!(
            role.outside(&set(&[Section::Vpn, Section::Firewall])),
            vec![Section::Firewall]
        );
        assert!(Role::admin().outside(&set(&Section::ALL)).is_empty());
    }

    #[test]
    fn secrets_are_long_and_differ() {
        let (a, b) = (new_secret().unwrap(), new_secret().unwrap());
        assert!(a.starts_with("ox_") && a.len() == 67);
        assert_ne!(a, b);
    }
}

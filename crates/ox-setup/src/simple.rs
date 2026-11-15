//! The simple view of a config: who can reach what, as a grid of networks.
//!
//! This is a second way to look at the same config, never a second model.
//! A cell of the grid is one zone pair. It reads as Allowed or Blocked only
//! when the pair's rules are ones the grid itself could have written.
//! Anything else reads as Custom and cannot be changed from the grid, so a
//! click here can never throw away or misstate a rule someone wrote by hand.

use ox_schema::{Action, AddrRef, Config, Outbound, Policy, Rule, ServiceRef, Translate, is_name};
use serde::Serialize;

/// What one network may do towards another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Cell {
    /// The same network on both sides. The box does not sit between them.
    Same,
    /// Everything is allowed, by one plain rule.
    Allowed,
    /// Nothing is allowed.
    Blocked,
    /// There are rules the grid cannot show as one word. `summary` says
    /// what they do in a few words.
    Custom { summary: String },
}

/// A network, which is a zone under its everyday name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Network {
    /// The zone name, as the config and the advanced screens have it.
    pub zone: String,
    /// What to call it: the zone's description, or its name.
    pub name: String,
    /// True for the zone the default route leaves by.
    pub internet: bool,
    pub interfaces: Vec<String>,
    /// The box's own addresses on this network.
    pub addresses: Vec<String>,
    /// What this network may reach, as a few words.
    pub reaches: String,
}

/// Something on the inside that the internet may reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LetIn {
    pub id: String,
    pub name: String,
    /// The outside port, such as `tcp/443`.
    pub service: String,
    pub to: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Grid {
    pub networks: Vec<Network>,
    /// `cells[from][to]`, in the order of `networks`.
    pub cells: Vec<Vec<Cell>>,
    pub let_in: Vec<LetIn>,
}

/// The ID of the one rule the grid writes for a pair.
fn grid_rule(from: &str, to: &str) -> String {
    format!("r-allow-{from}-{to}")
}

/// The ID of the address translation the grid adds with an allow to the internet.
fn grid_nat(from: &str) -> String {
    format!("n-{from}-out")
}

/// True for a rule that lets everything through, with no conditions.
fn allows_everything(rule: &Rule) -> bool {
    rule.enabled
        && rule.action == Action::Accept
        && rule.source == [AddrRef::Any]
        && rule.destination == [AddrRef::Any]
        && rule.service == [ServiceRef::Any]
}

fn internet_zones(config: &Config) -> Vec<&str> {
    let mut zones: Vec<&str> = config
        .interfaces
        .values()
        .filter(|i| i.default_route)
        .map(|i| i.zone.as_str())
        .collect();
    zones.sort_unstable();
    zones.dedup();
    zones
}

fn display_name(config: &Config, zone: &str) -> String {
    if internet_zones(config).contains(&zone) {
        return "Internet".into();
    }
    match config
        .zones
        .get(zone)
        .and_then(|z| z.description.as_deref())
    {
        Some(d) if !d.trim().is_empty() => d.trim().to_string(),
        _ => zone.to_string(),
    }
}

fn cell(config: &Config, from: &str, to: &str) -> Cell {
    if from == to {
        return Cell::Same;
    }
    let forwards = config
        .nat
        .forward
        .iter()
        .filter(|f| f.from == from && zone_of_address(config, f.to) == Some(to))
        .count();
    let rules: Vec<&Rule> = config
        .policies
        .iter()
        .filter(|p| p.from == from && p.to == to)
        .flat_map(|p| p.rules.iter())
        .filter(|r| r.enabled)
        .collect();
    if rules.is_empty() {
        return Cell::Blocked;
    }
    if rules.len() == 1 && allows_everything(rules[0]) && forwards == 0 {
        return Cell::Allowed;
    }
    // Rules that only open forwarded ports read as what they are.
    let accepts = rules.iter().filter(|r| r.action == Action::Accept).count();
    let summary = if forwards > 0 && forwards == rules.len() {
        format!(
            "{forwards} service{} let in",
            if forwards == 1 { "" } else { "s" }
        )
    } else if accepts == rules.len()
        && rules
            .iter()
            .all(|r| r.source == [AddrRef::Any] && r.destination == [AddrRef::Any])
    {
        let mut services: Vec<String> = rules
            .iter()
            .flat_map(|r| r.service.iter().map(ToString::to_string))
            .collect();
        services.sort();
        services.dedup();
        format!("Only {}", services.join(", "))
    } else {
        format!(
            "{} rule{}",
            rules.len(),
            if rules.len() == 1 { "" } else { "s" }
        )
    };
    Cell::Custom { summary }
}

/// The zone whose interface holds an address, if any does.
fn zone_of_address(config: &Config, addr: std::net::IpAddr) -> Option<&str> {
    config
        .interfaces
        .values()
        .find(|i| i.addresses.iter().any(|a| a.0.contains(&addr)))
        .map(|i| i.zone.as_str())
}

/// The grid for a config. Networks are the zones, with the internet last.
pub fn grid(config: &Config) -> Grid {
    let internet = internet_zones(config);
    let mut zones: Vec<&str> = config.zones.keys().map(String::as_str).collect();
    zones.sort_by_key(|z| (internet.contains(z), *z));
    let cells: Vec<Vec<Cell>> = zones
        .iter()
        .map(|from| zones.iter().map(|to| cell(config, from, to)).collect())
        .collect();
    let networks = zones
        .iter()
        .enumerate()
        .map(|(row, zone)| {
            let mut all = vec![];
            let mut some = vec![];
            for (col, to) in zones.iter().enumerate() {
                match &cells[row][col] {
                    Cell::Allowed => all.push(display_name(config, to)),
                    Cell::Custom { .. } => some.push(display_name(config, to)),
                    Cell::Same | Cell::Blocked => {}
                }
            }
            let reaches = match (all.is_empty(), some.is_empty()) {
                (true, true) => "Nothing".to_string(),
                (false, true) => all.join(" and "),
                (true, false) => format!("Parts of {}", some.join(" and ")),
                (false, false) => format!("{}; parts of {}", all.join(" and "), some.join(" and ")),
            };
            let mine = || {
                config
                    .interfaces
                    .iter()
                    .filter(move |(_, i)| i.zone == *zone)
            };
            let tunnels = || {
                config
                    .wireguard
                    .iter()
                    .filter(move |(_, w)| w.zone == *zone)
            };
            Network {
                zone: zone.to_string(),
                name: display_name(config, zone),
                internet: internet.contains(zone),
                interfaces: mine()
                    .map(|(n, _)| n.clone())
                    .chain(tunnels().map(|(n, _)| n.clone()))
                    .collect(),
                addresses: mine()
                    .flat_map(|(_, i)| i.addresses.iter().map(|a| a.0.to_string()))
                    .chain(tunnels().flat_map(|(_, w)| w.addresses.iter().map(|a| a.0.to_string())))
                    .collect(),
                reaches,
            }
        })
        .collect();
    Grid {
        networks,
        cells,
        let_in: config
            .nat
            .forward
            .iter()
            .map(|f| LetIn {
                id: f.id.clone(),
                name: f.name.clone(),
                service: f.service.to_string(),
                to: match f.to_port {
                    Some(p) => format!("{} port {p}", f.to),
                    None => f.to.to_string(),
                },
            })
            .collect(),
    }
}

/// Lets one network reach another, or stops it. Returns what was done, in
/// sentences. A pair with rules of its own is refused: those are edited
/// where they can be seen in full.
pub fn set_access(
    config: &mut Config,
    from: &str,
    to: &str,
    allow: bool,
) -> Result<Vec<String>, String> {
    for zone in [from, to] {
        if !config.zones.contains_key(zone) {
            return Err(format!("there is no network called '{zone}'"));
        }
    }
    if from == to {
        return Err("devices on the same network reach each other without crossing the box".into());
    }
    let internet: Vec<String> = internet_zones(config)
        .into_iter()
        .map(String::from)
        .collect();
    let is_internet = |zone: &str| internet.iter().any(|z| z == zone);
    if is_internet(from) {
        return Err(
            "the internet is let in one service at a time, with a port forward, never as a whole"
                .into(),
        );
    }
    let (from_name, to_name) = (display_name(config, from), display_name(config, to));
    let before = cell(config, from, to);
    if let Cell::Custom { summary } = &before {
        return Err(format!(
            "{from_name} to {to_name} has its own rules ({summary}); change them in the rule editor"
        ));
    }
    let mut done = vec![];
    let rule_id = grid_rule(from, to);
    let nat_id = grid_nat(from);
    if allow {
        if before == Cell::Allowed {
            return Err(format!("{from_name} can already reach {to_name}"));
        }
        if !is_name(&rule_id) {
            return Err(format!(
                "the names '{from}' and '{to}' are too long to make a rule name from"
            ));
        }
        let rule = Rule {
            id: rule_id,
            name: format!("{from_name} may reach {to_name}"),
            action: Action::Accept,
            source: vec![AddrRef::Any],
            destination: vec![AddrRef::Any],
            service: vec![ServiceRef::Any],
            log: false,
            enabled: true,
            reason: Some("allowed from the access grid".into()),
        };
        match config
            .policies
            .iter_mut()
            .find(|p| p.from == from && p.to == to)
        {
            Some(policy) => policy.rules.push(rule),
            None => config.policies.push(Policy {
                from: from.into(),
                to: to.into(),
                log_default: true,
                rules: vec![rule],
            }),
        }
        done.push(format!("{from_name} can reach {to_name}"));
        // Private addresses are not routed on the internet, so traffic
        // going there has to appear to come from the box.
        let hidden = config
            .nat
            .outbound
            .iter()
            .any(|o| o.from == from && o.to == to);
        if is_internet(to) && !hidden && is_name(&nat_id) {
            config.nat.outbound.push(Outbound {
                id: nat_id,
                name: format!("{from_name} to the internet"),
                from: from.into(),
                to: to.into(),
                source: vec![AddrRef::Any],
                translate: Translate::Masquerade,
            });
            done.push(format!(
                "traffic from {from_name} to the internet appears to come from the box's own address"
            ));
        }
    } else {
        if before == Cell::Blocked {
            return Err(format!("{from_name} is already blocked from {to_name}"));
        }
        for policy in config
            .policies
            .iter_mut()
            .filter(|p| p.from == from && p.to == to)
        {
            policy.rules.retain(|r| !allows_everything(r));
        }
        // An empty pair says nothing the default does not, unless it holds
        // rules that are switched off.
        config
            .policies
            .retain(|p| !(p.from == from && p.to == to && p.rules.is_empty()));
        config.nat.outbound.retain(|o| o.id != nat_id);
        done.push(format!("{from_name} can no longer reach {to_name}"));
    }
    // The grid never leaves a config the checks refuse.
    config.clone().checked().map_err(|e| e.to_string())?;
    Ok(done)
}

/// The network a device's address is on, by the box's own addresses.
pub fn interface_for(config: &Config, addr: std::net::IpAddr) -> Option<String> {
    config
        .interfaces
        .iter()
        .find(|(_, i)| i.addresses.iter().any(|a| a.0.contains(&addr)))
        .map(|(name, _)| name.clone())
        .or_else(|| {
            config
                .wireguard
                .iter()
                .find(|(_, w)| w.addresses.iter().any(|a| a.0.contains(&addr)))
                .map(|(name, _)| name.clone())
        })
        // Anything else arrives from the internet side.
        .or_else(|| {
            config
                .interfaces
                .iter()
                .find(|(_, i)| i.default_route)
                .map(|(name, _)| name.clone())
        })
}

/// What a change does, as the difference between two configs' plain
/// descriptions: the sentences that start being true and those that stop.
pub fn plain_changes(old: &Config, new: &Config) -> (Vec<String>, Vec<String>) {
    let (before, after) = (crate::describe(old), crate::describe(new));
    let starts = after
        .iter()
        .filter(|l| !before.contains(l))
        .cloned()
        .collect();
    let stops = before
        .iter()
        .filter(|l| !after.contains(l))
        .cloned()
        .collect();
    (starts, stops)
}

/// What a change means to someone who thinks in networks, in a few
/// sentences: who can newly reach what, who no longer can, what is let in
/// from the internet, which devices join or leave the VPN. A change the
/// grid cannot put into words gives an empty list, and the caller falls
/// back to the full description.
pub fn headline(old: &Config, new: &Config) -> Vec<String> {
    let (before, after) = (grid(old), grid(new));
    let mut out = vec![];
    for (i, from) in after.networks.iter().enumerate() {
        for (j, to) in after.networks.iter().enumerate() {
            let was = before
                .networks
                .iter()
                .position(|n| n.zone == from.zone)
                .zip(before.networks.iter().position(|n| n.zone == to.zone))
                .map(|(a, b)| &before.cells[a][b]);
            let now = &after.cells[i][j];
            if was == Some(now) {
                continue;
            }
            match (was, now) {
                (_, Cell::Allowed) => out.push(format!("{} can reach {}", from.name, to.name)),
                (Some(Cell::Allowed | Cell::Custom { .. }), Cell::Blocked) => {
                    out.push(format!("{} can no longer reach {}", from.name, to.name));
                }
                (_, Cell::Custom { summary }) if !from.internet => out.push(format!(
                    "What {} can reach on {} changes ({})",
                    from.name,
                    to.name,
                    summary.to_lowercase()
                )),
                _ => {}
            }
        }
    }
    for f in &after.let_in {
        if !before.let_in.iter().any(|b| b.id == f.id) {
            out.push(format!(
                "{} is let in from the internet: {} goes to {}",
                f.name, f.service, f.to
            ));
        }
    }
    for f in &before.let_in {
        if !after.let_in.iter().any(|a| a.id == f.id) {
            out.push(format!("{} is no longer let in from the internet", f.name));
        }
    }
    let peers = |c: &Config| -> Vec<String> {
        c.wireguard
            .values()
            .flat_map(|w| w.peers.iter().map(|p| p.name.clone()))
            .collect()
    };
    let (had, has) = (peers(old), peers(new));
    for name in has.iter().filter(|n| !had.contains(n)) {
        out.push(format!("{name} can connect to the VPN"));
    }
    for name in had.iter().filter(|n| !has.contains(n)) {
        out.push(format!("{name} can no longer connect to the VPN"));
    }
    let blocked = |c: &Config| {
        c.dns
            .as_ref()
            .map(|d| d.blocked.clone())
            .unwrap_or_default()
    };
    let (had, has) = (blocked(old), blocked(new));
    for name in has.iter().filter(|n| !had.contains(n)) {
        out.push(format!("{name} is blocked for every device"));
    }
    for name in had.iter().filter(|n| !has.contains(n)) {
        out.push(format!("{name} is no longer blocked"));
    }
    for name in new.zones.keys().filter(|z| !old.zones.contains_key(*z)) {
        out.push(format!("A new network: {}", display_name(new, name)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = include_str!("../../../examples/home.toml");
    const BRANCH: &str = include_str!("../../../examples/branch.toml");

    fn at<'a>(g: &'a Grid, from: &str, to: &str) -> &'a Cell {
        let idx = |z: &str| g.networks.iter().position(|n| n.zone == z).unwrap();
        &g.cells[idx(from)][idx(to)]
    }

    #[test]
    fn the_home_example_reads_as_a_grid() {
        let config = Config::from_toml(HOME).unwrap();
        let g = grid(&config);
        let names: Vec<&str> = g.networks.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names.last(), Some(&"Internet"), "{names:?}");
        assert_eq!(at(&g, "lan", "wan"), &Cell::Allowed);
        assert_eq!(at(&g, "wan", "lan"), &Cell::Blocked);
        assert_eq!(at(&g, "lan", "lan"), &Cell::Same);
        let lan = g.networks.iter().find(|n| n.zone == "lan").unwrap();
        assert_eq!(lan.reaches, "Internet");
        assert!(lan.addresses.iter().any(|a| a.contains("192.168.10.1")));
        assert!(!g.networks.iter().any(|n| n.zone == ox_schema::SELF_ZONE));
    }

    #[test]
    fn hand_written_rules_read_as_custom_and_cannot_be_clicked_away() {
        let mut config = Config::from_toml(BRANCH).unwrap();
        let g = grid(&config);
        // Three rules with groups and services.
        assert!(matches!(at(&g, "lan", "dmz"), Cell::Custom { summary } if summary == "3 rules"));
        // One rule, any to any, for named services only.
        assert!(
            matches!(at(&g, "guest", "wan"), Cell::Custom { summary } if summary.starts_with("Only "))
        );
        // A forwarded port and its rule.
        assert!(
            matches!(at(&g, "wan", "dmz"), Cell::Custom { summary } if summary == "1 service let in")
        );
        assert_eq!(g.let_in.len(), 1);

        let before = config.clone();
        for allow in [true, false] {
            let e = set_access(&mut config, "lan", "dmz", allow).unwrap_err();
            assert!(
                e.contains("has its own rules") && e.contains("rule editor"),
                "{e}"
            );
        }
        assert_eq!(config, before, "a refused click changes nothing");
        assert!(
            set_access(&mut config, "wan", "lan", true)
                .unwrap_err()
                .contains("port forward")
        );
        assert!(set_access(&mut config, "lan", "lan", true).is_err());
        assert!(
            set_access(&mut config, "lan", "moon", true)
                .unwrap_err()
                .contains("no network called")
        );
    }

    #[test]
    fn allow_and_block_are_each_others_undo() {
        let start = Config::from_toml(BRANCH).unwrap();
        let mut config = start.clone();
        assert_eq!(at(&grid(&config), "dmz", "wan"), &Cell::Blocked);

        let done = set_access(&mut config, "dmz", "wan", true).unwrap();
        assert!(done[0].contains("can reach Internet"), "{done:?}");
        assert!(
            done.iter().any(|d| d.contains("box's own address")),
            "{done:?}"
        );
        assert_eq!(at(&grid(&config), "dmz", "wan"), &Cell::Allowed);
        // What the grid wrote is ordinary config the rule editor shows.
        let text = config.to_toml();
        assert!(text.contains("r-allow-dmz-wan") && text.contains("n-dmz-out"));
        assert!(Config::from_toml(&text).is_ok());
        assert!(
            set_access(&mut config, "dmz", "wan", true)
                .unwrap_err()
                .contains("already")
        );

        let done = set_access(&mut config, "dmz", "wan", false).unwrap();
        assert!(done[0].contains("can no longer reach"), "{done:?}");
        assert_eq!(
            config, start,
            "blocking takes away exactly what allowing added"
        );
        assert!(
            set_access(&mut config, "dmz", "wan", false)
                .unwrap_err()
                .contains("already blocked")
        );
    }

    #[test]
    fn between_inside_networks_no_translation_is_added() {
        let mut config = Config::from_toml(BRANCH).unwrap();
        let done = set_access(&mut config, "dmz", "guest", true).unwrap();
        assert_eq!(done.len(), 1, "{done:?}");
        assert!(!config.to_toml().contains("n-dmz-out"));
    }

    #[test]
    fn a_change_reads_as_sentences_that_start_and_stop() {
        let old = Config::from_toml(BRANCH).unwrap();
        let mut new = old.clone();
        set_access(&mut new, "dmz", "wan", true).unwrap();
        let (starts, stops) = plain_changes(&old, &new);
        assert!(
            starts
                .iter()
                .any(|l| l.contains("dmz → wan") && l.contains("allowed")),
            "{starts:?}"
        );
        assert!(stops.iter().any(|l| l.contains("dmz → wan")), "{stops:?}");
        assert_eq!(plain_changes(&old, &old), (vec![], vec![]));
    }

    #[test]
    fn a_change_gets_a_headline_in_network_words() {
        let old = Config::from_toml(BRANCH).unwrap();
        let mut new = old.clone();
        set_access(&mut new, "dmz", "wan", true).unwrap();
        assert_eq!(headline(&old, &new), ["Servers can reach Internet"]);
        assert_eq!(
            headline(&new, &old),
            ["Servers can no longer reach Internet"]
        );
        assert!(headline(&old, &old).is_empty());

        // A port let in, by the one-step action.
        let mut fwd = old.clone();
        crate::add_forward(
            &mut fwd,
            &crate::ForwardRequest {
                name: "Mail".into(),
                service: "tcp/25".parse().unwrap(),
                to: "10.30.0.25".parse().unwrap(),
                to_port: None,
                address: None,
            },
        )
        .unwrap();
        let lines = headline(&old, &fwd);
        assert!(
            lines
                .iter()
                .any(|l| l == "Mail is let in from the internet: tcp/25 goes to 10.30.0.25"),
            "{lines:?}"
        );
        assert!(
            headline(&fwd, &old)
                .iter()
                .any(|l| l == "Mail is no longer let in from the internet")
        );

        // A change the grid has no words for says nothing here.
        let renamed =
            Config::from_toml(&BRANCH.replacen("syd-br-014-a", "syd-br-015-a", 1)).unwrap();
        assert!(headline(&old, &renamed).is_empty());
    }

    #[test]
    fn a_device_is_placed_on_its_network() {
        let config = Config::from_toml(HOME).unwrap();
        let on = |a: &str| interface_for(&config, a.parse().unwrap());
        assert_eq!(on("192.168.10.50").as_deref(), Some("eth1"));
        assert_eq!(on("2001:db8:2::50").as_deref(), Some("eth1"));
        // Not on any inside network: it comes in from the internet.
        assert_eq!(on("198.51.100.7").as_deref(), Some("eth0"));
    }
}

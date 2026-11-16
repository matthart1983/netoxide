//! The live view: what the box is doing right now, one reading a second.
//!
//! Every number here comes from a counter the kernel keeps. Traffic is the
//! byte counters of the interfaces, read over netlink. Connections is the
//! kernel's count of tracked connections. Blocked is the packet counters of
//! the rules that drop, which the ruleset already has. Nothing is estimated,
//! and nothing is shown that the box cannot measure: there is no latency,
//! no per-device figure and no destination name yet.
//!
//! Readings are only taken while someone is looking. A view that nobody has
//! asked for in a while stops sampling and forgets its history, so an idle
//! box does no work for it.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use futures_util::TryStreamExt;
use ox_schema::{Action, Config, SELF_ZONE};
use rtnetlink::packet_route::link::LinkAttribute;
use serde::Serialize;
use serde_json::Value;

/// How many readings are kept: two minutes at one a second.
pub const WINDOW: usize = 120;
/// Sampling stops this long after the last time someone asked.
const IDLE: Duration = Duration::from_secs(15);
/// How many "just blocked" lines are kept.
const FEED: usize = 12;
/// A block that repeats within this many seconds adds to its line
/// instead of starting a new one.
const SAME_EVENT_SECS: u64 = 10;

/// What one moment's counters say. All of them only ever grow.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reading {
    /// Bytes received and sent, by interface name.
    pub interfaces: BTreeMap<String, (u64, u64)>,
    /// Tracked connections, when the kernel says.
    pub connections: Option<u64>,
    /// Packets counted by each rule, by its comment. `None` when the rules
    /// are not in a kernel to ask, as in a dry run.
    pub packets: Option<BTreeMap<String, u64>>,
}

/// A port to read, and the VLANs that ride on it. The kernel counts a
/// VLAN's traffic on its parent port as well, so the parent's own traffic
/// is what is left after the VLANs are taken off.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Port {
    name: String,
    vlans: Vec<String>,
}

/// A network, as the simple screens name it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Net {
    zone: String,
    name: String,
    ports: Vec<Port>,
}

/// What a config says about where to read: which ports face the internet,
/// which belong to each network, and which counters mean "blocked".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    internet: Vec<Port>,
    networks: Vec<Net>,
    /// Counter comment → the sentence for the feed.
    blocks: BTreeMap<String, String>,
}

impl Plan {
    pub fn new(config: &Config) -> Plan {
        let grid = ox_setup::grid(config);
        let name_of = |zone: &str| -> String {
            if zone == SELF_ZONE {
                return "the box itself".to_string();
            }
            grid.networks
                .iter()
                .find(|n| n.zone == zone)
                .map_or(zone.to_string(), |n| n.name.clone())
        };
        let mut blocks = BTreeMap::new();
        // Each pair of zones ends in a default drop with its own counter.
        let zones: Vec<&str> = config
            .zones
            .keys()
            .map(String::as_str)
            .chain([SELF_ZONE])
            .collect();
        for from in &zones {
            for to in &zones {
                if from == to || *from == SELF_ZONE {
                    continue;
                }
                blocks.insert(
                    format!("default {from}-{to}"),
                    format!(
                        "{} tried to reach {}. Nothing allows it.",
                        name_of(from),
                        name_of(to)
                    ),
                );
            }
        }
        // What no zone pair accounts for: a port in no network.
        blocks.insert(
            "no policy".to_string(),
            "Something tried to cross between two networks. Nothing allows it.".to_string(),
        );
        blocks.insert(
            "no policy in".to_string(),
            "Something tried to reach the box itself. Nothing allows it.".to_string(),
        );
        for policy in &config.policies {
            for rule in &policy.rules {
                if rule.enabled && rule.action != Action::Accept {
                    blocks.insert(
                        rule.id.clone(),
                        format!(
                            "{} tried to reach {}. Stopped by \"{}\".",
                            name_of(&policy.from),
                            name_of(&policy.to),
                            rule.name
                        ),
                    );
                }
            }
        }
        let port = |name: &String| Port {
            name: name.clone(),
            vlans: config
                .interfaces
                .iter()
                .filter(|(_, i)| i.vlan.as_ref().is_some_and(|v| v.parent == *name))
                .map(|(child, _)| child.clone())
                .collect(),
        };
        Plan {
            internet: grid
                .networks
                .iter()
                .filter(|n| n.internet)
                .flat_map(|n| n.interfaces.iter().map(port))
                .collect(),
            networks: grid
                .networks
                .iter()
                .filter(|n| !n.internet)
                .map(|n| Net {
                    zone: n.zone.clone(),
                    name: n.name.clone(),
                    ports: n.interfaces.iter().map(port).collect(),
                })
                .collect(),
            blocks,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Event {
    key: String,
    at: u64,
    packets: u64,
}

fn push(series: &mut VecDeque<u64>, value: u64) {
    series.push_back(value);
    while series.len() > WINDOW {
        series.pop_front();
    }
}

/// The history, and the last reading to measure the next one against.
#[derive(Debug, Default)]
pub struct Live {
    plan: Plan,
    last: Option<(Reading, Instant)>,
    /// When someone last asked. `None` until the first time.
    asked: Option<Instant>,
    /// Seconds of readings taken, for the feed's "how long ago".
    clock: u64,
    download: VecDeque<u64>,
    upload: VecDeque<u64>,
    connections: VecDeque<u64>,
    blocked: VecDeque<u64>,
    /// Per network, in the plan's order.
    networks: Vec<Pair>,
    feed: VecDeque<Event>,
    has_connections: bool,
    has_blocked: bool,
}

pub type SharedLive = Arc<Mutex<Live>>;

/// One network's history: bits per second down, and up.
type Pair = (VecDeque<u64>, VecDeque<u64>);

/// One network's lines in the view.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct NetView {
    pub zone: String,
    pub name: String,
    /// Bits per second towards its devices, oldest first.
    pub down: Vec<u64>,
    /// Bits per second from its devices.
    pub up: Vec<u64>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct FeedLine {
    /// Seconds since it last happened.
    pub ago: u64,
    pub packets: u64,
    pub text: String,
}

/// What `/v1/live` answers. A series the box cannot measure is `null`, and
/// the screens leave it out.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct View {
    /// Seconds between readings.
    pub interval: u64,
    /// The most readings a series holds.
    pub window: usize,
    /// Bits per second in from the internet, oldest first.
    pub download: Option<Vec<u64>>,
    pub upload: Option<Vec<u64>>,
    /// Tracked connections.
    pub connections: Option<Vec<u64>>,
    /// Packets blocked per second.
    pub blocked: Option<Vec<u64>>,
    pub networks: Vec<NetView>,
    pub feed: Vec<FeedLine>,
}

impl Live {
    /// True while someone has asked recently, so readings are worth taking.
    pub fn watched(&self, now: Instant) -> bool {
        self.asked
            .is_some_and(|at| now.saturating_duration_since(at) < IDLE)
    }

    /// Forgets everything measured. The next reading starts a new history.
    pub fn forget(&mut self) {
        let plan = std::mem::take(&mut self.plan);
        let asked = self.asked;
        *self = Live {
            plan,
            asked,
            ..Live::default()
        };
        self.networks = self
            .plan
            .networks
            .iter()
            .map(|_| Default::default())
            .collect();
    }

    /// Follows a new config. What was measured stays: the internet's
    /// history, and each network's that is still there. A new network
    /// starts with none, and a block that no longer exists leaves the feed.
    pub fn set_plan(&mut self, plan: Plan) {
        if plan == self.plan {
            return;
        }
        let mut old: Vec<(String, Pair)> = self
            .plan
            .networks
            .iter()
            .map(|n| n.zone.clone())
            .zip(std::mem::take(&mut self.networks))
            .collect();
        self.networks = plan
            .networks
            .iter()
            .map(|n| {
                old.iter()
                    .position(|(zone, _)| *zone == n.zone)
                    .map(|at| old.swap_remove(at).1)
                    .unwrap_or_default()
            })
            .collect();
        self.feed.retain(|e| plan.blocks.contains_key(&e.key));
        self.plan = plan;
    }

    /// The interfaces worth reading.
    pub fn interfaces(&self) -> Vec<String> {
        self.plan
            .internet
            .iter()
            .chain(self.plan.networks.iter().flat_map(|n| n.ports.iter()))
            .flat_map(|p| std::iter::once(&p.name).chain(p.vlans.iter()))
            .cloned()
            .collect()
    }

    /// Takes one reading and turns it into rates against the one before.
    pub fn record(&mut self, reading: Reading, now: Instant) {
        let Some((before, then)) = self.last.replace((reading.clone(), now)) else {
            // The first reading has nothing to be measured against.
            return;
        };
        let secs = now.saturating_duration_since(then).as_secs_f64();
        if secs < 0.2 {
            self.last = Some((before, then));
            return;
        }
        self.clock += 1;
        // A counter that went backwards was reset, by a reload or a new
        // interface. That second reads as zero, never as a huge number.
        let rate = |new: u64, old: u64, scale: f64| -> u64 {
            (new.saturating_sub(old) as f64 * scale / secs).round() as u64
        };
        let one = |name: &String, side: fn(&(u64, u64)) -> u64| -> u64 {
            match (reading.interfaces.get(name), before.interfaces.get(name)) {
                (Some(new), Some(old)) => rate(side(new), side(old), 8.0),
                // A port that was not there a second ago has no rate yet.
                _ => 0,
            }
        };
        let sum = |ports: &[Port], side: fn(&(u64, u64)) -> u64| -> u64 {
            ports
                .iter()
                .map(|port| {
                    let vlans: u64 = port.vlans.iter().map(|v| one(v, side)).sum();
                    one(&port.name, side).saturating_sub(vlans)
                })
                .sum()
        };
        // What the internet port receives is the box's download.
        push(&mut self.download, sum(&self.plan.internet, |c| c.0));
        push(&mut self.upload, sum(&self.plan.internet, |c| c.1));
        for (net, (down, up)) in self.plan.networks.iter().zip(self.networks.iter_mut()) {
            // What the box sends out of a network's port goes down to its devices.
            push(down, sum(&net.ports, |c| c.1));
            push(up, sum(&net.ports, |c| c.0));
        }
        if let Some(count) = reading.connections {
            self.has_connections = true;
            push(&mut self.connections, count);
        }
        if let (Some(new), Some(old)) = (&reading.packets, &before.packets) {
            self.has_blocked = true;
            let mut total = 0;
            for key in self.plan.blocks.keys() {
                let more = new
                    .get(key)
                    .copied()
                    .unwrap_or(0)
                    .saturating_sub(old.get(key).copied().unwrap_or(0));
                // A rule that was not there a second ago is new, not busy.
                if more == 0 || !old.contains_key(key) {
                    continue;
                }
                total += more;
                match self
                    .feed
                    .iter_mut()
                    .find(|e| e.key == *key && self.clock - e.at <= SAME_EVENT_SECS)
                {
                    Some(event) => {
                        event.at = self.clock;
                        event.packets += more;
                    }
                    None => self.feed.push_front(Event {
                        key: key.clone(),
                        at: self.clock,
                        packets: more,
                    }),
                }
            }
            self.feed
                .make_contiguous()
                .sort_by_key(|e| std::cmp::Reverse(e.at));
            self.feed.truncate(FEED);
            push(&mut self.blocked, rate(total, 0, 1.0));
        }
    }

    /// The view, and a note that someone is looking.
    pub fn view(&mut self, now: Instant) -> View {
        self.asked = Some(now);
        let list = |series: &VecDeque<u64>| series.iter().copied().collect::<Vec<u64>>();
        let internet = !self.plan.internet.is_empty();
        View {
            interval: 1,
            window: WINDOW,
            download: internet.then(|| list(&self.download)),
            upload: internet.then(|| list(&self.upload)),
            connections: self.has_connections.then(|| list(&self.connections)),
            blocked: self.has_blocked.then(|| list(&self.blocked)),
            networks: self
                .plan
                .networks
                .iter()
                .zip(&self.networks)
                .map(|(net, (down, up))| NetView {
                    zone: net.zone.clone(),
                    name: net.name.clone(),
                    down: list(down),
                    up: list(up),
                })
                .collect(),
            feed: self
                .feed
                .iter()
                .filter_map(|e| {
                    Some(FeedLine {
                        ago: self.clock - e.at,
                        packets: e.packets,
                        text: self.plan.blocks.get(&e.key)?.clone(),
                    })
                })
                .collect(),
        }
    }
}

/// Byte counters of the named interfaces, over netlink. One that does not
/// exist is left out.
pub async fn interface_counters(names: &[String]) -> BTreeMap<String, (u64, u64)> {
    let mut out = BTreeMap::new();
    let Ok((connection, handle, _)) = rtnetlink::new_connection() else {
        return out;
    };
    let task = tokio::spawn(connection);
    let mut links = handle.link().get().execute();
    while let Ok(Some(link)) = links.try_next().await {
        let mut name = None;
        let mut bytes = None;
        for attribute in &link.attributes {
            match attribute {
                LinkAttribute::IfName(n) => name = Some(n.clone()),
                LinkAttribute::Stats64(s) => bytes = Some((s.rx_bytes, s.tx_bytes)),
                _ => {}
            }
        }
        if let (Some(name), Some(bytes)) = (name, bytes)
            && names.contains(&name)
        {
            out.insert(name, bytes);
        }
    }
    task.abort();
    out
}

/// How many connections the kernel is tracking, if connection tracking is
/// loaded in this network namespace.
pub fn connection_count() -> Option<u64> {
    std::fs::read_to_string("/proc/sys/net/netfilter/nf_conntrack_count")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Packets counted per rule comment in a ruleset listing.
pub fn rule_packets(dump: &Value) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for item in dump["nftables"].as_array().into_iter().flatten() {
        let rule = &item["rule"];
        let Some(comment) = rule["comment"].as_str() else {
            continue;
        };
        let packets: u64 = rule["expr"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| e["counter"]["packets"].as_u64())
            .sum();
        *out.entry(comment.to_string()).or_insert(0) += packets;
    }
    out
}

/// Takes a reading every second while the view is being watched.
pub fn start(live: SharedLive, engine: crate::Shared) {
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(1));
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // The commit the plan was made from, so the config is read once.
        let mut planned: Option<Option<u64>> = None;
        loop {
            every.tick().await;
            let lock = || live.lock().unwrap_or_else(|e| e.into_inner());
            if !lock().watched(Instant::now()) {
                // Nobody is looking. Start afresh when they come back.
                if planned.take().is_some() {
                    lock().forget();
                }
                continue;
            }
            let (commit, text, in_kernel) = {
                let mut e = engine.lock().unwrap_or_else(|e| e.into_inner());
                let commit = e.running().ok().flatten().map(|c| c.id);
                let text = (planned != Some(commit))
                    .then(|| e.running_config().ok().flatten())
                    .flatten();
                (commit, text, e.applier().name() == "kernel")
            };
            if planned != Some(commit) {
                planned = Some(commit);
                let plan = text
                    .and_then(|t| Config::from_toml(&t).ok())
                    .map(|c| Plan::new(&c))
                    .unwrap_or_default();
                lock().set_plan(plan);
            }
            let names = lock().interfaces();
            let interfaces = interface_counters(&names).await;
            let packets = if in_kernel && commit.is_some() {
                let engine = engine.clone();
                // Listing the ruleset runs a program, so keep it off the
                // threads that answer requests.
                tokio::task::spawn_blocking(move || {
                    engine
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .applier()
                        .dump()
                        .ok()
                })
                .await
                .ok()
                .flatten()
                .map(|dump| rule_packets(&dump))
            } else {
                None
            };
            let reading = Reading {
                interfaces,
                connections: connection_count(),
                packets,
            };
            lock().record(reading, Instant::now());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = include_str!("../../../examples/home.toml");

    fn reading(wan: (u64, u64), lan: (u64, u64), drops: u64) -> Reading {
        Reading {
            interfaces: [("eth0".to_string(), wan), ("eth1".to_string(), lan)]
                .into_iter()
                .collect(),
            connections: Some(40),
            packets: Some(
                [("default wan-self".to_string(), drops)]
                    .into_iter()
                    .collect(),
            ),
        }
    }

    fn live() -> Live {
        let config = Config::from_toml(HOME).expect("the example loads");
        let mut live = Live::default();
        live.set_plan(Plan::new(&config));
        live
    }

    #[test]
    fn rates_come_from_the_difference_between_two_readings() {
        let mut live = live();
        let start = Instant::now();
        let at = |s: u64| start + Duration::from_secs(s);
        live.record(reading((1_000, 500), (500, 1_000), 7), at(0));
        // One reading is not a rate yet.
        assert_eq!(live.view(at(0)).download, Some(vec![]));
        // In one second: 125,000 bytes in from the internet and 25,000 out.
        live.record(reading((126_000, 25_500), (25_500, 126_000), 10), at(1));
        let view = live.view(at(1));
        assert_eq!(view.download, Some(vec![1_000_000]));
        assert_eq!(view.upload, Some(vec![200_000]));
        // The inside network sees the same traffic from the other side:
        // what the box sends out of its port goes down to the devices.
        assert_eq!(view.networks.len(), 1);
        assert_eq!(view.networks[0].down, vec![1_000_000]);
        assert_eq!(view.networks[0].up, vec![200_000]);
        assert_eq!(view.connections, Some(vec![40]));
        // Three packets were dropped coming in from the internet.
        assert_eq!(view.blocked, Some(vec![3]));
        assert_eq!(view.feed.len(), 1);
        assert_eq!(view.feed[0].packets, 3);
        assert!(
            view.feed[0].text.contains("Internet") && view.feed[0].text.contains("the box itself"),
            "{}",
            view.feed[0].text
        );
    }

    #[test]
    fn a_counter_that_was_reset_reads_as_zero_not_as_a_spike() {
        let mut live = live();
        let start = Instant::now();
        let at = |s: u64| start + Duration::from_secs(s);
        live.record(reading((9_000_000, 9_000_000), (0, 0), 900), at(0));
        // A reload put the counters back to nothing.
        live.record(reading((10, 10), (0, 0), 0), at(1));
        let view = live.view(at(1));
        assert_eq!(view.download, Some(vec![0]));
        assert_eq!(view.blocked, Some(vec![0]));
        assert!(view.feed.is_empty());
    }

    #[test]
    fn repeated_blocks_add_to_one_line_and_the_window_is_kept() {
        let mut live = live();
        let start = Instant::now();
        let at = |s: u64| start + Duration::from_secs(s);
        for s in 0..(WINDOW as u64 + 30) {
            live.record(reading((s * 1000, 0), (0, 0), s * 2), at(s));
        }
        let view = live.view(at(200));
        assert_eq!(view.download.as_ref().map(Vec::len), Some(WINDOW));
        assert_eq!(view.blocked.as_ref().map(Vec::len), Some(WINDOW));
        // Two packets every second, all one kind of block: one line.
        assert_eq!(view.feed.len(), 1);
        assert_eq!(view.feed[0].ago, 0);
        assert_eq!(view.feed[0].packets, 2 * (WINDOW as u64 + 29));
    }

    #[test]
    fn what_cannot_be_measured_is_left_out_not_shown_as_zero() {
        let mut live = live();
        let start = Instant::now();
        // A dry run: no rules in a kernel, and no connection tracking.
        let dry = |n: u64| Reading {
            interfaces: [("eth0".to_string(), (n, n))].into_iter().collect(),
            connections: None,
            packets: None,
        };
        live.record(dry(0), start);
        live.record(dry(100), start + Duration::from_secs(1));
        let view = live.view(start);
        assert_eq!(view.blocked, None);
        assert_eq!(view.connections, None);
        assert_eq!(view.download, Some(vec![800]));
    }

    #[test]
    fn sampling_stops_when_nobody_is_looking_and_starts_clean() {
        let mut live = live();
        let start = Instant::now();
        assert!(!live.watched(start), "nobody has asked yet");
        live.view(start);
        assert!(live.watched(start + Duration::from_secs(5)));
        assert!(!live.watched(start + IDLE + Duration::from_secs(1)));
        live.record(reading((0, 0), (0, 0), 0), start);
        live.record(
            reading((1000, 0), (0, 0), 1),
            start + Duration::from_secs(1),
        );
        live.forget();
        let view = live.view(start);
        assert_eq!(view.download, Some(vec![]));
        assert!(view.feed.is_empty() && view.blocked.is_none());
        assert_eq!(view.networks.len(), 1, "the networks are still known");
    }

    #[test]
    fn a_vlan_is_counted_once_and_a_new_config_keeps_the_history() {
        let config = Config::from_toml(HOME).expect("the example loads");
        let mut live = live();
        let start = Instant::now();
        let at = |s: u64| start + Duration::from_secs(s);
        live.record(reading((0, 0), (0, 0), 0), at(0));
        live.record(reading((125_000, 0), (0, 125_000), 0), at(1));

        // A guest network is added as VLAN 30 on the inside port.
        let mut with_guest = config.clone();
        ox_setup::add_network(
            &mut with_guest,
            &ox_setup::NetworkRequest {
                name: "Guest Wi-Fi".into(),
                port: "eth1".into(),
                vlan: 30,
                address: None,
                internet: true,
            },
        )
        .expect("the network is added");
        live.set_plan(Plan::new(&with_guest));
        let view = live.view(at(1));
        // What was measured before the change is still there.
        assert_eq!(view.download, Some(vec![1_000_000]));
        assert_eq!(view.networks.len(), 2);
        let inside = view.networks.iter().find(|n| n.zone == "lan").unwrap();
        assert_eq!(inside.down, vec![1_000_000]);
        let guest = view.networks.iter().find(|n| n.zone != "lan").unwrap();
        assert!(guest.down.is_empty(), "a new network has no history yet");

        // In the next second 100 kB go down to a guest device and 25 kB to an
        // inside one. The kernel counts the guest's on eth1 as well.
        let with = |eth1_tx: u64, vlan_tx: u64| Reading {
            interfaces: [
                ("eth0".to_string(), (eth1_tx, 0)),
                ("eth1".to_string(), (0, eth1_tx)),
                ("eth1.30".to_string(), (0, vlan_tx)),
            ]
            .into_iter()
            .collect(),
            connections: None,
            packets: None,
        };
        live.record(with(125_000, 0), at(2));
        live.record(with(250_000, 100_000), at(3));
        let view = live.view(at(3));
        let inside = view.networks.iter().find(|n| n.zone == "lan").unwrap();
        let guest = view.networks.iter().find(|n| n.zone != "lan").unwrap();
        assert_eq!(guest.down.last(), Some(&800_000));
        assert_eq!(
            inside.down.last(),
            Some(&200_000),
            "the inside network is not charged for the guest's traffic"
        );
    }

    #[test]
    fn a_drop_rule_is_named_in_the_feed() {
        let config = Config::from_toml(HOME).expect("the example loads");
        let mut blocked = config.clone();
        ox_setup::block(
            &mut blocked,
            "192.168.10.66/32".parse().unwrap(),
            "Smart TV",
        )
        .expect("the block is added");
        let plan = Plan::new(&blocked);
        assert!(
            plan.blocks.values().any(|text| text.contains("Smart TV")),
            "{:?}",
            plan.blocks
        );
        // Every pair has its default, in both directions, IPv4 and IPv6 alike.
        assert!(plan.blocks.contains_key("default lan-wan"));
        assert!(plan.blocks.contains_key("default wan-lan"));
        assert!(plan.blocks.contains_key("default wan-self"));
    }

    #[test]
    fn rule_packets_adds_the_two_address_families() {
        let dump = serde_json::json!({ "nftables": [
            { "rule": { "comment": "default wan-self", "expr": [{ "counter": { "packets": 5, "bytes": 300 } }, { "drop": null }] } },
            { "rule": { "comment": "r-1", "expr": [{ "counter": { "packets": 2, "bytes": 120 } }] } },
            { "rule": { "comment": "r-1", "expr": [{ "counter": { "packets": 4, "bytes": 240 } }] } },
            { "rule": { "expr": [{ "accept": null }] } }
        ] });
        let packets = rule_packets(&dump);
        assert_eq!(packets.get("default wan-self"), Some(&5));
        assert_eq!(packets.get("r-1"), Some(&6));
    }
}

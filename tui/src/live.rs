//! Live mode: the TUI as a client of `oxd`.
//!
//! Every screen here shows what the daemon reports. There is no sample data.
//! Screens the daemon cannot back yet (VPN, IPS, HA, Fleet, Import) exist
//! only in the mock prototype.

use std::{collections::BTreeMap, net::IpAddr, path::Path};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ipnet::IpNet;
use ox_client::Client;
use ox_schema::{AddrRef, Config, PortSpec, Rule, SELF_ZONE, ServiceRef};
use serde_json::{Value, json};

/// A commit as the daemon reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    pub id: u64,
    pub author: String,
    pub source: String,
    pub reason: String,
    pub pending: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    pub running: Option<CommitInfo>,
    /// Seconds until the pending commit reverts.
    pub reverts_in: Option<u64>,
    pub candidates: Vec<String>,
    pub applier: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanView {
    pub first_commit: bool,
    pub summary: String,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainSide {
    pub verdict: String,
    /// The explanation, one line per row.
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExplainResult {
    pub packet: String,
    pub running: Option<ExplainSide>,
    pub candidate: Option<ExplainSide>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    pub seq: u64,
    pub time: u64,
    pub who: String,
    pub event: String,
    pub detail: String,
    pub hash: String,
}

/// The packet on the Explain screen, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub dport: String,
    pub iif: String,
}

impl Query {
    pub const FIELDS: [&'static str; 5] = ["src", "dst", "proto", "dport", "in"];

    pub fn field(&self, i: usize) -> &str {
        [&self.src, &self.dst, &self.proto, &self.dport, &self.iif][i]
    }

    fn field_mut(&mut self, i: usize) -> &mut String {
        [
            &mut self.src,
            &mut self.dst,
            &mut self.proto,
            &mut self.dport,
            &mut self.iif,
        ]
        .into_iter()
        .nth(i)
        .expect("five fields")
    }
}

type Res<T> = Result<T, String>;

/// What the TUI needs from the daemon. The socket client implements it, and
/// tests use a fixture.
pub trait Backend {
    fn status(&self) -> Res<Status>;
    /// The running config text, or `None` before the first commit.
    fn running(&self) -> Res<Option<String>>;
    /// Packets counted per rule ID, from the kernel's counters.
    fn hits(&self) -> Res<BTreeMap<String, u64>>;
    fn plan(&self, candidate: &str) -> Res<PlanView>;
    fn commit(&self, candidate: &str, confirm_secs: u64, reason: &str) -> Res<u64>;
    fn confirm(&self) -> Res<u64>;
    fn revert(&self) -> Res<u64>;
    fn explain(&self, q: &Query, candidate: Option<&str>) -> Res<ExplainResult>;
    fn audit(&self) -> Res<Vec<AuditRow>>;
}

pub struct SocketBackend(Client);

impl SocketBackend {
    pub fn new(socket: &Path) -> SocketBackend {
        SocketBackend(Client::new(socket))
    }

    /// A box on the network, saved earlier with `ox remote add`.
    pub fn remote(name: &str) -> Result<SocketBackend, String> {
        let file = ox_client::remotes::path()?;
        Ok(SocketBackend(Client::https(ox_client::remotes::find(
            &file, name,
        )?)))
    }
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn parse_commit(v: &Value) -> Option<CommitInfo> {
    Some(CommitInfo {
        id: v["id"].as_u64()?,
        author: s(&v["author"]),
        source: s(&v["source"]),
        reason: s(&v["reason"]),
        pending: v["state"] == "pending",
    })
}

pub fn parse_status(v: &Value) -> Status {
    Status {
        running: parse_commit(&v["running"]),
        reverts_in: v["reverts_in"].as_u64(),
        candidates: v["candidates"]
            .as_array()
            .into_iter()
            .flatten()
            .map(s)
            .collect(),
        applier: s(&v["applier"]),
    }
}

/// Sums the packet counters of the kernel's rules by rule ID. One config
/// rule can be several nftables rules, one per address family.
pub fn parse_hits(dump: &Value) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for item in dump["nftables"].as_array().into_iter().flatten() {
        let rule = &item["rule"];
        let Some(id) = rule["comment"].as_str() else {
            continue;
        };
        let packets: u64 = rule["expr"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| e["counter"]["packets"].as_u64())
            .sum();
        *out.entry(id.to_string()).or_insert(0) += packets;
    }
    out
}

fn parse_side(v: &Value) -> Option<ExplainSide> {
    Some(ExplainSide {
        verdict: v["verdict"].as_str()?.to_string(),
        lines: v["text"]
            .as_str()?
            .lines()
            .skip(1)
            .map(String::from)
            .collect(),
    })
}

impl Backend for SocketBackend {
    fn status(&self) -> Res<Status> {
        Ok(parse_status(&self.0.json("GET", "/v1/status", None)?))
    }

    fn running(&self) -> Res<Option<String>> {
        match self.0.get("/v1/running") {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.contains("no commit yet") => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn hits(&self) -> Res<BTreeMap<String, u64>> {
        Ok(parse_hits(&self.0.json("GET", "/v1/kernel", None)?))
    }

    fn plan(&self, candidate: &str) -> Res<PlanView> {
        let v = self
            .0
            .json("POST", &format!("/v1/candidates/{candidate}/plan"), None)?;
        Ok(PlanView {
            first_commit: v["first_commit"] == true,
            summary: s(&v["summary"]),
            changes: v["changes"]
                .as_array()
                .into_iter()
                .flatten()
                .map(s)
                .collect(),
        })
    }

    fn commit(&self, candidate: &str, confirm_secs: u64, reason: &str) -> Res<u64> {
        let body = json!({ "confirm_secs": confirm_secs, "reason": reason });
        let v = self.0.json(
            "POST",
            &format!("/v1/candidates/{candidate}/commit"),
            Some(&body),
        )?;
        Ok(v["id"].as_u64().unwrap_or(0))
    }

    fn confirm(&self) -> Res<u64> {
        Ok(self.0.json("POST", "/v1/confirm", None)?["id"]
            .as_u64()
            .unwrap_or(0))
    }

    fn revert(&self) -> Res<u64> {
        Ok(self.0.json("POST", "/v1/revert", None)?["id"]
            .as_u64()
            .unwrap_or(0))
    }

    fn explain(&self, q: &Query, candidate: Option<&str>) -> Res<ExplainResult> {
        let src: IpAddr = q
            .src
            .trim()
            .parse()
            .map_err(|_| format!("src '{}' is not an address", q.src))?;
        let dst: IpAddr = q
            .dst
            .trim()
            .parse()
            .map_err(|_| format!("dst '{}' is not an address", q.dst))?;
        let dport = match q.dport.trim() {
            "" => None,
            p => Some(
                p.parse::<u16>()
                    .map_err(|_| format!("dport '{p}' is not a port"))?,
            ),
        };
        let body = json!({
            "src": src, "dst": dst, "proto": q.proto.trim(), "dport": dport,
            "in": q.iif.trim(), "candidate": candidate,
        });
        let v = self.0.json("POST", "/v1/explain", Some(&body))?;
        Ok(ExplainResult {
            packet: s(&v["packet"]),
            running: parse_side(&v["running"]),
            candidate: parse_side(&v["candidate"]),
        })
    }

    fn audit(&self) -> Res<Vec<AuditRow>> {
        let v = self.0.json("GET", "/v1/audit", None)?;
        Ok(v["entries"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|e| AuditRow {
                seq: e["seq"].as_u64().unwrap_or(0),
                time: e["time"].as_u64().unwrap_or(0),
                who: s(&e["who"]),
                event: s(&e["event"]),
                detail: s(&e["detail"]),
                hash: s(&e["hash"]),
            })
            .collect())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen {
    Policy,
    Nat,
    Interfaces,
    Changes,
    Explain,
    Audit,
}

impl Screen {
    pub const ALL: [Screen; 6] = [
        Screen::Policy,
        Screen::Nat,
        Screen::Interfaces,
        Screen::Changes,
        Screen::Explain,
        Screen::Audit,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Screen::Policy => "Policy",
            Screen::Nat => "NAT",
            Screen::Interfaces => "Interfaces",
            Screen::Changes => "Changes",
            Screen::Explain => "Explain",
            Screen::Audit => "Audit",
        }
    }

    pub fn index(self) -> usize {
        Screen::ALL.iter().position(|x| *x == self).unwrap()
    }

    pub fn from_name(name: &str) -> Option<Screen> {
        Screen::ALL
            .into_iter()
            .find(|s| s.title().to_lowercase().starts_with(&name.to_lowercase()))
    }
}

/// Confirm windows the Changes screen offers, in seconds.
pub const WINDOWS: [u64; 4] = [30, 120, 300, 600];

pub struct LiveApp {
    pub screen: Screen,
    pub running: bool,
    pub show_help: bool,

    pub status: Status,
    /// The running config, parsed. `None` before the first commit.
    pub config: Option<Config>,
    pub hits: BTreeMap<String, u64>,
    /// Set when the daemon cannot be reached or sends something unusable.
    pub error: Option<String>,
    /// The result of the last action.
    pub message: Option<String>,

    pub pair: usize,
    pub rule: usize,

    pub candidate: usize,
    pub plan: Option<Result<PlanView, String>>,
    pub window: usize,
    /// The reason being typed before a commit, when the prompt is open.
    pub reason: Option<String>,

    pub query: Query,
    /// The Explain field being edited.
    pub editing: Option<usize>,
    pub compare: bool,
    pub explained: Option<Result<ExplainResult, String>>,

    pub audit: Vec<AuditRow>,
    pub audit_row: usize,
}

impl LiveApp {
    pub fn new(backend: &dyn Backend) -> LiveApp {
        let mut app = LiveApp {
            screen: Screen::Policy,
            running: true,
            show_help: false,
            status: Status::default(),
            config: None,
            hits: BTreeMap::new(),
            error: None,
            message: None,
            pair: 0,
            rule: 0,
            candidate: 0,
            plan: None,
            window: 2,
            reason: None,
            query: Query {
                proto: "tcp".into(),
                ..Query::default()
            },
            editing: None,
            compare: true,
            explained: None,
            audit: vec![],
            audit_row: 0,
        };
        app.refresh(backend);
        app
    }

    pub fn selected_candidate(&self) -> Option<&str> {
        self.status
            .candidates
            .get(self.candidate)
            .map(String::as_str)
    }

    /// Reads everything the screens show from the daemon.
    pub fn refresh(&mut self, backend: &dyn Backend) {
        self.error = None;
        match self.load(backend) {
            Ok(()) => {}
            Err(e) => self.error = Some(e),
        }
    }

    fn load(&mut self, backend: &dyn Backend) -> Res<()> {
        self.status = backend.status()?;
        self.config = match backend.running()? {
            None => None,
            Some(text) => Some(
                Config::from_toml(&text)
                    .map_err(|e| format!("the running config does not load here: {e}"))?,
            ),
        };
        self.hits = backend.hits().unwrap_or_default();
        self.audit = backend.audit()?;
        self.candidate = self
            .candidate
            .min(self.status.candidates.len().saturating_sub(1));
        self.plan = self.selected_candidate().map(|name| backend.plan(name));
        let pairs = self.config.as_ref().map_or(0, |c| c.policies.len());
        self.pair = self.pair.min(pairs.saturating_sub(1));
        self.rule = self.rule.min(self.rules().len().saturating_sub(1));
        self.audit_row = self.audit_row.min(self.audit.len().saturating_sub(1));
        Ok(())
    }

    /// The rules of the selected zone pair.
    pub fn rules(&self) -> &[Rule] {
        self.config
            .as_ref()
            .and_then(|c| c.policies.get(self.pair))
            .map_or(&[], |p| p.rules.as_slice())
    }

    fn act(&mut self, backend: &dyn Backend, result: Res<String>) {
        match result {
            Ok(msg) => self.message = Some(msg),
            Err(e) => self.message = Some(format!("refused: {e}")),
        }
        self.refresh(backend);
    }

    fn run_explain(&mut self, backend: &dyn Backend) {
        let candidate = self
            .selected_candidate()
            .filter(|_| self.compare)
            .map(String::from);
        self.explained = Some(backend.explain(&self.query, candidate.as_deref()));
    }

    /// Fills the Explain form with a packet the selected rule is about.
    fn query_for_rule(&mut self) {
        let Some(config) = &self.config else {
            return;
        };
        let Some(policy) = config.policies.get(self.pair) else {
            return;
        };
        let Some(rule) = policy.rules.get(self.rule) else {
            return;
        };
        let iif = config
            .zone_interfaces(&policy.from)
            .first()
            .map(|s| s.to_string());
        let (proto, dport) = match config
            .resolve_services(&rule.service)
            .and_then(|v| v.first().copied())
        {
            Some(PortSpec::Ports { proto, first, .. }) => (proto.as_str(), first.to_string()),
            Some(PortSpec::Icmp) => ("icmp", String::new()),
            Some(PortSpec::Icmpv6) => ("icmpv6", String::new()),
            None => ("tcp", "443".to_string()),
        };
        // Prefer IPv4 unless the rule is IPv6 only, so both ends are one family.
        let v6_only = [&rule.source, &rule.destination].iter().any(|side| {
            config
                .resolve_addrs(side)
                .is_some_and(|nets| !nets.is_empty() && nets.iter().all(|n| n.addr().is_ipv6()))
        });
        let (proto, dport) = if v6_only && proto == "icmp" {
            ("icmpv6", dport)
        } else {
            (proto, dport)
        };
        self.query = Query {
            src: sample(config, &rule.source, &policy.from, !v6_only, 7),
            dst: sample(config, &rule.destination, &policy.to, !v6_only, 9),
            proto: proto.to_string(),
            dport,
            iif: iif.unwrap_or_default(),
        };
    }

    pub fn on_key(&mut self, key: KeyEvent, backend: &dyn Backend) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.running = false;
            return;
        }
        if self.show_help {
            self.show_help = false;
            return;
        }
        // The reason prompt takes every key until it is answered.
        if let Some(reason) = &mut self.reason {
            match key.code {
                KeyCode::Enter => {
                    let reason = self.reason.take().unwrap_or_default();
                    let window = WINDOWS[self.window];
                    if let Some(name) = self.selected_candidate().map(String::from) {
                        let result = backend.commit(&name, window, &reason).map(|id| {
                            format!(
                                "applied #{id}; press y within {window} s to keep it, r to undo it"
                            )
                        });
                        self.act(backend, result);
                    }
                }
                KeyCode::Esc => self.reason = None,
                KeyCode::Backspace => {
                    reason.pop();
                }
                KeyCode::Char(c) if reason.len() < 80 => reason.push(c),
                _ => {}
            }
            return;
        }
        // So does a field on the Explain form.
        if let Some(i) = self.editing {
            match key.code {
                KeyCode::Enter => {
                    self.editing = None;
                    self.run_explain(backend);
                }
                KeyCode::Esc => self.editing = None,
                KeyCode::Tab | KeyCode::Down => self.editing = Some((i + 1) % 5),
                KeyCode::BackTab | KeyCode::Up => self.editing = Some((i + 4) % 5),
                KeyCode::Backspace => {
                    self.query.field_mut(i).pop();
                }
                KeyCode::Char(c) if !c.is_whitespace() && self.query.field(i).len() < 45 => {
                    self.query.field_mut(i).push(c);
                }
                _ => {}
            }
            return;
        }

        let pending = self.status.reverts_in.is_some();
        match key.code {
            KeyCode::Char('q') => self.running = false,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('R') => {
                self.message = None;
                self.refresh(backend);
            }
            KeyCode::Tab => self.screen = Screen::ALL[(self.screen.index() + 1) % 6],
            KeyCode::BackTab => self.screen = Screen::ALL[(self.screen.index() + 5) % 6],
            KeyCode::Char(c @ '1'..='6') => {
                self.screen = Screen::ALL[c as usize - '1' as usize];
            }
            // A pending commit can be kept or undone from any screen.
            KeyCode::Char('y') if pending => {
                let result = backend.confirm().map(|id| format!("kept #{id}"));
                self.act(backend, result);
            }
            KeyCode::Char('r') if pending => {
                let result = backend
                    .revert()
                    .map(|id| format!("undone #{id}; the candidate is kept"));
                self.act(backend, result);
            }
            code => self.on_screen_key(code, backend, pending),
        }
    }

    fn on_screen_key(&mut self, code: KeyCode, backend: &dyn Backend, pending: bool) {
        let step = |i: usize, n: usize, down: bool| -> usize {
            if n == 0 {
                0
            } else if down {
                (i + 1) % n
            } else {
                (i + n - 1) % n
            }
        };
        let (up, down) = (
            matches!(code, KeyCode::Up | KeyCode::Char('k')),
            matches!(code, KeyCode::Down | KeyCode::Char('j')),
        );
        match self.screen {
            Screen::Policy => {
                let pairs = self.config.as_ref().map_or(0, |c| c.policies.len());
                match code {
                    KeyCode::Left | KeyCode::Char('h') => {
                        self.pair = step(self.pair, pairs, false);
                        self.rule = 0;
                    }
                    KeyCode::Right | KeyCode::Char('l') => {
                        self.pair = step(self.pair, pairs, true);
                        self.rule = 0;
                    }
                    _ if up || down => self.rule = step(self.rule, self.rules().len(), down),
                    KeyCode::Char('x') if !self.rules().is_empty() => {
                        self.query_for_rule();
                        self.screen = Screen::Explain;
                        self.run_explain(backend);
                    }
                    _ => {}
                }
            }
            Screen::Changes => match code {
                _ if up || down => {
                    self.candidate = step(self.candidate, self.status.candidates.len(), down);
                    self.plan = self.selected_candidate().map(|name| backend.plan(name));
                }
                KeyCode::Char('w') => self.window = (self.window + 1) % WINDOWS.len(),
                KeyCode::Char('c') if !pending && self.selected_candidate().is_some() => {
                    self.reason = Some(String::new());
                }
                _ => {}
            },
            Screen::Explain => match code {
                KeyCode::Char('e') => self.editing = Some(0),
                KeyCode::Char('m') => {
                    self.compare = !self.compare;
                    if self.explained.is_some() {
                        self.run_explain(backend);
                    }
                }
                KeyCode::Enter => self.run_explain(backend),
                _ => {}
            },
            Screen::Audit if up || down => {
                // The newest entry is at the top, so "down" moves to older ones.
                self.audit_row = step(self.audit_row, self.audit.len(), down);
            }
            _ => {}
        }
    }
}

/// An address for the Explain form: inside the rule's side if it names
/// networks, else on the zone's own network.
fn sample(config: &Config, refs: &[AddrRef], zone: &str, v4: bool, n: u8) -> String {
    let inside = |net: &IpNet| -> String {
        if net.prefix_len() == net.max_prefix_len() {
            return net.addr().to_string();
        }
        match net.network() {
            IpAddr::V4(a) => {
                std::net::Ipv4Addr::from(u32::from(a).wrapping_add(10 + u32::from(n))).to_string()
            }
            IpAddr::V6(a) => {
                std::net::Ipv6Addr::from(u128::from(a).wrapping_add(10 + u128::from(n))).to_string()
            }
        }
    };
    let family = |net: &&IpNet| net.addr().is_ipv4() == v4;
    if let Some(nets) = config.resolve_addrs(refs)
        && let Some(net) = nets.iter().find(family)
    {
        return inside(net);
    }
    let ifaces: Vec<_> = config
        .interfaces
        .values()
        .filter(|i| zone == SELF_ZONE || i.zone == zone)
        .collect();
    // Traffic to the box goes to one of its own addresses.
    if zone == SELF_ZONE {
        return ifaces
            .iter()
            .flat_map(|i| i.addresses.iter())
            .find(|a| a.0.addr().is_ipv4() == v4)
            .map_or(String::new(), |a| a.0.addr().to_string());
    }
    if ifaces.iter().any(|i| i.default_route) {
        return if v4 {
            format!("198.51.100.{n}")
        } else {
            format!("2001:db8:ffff::{n}")
        };
    }
    ifaces
        .iter()
        .flat_map(|i| i.addresses.iter())
        .map(|a| a.0.trunc())
        .find(|net| net.addr().is_ipv4() == v4)
        .map_or(String::new(), |net| inside(&net))
}

/// The service list of a rule as one string.
pub fn services(rule: &Rule) -> String {
    rule.service
        .iter()
        .map(ServiceRef::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn addrs(refs: &[AddrRef]) -> String {
    refs.iter()
        .map(AddrRef::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// An in-memory daemon for tests: one running config, one candidate, and a
/// record of what the TUI asked for.
#[cfg(test)]
pub mod fixture {
    use super::*;
    use std::cell::RefCell;

    const BRANCH: &str = include_str!("../../examples/branch.toml");
    const CANDIDATE: &str = include_str!("../../examples/branch-candidate.toml");

    #[derive(Default)]
    pub struct State {
        /// True once the candidate has been committed.
        pub applied: bool,
        pub pending: bool,
        pub commits: Vec<(String, u64, String)>,
        pub explained: Vec<(Query, Option<String>)>,
    }

    #[derive(Default)]
    pub struct Fixture(pub RefCell<State>);

    impl Backend for Fixture {
        fn status(&self) -> Res<Status> {
            let s = self.0.borrow();
            Ok(Status {
                running: Some(CommitInfo {
                    id: if s.applied { 2 } else { 1 },
                    author: "ana".into(),
                    source: if s.applied {
                        "candidate block-legacy-smb"
                    } else {
                        "candidate base"
                    }
                    .into(),
                    reason: if s.applied {
                        "CHG-2207"
                    } else {
                        "first config"
                    }
                    .into(),
                    pending: s.pending,
                }),
                reverts_in: s.pending.then_some(287),
                candidates: if s.applied && !s.pending {
                    vec![]
                } else {
                    vec!["block-legacy-smb".into()]
                },
                applier: "kernel".into(),
            })
        }
        fn running(&self) -> Res<Option<String>> {
            Ok(Some(
                if self.0.borrow().applied {
                    CANDIDATE
                } else {
                    BRANCH
                }
                .to_string(),
            ))
        }
        fn hits(&self) -> Res<BTreeMap<String, u64>> {
            Ok([
                ("r-0388", 1204),
                ("r-0301", 88410),
                ("default lan-dmz", 2114),
                ("n-0010", 512880),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect())
        }
        fn plan(&self, _: &str) -> Res<PlanView> {
            Ok(PlanView {
                first_commit: false,
                summary: "9 rules in 5 zone pairs → 19 nftables rules, 27 sets, 2 verdict maps, longest chain 6".into(),
                changes: vec![
                    "+ rule r-0412 \"Drop SMB and NetBIOS\": lan → dmz: drop any → any · smb, netbios, position 1".into(),
                    "~ rule r-0388 \"Finance to file servers\": service: smb, netbios, https → https".into(),
                ],
            })
        }
        fn commit(&self, candidate: &str, confirm_secs: u64, reason: &str) -> Res<u64> {
            let mut s = self.0.borrow_mut();
            s.commits
                .push((candidate.to_string(), confirm_secs, reason.to_string()));
            s.applied = true;
            s.pending = true;
            Ok(2)
        }
        fn confirm(&self) -> Res<u64> {
            self.0.borrow_mut().pending = false;
            Ok(2)
        }
        fn revert(&self) -> Res<u64> {
            let mut s = self.0.borrow_mut();
            s.pending = false;
            s.applied = false;
            Ok(2)
        }
        fn explain(&self, q: &Query, candidate: Option<&str>) -> Res<ExplainResult> {
            self.0
                .borrow_mut()
                .explained
                .push((q.clone(), candidate.map(String::from)));
            if q.src.parse::<IpAddr>().is_err() {
                return Err(format!("src '{}' is not an address", q.src));
            }
            let side = |verdict: &str, rule: &str| ExplainSide {
                verdict: verdict.into(),
                lines: vec![
                    " 1 ingress    lan0.20 → zone lan".into(),
                    " 2 route      out lan0.30 → zone dmz".into(),
                    format!(" 3 rule       {rule}"),
                ],
            };
            Ok(ExplainResult {
                packet: format!("{} → {} {}/{} in {}", q.src, q.dst, q.proto, q.dport, q.iif),
                running: Some(side("ACCEPT", "r-0388 accept · Finance to file servers")),
                candidate: candidate.map(|_| side("DROP", "r-0412 drop · Drop SMB and NetBIOS")),
            })
        }
        fn audit(&self) -> Res<Vec<AuditRow>> {
            let row = |seq, who: &str, event: &str, detail: &str| AuditRow {
                seq,
                time: 1_794_653_523 + seq * 60,
                who: who.into(),
                event: event.into(),
                detail: detail.into(),
                hash: format!("{seq:02}9f3ca1e041d27b9cc07a3f122be890d477e1c5aae4f912bd0a9915cf22"),
            };
            Ok(vec![
                row(1, "system", "start", "no commit yet, nothing applied"),
                row(2, "ana", "candidate saved", "base sha256 1b81b81c"),
                row(
                    3,
                    "ana",
                    "commit",
                    "#1 from candidate base sha256 1b81b81c reason: first config",
                ),
                row(
                    4,
                    "jun",
                    "candidate saved",
                    "block-legacy-smb sha256 762941b3",
                ),
            ])
        }
    }
}

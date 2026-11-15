//! Live mode: the TUI as a client of `oxd`.
//!
//! Every screen here shows what the daemon reports. There is no sample data.
//! Screens the daemon cannot back yet (VPN, IPS, HA, Fleet, Import) exist
//! only in the mock prototype.

use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::{Path, PathBuf},
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ipnet::IpNet;
use ox_client::Client;
use ox_schema::{AddrRef, Config, PortSpec, Rule, SELF_ZONE, ServiceRef};
use serde_json::{Value, json};

use crate::tasks::{self, Choice, Device, Form, MENU, Saved, Task};

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
    /// The change in a few sentences about networks. Empty when it has none.
    pub headline: Vec<String>,
    /// What the box starts and stops doing, in sentences.
    pub starts: Vec<String>,
    pub stops: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainSide {
    pub verdict: String,
    /// The rule that decided, if one did.
    pub rule: Option<String>,
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
    /// How many devices each network of the grid has handed an address to.
    fn devices(&self) -> Res<Vec<usize>>;
    /// Runs one plain-language task. It saves a waiting change and applies nothing.
    fn action(&self, path: &str, body: &Value) -> Res<Saved>;
    /// Throws a waiting change away.
    fn discard(&self, candidate: &str) -> Res<()>;
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
        rule: v["rule"].as_str().map(String::from),
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
        let list =
            |v: &Value| -> Vec<String> { v.as_array().into_iter().flatten().map(s).collect() };
        Ok(PlanView {
            first_commit: v["first_commit"] == true,
            summary: s(&v["summary"]),
            changes: list(&v["changes"]),
            headline: list(&v["headline"]),
            starts: list(&v["starts"]),
            stops: list(&v["stops"]),
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

    fn devices(&self) -> Res<Vec<usize>> {
        let v = self.0.json("GET", "/v1/home", None)?;
        Ok(v["devices"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|n| n.as_u64().unwrap_or(0) as usize)
            .collect())
    }

    fn action(&self, path: &str, body: &Value) -> Res<Saved> {
        Ok(tasks::parse_saved(&self.0.json(
            "POST",
            path,
            Some(body),
        )?))
    }

    fn discard(&self, candidate: &str) -> Res<()> {
        self.0
            .send("DELETE", &format!("/v1/candidates/{candidate}"), None)
            .map(|_| ())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Screen {
    Home,
    Access,
    Review,
    Settings,
    Policy,
    Nat,
    Interfaces,
    Changes,
    Explain,
    Audit,
}

impl Screen {
    pub const ALL: [Screen; 10] = [
        Screen::Home,
        Screen::Access,
        Screen::Review,
        Screen::Settings,
        Screen::Policy,
        Screen::Nat,
        Screen::Interfaces,
        Screen::Changes,
        Screen::Explain,
        Screen::Audit,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Screen::Home => "Home",
            Screen::Access => "Access",
            Screen::Review => "Review",
            Screen::Settings => "Settings",
            Screen::Policy => "Policy",
            Screen::Nat => "NAT",
            Screen::Interfaces => "Interfaces",
            Screen::Changes => "Changes",
            Screen::Explain => "Explain",
            Screen::Audit => "Audit",
        }
    }

    pub fn from_name(name: &str) -> Option<Screen> {
        Screen::ALL
            .into_iter()
            .find(|s| s.title().to_lowercase().starts_with(&name.to_lowercase()))
    }
}

/// Confirm windows the Changes screen offers, in seconds.
pub const WINDOWS: [u64; 4] = [30, 120, 300, 600];

/// The screens everyone sees.
pub const SIMPLE: [Screen; 4] = [
    Screen::Home,
    Screen::Access,
    Screen::Review,
    Screen::Settings,
];

/// The detailed screens. Each is a switch on Settings, off to begin with,
/// and a switch only shows or hides a tab.
pub const DETAILED: [(Screen, &str, &str); 6] = [
    (
        Screen::Policy,
        "The full rule list",
        "every rule, with packet counts",
    ),
    (
        Screen::Nat,
        "Address translation",
        "port forwards and outbound, line by line",
    ),
    (
        Screen::Interfaces,
        "Ports and addresses",
        "each port and its addresses",
    ),
    (
        Screen::Changes,
        "The full plan",
        "the technical plan, a reason, your own timer",
    ),
    (
        Screen::Explain,
        "The packet tracer",
        "any packet, step by step",
    ),
    (Screen::Audit, "The audit log", "who did what and when"),
];

/// How long the simple layer gives you to keep a change, in seconds.
pub const SAFE_SECS: u64 = 120;

/// The answer to "is something blocked?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub packet: String,
    pub allowed: bool,
    pub why: String,
}

pub struct LiveApp {
    pub screen: Screen,
    /// The detailed screens that are switched on. None to begin with.
    pub detailed: Vec<Screen>,
    /// Where the switches are kept between runs, if anywhere.
    pub prefs: Option<PathBuf>,
    /// The selected line of the Home menu.
    pub menu: usize,
    /// The selected cell of the Access grid: from, to.
    pub cell: (usize, usize),
    /// The selected switch on Settings.
    pub switch: usize,
    /// The task being filled in, when one is open.
    pub form: Option<Form>,
    /// The screen a task was started from.
    pub back: Screen,
    pub checked: Option<Result<Checked, String>>,
    /// A VPN device's settings, on show until dismissed.
    pub device: Option<Device>,
    /// Show the settings as text when the code and the text do not both fit.
    pub device_text: bool,
    /// Set after one press of d on Review; a second press discards.
    pub discarding: bool,
    pub devices: Vec<usize>,
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
            screen: Screen::Home,
            detailed: vec![],
            prefs: None,
            menu: 0,
            cell: (0, 1),
            switch: 0,
            form: None,
            back: Screen::Home,
            checked: None,
            device: None,
            device_text: false,
            discarding: false,
            devices: vec![],
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
        self.devices = backend.devices().unwrap_or_default();
        self.audit = backend.audit()?;
        self.candidate = self
            .candidate
            .min(self.status.candidates.len().saturating_sub(1));
        self.plan = self.selected_candidate().map(|name| backend.plan(name));
        let pairs = self.config.as_ref().map_or(0, |c| c.policies.len());
        self.pair = self.pair.min(pairs.saturating_sub(1));
        self.rule = self.rule.min(self.rules().len().saturating_sub(1));
        self.audit_row = self.audit_row.min(self.audit.len().saturating_sub(1));
        self.menu = self.menu.min(self.menu_items().len().saturating_sub(1));
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
        // A VPN device's settings stay up until they are dismissed on purpose.
        if self.device.is_some() {
            match key.code {
                KeyCode::Esc => {
                    self.device = None;
                    self.device_text = false;
                }
                KeyCode::Tab => self.device_text = !self.device_text,
                _ => {}
            }
            return;
        }
        let again = self.discarding;
        self.discarding = false;
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

        // And a task form.
        if self.form.is_some() {
            self.on_form_key(key.code, backend);
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
            KeyCode::Tab | KeyCode::BackTab => {
                let tabs = self.tabs();
                let at = tabs.iter().position(|s| *s == self.screen).unwrap_or(0);
                let step = if key.code == KeyCode::Tab {
                    1
                } else {
                    tabs.len() - 1
                };
                self.screen = tabs[(at + step) % tabs.len()];
            }
            KeyCode::Char(c @ '0'..='9') => {
                // 0 is the tenth tab.
                let at = (c as usize - '0' as usize + 9) % 10;
                if let Some(screen) = self.tabs().get(at) {
                    self.screen = *screen;
                }
            }
            // The detailed screens are a switch, as in the web interface.
            // It shows or hides tabs and changes nothing on the box.
            KeyCode::Char('A') => {
                self.detailed = if self.detailed.is_empty() {
                    DETAILED.iter().map(|d| d.0).collect()
                } else {
                    vec![]
                };
                self.switched();
            }
            // From Home, straight to the waiting change.
            KeyCode::Char('a') if self.screen == Screen::Home => self.screen = Screen::Review,
            // An applied change can be kept or undone from any screen.
            KeyCode::Char('y') if pending => {
                let result = backend
                    .confirm()
                    .map(|id| format!("Kept. Change #{id} stays."));
                self.act(backend, result);
            }
            KeyCode::Char('r') if pending => {
                let result = backend.revert().map(|id| {
                    format!("Undone. The box is as it was before change #{id}, and the change is still waiting if you want it.")
                });
                self.act(backend, result);
            }
            KeyCode::Char('d') if self.screen == Screen::Review => {
                let Some(name) = self.selected_candidate().map(String::from) else {
                    return;
                };
                if again {
                    let result = backend
                        .discard(&name)
                        .map(|()| "Discarded. Nothing was changed.".to_string());
                    self.act(backend, result);
                } else {
                    self.discarding = true;
                }
            }
            code => self.on_screen_key(code, backend, pending),
        }
    }

    /// The screens that have a tab right now.
    pub fn tabs(&self) -> Vec<Screen> {
        Screen::ALL
            .into_iter()
            .filter(|s| SIMPLE.contains(s) || self.detailed.contains(s))
            .collect()
    }

    /// After a switch changed: never leave the user on a hidden screen, and
    /// remember the choice.
    fn switched(&mut self) {
        self.detailed.sort();
        if !self.tabs().contains(&self.screen) {
            self.screen = Screen::Home;
        }
        if let Some(path) = &self.prefs {
            let text: String = self
                .detailed
                .iter()
                .map(|s| format!("{}\n", s.title()))
                .collect();
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            // Losing this costs one key press next time, so a failure is not reported.
            let _ = std::fs::write(path, text);
        }
    }

    /// Reads the switches kept by an earlier run.
    pub fn load_prefs(&mut self, path: PathBuf) {
        if let Ok(text) = std::fs::read_to_string(&path) {
            self.detailed = DETAILED
                .iter()
                .map(|d| d.0)
                .filter(|s| text.lines().any(|l| l.trim() == s.title()))
                .collect();
        }
        self.prefs = Some(path);
    }

    /// How many changes wait to be reviewed. One that is applied and not
    /// kept yet is past that point, though the box holds it until it is kept.
    pub fn waiting(&self) -> usize {
        let applied = self
            .status
            .running
            .as_ref()
            .filter(|c| c.pending)
            .map(|c| c.source.as_str());
        self.status
            .candidates
            .iter()
            .filter(|c| applied != Some(format!("candidate {c}").as_str()))
            .count()
    }

    /// The Home menu as it stands: the review line only when a change waits.
    pub fn menu_items(&self) -> Vec<(Choice, &'static str)> {
        let waiting = self.waiting();
        MENU.into_iter()
            .filter(|(c, _)| *c != Choice::Review || waiting > 0)
            .map(|(c, label)| match (c, waiting) {
                (Choice::Review, n) if n > 1 => (c, "Review and apply the waiting changes"),
                _ => (c, label),
            })
            .collect()
    }

    fn start_task(&mut self, task: Task) {
        let Some(config) = &self.config else {
            self.message = Some(
                "refused: the box is not set up yet. Run `ox init --save starter` then `ox apply starter` on it first."
                    .into(),
            );
            return;
        };
        self.form = Some(Form::new(task, config));
        self.back = self.screen;
        self.message = None;
    }

    /// The name someone gave a rule or a port forward, by its ID.
    fn rule_name(&self, id: &str) -> Option<String> {
        let config = self.config.as_ref()?;
        config
            .policies
            .iter()
            .flat_map(|p| p.rules.iter())
            .find(|r| r.id == id)
            .map(|r| r.name.clone())
            .or_else(|| {
                config
                    .nat
                    .forward
                    .iter()
                    .find(|f| f.id == id || f.rule == id)
                    .map(|f| f.name.clone())
            })
    }

    fn on_form_key(&mut self, code: KeyCode, backend: &dyn Backend) {
        let Some(form) = &mut self.form else {
            return;
        };
        match code {
            KeyCode::Esc => {
                self.form = None;
                self.screen = self.back;
            }
            KeyCode::Tab | KeyCode::Down => form.step(true),
            KeyCode::BackTab | KeyCode::Up => form.step(false),
            KeyCode::Left => form.turn(false),
            KeyCode::Right => form.turn(true),
            KeyCode::Backspace => form.backspace(),
            KeyCode::Char(c) => form.type_char(c),
            KeyCode::Enter => self.send_form(backend),
            _ => {}
        }
    }

    fn send_form(&mut self, backend: &dyn Backend) {
        let Some(form) = &mut self.form else {
            return;
        };
        if form.task == Task::Check {
            let (src, dst, proto, dport) = match form.connection() {
                Ok(c) => c,
                Err(e) => {
                    form.error = Some(e);
                    return;
                }
            };
            let query = Query {
                src,
                dst,
                proto,
                dport,
                iif: String::new(),
            };
            let answer = backend.explain(&query, None).and_then(|r| {
                let side = r
                    .running
                    .ok_or("The box is not set up yet, so nothing decides this.")?;
                let allowed = side.verdict == "ACCEPT";
                let why = match &side.rule {
                    Some(id) => format!(
                        "{} {}.",
                        if allowed {
                            "It is allowed by"
                        } else {
                            "It is stopped by"
                        },
                        self.rule_name(id)
                            .map_or(format!("rule {id}"), |n| format!("\"{n}\""))
                    ),
                    None if allowed => "Nothing stands in its way.".to_string(),
                    None => "Nothing allows it, and anything not allowed is blocked.".to_string(),
                };
                Ok(Checked {
                    packet: r.packet,
                    allowed,
                    why,
                })
            });
            match answer {
                Err(e) => {
                    if let Some(form) = &mut self.form {
                        form.error = Some(e);
                    }
                }
                ok => {
                    self.checked = Some(ok);
                    self.form = None;
                    self.screen = Screen::Home;
                }
            }
            return;
        }
        let sent = form
            .request()
            .and_then(|(path, body)| backend.action(path, &body));
        match sent {
            Err(e) => form.error = Some(e),
            Ok(saved) => {
                self.form = None;
                self.saved(backend, saved);
            }
        }
    }

    /// A task saved a waiting change: show it for review.
    fn saved(&mut self, backend: &dyn Backend, saved: Saved) {
        self.device = saved.device;
        self.device_text = false;
        self.refresh(backend);
        if let Some(at) = self
            .status
            .candidates
            .iter()
            .position(|c| *c == saved.candidate)
        {
            self.candidate = at;
            self.plan = Some(backend.plan(&saved.candidate));
        }
        self.screen = Screen::Review;
        // What it does is on the Review screen in full, so the banner stays short.
        self.message = Some("Ready to review. Nothing is applied yet.".to_string());
    }

    /// Lets the selected network reach the other, or stops it.
    fn flip_access(&mut self, backend: &dyn Backend, pending: bool) {
        let Some(config) = &self.config else {
            return;
        };
        let grid = ox_setup::grid(config);
        let (i, j) = self.cell;
        let (Some(from), Some(to)) = (grid.networks.get(i), grid.networks.get(j)) else {
            return;
        };
        let refuse = |why: &str| Some(format!("refused: {why}"));
        let allow = match &grid.cells[i][j] {
            _ if pending => {
                self.message =
                    refuse("a change is waiting to be kept or undone. Deal with that first.");
                return;
            }
            ox_setup::Cell::Same => return,
            _ if from.internet => {
                self.message = refuse(
                    "the internet is let in one service at a time. On Home, choose \"Let something in from the internet\".",
                );
                return;
            }
            ox_setup::Cell::Custom { .. } => {
                self.message = refuse(
                    "this pair has rules of its own, so it is not changed here by accident. Switch on the full rule list under Settings to see them.",
                );
                return;
            }
            ox_setup::Cell::Allowed => false,
            ox_setup::Cell::Blocked => true,
        };
        let body = json!({ "from": from.zone, "to": to.zone, "allow": allow });
        match backend.action("/v1/actions/access", &body) {
            Ok(saved) => self.saved(backend, saved),
            Err(e) => self.act(backend, Err(e)),
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
        let networks = self
            .config
            .as_ref()
            .map_or(0, |c| ox_setup::grid(c).networks.len());
        match self.screen {
            Screen::Home => match code {
                _ if up || down => self.menu = step(self.menu, self.menu_items().len(), down),
                KeyCode::Enter | KeyCode::Char(' ') => {
                    match self.menu_items().get(self.menu).map(|m| m.0) {
                        Some(Choice::Review) => self.screen = Screen::Review,
                        Some(Choice::Access) => self.screen = Screen::Access,
                        Some(Choice::Task(task)) => self.start_task(task),
                        None => {}
                    }
                }
                _ => {}
            },
            Screen::Access => match code {
                _ if up || down => self.cell.0 = step(self.cell.0, networks, down),
                KeyCode::Left | KeyCode::Char('h') => {
                    self.cell.1 = step(self.cell.1, networks, false);
                }
                KeyCode::Right | KeyCode::Char('l') => {
                    self.cell.1 = step(self.cell.1, networks, true);
                }
                KeyCode::Enter | KeyCode::Char(' ') => self.flip_access(backend, pending),
                _ => {}
            },
            Screen::Review => match code {
                _ if up || down => {
                    self.candidate = step(self.candidate, self.status.candidates.len(), down);
                    self.plan = self.selected_candidate().map(|name| backend.plan(name));
                }
                KeyCode::Enter | KeyCode::Char('a') if !pending => {
                    if let Some(name) = self.selected_candidate().map(String::from) {
                        let result = backend.commit(&name, SAFE_SECS, "").map(|_| {
                            "Applied. Check things still work, then press y to keep it.".to_string()
                        });
                        self.act(backend, result);
                    }
                }
                _ => {}
            },
            Screen::Settings => match code {
                _ if up || down => self.switch = step(self.switch, DETAILED.len(), down),
                KeyCode::Enter | KeyCode::Char(' ') => {
                    let screen = DETAILED[self.switch].0;
                    match self.detailed.iter().position(|s| *s == screen) {
                        Some(at) => {
                            self.detailed.remove(at);
                        }
                        None => self.detailed.push(screen),
                    }
                    self.switched();
                }
                _ => {}
            },
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
        /// The tasks the TUI asked for: route and body.
        pub actions: Vec<(String, Value)>,
        /// Waiting changes those tasks saved.
        pub saved: Vec<String>,
        /// True once the candidate that was there to begin with is discarded.
        pub discarded: bool,
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
                candidates: if s.discarded || (s.applied && !s.pending) {
                    vec![]
                } else {
                    vec!["block-legacy-smb".into()]
                }
                .into_iter()
                .chain(s.saved.iter().cloned())
                .collect(),
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
            let old = Config::from_toml(BRANCH).map_err(|e| e.to_string())?;
            let new = Config::from_toml(CANDIDATE).map_err(|e| e.to_string())?;
            let (starts, stops) = ox_setup::plain_changes(&old, &new);
            Ok(PlanView {
                headline: ox_setup::headline(&old, &new),
                starts,
                stops,
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
            s.saved.retain(|c| c != candidate);
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
                rule: rule.split(' ').next().map(String::from),
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
        fn devices(&self) -> Res<Vec<usize>> {
            Ok(vec![14, 3, 0, 0, 0, 0])
        }
        fn action(&self, path: &str, body: &Value) -> Res<Saved> {
            let mut s = self.0.borrow_mut();
            s.actions.push((path.to_string(), body.clone()));
            if body["name"] == "refuse me" {
                return Err("the daemon said no".into());
            }
            let candidate = format!("task-{}", s.actions.len());
            s.saved.push(candidate.clone());
            Ok(Saved {
                candidate,
                done: vec!["Did what was asked".into()],
                device: path.ends_with("vpn-peer").then(|| Device {
                    config: "[Interface]\nPrivateKey = not-a-real-key\nAddress = 10.99.0.2/32\n\n[Peer]\nPublicKey = also-not-real\nEndpoint = home.example.net:51820\n".into(),
                    key_made_here: true,
                }),
            })
        }
        fn discard(&self, candidate: &str) -> Res<()> {
            let mut s = self.0.borrow_mut();
            if candidate == "block-legacy-smb" {
                s.discarded = true;
            }
            s.saved.retain(|c| c != candidate);
            Ok(())
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

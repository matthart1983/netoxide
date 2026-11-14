use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;

use crate::data::{self, NatTab, ZonePair};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Screen {
    Policy,
    Nat,
    Vpn,
    Ips,
    Interfaces,
    Ha,
    Changes,
    Explain,
    Audit,
    Fleet,
    Import,
}

impl Screen {
    pub const ALL: [Screen; 11] = [
        Screen::Policy,
        Screen::Nat,
        Screen::Vpn,
        Screen::Ips,
        Screen::Interfaces,
        Screen::Ha,
        Screen::Changes,
        Screen::Explain,
        Screen::Audit,
        Screen::Fleet,
        Screen::Import,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Screen::Policy => "Policy",
            Screen::Nat => "NAT",
            Screen::Vpn => "VPN",
            Screen::Ips => "IPS",
            Screen::Interfaces => "Interfaces",
            Screen::Ha => "HA",
            Screen::Changes => "Changes",
            Screen::Explain => "Explain",
            Screen::Audit => "Admin/Audit",
            Screen::Fleet => "Fleet",
            Screen::Import => "Import",
        }
    }

    pub fn key(self) -> char {
        match self {
            Screen::Fleet => '0',
            Screen::Import => 'i',
            s => char::from_digit(
                Screen::ALL.iter().position(|x| *x == s).unwrap() as u32 + 1,
                10,
            )
            .unwrap(),
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CommitPhase {
    Review,
    Pending { deadline: Instant },
    Confirmed,
    Reverted { auto: bool },
}

pub struct App {
    pub screen: Screen,
    pub running: bool,
    pub show_help: bool,

    pub pairs: Vec<ZonePair>,
    pub pair_idx: usize,
    pub rule_state: TableState,

    pub nat: Vec<NatTab>,
    pub nat_idx: usize,
    pub nat_state: TableState,

    pub tunnel_state: TableState,
    pub ips_state: TableState,
    pub iface_state: TableState,
    pub audit_state: TableState,
    pub fleet_state: TableState,

    pub ha_active_a: bool,
    pub ha_confirming: bool,
    pub ha_message: Option<String>,

    pub commit_window: u64,
    pub commit: CommitPhase,

    pub explain_candidate: bool,
}

impl App {
    pub fn new() -> Self {
        let mut s = TableState::default();
        s.select(Some(0));
        App {
            screen: Screen::Policy,
            running: true,
            show_help: false,
            pairs: data::zone_pairs(),
            pair_idx: 0,
            rule_state: s.clone(),
            nat: data::nat_tabs(),
            nat_idx: 0,
            nat_state: s.clone(),
            tunnel_state: s.clone(),
            ips_state: s.clone(),
            iface_state: s.clone(),
            audit_state: s.clone(),
            fleet_state: s,
            ha_active_a: true,
            ha_confirming: false,
            ha_message: None,
            commit_window: 300,
            commit: CommitPhase::Review,
            explain_candidate: false,
        }
    }

    /// True while the candidate's rules are what the box is running:
    /// during the confirm window and after the commit is confirmed.
    pub fn applied(&self) -> bool {
        matches!(
            self.commit,
            CommitPhase::Pending { .. } | CommitPhase::Confirmed
        )
    }

    /// True while there is still a candidate that could be committed.
    pub fn has_candidate(&self) -> bool {
        !matches!(self.commit, CommitPhase::Confirmed)
    }

    /// The commit the box is running right now.
    pub fn running_commit(&self) -> &'static str {
        if self.applied() {
            data::NEXT_COMMIT
        } else {
            data::BASE_COMMIT
        }
    }

    /// Seconds left in the commit-confirm window, if one is open.
    pub fn commit_remaining(&self) -> Option<u64> {
        match self.commit {
            CommitPhase::Pending { deadline } => {
                Some(deadline.saturating_duration_since(Instant::now()).as_secs())
            }
            _ => None,
        }
    }

    pub fn tick(&mut self) {
        if let CommitPhase::Pending { deadline } = self.commit
            && Instant::now() >= deadline
        {
            self.commit = CommitPhase::Reverted { auto: true };
        }
    }

    fn rows_on_screen(&self) -> usize {
        match self.screen {
            Screen::Policy => self.pairs[self.pair_idx].rules.len(),
            Screen::Nat => self.nat[self.nat_idx].rows.len(),
            Screen::Vpn => data::tunnels().len(),
            Screen::Ips => data::IPS_EVENTS.len(),
            Screen::Interfaces => data::IFACES.len(),
            Screen::Audit => data::AUDIT.len(),
            Screen::Fleet => data::FLEET.len(),
            _ => 0,
        }
    }

    fn table_state(&mut self) -> Option<&mut TableState> {
        match self.screen {
            Screen::Policy => Some(&mut self.rule_state),
            Screen::Nat => Some(&mut self.nat_state),
            Screen::Vpn => Some(&mut self.tunnel_state),
            Screen::Ips => Some(&mut self.ips_state),
            Screen::Interfaces => Some(&mut self.iface_state),
            Screen::Audit => Some(&mut self.audit_state),
            Screen::Fleet => Some(&mut self.fleet_state),
            _ => None,
        }
    }

    fn move_row(&mut self, delta: i32) {
        let n = self.rows_on_screen();
        if n == 0 {
            return;
        }
        if let Some(st) = self.table_state() {
            let cur = st.selected().unwrap_or(0) as i32;
            let next = (cur + delta).rem_euclid(n as i32) as usize;
            st.select(Some(next));
        }
    }

    fn move_sideways(&mut self, delta: i32) {
        match self.screen {
            Screen::Policy => {
                let n = self.pairs.len() as i32;
                self.pair_idx = (self.pair_idx as i32 + delta).rem_euclid(n) as usize;
                self.rule_state.select(Some(0));
            }
            Screen::Nat => {
                let n = self.nat.len() as i32;
                self.nat_idx = (self.nat_idx as i32 + delta).rem_euclid(n) as usize;
                self.nat_state.select(Some(0));
            }
            _ => {}
        }
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.running = false;
            return;
        }
        if self.show_help {
            self.show_help = false;
            return;
        }
        // Modal prompt on the HA screen takes every key until answered.
        if self.ha_confirming {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    self.ha_active_a = !self.ha_active_a;
                    self.ha_confirming = false;
                    let now = if self.ha_active_a {
                        "syd-br-014-a"
                    } else {
                        "syd-br-014-b"
                    };
                    self.ha_message = Some(format!(
                        "Failover complete in 0.64 s. {now} is active. 99.6% of established TCP flows kept."
                    ));
                }
                _ => self.ha_confirming = false,
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') => self.running = false,
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Tab => {
                self.screen = Screen::ALL[(self.screen.index() + 1) % Screen::ALL.len()]
            }
            KeyCode::BackTab => {
                self.screen =
                    Screen::ALL[(self.screen.index() + Screen::ALL.len() - 1) % Screen::ALL.len()]
            }
            KeyCode::Char(c) if Screen::ALL.iter().any(|s| s.key() == c) => {
                if let Some(s) = Screen::ALL.into_iter().find(|s| s.key() == c) {
                    self.screen = s;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_row(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_row(-1),
            KeyCode::Right | KeyCode::Char('l') => self.move_sideways(1),
            KeyCode::Left | KeyCode::Char('h') => self.move_sideways(-1),
            // While a commit-confirm window is open, y and r work from any screen.
            KeyCode::Char('y') if matches!(self.commit, CommitPhase::Pending { .. }) => {
                self.commit = CommitPhase::Confirmed;
            }
            KeyCode::Char('r') if matches!(self.commit, CommitPhase::Pending { .. }) => {
                self.commit = CommitPhase::Reverted { auto: false };
            }
            _ => self.on_screen_key(key.code),
        }
    }

    fn on_screen_key(&mut self, code: KeyCode) {
        match (self.screen, code) {
            (Screen::Policy, KeyCode::Char('x')) => {
                // Jump to Explain; the demo packet is the one the candidate rule changes.
                self.screen = Screen::Explain;
            }
            (Screen::Ha, KeyCode::Char('f')) => {
                self.ha_message = None;
                self.ha_confirming = true;
            }
            (Screen::Changes, KeyCode::Char('c')) => {
                // A confirmed commit leaves no candidate, so there is nothing to commit again.
                if matches!(
                    self.commit,
                    CommitPhase::Review | CommitPhase::Reverted { .. }
                ) {
                    self.commit = CommitPhase::Pending {
                        deadline: Instant::now() + Duration::from_secs(self.commit_window),
                    };
                }
            }
            (Screen::Changes, KeyCode::Char('w')) => {
                if !matches!(self.commit, CommitPhase::Pending { .. }) {
                    self.commit_window = match self.commit_window {
                        120 => 300,
                        300 => 600,
                        _ => 120,
                    };
                }
            }
            // The toggle only means something while a candidate is waiting, unapplied.
            (Screen::Explain, KeyCode::Char('m')) if !self.applied() => {
                self.explain_candidate = !self.explain_candidate;
            }
            _ => {}
        }
    }
}

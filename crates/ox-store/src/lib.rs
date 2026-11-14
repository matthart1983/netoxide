//! The commit engine: what the box runs, what is proposed, and how one
//! becomes the other.
//!
//! - A **candidate** is a named config that is not running.
//! - A **commit** applies a candidate. It applies in full or not at all.
//! - A commit made with a confirm window is **pending**: it is running, and
//!   it reverts by itself unless someone confirms it before the deadline.
//!   The revert replays the previous commit through the same path. It does
//!   not reboot. A daemon that restarts with a commit still pending reverts
//!   it, because nobody can have confirmed it.
//!
//! The engine never talks to the kernel directly. It hands rendered rulesets
//! to an [`Applier`], so the same code runs against the kernel, in tests,
//! and in dry-run mode.

mod audit;

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use ox_nft::{Ruleset, compile, render, render_empty, render_lockdown};
use ox_schema::{Config, is_name};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub use audit::{Audit, AuditError, Entry};

/// How many commits the box keeps.
pub const HISTORY: u64 = 100;

/// Everything one config asks the box to do.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Target {
    /// The firewall, as a libnftables JSON document that is one transaction.
    pub ruleset: Value,
    /// Config text for each service the box runs, by service name. A
    /// service that is not listed must not be running.
    pub services: BTreeMap<String, String>,
}

/// What the box does before it has any config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Baseline {
    /// Load nothing. The kernel's own defaults apply.
    #[default]
    Open,
    /// Drop forwarded and inbound traffic until the first commit.
    Lockdown,
}

impl Baseline {
    fn target(self) -> Target {
        Target {
            ruleset: match self {
                Baseline::Open => render_empty(),
                Baseline::Lockdown => render_lockdown(),
            },
            services: BTreeMap::new(),
        }
    }
}

/// Puts a target into effect: the firewall and the services together.
pub trait Applier: Send {
    /// Applies the whole target. On `Err` the box is as it was before.
    fn apply(&mut self, target: &Target) -> std::result::Result<(), String>;
    /// The Netoxide table as the enforcer holds it now.
    fn dump(&mut self) -> std::result::Result<Value, String>;
    fn name(&self) -> &'static str;
    /// Called about once a second, for work such as restarting a service
    /// that stopped.
    fn tick(&mut self) {}
    /// Each service and its state in a few words.
    fn services(&mut self) -> Vec<(String, String)> {
        vec![]
    }
}

/// Applies nothing and remembers the last ruleset. For dry runs and tests.
#[derive(Default)]
pub struct NullApplier {
    pub last: Option<Target>,
    pub applied: usize,
    /// When set, the next `apply` fails with this message.
    pub fail_next: Option<String>,
}

impl Applier for NullApplier {
    fn apply(&mut self, target: &Target) -> std::result::Result<(), String> {
        if let Some(msg) = self.fail_next.take() {
            return Err(msg);
        }
        self.last = Some(target.clone());
        self.applied += 1;
        Ok(())
    }
    fn dump(&mut self) -> std::result::Result<Value, String> {
        Ok(self
            .last
            .as_ref()
            .map_or(Value::Null, |t| t.ruleset.clone()))
    }
    fn name(&self) -> &'static str {
        "dry-run"
    }
    fn services(&mut self) -> Vec<(String, String)> {
        self.last
            .iter()
            .flat_map(|t| t.services.keys())
            .map(|name| (name.clone(), "would run (dry run)".to_string()))
            .collect()
    }
}

impl Applier for Box<dyn Applier> {
    fn apply(&mut self, target: &Target) -> std::result::Result<(), String> {
        (**self).apply(target)
    }
    fn tick(&mut self) {
        (**self).tick();
    }
    fn services(&mut self) -> Vec<(String, String)> {
        (**self).services()
    }
    fn dump(&mut self) -> std::result::Result<Value, String> {
        (**self).dump()
    }
    fn name(&self) -> &'static str {
        (**self).name()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{0} not found")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    #[error("commit #{commit} is waiting for confirmation; confirm or revert it first")]
    Busy { commit: u64 },
    #[error("no commit is waiting for confirmation")]
    NothingPending,
    #[error("not applied, nothing changed: {0}")]
    Apply(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Audit(#[from] AuditError),
    #[error("state directory is damaged: {0}")]
    Corrupt(String),
}

type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum Outcome {
    /// Running, and will revert at `deadline` (Unix seconds) unless confirmed.
    Pending {
        deadline: u64,
    },
    Confirmed {
        by: String,
        at: u64,
    },
    Reverted {
        auto: bool,
        at: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    pub id: u64,
    /// Unix time in seconds.
    pub time: u64,
    pub author: String,
    pub reason: String,
    /// Where the config came from, such as `candidate block-legacy-smb`.
    pub source: String,
    /// The commit that was running before this one.
    pub parent: Option<u64>,
    /// SHA-256 of the config text.
    pub sha256: String,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct State {
    next_id: u64,
    running: Option<u64>,
    pending: Option<Pending>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Pending {
    commit: u64,
    deadline: u64,
    /// The candidate to delete on confirm, if the commit came from one.
    candidate: Option<String>,
}

/// What `status` reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub running: Option<Commit>,
    /// Seconds until the pending commit reverts, when one is pending.
    pub reverts_in: Option<u64>,
    pub candidates: Vec<String>,
    pub applier: String,
    /// Each service and its state in a few words.
    #[serde(default)]
    pub services: Vec<(String, String)>,
    /// True while the box has no config and drops inbound and forwarded traffic.
    #[serde(default)]
    pub lockdown: bool,
}

/// What `apply_new` needs to make a commit.
struct NewCommit<'a> {
    text: &'a str,
    /// Where the config came from, such as `candidate block-legacy-smb`.
    source: String,
    /// The candidate to delete once the commit is final.
    candidate: Option<String>,
    who: &'a str,
    reason: &'a str,
    confirm_secs: Option<u64>,
}

pub struct Engine<A: Applier> {
    dir: PathBuf,
    applier: A,
    baseline: Baseline,
    state: State,
    audit: Audit,
}

fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

/// The firewall and the service configs one config renders to.
fn target(config: &Config, ruleset: &Ruleset) -> Target {
    Target {
        ruleset: render(ruleset).0,
        services: ox_services::dnsmasq_conf(config)
            .map(|conf| (ox_services::DNSMASQ.to_string(), conf))
            .into_iter()
            .collect(),
    }
}

fn check(text: &str) -> Result<(Config, Ruleset)> {
    let config = Config::from_toml(text).map_err(|e| StoreError::Invalid(e.to_string()))?;
    let ruleset = compile(&config).map_err(|e| StoreError::Invalid(e.to_string()))?;
    Ok((config, ruleset))
}

impl<A: Applier> Engine<A> {
    /// Opens the state directory and brings the enforcer in line with it.
    ///
    /// A commit that was still pending is reverted. Otherwise the running
    /// commit is applied again, so a restart or reboot ends in a known state.
    pub fn open(dir: &Path, applier: A, now: u64) -> Result<Engine<A>> {
        Engine::open_with(dir, applier, Baseline::Open, now)
    }

    /// Like [`Engine::open`], with a choice of what the box does while it
    /// has no config.
    pub fn open_with(dir: &Path, applier: A, baseline: Baseline, now: u64) -> Result<Engine<A>> {
        fs::create_dir_all(dir.join("commits"))?;
        fs::create_dir_all(dir.join("candidates"))?;
        let state = match fs::read_to_string(dir.join("state.json")) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| StoreError::Corrupt(format!("state.json: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State {
                next_id: 1,
                ..State::default()
            },
            Err(e) => return Err(e.into()),
        };
        let mut engine = Engine {
            dir: dir.to_path_buf(),
            applier,
            baseline,
            state,
            audit: Audit::open(&dir.join("audit.log"))?,
        };
        if engine.state.pending.is_some() {
            engine.revert("system", true, now)?;
        } else if let Some(id) = engine.state.running {
            let target = engine.target_of(Some(id))?;
            engine.applier.apply(&target).map_err(StoreError::Apply)?;
            engine.audit.append(
                now,
                "system",
                "start",
                &format!("applied running commit #{id}"),
            )?;
        } else if baseline == Baseline::Lockdown {
            engine
                .applier
                .apply(&baseline.target())
                .map_err(StoreError::Apply)?;
            engine.audit.append(
                now,
                "system",
                "start",
                "no commit yet, inbound and forwarded traffic is dropped",
            )?;
        } else {
            engine
                .audit
                .append(now, "system", "start", "no commit yet, nothing applied")?;
        }
        Ok(engine)
    }

    pub fn applier(&mut self) -> &mut A {
        &mut self.applier
    }

    fn commit_path(&self, id: u64, ext: &str) -> PathBuf {
        self.dir.join("commits").join(format!("{id:06}.{ext}"))
    }

    fn candidate_path(&self, name: &str) -> Result<PathBuf> {
        if !is_name(name) {
            return Err(StoreError::Invalid(format!(
                "'{name}' is not a candidate name; use lowercase letters, digits and hyphens"
            )));
        }
        Ok(self.dir.join("candidates").join(format!("{name}.toml")))
    }

    fn save_state(&self) -> Result<()> {
        let json = serde_json::to_vec_pretty(&self.state).expect("state is plain JSON");
        Ok(write_atomic(&self.dir.join("state.json"), &json)?)
    }

    fn save_commit(&self, commit: &Commit) -> Result<()> {
        let json = serde_json::to_vec_pretty(commit).expect("a commit is plain JSON");
        Ok(write_atomic(&self.commit_path(commit.id, "json"), &json)?)
    }

    pub fn commit(&self, id: u64) -> Result<Commit> {
        let text = fs::read_to_string(self.commit_path(id, "json"))
            .map_err(|_| StoreError::NotFound(format!("commit #{id}")))?;
        serde_json::from_str(&text).map_err(|e| StoreError::Corrupt(format!("commit #{id}: {e}")))
    }

    /// The config text of a commit.
    pub fn commit_config(&self, id: u64) -> Result<String> {
        fs::read_to_string(self.commit_path(id, "toml"))
            .map_err(|_| StoreError::NotFound(format!("commit #{id}")))
    }

    /// Commits the box still holds, newest first.
    pub fn history(&self) -> Result<Vec<Commit>> {
        let mut out = vec![];
        for id in (1..self.state.next_id).rev() {
            match self.commit(id) {
                Ok(c) => out.push(c),
                Err(StoreError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    pub fn running(&self) -> Result<Option<Commit>> {
        self.state.running.map(|id| self.commit(id)).transpose()
    }

    /// The running config text, or `None` before the first commit.
    pub fn running_config(&self) -> Result<Option<String>> {
        self.state
            .running
            .map(|id| self.commit_config(id))
            .transpose()
    }

    /// What a commit asks of the box, or the baseline when there is none.
    fn target_of(&self, id: Option<u64>) -> Result<Target> {
        match id {
            None => Ok(self.baseline.target()),
            Some(id) => {
                let (config, rs) = check(&self.commit_config(id)?).map_err(|e| {
                    StoreError::Corrupt(format!("commit #{id} no longer loads: {e}"))
                })?;
                Ok(target(&config, &rs))
            }
        }
    }

    pub fn status(&mut self, now: u64) -> Result<Status> {
        Ok(Status {
            running: self.running()?,
            reverts_in: self
                .state
                .pending
                .as_ref()
                .map(|p| p.deadline.saturating_sub(now)),
            candidates: self.candidates()?,
            applier: self.applier.name().to_string(),
            services: self.applier.services(),
            lockdown: self.baseline == Baseline::Lockdown && self.state.running.is_none(),
        })
    }

    // ── candidates ──────────────────────────────────────────────────────

    pub fn candidates(&self) -> Result<Vec<String>> {
        let mut names: Vec<String> = fs::read_dir(self.dir.join("candidates"))?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                e.file_name()
                    .to_str()?
                    .strip_suffix(".toml")
                    .map(String::from)
            })
            .collect();
        names.sort();
        Ok(names)
    }

    /// Stores a candidate. A config that does not validate and compile is refused.
    pub fn put_candidate(&mut self, name: &str, text: &str, who: &str, now: u64) -> Result<()> {
        let path = self.candidate_path(name)?;
        check(text)?;
        write_atomic(&path, text.as_bytes())?;
        self.audit.append(
            now,
            who,
            "candidate saved",
            &format!("{name} sha256 {}", audit::sha256_hex(text.as_bytes())),
        )?;
        Ok(())
    }

    pub fn candidate(&self, name: &str) -> Result<String> {
        fs::read_to_string(self.candidate_path(name)?)
            .map_err(|_| StoreError::NotFound(format!("candidate '{name}'")))
    }

    pub fn delete_candidate(&mut self, name: &str, who: &str, now: u64) -> Result<()> {
        fs::remove_file(self.candidate_path(name)?)
            .map_err(|_| StoreError::NotFound(format!("candidate '{name}'")))?;
        self.audit.append(now, who, "candidate deleted", name)?;
        Ok(())
    }

    // ── commits ─────────────────────────────────────────────────────────

    /// Applies a config and records it as the running commit.
    fn apply_new(&mut self, new: NewCommit, now: u64) -> Result<Commit> {
        let NewCommit {
            text,
            source,
            candidate,
            who,
            reason,
            confirm_secs,
        } = new;
        if let Some(p) = &self.state.pending {
            return Err(StoreError::Busy { commit: p.commit });
        }
        let (config, ruleset) = check(text)?;
        // Apply first. If the daemon dies before the commit is recorded, the
        // next start applies the old running commit again.
        self.applier
            .apply(&target(&config, &ruleset))
            .map_err(StoreError::Apply)?;

        let id = self.state.next_id;
        let outcome = match confirm_secs {
            Some(secs) => Outcome::Pending {
                deadline: now + secs,
            },
            None => Outcome::Confirmed {
                by: who.to_string(),
                at: now,
            },
        };
        let commit = Commit {
            id,
            time: now,
            author: who.to_string(),
            reason: reason.to_string(),
            source,
            parent: self.state.running,
            sha256: audit::sha256_hex(text.as_bytes()),
            outcome,
        };
        write_atomic(&self.commit_path(id, "toml"), text.as_bytes())?;
        self.save_commit(&commit)?;
        self.state.next_id += 1;
        self.state.running = Some(id);
        match confirm_secs {
            Some(secs) => {
                self.state.pending = Some(Pending {
                    commit: id,
                    deadline: now + secs,
                    candidate,
                });
            }
            None => {
                if let Some(name) = &candidate {
                    let _ = fs::remove_file(self.candidate_path(name)?);
                }
            }
        }
        self.save_state()?;
        self.audit.append(
            now,
            who,
            "commit",
            &format!(
                "#{id} from {}{} sha256 {} reason: {reason}",
                commit.source,
                confirm_secs
                    .map(|s| format!(", confirm window {s} s"))
                    .unwrap_or_default(),
                commit.sha256
            ),
        )?;
        self.prune()?;
        Ok(commit)
    }

    /// Commits a candidate. With `confirm_secs`, the commit reverts by itself
    /// unless [`Engine::confirm`] is called within the window.
    pub fn commit_candidate(
        &mut self,
        name: &str,
        who: &str,
        reason: &str,
        confirm_secs: Option<u64>,
        now: u64,
    ) -> Result<Commit> {
        let text = self.candidate(name)?;
        self.apply_new(
            NewCommit {
                text: &text,
                source: format!("candidate {name}"),
                candidate: Some(name.to_string()),
                who,
                reason,
                confirm_secs,
            },
            now,
        )
    }

    /// Makes the config from `steps` commits back the running one, as a new commit.
    pub fn rollback(
        &mut self,
        steps: u64,
        who: &str,
        reason: &str,
        confirm_secs: Option<u64>,
        now: u64,
    ) -> Result<Commit> {
        if steps == 0 {
            return Err(StoreError::Invalid("rollback needs at least 1 step".into()));
        }
        let mut target = self.state.running;
        for _ in 0..steps {
            let id = target.ok_or_else(|| {
                StoreError::Invalid(format!("there are fewer than {steps} commits to go back"))
            })?;
            target = self.commit(id)?.parent;
        }
        let id = target.ok_or_else(|| {
            StoreError::Invalid(format!("there are fewer than {steps} commits to go back"))
        })?;
        let text = self.commit_config(id)?;
        self.apply_new(
            NewCommit {
                text: &text,
                source: format!("rollback to #{id}"),
                candidate: None,
                who,
                reason,
                confirm_secs,
            },
            now,
        )
    }

    /// Keeps the pending commit.
    pub fn confirm(&mut self, who: &str, now: u64) -> Result<Commit> {
        let pending = self
            .state
            .pending
            .clone()
            .ok_or(StoreError::NothingPending)?;
        let mut commit = self.commit(pending.commit)?;
        commit.outcome = Outcome::Confirmed {
            by: who.to_string(),
            at: now,
        };
        self.save_commit(&commit)?;
        self.state.pending = None;
        self.save_state()?;
        if let Some(name) = &pending.candidate {
            let _ = fs::remove_file(self.candidate_path(name)?);
        }
        self.audit
            .append(now, who, "confirm", &format!("#{}", commit.id))?;
        Ok(commit)
    }

    /// Undoes the pending commit by applying the one before it. The candidate
    /// it came from is kept.
    pub fn revert(&mut self, who: &str, auto: bool, now: u64) -> Result<Commit> {
        let pending = self
            .state
            .pending
            .clone()
            .ok_or(StoreError::NothingPending)?;
        let mut commit = self.commit(pending.commit)?;
        let previous = self.target_of(commit.parent)?;
        self.applier.apply(&previous).map_err(StoreError::Apply)?;
        commit.outcome = Outcome::Reverted { auto, at: now };
        self.save_commit(&commit)?;
        self.state.running = commit.parent;
        self.state.pending = None;
        self.save_state()?;
        self.audit.append(
            now,
            who,
            if auto { "auto revert" } else { "revert" },
            &format!(
                "#{} → {}",
                commit.id,
                commit
                    .parent
                    .map_or("no config".to_string(), |p| format!("#{p}"))
            ),
        )?;
        Ok(commit)
    }

    /// Reverts the pending commit if its window has passed. Call this often.
    pub fn tick(&mut self, now: u64) -> Result<Option<Commit>> {
        self.applier.tick();
        match &self.state.pending {
            Some(p) if now >= p.deadline => self.revert("system", true, now).map(Some),
            _ => Ok(None),
        }
    }

    /// Drops commits older than the last [`HISTORY`], never the running one
    /// or its parent.
    fn prune(&mut self) -> Result<()> {
        let newest = self.state.next_id.saturating_sub(1);
        let keep_parent = self.running()?.and_then(|c| c.parent);
        for id in 1..newest.saturating_sub(HISTORY - 1) {
            if Some(id) == self.state.running || Some(id) == keep_parent {
                continue;
            }
            let _ = fs::remove_file(self.commit_path(id, "json"));
            let _ = fs::remove_file(self.commit_path(id, "toml"));
        }
        Ok(())
    }

    // ── audit ───────────────────────────────────────────────────────────

    /// Every audit entry, oldest first. Fails if the chain is broken.
    pub fn audit(&self) -> std::result::Result<Vec<Entry>, AuditError> {
        self.audit.read()
    }

    pub fn note(&mut self, now: u64, who: &str, event: &str, detail: &str) -> Result<()> {
        self.audit.append(now, who, event, detail)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BRANCH: &str = include_str!("../../../examples/branch.toml");
    const CANDIDATE: &str = include_str!("../../../examples/branch-candidate.toml");

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ox-store-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn open(d: &Path, now: u64) -> Engine<NullApplier> {
        Engine::open(d, NullApplier::default(), now).unwrap()
    }

    /// True when the ruleset the applier holds contains a rule for this ID.
    fn has_rule(e: &mut Engine<NullApplier>, id: &str) -> bool {
        e.applier()
            .dump()
            .unwrap()
            .to_string()
            .contains(&format!("\"comment\":\"{id}\""))
    }

    fn with_base(name: &str) -> (PathBuf, Engine<NullApplier>) {
        let d = dir(name);
        let mut e = open(&d, 1000);
        e.put_candidate("base", BRANCH, "ana", 1001).unwrap();
        e.commit_candidate("base", "ana", "first config", None, 1002)
            .unwrap();
        e.put_candidate("block-legacy-smb", CANDIDATE, "jun", 1003)
            .unwrap();
        (d, e)
    }

    #[test]
    fn a_plain_commit_runs_and_closes_its_candidate() {
        let (d, mut e) = with_base("plain");
        let running = e.running().unwrap().unwrap();
        assert_eq!((running.id, running.parent), (1, None));
        assert!(matches!(running.outcome, Outcome::Confirmed { .. }));
        assert_eq!(e.candidates().unwrap(), ["block-legacy-smb"]);
        assert!(has_rule(&mut e, "r-0388") && !has_rule(&mut e, "r-0412"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn an_invalid_candidate_is_refused_and_named() {
        let d = dir("invalid");
        let mut e = open(&d, 1000);
        let bad = BRANCH.replace("service = [\"tcp/873\"]", "service = [\"rsyncd\"]");
        let err = e
            .put_candidate("bad", &bad, "ana", 1001)
            .unwrap_err()
            .to_string();
        assert!(err.contains("service 'rsyncd' is not defined"), "{err}");
        assert!(e.candidates().unwrap().is_empty());
        assert!(e.put_candidate("Bad Name", BRANCH, "ana", 1001).is_err());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn an_unconfirmed_commit_reverts_by_itself() {
        let (d, mut e) = with_base("auto");
        let c = e
            .commit_candidate("block-legacy-smb", "jun", "CHG-2207", Some(300), 2000)
            .unwrap();
        assert_eq!(c.id, 2);
        assert!(has_rule(&mut e, "r-0412"));
        assert_eq!(e.status(2100).unwrap().reverts_in, Some(200));
        assert!(
            e.tick(2299).unwrap().is_none(),
            "one second before the deadline"
        );

        let reverted = e.tick(2300).unwrap().unwrap();
        assert_eq!(
            reverted.outcome,
            Outcome::Reverted {
                auto: true,
                at: 2300
            }
        );
        assert_eq!(e.running().unwrap().unwrap().id, 1);
        assert!(!has_rule(&mut e, "r-0412") && has_rule(&mut e, "r-0388"));
        // The candidate is kept, so it can be fixed and committed again.
        assert_eq!(e.candidates().unwrap(), ["block-legacy-smb"]);
        assert!(e.tick(9999).unwrap().is_none());
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn confirm_keeps_the_commit_and_closes_the_candidate() {
        let (d, mut e) = with_base("confirm");
        e.commit_candidate("block-legacy-smb", "jun", "CHG-2207", Some(300), 2000)
            .unwrap();
        let c = e.confirm("jun", 2050).unwrap();
        assert_eq!(
            c.outcome,
            Outcome::Confirmed {
                by: "jun".into(),
                at: 2050
            }
        );
        assert!(
            e.tick(9999).unwrap().is_none(),
            "a confirmed commit never reverts"
        );
        assert!(has_rule(&mut e, "r-0412"));
        assert!(e.candidates().unwrap().is_empty());
        assert!(matches!(
            e.confirm("jun", 2051),
            Err(StoreError::NothingPending)
        ));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn only_one_commit_can_be_pending() {
        let (d, mut e) = with_base("busy");
        e.commit_candidate("block-legacy-smb", "jun", "x", Some(300), 2000)
            .unwrap();
        e.put_candidate("other", BRANCH, "ana", 2001).unwrap();
        assert!(matches!(
            e.commit_candidate("other", "ana", "y", None, 2002),
            Err(StoreError::Busy { commit: 2 })
        ));
        assert!(matches!(
            e.rollback(1, "ana", "y", None, 2003),
            Err(StoreError::Busy { .. })
        ));
        e.revert("jun", false, 2004).unwrap();
        e.commit_candidate("other", "ana", "y", None, 2005).unwrap();
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_failed_apply_changes_nothing() {
        let (d, mut e) = with_base("fail");
        e.applier().fail_next = Some("kernel said no".into());
        let err = e
            .commit_candidate("block-legacy-smb", "jun", "x", Some(60), 2000)
            .unwrap_err();
        assert!(matches!(err, StoreError::Apply(_)));
        assert_eq!(e.running().unwrap().unwrap().id, 1);
        assert_eq!(e.status(2000).unwrap().reverts_in, None);
        assert_eq!(e.history().unwrap().len(), 1);
        assert!(!has_rule(&mut e, "r-0412"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_restart_reverts_a_pending_commit_and_reapplies_the_running_one() {
        let (d, mut e) = with_base("restart");
        e.commit_candidate("block-legacy-smb", "jun", "x", Some(300), 2000)
            .unwrap();
        drop(e);

        // Nobody could confirm while the daemon was down, even inside the window.
        let mut e = open(&d, 2010);
        assert_eq!(e.running().unwrap().unwrap().id, 1);
        assert_eq!(
            e.applier().applied,
            1,
            "the previous commit was applied at start"
        );
        assert!(has_rule(&mut e, "r-0388") && !has_rule(&mut e, "r-0412"));
        assert_eq!(
            e.commit(2).unwrap().outcome,
            Outcome::Reverted {
                auto: true,
                at: 2010
            }
        );
        drop(e);

        let mut e = open(&d, 2020);
        assert_eq!(
            e.applier().applied,
            1,
            "a clean restart applies the running commit"
        );
        assert!(has_rule(&mut e, "r-0388"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn reverting_the_first_commit_leaves_no_ruleset() {
        let d = dir("first");
        let mut e = open(&d, 1000);
        e.put_candidate("base", BRANCH, "ana", 1001).unwrap();
        e.commit_candidate("base", "ana", "first", Some(60), 1002)
            .unwrap();
        e.tick(1062).unwrap().unwrap();
        assert!(e.running().unwrap().is_none());
        let dump = e.applier().dump().unwrap().to_string();
        assert!(
            dump.contains("\"delete\"") && !dump.contains("r-0388"),
            "{dump}"
        );
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn rollback_is_a_new_commit_with_the_old_config() {
        let (d, mut e) = with_base("rollback");
        e.commit_candidate("block-legacy-smb", "jun", "x", None, 2000)
            .unwrap();
        assert!(has_rule(&mut e, "r-0412"));
        let c = e
            .rollback(1, "ana", "broke the scanner", None, 2100)
            .unwrap();
        assert_eq!(
            (c.id, c.parent, c.source.as_str()),
            (3, Some(2), "rollback to #1")
        );
        assert_eq!(c.sha256, e.commit(1).unwrap().sha256);
        assert!(!has_rule(&mut e, "r-0412"));
        let err = e
            .rollback(9, "ana", "x", None, 2200)
            .unwrap_err()
            .to_string();
        assert!(err.contains("fewer than 9"), "{err}");
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn every_change_is_in_the_audit_log() {
        let (d, mut e) = with_base("audit");
        e.commit_candidate("block-legacy-smb", "jun", "CHG-2207", Some(300), 2000)
            .unwrap();
        e.tick(2300).unwrap();
        let events: Vec<String> = e
            .audit()
            .unwrap()
            .into_iter()
            .map(|a| format!("{} {}", a.who, a.event))
            .collect();
        assert_eq!(
            events,
            [
                "system start",
                "ana candidate saved",
                "ana commit",
                "jun candidate saved",
                "jun commit",
                "system auto revert",
            ]
        );
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn services_are_applied_with_the_firewall_and_go_back_with_it() {
        const HOME: &str = include_str!("../../../examples/home.toml");
        let d = dir("services");
        let mut e = open(&d, 1000);
        e.put_candidate("base", BRANCH, "ana", 1001).unwrap();
        e.commit_candidate("base", "ana", "no services", None, 1002)
            .unwrap();
        assert!(e.applier().last.as_ref().unwrap().services.is_empty());

        e.put_candidate("home", HOME, "ana", 1003).unwrap();
        e.commit_candidate("home", "ana", "dns and dhcp", Some(60), 1004)
            .unwrap();
        let conf = e.applier().last.as_ref().unwrap().services["dnsmasq"].clone();
        assert!(conf.contains("dhcp-range=interface:eth1,192.168.10.100"));
        assert_eq!(e.status(1005).unwrap().services.len(), 1);

        // Not confirmed: the service config goes away with the rules.
        e.tick(1064).unwrap().unwrap();
        assert!(e.applier().last.as_ref().unwrap().services.is_empty());
        assert!(has_rule(&mut e, "r-0388"));
        fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn lockdown_holds_until_the_first_commit_and_returns_after_its_revert() {
        let d = dir("lockdown");
        let locked = |e: &mut Engine<NullApplier>| {
            e.applier()
                .dump()
                .unwrap()
                .to_string()
                .contains("\"comment\":\"lockdown\"")
        };
        let mut e =
            Engine::open_with(&d, NullApplier::default(), Baseline::Lockdown, 1000).unwrap();
        assert!(locked(&mut e));
        assert!(e.status(1000).unwrap().lockdown);

        e.put_candidate("base", BRANCH, "ana", 1001).unwrap();
        e.commit_candidate("base", "ana", "first", Some(60), 1002)
            .unwrap();
        assert!(!locked(&mut e) && has_rule(&mut e, "r-0388"));
        assert!(!e.status(1003).unwrap().lockdown);

        // Reverting the first commit must not leave the box open.
        e.tick(1062).unwrap().unwrap();
        assert!(locked(&mut e));

        // Without the option, a box with no commit has nothing loaded.
        let d2 = dir("open");
        let mut open_box = open(&d2, 1000);
        assert_eq!(open_box.applier().applied, 0);
        assert!(!open_box.status(1000).unwrap().lockdown);
        fs::remove_dir_all(d).unwrap();
        fs::remove_dir_all(d2).unwrap();
    }

    #[test]
    fn history_is_capped() {
        let d = dir("prune");
        let mut e = open(&d, 1000);
        for i in 0..(HISTORY + 5) {
            let text = if i % 2 == 0 { BRANCH } else { CANDIDATE };
            e.put_candidate("c", text, "ana", 1000 + i).unwrap();
            e.commit_candidate("c", "ana", "churn", None, 1000 + i)
                .unwrap();
        }
        let history = e.history().unwrap();
        assert_eq!(history.len() as u64, HISTORY);
        assert_eq!(history[0].id, HISTORY + 5);
        assert!(matches!(e.commit(1), Err(StoreError::NotFound(_))));
        fs::remove_dir_all(d).unwrap();
    }
}

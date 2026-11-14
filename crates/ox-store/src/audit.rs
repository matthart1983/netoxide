//! The audit log: an append-only file of JSON lines where each entry carries
//! the hash of the one before it. Changing or deleting any line breaks every
//! hash after it, and `verify` reports the first broken line.

use std::{
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The `prev` value of the first entry.
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    /// Unix time in seconds.
    pub time: u64,
    pub who: String,
    pub event: String,
    pub detail: String,
    /// Hash of the previous entry.
    pub prev: String,
    /// SHA-256 over this entry's other fields.
    pub hash: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

impl Entry {
    fn compute_hash(&self) -> String {
        // Length-prefix each field so "ab"+"c" and "a"+"bc" hash differently.
        let mut h = Sha256::new();
        for field in [
            self.seq.to_string(),
            self.time.to_string(),
            self.who.clone(),
            self.event.clone(),
            self.detail.clone(),
            self.prev.clone(),
        ] {
            h.update((field.len() as u64).to_be_bytes());
            h.update(field.as_bytes());
        }
        hex(&h.finalize())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit log: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit log line {line} is not a valid entry: {source}")]
    Parse {
        line: u64,
        source: serde_json::Error,
    },
    #[error("audit log is broken at line {line}: {why}")]
    Broken { line: u64, why: &'static str },
}

/// Checks a log's text: every line an entry, in order, each chained to the
/// one before.
fn verify(bytes: &[u8]) -> Result<Vec<Entry>, AuditError> {
    let mut entries: Vec<Entry> = vec![];
    for (i, line) in bytes.split(|b| *b == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let n = i as u64 + 1;
        let entry: Entry =
            serde_json::from_slice(line).map_err(|source| AuditError::Parse { line: n, source })?;
        let prev = entries.last().map_or(GENESIS, |e| e.hash.as_str());
        if entry.seq != entries.len() as u64 + 1 {
            return Err(AuditError::Broken {
                line: n,
                why: "an entry is missing or out of order",
            });
        }
        if entry.prev != prev {
            return Err(AuditError::Broken {
                line: n,
                why: "it does not follow the entry before it",
            });
        }
        if entry.hash != entry.compute_hash() {
            return Err(AuditError::Broken {
                line: n,
                why: "its content does not match its hash",
            });
        }
        entries.push(entry);
    }
    Ok(entries)
}

pub struct Audit {
    path: PathBuf,
    next_seq: u64,
    last_hash: String,
    /// What was wrong with the log when it was opened, if anything.
    damage: Option<String>,
}

impl Audit {
    /// Opens the log and verifies the whole chain.
    ///
    /// A damaged log never stops the caller from starting: a firewall that
    /// will not load its rules because of a log line is worse than a gap in
    /// the log. A last line cut short by a power loss is removed. A log that
    /// fails verification anywhere else is set aside under a new name and a
    /// fresh log is started. Either way [`Audit::take_damage`] says what
    /// happened, so the caller can record it as the next entry.
    pub fn open(path: &Path) -> Result<Audit, AuditError> {
        let mut audit = Audit {
            path: path.to_path_buf(),
            next_seq: 1,
            last_hash: GENESIS.to_string(),
            damage: None,
        };
        let entries = match audit.read_file() {
            Ok(entries) => entries,
            Err(AuditError::Io(e)) => return Err(e.into()),
            Err(problem) => {
                if let Some(kept) = audit.cut_torn_tail()? {
                    audit.damage = Some(
                        "the last entry was cut short, as after a power loss, and was removed"
                            .to_string(),
                    );
                    kept
                } else {
                    let aside = audit.set_aside()?;
                    audit.damage = Some(format!(
                        "the log failed verification ({problem}); it was kept as {} and a new log was started",
                        aside.display()
                    ));
                    vec![]
                }
            }
        };
        if let Some(last) = entries.last() {
            audit.next_seq = last.seq + 1;
            audit.last_hash = last.hash.clone();
        }
        if audit.damage.is_none()
            && let Some((seq, _)) = audit.head()
            && seq >= audit.next_seq
        {
            audit.damage = Some(format!(
                "the log ends at entry {} but entry {seq} was written earlier; the newest entries are missing",
                audit.next_seq - 1
            ));
        }
        Ok(audit)
    }

    /// What was wrong with the log at open. Returns it once.
    pub fn take_damage(&mut self) -> Option<String> {
        self.damage.take()
    }

    /// How many entries the log holds.
    pub fn len(&self) -> u64 {
        self.next_seq - 1
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn head_path(&self) -> PathBuf {
        self.path.with_extension("head")
    }

    /// The sequence number and hash of the newest entry ever written, kept
    /// beside the log so that cutting entries off its end is noticed. Someone
    /// who can write both files can still forge both: the chain has no key.
    /// Shipping the head off the box is what would close that.
    fn head(&self) -> Option<(u64, String)> {
        let text = std::fs::read_to_string(self.head_path()).ok()?;
        let (seq, hash) = text.trim().split_once(' ')?;
        Some((seq.parse().ok()?, hash.to_string()))
    }

    /// If everything but the last line verifies, removes that line and
    /// returns the entries that remain.
    fn cut_torn_tail(&self) -> Result<Option<Vec<Entry>>, AuditError> {
        let bytes = std::fs::read(&self.path)?;
        let body = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
        let keep = body.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        // A whole, readable entry that does not fit the chain is not a
        // torn write. Only a line that is not an entry at all is.
        if serde_json::from_slice::<Entry>(&body[keep..]).is_ok() {
            return Ok(None);
        }
        let Ok(entries) = verify(&bytes[..keep]) else {
            return Ok(None);
        };
        let file = OpenOptions::new().write(true).open(&self.path)?;
        file.set_len(keep as u64)?;
        file.sync_data()?;
        Ok(Some(entries))
    }

    fn set_aside(&self) -> Result<PathBuf, AuditError> {
        let mut n = 1;
        loop {
            let aside = self.path.with_extension(format!("broken-{n}"));
            if !aside.exists() {
                std::fs::rename(&self.path, &aside)?;
                let _ = std::fs::remove_file(self.head_path());
                return Ok(aside);
            }
            n += 1;
        }
    }

    fn read_file(&self) -> Result<Vec<Entry>, AuditError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => verify(&bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
            Err(e) => Err(e.into()),
        }
    }

    /// Reads and checks every entry. Returns them oldest first. Entries
    /// missing from the end are an error too.
    pub fn read(&self) -> Result<Vec<Entry>, AuditError> {
        let entries = self.read_file()?;
        if let Some((seq, _)) = self.head()
            && seq > entries.len() as u64
        {
            return Err(AuditError::Broken {
                line: entries.len() as u64,
                why: "entries after this one are missing",
            });
        }
        Ok(entries)
    }
    /// Appends one entry and syncs it to disk before returning.
    pub fn append(
        &mut self,
        time: u64,
        who: &str,
        event: &str,
        detail: &str,
    ) -> Result<Entry, AuditError> {
        let mut entry = Entry {
            seq: self.next_seq,
            time,
            who: who.to_string(),
            event: event.to_string(),
            detail: detail.to_string(),
            prev: self.last_hash.clone(),
            hash: String::new(),
        };
        entry.hash = entry.compute_hash();
        let mut line = serde_json::to_string(&entry).expect("an entry is plain JSON");
        line.push('\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.sync_data()?;
        self.next_seq += 1;
        self.last_hash = entry.hash.clone();
        // Best effort: without the head, a cut-off tail goes unnoticed, and
        // nothing else is lost.
        let head = self.head_path();
        let tmp = head.with_extension("head.tmp");
        if std::fs::write(&tmp, format!("{} {}\n", entry.seq, entry.hash)).is_ok() {
            let _ = std::fs::rename(&tmp, &head);
        }
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("ox-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn entries_chain_and_survive_reopen() {
        let path = temp("chain");
        let mut a = Audit::open(&path).unwrap();
        let first = a.append(100, "ana", "commit", "#1").unwrap();
        assert_eq!(first.prev, GENESIS);
        let second = a.append(101, "ana", "confirm", "#1").unwrap();
        assert_eq!(second.prev, first.hash);

        let mut reopened = Audit::open(&path).unwrap();
        let third = reopened.append(102, "jun", "revert", "#2").unwrap();
        assert_eq!((third.seq, &third.prev), (3, &second.hash));
        assert_eq!(reopened.read().unwrap().len(), 3);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn an_edited_or_deleted_line_is_detected() {
        let path = temp("tamper");
        let mut a = Audit::open(&path).unwrap();
        for i in 0..3 {
            a.append(100 + i, "ana", "commit", &format!("#{i}"))
                .unwrap();
        }
        let original = std::fs::read_to_string(&path).unwrap();

        std::fs::write(
            &path,
            original.replace(
                "\"who\":\"ana\",\"event\":\"commit\",\"detail\":\"#1\"",
                "\"who\":\"eve\",\"event\":\"commit\",\"detail\":\"#1\"",
            ),
        )
        .unwrap();
        let err = a.read().unwrap_err().to_string();
        assert!(
            err.contains("line 2") && err.contains("does not match its hash"),
            "{err}"
        );

        let without_second: String = original
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| format!("{l}\n"))
            .collect();
        std::fs::write(&path, without_second).unwrap();
        assert!(a.read().unwrap_err().to_string().contains("line 2"));
        // Opening it does not fail, because the firewall must still start.
        // The broken log is kept under another name and a new one begins.
        let mut reopened = Audit::open(&path).unwrap();
        let damage = reopened.take_damage().unwrap();
        assert!(damage.contains("failed verification"), "{damage}");
        assert!(path.with_extension("broken-1").exists());
        assert_eq!(reopened.len(), 0);
        reopened
            .append(200, "system", "audit log damaged", &damage)
            .unwrap();
        assert_eq!(reopened.read().unwrap().len(), 1);
        for ext in ["broken-1", "head"] {
            let _ = std::fs::remove_file(path.with_extension(ext));
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_last_line_cut_short_is_removed_and_the_rest_kept() {
        let path = temp("torn");
        let mut a = Audit::open(&path).unwrap();
        for i in 0..3 {
            a.append(100 + i, "ana", "commit", &format!("#{i}"))
                .unwrap();
        }
        // A power loss in the middle of writing a fourth entry.
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"seq\":4,\"time\":10");
        std::fs::write(&path, text).unwrap();

        let mut reopened = Audit::open(&path).unwrap();
        assert!(reopened.take_damage().unwrap().contains("cut short"));
        assert_eq!(reopened.len(), 3);
        let next = reopened.append(104, "ana", "commit", "#3").unwrap();
        assert_eq!(next.seq, 4);
        assert_eq!(reopened.read().unwrap().len(), 4);
        let _ = std::fs::remove_file(path.with_extension("head"));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn entries_cut_off_the_end_are_noticed() {
        let path = temp("cut");
        let mut a = Audit::open(&path).unwrap();
        for i in 0..3 {
            a.append(100 + i, "ana", "commit", &format!("#{i}"))
                .unwrap();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let first_two: String = text.lines().take(2).map(|l| format!("{l}\n")).collect();
        std::fs::write(&path, first_two).unwrap();

        assert!(a.read().unwrap_err().to_string().contains("missing"));
        let mut reopened = Audit::open(&path).unwrap();
        let damage = reopened.take_damage().unwrap();
        assert!(damage.contains("ends at entry 2 but entry 3"), "{damage}");
        // Recording the damage makes the log whole again from here on.
        reopened
            .append(200, "system", "audit log damaged", &damage)
            .unwrap();
        assert_eq!(reopened.read().unwrap().len(), 3);
        let _ = std::fs::remove_file(path.with_extension("head"));
        std::fs::remove_file(&path).unwrap();
    }
}

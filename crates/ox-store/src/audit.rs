//! The audit log: an append-only file of JSON lines where each entry carries
//! the hash of the one before it. Changing or deleting any line breaks every
//! hash after it, and `verify` reports the first broken line.

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
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

pub struct Audit {
    path: PathBuf,
    next_seq: u64,
    last_hash: String,
}

impl Audit {
    /// Opens the log and verifies the whole chain, so a tampered log is
    /// noticed at start, before anything is appended to it.
    pub fn open(path: &Path) -> Result<Audit, AuditError> {
        let mut audit = Audit {
            path: path.to_path_buf(),
            next_seq: 1,
            last_hash: GENESIS.to_string(),
        };
        if let Some(last) = audit.read()?.last() {
            audit.next_seq = last.seq + 1;
            audit.last_hash = last.hash.clone();
        }
        Ok(audit)
    }

    /// Reads and checks every entry. Returns them oldest first.
    pub fn read(&self) -> Result<Vec<Entry>, AuditError> {
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut entries: Vec<Entry> = vec![];
        for (i, line) in BufReader::new(file).lines().enumerate() {
            let n = i as u64 + 1;
            let entry: Entry = serde_json::from_str(&line?)
                .map_err(|source| AuditError::Parse { line: n, source })?;
            let prev = entries.last().map_or(GENESIS, |e| e.hash.as_str());
            if entry.seq != n {
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
        assert!(
            Audit::open(&path).is_err(),
            "a broken log must not be appended to"
        );
        std::fs::remove_file(&path).unwrap();
    }
}

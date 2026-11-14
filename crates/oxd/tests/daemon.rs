//! Runs the real daemon against a real kernel, inside a private, rootless
//! network namespace, and drives it through its socket.
//!
//! The test skips itself, with a note, where `unshare`, user namespaces or
//! libnftables are not available. It never touches the host's ruleset.

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use serde_json::{Value, json};

const BRANCH: &str = include_str!("../../../examples/branch.toml");
const CANDIDATE: &str = include_str!("../../../examples/branch-candidate.toml");

struct Daemon {
    child: Child,
    dir: PathBuf,
}

impl Daemon {
    fn socket(&self) -> PathBuf {
        self.dir.join("oxd.sock")
    }

    /// Starts `oxd` in a new user and network namespace and waits for its socket.
    fn start(dir: &Path) -> Option<Daemon> {
        let _ = std::fs::remove_file(dir.join("oxd.sock"));
        let child = Command::new("unshare")
            .args(["-Urn", env!("CARGO_BIN_EXE_oxd"), "--state-dir"])
            .arg(dir.join("state"))
            .arg("--socket")
            .arg(dir.join("oxd.sock"))
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut d = Daemon {
            child,
            dir: dir.to_path_buf(),
        };
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if UnixStream::connect(d.socket()).is_ok() {
                return Some(d);
            }
            if d.child.try_wait().ok().flatten().is_some() {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    fn call(&self, method: &str, path: &str, body: &str) -> (u16, String) {
        let mut s = UnixStream::connect(self.socket()).unwrap();
        write!(
            s,
            "{method} {path} HTTP/1.1\r\nHost: oxd\r\nConnection: close\r\nx-ox-user: tester\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).unwrap();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, body.to_string())
    }

    fn ok(&self, method: &str, path: &str, body: &str) -> Value {
        let (status, text) = self.call(method, path, body);
        assert!(
            (200..300).contains(&status),
            "{method} {path} → {status}: {text}"
        );
        serde_json::from_str(&text).unwrap_or(Value::String(text))
    }

    /// True when the kernel's table holds a rule for this config rule ID.
    fn kernel_has(&self, rule: &str) -> bool {
        let dump = self.ok("GET", "/v1/kernel", "");
        dump["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["rule"]["comment"] == rule)
    }

    fn running(&self) -> Value {
        self.ok("GET", "/v1/status", "")["running"]["id"].clone()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn commit_confirm_revert_and_rollback_against_the_kernel() {
    let dir = std::env::temp_dir().join(format!("oxd-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(d) = Daemon::start(&dir) else {
        eprintln!("skipped: needs unshare(1), unprivileged user namespaces and libnftables");
        return;
    };

    // First commit, no confirm window.
    assert_eq!(d.running(), Value::Null);
    d.ok("PUT", "/v1/candidates/base", BRANCH);
    let plan = d.ok("POST", "/v1/candidates/base/plan", "");
    assert_eq!(plan["first_commit"], true);
    d.ok(
        "POST",
        "/v1/candidates/base/commit",
        r#"{"reason":"first"}"#,
    );
    assert_eq!(d.running(), 1);
    assert!(d.kernel_has("r-0388") && !d.kernel_has("r-0412"));

    // A broken candidate is refused with the problem named, and nothing changes.
    let bad = BRANCH.replace("tcp/873", "tcp/0");
    let (status, text) = d.call("PUT", "/v1/candidates/bad", &bad);
    assert_eq!(status, 422, "{text}");
    assert!(text.contains("tcp/0"), "{text}");

    // The plan lists the change before anything is applied.
    d.ok("PUT", "/v1/candidates/block-legacy-smb", CANDIDATE);
    let plan = d.ok("POST", "/v1/candidates/block-legacy-smb/plan", "");
    let first = plan["changes"][0].as_str().unwrap();
    assert!(first.starts_with("+ rule r-0412"), "{first}");
    assert!(!d.kernel_has("r-0412"));

    // Explain answers for both configs before the commit, here for IPv6.
    let packet = json!({ "src": "2001:db8:4a00:1:4::17", "dst": "2001:db8:4a00:2::8",
        "proto": "tcp", "dport": 445, "in": "lan0.20", "candidate": "block-legacy-smb" });
    let e = d.ok("POST", "/v1/explain", &packet.to_string());
    assert_eq!(e["running"]["verdict"], "ACCEPT");
    assert_eq!(e["candidate"]["verdict"], "DROP");

    // Commit with the shortest window and let it lapse: the kernel goes back by itself.
    let window = r#"{"confirm_secs":10,"reason":"CHG-2207"}"#;
    d.ok("POST", "/v1/candidates/block-legacy-smb/commit", window);
    assert!(d.kernel_has("r-0412"));
    let (status, _) = d.call("POST", "/v1/rollback", "{}");
    assert_eq!(
        status, 409,
        "a second change is refused while one is pending"
    );
    std::thread::sleep(Duration::from_secs(12));
    assert_eq!(d.running(), 1);
    assert!(!d.kernel_has("r-0412") && d.kernel_has("r-0388"));

    // Commit again and confirm: it stays.
    d.ok("POST", "/v1/candidates/block-legacy-smb/commit", window);
    d.ok("POST", "/v1/confirm", "");
    assert_eq!(d.running(), 3);
    assert!(d.kernel_has("r-0412"));

    // Roll back one commit with a long window, then kill the daemon inside it.
    let rollback = r#"{"steps":1,"confirm_secs":600,"reason":"test"}"#;
    d.ok("POST", "/v1/rollback", rollback);
    assert_eq!(d.running(), 4);
    assert!(!d.kernel_has("r-0412"));
    drop(d);

    // A fresh namespace has an empty kernel. The restarted daemon must revert
    // the unconfirmed rollback and load commit #3 into it.
    let d = Daemon::start(&dir).expect("daemon restarts");
    assert_eq!(d.running(), 3);
    assert!(d.kernel_has("r-0412"));

    let audit = d.ok("GET", "/v1/audit", "");
    assert_eq!(audit["verified"], true);
    let entries = audit["entries"].as_array().unwrap();
    let reverts = entries
        .iter()
        .filter(|e| e["event"] == "auto revert")
        .count();
    assert_eq!(reverts, 2);
    assert!(entries.iter().any(|e| e["who"] == "tester"));

    drop(d);
    std::fs::remove_dir_all(&dir).unwrap();
}

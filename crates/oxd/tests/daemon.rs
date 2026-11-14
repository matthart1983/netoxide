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

const HOME: &str = include_str!("../../../examples/home.toml");

/// A daemon in a namespace that has the inside interface of the home
/// example, so DNS and DHCP have somewhere to listen.
fn start_home(dir: &Path, extra: &[&str]) -> Option<Daemon> {
    let _ = std::fs::remove_file(dir.join("oxd.sock"));
    // The setup needs a shell because it runs several `ip` commands inside
    // the new namespace before the daemon starts. This is test scaffolding.
    // eth1 is one end of a cable; cli0 is the other, where test clients sit.
    let setup = "ip link set lo up && ip link add eth1 type veth peer name cli0 \
                 && ip link set cli0 up \
                 && ip addr add 192.168.10.1/24 dev eth1 \
                 && ip -6 addr add 2001:db8:2::1/64 dev eth1 nodad \
                 && ip link set eth1 up && exec \"$@\"";
    let child = Command::new("unshare")
        .args(["-Urn", "sh", "-c", setup, "sh", env!("CARGO_BIN_EXE_oxd")])
        .arg("--state-dir")
        .arg(dir.join("state"))
        .arg("--socket")
        .arg(dir.join("oxd.sock"))
        .arg("--keep-service-privileges")
        .args(extra)
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

/// Asks the resolver inside the daemon's namespace. `None` when there is no answer.
fn dig(d: &Daemon, server: &str, name: &str, kind: &str) -> Option<String> {
    let out = Command::new("nsenter")
        .args(["--user", "--net", "--preserve-credentials", "-t"])
        .arg(d.child.id().to_string())
        .args(["dig", "+short", "+time=2", "+tries=1"])
        .arg(format!("@{server}"))
        .args([name, kind])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !text.is_empty()).then_some(text)
}

fn have(program: &str, arg: &str) -> bool {
    Command::new(program)
        .arg(arg)
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn dns_and_dhcp_follow_the_commits() {
    if !(have("dnsmasq", "--version") && have("dig", "-v") && have("nsenter", "--version")) {
        eprintln!("skipped: needs dnsmasq, dig and nsenter");
        return;
    }
    let dir = std::env::temp_dir().join(format!("oxd-dns-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(d) = start_home(&dir, &["--lockdown"]) else {
        eprintln!("skipped: needs unshare(1), unprivileged user namespaces and libnftables");
        return;
    };

    // No config yet: locked down, and nothing answers DNS.
    let status = d.ok("GET", "/v1/status", "");
    assert_eq!(status["lockdown"], true);
    assert!(d.kernel_has("lockdown"));
    assert_eq!(dig(&d, "192.168.10.1", "nas.home.arpa", "A"), None);

    // The home config brings up the resolver and the address pool.
    d.ok("PUT", "/v1/candidates/home", HOME);
    d.ok(
        "POST",
        "/v1/candidates/home/commit",
        r#"{"reason":"home router"}"#,
    );
    let status = d.ok("GET", "/v1/status", "");
    assert_eq!(status["lockdown"], false);
    assert_eq!(status["services"][0], json!(["dnsmasq", "running"]));
    assert!(!d.kernel_has("lockdown") && d.kernel_has("r-services"));
    for (server, kind, want) in [
        ("192.168.10.1", "A", "192.168.10.5"),
        ("192.168.10.1", "AAAA", "2001:db8:2::5"),
        ("2001:db8:2::1", "A", "192.168.10.5"),
    ] {
        assert_eq!(
            dig(&d, server, "nas.home.arpa", kind).as_deref(),
            Some(want),
            "{server} {kind}"
        );
    }
    assert_eq!(
        dig(&d, "192.168.10.1", "nas", "A").as_deref(),
        Some("192.168.10.5"),
        "short name"
    );
    assert_eq!(d.ok("GET", "/v1/leases", ""), json!([]));

    // Change a record with a confirm window and let it lapse: the old answer returns.
    let moved = HOME.replace(
        "address = \"192.168.10.5\"\n\n[[dns.host]]",
        "address = \"192.168.10.77\"\n\n[[dns.host]]",
    );
    assert_ne!(moved, HOME);
    d.ok("PUT", "/v1/candidates/moved", &moved);
    d.ok(
        "POST",
        "/v1/candidates/moved/commit",
        r#"{"confirm_secs":10,"reason":"move nas"}"#,
    );
    assert_eq!(
        dig(&d, "192.168.10.1", "nas.home.arpa", "A").as_deref(),
        Some("192.168.10.77")
    );
    std::thread::sleep(Duration::from_secs(12));
    assert_eq!(d.running(), 1);
    assert_eq!(
        dig(&d, "192.168.10.1", "nas.home.arpa", "A").as_deref(),
        Some("192.168.10.5")
    );

    // A config without services stops the resolver.
    d.ok("PUT", "/v1/candidates/plain", BRANCH);
    d.ok(
        "POST",
        "/v1/candidates/plain/commit",
        r#"{"reason":"no services"}"#,
    );
    assert_eq!(dig(&d, "192.168.10.1", "nas.home.arpa", "A"), None);
    assert_eq!(d.ok("GET", "/v1/status", "")["services"], json!([]));

    drop(d);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_service_that_cannot_run_refuses_the_commit_and_changes_nothing() {
    let dir = std::env::temp_dir().join(format!("oxd-svc-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // `false` stands in for a dnsmasq that rejects every config.
    let Some(d) = start_home(&dir, &["--dnsmasq", "false"]) else {
        eprintln!("skipped: needs unshare(1), unprivileged user namespaces and libnftables");
        return;
    };
    d.ok("PUT", "/v1/candidates/base", BRANCH);
    d.ok(
        "POST",
        "/v1/candidates/base/commit",
        r#"{"reason":"first"}"#,
    );
    assert!(d.kernel_has("r-0388"));

    d.ok("PUT", "/v1/candidates/home", HOME);
    let (status, text) = d.call("POST", "/v1/candidates/home/commit", r#"{"reason":"x"}"#);
    assert_eq!(status, 500, "{text}");
    assert!(text.contains("not applied, nothing changed"), "{text}");
    assert_eq!(d.running(), 1);
    assert!(d.kernel_has("r-0388") && !d.kernel_has("r-services"));

    drop(d);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Runs the test DHCP client on the far end of the cable. Returns
/// `(address, server, lease seconds)`.
fn dhcp(d: &Daemon, mac: &str, name: &str) -> Option<(String, String, u32)> {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/dhcp_client.py");
    let out = Command::new("nsenter")
        .args(["--user", "--net", "--preserve-credentials", "-t"])
        .arg(d.child.id().to_string())
        .args(["python3", "-I", script, "cli0", mac, name])
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!(
            "dhcp client: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut parts = text.split_whitespace();
    Some((
        parts.next()?.to_string(),
        parts.next()?.to_string(),
        parts.next()?.parse().ok()?,
    ))
}

/// A real DHCP exchange through the firewall: a client on the inside cable
/// asks for an address and gets one from the pool, a known device gets its
/// fixed address, and both show up in the lease list.
#[test]
fn a_dhcp_client_gets_an_address_through_the_firewall() {
    if !(have("dnsmasq", "--version")
        && have("python3", "--version")
        && have("nsenter", "--version"))
    {
        eprintln!("skipped: needs dnsmasq, python3 and nsenter");
        return;
    }
    let dir = std::env::temp_dir().join(format!("oxd-dhcp-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(d) = start_home(&dir, &["--lockdown"]) else {
        eprintln!("skipped: needs unshare(1), unprivileged user namespaces and libnftables");
        return;
    };

    // Locked down and nothing configured: nobody answers.
    assert_eq!(dhcp(&d, "02:00:00:00:00:01", "laptop"), None);

    d.ok("PUT", "/v1/candidates/home", HOME);
    d.ok(
        "POST",
        "/v1/candidates/home/commit",
        r#"{"reason":"home router"}"#,
    );

    let (address, server, lease) =
        dhcp(&d, "02:00:00:00:00:01", "laptop").expect("an address from the pool");
    let last: u8 = address.rsplit('.').next().unwrap().parse().unwrap();
    assert!(
        address.starts_with("192.168.10.") && (100..=199).contains(&last),
        "{address}"
    );
    assert_eq!((server.as_str(), lease), ("192.168.10.1", 43_200));

    // The NAS has a fixed address in the config.
    let (address, _, _) = dhcp(&d, "aa:bb:cc:dd:ee:01", "").expect("the fixed address");
    assert_eq!(address, "192.168.10.5");

    let leases = d.ok("GET", "/v1/leases", "");
    let rows = leases.as_array().unwrap();
    assert_eq!(rows.len(), 2, "{leases}");
    assert!(
        rows.iter()
            .any(|r| r["mac"] == "02:00:00:00:00:01" && r["name"] == "laptop")
    );
    assert!(
        rows.iter()
            .any(|r| r["address"] == "192.168.10.5" && r["name"] == "nas")
    );

    // The box announces its IPv6 network on the same interface.
    let log = std::fs::read_to_string(dir.join("state/services/dnsmasq.log")).unwrap();
    assert!(
        log.contains("router advertisement on 2001:db8:2::"),
        "{log}"
    );

    // Take the DHCP rule away: the firewall now drops the requests, and
    // validation would have refused this, so remove the pool with it.
    let closed = HOME
        .split("[dns]")
        .next()
        .unwrap()
        .replace("service = [\"dns\", \"dhcp\"]", "service = [\"dns\"]");
    d.ok("PUT", "/v1/candidates/closed", &closed);
    d.ok(
        "POST",
        "/v1/candidates/closed/commit",
        r#"{"reason":"no dhcp"}"#,
    );
    assert_eq!(dhcp(&d, "02:00:00:00:00:02", "phone"), None);

    drop(d);
    std::fs::remove_dir_all(&dir).unwrap();
}

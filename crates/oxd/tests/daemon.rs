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
        skip("needs unshare(1), unprivileged user namespaces and libnftables");
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

    // Metrics and hygiene read the kernel's counters for the running rules.
    let (status, metrics) = d.call("GET", "/metrics", "");
    assert_eq!(status, 200);
    for want in [
        "netoxide_running_commit 3",
        "netoxide_commit_pending 0",
        "netoxide_rule_packets_total{rule=\"r-0412\"} 0",
        "netoxide_rule_packets_total{rule=\"default lan-dmz\"} 0",
        "# TYPE netoxide_rule_bytes_total counter",
    ] {
        assert!(metrics.contains(want), "missing `{want}` in:\n{metrics}");
    }
    let hygiene = d.ok("GET", "/v1/hygiene", "");
    assert!(
        hygiene
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule"] == "r-0412" && f["kind"] == "no packets"),
        "nothing has passed through the namespace, so every rule is unused: {hygiene}"
    );

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
    // The name comes from the kernel, not from anything the client sends.
    // Inside the daemon's user namespace an outside caller has no name, so
    // it is recorded by its mapped user ID.
    assert!(
        entries.iter().all(|e| e["who"] != "tester"),
        "the x-ox-user header must not be trusted"
    );
    assert!(
        entries
            .iter()
            .any(|e| e["event"] == "commit" && !e["who"].as_str().unwrap().is_empty())
    );

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
        skip("needs dnsmasq, dig and nsenter");
        return;
    }
    let dir = std::env::temp_dir().join(format!("oxd-dns-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(d) = start_home(&dir, &["--lockdown"]) else {
        skip("needs unshare(1), unprivileged user namespaces and libnftables");
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
    assert!(
        status["services"]
            .as_array()
            .unwrap()
            .contains(&json!(["dnsmasq", "running"]))
    );
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
    let services = d.ok("GET", "/v1/status", "")["services"].clone();
    assert!(
        services
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s[0] != "dnsmasq"),
        "{services}"
    );
    // The branch example names interfaces this namespace does not have. That
    // is reported, not fatal.
    assert!(
        services.to_string().contains("interface wan0"),
        "{services}"
    );

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
        skip("needs unshare(1), unprivileged user namespaces and libnftables");
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
        skip("needs dnsmasq, python3 and nsenter");
        return;
    }
    let dir = std::env::temp_dir().join(format!("oxd-dhcp-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(d) = start_home(&dir, &["--lockdown"]) else {
        skip("needs unshare(1), unprivileged user namespaces and libnftables");
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

/// Calls the HTTPS listener from inside the daemon's namespace with curl.
/// Returns the status and the body.
fn https(
    d: &Daemon,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> (u16, String) {
    let mut cmd = Command::new("nsenter");
    cmd.args(["--user", "--net", "--preserve-credentials", "-t"])
        .arg(d.child.id().to_string())
        // -k: the daemon made its own certificate, which curl has no reason to trust.
        .args(["curl", "-sk", "-X", method, "-w", "\n%{http_code}"])
        .arg(format!("https://127.0.0.1:8443{path}"));
    if let Some(t) = token {
        cmd.args(["-H", &format!("Authorization: Bearer {t}")]);
    }
    if let Some(b) = body {
        cmd.args(["-H", "Content-Type: application/json", "--data-binary", b]);
    }
    let out = cmd.output().expect("curl runs");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let (body, code) = text.rsplit_once('\n').unwrap_or(("", "0"));
    (code.trim().parse().unwrap_or(0), body.to_string())
}

/// Tokens, roles and four-eyes approval over the HTTPS listener.
#[test]
fn the_https_api_needs_a_token_and_respects_its_role() {
    if !(have("curl", "--version") && have("nsenter", "--version")) {
        skip("needs curl and nsenter");
        return;
    }
    let dir = std::env::temp_dir().join(format!("oxd-https-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(d) = start_home(&dir, &["--listen", "127.0.0.1:8443", "--dry-run"]) else {
        skip("needs unshare(1) and unprivileged user namespaces");
        return;
    };
    // Give the listener a moment to come up after the socket.
    std::thread::sleep(Duration::from_millis(300));

    // No token, or a wrong one: nothing but the page itself.
    assert_eq!(https(&d, "GET", "/v1/status", None, None).0, 401);
    assert_eq!(
        https(&d, "GET", "/v1/status", Some("ox_wrong"), None).0,
        401
    );
    let (code, page) = https(&d, "GET", "/", None, None);
    assert_eq!(code, 200);
    assert!(page.contains("Netoxide"));

    // Tokens are made on the local socket, by an admin.
    let token = |name: &str, role: &str| -> String {
        let v = d.ok(
            "POST",
            "/v1/tokens",
            &json!({ "name": name, "role": role }).to_string(),
        );
        v["token"].as_str().unwrap().to_string()
    };
    let (viewer, ana, jun, auditor) = (
        token("viewer", "viewer"),
        token("ana", "operator"),
        token("jun", "operator"),
        token("auditor", "auditor"),
    );
    let who = https(&d, "GET", "/v1/whoami", Some(&ana), None).1;
    assert!(
        who.contains("token:ana") && who.contains("operator"),
        "{who}"
    );

    // A viewer reads and nothing else.
    assert_eq!(https(&d, "GET", "/v1/status", Some(&viewer), None).0, 200);
    let (code, text) = https(
        &d,
        "PUT",
        "/v1/candidates/base",
        Some(&viewer),
        Some(BRANCH),
    );
    assert_eq!(code, 403, "{text}");
    assert!(text.contains("may not save or delete candidates"), "{text}");
    assert_eq!(https(&d, "GET", "/v1/audit", Some(&viewer), None).0, 403);
    assert_eq!(https(&d, "GET", "/v1/audit", Some(&auditor), None).0, 200);
    // Only an admin manages tokens, and an operator is not one.
    assert_eq!(https(&d, "GET", "/v1/tokens", Some(&ana), None).0, 403);
    assert_eq!(
        https(&d, "POST", "/v1/rollback", Some(&ana), Some("{}")).0,
        403
    );

    // An operator saves and commits.
    assert_eq!(
        https(&d, "PUT", "/v1/candidates/base", Some(&ana), Some(BRANCH)).0,
        200
    );
    let (code, text) = https(
        &d,
        "POST",
        "/v1/candidates/base/commit",
        Some(&ana),
        Some(r#"{"reason":"first"}"#),
    );
    assert_eq!(code, 200, "{text}");

    // With four-eyes on, the author cannot approve their own candidate.
    d.ok("PUT", "/v1/settings", r#"{"four_eyes":true}"#);
    assert_eq!(
        https(&d, "PUT", "/v1/candidates/smb", Some(&jun), Some(CANDIDATE)).0,
        200
    );
    let commit = |t: &str| {
        https(
            &d,
            "POST",
            "/v1/candidates/smb/commit",
            Some(t),
            Some(r#"{"reason":"CHG-2207"}"#),
        )
    };
    let (code, text) = commit(&jun);
    assert_eq!(code, 403, "{text}");
    assert!(text.contains("needs approval"), "{text}");
    let (code, text) = https(&d, "POST", "/v1/candidates/smb/approve", Some(&jun), None);
    assert_eq!(code, 422, "{text}");
    assert_eq!(
        https(
            &d,
            "POST",
            "/v1/candidates/smb/approve",
            Some(&viewer),
            None
        )
        .0,
        403
    );
    assert_eq!(
        https(&d, "POST", "/v1/candidates/smb/approve", Some(&ana), None).0,
        200
    );
    assert_eq!(commit(&jun).0, 200);

    // A revoked token stops working at once.
    d.ok("DELETE", "/v1/tokens/jun", "");
    assert_eq!(https(&d, "GET", "/v1/status", Some(&jun), None).0, 401);

    // The audit log names the tokens that acted.
    let audit = https(&d, "GET", "/v1/audit", Some(&auditor), None).1;
    assert!(
        audit.contains("token:jun") && audit.contains("candidate approved"),
        "{audit}"
    );

    // The private key the daemon made is readable by its owner only.
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dir.join("state/tls/key.pem"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "key.pem mode is {mode:o}");

    drop(d);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The endpoints the web UI is built on, and the page itself.
#[test]
fn the_web_ui_endpoints_work_and_the_page_is_locked_down() {
    if !(have("curl", "--version") && have("nsenter", "--version")) {
        skip("needs curl and nsenter");
        return;
    }
    let dir = std::env::temp_dir().join(format!("oxd-web-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(d) = start_home(&dir, &["--listen", "127.0.0.1:8443", "--dry-run"]) else {
        skip("needs unshare(1) and unprivileged user namespaces");
        return;
    };
    std::thread::sleep(Duration::from_millis(300));

    // One-step actions need a running config to start from.
    let forward = r#"{"name":"Home Assistant","port":"tcp/443","to":"192.168.10.20","to_port":8123,"address":"203.0.113.10"}"#;
    let (status, text) = d.call("POST", "/v1/actions/forward", forward);
    assert_eq!(status, 422, "{text}");
    assert!(text.contains("no commit yet"), "{text}");

    d.ok("PUT", "/v1/candidates/home", HOME);
    d.ok("POST", "/v1/candidates/home/commit", r#"{"reason":"home"}"#);

    let view = d.ok("GET", "/v1/running/json", "");
    assert_eq!(view["config"]["hostname"], "homebox");
    assert!(
        view["describe"]
            .as_array()
            .unwrap()
            .iter()
            .any(|l| l.as_str().unwrap().contains("answers DNS"))
    );

    // Forward a port: saved as a candidate, with the rule it needs, and not applied.
    let done = d.ok("POST", "/v1/actions/forward", forward);
    assert_eq!(done["candidate"], "forward-home-assistant");
    assert!(
        done["done"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .as_str()
            .unwrap()
            .starts_with("checked:")
    );
    let plan = d.ok("POST", "/v1/candidates/forward-home-assistant/plan", "");
    assert!(plan["changes"].to_string().contains("r-fwd-home-assistant"));
    assert_eq!(d.running(), 1);

    // Block a device, and refuse an address that is not on the box's networks.
    let done = d.ok(
        "POST",
        "/v1/actions/block",
        r#"{"address":"192.168.10.66","name":"Smart TV"}"#,
    );
    assert_eq!(done["candidate"], "block-smart-tv");
    let (status, text) = d.call("POST", "/v1/actions/block", r#"{"address":"10.9.9.9"}"#);
    assert_eq!(status, 422, "{text}");
    assert!(text.contains("not on any network"), "{text}");

    // Check a config without storing it.
    let ok = d.ok("POST", "/v1/check", HOME);
    assert_eq!(ok["valid"], true);
    let (status, text) = d.call("POST", "/v1/check", &HOME.replace("tcp/22", "tcp/0"));
    assert_eq!(status, 422);
    assert!(text.contains("tcp/0"), "{text}");
    assert_eq!(
        d.ok("GET", "/v1/candidates", "").as_array().unwrap().len(),
        2,
        "check stores nothing"
    );

    // A viewer cannot use the actions.
    let viewer = d.ok("POST", "/v1/tokens", r#"{"name":"viewer","role":"viewer"}"#)["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(
        https(
            &d,
            "POST",
            "/v1/actions/forward",
            Some(&viewer),
            Some(forward)
        )
        .0,
        403
    );

    // The page and its two files are served without a token, and forbid
    // inline script, other origins and framing.
    let out = Command::new("nsenter")
        .args(["--user", "--net", "--preserve-credentials", "-t"])
        .arg(d.child.id().to_string())
        .args(["curl", "-skD", "-", "https://127.0.0.1:8443/"])
        .output()
        .unwrap();
    let page = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(
        page.contains("content-security-policy: default-src 'self'"),
        "{page}"
    );
    assert!(
        page.contains("x-frame-options: deny") && page.contains("x-content-type-options: nosniff")
    );
    assert!(page.contains("<script src=\"/app.js\">"), "{page}");
    for file in ["/app.js", "/app.css"] {
        let (code, body) = https(&d, "GET", file, None, None);
        assert_eq!(code, 200);
        assert!(body.len() > 1000, "{file} is empty");
    }

    drop(d);
    std::fs::remove_dir_all(&dir).unwrap();
}

const ROUTER: &str = include_str!("../../../examples/router.toml");

/// Three namespaces joined by two virtual cables: a client inside, the box
/// in the middle, a server outside. The box's interfaces start with no
/// address and down, and the daemon has to bring them up from the config.
struct Lab {
    daemon: Daemon,
    client: u32,
    server: u32,
    helpers: Vec<Child>,
}

impl Lab {
    fn start(dir: &Path) -> Option<Lab> {
        let _ = std::fs::remove_file(dir.join("oxd.sock"));
        // Test scaffolding: a shell builds the lab, then becomes the daemon.
        let setup = format!(
            "ip link set lo up \
             && (unshare -n sleep 600 & echo $! > {dir}/client) \
             && (unshare -n sleep 600 & echo $! > {dir}/server) \
             && sleep 0.3 \
             && ip link add eth1 type veth peer name c0 && ip link set c0 netns $(cat {dir}/client) \
             && ip link add eth0 type veth peer name s0 && ip link set s0 netns $(cat {dir}/server) \
             && nsenter -t $(cat {dir}/client) -n sh -c 'ip link set lo up; ip addr add 192.168.10.50/24 dev c0; \
                  ip -6 addr add 2001:db8:2::50/64 dev c0 nodad; ip link set c0 up; \
                  ip route add default via 192.168.10.1; ip -6 route add default via 2001:db8:2::1' \
             && nsenter -t $(cat {dir}/server) -n sh -c 'ip link set lo up; ip addr add 203.0.113.9/24 dev s0; ip link set s0 up' \
             && exec \"$@\"",
            dir = dir.display()
        );
        let child = Command::new("unshare")
            .args(["-Urn", "sh", "-c", &setup, "sh", env!("CARGO_BIN_EXE_oxd")])
            .arg("--state-dir")
            .arg(dir.join("state"))
            .arg("--socket")
            .arg(dir.join("oxd.sock"))
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut daemon = Daemon {
            child,
            dir: dir.to_path_buf(),
        };
        let start = Instant::now();
        loop {
            if UnixStream::connect(daemon.socket()).is_ok() {
                break;
            }
            if daemon.child.try_wait().ok().flatten().is_some()
                || start.elapsed() > Duration::from_secs(8)
            {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let pid = |name: &str| -> Option<u32> {
            std::fs::read_to_string(dir.join(name))
                .ok()?
                .trim()
                .parse()
                .ok()
        };
        Some(Lab {
            client: pid("client")?,
            server: pid("server")?,
            daemon,
            helpers: vec![],
        })
    }

    /// A command inside one of the lab's namespaces.
    fn cmd(&self, ns: u32, program: &str) -> Command {
        let mut c = Command::new("nsenter");
        c.arg(format!("--user=/proc/{}/ns/user", self.daemon.child.id()))
            .arg(format!("--net=/proc/{ns}/ns/net"))
            .args(["--preserve-credentials", program]);
        c
    }

    /// Serves a one-line page on a port, so a fetch proves who answered.
    fn serve(&mut self, ns: u32, bind: &str, port: u16, dir: &Path, text: &str) {
        let root = dir.join(format!("www-{ns}-{port}"));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.html"), text).unwrap();
        let child = self
            .cmd(ns, "python3")
            .args([
                "-I",
                "-m",
                "http.server",
                &port.to_string(),
                "--bind",
                bind,
                "--directory",
            ])
            .arg(&root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.helpers.push(child);
    }

    /// Fetches a URL from a namespace. `None` when nothing answers in time.
    fn fetch(&self, ns: u32, url: &str) -> Option<String> {
        let out = self
            .cmd(ns, "curl")
            .args(["-s", "--max-time", "2", url])
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn ping(&self, ns: u32, target: &str) -> bool {
        self.cmd(ns, "ping")
            .args(["-c", "1", "-W", "2", target])
            .output()
            .is_ok_and(|o| o.status.success())
    }

    /// What the daemon's explain says about a packet from the client.
    fn explain(&self, dst: &str, proto: &str, dport: Option<u16>) -> String {
        let src = if dst.contains(':') {
            "2001:db8:2::50"
        } else {
            "192.168.10.50"
        };
        let body = json!({ "src": src, "dst": dst, "proto": proto, "dport": dport, "in": "eth1" });
        self.daemon.ok("POST", "/v1/explain", &body.to_string())["running"]["verdict"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        for h in &mut self.helpers {
            let _ = h.kill();
            let _ = h.wait();
        }
        for pid in [self.client, self.server] {
            let _ = Command::new("kill").arg(pid.to_string()).output();
        }
    }
}

/// Real packets through the firewall. The kernel's behaviour is compared
/// with what `explain` says for the same packets.
#[test]
fn packets_cross_the_box_as_the_config_and_explain_say() {
    if !(have("curl", "--version")
        && have("python3", "--version")
        && have("nsenter", "--version")
        && have("ping", "-V"))
    {
        skip("needs curl, python3, nsenter and ping");
        return;
    }
    let dir = std::env::temp_dir().join(format!("oxd-lab-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(mut lab) = Lab::start(&dir) else {
        skip("needs unshare(1), unprivileged user namespaces and libnftables");
        return;
    };
    let (client, server) = (lab.client, lab.server);
    lab.serve(server, "203.0.113.9", 80, &dir, "outside web");
    lab.serve(server, "203.0.113.9", 8081, &dir, "outside other");
    lab.serve(client, "192.168.10.50", 80, &dir, "inside web");
    std::thread::sleep(Duration::from_millis(600));

    // No config: the box's interfaces are down and have no address.
    assert_eq!(lab.fetch(client, "http://203.0.113.9/"), None);

    lab.daemon.ok("PUT", "/v1/candidates/router", ROUTER);
    lab.daemon.ok(
        "POST",
        "/v1/candidates/router/commit",
        r#"{"reason":"lab"}"#,
    );
    // The daemon has put the addresses on eth0 and eth1 and turned on forwarding.

    // Allowed: web and ping from inside to outside. The server has no route
    // back to 192.168.10.0/24, so an answer proves the source was rewritten.
    assert_eq!(
        lab.fetch(client, "http://203.0.113.9/").as_deref(),
        Some("outside web")
    );
    assert!(lab.ping(client, "203.0.113.9"));
    assert_eq!(lab.explain("203.0.113.9", "tcp", Some(80)), "ACCEPT");
    assert_eq!(lab.explain("203.0.113.9", "icmp", None), "ACCEPT");

    // Not allowed: another port outside.
    assert_eq!(lab.fetch(client, "http://203.0.113.9:8081/"), None);
    assert_eq!(lab.explain("203.0.113.9", "tcp", Some(8081)), "DROP");

    // The box itself: ping yes, anything else no, in both address families.
    assert!(lab.ping(client, "192.168.10.1"));
    assert_eq!(lab.explain("192.168.10.1", "icmp", None), "ACCEPT");
    let mut v6 = false;
    for _ in 0..10 {
        // A new IPv6 address takes a moment to finish duplicate detection.
        v6 = lab.ping(client, "2001:db8:2::1");
        if v6 {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(v6, "ping to the box over IPv6");
    assert_eq!(lab.explain("2001:db8:2::1", "icmpv6", None), "ACCEPT");
    assert_eq!(lab.fetch(client, "http://192.168.10.1:8443/"), None);
    assert_eq!(lab.explain("192.168.10.1", "tcp", Some(8443)), "DROP");

    // Inbound: the forwarded port reaches the inside server, nothing else does.
    assert_eq!(
        lab.fetch(server, "http://203.0.113.10:8080/").as_deref(),
        Some("inside web")
    );
    assert_eq!(lab.fetch(server, "http://203.0.113.10:80/"), None);

    // The kernel counted those packets against the right rules.
    let (_, metrics) = lab.daemon.call("GET", "/metrics", "");
    let packets = |rule: &str| -> u64 {
        metrics
            .lines()
            .find(|l| l.starts_with(&format!("netoxide_rule_packets_total{{rule=\"{rule}\"}}")))
            .and_then(|l| l.rsplit(' ').next()?.parse().ok())
            .unwrap_or(0)
    };
    for rule in [
        "r-web",
        "r-ping-box",
        "r-fwd-web",
        "n-fwd-web",
        "n-out",
        "default lan-wan",
    ] {
        assert!(packets(rule) > 0, "{rule} counted no packets:\n{metrics}");
    }
    let hygiene = lab.daemon.ok("GET", "/v1/hygiene", "");
    assert_eq!(hygiene, json!([]), "every rule has now seen traffic");

    // A change with a confirm window that is not kept: the block goes away again.
    let blocked = ROUTER.replace("service = [\"web\", \"ping\"]", "service = [\"ping\"]");
    lab.daemon.ok("PUT", "/v1/candidates/no-web", &blocked);
    lab.daemon.ok(
        "POST",
        "/v1/candidates/no-web/commit",
        r#"{"confirm_secs":10,"reason":"test"}"#,
    );
    assert_eq!(lab.fetch(client, "http://203.0.113.9/"), None);
    assert_eq!(lab.explain("203.0.113.9", "tcp", Some(80)), "DROP");
    std::thread::sleep(Duration::from_secs(12));
    assert_eq!(
        lab.fetch(client, "http://203.0.113.9/").as_deref(),
        Some("outside web")
    );

    // Renumbering the inside network takes the old address off the port,
    // because the daemon put it there. An address it did not put there stays.
    let box_ns = lab.daemon.child.id();
    let addrs = |lab: &Lab| {
        let out = lab
            .cmd(box_ns, "ip")
            .args(["-br", "addr", "show", "eth1"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    assert!(
        lab.cmd(box_ns, "ip")
            .args(["addr", "add", "10.99.0.1/24", "dev", "eth1"])
            .status()
            .unwrap()
            .success()
    );
    assert!(addrs(&lab).contains("192.168.10.1/24"));
    let renumbered = ROUTER
        .replace("192.168.10.1/24", "192.168.77.1/24")
        .replace("192.168.10.0/24", "192.168.77.0/24")
        .replace("192.168.10.50", "192.168.77.50");
    lab.daemon.ok("PUT", "/v1/candidates/renumber", &renumbered);
    lab.daemon.ok(
        "POST",
        "/v1/candidates/renumber/commit",
        r#"{"confirm_secs":10,"reason":"renumber"}"#,
    );
    let now = addrs(&lab);
    assert!(
        now.contains("192.168.77.1/24") && !now.contains("192.168.10.1/24"),
        "{now}"
    );
    assert!(
        now.contains("10.99.0.1/24"),
        "someone else's address is left alone: {now}"
    );
    // Nobody keeps it, and the old address comes back with the old rules.
    std::thread::sleep(Duration::from_secs(12));
    let back = addrs(&lab);
    assert!(
        back.contains("192.168.10.1/24") && !back.contains("192.168.77.1/24"),
        "{back}"
    );
    assert_eq!(
        lab.fetch(client, "http://203.0.113.9/").as_deref(),
        Some("outside web")
    );

    drop(lab);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Notes a test that cannot run here. With OX_REQUIRE_KERNEL_TESTS set, as
/// in CI, a skip is a failure, so these tests cannot silently stop running.
fn skip(why: &str) {
    assert!(
        std::env::var_os("OX_REQUIRE_KERNEL_TESTS").is_none(),
        "this test was required but could not run: it {why}"
    );
    eprintln!("skipped: {why}");
}

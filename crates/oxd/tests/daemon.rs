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
        eprintln!("skipped: needs curl and nsenter");
        return;
    }
    let dir = std::env::temp_dir().join(format!("oxd-https-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(d) = start_home(&dir, &["--listen", "127.0.0.1:8443", "--dry-run"]) else {
        eprintln!("skipped: needs unshare(1) and unprivileged user namespaces");
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

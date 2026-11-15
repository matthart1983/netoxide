//! `ox` from another machine: saving a box, checking its certificate, and
//! roles that are held to parts of the config.
//!
//! The daemon runs in its own network namespace with `--dry-run`, and `ox`
//! runs in the same namespace, talking to the HTTPS listener over IPv4 and
//! IPv6 loopback. Needs unshare(1), nsenter(1) and unprivileged user
//! namespaces; without them the test says so and passes, unless
//! OX_REQUIRE_KERNEL_TESTS is set.

use std::{
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const HOME: &str = include_str!("../../../examples/home.toml");

fn skip(why: &str) {
    assert!(
        std::env::var_os("OX_REQUIRE_KERNEL_TESTS").is_none(),
        "this test was required but could not run: it {why}"
    );
    eprintln!("skipped: {why}");
}

struct Box_ {
    child: Child,
    dir: PathBuf,
}

impl Drop for Box_ {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The result of one `ox` run.
struct Ran {
    ok: bool,
    out: String,
    err: String,
}

impl Box_ {
    fn start(dir: &Path) -> Option<Box_> {
        // Built by the same `cargo test --workspace` that built this test.
        let oxd = Path::new(env!("CARGO_BIN_EXE_ox")).with_file_name("oxd");
        if !oxd.exists() {
            return None;
        }
        let child = Command::new("unshare")
            .args(["-Urn", "sh", "-c", "ip link set lo up && exec \"$@\"", "sh"])
            .arg(oxd)
            .arg("--state-dir")
            .arg(dir.join("state"))
            .arg("--socket")
            .arg(dir.join("oxd.sock"))
            .args(["--listen", "[::]:8443", "--dry-run"])
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut b = Box_ {
            child,
            dir: dir.to_path_buf(),
        };
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if UnixStream::connect(dir.join("oxd.sock")).is_ok() {
                // The HTTPS listener comes up after the socket, once the
                // daemon has made its certificate. How long that takes
                // depends on the machine, so wait for the daemon to report it.
                let listening = Instant::now();
                while listening.elapsed() < Duration::from_secs(20)
                    && !b.local(&["status"]).out.contains("certificate sha256:")
                {
                    std::thread::sleep(Duration::from_millis(100));
                }
                std::thread::sleep(Duration::from_millis(400));
                return Some(b);
            }
            if b.child.try_wait().ok().flatten().is_some() {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }

    /// Runs `ox` inside the box's network namespace, as a machine that can
    /// reach it would. `env` adds to a clean set of variables.
    fn ox_env(&self, env: &[(&str, &str)], args: &[&str]) -> Ran {
        let mut cmd = Command::new("nsenter");
        cmd.args(["--user", "--net", "--preserve-credentials", "-t"])
            .arg(self.child.id().to_string())
            .arg(env!("CARGO_BIN_EXE_ox"))
            .args(args)
            .stdin(Stdio::null())
            .env_remove("OX_REMOTE")
            .env_remove("OX_URL")
            .env_remove("OX_TOKEN")
            .env_remove("OX_FINGERPRINT")
            .env_remove("OX_SOCKET")
            .env("OX_REMOTES", self.dir.join("remotes.toml"));
        for (k, v) in env {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("nsenter runs");
        Ran {
            ok: out.status.success(),
            out: String::from_utf8_lossy(&out.stdout).to_string(),
            err: String::from_utf8_lossy(&out.stderr).to_string(),
        }
    }

    fn ox(&self, args: &[&str]) -> Ran {
        self.ox_env(&[], args)
    }

    /// `ox` on the box itself, over the Unix socket, where the caller is an admin.
    fn local(&self, args: &[&str]) -> Ran {
        let socket = self.dir.join("oxd.sock");
        let mut all = vec!["--socket", socket.to_str().unwrap()];
        all.extend_from_slice(args);
        self.ox(&all)
    }

    /// Makes a token on the box and returns its secret.
    fn token(&self, name: &str, role: &str) -> String {
        let ran = self.local(&["token", "create", name, "--role", role]);
        assert!(ran.ok, "{}", ran.err);
        ran.out
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("ox_"))
            .expect("the secret is printed")
            .to_string()
    }

    fn file(&self, name: &str, text: &str) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, text).unwrap();
        path.to_str().unwrap().to_string()
    }

    /// Saves a box under `name` with a new token of `role`.
    fn add(&self, name: &str, url: &str, fingerprint: &str, role: &str) -> Ran {
        let token = self.file(&format!("{name}.token"), &self.token(name, role));
        self.ox(&[
            "remote",
            "add",
            name,
            url,
            "--fingerprint",
            fingerprint,
            "--token-file",
            &token,
        ])
    }
}

#[track_caller]
fn good(ran: &Ran) -> &str {
    assert!(ran.ok, "failed: {}{}", ran.out, ran.err);
    &ran.out
}

#[track_caller]
fn refused<'a>(ran: &'a Ran, because: &str) -> &'a str {
    assert!(!ran.ok, "should have failed: {}", ran.out);
    assert!(
        ran.err.contains(because),
        "wanted '{because}' in: {}",
        ran.err
    );
    &ran.err
}

#[test]
fn ox_manages_a_box_from_another_machine() {
    let dir = std::env::temp_dir().join(format!("ox-remote-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let Some(b) = Box_::start(&dir) else {
        skip("needs unshare(1), unprivileged user namespaces and a built oxd");
        return;
    };
    let v4 = "https://127.0.0.1:8443";
    let v6 = "https://[::1]:8443";

    // The box shows where it listens and the fingerprint of its certificate.
    let status = b.local(&["status"]);
    let fingerprint = good(&status)
        .lines()
        .find_map(|l| l.trim().strip_prefix("certificate "))
        .expect("status shows the certificate")
        .to_string();
    assert!(fingerprint.starts_with("sha256:") && fingerprint.len() == 71);
    assert!(status.out.contains("[::]:8443"), "{}", status.out);

    // ── saving a box ────────────────────────────────────────────────────
    let other = format!("sha256:{}", "ab".repeat(32));
    let token = b.file("first.token", &b.token("first", "operator"));

    // A fingerprint that is not the box's: nothing is saved.
    let ran = b.ox(&[
        "remote",
        "add",
        "home",
        v4,
        "--fingerprint",
        &other,
        "--token-file",
        &token,
    ]);
    refused(&ran, "not the fingerprint you gave");
    assert!(
        ran.err.contains(&fingerprint),
        "the real one is shown: {}",
        ran.err
    );
    assert!(!dir.join("remotes.toml").exists());

    // No fingerprint and nobody to ask: the box's is shown, and nothing is saved.
    let ran = b.ox(&["remote", "add", "home", v4, "--token-file", &token]);
    refused(&ran, "--fingerprint");
    assert!(ran.out.contains(&fingerprint), "{}", ran.out);
    assert!(!dir.join("remotes.toml").exists());

    // A token the box does not know: nothing is saved.
    let bad = b.file("bad.token", "ox_0000");
    let ran = b.ox(&[
        "remote",
        "add",
        "home",
        v4,
        "--fingerprint",
        &fingerprint,
        "--token-file",
        &bad,
    ]);
    refused(&ran, "unknown, expired or revoked");
    assert!(!dir.join("remotes.toml").exists());

    // Plain HTTP is refused before anything is sent.
    let ran = b.ox(&[
        "remote",
        "add",
        "home",
        "http://127.0.0.1:8443",
        "--token-file",
        &token,
    ]);
    refused(&ran, "unencrypted");

    // The right fingerprint and token, over IPv4 and over IPv6.
    let ran = b.add("home", v4, &fingerprint, "operator");
    assert!(
        good(&ran).contains("you are token:home with the role operator"),
        "{}",
        ran.out
    );
    let ran = b.add("six", v6, &fingerprint, "viewer");
    assert!(good(&ran).contains("token:six"), "{}", ran.out);

    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(dir.join("remotes.toml"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "the file with tokens is private");
    let listed = b.ox(&["remote", "list"]);
    assert!(good(&listed).contains("home") && listed.out.contains("https://[::1]:8443"));
    assert!(
        !listed.out.contains("ox_"),
        "tokens are not listed: {}",
        listed.out
    );

    // ── using it ────────────────────────────────────────────────────────
    let who = b.ox(&["--remote", "home", "whoami"]);
    assert!(good(&who).contains("token:home (operator)"), "{}", who.out);
    let who = b.ox(&["-r", "six", "whoami"]);
    assert!(good(&who).contains("token:six (viewer)"), "{}", who.out);
    let who = b.ox_env(&[("OX_REMOTE", "six")], &["whoami"]);
    assert!(good(&who).contains("token:six"), "{}", who.out);
    refused(
        &b.ox(&["-r", "lab", "status"]),
        "the saved ones are home, six",
    );

    // The whole change cycle, from the other machine.
    let home = b.file("home.toml", HOME);
    good(&b.ox(&["-r", "home", "candidate", "save", "base", &home]));
    let ran = b.ox(&["-r", "home", "commit", "base", "--reason", "first"]);
    good(&ran);
    assert_eq!(good(&b.ox(&["-r", "home", "running"])), HOME);
    assert_eq!(
        good(&b.ox(&["-r", "six", "running"])),
        HOME,
        "the same over IPv6"
    );
    let history = b.ox(&["-r", "home", "history"]);
    assert!(good(&history).contains("token:home"), "{}", history.out);
    // A viewer reads and may not change.
    refused(
        &b.ox(&["-r", "six", "candidate", "save", "x", &home]),
        "may not save or delete candidates",
    );
    // Setup looks at this machine's ports, so it is refused for a remote box.
    refused(
        &b.ox(&["-r", "home", "init", "--wan", "eth0", "--lan", "eth1"]),
        "run it on the box",
    );

    // For scripts: the box in environment variables, with no file.
    let secret = std::fs::read_to_string(dir.join("home.token")).unwrap();
    let env = [
        ("OX_URL", v6),
        ("OX_TOKEN", secret.as_str()),
        ("OX_FINGERPRINT", fingerprint.as_str()),
    ];
    assert!(good(&b.ox_env(&env, &["whoami"])).contains("token:home"));
    refused(&b.ox_env(&env[..1], &["whoami"]), "OX_TOKEN");
    // Without a fingerprint, the machine's certificate authorities decide,
    // and none of them signed a certificate the box made itself.
    refused(&b.ox_env(&env[..2], &["whoami"]), "does not trust");

    // ── a certificate that is not the saved one ─────────────────────────
    let saved = std::fs::read_to_string(dir.join("remotes.toml")).unwrap();
    assert!(saved.contains(&fingerprint));
    std::fs::write(
        dir.join("remotes.toml"),
        saved.replace(&fingerprint, &other),
    )
    .unwrap();
    let ran = b.ox(&["-r", "home", "status"]);
    let why = refused(&ran, "is not showing the certificate saved for it");
    assert!(why.contains(&fingerprint) && why.contains(&other), "{why}");
    assert!(why.contains("the access token was not sent"), "{why}");
    std::fs::write(dir.join("remotes.toml"), &saved).unwrap();
    good(&b.ox(&["-r", "home", "status"]));

    // A file other users can read is refused.
    std::fs::set_permissions(
        dir.join("remotes.toml"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    refused(&b.ox(&["-r", "home", "status"]), "chmod 600");
    std::fs::set_permissions(
        dir.join("remotes.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    // ── roles held to parts of the config ───────────────────────────────
    let roles = b.ox(&["-r", "six", "role", "list"]);
    for name in [
        "viewer",
        "auditor",
        "operator",
        "network-admin",
        "security-admin",
        "admin",
    ] {
        assert!(good(&roles).contains(name), "{name}: {}", roles.out);
    }
    // Only an admin makes roles, and the operator is not one.
    refused(
        &b.ox(&[
            "-r",
            "home",
            "role",
            "create",
            "helpdesk",
            "--can",
            "edit,commit",
            "--sections",
            "vpn",
        ]),
        "may not manage tokens, roles and settings",
    );
    refused(
        &b.local(&["role", "create", "x", "--can", "fly"]),
        "is not an action",
    );
    refused(
        &b.local(&["role", "create", "x", "--can", "edit", "--sections", "moon"]),
        "is not a section",
    );
    refused(
        &b.local(&["token", "create", "t", "--role", "nobody"]),
        "there is no role called 'nobody'",
    );
    let made = b.local(&[
        "role",
        "create",
        "helpdesk",
        "--can",
        "edit,commit",
        "--sections",
        "vpn",
    ]);
    assert!(
        good(&made).contains("may read, edit, commit"),
        "{}",
        made.out
    );
    assert!(good(&b.local(&["role", "list"])).contains("(made here)"));

    good(&b.add("desk", v4, &fingerprint, "helpdesk"));
    good(&b.add("net", v6, &fingerprint, "network-admin"));
    good(&b.add("sec", v4, &fingerprint, "security-admin"));
    let who = b.ox(&["-r", "desk", "whoami"]);
    assert!(good(&who).contains("changes in  vpn only"), "{}", who.out);

    // A new hostname is a change to the network section.
    let renamed = b.file(
        "renamed.toml",
        &HOME.replacen("hostname = \"", "hostname = \"new-", 1),
    );
    assert_ne!(std::fs::read_to_string(&renamed).unwrap(), HOME);
    let why = b.ox(&["-r", "desk", "candidate", "save", "rename", &renamed]);
    let why = refused(
        &why,
        "which may only change vpn; this would also change network",
    );
    assert!(why.contains("token:desk"), "{why}");
    refused(
        &b.ox(&["-r", "sec", "candidate", "save", "rename", &renamed]),
        "would also change network",
    );
    good(&b.ox(&["-r", "net", "candidate", "save", "rename", &renamed]));
    // The helpdesk may read it, and may not commit, approve or delete it,
    // nor save something harmless over it.
    let same = b.file("same.toml", HOME);
    refused(
        &b.ox(&["-r", "desk", "candidate", "save", "rename", &same]),
        "would also change network",
    );
    good(&b.ox(&["-r", "desk", "candidate", "save", "nothing", &same]));
    good(&b.ox(&["-r", "desk", "candidate", "rm", "nothing"]));
    good(&b.ox(&["-r", "desk", "candidate", "show", "rename"]));
    refused(
        &b.ox(&["-r", "desk", "commit", "rename"]),
        "would also change network",
    );
    refused(
        &b.ox(&["-r", "desk", "candidate", "rm", "rename"]),
        "would also change network",
    );
    refused(
        &b.ox(&["-r", "sec", "approve", "rename"]),
        "would also change network",
    );

    // Moving a port into another zone gives its traffic other rules. That
    // is a firewall change even though the key is in the network section.
    // The operator adds a spare inside port; the network admin may then
    // renumber it, and may not move it to the internet side.
    let spare = "\n[interfaces.eth9]\nzone = \"lan\"\naddresses = [\"192.168.99.1/24\", \"2001:db8:99::1/64\"]\n";
    let with_spare = format!("{HOME}{spare}");
    good(&b.ox(&[
        "-r",
        "home",
        "candidate",
        "save",
        "spare",
        &b.file("spare.toml", &with_spare),
    ]));
    good(&b.ox(&["-r", "home", "commit", "spare"]));
    let renumbered = b.file(
        "renumbered.toml",
        &with_spare.replace("192.168.99.1/24", "192.168.98.1/24"),
    );
    good(&b.ox(&["-r", "net", "candidate", "save", "renumbered", &renumbered]));
    good(&b.ox(&["-r", "net", "candidate", "rm", "renumbered"]));
    let moved = b.file(
        "moved.toml",
        &with_spare.replace(spare, &spare.replace("\"lan\"", "\"wan\"")),
    );
    refused(
        &b.ox(&["-r", "net", "candidate", "save", "moved", &moved]),
        "would also change firewall",
    );
    // The same file is a valid config: the operator may save it.
    good(&b.ox(&["-r", "home", "candidate", "save", "moved", &moved]));
    good(&b.ox(&["-r", "home", "candidate", "rm", "moved"]));
    // Back to the example config for the rest of the test.
    good(&b.ox(&["-r", "home", "candidate", "save", "base", &home]));
    good(&b.ox(&["-r", "home", "commit", "base"]));

    // A block is a firewall change: the security admin's, not the network admin's.
    refused(
        &b.ox(&["-r", "net", "block", "192.168.10.66"]),
        "would also change firewall",
    );
    refused(
        &b.ox(&["-r", "net", "block", "2001:db8:2::66"]),
        "would also change firewall",
    );
    refused(
        &b.ox(&[
            "-r",
            "desk",
            "forward",
            "--name",
            "web",
            "--port",
            "tcp/443",
            "--to",
            "192.168.10.5",
        ]),
        "would also change firewall",
    );
    let blocked = b.ox(&["-r", "sec", "block", "2001:db8:2::66"]);
    good(&blocked);

    // A commit that is waiting belongs to the section it changed: the
    // helpdesk can neither keep nor undo the network admin's.
    good(&b.ox(&["-r", "net", "commit", "rename", "--confirm", "5m"]));
    refused(
        &b.ox(&["-r", "desk", "confirm"]),
        "would also change network",
    );
    refused(
        &b.ox(&["-r", "desk", "revert"]),
        "would also change network",
    );
    refused(
        &b.ox(&["-r", "sec", "confirm"]),
        "would also change network",
    );
    good(&b.ox(&["-r", "net", "confirm"]));
    assert!(good(&b.ox(&["-r", "six", "running"])).contains("hostname = \"new-"));

    // The first VPN device also needs a firewall rule for the tunnel's
    // port, so it is the operator's to add. After that the helpdesk can add
    // devices by itself, and commit them.
    refused(
        &b.ox(&[
            "-r",
            "desk",
            "vpn",
            "add",
            "phone",
            "--endpoint",
            "box.example.net",
        ]),
        "would also change",
    );
    let first = b.ox(&[
        "-r",
        "home",
        "vpn",
        "add",
        "phone",
        "--endpoint",
        "box.example.net",
    ]);
    assert!(good(&first).contains("[Interface]"), "{}", first.out);
    let candidate = |ran: &Ran| -> String {
        ran.out
            .lines()
            .find_map(|l| l.strip_prefix("Saved as candidate "))
            .and_then(|l| l.split('.').next())
            .expect("the candidate is named")
            .to_string()
    };
    good(&b.ox(&["-r", "home", "commit", &candidate(&first)]));
    let second = b.ox(&[
        "-r",
        "desk",
        "vpn",
        "add",
        "tablet",
        "--endpoint",
        "2001:db8::1",
        "--qr",
    ]);
    assert!(good(&second).contains("[Interface]"), "{}", second.out);
    // The same config drawn as a code for a phone to scan.
    assert!(
        second.out.contains("Scan from QR code") && second.out.contains('█'),
        "{}",
        second.out
    );
    assert!(!first.out.contains('█'), "no code unless asked for");
    good(&b.ox(&[
        "-r",
        "desk",
        "commit",
        &candidate(&second),
        "--reason",
        "tablet",
    ]));
    let running = b.ox(&["-r", "six", "running"]);
    assert!(good(&running).contains("tablet") && running.out.contains("phone"));

    // ── the everyday commands ───────────────────────────────────────────
    // The short help lists a dozen commands and points at the rest.
    let help = b.ox(&["--help"]);
    assert!(
        good(&help).contains("apply") && help.out.contains("ox more"),
        "{}",
        help.out
    );
    assert!(
        !help.out.contains("rollback  "),
        "advanced commands stay out of the short help"
    );
    assert!(good(&b.ox(&["more"])).contains("rollback"));
    // Who can reach what, as a grid, then changed in plain words.
    let grid = b.ox(&["-r", "six", "access"]);
    assert!(
        good(&grid).contains("Inside network") && grid.out.contains("Allowed"),
        "{}",
        grid.out
    );
    refused(
        &b.ox(&["-r", "six", "access", "block", "lan", "wan"]),
        "may not save",
    );
    let blocked = b.ox(&["-r", "home", "access", "block", "lan", "wan"]);
    assert!(
        good(&blocked).contains("can no longer reach Internet"),
        "{}",
        blocked.out
    );
    assert!(
        blocked.out.contains("ox apply block-lan-wan"),
        "{}",
        blocked.out
    );
    // Apply it without naming it is refused while other changes wait too.
    let which = b.ox(&["-r", "home", "apply"]);
    assert!(
        !which.ok && which.err.contains("say which"),
        "{}{}",
        which.out,
        which.err
    );
    let applied = b.ox(&["-r", "home", "apply", "block-lan-wan"]);
    assert!(
        good(&applied).contains("can no longer reach Internet"),
        "{}",
        applied.out
    );
    assert!(applied.out.contains("ox keep"), "{}", applied.out);
    // What the inside network may do towards the internet, from the grid.
    let inside_to_internet = || -> String {
        let grid = b.ox(&["-r", "six", "access"]);
        good(&grid)
            .lines()
            .find(|l| l.starts_with("Inside network") && !l.contains("zone "))
            .and_then(|l| l.split_whitespace().last())
            .expect("the grid has a row for the inside network")
            .to_string()
    };
    assert_eq!(inside_to_internet(), "Blocked");
    // Undone, the grid is as before; applied again and kept, it stays.
    good(&b.ox(&["-r", "home", "undo"]));
    assert_eq!(inside_to_internet(), "Allowed");
    good(&b.ox(&["-r", "home", "apply", "block-lan-wan"]));
    good(&b.ox(&["-r", "home", "keep"]));
    assert_eq!(inside_to_internet(), "Blocked");
    good(&b.ox(&["-r", "home", "access", "allow", "lan", "wan"]));
    good(&b.ox(&["-r", "home", "apply", "allow-lan-wan"]));
    good(&b.ox(&["-r", "home", "keep"]));
    assert_eq!(inside_to_internet(), "Allowed");
    // A guest network in one step, then seen in the grid.
    let guest = b.ox(&[
        "-r",
        "home",
        "network",
        "add",
        "Guest Wi-Fi",
        "--port",
        "eth1",
        "--vlan",
        "20",
    ]);
    assert!(
        good(&guest).contains("VLAN 20 on eth1, where the box is 192.168.20.1/24"),
        "{}",
        guest.out
    );
    assert!(
        guest.out.contains("ox apply network-guest-wi-fi"),
        "{}",
        guest.out
    );
    refused(
        &b.ox(&[
            "-r", "home", "network", "add", "Bad", "--port", "eth0", "--vlan", "30",
        ]),
        "faces the internet",
    );
    let applied = b.ox(&["-r", "home", "apply", "network-guest-wi-fi"]);
    assert!(
        good(&applied).contains("A new network: Guest Wi-Fi"),
        "{}",
        applied.out
    );
    good(&b.ox(&["-r", "home", "keep"]));
    assert!(good(&b.ox(&["-r", "six", "access"])).contains("Guest Wi-Fi"));
    // Explain needs no interface name: the box places the device itself.
    let why = b.ox(&[
        "-r",
        "six",
        "explain",
        "--src",
        "192.168.10.50",
        "--dst",
        "1.1.1.1",
        "--proto",
        "tcp",
        "--dport",
        "443",
    ]);
    assert!(good(&why).contains("ACCEPT"), "{}", why.out);

    // ── backup and restore ──────────────────────────────────────────────
    // A backup holds private keys: only an admin may take one, and the file
    // is private. A second box restored from it has the same VPN identity.
    let file = dir.join("box.backup");
    let file = file.to_str().unwrap();
    refused(
        &b.ox(&["-r", "home", "backup", "--out", file]),
        "may not manage",
    );
    assert!(!Path::new(file).exists());
    let took = b.local(&["backup", "--out", file]);
    assert!(
        good(&took).contains("the running config, 1 VPN key(s), 1 role(s)"),
        "{}",
        took.out
    );
    let mode = std::fs::metadata(file).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let public = good(&b.local(&["vpn", "--key", "wg0"])).trim().to_string();

    let dir2 = dir.join("second");
    std::fs::create_dir_all(&dir2).unwrap();
    {
        let Some(b2) = Box_::start(&dir2) else {
            panic!("the second box did not start");
        };
        refused(&b2.local(&["restore", &b.file("junk", "{}")]), "format");
        let restored = b2.local(&["restore", file]);
        let text = good(&restored);
        assert!(
            text.contains("candidate restore") && text.contains("VPN key for wg0"),
            "{text}"
        );
        assert!(text.contains("made the role helpdesk"), "{text}");
        // Same key, so the devices' configs still match this box.
        assert_eq!(good(&b2.local(&["vpn", "--key", "wg0"])).trim(), public);
        // Nothing runs until the candidate is committed.
        refused(&b2.local(&["running"]), "no commit yet");
        good(&b2.local(&["commit", "restore"]));
        assert_eq!(
            good(&b2.local(&["running"])),
            good(&b.local(&["running"])),
            "the restored box runs the same config"
        );
        assert!(good(&b2.local(&["role", "list"])).contains("helpdesk"));
        assert!(good(&b2.local(&["audit"])).contains("backup restored"));
    }
    assert!(good(&b.local(&["audit"])).contains("backup taken"));

    // A role stays while a token has it.
    refused(
        &b.local(&["role", "delete", "helpdesk"]),
        "still used by the token desk",
    );
    refused(&b.local(&["role", "delete", "admin"]), "built-in");
    good(&b.local(&["token", "revoke", "desk"]));
    refused(
        &b.ox(&["-r", "desk", "status"]),
        "unknown, expired or revoked",
    );
    good(&b.local(&["role", "delete", "helpdesk"]));

    // Forgetting a box takes it out of the file.
    good(&b.ox(&["remote", "remove", "desk"]));
    refused(
        &b.ox(&["-r", "desk", "status"]),
        "no box is saved as 'desk'",
    );
    refused(&b.ox(&["remote", "remove", "desk"]), "no box is saved");

    // The audit log names every token that acted, and what was refused left no trace of a change.
    let audit = b.local(&["audit"]);
    for who in ["token:home", "token:net", "token:desk", "token:sec"] {
        assert!(good(&audit).contains(who), "{who}: {}", audit.out);
    }
    assert!(audit.out.contains("role created") && audit.out.contains("role deleted"));

    drop(b);
    std::fs::remove_dir_all(&dir).unwrap();
}

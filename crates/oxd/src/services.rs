//! Runs dnsmasq for the config's DNS and DHCP settings.
//!
//! The daemon starts dnsmasq itself, with a fixed argument list and no
//! shell, and restarts it when its config changes or it stops. dnsmasq does
//! not re-read its main config on a signal, so a change is a restart.
//!
//! TODO(spec): the spec has each service in its own systemd unit with a
//! seccomp profile. This direct supervision is the first step and is what
//! runs in a network namespace, where there is no systemd.

use std::{
    fs,
    io::Read,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};

pub struct Dnsmasq {
    /// Where the config, lease file, pid file and log live.
    dir: PathBuf,
    /// The program to run. Normally `dnsmasq`.
    program: String,
    /// Run without switching to an unprivileged user. Needed in a user
    /// namespace, where that switch is not permitted.
    keep_privileges: bool,
    child: Option<Child>,
    /// The config the running process was started with.
    conf: Option<String>,
}

impl Dnsmasq {
    pub fn new(dir: PathBuf, program: String, keep_privileges: bool) -> Dnsmasq {
        let d = Dnsmasq {
            dir,
            program,
            keep_privileges,
            child: None,
            conf: None,
        };
        d.stop_stale();
        d
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    pub fn lease_file(&self) -> PathBuf {
        self.path("dnsmasq.leases")
    }

    /// A dnsmasq left behind by a daemon that was killed would hold the
    /// ports. Stop it, but only if the pid really is a dnsmasq.
    fn stop_stale(&self) {
        let Ok(text) = fs::read_to_string(self.path("dnsmasq.pid")) else {
            return;
        };
        let Ok(pid) = text.trim().parse::<i32>() else {
            return;
        };
        let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        if comm.trim() == "dnsmasq" {
            let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
            std::thread::sleep(Duration::from_millis(200));
        }
        let _ = fs::remove_file(self.path("dnsmasq.pid"));
    }

    /// Runs dnsmasq's own syntax check on a config, without touching the
    /// running process.
    pub fn check(&self, conf: Option<&String>) -> Result<(), String> {
        let Some(conf) = conf else {
            return Ok(());
        };
        fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        let path = self.path("dnsmasq.conf.check");
        fs::write(&path, conf).map_err(|e| format!("{}: {e}", path.display()))?;
        let out = Command::new(&self.program)
            .arg("--test")
            .arg(format!("--conf-file={}", path.display()))
            .output()
            .map_err(|e| {
                format!(
                    "the config asks for DNS or DHCP, but '{}' could not be run: {e}",
                    self.program
                )
            })?;
        let _ = fs::remove_file(&path);
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "dnsmasq refused the DNS and DHCP settings: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn alive(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|c| matches!(c.try_wait(), Ok(None)))
    }

    /// Stops dnsmasq and waits for it to be gone. Never waits forever: a
    /// daemon that may not signal its own child (it runs as another user,
    /// which needs CAP_KILL) reports that instead of hanging.
    fn stop(&mut self) -> Result<(), String> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        let pid = Pid::from_raw(child.id() as i32);
        let gone = |child: &mut Child, tries: u32| {
            for _ in 0..tries {
                if !matches!(child.try_wait(), Ok(None)) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            false
        };
        // SIGTERM lets dnsmasq write its lease file before it exits.
        let asked = kill(pid, Signal::SIGTERM);
        if gone(&mut child, 20) {
            return Ok(());
        }
        let forced = kill(pid, Signal::SIGKILL);
        if gone(&mut child, 40) {
            return Ok(());
        }
        let why = match (asked, forced) {
            (Err(e), _) | (_, Err(e)) => format!(
                "the daemon may not signal it ({e}); it needs the CAP_KILL capability, which dist/oxd.service grants"
            ),
            _ => "it did not exit".to_string(),
        };
        // Still ours to watch: the next attempt tries again.
        self.child = Some(child);
        Err(format!("dnsmasq could not be stopped: {why}"))
    }

    fn spawn(&mut self) -> Result<(), String> {
        let log = fs::File::create(self.path("dnsmasq.log")).map_err(|e| e.to_string())?;
        let mut cmd = Command::new(&self.program);
        // --no-daemon also skips the switch to an unprivileged user.
        cmd.arg(if self.keep_privileges {
            "--no-daemon"
        } else {
            "--keep-in-foreground"
        })
        .arg(format!(
            "--conf-file={}",
            self.path("dnsmasq.conf").display()
        ))
        .arg(format!("--dhcp-leasefile={}", self.lease_file().display()))
        // The daemon writes the pid file itself, below. dnsmasq would hand
        // its own to the dnsmasq user, which needs the right to change file
        // owners, and the daemon runs without it.
        .arg("--pid-file=")
        .arg("--log-facility=-")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log);
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("'{}' could not be started: {e}", self.program))?;
        // A dnsmasq that cannot bind its ports exits at once. Give it a moment.
        std::thread::sleep(Duration::from_millis(300));
        if let Ok(Some(status)) = child.try_wait() {
            let mut tail = String::new();
            if let Ok(mut f) = fs::File::open(self.path("dnsmasq.log")) {
                let _ = f.read_to_string(&mut tail);
            }
            let last = tail
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("no output");
            return Err(format!(
                "dnsmasq stopped right after starting ({status}): {last}"
            ));
        }
        let _ = fs::write(self.path("dnsmasq.pid"), child.id().to_string());
        self.child = Some(child);
        Ok(())
    }

    /// Makes the running dnsmasq match `conf`. `None` means it should not run.
    pub fn apply(&mut self, conf: Option<&String>) -> Result<(), String> {
        if conf == self.conf.as_ref() && (conf.is_none() || self.alive()) {
            return Ok(());
        }
        self.stop()?;
        self.conf = None;
        let Some(text) = conf else {
            let _ = fs::remove_file(self.path("dnsmasq.conf"));
            return Ok(());
        };
        fs::create_dir_all(&self.dir).map_err(|e| format!("{}: {e}", self.dir.display()))?;
        let tmp = self.path("dnsmasq.conf.tmp");
        fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
        fs::rename(&tmp, self.path("dnsmasq.conf")).map_err(|e| e.to_string())?;
        self.spawn()?;
        self.conf = Some(text.clone());
        Ok(())
    }

    /// Starts dnsmasq again if it should be running and is not.
    pub fn tick(&mut self) {
        if self.conf.is_some() && !self.alive() {
            self.child = None;
            match self.spawn() {
                Ok(()) => eprintln!("oxd: dnsmasq had stopped and was started again"),
                Err(e) => eprintln!("oxd: dnsmasq is down: {e}"),
            }
        }
    }

    pub fn state(&mut self) -> Option<String> {
        self.conf.as_ref()?;
        Some(if self.alive() {
            "running".to_string()
        } else {
            "stopped; the daemon is trying to start it".to_string()
        })
    }
}

impl Drop for Dnsmasq {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

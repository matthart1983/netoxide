//! `ox`: the Netoxide command line tool.
//!
//! Most commands talk to `oxd` over its Unix socket. The commands under
//! `ox file` work on config files alone and need no daemon.

use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    process::ExitCode,
};

use clap::{Parser, Subcommand, ValueEnum};
use ox_client::Client;
use ox_explain::{Packet, explain};
use ox_nft::{L4, Ruleset, compile, render};
use ox_schema::Config;
use serde_json::{Value, json};

#[derive(Parser)]
#[command(name = "ox", version, about = "Netoxide command line tool")]
struct Cli {
    /// The daemon's Unix socket
    #[arg(
        long,
        global = true,
        env = "OX_SOCKET",
        default_value = "/run/netoxide/oxd.sock"
    )]
    socket: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// What the box is running, and whether a commit is waiting for confirmation
    Status,
    /// Print the running config
    Running,
    /// Save, list, show or delete candidate configs
    #[command(subcommand)]
    Candidate(CandidateCmd),
    /// Show what a candidate would change, without applying it
    Plan {
        candidate: String,
        /// JSON Lines file of observed flows; reports those whose verdict changes
        #[arg(long)]
        flows: Option<PathBuf>,
    },
    /// Apply a candidate
    Commit {
        candidate: String,
        /// Revert unless confirmed within this time, such as 5m or 90s
        #[arg(long, value_parser = parse_window)]
        confirm: Option<u64>,
        /// Why, such as a change ticket. Recorded with the commit
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// Keep the commit that is waiting for confirmation
    Confirm,
    /// Undo the commit that is waiting for confirmation, now
    Revert,
    /// Go back to the config from N commits ago, as a new commit
    Rollback {
        #[arg(default_value_t = 1)]
        steps: u64,
        #[arg(long, value_parser = parse_window)]
        confirm: Option<u64>,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// List commits, newest first
    History,
    /// Show one commit and its config
    Show { id: u64 },
    /// Say what happens to one packet under the running config
    Explain {
        #[command(flatten)]
        packet: PacketArgs,
        /// Also evaluate against this candidate and show both verdicts
        #[arg(long)]
        candidate: Option<String>,
    },
    /// Print the audit log and check its hash chain
    Audit,
    /// Print the Netoxide table as the kernel holds it
    Kernel,
    /// Translate a pfSense config.xml backup into a Netoxide config and a report
    Import {
        backup: PathBuf,
        /// Write the translated config here
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// JSON Lines file of flows to replay through both rulesets.
        /// Without it, generated probes for every translated rule are replayed
        #[arg(long)]
        verify: Option<PathBuf>,
    },
    /// Print the JSON Schema of the config format
    Schema,
    /// Work on config files, without the daemon
    #[command(subcommand)]
    File(FileCmd),
}

#[derive(Subcommand)]
enum CandidateCmd {
    /// Validate a config file and store it as a candidate
    Save { name: String, file: PathBuf },
    /// List candidate names
    List,
    /// Print a candidate's config
    Show { name: String },
    /// Delete a candidate
    Rm { name: String },
}

#[derive(Subcommand)]
enum FileCmd {
    /// Check a config file and report every problem found
    Validate { config: PathBuf },
    /// Print the nftables ruleset a config compiles to, as libnftables JSON
    Compile {
        config: PathBuf,
        /// Print counts instead of the ruleset
        #[arg(long)]
        stats: bool,
    },
    /// List what a candidate file changes
    Diff {
        running: PathBuf,
        candidate: PathBuf,
    },
    /// Validate and compile a candidate file, list its changes, and replay flows
    Plan {
        running: PathBuf,
        candidate: PathBuf,
        /// JSON Lines file of observed flows
        #[arg(long)]
        flows: Option<PathBuf>,
    },
    /// Say what happens to one packet under a config file
    Explain {
        config: PathBuf,
        #[command(flatten)]
        packet: PacketArgs,
        /// Also evaluate against this candidate file
        #[arg(long)]
        candidate: Option<PathBuf>,
    },
}

#[derive(clap::Args)]
struct PacketArgs {
    #[arg(long)]
    src: IpAddr,
    #[arg(long)]
    dst: IpAddr,
    #[arg(long, value_enum)]
    proto: Proto,
    /// Destination port, for tcp and udp
    #[arg(long)]
    dport: Option<u16>,
    /// Interface the packet arrives on
    #[arg(long = "in")]
    iif: String,
}

#[derive(Clone, Copy, ValueEnum)]
enum Proto {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

impl Proto {
    fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Icmp => "icmp",
            Proto::Icmpv6 => "icmpv6",
        }
    }
}

impl From<Proto> for L4 {
    fn from(p: Proto) -> L4 {
        match p {
            Proto::Tcp => L4::Tcp,
            Proto::Udp => L4::Udp,
            Proto::Icmp => L4::Icmp,
            Proto::Icmpv6 => L4::Icmpv6,
        }
    }
}

/// Parses a confirm window: `90`, `90s` or `5m`, as seconds.
fn parse_window(s: &str) -> std::result::Result<u64, String> {
    let (digits, scale) = match s.strip_suffix('m') {
        Some(d) => (d, 60),
        None => (s.strip_suffix('s').unwrap_or(s), 1),
    };
    digits
        .parse::<u64>()
        .map(|n| n * scale)
        .map_err(|_| format!("'{s}' is not a time; write 5m or 90s"))
}

/// `println!` that ignores a closed pipe, so `ox history | head` ends quietly.
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), $($arg)*);
    }};
}

/// `print!` with the same behaviour.
macro_rules! outp {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = write!(std::io::stdout(), $($arg)*);
    }};
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn load(path: &Path) -> Result<(Config, Ruleset)> {
    let config = Config::load(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let ruleset = compile(&config).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((config, ruleset))
}

fn read(path: &Path) -> Result<String> {
    Ok(std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?)
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// `2026-11-14 10:52:03 UTC` from Unix seconds, without a date library.
fn when(secs: u64) -> String {
    let days = secs / 86_400;
    let (h, m, s) = ((secs % 86_400) / 3600, (secs % 3600) / 60, secs % 60);
    // Civil-from-days, after Howard Hinnant.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {h:02}:{m:02}:{s:02} UTC")
}

/// One line for a commit, with its state in words.
fn commit_line(c: &Value) -> String {
    let state = match text(&c["state"]) {
        "pending" => format!(
            "unconfirmed, reverts at {}",
            when(c["deadline"].as_u64().unwrap_or(0))
        ),
        "confirmed" => "confirmed".to_string(),
        "reverted" if c["auto"] == true => "reverted, not confirmed in time".to_string(),
        "reverted" => "reverted".to_string(),
        other => other.to_string(),
    };
    let reason = text(&c["reason"]);
    format!(
        "#{} {}  {}  {}  {state}{}",
        c["id"],
        when(c["time"].as_u64().unwrap_or(0)),
        text(&c["author"]),
        text(&c["source"]),
        if reason.is_empty() {
            String::new()
        } else {
            format!("  · {reason}")
        }
    )
}

fn print_plan(summary: &str, changes: &[String], flows: Option<(usize, &[String])>) {
    out!("✓ schema validation passed");
    out!("✓ compiled {summary}");
    out!("✓ one nftables transaction, atomic swap");
    out!("\n{} change(s)", changes.len());
    for c in changes {
        out!("  {c}");
    }
    if let Some((checked, hits)) = flows {
        out!(
            "\n{} of {checked} replayed flows get a different verdict",
            hits.len()
        );
        for h in hits {
            out!("  {h}");
        }
    }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .into_iter()
        .flatten()
        .map(|s| text(s).to_string())
        .collect()
}

fn daemon(cli: &Cli) -> Result<()> {
    let oxd = Client::new(&cli.socket);
    match &cli.command {
        Command::Status => {
            let s = oxd.json("GET", "/v1/status", None)?;
            match &s["running"] {
                Value::Null => out!("running     no commit yet; nothing is loaded"),
                c => out!("running     {}", commit_line(c)),
            }
            if let Some(left) = s["reverts_in"].as_u64() {
                out!("pending     reverts in {left} s unless you run `ox confirm`");
            }
            let names = strings(&s["candidates"]);
            out!(
                "candidates  {}",
                if names.is_empty() {
                    "none".into()
                } else {
                    names.join(", ")
                }
            );
            out!("applier     {}", text(&s["applier"]));
        }
        Command::Running => outp!("{}", oxd.get("/v1/running")?),
        Command::Candidate(cmd) => match cmd {
            CandidateCmd::Save { name, file } => {
                oxd.send(
                    "PUT",
                    &format!("/v1/candidates/{name}"),
                    Some(("text/plain", &read(file)?)),
                )?;
                out!("saved candidate {name}");
            }
            CandidateCmd::List => {
                for n in strings(&oxd.json("GET", "/v1/candidates", None)?) {
                    out!("{n}");
                }
            }
            CandidateCmd::Show { name } => {
                outp!("{}", oxd.get(&format!("/v1/candidates/{name}"))?);
            }
            CandidateCmd::Rm { name } => {
                oxd.send("DELETE", &format!("/v1/candidates/{name}"), None)?;
                out!("deleted candidate {name}");
            }
        },
        Command::Plan { candidate, flows } => {
            let body = flows.as_deref().map(read).transpose()?.unwrap_or_default();
            let p: Value = serde_json::from_str(&oxd.send(
                "POST",
                &format!("/v1/candidates/{candidate}/plan"),
                Some(("application/x-ndjson", &body)),
            )?)?;
            let impact = strings(&p["impact"]);
            let changes = if p["first_commit"] == true {
                vec!["first commit: there is no running config to compare with".to_string()]
            } else {
                strings(&p["changes"])
            };
            print_plan(
                text(&p["summary"]),
                &changes,
                p["flows_checked"]
                    .as_u64()
                    .map(|n| (n as usize, impact.as_slice())),
            );
        }
        Command::Commit {
            candidate,
            confirm,
            reason,
        } => {
            let c = oxd.json(
                "POST",
                &format!("/v1/candidates/{candidate}/commit"),
                Some(&json!({ "confirm_secs": confirm, "reason": reason })),
            )?;
            out!("applied {}", commit_line(&c));
            if let Some(secs) = confirm {
                out!("run `ox confirm` within {secs} s to keep it, or `ox revert` to undo it now");
            }
        }
        Command::Confirm => {
            out!(
                "kept {}",
                commit_line(&oxd.json("POST", "/v1/confirm", None)?)
            );
        }
        Command::Revert => {
            let c = oxd.json("POST", "/v1/revert", None)?;
            out!("undone {}", commit_line(&c));
            match c["parent"].as_u64() {
                Some(p) => out!("running #{p} again; the candidate is kept"),
                None => out!("no config is loaded; the candidate is kept"),
            }
        }
        Command::Rollback {
            steps,
            confirm,
            reason,
        } => {
            let c = oxd.json(
                "POST",
                "/v1/rollback",
                Some(&json!({ "steps": steps, "confirm_secs": confirm, "reason": reason })),
            )?;
            out!("applied {}", commit_line(&c));
        }
        Command::History => {
            let commits = oxd.json("GET", "/v1/commits", None)?;
            for c in commits.as_array().into_iter().flatten() {
                out!("{}", commit_line(c));
            }
        }
        Command::Show { id } => {
            let v = oxd.json("GET", &format!("/v1/commits/{id}"), None)?;
            out!("{}", commit_line(&v["commit"]));
            out!("sha256 {}\n", text(&v["commit"]["sha256"]));
            outp!("{}", text(&v["config"]));
        }
        Command::Explain { packet, candidate } => {
            let v = oxd.json(
                "POST",
                "/v1/explain",
                Some(&json!({
                    "src": packet.src, "dst": packet.dst, "proto": packet.proto.as_str(),
                    "dport": packet.dport, "in": packet.iif, "candidate": candidate,
                })),
            )?;
            out!("{}", text(&v["packet"]));
            match (&v["running"], &v["candidate"]) {
                (Value::Null, Value::Null) => {
                    out!("\nthere is no commit yet, so nothing decides this packet");
                }
                (r, Value::Null) => outp!("\n{}", text(&r["text"])),
                (r, c) => {
                    if !r.is_null() {
                        outp!("\nrunning\n{}", text(&r["text"]));
                    }
                    outp!(
                        "\ncandidate {}\n{}",
                        candidate.as_deref().unwrap_or(""),
                        text(&c["text"])
                    );
                    if !r.is_null() && r["verdict"] != c["verdict"] {
                        out!(
                            "\nthe candidate changes this packet: {} → {}",
                            text(&r["verdict"]),
                            text(&c["verdict"])
                        );
                    }
                }
            }
        }
        Command::Audit => {
            let v = oxd.json("GET", "/v1/audit", None)?;
            let entries = v["entries"].as_array().cloned().unwrap_or_default();
            for e in &entries {
                let hash = text(&e["hash"]);
                out!(
                    "{:>4}  {}  {:<10} {:<18} {}  {}…",
                    e["seq"],
                    when(e["time"].as_u64().unwrap_or(0)),
                    text(&e["who"]),
                    text(&e["event"]),
                    text(&e["detail"]),
                    &hash[..hash.len().min(12)],
                );
            }
            out!("\nchain verified: {} entries", entries.len());
        }
        Command::Kernel => {
            let dump = oxd.json("GET", "/v1/kernel", None)?;
            out!("{}", serde_json::to_string_pretty(&dump)?);
        }
        Command::Schema | Command::File(_) | Command::Import { .. } => {
            unreachable!("handled before the daemon is contacted")
        }
    }
    Ok(())
}

fn file(cmd: &FileCmd) -> Result<()> {
    match cmd {
        FileCmd::Validate { config } => {
            let (c, rs) = load(config)?;
            out!("{}: valid, schema {}", config.display(), c.schema);
            out!("{}", rs.summary());
        }
        FileCmd::Compile { config, stats } => {
            let (_, rs) = load(config)?;
            if *stats {
                out!("{}", rs.summary());
            } else {
                out!("{}", serde_json::to_string_pretty(&render(&rs).0)?);
            }
        }
        FileCmd::Diff { running, candidate } => {
            let ((old, _), (new, _)) = (load(running)?, load(candidate)?);
            let changes = ox_plan::diff(&old, &new);
            if changes.is_empty() {
                out!("no changes");
            }
            for c in changes {
                out!("{c}");
            }
        }
        FileCmd::Plan {
            running,
            candidate,
            flows,
        } => {
            let ((old, old_rs), (new, new_rs)) = (load(running)?, load(candidate)?);
            let changes: Vec<String> = ox_plan::diff(&old, &new)
                .iter()
                .map(ToString::to_string)
                .collect();
            let hits = match flows {
                None => None,
                Some(path) => {
                    let flows = ox_plan::parse_flows(&read(path)?)?;
                    let hits: Vec<String> = ox_plan::impact(&old_rs, &new_rs, &flows)?
                        .iter()
                        .map(ToString::to_string)
                        .collect();
                    Some((flows.len(), hits))
                }
            };
            print_plan(
                &new_rs.summary(),
                &changes,
                hits.as_ref().map(|(n, h)| (*n, h.as_slice())),
            );
        }
        FileCmd::Explain {
            config,
            packet,
            candidate,
        } => {
            let packet = Packet {
                src: packet.src,
                dst: packet.dst,
                l4: packet.proto.into(),
                dport: packet.dport,
                iif: packet.iif.clone(),
            };
            let (_, rs) = load(config)?;
            let running = explain(&rs, &packet)?;
            out!("{packet}");
            match candidate {
                None => outp!("\n{running}"),
                Some(path) => {
                    let (_, cand_rs) = load(path)?;
                    let cand = explain(&cand_rs, &packet)?;
                    outp!("\nrunning ({})\n{running}", config.display());
                    outp!("\ncandidate ({})\n{cand}", path.display());
                    if running.verdict != cand.verdict {
                        out!(
                            "\nthe candidate changes this packet: {} → {}",
                            running.verdict.as_str(),
                            cand.verdict.as_str()
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn import(backup: &Path, out: Option<&Path>, verify: Option<&Path>) -> Result<()> {
    let imported = ox_import::import_pfsense(&read(backup)?)
        .map_err(|e| format!("{}: {e}", backup.display()))?;
    outp!("{}", imported.report);

    let (packets, what) = match verify {
        Some(path) => {
            let flows = ox_plan::parse_flows(&read(path)?)?;
            (
                flows.iter().map(|(_, f)| f.packet()).collect::<Vec<_>>(),
                "replayed flows",
            )
        }
        None => (imported.probes(), "generated probes"),
    };
    let diffs = imported.verify(&packets);
    out!(
        "\nverify: {} of {} {what} get a different verdict",
        diffs.len(),
        packets.len()
    );
    for d in &diffs {
        out!("  {d}");
    }

    match out {
        Some(path) => {
            std::fs::write(path, imported.config.to_toml())
                .map_err(|e| format!("{}: {e}", path.display()))?;
            out!("\nwrote {}", path.display());
        }
        None => out!("\nno config written; pass --out <file> to keep it"),
    }
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Schema => serde_json::to_string_pretty(&Config::json_schema())
            .map(|s| out!("{s}"))
            .map_err(Into::into),
        Command::File(cmd) => file(cmd),
        Command::Import {
            backup,
            out,
            verify,
        } => import(backup, out.as_deref(), verify.as_deref()),
        _ => daemon(&cli),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ox: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_parse() {
        assert_eq!(parse_window("5m"), Ok(300));
        assert_eq!(parse_window("90s"), Ok(90));
        assert_eq!(parse_window("45"), Ok(45));
        assert!(parse_window("soon").is_err());
    }

    #[test]
    fn unix_time_formats_as_utc() {
        assert_eq!(when(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(when(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(when(1_794_653_523), "2026-11-14 10:52:03 UTC");
    }
}

//! `ox`: the Netoxide command line tool.
//!
//! Most commands talk to `oxd`: over its Unix socket on the box, or over
//! HTTPS from another machine with `--remote`. The commands under `ox file`
//! work on config files alone and need no daemon.

/// Text made safe to print. What `ox` prints mostly comes from a daemon,
/// which with `--remote` is another machine: its control characters could
/// rewrite the terminal, so only line breaks and tabs get through.
pub(crate) fn plain(text: String) -> String {
    text.chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .collect()
}

/// `println!` that ignores a closed pipe, so `ox history | head` ends quietly.
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout(), "{}", $crate::plain(format!($($arg)*)));
    }};
}

/// `print!` with the same behaviour.
macro_rules! outp {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = write!(std::io::stdout(), "{}", $crate::plain(format!($($arg)*)));
    }};
}

mod easy;
mod remote;

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
#[command(
    name = "ox",
    version,
    about = "Netoxide command line tool",
    after_help = "These are the everyday commands. A change you make is saved, shown to you, and\napplied with `ox apply`. Run `ox more` for every command, including candidates,\nrollback, the audit log, tokens and roles."
)]
struct Cli {
    /// The daemon's Unix socket
    #[arg(
        long,
        global = true,
        env = "OX_SOCKET",
        default_value = "/run/netoxide/oxd.sock"
    )]
    socket: PathBuf,
    /// A box on the network, by the name it was saved under with `ox remote add`
    #[arg(
        long,
        short,
        global = true,
        env = "OX_REMOTE",
        conflicts_with = "socket"
    )]
    remote: Option<String>,
    #[command(subcommand)]
    command: Command,
}

impl Cli {
    /// The daemon to talk to: a saved box, a box named by the environment,
    /// or the one on this machine.
    fn client(&self) -> Result<Client> {
        if let Some(name) = &self.remote {
            let file = ox_client::remotes::path()?;
            return Ok(Client::https(ox_client::remotes::find(&file, name)?));
        }
        // For scripts and CI, where there is no file to keep a box in.
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        if let Some(url) = var("OX_URL") {
            let token = var("OX_TOKEN")
                .ok_or("OX_URL is set, so OX_TOKEN must hold an access token for that box")?;
            return Ok(Client::https(ox_client::remotes::remote(
                &url,
                var("OX_FINGERPRINT").as_deref(),
                &token,
            )?));
        }
        Ok(Client::new(&self.socket))
    }
}

#[derive(Subcommand)]
enum Command {
    /// The networks, and who can reach what
    #[command(display_order = 3)]
    Access {
        #[command(subcommand)]
        action: Option<AccessCmd>,
    },
    /// Add a network of its own, such as one for guests or cameras
    #[command(display_order = 4)]
    Network {
        #[command(subcommand)]
        action: NetworkCmd,
    },
    /// Apply a waiting change safely; it undoes itself unless you keep it
    #[command(display_order = 7)]
    Apply {
        /// The change to apply. Not needed when only one is waiting
        change: Option<String>,
    },
    /// Keep the change you just applied
    #[command(display_order = 8)]
    Keep,
    /// Undo the change you just applied, now
    #[command(display_order = 9)]
    Undo,
    /// List every command, including the advanced ones
    #[command(display_order = 13)]
    More,
    /// What the box is running, and whether a change is waiting to be kept
    #[command(display_order = 2)]
    Status,
    /// Print the running config
    #[command(hide = true)]
    Running,
    /// Save, list, show or delete candidate configs
    #[command(subcommand)]
    #[command(hide = true)]
    Candidate(CandidateCmd),
    /// Show what a candidate would change, without applying it
    #[command(hide = true)]
    Plan {
        candidate: String,
        /// JSON Lines file of observed flows; reports those whose verdict changes
        #[arg(long)]
        flows: Option<PathBuf>,
    },
    /// Apply a candidate
    #[command(hide = true)]
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
    #[command(hide = true)]
    Confirm,
    /// Undo the commit that is waiting for confirmation, now
    #[command(hide = true)]
    Revert,
    /// Go back to the config from N commits ago, as a new commit
    #[command(hide = true)]
    Rollback {
        #[arg(default_value_t = 1)]
        steps: u64,
        #[arg(long, value_parser = parse_window)]
        confirm: Option<u64>,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// List commits, newest first
    #[command(hide = true)]
    History,
    /// Show one commit and its config
    #[command(hide = true)]
    Show { id: u64 },
    /// Say what the box does with one connection, and why
    #[command(display_order = 10)]
    Explain {
        #[command(flatten)]
        packet: PacketArgs,
        /// Also evaluate against this candidate and show both verdicts
        #[arg(long)]
        candidate: Option<String>,
    },
    /// Print the audit log and check its hash chain
    #[command(hide = true)]
    Audit,
    /// List rules that never apply, add nothing, allow everything or see no traffic
    #[command(hide = true)]
    Hygiene,
    /// List the addresses DHCP has handed out
    #[command(hide = true)]
    Leases,
    /// The VPN: add a phone or laptop, and see who is connected
    #[command(display_order = 6)]
    Vpn {
        /// Print only the box's public key for this tunnel, making the key
        /// if there is none. Use it to swap keys before a first commit
        #[arg(long, value_name = "INTERFACE")]
        key: Option<String>,
        #[command(subcommand)]
        action: Option<VpnCmd>,
    },
    /// Approve a candidate someone else saved (four-eyes)
    #[command(hide = true)]
    Approve { candidate: String },
    /// Require a second person's approval before a commit: on or off
    #[command(hide = true)]
    FourEyes {
        #[arg(value_parser = ["on", "off"])]
        state: String,
    },
    /// Access tokens for the HTTPS API and the web UI
    #[command(subcommand)]
    #[command(hide = true)]
    Token(TokenCmd),
    /// Roles: what a token may do, and in which parts of the config
    #[command(subcommand)]
    #[command(hide = true)]
    Role(RoleCmd),
    /// Boxes on the network that `ox --remote <name>` can manage from here
    #[command(subcommand)]
    #[command(hide = true)]
    Remote(RemoteCmd),
    /// Save the config, VPN keys, roles and settings to a file
    #[command(display_order = 11)]
    Backup {
        /// Where to write it. The file is readable by you only
        #[arg(long, short)]
        out: PathBuf,
    },
    /// Bring a backup back, as a change for you to apply
    #[command(display_order = 12)]
    Restore { file: PathBuf },
    /// Show who the daemon thinks you are
    #[command(hide = true)]
    Whoami,
    /// Print the Netoxide table as the kernel holds it
    #[command(hide = true)]
    Kernel,
    /// Guided setup: pick the internet port and your own, get a working config
    #[command(display_order = 1)]
    Init {
        /// The port that faces the internet
        #[arg(long)]
        wan: Option<String>,
        /// A port that faces the inside network, optionally with the box's
        /// address on it: eth1 or eth1=192.168.10.1/24. Repeat for more ports
        #[arg(long)]
        lan: Vec<String>,
        #[arg(long)]
        hostname: Option<String>,
        /// Write the config to this file
        #[arg(long, short)]
        out: Option<PathBuf>,
        /// Store the config in the daemon as a candidate with this name
        #[arg(long)]
        save: Option<String>,
        /// Do not hand out addresses or answer DNS for the inside network
        #[arg(long)]
        no_services: bool,
        /// Resolvers to forward DNS to (default 1.1.1.1 and 9.9.9.9). Repeat for more
        #[arg(long)]
        dns_upstream: Vec<IpAddr>,
        /// The provider assigns the address on the internet port (DHCP)
        #[arg(long, conflicts_with = "gateway")]
        wan_dhcp: bool,
        /// The provider's router, for an internet port with a fixed address.
        /// Repeat to give one for IPv4 and one for IPv6
        #[arg(long)]
        gateway: Vec<IpAddr>,
    },
    /// Let a port in from the internet to a device inside
    #[command(display_order = 4)]
    Forward {
        /// What this is for, such as "Home Assistant"
        #[arg(long)]
        name: String,
        /// The outside port, such as tcp/443
        #[arg(long)]
        port: String,
        /// The inside host, with its port if different: 192.168.10.20:8123
        #[arg(long)]
        to: String,
        /// The outside address, when the box has more than one
        #[arg(long)]
        address: Option<IpAddr>,
    },
    /// Block everything a device inside sends
    #[command(display_order = 5)]
    Block {
        /// The device's address, or a network
        address: String,
        /// What the device is, such as "Smart TV"
        #[arg(long)]
        name: Option<String>,
    },
    /// Translate a pfSense config.xml backup into a Netoxide config and a report
    #[command(hide = true)]
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
    #[command(hide = true)]
    Schema,
    /// Work on config files, without the daemon
    #[command(subcommand)]
    #[command(hide = true)]
    File(FileCmd),
}

#[derive(Subcommand)]
enum VpnCmd {
    /// Add a phone or laptop to the VPN, setting the VPN up if there is
    /// none. Saved as a candidate; prints the config file for the device
    Add {
        /// What the device is, such as laptop
        name: String,
        /// How the device finds the box from outside: a name such as
        /// home.example.net, or an address
        #[arg(long)]
        endpoint: String,
        /// The device's own public key. Without it a key pair is made for
        /// the device and its private key is printed once
        #[arg(long)]
        public_key: Option<String>,
        /// Also draw the config as a QR code, for a phone to scan
        #[arg(long)]
        qr: bool,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Create a token. Its secret is printed once and cannot be shown again
    Create {
        name: String,
        /// A role from `ox role list`, such as viewer, operator or admin
        #[arg(long)]
        role: String,
        /// Stop working after this many days
        #[arg(long)]
        days: Option<u64>,
    },
    /// List tokens
    List,
    /// Revoke a token
    Revoke { name: String },
}

#[derive(Subcommand)]
enum NetworkCmd {
    /// Add a network as a VLAN on an inside port. Devices on it get an
    /// address and DNS from the box, and reach nothing else until allowed
    Add {
        /// What to call it, such as "Guest Wi-Fi"
        name: String,
        /// The inside port that carries it, such as eth1
        #[arg(long)]
        port: String,
        /// Its VLAN number on that port. The switch or access point must
        /// use the same number for this network
        #[arg(long)]
        vlan: u16,
        /// The box's address on it, such as 192.168.20.1/24. Left out, a
        /// free one is chosen
        #[arg(long)]
        address: Option<String>,
        /// Do not let it reach the internet
        #[arg(long)]
        no_internet: bool,
    },
}

#[derive(Subcommand)]
enum AccessCmd {
    /// Let one network reach another
    Allow { from: String, to: String },
    /// Stop one network reaching another
    Block { from: String, to: String },
}

#[derive(Subcommand)]
enum RoleCmd {
    /// List the roles, with what each may do
    List,
    /// Make a role. Every role can read the config and status
    Create {
        name: String,
        /// What the role may do besides reading: read-audit, edit, approve,
        /// commit, rollback, manage. Separate with commas
        #[arg(long, value_delimiter = ',', required = true)]
        can: Vec<String>,
        /// Hold the role to changes in these parts of the config: firewall,
        /// network, services, vpn. Separate with commas. Without this, any part
        #[arg(long, value_delimiter = ',')]
        sections: Option<Vec<String>>,
    },
    /// Delete a role made on this box
    Delete { name: String },
}

#[derive(Subcommand)]
enum RemoteCmd {
    /// Save a box, after checking its certificate and your access token
    Add {
        /// What to call the box here
        name: String,
        /// Where its HTTPS listener is, such as https://192.0.2.1:8443
        url: String,
        /// The certificate fingerprint from `ox status` on the box. Without
        /// this, the fingerprint is shown and you are asked whether it matches
        #[arg(long)]
        fingerprint: Option<String>,
        /// A file holding the access token. Without this, the token is read
        /// from OX_TOKEN or asked for
        #[arg(long)]
        token_file: Option<PathBuf>,
    },
    /// List the saved boxes
    List,
    /// Forget a saved box
    Remove { name: String },
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
    /// List rules in a config file that never apply, add nothing or allow everything
    Hygiene { config: PathBuf },
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
    /// Interface the packet arrives on. Left out, the box works it out
    /// from the source address
    #[arg(long = "in")]
    iif: Option<String>,
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
/// A length of time in the largest unit that fits.
fn span(secs: u64) -> String {
    match secs {
        s if s >= 172_800 => format!("{} days", s / 86_400),
        s if s >= 7200 => format!("{} hours", s / 3600),
        s if s >= 120 => format!("{} minutes", s / 60),
        s => format!("{s} seconds"),
    }
}

/// A byte count in the largest unit that fits.
fn bytes(n: u64) -> String {
    match n {
        n if n >= 1 << 30 => format!("{:.1} GiB", n as f64 / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:.1} MiB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.1} KiB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}

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
    let oxd = cli.client()?;
    match &cli.command {
        Command::Status => {
            let s = oxd.json("GET", "/v1/status", None)?;
            match &s["running"] {
                Value::Null if s["lockdown"] == true => out!(
                    "running     no commit yet; inbound and forwarded traffic is dropped until the first one"
                ),
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
            if s["four_eyes"] == true {
                out!("four-eyes   on: a commit needs approval from someone other than its author");
            }
            for svc in s["services"].as_array().into_iter().flatten() {
                out!("service     {} {}", text(&svc[0]), text(&svc[1]));
            }
            if let Some(code) = s["setup_code"].as_str() {
                out!("setup       code {code}");
                out!(
                    "            open the box's web interface from the inside network and enter it, or run `ox init` here"
                );
            }
            if s["https"].is_object() {
                out!("https       {}", text(&s["https"]["listen"]));
                out!(
                    "            certificate {}",
                    text(&s["https"]["fingerprint"])
                );
            }
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
        Command::Access { action: None } => {
            let home = oxd.json("GET", "/v1/home", None)?;
            let names: Vec<String> = home["networks"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|n| text(&n["name"]).to_string())
                .collect();
            let wide = names
                .iter()
                .map(|n| n.chars().count())
                .max()
                .unwrap_or(8)
                .max(12)
                + 2;
            outp!("{:<wide$}", "from \\ to");
            for n in &names {
                outp!("{n:<wide$}");
            }
            out!("");
            for (i, from) in names.iter().enumerate() {
                outp!("{from:<wide$}");
                for j in 0..names.len() {
                    let cell = &home["cells"][i][j];
                    let word = match text(&cell["state"]) {
                        "allowed" => "Allowed".to_string(),
                        "blocked" => "Blocked".to_string(),
                        "same" => "-".to_string(),
                        _ => format!("Custom: {}", text(&cell["summary"])),
                    };
                    outp!("{word:<wide$}");
                }
                out!("");
            }
            out!("");
            for n in home["networks"].as_array().into_iter().flatten() {
                out!(
                    "{:<wide$}zone {}  {}",
                    text(&n["name"]),
                    text(&n["zone"]),
                    strings(&n["interfaces"]).join(", ")
                );
            }
            let let_in = home["let_in"].as_array().cloned().unwrap_or_default();
            if let_in.is_empty() {
                out!("\nNothing is let in from the internet.");
            } else {
                out!("\nLet in from the internet:");
                for f in &let_in {
                    out!(
                        "  {}: {} goes to {}",
                        text(&f["name"]),
                        text(&f["service"]),
                        text(&f["to"])
                    );
                }
            }
            out!(
                "\nChange it with: ox access allow <from> <to>   or   ox access block <from> <to>"
            );
            out!(
                "Use the zone names. A Custom pair has rules of its own; edit those in the config."
            );
        }
        Command::Access {
            action: Some(action),
        } => {
            let (from, to, allow) = match action {
                AccessCmd::Allow { from, to } => (from, to, true),
                AccessCmd::Block { from, to } => (from, to, false),
            };
            let v = oxd.json(
                "POST",
                "/v1/actions/access",
                Some(&json!({ "from": from, "to": to, "allow": allow })),
            )?;
            for line in strings(&v["done"]) {
                out!("{line}");
            }
            out!(
                "\nNothing is applied yet. Apply it with: ox apply {}",
                text(&v["candidate"])
            );
        }
        Command::Network {
            action:
                NetworkCmd::Add {
                    name,
                    port,
                    vlan,
                    address,
                    no_internet,
                },
        } => {
            let v = oxd.json(
                "POST",
                "/v1/actions/network",
                Some(&json!({
                    "name": name, "port": port, "vlan": vlan,
                    "address": address, "internet": !no_internet,
                })),
            )?;
            for line in strings(&v["done"]) {
                out!("{line}");
            }
            out!(
                "\nNothing is applied yet. Apply it with: ox apply {}",
                text(&v["candidate"])
            );
            out!("Set the switch or access point on {port} to use VLAN {vlan} for this network.");
        }
        Command::Apply { change } => {
            let name = match change {
                Some(name) => name.clone(),
                None => {
                    let waiting = strings(&oxd.json("GET", "/v1/status", None)?["candidates"]);
                    match waiting.as_slice() {
                        [one] => one.clone(),
                        [] => return Err("nothing is waiting to be applied".into()),
                        many => {
                            return Err(format!(
                                "{} changes are waiting; say which: {}",
                                many.len(),
                                many.join(", ")
                            )
                            .into());
                        }
                    }
                }
            };
            let plan = oxd.json("POST", &format!("/v1/candidates/{name}/plan"), None)?;
            for line in strings(&plan["headline"]) {
                out!("{line}");
            }
            let c = oxd.json(
                "POST",
                &format!("/v1/candidates/{name}/commit"),
                Some(&json!({ "confirm_secs": 120, "reason": "" })),
            )?;
            out!("applied {}", commit_line(&c));
            out!(
                "Check things still work, then run `ox keep`. If you do nothing, it undoes itself in 2 minutes."
            );
        }
        Command::Keep => {
            oxd.json("POST", "/v1/confirm", None)?;
            out!("kept; the change is now permanent");
        }
        Command::Undo => {
            oxd.json("POST", "/v1/revert", None)?;
            out!("undone; the box is as it was before");
        }
        Command::More => unreachable!("handled before a daemon is chosen"),
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
        Command::Approve { candidate } => {
            let m = oxd.json("POST", &format!("/v1/candidates/{candidate}/approve"), None)?;
            out!(
                "approved {candidate}, saved by {}. It can now be committed.",
                text(&m["author"])
            );
        }
        Command::FourEyes { state } => {
            let on = state == "on";
            oxd.json("PUT", "/v1/settings", Some(&json!({ "four_eyes": on })))?;
            out!(
                "{}",
                if on {
                    "A commit now needs approval from someone other than the candidate's author."
                } else {
                    "Commits no longer need a second person's approval."
                }
            );
        }
        Command::Token(cmd) => match cmd {
            TokenCmd::Create { name, role, days } => {
                let v = oxd.json(
                    "POST",
                    "/v1/tokens",
                    Some(&json!({ "name": name, "role": role, "ttl_secs": days.map(|d| d * 86_400) })),
                )?;
                out!("Token {name} with role {role}. This secret is shown once:\n");
                out!("  {}", text(&v["token"]));
                out!("\nUse it in the web UI, or send it as: Authorization: Bearer <token>");
                out!(
                    "To run ox from another machine: ox remote add <name> https://<this box>:<port>"
                );
            }
            TokenCmd::List => {
                let rows = oxd.json("GET", "/v1/tokens", None)?;
                let rows = rows.as_array().cloned().unwrap_or_default();
                if rows.is_empty() {
                    out!("no tokens");
                }
                for t in &rows {
                    out!(
                        "{:<20} {:<9} created {} by {}  {}",
                        text(&t["name"]),
                        text(&t["role"]),
                        when(t["created"].as_u64().unwrap_or(0)),
                        text(&t["created_by"]),
                        match t["expires"].as_u64() {
                            Some(e) => format!("expires {}", when(e)),
                            None => "does not expire".to_string(),
                        }
                    );
                }
            }
            TokenCmd::Revoke { name } => {
                oxd.send("DELETE", &format!("/v1/tokens/{name}"), None)?;
                out!("revoked token {name}");
            }
        },
        Command::Backup { out } => {
            let doc = oxd.get("/v1/backup")?;
            // Private keys are inside, so the file is never wider than its owner.
            use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};
            let _ = std::fs::remove_file(out);
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(out)
                .map_err(|e| format!("{}: {e}", out.display()))?;
            f.write_all(doc.as_bytes())
                .and_then(|()| f.sync_all())
                .map_err(|e| format!("{}: {e}", out.display()))?;
            let v: Value = serde_json::from_str(&doc)?;
            out!(
                "wrote {}: {}, {} VPN key(s), {} role(s)",
                out.display(),
                if v["config"].is_string() {
                    "the running config"
                } else {
                    "no config"
                },
                v["wireguard_keys"].as_object().map_or(0, |m| m.len()),
                v["roles"].as_array().map_or(0, |a| a.len()),
            );
            out!("It holds the box's private VPN keys. Keep it somewhere only you can read.");
            out!("Access tokens are not in it; make new ones after a restore.");
        }
        Command::Restore { file } => {
            let doc: Value = serde_json::from_str(&read(file)?)
                .map_err(|e| format!("{} is not a backup: {e}", file.display()))?;
            let v = oxd.json("POST", "/v1/restore", Some(&doc))?;
            for line in strings(&v["done"]) {
                out!("{line}");
            }
            match v["candidate"].as_str() {
                Some(name) => out!("\nNothing is applied yet. Apply it with: ox apply {name}"),
                None => out!("\nThe backup held no config, so there is nothing to commit."),
            }
        }
        Command::Whoami => {
            let v = oxd.json("GET", "/v1/whoami", None)?;
            out!("{} ({})", text(&v["name"]), text(&v["role"]));
            out!("may         {}", strings(&v["can"]).join(", "));
            if v["sections"].is_array() {
                out!("changes in  {} only", strings(&v["sections"]).join(", "));
            }
        }
        Command::Role(cmd) => match cmd {
            RoleCmd::List => {
                let rows = oxd.json("GET", "/v1/roles", None)?;
                for r in rows.as_array().into_iter().flatten() {
                    out!(
                        "{:<16} {}{}{}",
                        text(&r["name"]),
                        strings(&r["can"]).join(", "),
                        if r["sections"].is_array() {
                            format!("; changes only in {}", strings(&r["sections"]).join(", "))
                        } else {
                            String::new()
                        },
                        if r["builtin"] == true {
                            ""
                        } else {
                            "  (made here)"
                        },
                    );
                }
            }
            RoleCmd::Create {
                name,
                can,
                sections,
            } => {
                let r = oxd.json(
                    "POST",
                    "/v1/roles",
                    Some(&json!({ "name": name, "can": can, "sections": sections })),
                )?;
                out!("made role {name}: may {}", strings(&r["can"]).join(", "));
                if r["sections"].is_array() {
                    out!("changes only in {}", strings(&r["sections"]).join(", "));
                }
                out!("Give it to someone with: ox token create <name> --role {name}");
            }
            RoleCmd::Delete { name } => {
                oxd.send("DELETE", &format!("/v1/roles/{name}"), None)?;
                out!("deleted role {name}");
            }
        },
        Command::Remote(_) => unreachable!("handled before a daemon is chosen"),
        Command::Hygiene => {
            let rows = oxd.json("GET", "/v1/hygiene", None)?;
            let rows = rows.as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                out!("nothing to report: no rule is shadowed, redundant, wide open or unused");
            }
            for r in &rows {
                out!(
                    "{:<20} {} → {}  {}: {}",
                    text(&r["rule"]),
                    text(&r["from"]),
                    text(&r["to"]),
                    text(&r["kind"]),
                    text(&r["detail"])
                );
            }
        }
        Command::Vpn {
            action:
                Some(VpnCmd::Add {
                    name,
                    endpoint,
                    public_key,
                    qr,
                }),
            ..
        } => {
            let body = json!({ "name": name, "endpoint": endpoint, "public_key": public_key });
            let v = oxd.json("POST", "/v1/actions/vpn-peer", Some(&body))?;
            for line in v["done"].as_array().into_iter().flatten() {
                out!("{}", text(line));
            }
            let candidate = text(&v["candidate"]);
            out!("\nSaved as candidate {candidate}. Nothing is applied yet.");
            out!("Apply it with: ox apply {candidate}\n");
            out!("The config for the device. Import it into the WireGuard app:\n");
            out!("{}", text(&v["client_config"]));
            if *qr {
                match v["qr"].as_array() {
                    Some(_) => {
                        out!(
                            "For a phone, scan this in the WireGuard app (Add a tunnel, Scan from QR code):\n"
                        );
                        outp!("{}", ox_setup::qr_text(&strings(&v["qr"])));
                        out!("\nIf the phone cannot read it, use the config above as a file.");
                    }
                    None => out!(
                        "No QR code: it would need the device's private key, which the box was not given."
                    ),
                }
            }
            if v["key_made_here"] == true {
                out!(
                    "This is the only copy of the device's private key. The box does not keep it."
                );
            }
        }
        Command::Vpn {
            key: Some(iface), ..
        } => {
            let v = oxd.json("GET", &format!("/v1/wireguard/{iface}/key"), None)?;
            out!("{}", text(&v["public_key"]));
        }
        Command::Vpn { key: None, .. } => {
            let tunnels = oxd.json("GET", "/v1/wireguard", None)?;
            let tunnels = tunnels.as_array().cloned().unwrap_or_default();
            if tunnels.is_empty() {
                out!("the running config has no WireGuard tunnel");
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            for t in &tunnels {
                out!(
                    "{}  zone {}  {}",
                    text(&t["name"]),
                    text(&t["zone"]),
                    match t["listen_port"].as_u64() {
                        Some(p) => format!("listens on udp/{p}"),
                        None => "connects out only".to_string(),
                    }
                );
                out!("  this box's public key  {}", text(&t["public_key"]));
                for p in t["peers"].as_array().into_iter().flatten() {
                    let state = match p["last_handshake"].as_i64() {
                        Some(at) if now - at < 180 => "connected".to_string(),
                        Some(at) => {
                            format!("last heard from {} ago", span((now - at).max(0) as u64))
                        }
                        None => "never connected".to_string(),
                    };
                    out!(
                        "  {:<16} {:<28} received {}  sent {}  {}",
                        text(&p["name"]),
                        state,
                        bytes(p["rx_bytes"].as_u64().unwrap_or(0)),
                        bytes(p["tx_bytes"].as_u64().unwrap_or(0)),
                        p["seen_at"]
                            .as_str()
                            .map(|s| format!("from {s}"))
                            .unwrap_or_default()
                    );
                }
            }
        }
        Command::Leases => {
            let rows = oxd.json("GET", "/v1/leases", None)?;
            let rows = rows.as_array().cloned().unwrap_or_default();
            if rows.is_empty() {
                out!("no addresses are handed out right now");
            }
            for r in &rows {
                out!(
                    "{:<16} {}  {:<20} until {}",
                    text(&r["address"]),
                    text(&r["mac"]),
                    r["name"].as_str().unwrap_or("(no name)"),
                    when(r["expires"].as_u64().unwrap_or(0))
                );
            }
        }
        Command::Kernel => {
            let dump = oxd.json("GET", "/v1/kernel", None)?;
            out!("{}", serde_json::to_string_pretty(&dump)?);
        }
        Command::Init { .. } | Command::Forward { .. } | Command::Block { .. } => {
            unreachable!("handled in main")
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
        FileCmd::Hygiene { config } => {
            let (_, rs) = load(config)?;
            let found = ox_nft::hygiene(&rs);
            if found.is_empty() {
                out!("nothing to report: no rule is shadowed, redundant or wide open");
            }
            for f in found {
                out!(
                    "{:<20} {} → {}  {}: {}",
                    f.rule,
                    f.from,
                    f.to,
                    f.kind.as_str(),
                    f.detail
                );
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
                iif: packet.iif.clone().ok_or(
                    "say which interface the packet arrives on with --in; a config file alone cannot tell",
                )?,
                box_addrs: vec![],
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
    let run = || -> Result<()> {
        match &cli.command {
            Command::Schema => serde_json::to_string_pretty(&Config::json_schema())
                .map(|s| out!("{s}"))
                .map_err(Into::into),
            Command::File(cmd) => file(cmd),
            Command::Init {
                wan,
                lan,
                hostname,
                out,
                save,
                no_services,
                dns_upstream,
                wan_dhcp,
                gateway,
            } => easy::init(
                &easy::InitArgs {
                    wan: wan.as_deref(),
                    lan,
                    hostname: hostname.as_deref(),
                    out: out.as_deref(),
                    save: save.as_deref(),
                    no_services: *no_services,
                    dns_upstream,
                    wan_dhcp: *wan_dhcp,
                    gateway,
                },
                &cli.client()?,
            ),
            Command::Forward {
                name,
                port,
                to,
                address,
            } => easy::forward(&cli.client()?, name, port, to, *address),
            Command::Block { address, name } => {
                easy::block(&cli.client()?, address, name.as_deref())
            }
            Command::Remote(cmd) => remote::run(cmd),
            Command::More => {
                use clap::CommandFactory;
                let all = Cli::command();
                let (mut everyday, mut advanced) = (vec![], vec![]);
                for c in all.get_subcommands().filter(|c| c.get_name() != "more") {
                    let about = c.get_about().map(|a| a.to_string()).unwrap_or_default();
                    let line = format!(
                        "  {:<11}{}",
                        c.get_name(),
                        about.lines().next().unwrap_or("")
                    );
                    if c.is_hide_set() {
                        advanced.push(line)
                    } else {
                        everyday.push(line)
                    }
                }
                out!(
                    "Everyday:\n{}\n\nAdvanced:\n{}",
                    everyday.join("\n"),
                    advanced.join("\n")
                );
                out!("\n`ox <command> --help` explains any of them.");
                Ok(())
            }
            Command::Import {
                backup,
                out,
                verify,
            } => import(backup, out.as_deref(), verify.as_deref()),
            _ => daemon(&cli),
        }
    };
    let result = run();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ox: {}", plain(e.to_string()));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_characters_are_not_printed() {
        assert_eq!(plain("a\x1b[2Jb\r\n\tc\x07".into()), "a[2Jb\n\tc");
    }

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

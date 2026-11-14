//! The easy path: `ox init`, `ox forward` and `ox block`.
//!
//! Each one produces ordinary config and shows it before anything is applied.

use std::{
    io::{BufRead, IsTerminal, Write},
    net::IpAddr,
    path::Path,
};

use ox_client::Client;
use ox_schema::{Config, Net, PortSpec};
use ox_setup::{Answers, Detected, ForwardRequest, Port};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Asks one question on the terminal. An empty answer takes the default.
fn ask(question: &str, default: &str) -> Result<String> {
    let mut out = std::io::stdout();
    if default.is_empty() {
        write!(out, "{question}: ")?;
    } else {
        write!(out, "{question} [{default}]: ")?;
    }
    out.flush()?;
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line)? == 0 {
        return Err("no answer given".into());
    }
    let answer = line.trim();
    Ok(if answer.is_empty() { default } else { answer }.to_string())
}

/// `eth1` or `eth1=192.168.10.1/24`.
fn parse_lan(spec: &str, found: &[Detected]) -> Result<Port> {
    let (name, addr) = match spec.split_once('=') {
        Some((n, a)) => (n, Some(a)),
        None => (spec, None),
    };
    let addrs = match addr {
        Some(a) => vec![a.parse().map_err(|_| {
            format!("'{a}' is not an address with a prefix length, such as 192.168.10.1/24")
        })?],
        None => found
            .iter()
            .find(|d| d.name == name)
            .map(|d| d.addrs.clone())
            .unwrap_or_default(),
    };
    Ok(Port {
        name: name.to_string(),
        addrs,
    })
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "netoxide".into())
}

pub struct InitArgs<'a> {
    pub wan: Option<&'a str>,
    pub lan: &'a [String],
    pub hostname: Option<&'a str>,
    pub out: Option<&'a Path>,
    pub save: Option<&'a str>,
}

pub fn init(args: &InitArgs, oxd: &Client) -> Result<()> {
    let found = ox_setup::detect()?;
    let interactive = std::io::stdin().is_terminal() && (args.wan.is_none() || args.lan.is_empty());
    if (args.wan.is_none() || args.lan.is_empty()) && !interactive {
        return Err("say which ports to use: --wan <port> --lan <port>[=<address/prefix>]".into());
    }

    if interactive {
        out!("Ports on this machine:\n");
        for d in &found {
            out!(
                "  {:<14} {:<5} {}{}",
                d.name,
                if d.up { "up" } else { "down" },
                if d.addrs.is_empty() {
                    "no address".to_string()
                } else {
                    d.addrs
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                if d.default_route {
                    "  ← reaches the internet now"
                } else {
                    ""
                }
            );
        }
        out!("");
    }

    let wan_name = match args.wan {
        Some(w) => w.to_string(),
        None => {
            let guess = found
                .iter()
                .find(|d| d.default_route)
                .map_or("", |d| d.name.as_str());
            ask("Which port faces the internet?", guess)?
        }
    };
    let wan = Port {
        addrs: found
            .iter()
            .find(|d| d.name == wan_name)
            .map(|d| d.addrs.clone())
            .unwrap_or_default(),
        name: wan_name.clone(),
    };

    let mut lans = vec![];
    if args.lan.is_empty() {
        let guess: Vec<&str> = found
            .iter()
            .filter(|d| d.name != wan_name && !d.default_route)
            .map(|d| d.name.as_str())
            .collect();
        let answer = ask(
            "Which ports face your inside network? (separate with spaces)",
            &guess.join(" "),
        )?;
        for name in answer.split([' ', ',']).filter(|s| !s.is_empty()) {
            lans.push(parse_lan(name, &found)?);
        }
    } else {
        for spec in args.lan.iter().flat_map(|s| s.split(',')) {
            lans.push(parse_lan(spec, &found)?);
        }
    }
    for (i, lan) in lans.iter_mut().enumerate() {
        if lan.addrs.is_empty() && interactive {
            let answer = ask(
                &format!("What address should the box have on {}?", lan.name),
                &format!("192.168.{}.1/24", 10 + i),
            )?;
            lan.addrs = vec![answer.parse().map_err(|_| {
                format!(
                    "'{answer}' is not an address with a prefix length, such as 192.168.10.1/24"
                )
            })?];
        }
    }

    let answers = Answers {
        hostname: args.hostname.map(String::from).unwrap_or_else(hostname),
        wan,
        lans,
    };
    let config = ox_setup::starter(&answers)?;
    for port in std::iter::once(&answers.wan).chain(&answers.lans) {
        if !found.iter().any(|d| d.name == port.name) {
            out!(
                "Note: {} is not a port on this machine. The config names it anyway.",
                port.name
            );
        }
    }

    out!("\nThis config will do the following:\n");
    for line in ox_setup::describe(&config) {
        out!("  {line}");
    }
    out!(
        "\nNot covered yet: Netoxide does not serve DHCP or DNS, so keep those running elsewhere."
    );
    if answers.wan.addrs.is_empty() {
        out!(
            "{} has no fixed address in the config, which is fine for a provider that assigns one.",
            answers.wan.name
        );
    }

    let toml = config.to_toml();
    match (args.out, args.save) {
        (Some(path), _) => {
            std::fs::write(path, &toml).map_err(|e| format!("{}: {e}", path.display()))?;
            out!("\nWrote {}. Nothing has been applied.", path.display());
            out!(
                "Next: ox candidate save starter {}  then  ox commit starter --confirm 5m",
                path.display()
            );
        }
        (None, Some(name)) => {
            oxd.send(
                "PUT",
                &format!("/v1/candidates/{name}"),
                Some(("text/plain", &toml)),
            )?;
            out!("\nSaved as candidate {name}. Nothing has been applied.");
            out!("Next: ox plan {name}  then  ox commit {name} --confirm 5m");
            out!(
                "With --confirm, the change undoes itself unless you run `ox confirm`, so a mistake cannot lock you out."
            );
        }
        (None, None) => {
            out!(
                "\nNothing was written. Pass --out <file> to keep the config, or --save <name> to store it as a candidate.\n"
            );
            outp!("{toml}");
        }
    }
    Ok(())
}

/// Reads the running config, applies an edit, and stores the result as a candidate.
fn edit(
    oxd: &Client,
    candidate: &str,
    change: impl FnOnce(&mut Config) -> std::result::Result<Vec<String>, String>,
) -> Result<()> {
    let running = oxd
        .get("/v1/running")
        .map_err(|e| format!("{e}. Run `ox init` and commit a first config before changing it"))?;
    let mut config = Config::from_toml(&running)?;
    let done = change(&mut config)?;
    oxd.send(
        "PUT",
        &format!("/v1/candidates/{candidate}"),
        Some(("text/plain", &config.to_toml())),
    )?;
    for line in done {
        out!("{line}");
    }
    out!("\nSaved as candidate {candidate}. Nothing has been applied.");
    out!("Next: ox commit {candidate} --confirm 5m");
    Ok(())
}

/// A candidate name from free text.
fn candidate_name(prefix: &str, name: &str) -> String {
    let mut s = String::new();
    for c in name.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            s.push(c);
        } else if !s.ends_with('-') && !s.is_empty() {
            s.push('-');
        }
    }
    s.truncate(20);
    format!("{prefix}-{}", s.trim_end_matches('-'))
        .trim_end_matches('-')
        .to_string()
}

/// `192.168.10.20`, `192.168.10.20:8123` or `[2001:db8::20]:8123`.
pub fn parse_target(s: &str) -> std::result::Result<(IpAddr, Option<u16>), String> {
    let bad =
        || format!("'{s}' is not an address, or an address and port such as 192.168.10.20:8123");
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((ip, None));
    }
    let (host, port) = s.rsplit_once(':').ok_or_else(bad)?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Ok((
        host.parse().map_err(|_| bad())?,
        Some(port.parse().map_err(|_| bad())?),
    ))
}

pub fn forward(
    oxd: &Client,
    name: &str,
    port: &str,
    to: &str,
    address: Option<IpAddr>,
) -> Result<()> {
    let service: PortSpec = port.parse()?;
    let (to, to_port) = parse_target(to)?;
    let req = ForwardRequest {
        name: name.to_string(),
        service,
        to,
        to_port,
        address,
    };
    edit(oxd, &candidate_name("forward", name), |c| {
        ox_setup::add_forward(c, &req)
    })
}

pub fn block(oxd: &Client, address: &str, name: Option<&str>) -> Result<()> {
    let who: Net = address.parse()?;
    let name = name.unwrap_or(address);
    edit(oxd, &candidate_name("block", name), |c| {
        ox_setup::block(c, who, name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_parse_with_and_without_a_port() {
        assert_eq!(
            parse_target("192.168.10.20"),
            Ok(("192.168.10.20".parse().unwrap(), None))
        );
        assert_eq!(
            parse_target("192.168.10.20:8123"),
            Ok(("192.168.10.20".parse().unwrap(), Some(8123)))
        );
        assert_eq!(
            parse_target("2001:db8::20"),
            Ok(("2001:db8::20".parse().unwrap(), None))
        );
        assert_eq!(
            parse_target("[2001:db8::20]:8123"),
            Ok(("2001:db8::20".parse().unwrap(), Some(8123)))
        );
        assert!(parse_target("nonsense").is_err());
        assert!(parse_target("192.168.10.20:http").is_err());
    }

    #[test]
    fn candidate_names_are_valid() {
        assert_eq!(
            candidate_name("forward", "Home Assistant"),
            "forward-home-assistant"
        );
        assert_eq!(
            candidate_name("block", "192.168.10.66"),
            "block-192-168-10-66"
        );
        assert_eq!(candidate_name("block", "!!!"), "block");
    }
}

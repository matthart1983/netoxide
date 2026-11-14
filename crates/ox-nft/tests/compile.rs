//! Compiling the example config, and loading the result into a real kernel.

use std::{net::IpAddr, process::Command};

use ox_nft::{AddrMatch, CompileError, L4, MAX_CHAIN, compile, render};
use ox_schema::Config;

const BRANCH: &str = include_str!("../../../examples/branch.toml");
const CANDIDATE: &str = include_str!("../../../examples/branch-candidate.toml");

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn references_resolve_for_both_families() {
    let rs = compile(&Config::from_toml(BRANCH).unwrap()).unwrap();
    let chain = rs.chain("lan", "dmz").unwrap();
    let r = &chain.rules[0];
    assert_eq!(r.id, "r-0388");
    for (src, dst) in [
        ("10.20.4.17", "10.30.0.8"),
        ("2001:db8:4a00:1:4::17", "2001:db8:4a00:2::8"),
    ] {
        assert!(
            r.matches(ip(src), ip(dst), L4::Tcp, Some(445)),
            "{src} → {dst}"
        );
        assert!(r.matches(ip(src), ip(dst), L4::Udp, Some(138)));
        assert!(!r.matches(ip(src), ip(dst), L4::Tcp, Some(22)));
        assert!(!r.matches(ip(src), ip(dst), L4::Icmp, None));
    }
    // Outside the finance range, in each family.
    assert!(!r.matches(ip("10.20.5.1"), ip("10.30.0.8"), L4::Tcp, Some(445)));
    assert!(!r.matches(
        ip("2001:db8:4a00:1:5::1"),
        ip("2001:db8:4a00:2::8"),
        L4::Tcp,
        Some(445)
    ));
}

#[test]
fn a_dual_stack_rule_becomes_one_nft_rule_per_family() {
    let rs = compile(&Config::from_toml(BRANCH).unwrap()).unwrap();
    let chain = rs.chain("lan", "dmz").unwrap();
    assert_eq!(
        chain.rules[0].expansions().len(),
        2,
        "r-0388 covers IPv4 and IPv6"
    );
    assert_eq!(chain.rules[2].expansions().len(), 1, "r-0277 is IPv4 only");
    // r-0002 allows ping, which is a different protocol in each family, plus DNS.
    let to_self = rs.chain("lan", "self").unwrap();
    assert_eq!(to_self.rules[1].expansions().len(), 4);
}

#[test]
fn overlapping_addresses_and_ports_are_merged() {
    let toml = BRANCH.replace(
        "backup-agents = [\"10.20.9.0/28\"]",
        "backup-agents = [\"10.20.9.0/28\", \"10.20.9.0/24\", \"10.20.9.4\"]",
    );
    let rs = compile(&Config::from_toml(&toml).unwrap()).unwrap();
    let r = &rs.chain("lan", "dmz").unwrap().rules[2];
    let AddrMatch::Nets { v4, .. } = &r.src else {
        panic!("expected networks")
    };
    assert_eq!(v4.len(), 1, "nftables refuses overlapping set elements");
    // tcp/139, tcp/443, tcp/445 and udp/137-138: four ranges, none adjacent.
    assert_eq!(rs.chain("lan", "dmz").unwrap().rules[0].svc.ports.len(), 4);
}

#[test]
fn disabled_rules_are_left_out() {
    let toml = BRANCH.replace("id = \"r-0277\"", "id = \"r-0277\"\nenabled = false");
    let rs = compile(&Config::from_toml(&toml).unwrap()).unwrap();
    assert!(
        rs.chain("lan", "dmz")
            .unwrap()
            .rules
            .iter()
            .all(|r| r.id != "r-0277")
    );
}

#[test]
fn a_chain_over_the_limit_is_refused() {
    let mut toml = BRANCH.to_string();
    for i in 0..=MAX_CHAIN {
        toml = toml.replace(
            "[[policy]]\nfrom = \"lan\"\nto = \"wan\"",
            &format!(
                "[[policy.rule]]\nid = \"x-{i}\"\nname = \"filler\"\naction = \"accept\"\nservice = [\"tcp/{}\"]\n\n[[policy]]\nfrom = \"lan\"\nto = \"wan\"",
                1000 + i
            ),
        );
    }
    let err = compile(&Config::from_toml(&toml).unwrap()).unwrap_err();
    assert!(
        matches!(err, CompileError::ChainTooLong { ref from, ref to, .. } if from == "lan" && to == "dmz")
    );
}

#[test]
fn stats_count_what_was_rendered() {
    let rs = compile(&Config::from_toml(BRANCH).unwrap()).unwrap();
    let (json, stats) = render(&rs);
    let cmds = json["nftables"].as_array().unwrap();
    let count = |kind: &str| cmds.iter().filter(|c| c["add"][kind].is_object()).count();
    assert_eq!(stats.sets, count("set"));
    assert_eq!(stats.verdict_maps, count("map"));
    assert_eq!(stats.verdict_maps, 2);
    assert!(stats.longest_chain <= MAX_CHAIN);
}

/// Loads the rendered ruleset into the kernel inside a private, rootless
/// network namespace. This is the check that the JSON is what nftables
/// accepts: the kernel gives every rule it stores a handle, and a second
/// load in the same transaction must replace the table.
#[test]
fn the_kernel_accepts_the_ruleset() {
    let nft = |args: &[&str]| {
        Command::new("unshare")
            .args(["-Urn", "nft"])
            .args(args)
            .output()
    };
    match nft(&["--version"]) {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!("skipped: needs unshare(1), nft(8) and unprivileged user namespaces");
            return;
        }
    }
    for (name, toml) in [("branch", BRANCH), ("candidate", CANDIDATE)] {
        let rs = compile(&Config::from_toml(toml).unwrap()).unwrap();
        let (json, stats) = render(&rs);
        let load = |tag: &str, doc: &serde_json::Value, echo: bool| {
            let path = std::env::temp_dir()
                .join(format!("ox-nft-{name}-{tag}-{}.json", std::process::id()));
            std::fs::write(&path, doc.to_string()).unwrap();
            let file = path.to_str().unwrap();
            let out = if echo {
                nft(&["-j", "-e", "-f", file])
            } else {
                nft(&["-j", "-f", file])
            }
            .unwrap();
            std::fs::remove_file(&path).ok();
            assert!(
                out.status.success(),
                "{name}: nft refused the ruleset:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
            out.stdout
        };

        // With --echo, nft prints each object the kernel stored, with its handle.
        let echoed: serde_json::Value = serde_json::from_slice(&load("once", &json, true)).unwrap();
        let stored = echoed["nftables"].as_array().unwrap();
        let sets = stored
            .iter()
            .filter(|i| i["add"]["set"].is_object())
            .count();
        let filter_rules = stored
            .iter()
            .map(|i| &i["add"]["rule"])
            .filter(|r| r["handle"].is_number())
            .filter(|r| r["chain"].as_str().is_some_and(|c| c.starts_with("p_")))
            .filter(|r| {
                !r["comment"]
                    .as_str()
                    .is_some_and(|c| c.starts_with("default "))
            })
            .count();
        assert_eq!(sets, stats.sets, "{name}");
        assert_eq!(filter_rules, stats.rules, "{name}");

        // The same transaction twice in a row: the reload path.
        let mut twice = json["nftables"].as_array().unwrap().clone();
        twice.extend(json["nftables"].as_array().unwrap().clone());
        load("twice", &serde_json::json!({ "nftables": twice }), false);
    }
}

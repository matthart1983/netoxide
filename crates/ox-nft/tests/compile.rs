//! Compiling the example config, and loading the result into a real kernel.

use std::{net::IpAddr, process::Command};

use ox_nft::{AddrMatch, CompileError, Family, L4, MAX_CHAIN, Segment, compile, render};
use ox_schema::Config;
use ox_schema::Proto;

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

/// The example config with extra rules appended to the lan → dmz policy.
fn with_rules(extra: &[String]) -> String {
    BRANCH.replace(
        "[[policy]]\nfrom = \"lan\"\nto = \"wan\"",
        &format!(
            "{}\n[[policy]]\nfrom = \"lan\"\nto = \"wan\"",
            extra.join("\n")
        ),
    )
}

fn rule(id: &str, action: &str, rest: &str) -> String {
    format!("[[policy.rule]]\nid = \"{id}\"\nname = \"{id}\"\naction = \"{action}\"\n{rest}\n")
}

/// Sixty accept rules, each for one host and port: far past the limit as
/// separate kernel rules.
fn sixty() -> Vec<String> {
    (0..60)
        .map(|i| {
            rule(
                &format!("x-{i}"),
                "accept",
                &format!(
                    "destination = [\"10.30.1.{i}\"]\nservice = [\"tcp/{}\"]",
                    2000 + i
                ),
            )
        })
        .collect()
}

#[test]
fn a_short_chain_keeps_one_kernel_rule_per_config_rule() {
    let rs = compile(&Config::from_toml(BRANCH).unwrap()).unwrap();
    for chain in &rs.chains {
        assert!(
            chain
                .layout()
                .iter()
                .all(|s| matches!(s, Segment::Single(_))),
            "{}",
            chain.name()
        );
    }
    assert_eq!(render(&rs).1.merged, 0);
}

#[test]
fn a_long_chain_is_merged_instead_of_refused() {
    let rs = compile(&Config::from_toml(&with_rules(&sixty())).unwrap()).unwrap();
    let chain = rs.chain("lan", "dmz").unwrap();
    assert_eq!(chain.rules.len(), 63);
    assert!(
        chain.nft_rules() <= MAX_CHAIN,
        "{} kernel rules",
        chain.nft_rules()
    );
    let runs: Vec<usize> = chain
        .layout()
        .iter()
        .filter_map(|s| match s {
            Segment::Run(r) => Some(r.len()),
            Segment::Single(_) => None,
        })
        .collect();
    // The three original rules and the sixty new ones all accept and none
    // overlap, so they form one run.
    assert_eq!(runs, [63]);
    let (_, stats) = render(&rs);
    assert_eq!(stats.merged, 63);
    assert!(rs.summary().contains("63 rules merged"));
}

#[test]
fn merging_never_moves_a_rule_past_one_with_another_action() {
    let mut extra = sixty();
    extra.insert(
        30,
        rule(
            "stop",
            "drop",
            "destination = [\"10.30.1.0/24\"]\nservice = [\"tcp/2000-2100\"]",
        ),
    );
    let rs = compile(&Config::from_toml(&with_rules(&extra)).unwrap()).unwrap();
    let shape: Vec<String> = rs
        .chain("lan", "dmz")
        .unwrap()
        .layout()
        .iter()
        .map(|s| match s {
            Segment::Single(r) => r.id.clone(),
            Segment::Run(r) => format!("{}..{}", r[0].id, r[r.len() - 1].id),
        })
        .collect();
    assert_eq!(shape, ["r-0388..x-29", "stop", "x-30..x-59"]);
}

#[test]
fn rules_that_cannot_share_a_set_stay_on_their_own() {
    let mut extra = sixty();
    // Same action as its neighbours, but it overlaps x-5, and nftables
    // refuses overlapping set entries.
    extra.insert(
        6,
        rule(
            "wide",
            "accept",
            "destination = [\"10.30.1.0/24\"]\nservice = [\"tcp/2005\"]",
        ),
    );
    extra.insert(
        20,
        rule(
            "logged",
            "accept",
            "destination = [\"10.30.2.1\"]\nservice = [\"tcp/9\"]\nlog = true",
        ),
    );
    extra.insert(
        40,
        rule(
            "ping",
            "accept",
            "destination = [\"10.30.2.2\"]\nservice = [\"icmp\"]",
        ),
    );
    let rs = compile(&Config::from_toml(&with_rules(&extra)).unwrap()).unwrap();
    let layout = rs.chain("lan", "dmz").unwrap().layout();
    let singles: Vec<&str> = layout
        .iter()
        .filter_map(|s| match s {
            Segment::Single(r) => Some(r.id.as_str()),
            Segment::Run(_) => None,
        })
        .collect();
    assert_eq!(singles, ["logged", "ping"]);
    // "wide" starts a new run, so it is tried after x-5 and before x-6, as written.
    let starts: Vec<&str> = layout
        .iter()
        .filter_map(|s| match s {
            Segment::Run(r) => Some(r[0].id.as_str()),
            Segment::Single(_) => None,
        })
        .collect();
    assert_eq!(starts, ["r-0388", "wide", "x-19", "x-38"]);
}

/// Walks the merged layout the way the kernel does and compares the verdict
/// with the plain first-match walk over the config rules.
#[test]
fn the_merged_layout_gives_the_same_verdicts() {
    let mut extra = sixty();
    extra.insert(
        30,
        rule(
            "stop",
            "drop",
            "destination = [\"10.30.1.0/24\"]\nservice = [\"tcp/2000-2100\"]",
        ),
    );
    extra.insert(
        6,
        rule(
            "wide",
            "accept",
            "destination = [\"10.30.1.0/24\"]\nservice = [\"tcp/2005\"]",
        ),
    );
    extra.push(rule(
        "six",
        "accept",
        "destination = [\"2001:db8:4a00:2::50\"]\nservice = [\"udp/5000-5010\"]",
    ));
    let rs = compile(&Config::from_toml(&with_rules(&extra)).unwrap()).unwrap();
    let chain = rs.chain("lan", "dmz").unwrap();
    assert!(chain.layout().iter().any(|s| matches!(s, Segment::Run(_))));

    let mut checked = 0;
    let dsts: Vec<IpAddr> = (0..70)
        .map(|i| ip(&format!("10.30.1.{i}")))
        .chain([
            ip("10.30.0.8"),
            ip("2001:db8:4a00:2::50"),
            ip("2001:db8:4a00:2::8"),
        ])
        .collect();
    for dst in &dsts {
        let src = if dst.is_ipv4() {
            ip("10.20.4.17")
        } else {
            ip("2001:db8:4a00:1:4::17")
        };
        for (l4, port) in [
            (L4::Tcp, 2005),
            (L4::Tcp, 2031),
            (L4::Tcp, 2060),
            (L4::Tcp, 445),
            (L4::Udp, 5005),
            (L4::Tcp, 1),
        ] {
            let plain = chain
                .rules
                .iter()
                .find(|r| r.matches(src, *dst, l4, Some(port)))
                .map(|r| r.action);
            let merged = chain.layout().iter().find_map(|s| match s {
                Segment::Single(r) => r.matches(src, *dst, l4, Some(port)).then_some(r.action),
                Segment::Run(rules) => {
                    let family = if dst.is_ipv4() {
                        Family::V4
                    } else {
                        Family::V6
                    };
                    let proto = if l4 == L4::Tcp {
                        Proto::Tcp
                    } else {
                        Proto::Udp
                    };
                    rules
                        .iter()
                        .flat_map(|r| r.tuples(family))
                        .any(|t| {
                            t.src.contains(&src)
                                && t.dst.contains(dst)
                                && t.proto == proto
                                && (t.first..=t.last).contains(&port)
                        })
                        .then_some(rules[0].action)
                }
            });
            assert_eq!(plain, merged, "{src} → {dst} {l4:?}/{port}");
            checked += 1;
        }
    }
    assert_eq!(checked, 73 * 6);
}

#[test]
fn a_chain_that_cannot_be_merged_enough_is_refused() {
    // Alternating actions leave no two neighbours to merge.
    let extra: Vec<String> = (0..40)
        .map(|i| {
            rule(
                &format!("a-{i}"),
                if i % 2 == 0 { "accept" } else { "drop" },
                &format!(
                    "destination = [\"10.30.1.{i}\"]\nservice = [\"tcp/{}\"]",
                    2000 + i
                ),
            )
        })
        .collect();
    let err = compile(&Config::from_toml(&with_rules(&extra)).unwrap()).unwrap_err();
    assert!(
        matches!(err, CompileError::ChainTooLong { ref from, ref to, .. } if from == "lan" && to == "dmz")
    );
    assert!(err.to_string().contains("after merging"));
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
    // The third config is long enough to be merged into shared set lookups.
    let mut long = sixty();
    long.push(rule(
        "six",
        "accept",
        "destination = [\"2001:db8:4a00:2::50\"]\nservice = [\"udp/5000-5010\"]",
    ));
    long.push(rule(
        "anysrc",
        "accept",
        "source = [\"any\"]\ndestination = [\"10.30.3.0/24\"]\nservice = [\"tcp/8080\"]",
    ));
    let long = with_rules(&long);
    for (name, toml) in [
        ("branch", BRANCH),
        ("candidate", CANDIDATE),
        ("merged", long.as_str()),
    ] {
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

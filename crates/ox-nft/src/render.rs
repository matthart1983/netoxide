//! Renders a [`Ruleset`] as libnftables JSON.
//!
//! The output is one transaction. It creates the table if missing, deletes
//! it, and builds it again, so the kernel swaps the whole ruleset at once and
//! no packet sees half of it.

use ipnet::{Ipv4Net, Ipv6Net};
use ox_schema::{Action, SELF_ZONE, Translate};
use serde_json::{Value, json};

use crate::{AddrMatch, CRule, Chain, Family, Ruleset, Segment, SvcKind, TABLE};

/// Counts for the plan output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Stats {
    /// Filter rules across all zone-pair chains, without default drops.
    pub rules: usize,
    pub sets: usize,
    pub verdict_maps: usize,
    /// Rules in the longest zone-pair chain.
    pub longest_chain: usize,
    /// Config rules that share a merged set lookup, and so share a counter.
    pub merged: usize,
}

const FAMILY: &str = "inet";

struct Out {
    cmds: Vec<Value>,
    stats: Stats,
}

impl Out {
    fn add(&mut self, kind: &str, mut body: Value) {
        body["family"] = json!(FAMILY);
        body["table"] = json!(TABLE);
        self.cmds.push(json!({ "add": { kind: body } }));
    }

    fn rule(&mut self, chain: &str, comment: Option<&str>, expr: Vec<Value>) {
        let mut body = json!({ "chain": chain, "expr": expr });
        if let Some(c) = comment {
            body["comment"] = json!(c);
        }
        self.add("rule", body);
    }
}

fn meta(key: &str) -> Value {
    json!({ "meta": { "key": key } })
}

fn payload(protocol: &str, field: &str) -> Value {
    json!({ "payload": { "protocol": protocol, "field": field } })
}

fn eq(left: Value, right: Value) -> Value {
    json!({ "match": { "op": "==", "left": left, "right": right } })
}

fn ct_state(states: &[&str]) -> Value {
    json!({ "match": { "op": "in", "left": { "ct": { "key": "state" } }, "right": states } })
}

fn counter() -> Value {
    json!({ "counter": null })
}

fn log(prefix: &str) -> Value {
    json!({ "log": { "prefix": prefix } })
}

fn verdict(action: Action) -> Value {
    json!({ action.as_str(): null })
}

fn jump(target: &str) -> Value {
    json!({ "jump": { "target": target } })
}

/// One interface name, or an anonymous set of several.
fn ifaces(names: &[&str]) -> Value {
    match names {
        [one] => json!(one),
        many => json!({ "set": many }),
    }
}

fn v4_elems(nets: &[Ipv4Net]) -> Vec<Value> {
    nets.iter()
        .map(|n| json!({ "prefix": { "addr": n.network().to_string(), "len": n.prefix_len() } }))
        .collect()
}

fn v6_elems(nets: &[Ipv6Net]) -> Vec<Value> {
    nets.iter()
        .map(|n| json!({ "prefix": { "addr": n.network().to_string(), "len": n.prefix_len() } }))
        .collect()
}

/// Renders the ruleset. The value is ready to hand to libnftables or to
/// `nft -j -f -`.
pub fn render(rs: &Ruleset) -> (Value, Stats) {
    let table = json!({ "family": FAMILY, "name": TABLE });
    let mut out = Out {
        cmds: vec![
            json!({ "add": { "table": table } }),
            json!({ "delete": { "table": table } }),
            json!({ "add": { "table": table } }),
        ],
        stats: Stats::default(),
    };

    base_chains(&mut out);
    for chain in &rs.chains {
        out.add("chain", json!({ "name": chain.name() }));
    }
    dispatch(&mut out, rs);
    for chain in &rs.chains {
        pair_chain(&mut out, chain);
    }
    nat(&mut out, rs);

    (json!({ "nftables": out.cmds }), out.stats)
}

/// A transaction that removes the Netoxide table and everything in it.
/// Used when there is no config to run, such as reverting the first commit.
pub fn render_empty() -> Value {
    let table = json!({ "family": FAMILY, "name": TABLE });
    json!({ "nftables": [
        { "add": { "table": table } },
        { "delete": { "table": table } },
    ] })
}

/// A command that lists the Netoxide table as the kernel holds it.
pub fn list_command() -> Value {
    json!({ "nftables": [{ "list": { "table": { "family": FAMILY, "name": TABLE } } }] })
}

fn base_chains(out: &mut Out) {
    for (name, kind, hook, prio, policy) in [
        ("input", "filter", "input", 0, "drop"),
        ("forward", "filter", "forward", 0, "drop"),
        // Schema 1 has no rules for traffic the box itself sends.
        ("output", "filter", "output", 0, "accept"),
        ("prerouting", "nat", "prerouting", -100, "accept"),
        ("postrouting", "nat", "postrouting", 100, "accept"),
    ] {
        out.add(
            "chain",
            json!({ "name": name, "type": kind, "hook": hook, "prio": prio, "policy": policy }),
        );
    }
}

/// The start of `input` and `forward`: connection tracking first, then one
/// verdict-map lookup that jumps to the chain for the packet's zone pair.
fn dispatch(out: &mut Out, rs: &Ruleset) {
    out.rule(
        "input",
        None,
        vec![eq(meta("iifname"), json!("lo")), verdict(Action::Accept)],
    );
    for chain in ["input", "forward"] {
        out.rule(
            chain,
            None,
            vec![
                ct_state(&["established", "related"]),
                verdict(Action::Accept),
            ],
        );
        out.rule(
            chain,
            None,
            vec![ct_state(&["invalid"]), counter(), verdict(Action::Drop)],
        );
    }
    // IPv6 stops working without neighbour discovery, so it is never a policy choice.
    out.rule(
        "input",
        Some("ipv6 neighbour discovery"),
        vec![
            eq(
                payload("icmpv6", "type"),
                json!({ "set": [
                    "nd-neighbor-solicit", "nd-neighbor-advert",
                    "nd-router-solicit", "nd-router-advert"
                ] }),
            ),
            verdict(Action::Accept),
        ],
    );

    let mut to_self = vec![];
    let mut pairs = vec![];
    for chain in &rs.chains {
        let target = jump(&chain.name());
        for iif in rs.zone_interfaces(&chain.from) {
            if chain.to == SELF_ZONE {
                to_self.push(json!([iif, target]));
            } else {
                for oif in rs.zone_interfaces(&chain.to) {
                    pairs.push(json!([{ "concat": [iif, oif] }, target]));
                }
            }
        }
    }
    if !to_self.is_empty() {
        out.add(
            "map",
            json!({ "name": "in_zones", "type": "ifname", "map": "verdict", "elem": to_self }),
        );
        out.stats.verdict_maps += 1;
        out.rule(
            "input",
            None,
            vec![json!({ "vmap": { "key": meta("iifname"), "data": "@in_zones" } })],
        );
    }
    if !pairs.is_empty() {
        out.add(
            "map",
            json!({ "name": "zone_pairs", "type": ["ifname", "ifname"], "map": "verdict", "elem": pairs }),
        );
        out.stats.verdict_maps += 1;
        out.rule(
            "forward",
            None,
            vec![json!({ "vmap": {
                "key": { "concat": [meta("iifname"), meta("oifname")] },
                "data": "@zone_pairs"
            } })],
        );
    }
    // A packet for a zone pair with no policy reaches here and meets the chain's drop policy.
    out.rule("input", None, vec![log("ox no-policy-in "), counter()]);
    out.rule("forward", None, vec![log("ox no-policy "), counter()]);
}

fn pair_chain(out: &mut Out, chain: &Chain) {
    let name = chain.name();
    for (i, segment) in chain.layout().iter().enumerate() {
        match segment {
            Segment::Single(rule) => filter_rule(out, &name, rule),
            Segment::Run(rules) => merged_run(out, &name, i, rules),
        }
    }
    let mut end = vec![];
    if chain.log_default {
        end.push(log(&format!("ox default {}-{} ", chain.from, chain.to)));
    }
    end.extend([counter(), verdict(Action::Drop)]);
    // The comment is unique per pair so its counter can be read back.
    out.rule(
        &name,
        Some(&format!("default {}-{}", chain.from, chain.to)),
        end,
    );

    out.stats.rules += chain.nft_rules();
    out.stats.longest_chain = out.stats.longest_chain.max(chain.nft_rules());
}

/// Renders neighbouring rules with one action as one set lookup per family.
fn merged_run(out: &mut Out, chain: &str, index: usize, rules: &[&CRule]) {
    let comment = format!(
        "merged {} … {} ({} rules)",
        rules[0].id,
        rules[rules.len() - 1].id,
        rules.len()
    );
    for (family, tag, ip, addr_type) in [
        (Family::V4, "4", "ip", "ipv4_addr"),
        (Family::V6, "6", "ip6", "ipv6_addr"),
    ] {
        let elems: Vec<Value> = rules
            .iter()
            .flat_map(|r| r.tuples(family))
            .map(|t| {
                let net = |n: &ipnet::IpNet| {
                    json!({ "prefix": { "addr": n.network().to_string(), "len": n.prefix_len() } })
                };
                let port = if t.first == t.last {
                    json!(t.first)
                } else {
                    json!({ "range": [t.first, t.last] })
                };
                json!({ "concat": [net(&t.src), net(&t.dst), t.proto.as_str(), port] })
            })
            .collect();
        if elems.is_empty() {
            continue;
        }
        let set = format!("{}_m{index}_{tag}", chain.trim_start_matches("p_"));
        out.add(
            "set",
            json!({
                "name": set,
                "type": [addr_type, addr_type, "inet_proto", "inet_service"],
                "flags": ["interval"],
                "elem": elems,
            }),
        );
        out.stats.sets += 1;
        out.rule(
            chain,
            Some(&comment),
            vec![
                eq(
                    json!({ "concat": [
                        payload(ip, "saddr"), payload(ip, "daddr"),
                        meta("l4proto"), payload("th", "dport")
                    ] }),
                    json!(format!("@{set}")),
                ),
                counter(),
                verdict(rules[0].action),
            ],
        );
    }
    out.stats.merged += rules.len();
}

fn filter_rule(out: &mut Out, chain: &str, rule: &CRule) {
    let base = rule.id.replace('-', "_");
    let mut made = vec![];
    // Each set is declared once, then shared by the rule's expansions.
    let mut set = |out: &mut Out, suffix: &str, ty: Value, elem: Vec<Value>| -> String {
        let name = format!("{base}_{suffix}");
        if !made.contains(&name) {
            out.add(
                "set",
                json!({ "name": name, "type": ty, "flags": ["interval"], "elem": elem }),
            );
            out.stats.sets += 1;
            made.push(name.clone());
        }
        format!("@{name}")
    };

    for (family, kind) in rule.expansions() {
        let mut expr = vec![];
        for (side, field, m) in [("s", "saddr", &rule.src), ("d", "daddr", &rule.dst)] {
            let AddrMatch::Nets { v4, v6 } = m else {
                continue;
            };
            match family {
                Some(Family::V4) => {
                    let s = set(out, &format!("{side}4"), json!("ipv4_addr"), v4_elems(v4));
                    expr.push(eq(payload("ip", field), json!(s)));
                }
                Some(Family::V6) => {
                    let s = set(out, &format!("{side}6"), json!("ipv6_addr"), v6_elems(v6));
                    expr.push(eq(payload("ip6", field), json!(s)));
                }
                None => {}
            }
        }
        match kind {
            SvcKind::All => {}
            SvcKind::Ports => {
                let elems = rule
                    .svc
                    .ports
                    .iter()
                    .map(|(proto, first, last)| {
                        let port = if first == last {
                            json!(first)
                        } else {
                            json!({ "range": [first, last] })
                        };
                        json!({ "concat": [proto.as_str(), port] })
                    })
                    .collect();
                let s = set(out, "svc", json!(["inet_proto", "inet_service"]), elems);
                expr.push(eq(
                    json!({ "concat": [meta("l4proto"), payload("th", "dport")] }),
                    json!(s),
                ));
            }
            SvcKind::Icmp => expr.push(eq(meta("l4proto"), json!("icmp"))),
            SvcKind::Icmpv6 => expr.push(eq(meta("l4proto"), json!("ipv6-icmp"))),
        }
        expr.push(counter());
        if rule.log {
            expr.push(log(&format!("ox {} ", rule.id)));
        }
        expr.push(verdict(rule.action));
        out.rule(chain, Some(&rule.id), expr);
    }
}

fn nat(out: &mut Out, rs: &Ruleset) {
    for f in &rs.forwards {
        let from = rs.zone_interfaces(&f.from);
        if from.is_empty() {
            continue;
        }
        let (ip, family) = if f.address.is_ipv4() {
            ("ip", "ip")
        } else {
            ("ip6", "ip6")
        };
        let port = if f.first == f.last {
            json!(f.first)
        } else {
            json!({ "range": [f.first, f.last] })
        };
        let mut dnat = json!({ "family": family, "addr": f.to.to_string() });
        if let Some(p) = f.to_port {
            dnat["port"] = json!(p);
        }
        out.rule(
            "prerouting",
            Some(&f.id),
            vec![
                eq(meta("iifname"), ifaces(&from)),
                eq(payload(ip, "daddr"), json!(f.address.to_string())),
                eq(payload(f.proto.as_str(), "dport"), port),
                counter(),
                json!({ "dnat": dnat }),
            ],
        );
    }

    for o in &rs.outbound {
        let (from, to) = (rs.zone_interfaces(&o.from), rs.zone_interfaces(&o.to));
        if from.is_empty() || to.is_empty() {
            continue;
        }
        let zones = [
            eq(meta("iifname"), ifaces(&from)),
            eq(meta("oifname"), ifaces(&to)),
        ];
        let action = |family: Family| match o.translate {
            Translate::Masquerade => Some(json!({ "masquerade": null })),
            Translate::Address(a) if a.is_ipv4() == (family == Family::V4) => Some(json!({
                "snat": { "family": if a.is_ipv4() { "ip" } else { "ip6" }, "addr": a.to_string() }
            })),
            Translate::Address(_) => None,
        };
        for family in [Family::V4, Family::V6] {
            let Some(action) = action(family) else {
                continue;
            };
            let source = match (&o.src, family) {
                (AddrMatch::Any, Family::V4) => Some(eq(meta("nfproto"), json!("ipv4"))),
                (AddrMatch::Any, Family::V6) => Some(eq(meta("nfproto"), json!("ipv6"))),
                (AddrMatch::Nets { v4, .. }, Family::V4) if !v4.is_empty() => {
                    Some(eq(payload("ip", "saddr"), json!({ "set": v4_elems(v4) })))
                }
                (AddrMatch::Nets { v6, .. }, Family::V6) if !v6.is_empty() => {
                    Some(eq(payload("ip6", "saddr"), json!({ "set": v6_elems(v6) })))
                }
                _ => None,
            };
            let Some(source) = source else {
                continue;
            };
            let mut expr = zones.to_vec();
            expr.extend([source, counter(), action]);
            out.rule("postrouting", Some(&o.id), expr);
        }
    }
}

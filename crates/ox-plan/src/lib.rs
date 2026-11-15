//! What a candidate config changes, compared with the running one.
//!
//! Two answers: [`diff`] lists the config items that differ, and [`impact`]
//! replays known flows through both rulesets and reports the ones whose
//! verdict changes. The second is what "this commit would have blocked 3
//! active services" is built from.

use std::{collections::BTreeMap, fmt, net::IpAddr};

use ox_explain::{ExplainError, Packet, Verdict, explain};
use ox_nft::{L4, Ruleset};
use ox_schema::{Config, Forward, Outbound, Policy, Rule};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Added,
    Removed,
    Changed,
}

/// One config item that differs between running and candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub kind: Kind,
    /// The item, such as `rule r-0412` or `address group staff`.
    pub what: String,
    pub detail: String,
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let sign = match self.kind {
            Kind::Added => '+',
            Kind::Removed => '-',
            Kind::Changed => '~',
        };
        write!(f, "{sign} {}", self.what)?;
        if !self.detail.is_empty() {
            write!(f, ": {}", self.detail)?;
        }
        Ok(())
    }
}

fn list<T: ToString>(items: &[T]) -> String {
    items
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Compares two maps of named items.
fn named<T: PartialEq>(
    out: &mut Vec<Change>,
    label: &str,
    old: &BTreeMap<String, T>,
    new: &BTreeMap<String, T>,
    show: impl Fn(&T) -> String,
) {
    for (name, item) in new {
        match old.get(name) {
            None => out.push(Change {
                kind: Kind::Added,
                what: format!("{label} {name}"),
                detail: show(item),
            }),
            Some(before) if before != item => out.push(Change {
                kind: Kind::Changed,
                what: format!("{label} {name}"),
                detail: format!("{} → {}", show(before), show(item)),
            }),
            Some(_) => {}
        }
    }
    for (name, item) in old {
        if !new.contains_key(name) {
            out.push(Change {
                kind: Kind::Removed,
                what: format!("{label} {name}"),
                detail: show(item),
            });
        }
    }
}

fn rule_summary(p: &Policy, r: &Rule) -> String {
    format!(
        "{} → {}: {} {} → {} · {}",
        p.from,
        p.to,
        r.action.as_str(),
        list(&r.source),
        list(&r.destination),
        list(&r.service)
    )
}

/// The fields of a rule that differ, as `field: old → new`.
fn rule_fields(old: (&Policy, &Rule), new: (&Policy, &Rule)) -> Vec<String> {
    let ((op, o), (np, n)) = (old, new);
    let mut out = vec![];
    let mut field = |name: &str, a: String, b: String| {
        if a != b {
            out.push(format!("{name}: {a} → {b}"));
        }
    };
    field(
        "policy",
        format!("{} → {}", op.from, op.to),
        format!("{} → {}", np.from, np.to),
    );
    field("name", o.name.clone(), n.name.clone());
    field("action", o.action.as_str().into(), n.action.as_str().into());
    field("source", list(&o.source), list(&n.source));
    field("destination", list(&o.destination), list(&n.destination));
    field("service", list(&o.service), list(&n.service));
    field("log", o.log.to_string(), n.log.to_string());
    field("enabled", o.enabled.to_string(), n.enabled.to_string());
    field(
        "reason",
        o.reason.clone().unwrap_or_default(),
        n.reason.clone().unwrap_or_default(),
    );
    out
}

fn forward_summary(f: &Forward) -> String {
    format!(
        "from {} {} {} to {}{}, filter rule {}",
        f.from,
        f.address
            .map_or("the box's own address".to_string(), |a| a.to_string()),
        f.service,
        f.to,
        f.to_port.map(|p| format!(":{p}")).unwrap_or_default(),
        f.rule
    )
}

fn outbound_summary(o: &Outbound) -> String {
    format!(
        "{} → {} source {} translate {}",
        o.from,
        o.to,
        list(&o.source),
        o.translate
    )
}

/// Lists what differs between two configs, in document order.
pub fn diff(running: &Config, candidate: &Config) -> Vec<Change> {
    let mut out = vec![];
    if running.hostname != candidate.hostname {
        out.push(Change {
            kind: Kind::Changed,
            what: "hostname".into(),
            detail: format!("{} → {}", running.hostname, candidate.hostname),
        });
    }
    named(&mut out, "zone", &running.zones, &candidate.zones, |z| {
        z.description.clone().unwrap_or_default()
    });
    named(
        &mut out,
        "interface",
        &running.interfaces,
        &candidate.interfaces,
        |i| {
            format!(
                "zone {} addresses {}{}{}{}{}",
                i.zone,
                list(&i.addresses.iter().map(|a| a.0).collect::<Vec<_>>()),
                if i.default_route {
                    " default route"
                } else {
                    ""
                },
                if i.gateway.is_empty() {
                    String::new()
                } else {
                    format!(" through {}", list(&i.gateway))
                },
                if i.dhcp_client {
                    " address from the network"
                } else {
                    ""
                },
                match &i.vlan {
                    Some(v) => format!(" VLAN {} on {}", v.id, v.parent),
                    None => String::new(),
                }
            )
        },
    );
    named(
        &mut out,
        "address group",
        &running.addresses,
        &candidate.addresses,
        |v| list(v),
    );
    named(
        &mut out,
        "service",
        &running.services,
        &candidate.services,
        |v| list(v),
    );

    // Policies by zone pair.
    let pair = |p: &Policy| format!("{} → {}", p.from, p.to);
    for p in &candidate.policies {
        match running.policies.iter().find(|o| pair(o) == pair(p)) {
            None => out.push(Change {
                kind: Kind::Added,
                what: format!("policy {}", pair(p)),
                detail: format!("{} rules", p.rules.len()),
            }),
            Some(o) => {
                if o.log_default != p.log_default {
                    out.push(Change {
                        kind: Kind::Changed,
                        what: format!("policy {}", pair(p)),
                        detail: format!("log_default: {} → {}", o.log_default, p.log_default),
                    });
                }
                // Order matters: first match wins. Compare the rules both sides have.
                let ids = |a: &Policy, b: &Policy| -> Vec<String> {
                    a.rules
                        .iter()
                        .filter(|r| b.rules.iter().any(|x| x.id == r.id))
                        .map(|r| r.id.clone())
                        .collect()
                };
                let (before, after) = (ids(o, p), ids(p, o));
                if before != after {
                    out.push(Change {
                        kind: Kind::Changed,
                        what: format!("policy {}", pair(p)),
                        detail: format!("rule order: {} → {}", list(&before), list(&after)),
                    });
                }
            }
        }
    }
    for o in &running.policies {
        if !candidate.policies.iter().any(|p| pair(p) == pair(o)) {
            out.push(Change {
                kind: Kind::Removed,
                what: format!("policy {}", pair(o)),
                detail: format!("{} rules", o.rules.len()),
            });
        }
    }

    // Rules by ID, wherever they sit.
    for (p, r) in candidate.rules() {
        match running.rules().find(|(_, o)| o.id == r.id) {
            None => out.push(Change {
                kind: Kind::Added,
                what: format!("rule {} \"{}\"", r.id, r.name),
                detail: format!(
                    "{}, position {}",
                    rule_summary(p, r),
                    p.rules.iter().position(|x| x.id == r.id).unwrap_or(0) + 1
                ),
            }),
            Some(old) => {
                let fields = rule_fields(old, (p, r));
                if !fields.is_empty() {
                    out.push(Change {
                        kind: Kind::Changed,
                        what: format!("rule {} \"{}\"", r.id, r.name),
                        detail: fields.join("; "),
                    });
                }
            }
        }
    }
    for (p, r) in running.rules() {
        if !candidate.rules().any(|(_, n)| n.id == r.id) {
            out.push(Change {
                kind: Kind::Removed,
                what: format!("rule {} \"{}\"", r.id, r.name),
                detail: rule_summary(p, r),
            });
        }
    }

    let by_id = |v: &[Forward]| -> BTreeMap<String, Forward> {
        v.iter().map(|f| (f.id.clone(), f.clone())).collect()
    };
    named(
        &mut out,
        "port forward",
        &by_id(&running.nat.forward),
        &by_id(&candidate.nat.forward),
        forward_summary,
    );
    let by_id = |v: &[Outbound]| -> BTreeMap<String, Outbound> {
        v.iter().map(|o| (o.id.clone(), o.clone())).collect()
    };
    named(
        &mut out,
        "outbound nat",
        &by_id(&running.nat.outbound),
        &by_id(&candidate.nat.outbound),
        outbound_summary,
    );

    // The services the box runs.
    let dns = |c: &Config| -> BTreeMap<String, ox_schema::Dns> {
        c.dns
            .iter()
            .map(|d| ("resolver".to_string(), d.clone()))
            .collect()
    };
    named(&mut out, "dns", &dns(running), &dns(candidate), |d| {
        format!(
            "answers {}; forwards to {}; DNSSEC {}; {}{} local name(s); {} blocked name(s)",
            list(&d.zones),
            list(&d.upstream),
            if d.dnssec { "on" } else { "off" },
            d.domain
                .as_ref()
                .map(|x| format!("domain {x}; "))
                .unwrap_or_default(),
            d.hosts.len(),
            d.blocked.len()
        )
    });
    named(&mut out, "dhcp pool", &running.dhcp, &candidate.dhcp, |p| {
        format!(
            "{} to {}, kept for {}, {} fixed address(es){}",
            p.first,
            p.last,
            p.lease,
            p.statics.len(),
            if p.dns.is_empty() {
                String::new()
            } else {
                format!(", DNS {}", list(&p.dns))
            }
        )
    });
    if running.ipv6_autoconfig != candidate.ipv6_autoconfig {
        out.push(Change {
            kind: Kind::Changed,
            what: "ipv6 announcements".into(),
            detail: format!(
                "{} → {}",
                list(&running.ipv6_autoconfig),
                list(&candidate.ipv6_autoconfig)
            ),
        });
    }

    // Tunnels, then their peers one by one, so adding a device reads as
    // one added peer and not as a changed tunnel.
    let shell = |c: &Config| -> BTreeMap<String, (String, String, Option<u16>)> {
        c.wireguard
            .iter()
            .map(|(name, w)| {
                let addrs: Vec<_> = w.addresses.iter().map(|a| a.0).collect();
                (name.clone(), (w.zone.clone(), list(&addrs), w.listen_port))
            })
            .collect()
    };
    named(
        &mut out,
        "tunnel",
        &shell(running),
        &shell(candidate),
        |(zone, addrs, port)| {
            format!(
                "zone {zone} addresses {addrs}{}",
                port.map(|p| format!(" listening on udp/{p}"))
                    .unwrap_or_default()
            )
        },
    );
    let peers = |c: &Config| -> BTreeMap<String, ox_schema::WgPeer> {
        c.wireguard
            .iter()
            .flat_map(|(name, w)| {
                w.peers
                    .iter()
                    .map(move |p| (format!("{name} {}", p.name), p.clone()))
            })
            .collect()
    };
    named(
        &mut out,
        "tunnel peer",
        &peers(running),
        &peers(candidate),
        |p| {
            format!(
                "may use {}{}{}; key {}…",
                list(&p.allowed),
                p.endpoint
                    .map(|e| format!("; reached at {e}"))
                    .unwrap_or_default(),
                p.keepalive
                    .map(|k| format!("; keepalive {k} s"))
                    .unwrap_or_default(),
                p.public_key.chars().take(8).collect::<String>()
            )
        },
    );

    // A plan that says "no changes" for two different configs would be a
    // lie. This catches a setting added to the schema and not to this list.
    if out.is_empty() && running != candidate {
        out.push(Change {
            kind: Kind::Changed,
            what: "config".into(),
            detail:
                "something differs that this plan has no description for; compare the two files"
                    .into(),
        });
    }
    out
}

/// A flow seen on the network, one per line of a JSON Lines file:
/// `{"src":"10.20.4.17","dst":"10.30.0.8","proto":"tcp","dport":445,"in":"lan0.20","count":1204,"label":"finance-pc pool"}`
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: FlowProto,
    #[serde(default)]
    pub dport: Option<u16>,
    #[serde(rename = "in")]
    pub iif: String,
    /// How many times the flow was seen.
    #[serde(default)]
    pub count: Option<u64>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowProto {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

impl From<FlowProto> for L4 {
    fn from(p: FlowProto) -> L4 {
        match p {
            FlowProto::Tcp => L4::Tcp,
            FlowProto::Udp => L4::Udp,
            FlowProto::Icmp => L4::Icmp,
            FlowProto::Icmpv6 => L4::Icmpv6,
        }
    }
}

impl Flow {
    pub fn packet(&self) -> Packet {
        Packet {
            src: self.src,
            dst: self.dst,
            l4: self.proto.into(),
            dport: self.dport,
            iif: self.iif.clone(),
            box_addrs: vec![],
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    #[error("flows line {line}: {source}")]
    Parse {
        line: usize,
        source: serde_json::Error,
    },
    #[error("flows line {line}: {source}")]
    Explain { line: usize, source: ExplainError },
}

/// Parses a JSON Lines flow file. Blank lines and lines starting with `#` are skipped.
pub fn parse_flows(text: &str) -> Result<Vec<(usize, Flow)>, FlowError> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|(i, l)| {
            serde_json::from_str(l)
                .map(|f| (i + 1, f))
                .map_err(|source| FlowError::Parse {
                    line: i + 1,
                    source,
                })
        })
        .collect()
}

/// A flow whose verdict differs between the two rulesets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Impact {
    pub flow: Flow,
    pub before: Verdict,
    pub after: Verdict,
    /// The rule that decides in the candidate, or `None` for a default drop.
    pub rule: Option<String>,
}

impl fmt::Display for Impact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}  {} → {}  by {}",
            self.flow.packet(),
            self.before.as_str(),
            self.after.as_str(),
            self.rule.as_deref().unwrap_or("default drop")
        )?;
        if let Some(c) = self.flow.count {
            write!(f, "  · {c} flows")?;
        }
        if let Some(l) = &self.flow.label {
            write!(f, " · {l}")?;
        }
        Ok(())
    }
}

/// Replays flows through both rulesets and returns those whose verdict differs.
pub fn impact(
    running: &Ruleset,
    candidate: &Ruleset,
    flows: &[(usize, Flow)],
) -> Result<Vec<Impact>, FlowError> {
    let mut out = vec![];
    for (line, flow) in flows {
        let run = |rs| {
            explain(rs, &flow.packet()).map_err(|source| FlowError::Explain {
                line: *line,
                source,
            })
        };
        let (before, after) = (run(running)?, run(candidate)?);
        if before.verdict != after.verdict {
            out.push(Impact {
                flow: flow.clone(),
                before: before.verdict,
                after: after.verdict,
                rule: after.rule.map(|r| r.id),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ox_nft::compile;

    const BRANCH: &str = include_str!("../../../examples/branch.toml");
    const CANDIDATE: &str = include_str!("../../../examples/branch-candidate.toml");
    const FLOWS: &str = include_str!("../../../examples/flows.jsonl");

    fn load(toml: &str) -> Config {
        Config::from_toml(toml).unwrap()
    }

    #[test]
    fn identical_configs_have_no_changes() {
        assert!(diff(&load(BRANCH), &load(BRANCH)).is_empty());
    }

    #[test]
    fn the_candidate_adds_one_rule_and_narrows_another() {
        let changes = diff(&load(BRANCH), &load(CANDIDATE));
        let text: Vec<String> = changes.iter().map(ToString::to_string).collect();
        assert_eq!(changes.len(), 2, "{text:#?}");
        assert!(text[0].starts_with("+ rule r-0412") && text[0].contains("position 1"));
        assert!(text[1].starts_with("~ rule r-0388"));
        assert!(
            text[1].contains("service: smb, netbios, https → https"),
            "{}",
            text[1]
        );
    }

    #[test]
    fn reordering_and_removal_are_reported() {
        let mut c = load(BRANCH);
        c.policies[0].rules.swap(0, 1);
        let removed = c.policies[0].rules.pop().unwrap();
        c.addresses.remove("nas");
        c.addresses
            .insert("nas2".into(), vec!["10.30.0.41".parse().unwrap()]);
        let text: Vec<String> = diff(&load(BRANCH), &c)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(
            text.iter()
                .any(|t| t.contains("rule order: r-0388, r-0301 → r-0301, r-0388")),
            "{text:#?}"
        );
        assert!(
            text.iter()
                .any(|t| t.starts_with(&format!("- rule {}", removed.id)))
        );
        assert!(text.iter().any(|t| t.starts_with("- address group nas")));
        assert!(text.iter().any(|t| t.starts_with("+ address group nas2")));
    }

    #[test]
    fn impact_names_the_flows_the_candidate_blocks() {
        let flows = parse_flows(FLOWS).unwrap();
        let (running, candidate) = (
            compile(&load(BRANCH)).unwrap(),
            compile(&load(CANDIDATE)).unwrap(),
        );
        let hits = impact(&running, &candidate, &flows).unwrap();
        // The SMB and NetBIOS flows flip in IPv4 and IPv6; HTTPS and web traffic do not.
        assert_eq!(hits.len(), 4, "{hits:#?}");
        assert!(
            hits.iter()
                .all(|h| h.before == Verdict::Accept && h.after == Verdict::Drop)
        );
        assert!(hits.iter().all(|h| h.rule.as_deref() == Some("r-0412")));
        assert!(hits.iter().any(|h| h.flow.src.is_ipv6()));
        assert!(impact(&running, &running, &flows).unwrap().is_empty());
    }

    #[test]
    fn a_bad_flow_line_is_named() {
        let err = parse_flows("{\"src\":\"10.0.0.1\"}\n").unwrap_err();
        assert!(err.to_string().starts_with("flows line 1"));
    }
}

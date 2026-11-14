//! Answers "what happens to this packet, and why" against a compiled ruleset.
//!
//! The packet is treated as the first of a new connection. Packets of an
//! established connection are accepted by connection tracking before any
//! policy runs, so they have nothing to explain.
//!
//! Routing is limited to what the config states: the box's own addresses,
//! the networks on its interfaces, and the default route. Static and dynamic
//! routes are not in schema 1, so a destination behind one shows "no route".

use std::{fmt, net::IpAddr};

use ox_nft::{L4, Ruleset};
use ox_schema::{Action, SELF_ZONE, Translate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub l4: L4,
    /// Destination port. Required for TCP and UDP, ignored for ICMP.
    pub dport: Option<u16>,
    /// The interface the packet arrives on.
    pub iif: String,
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} → {} {}", self.src, self.dst, self.l4.as_str())?;
        if let Some(p) = self.dport.filter(|_| matches!(self.l4, L4::Tcp | L4::Udp)) {
            write!(f, "/{p}")?;
        }
        write!(f, " in {}", self.iif)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Reject,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Accept => "ACCEPT",
            Verdict::Drop => "DROP",
            Verdict::Reject => "REJECT",
        }
    }
}

impl From<Action> for Verdict {
    fn from(a: Action) -> Verdict {
        match a {
            Action::Accept => Verdict::Accept,
            Action::Drop => Verdict::Drop,
            Action::Reject => Verdict::Reject,
        }
    }
}

/// One stage the packet went through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub label: &'static str,
    pub value: String,
    pub detail: String,
}

/// The rule that decided the verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matched {
    pub id: String,
    pub name: String,
    pub reason: Option<String>,
    /// 1-based position in its zone pair.
    pub position: usize,
    pub of: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    pub verdict: Verdict,
    pub steps: Vec<Step>,
    /// `None` when no rule matched and a default decided.
    pub rule: Option<Matched>,
}

impl fmt::Display for Explanation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "verdict  {}", self.verdict.as_str())?;
        for (i, s) in self.steps.iter().enumerate() {
            writeln!(f, "{:>2} {:<10} {}", i + 1, s.label, s.value)?;
            if !s.detail.is_empty() {
                writeln!(f, "   {:<10} {}", "", s.detail)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplainError {
    UnknownInterface { name: String, known: Vec<String> },
    MixedFamilies,
    PortNeeded,
    WrongIcmp,
}

impl fmt::Display for ExplainError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ExplainError::UnknownInterface { name, known } => write!(
                f,
                "interface '{name}' is not in the config; it has {}",
                known.join(", ")
            ),
            ExplainError::MixedFamilies => {
                f.write_str("source and destination must both be IPv4 or both be IPv6")
            }
            ExplainError::PortNeeded => f.write_str("TCP and UDP packets need a destination port"),
            ExplainError::WrongIcmp => {
                f.write_str("use icmp with IPv4 addresses and icmpv6 with IPv6 addresses")
            }
        }
    }
}

impl std::error::Error for ExplainError {}

struct Trace {
    steps: Vec<Step>,
}

impl Trace {
    fn step(&mut self, label: &'static str, value: impl Into<String>, detail: impl Into<String>) {
        self.steps.push(Step {
            label,
            value: value.into(),
            detail: detail.into(),
        });
    }

    fn end(self, verdict: Verdict, rule: Option<Matched>) -> Explanation {
        Explanation {
            verdict,
            steps: self.steps,
            rule,
        }
    }
}

/// Where the routing in the config sends a destination.
enum Route<'a> {
    Local,
    Via {
        iface: &'a str,
        zone: &'a str,
        how: String,
    },
    None,
}

fn route<'a>(rs: &'a Ruleset, dst: IpAddr) -> Route<'a> {
    if rs
        .interfaces
        .iter()
        .any(|i| i.addrs.iter().any(|a| a.addr() == dst))
    {
        return Route::Local;
    }
    let connected = rs
        .interfaces
        .iter()
        .flat_map(|i| i.addrs.iter().map(move |a| (i, a.trunc())))
        .filter(|(_, net)| net.contains(&dst))
        .max_by_key(|(_, net)| net.prefix_len());
    if let Some((i, net)) = connected {
        return Route::Via {
            iface: &i.name,
            zone: &i.zone,
            how: format!("{net} is connected"),
        };
    }
    let default = rs
        .interfaces
        .iter()
        .find(|i| i.default_route && i.addrs.iter().any(|a| a.addr().is_ipv4() == dst.is_ipv4()));
    match default {
        Some(i) => Route::Via {
            iface: &i.name,
            zone: &i.zone,
            how: "default route".to_string(),
        },
        None => Route::None,
    }
}

/// Explains one packet against a ruleset.
pub fn explain(rs: &Ruleset, p: &Packet) -> Result<Explanation, ExplainError> {
    if p.src.is_ipv4() != p.dst.is_ipv4() {
        return Err(ExplainError::MixedFamilies);
    }
    match p.l4 {
        L4::Tcp | L4::Udp if p.dport.is_none() => return Err(ExplainError::PortNeeded),
        L4::Icmp if p.src.is_ipv6() => return Err(ExplainError::WrongIcmp),
        L4::Icmpv6 if p.src.is_ipv4() => return Err(ExplainError::WrongIcmp),
        _ => {}
    }
    let Some(ingress) = rs.interfaces.iter().find(|i| i.name == p.iif) else {
        return Err(ExplainError::UnknownInterface {
            name: p.iif.clone(),
            known: rs.interfaces.iter().map(|i| i.name.clone()).collect(),
        });
    };

    let mut t = Trace { steps: vec![] };
    t.step("ingress", format!("{} → zone {}", p.iif, ingress.zone), "");

    // Destination NAT runs before routing, so everything after sees the new destination.
    let (mut dst, mut dport) = (p.dst, p.dport);
    if let Some(f) = rs
        .forwards
        .iter()
        .find(|f| f.matches(&ingress.zone, p.dst, p.l4, p.dport))
    {
        dst = f.to;
        dport = f.to_port.or(p.dport);
        t.step(
            "forward",
            format!("{} {}", f.id, f.name),
            format!(
                "destination becomes {dst}{}; filter rule {} must still accept it",
                dport.map(|d| format!(" port {d}")).unwrap_or_default(),
                f.rule
            ),
        );
    }

    let (to_zone, egress) = match route(rs, dst) {
        Route::Local => {
            t.step(
                "route",
                "to the box itself",
                format!("{dst} is one of its addresses"),
            );
            (SELF_ZONE, None)
        }
        Route::Via { iface, zone, how } => {
            t.step("route", format!("out {iface} → zone {zone}"), how);
            (zone, Some(iface))
        }
        Route::None => {
            t.step(
                "route",
                "no route",
                format!(
                    "{dst} is on no interface network and there is no default route for its family"
                ),
            );
            return Ok(t.end(Verdict::Drop, None));
        }
    };

    let Some(chain) = rs.chain(&ingress.zone, to_zone) else {
        t.step(
            "zone pair",
            format!("{} → {to_zone}", ingress.zone),
            "no policy for this pair, so the base chain drops the packet and logs it",
        );
        return Ok(t.end(Verdict::Drop, None));
    };
    t.step(
        "zone pair",
        format!("{} → {}", chain.from, chain.to),
        format!(
            "{} rule{}, first match wins",
            chain.rules.len(),
            if chain.rules.len() == 1 { "" } else { "s" }
        ),
    );

    let hit = chain
        .rules
        .iter()
        .enumerate()
        .find(|(_, r)| r.matches(p.src, dst, p.l4, dport));
    let Some((index, rule)) = hit else {
        t.step(
            "rule",
            "none matched, default drop",
            if chain.log_default {
                "logged"
            } else {
                "not logged"
            },
        );
        return Ok(t.end(Verdict::Drop, None));
    };
    let matched = Matched {
        id: rule.id.clone(),
        name: rule.name.clone(),
        reason: rule.reason.clone(),
        position: index + 1,
        of: chain.rules.len(),
    };
    let mut detail = format!("position {} of {}", matched.position, matched.of);
    if let Some(r) = &rule.reason {
        detail.push_str(&format!(" · {r}"));
    }
    if rule.log {
        detail.push_str(" · logged");
    }
    t.step(
        "rule",
        format!("{} {} · {}", rule.id, rule.action.as_str(), rule.name),
        detail,
    );
    let verdict = Verdict::from(rule.action);

    // Source NAT only applies to packets that are let through to another zone.
    if verdict == Verdict::Accept
        && let Some(egress) = egress
        && let Some(o) = rs
            .outbound
            .iter()
            .find(|o| o.matches(&ingress.zone, to_zone, p.src))
    {
        let to = match o.translate {
            Translate::Masquerade => format!("the address of {egress}"),
            Translate::Address(a) => a.to_string(),
        };
        t.step(
            "source nat",
            format!("{} {}", o.id, o.name),
            format!("source becomes {to}"),
        );
    }
    Ok(t.end(verdict, Some(matched)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ox_nft::compile;
    use ox_schema::Config;

    const BRANCH: &str = include_str!("../../../examples/branch.toml");
    const CANDIDATE: &str = include_str!("../../../examples/branch-candidate.toml");

    fn ruleset(toml: &str) -> Ruleset {
        compile(&Config::from_toml(toml).unwrap()).unwrap()
    }

    fn packet(src: &str, dst: &str, l4: L4, dport: Option<u16>, iif: &str) -> Packet {
        Packet {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            l4,
            dport,
            iif: iif.to_string(),
        }
    }

    fn run(toml: &str, p: &Packet) -> Explanation {
        explain(&ruleset(toml), p).unwrap()
    }

    /// The demo from the spec: the same packet is accepted by the running
    /// config and dropped by the candidate, in both address families.
    #[test]
    fn the_candidate_flips_smb_to_the_file_server() {
        for (src, dst) in [
            ("10.20.4.17", "10.30.0.8"),
            ("2001:db8:4a00:1:4::17", "2001:db8:4a00:2::8"),
        ] {
            let p = packet(src, dst, L4::Tcp, Some(445), "lan0.20");
            let before = run(BRANCH, &p);
            assert_eq!(before.verdict, Verdict::Accept, "{src}");
            let rule = before.rule.unwrap();
            assert_eq!((rule.id.as_str(), rule.position, rule.of), ("r-0388", 1, 3));
            assert!(rule.reason.unwrap().contains("CHG-1984"));

            let after = run(CANDIDATE, &p);
            assert_eq!(after.verdict, Verdict::Drop, "{src}");
            assert_eq!(after.rule.unwrap().id, "r-0412");

            // HTTPS to the same server is untouched by the candidate.
            let https = packet(src, dst, L4::Tcp, Some(443), "lan0.20");
            assert_eq!(run(BRANCH, &https).verdict, Verdict::Accept);
            assert_eq!(run(CANDIDATE, &https).rule.unwrap().id, "r-0388");
        }
    }

    #[test]
    fn no_match_falls_to_the_default_drop() {
        for (src, dst) in [
            ("10.20.7.7", "10.30.0.99"),
            ("2001:db8:4a00:1::77", "2001:db8:4a00:2::99"),
        ] {
            let e = run(BRANCH, &packet(src, dst, L4::Tcp, Some(22), "lan0.20"));
            assert_eq!(e.verdict, Verdict::Drop);
            assert!(e.rule.is_none());
            assert!(e.steps.last().unwrap().value.contains("default drop"));
        }
    }

    #[test]
    fn a_pair_without_a_policy_is_dropped() {
        let e = run(
            BRANCH,
            &packet("10.50.0.9", "10.20.0.5", L4::Tcp, Some(443), "lan0.50"),
        );
        assert_eq!(e.verdict, Verdict::Drop);
        assert!(e.steps.last().unwrap().detail.contains("no policy"));
    }

    #[test]
    fn a_port_forward_still_needs_its_filter_rule() {
        let p = packet("198.51.100.7", "203.0.113.10", L4::Tcp, Some(443), "wan0");
        let e = run(BRANCH, &p);
        assert_eq!(e.verdict, Verdict::Accept);
        assert_eq!(e.rule.unwrap().id, "r-0200");
        assert!(
            e.steps
                .iter()
                .any(|s| s.label == "forward" && s.detail.contains("10.30.0.10"))
        );

        // Take the web server out of the rule's destination: the forward alone lets nothing in.
        let closed = BRANCH.replace("web = [\"10.30.0.10\",", "web = [\"10.30.0.11\",");
        assert_eq!(run(&closed, &p).verdict, Verdict::Drop);

        // No forward exists for IPv6; the same rule accepts the server's own address.
        let v6 = packet(
            "2001:db8:ffff::7",
            "2001:db8:4a00:2::10",
            L4::Tcp,
            Some(443),
            "wan0",
        );
        let e = run(BRANCH, &v6);
        assert_eq!(e.verdict, Verdict::Accept);
        assert!(e.steps.iter().all(|s| s.label != "forward"));
    }

    #[test]
    fn outbound_nat_applies_to_ipv4_only_here() {
        let v4 = run(
            BRANCH,
            &packet("10.20.3.3", "198.51.100.9", L4::Tcp, Some(443), "lan0.20"),
        );
        assert_eq!(v4.verdict, Verdict::Accept);
        assert!(
            v4.steps
                .iter()
                .any(|s| s.label == "source nat" && s.detail.contains("wan0"))
        );

        let v6 = run(
            BRANCH,
            &packet(
                "2001:db8:4a00:1::33",
                "2001:db8:ffff::9",
                L4::Tcp,
                Some(443),
                "lan0.20",
            ),
        );
        assert_eq!(v6.verdict, Verdict::Accept);
        assert!(v6.steps.iter().all(|s| s.label != "source nat"));
    }

    #[test]
    fn traffic_to_the_box_uses_the_self_policy() {
        let admin = run(
            BRANCH,
            &packet("10.20.1.5", "10.20.0.1", L4::Tcp, Some(22), "lan0.20"),
        );
        assert_eq!(admin.rule.unwrap().id, "r-0001");
        let staff = run(
            BRANCH,
            &packet("10.20.7.7", "10.20.0.1", L4::Tcp, Some(22), "lan0.20"),
        );
        assert_eq!(staff.verdict, Verdict::Drop);

        let ping4 = run(
            BRANCH,
            &packet("10.20.7.7", "10.20.0.1", L4::Icmp, None, "lan0.20"),
        );
        assert_eq!(ping4.rule.unwrap().id, "r-0002");
        let ping6 = run(
            BRANCH,
            &packet(
                "2001:db8:4a00:1::77",
                "2001:db8:4a00:1::1",
                L4::Icmpv6,
                None,
                "lan0.20",
            ),
        );
        assert_eq!(ping6.rule.unwrap().id, "r-0002");
    }

    #[test]
    fn bad_questions_are_refused() {
        let rs = ruleset(BRANCH);
        let e = explain(
            &rs,
            &packet("10.20.1.5", "10.30.0.8", L4::Tcp, Some(1), "eth9"),
        )
        .unwrap_err();
        assert!(e.to_string().contains("lan0.20"));
        let e = explain(
            &rs,
            &packet("10.20.1.5", "2001:db8::1", L4::Tcp, Some(1), "lan0.20"),
        );
        assert_eq!(e.unwrap_err(), ExplainError::MixedFamilies);
        let e = explain(
            &rs,
            &packet("10.20.1.5", "10.30.0.8", L4::Tcp, None, "lan0.20"),
        );
        assert_eq!(e.unwrap_err(), ExplainError::PortNeeded);
        let e = explain(
            &rs,
            &packet("10.20.1.5", "10.30.0.8", L4::Icmpv6, None, "lan0.20"),
        );
        assert_eq!(e.unwrap_err(), ExplainError::WrongIcmp);
    }

    #[test]
    fn a_destination_with_no_route_is_dropped() {
        // The guest interface has no IPv6 address and wan0 carries the only default route,
        // so strip the default route to leave IPv4 internet destinations unreachable.
        let toml = BRANCH.replace("default_route = true\n", "");
        let e = run(
            &toml,
            &packet("10.20.3.3", "198.51.100.9", L4::Tcp, Some(443), "lan0.20"),
        );
        assert_eq!(e.verdict, Verdict::Drop);
        assert_eq!(e.steps.last().unwrap().value, "no route");
    }
}

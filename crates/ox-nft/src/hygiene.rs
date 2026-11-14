//! Finds rules that can never match, rules that add nothing, and rules that
//! allow more than their name suggests.
//!
//! Everything here is worked out from the config alone. Whether a rule has
//! seen traffic is a separate question that needs the kernel's counters.

use ox_schema::Action;

use crate::{AddrMatch, CRule, Ruleset, SvcMatch};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An earlier rule with a different action takes all of this rule's traffic.
    Shadowed,
    /// An earlier rule with the same action already covers this rule.
    Redundant,
    /// The rule accepts everything from anyone to anywhere.
    AllowsEverything,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Shadowed => "shadowed",
            Kind::Redundant => "redundant",
            Kind::AllowsEverything => "allows everything",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub from: String,
    pub to: String,
    pub rule: String,
    pub kind: Kind,
    pub detail: String,
}

impl AddrMatch {
    /// True when every address `other` matches is matched by `self` too.
    pub fn covers(&self, other: &AddrMatch) -> bool {
        match (self, other) {
            (AddrMatch::Any, _) => true,
            (AddrMatch::Nets { .. }, AddrMatch::Any) => false,
            (AddrMatch::Nets { v4: a4, v6: a6 }, AddrMatch::Nets { v4: b4, v6: b6 }) => {
                b4.iter().all(|b| a4.iter().any(|a| a.contains(b)))
                    && b6.iter().all(|b| a6.iter().any(|a| a.contains(b)))
            }
        }
    }
}

impl SvcMatch {
    /// True when every packet `other` matches is matched by `self` too.
    pub fn covers(&self, other: &SvcMatch) -> bool {
        if self.any {
            return true;
        }
        if other.any {
            return false;
        }
        (!other.icmp || self.icmp)
            && (!other.icmpv6 || self.icmpv6)
            && other.ports.iter().all(|(proto, first, last)| {
                self.ports
                    .iter()
                    .any(|(p, a, b)| p == proto && a <= first && last <= b)
            })
    }
}

impl CRule {
    /// True when this rule matches every packet `other` matches.
    pub fn covers(&self, other: &CRule) -> bool {
        self.src.covers(&other.src) && self.dst.covers(&other.dst) && self.svc.covers(&other.svc)
    }
}

/// Checks every zone pair of a ruleset.
pub fn hygiene(rs: &Ruleset) -> Vec<Finding> {
    let mut out = vec![];
    for chain in &rs.chains {
        for (i, rule) in chain.rules.iter().enumerate() {
            let mut add = |kind, detail: String| {
                out.push(Finding {
                    from: chain.from.clone(),
                    to: chain.to.clone(),
                    rule: rule.id.clone(),
                    kind,
                    detail,
                });
            };
            // First match wins, so one earlier rule that covers this one
            // decides all of its traffic.
            if let Some(earlier) = chain.rules[..i].iter().find(|e| e.covers(rule)) {
                if earlier.action == rule.action {
                    add(
                        Kind::Redundant,
                        format!(
                            "{} already {}s everything this rule matches; it can be removed",
                            earlier.id,
                            earlier.action.as_str()
                        ),
                    );
                } else {
                    add(
                        Kind::Shadowed,
                        format!(
                            "{} {}s everything this rule matches first, so this rule never applies",
                            earlier.id,
                            earlier.action.as_str()
                        ),
                    );
                }
                continue;
            }
            if rule.action == Action::Accept
                && rule.src == AddrMatch::Any
                && rule.dst == AddrMatch::Any
                && rule.svc.any
            {
                add(
                    Kind::AllowsEverything,
                    format!(
                        "accepts every packet from {} to {}; rules after it in this pair never apply",
                        chain.from, chain.to
                    ),
                );
            }
        }
    }
    out
}

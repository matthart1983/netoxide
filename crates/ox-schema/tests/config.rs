//! The example configs load, round-trip, and bad documents fail with the
//! problem named.

use ox_schema::{Config, LoadError};

const BRANCH: &str = include_str!("../../../examples/branch.toml");
const CANDIDATE: &str = include_str!("../../../examples/branch-candidate.toml");

fn problems(toml: &str) -> Vec<String> {
    match Config::from_toml(toml) {
        Err(LoadError::Invalid(p)) => p.iter().map(ToString::to_string).collect(),
        Err(e) => vec![e.to_string()],
        Ok(_) => vec![],
    }
}

/// The smallest config the mutations below start from.
const MINI: &str = r#"
schema = 1
hostname = "t"
[zones.lan]
[zones.wan]
[interfaces.lan0]
zone = "lan"
addresses = ["10.0.0.1/24", "2001:db8:1::1/64"]
[interfaces.wan0]
zone = "wan"
addresses = ["192.0.2.2/30", "2001:db8::2/64"]
default_route = true
[addresses]
v4 = ["10.0.0.0/24"]
v6 = ["2001:db8:1::/64"]
[[policy]]
from = "lan"
to = "wan"
[[policy.rule]]
id = "r-1"
name = "out"
action = "accept"
"#;

#[test]
fn examples_are_valid() {
    let branch = Config::from_toml(BRANCH).unwrap();
    assert_eq!(branch.rules().count(), 8);
    let candidate = Config::from_toml(CANDIDATE).unwrap();
    assert_eq!(candidate.rules().count(), 9);
}

#[test]
fn toml_and_json_round_trip() {
    let config = Config::from_toml(BRANCH).unwrap();
    assert_eq!(Config::from_toml(&config.to_toml()).unwrap(), config);
    let json = serde_json::to_string(&config).unwrap();
    assert_eq!(Config::from_json(&json).unwrap(), config);
}

#[test]
fn schema_describes_the_top_level() {
    let schema = Config::json_schema();
    let props = schema["properties"].as_object().unwrap();
    for key in [
        "schema",
        "hostname",
        "zones",
        "interfaces",
        "addresses",
        "services",
        "policy",
        "nat",
    ] {
        assert!(props.contains_key(key), "schema lacks {key}");
    }
}

#[test]
fn minimal_config_is_valid() {
    assert_eq!(problems(MINI), Vec::<String>::new());
}

#[test]
fn unknown_fields_are_refused() {
    let p = problems(&MINI.replace("hostname = \"t\"", "hostname = \"t\"\nhostnme = \"x\""));
    assert!(p[0].contains("hostnme"), "{p:?}");
}

#[test]
fn bad_values_name_the_value() {
    let p = problems(&MINI.replace(
        "action = \"accept\"",
        "action = \"accept\"\nservice = [\"tcp/99999\"]",
    ));
    assert!(p[0].contains("tcp/99999"), "{p:?}");
}

#[test]
fn references_must_exist() {
    let p = problems(&MINI.replace(
        "action = \"accept\"",
        "action = \"accept\"\nsource = [\"@nope\"]\nservice = [\"nope\"]",
    ));
    assert!(p.iter().any(|m| m.contains("'@nope'")), "{p:?}");
    assert!(p.iter().any(|m| m.contains("service 'nope'")), "{p:?}");
    let p = problems(&MINI.replace("to = \"wan\"", "to = \"dmz\""));
    assert!(
        p.iter().any(|m| m.contains("zone 'dmz' is not defined")),
        "{p:?}"
    );
}

#[test]
fn rule_ids_are_unique() {
    let extra = "[[policy.rule]]\nid = \"r-1\"\nname = \"again\"\naction = \"drop\"\n";
    let p = problems(&format!("{MINI}{extra}"));
    assert!(p.iter().any(|m| m.contains("already used")), "{p:?}");
}

#[test]
fn mixed_families_can_never_match() {
    for (src, dst) in [("@v4", "@v6"), ("@v6", "@v4")] {
        let p = problems(&MINI.replace(
            "action = \"accept\"",
            &format!("action = \"accept\"\nsource = [\"{src}\"]\ndestination = [\"{dst}\"]"),
        ));
        assert!(
            p.iter().any(|m| m.contains("can never match")),
            "{src} {dst}: {p:?}"
        );
    }
}

#[test]
fn icmp_must_fit_the_address_family() {
    let p = problems(&MINI.replace(
        "action = \"accept\"",
        "action = \"accept\"\nsource = [\"@v6\"]\nservice = [\"icmp\"]",
    ));
    assert!(p.iter().any(|m| m.contains("use icmpv6")), "{p:?}");
    let p = problems(&MINI.replace(
        "action = \"accept\"",
        "action = \"accept\"\nsource = [\"@v4\"]\nservice = [\"icmpv6\"]",
    ));
    assert!(p.iter().any(|m| m.contains("use icmp")), "{p:?}");
}

#[test]
fn a_forward_must_name_an_accept_rule_from_its_zone() {
    let fwd = |addr: &str, to: &str, rule: &str| {
        format!(
            "{MINI}[[nat.forward]]\nid = \"n-1\"\nname = \"f\"\nfrom = \"wan\"\naddress = \"{addr}\"\nservice = \"tcp/443\"\nto = \"{to}\"\nrule = \"{rule}\"\n"
        )
    };
    // r-1 is in policy lan → wan, so a forward from wan cannot use it.
    for (addr, to) in [("192.0.2.2", "10.0.0.5"), ("2001:db8::2", "2001:db8:1::5")] {
        let p = problems(&fwd(addr, to, "r-1"));
        assert!(
            p.iter().any(|m| m.contains("not a policy from 'wan'")),
            "{p:?}"
        );
        let p = problems(&fwd(addr, to, "r-9"));
        assert!(p.iter().any(|m| m.contains("does not exist")), "{p:?}");
    }
    let p = problems(&fwd("192.0.2.2", "2001:db8:1::5", "r-1"));
    assert!(
        p.iter().any(|m| m.contains("different address families")),
        "{p:?}"
    );
}

#[test]
fn wrong_schema_version_is_refused() {
    let p = problems(&MINI.replace("schema = 1", "schema = 2"));
    assert!(p.iter().any(|m| m.contains("reads schema 1")), "{p:?}");
}

/// `schema/netoxide-config-1.schema.json` is the published schema. Regenerate
/// it with `cargo run -p ox-cli -- schema` when the config types change.
#[test]
fn the_published_schema_is_current() {
    let published: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schema/netoxide-config-1.schema.json"
    ))
    .unwrap();
    assert!(
        published == Config::json_schema(),
        "schema/netoxide-config-1.schema.json is stale"
    );
}

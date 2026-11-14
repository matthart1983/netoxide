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

const HOME: &str = include_str!("../../../examples/home.toml");

#[test]
fn the_home_example_with_dns_and_dhcp_is_valid_and_round_trips() {
    let config = Config::from_toml(HOME).unwrap();
    assert_eq!(config.dns.as_ref().unwrap().hosts.len(), 2);
    assert_eq!(config.dhcp["eth1"].statics.len(), 1);
    assert_eq!(Config::from_toml(&config.to_toml()).unwrap(), config);
}

#[test]
fn a_service_needs_a_rule_that_lets_its_clients_in() {
    // Take DNS and DHCP out of the rule that allows them.
    let closed = HOME.replace("service = [\"dns\", \"dhcp\"]", "service = [\"tcp/8080\"]");
    let p = problems(&closed);
    assert!(
        p.iter()
            .any(|m| m.contains("no rule in lan → self accepts DNS")),
        "{p:?}"
    );
    assert!(
        p.iter()
            .any(|m| m.contains("no rule in lan → self accepts DHCP")),
        "{p:?}"
    );
    // UDP alone is not enough for DNS: large answers come over TCP.
    let udp_only = HOME.replace("dns = [\"udp/53\", \"tcp/53\"]", "dns = [\"udp/53\"]");
    assert!(
        problems(&udp_only)
            .iter()
            .any(|m| m.contains("accepts DNS"))
    );
}

#[test]
fn dhcp_pools_must_fit_their_network() {
    let with = |first: &str, last: &str| {
        HOME.replace(
            "first = \"192.168.10.100\"\nlast = \"192.168.10.199\"",
            &format!("first = \"{first}\"\nlast = \"{last}\""),
        )
    };
    for (first, last, needle) in [
        ("192.168.10.200", "192.168.10.100", "runs backwards"),
        (
            "192.168.11.100",
            "192.168.11.199",
            "not a usable address on 192.168.10.0/24",
        ),
        ("192.168.10.1", "192.168.10.50", "the box's own address"),
        ("192.168.10.100", "192.168.10.255", "not a usable address"),
    ] {
        let p = problems(&with(first, last));
        assert!(
            p.iter().any(|m| m.contains(needle)),
            "{first}-{last}: {p:?}"
        );
    }
    let p = problems(&HOME.replace("dhcp.eth1", "dhcp.eth9"));
    assert!(
        p.iter()
            .any(|m| m.contains("dhcp eth9: this interface is not defined")),
        "{p:?}"
    );
    let p = problems(&HOME.replace("dhcp.eth1", "dhcp.eth0"));
    assert!(p.iter().any(|m| m.contains("no IPv4 address")), "{p:?}");
}

#[test]
fn static_leases_and_names_are_checked() {
    let second = "\n[[dhcp.eth1.static]]\nmac = \"aa:bb:cc:dd:ee:01\"\naddress = \"192.168.10.5\"\nname = \"my nas\"\n";
    let p = problems(&format!("{HOME}{second}"));
    assert!(
        p.iter().any(|m| m.contains("more than one static lease")),
        "{p:?}"
    );
    assert!(
        p.iter()
            .any(|m| m.contains("given to more than one device")),
        "{p:?}"
    );
    assert!(p.iter().any(|m| m.contains("name 'my nas'")), "{p:?}");
    let p = problems(&HOME.replace("mac = \"aa:bb:cc:dd:ee:01\"", "mac = \"aa:bb:cc\""));
    assert!(p[0].contains("aa:bb:cc:dd:ee:ff"), "{p:?}");
    let p = problems(&HOME.replace(
        "last = \"192.168.10.199\"",
        "last = \"192.168.10.199\"\nlease = \"5s\"",
    ));
    assert!(p[0].contains("30m, 12h or 7d"), "{p:?}");
}

#[test]
fn dns_settings_are_checked() {
    let p = problems(&HOME.replace("zones = [\"lan\"]", "zones = [\"dmz\"]"));
    assert!(
        p.iter()
            .any(|m| m.contains("dns, zone dmz: this zone is not defined")),
        "{p:?}"
    );
    let p = problems(&HOME.replace(
        "upstream = [\"1.1.1.1\", \"9.9.9.9\", \"2606:4700:4700::1111\"]",
        "upstream = []",
    ));
    assert!(p.iter().any(|m| m.contains("upstream is empty")), "{p:?}");
    // Without the resolver, the pool has to say which DNS servers to hand out.
    let no_dns = HOME.split("[dns]").next().unwrap().to_string()
        + "[dhcp.eth1]\nfirst = \"192.168.10.100\"\nlast = \"192.168.10.199\"\n";
    let p = problems(&no_dns);
    assert!(
        p.iter().any(|m| m.contains("clients need a DNS server")),
        "{p:?}"
    );
}

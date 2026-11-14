//! Imports the sample pfSense backup and checks the translation against a
//! model of pfSense's own rule evaluation.

use ox_explain::Packet;
use ox_import::{ImportError, PfVerdict, import_pfsense};
use ox_nft::L4;

const BACKUP: &str = include_str!("../../../examples/pfsense-config.xml");

fn packet(src: &str, dst: &str, l4: L4, dport: Option<u16>, iif: &str) -> Packet {
    Packet {
        src: src.parse().unwrap(),
        dst: dst.parse().unwrap(),
        l4,
        dport,
        iif: iif.to_string(),
        box_addrs: vec![],
    }
}

#[test]
fn every_item_lands_in_one_list() {
    let r = import_pfsense(BACKUP).unwrap().report;
    assert_eq!(r.source, "pfSense config version 23.3");
    assert_eq!(
        (r.translated.len(), r.changed.len(), r.unsupported.len()),
        (11, 10, 10)
    );
    assert_eq!(r.total(), 31);

    let changed = |needle: &str| r.changed.iter().any(|c| c.from.contains(needle));
    assert!(changed("Floating rule 1"));
    assert!(changed("Implicit anti-lockout rule"));
    assert!(changed("Automatic outbound NAT"));
    assert!(changed("filter rule association \"Pass\""));

    let unsupported = |needle: &str| r.unsupported.iter().find(|u| u.item.contains(needle));
    assert!(
        unsupported("rule 6")
            .unwrap()
            .step
            .contains("negated match")
    );
    assert!(unsupported("rule 8").unwrap().step.contains("OFFICE_NETS"));
    assert!(unsupported("rule 12").unwrap().step.contains("esp"));
    for item in [
        "OpenVPN server",
        "Captive portal",
        "pfBlockerNG",
        "Static route",
        "Gateway group",
    ] {
        assert!(
            unsupported(item).is_some(),
            "{item} is missing from the report"
        );
    }
}

#[test]
fn the_result_is_a_valid_config_that_round_trips() {
    let config = import_pfsense(BACKUP).unwrap().config;
    assert!(config.validate().is_empty());
    assert_eq!(
        ox_schema::Config::from_toml(&config.to_toml()).unwrap(),
        config
    );
    assert_eq!(config.hostname, "fw-par-02");
    assert_eq!(
        config.zones.keys().collect::<Vec<_>>(),
        ["dmz", "guest-wifi", "lan", "wan"]
    );
    // A pfSense rule sits on its ingress interface; here it sits in a zone pair.
    let pair = config
        .policies
        .iter()
        .find(|p| p.from == "lan" && p.to == "dmz")
        .unwrap();
    let ids: Vec<&str> = pair.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "r-0001-lan-dmz",
            "r-0002",
            "r-0003-dmz",
            "r-0004-dmz",
            "r-0005-dmz",
            "r-0011-dmz"
        ],
        "the floating rule comes first, then the interface rules in order"
    );
    assert!(
        !pair.rules.last().unwrap().enabled,
        "a disabled rule stays disabled"
    );
    assert_eq!(config.nat.forward.len(), 2);
    assert_eq!(config.nat.forward[0].rule, "r-0009");
    assert_eq!(config.nat.outbound.len(), 3);
}

/// The differential check: every probe gets the same verdict from the model
/// of pfSense and from the translated config, with one known exception.
#[test]
fn pfsense_and_the_translation_agree_on_every_probe() {
    let imported = import_pfsense(BACKUP).unwrap();
    let probes = imported.probes();
    assert!(probes.len() > 100, "only {} probes", probes.len());
    assert!(
        probes.iter().any(|p| p.src.is_ipv6()),
        "IPv6 rules must be probed too"
    );

    let diffs = imported.verify(&probes);
    let lines: Vec<String> = diffs.iter().map(ToString::to_string).collect();
    // The "Pass" association cannot be expressed exactly: the explicit rule
    // also lets in packets sent straight to the internal host. The report says so.
    assert_eq!(lines.len(), 1, "{lines:#?}");
    assert!(
        lines[0].contains("10.30.0.11") && lines[0].contains("r-fwd-2"),
        "{}",
        lines[0]
    );
}

#[test]
fn verify_names_packets_an_untranslated_rule_would_have_decided() {
    let imported = import_pfsense(BACKUP).unwrap();
    // Rule 6 (negated match) let guests reach the internet on 443. It was left out.
    let guest = packet("10.50.1.23", "198.51.100.9", L4::Tcp, Some(443), "igb2.50");
    let diffs = imported.verify(std::slice::from_ref(&guest));
    assert_eq!(diffs.len(), 1);
    assert!(matches!(&diffs[0].pfsense, PfVerdict::Untranslated(by) if by.contains("rule 6")));

    // Both families of the default LAN rule agree.
    let lan = [
        packet("10.40.7.7", "198.51.100.9", L4::Tcp, Some(443), "igb1"),
        packet(
            "2001:db8:4a00:1::77",
            "2001:db8:ffff::9",
            L4::Tcp,
            Some(443),
            "igb1",
        ),
    ];
    assert!(imported.verify(&lan).is_empty());
}

#[test]
fn other_files_are_refused_by_name() {
    assert!(matches!(
        import_pfsense("<opnsense></opnsense>"),
        Err(ImportError::Opnsense)
    ));
    assert!(matches!(
        import_pfsense("<html></html>"),
        Err(ImportError::NotPfsense(_))
    ));
    assert!(matches!(
        import_pfsense("not xml"),
        Err(ImportError::Xml(_))
    ));
    assert!(matches!(
        import_pfsense("<pfsense><version>1</version></pfsense>"),
        Err(ImportError::NoInterfaces)
    ));
}

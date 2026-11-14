//! The rendered dnsmasq config, checked by reading it and, where dnsmasq is
//! installed, by dnsmasq's own syntax check.

use std::process::Command;

use ox_schema::Config;
use ox_services::{dnsmasq_conf, parse_leases};

const HOME: &str = include_str!("../../../examples/home.toml");

fn lines(conf: &str) -> Vec<&str> {
    conf.lines().filter(|l| !l.starts_with('#')).collect()
}

#[test]
fn a_config_without_services_renders_nothing() {
    let branch = include_str!("../../../examples/branch.toml");
    assert_eq!(dnsmasq_conf(&Config::from_toml(branch).unwrap()), None);
}

#[test]
fn the_home_example_renders_dns_and_dhcp() {
    let conf = dnsmasq_conf(&Config::from_toml(HOME).unwrap()).unwrap();
    let l = lines(&conf);
    for want in [
        "no-resolv",
        "interface=eth1",
        "server=1.1.1.1",
        "server=2606:4700:4700::1111",
        "dnssec",
        "domain=home.arpa",
        "local=/home.arpa/",
        "host-record=nas.home.arpa,nas,192.168.10.5",
        "host-record=nas.home.arpa,nas,2001:db8:2::5",
        "dhcp-range=interface:eth1,192.168.10.100,192.168.10.199,255.255.255.0,43200",
        "dhcp-host=aa:bb:cc:dd:ee:01,192.168.10.5,nas",
        "dhcp-authoritative",
    ] {
        assert!(l.contains(&want), "missing `{want}` in:\n{conf}");
    }
    assert!(
        !l.iter().any(|x| x.starts_with("interface=eth0")),
        "the internet side is never served"
    );
    assert!(!l.iter().any(|x| x.starts_with("port=")));
    assert!(
        !l.iter().any(|x| x.contains("dns-server")),
        "the box hands out itself by default"
    );
}

#[test]
fn dhcp_alone_turns_the_resolver_off_and_names_the_servers_to_use() {
    // Everything before [dns], then a pool that names its own resolvers.
    let toml = HOME.split("[dns]").next().unwrap().to_string()
        + "[dhcp.eth1]\nfirst = \"192.168.10.100\"\nlast = \"192.168.10.199\"\nlease = \"30m\"\ndns = [\"1.1.1.1\", \"9.9.9.9\"]\n";
    let conf = dnsmasq_conf(&Config::from_toml(&toml).unwrap()).unwrap();
    let l = lines(&conf);
    assert!(l.contains(&"port=0"), "{conf}");
    assert!(
        l.contains(&"dhcp-option=tag:eth1,option:dns-server,1.1.1.1,9.9.9.9"),
        "{conf}"
    );
    assert!(
        l.contains(&"dhcp-range=interface:eth1,192.168.10.100,192.168.10.199,255.255.255.0,1800")
    );
    assert!(!l.iter().any(|x| x.starts_with("server=")));
}

#[test]
fn dnssec_can_be_turned_off() {
    let toml = HOME.replace("upstream = ", "dnssec = false\nupstream = ");
    let conf = dnsmasq_conf(&Config::from_toml(&toml).unwrap()).unwrap();
    assert!(!conf.contains("dnssec") && !conf.contains("trust-anchor"));
}

#[test]
fn rendering_depends_on_the_config_alone() {
    let config = Config::from_toml(HOME).unwrap();
    assert_eq!(dnsmasq_conf(&config), dnsmasq_conf(&config));
    // No file paths: the daemon supplies those when it starts the process.
    assert!(!dnsmasq_conf(&config).unwrap().contains("leasefile"));
}

/// dnsmasq's own parser accepts what we write.
#[test]
fn dnsmasq_accepts_the_rendered_config() {
    let ok = Command::new("dnsmasq")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        skip("dnsmasq is not installed");
        return;
    }
    let dhcp_only = HOME.split("[dns]").next().unwrap().to_string()
        + "[dhcp.eth1]\nfirst = \"192.168.10.100\"\nlast = \"192.168.10.199\"\ndns = [\"1.1.1.1\"]\n";
    for (name, toml) in [("home", HOME.to_string()), ("dhcp-only", dhcp_only)] {
        let conf = dnsmasq_conf(&Config::from_toml(&toml).unwrap()).unwrap();
        let path =
            std::env::temp_dir().join(format!("ox-dnsmasq-{name}-{}.conf", std::process::id()));
        std::fs::write(&path, &conf).unwrap();
        let out = Command::new("dnsmasq")
            .arg("--test")
            .arg(format!("--conf-file={}", path.display()))
            .output()
            .unwrap();
        std::fs::remove_file(&path).ok();
        assert!(
            out.status.success(),
            "{name}: dnsmasq refused the config:\n{}\n{conf}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn lease_files_are_read() {
    let rows = parse_leases(
        "1794700000 aa:bb:cc:dd:ee:01 192.168.10.5 nas 01:aa:bb:cc:dd:ee:01\n\
         1794700100 aa:bb:cc:dd:ee:02 192.168.10.101 * *\n\
         duid 00:01:00:01:2f:aa:bb:cc:aa:bb:cc:dd:ee:ff\n\
         garbage\n",
    );
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[0].address.as_str(), rows[0].name.as_deref()),
        ("192.168.10.5", Some("nas"))
    );
    assert_eq!(rows[1].name, None);
}

/// Notes a test that cannot run here. With OX_REQUIRE_KERNEL_TESTS set, as
/// in CI, a skip is a failure, so these tests cannot silently stop running.
fn skip(why: &str) {
    assert!(
        std::env::var_os("OX_REQUIRE_KERNEL_TESTS").is_none(),
        "this test was required but could not run: it {why}"
    );
    eprintln!("skipped: {why}");
}

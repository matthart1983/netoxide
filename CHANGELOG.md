# Changelog

Releases are listed newest first. Versions follow [semantic versioning](https://semver.org). Before 1.0, a minor version may change the config schema, the API or the command line; each such change is listed under "Changed" with what to do about it.

## 0.1.0 (not yet released)

The first preview. A single-box firewall and router that passes its tests in network namespaces and in a virtual machine under systemd. It has not run on hardware and has had no outside security audit. See [docs/status.md](docs/status.md) for the limits.

### What is in it

- **Config.** One typed TOML or JSON document per box, schema version 1, with a published JSON Schema. Zones, interfaces, address groups, services, zone-pair rules, port forwards, outbound NAT, DNS, DHCP and WireGuard tunnels. IPv4 and IPv6 in the same rules.
- **Compiler.** A config becomes one nftables ruleset built from sets and verdict maps, loaded as an atomic transaction.
- **Daemon `oxd`.** Named candidates, plan, commit, a confirm window with automatic revert, rollback, and a history of the last 100 commits. A daemon that restarts with an unconfirmed commit reverts it.
- **Audit log.** Hash-chained. A damaged log is repaired or set aside and never stops the firewall loading.
- **Router functions.** Interface addresses and default routes over netlink, packet forwarding, an internet-side address by DHCP, IPv6 router announcements, DNS and DHCP through dnsmasq.
- **VLANs.** An interface can be a tagged network on a port (`vlan = { parent, id }`). The box creates it and removes it.
- **VPN.** WireGuard over the kernel's netlink interface, with `ox vpn add` to add a device in one step.
- **Explain and plan.** What happens to one packet and which rule decides; what a candidate changes and which observed flows would get a different verdict.
- **Guided setup and one-step changes.** `ox init`, `ox forward`, `ox block`.
- **Interfaces.** The `ox` command line tool, a terminal UI with six live screens, and a web UI served by the daemon over HTTPS.
- **Access control.** The Unix socket identifies the caller from the kernel. The HTTPS listener takes access tokens with roles. A role is a set of actions that can be held to the firewall, network, services or VPN part of the config. Four-eyes approval is optional.
- **Remote management.** `ox --remote <name>` and the terminal UI over HTTPS, with the box's certificate pinned by fingerprint.
- **Listener limits.** 256 connections, 32 per IPv4 address or IPv6 /64, 30 seconds for request headers, closed after 120 seconds with no bytes.
- **Import.** pfSense `config.xml` to a config and a report, checked against a model of the pfSense ruleset.
- **Monitoring.** Prometheus metrics and a rule hygiene report.
- **Install.** A sandboxed systemd unit and install steps in `dist/`, exercised by a virtual machine test.

### Known gaps

- Never run on real hardware. SELinux and AppArmor enforcing are untested.
- No bridge, bond or PPPoE creation. No DHCPv6 prefix delegation.
- No multi-WAN, routing protocols, traffic shaping, intrusion detection or high availability.
- WireGuard only, untested against the official apps. No peer may be allowed `0.0.0.0/0`.
- No single sign-on. No fleet controller, Terraform provider or OS image.
- Token expiry and the undo timer follow the wall clock. The audit chain has no key.

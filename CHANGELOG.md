# Changelog

Releases are listed newest first. Versions follow [semantic versioning](https://semver.org). Before 1.0, a minor version may change the config schema, the API or the command line; each such change is listed under "Changed" with what to do about it.

## 0.1.0 (15 November 2026)

The first preview. A single-box firewall and router that passes its tests in network namespaces and in a virtual machine under systemd. It has not run on hardware and has had no outside security audit. See [docs/status.md](docs/status.md) for the limits.

### What is in it

- **Licence.** MIT.
- **No unsafe code.** The daemon loads rules by running the `nft` program with a fixed argument list and the ruleset on standard input. Nothing links libnftables.

- **Config.** One typed TOML or JSON document per box, schema version 1, with a published JSON Schema. Zones, interfaces, address groups, services, zone-pair rules, port forwards, outbound NAT, DNS, DHCP and WireGuard tunnels. IPv4 and IPv6 in the same rules.
- **Compiler.** A config becomes one nftables ruleset built from sets and verdict maps, loaded as an atomic transaction.
- **Daemon `oxd`.** Named candidates, plan, commit, a confirm window with automatic revert, rollback, and a history of the last 100 commits. A daemon that restarts with an unconfirmed commit reverts it.
- **Audit log.** Hash-chained. A damaged log is repaired or set aside and never stops the firewall loading.
- **Router functions.** Interface addresses and default routes over netlink, packet forwarding, an internet-side address by DHCP, IPv6 router announcements, DNS and DHCP through dnsmasq.
- **VLANs.** An interface can be a tagged network on a port (`vlan = { parent, id }`). The box creates it and removes it.
- **Blocking.** `ox block` drops everything a device sends, given its address, or stops every device looking up a website, given its name.
- **Install script.** `dist/install.sh` installs, starts and prints the setup code; `--remove` takes it off. `docs/proxmox.md` covers a VM on Proxmox.
- **Backup and restore.** `ox backup` and `ox restore` move a box to other hardware with its VPN keys, roles and settings.
- **VPN.** WireGuard over the kernel's netlink interface, with `ox vpn add` to add a device in one step, and a QR code for phones.
- **Explain and plan.** What happens to one packet and which rule decides; what a candidate changes and which observed flows would get a different verdict.
- **Simple by default.** The web interface and the terminal UI open on Home, Access, Review and Settings; the detailed screens are opt-in switches. The terminal UI does the everyday tasks from a menu and fits an 80×24 terminal. `ox --help` shows the everyday commands, with `ox apply`, `ox keep` and `ox undo` in plain words.
- **Setup from a browser**, with a one-time code shown on the box.
- **Guided setup and one-step changes.** `ox init`, `ox forward`, `ox block`, `ox access`, and `ox network add` for a guest or camera network kept apart from the rest.
- **Interfaces.** The `ox` command line tool, a terminal UI, and a web UI served by the daemon over HTTPS.
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

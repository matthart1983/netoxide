# What works, limits and what is not built

An honest list. Read the limits before you rely on anything here.

- [Easy path and advanced path](#easy-path-and-advanced-path)
- [What works today](#what-works-today)
- [Limits today](#limits-today)
- [Not built yet](#not-built-yet)

## Easy path and advanced path

Each area has an easy path and an advanced path over the same config.

| Area | Easy path | Advanced path |
| --- | --- | --- |
| Setup | `ox init` asks which port faces the internet and writes a complete starter config. **Works today** | Write the config file. **Works today** |
| Rules | `ox forward` and `ox block` do it in one step and show the result first. **Work today.** "Add a guest network" is planned | Zone-pair rules, address groups, services, NAT. **Works today** |
| Changes | Apply, with automatic undo if you lock yourself out. **Works today** | Named candidates, plan with flow impact, rollback, four-eyes approval. **Work today** |
| Understanding | Press `x` on a rule in the terminal UI to see what it does to a packet. **Works today** | `ox explain` for any packet, against running and candidate. **Works today.** Live trace is planned |
| Interface | Web UI and terminal UI. **Work today** | CLI and HTTP API with tokens and roles, from the box or from another machine. **Work today.** Terraform provider is planned |
| Scale | One box with no extra parts. **Works today** | Fleet controller, templates, staged rollouts. **Planned** |

## What works today

| Piece | What it does |
| --- | --- |
| Config schema | One typed TOML or JSON document per box: zones, interfaces, address groups, services, zone-pair filter rules, port forwards, outbound NAT, a DNS resolver and DHCP pools. Validation reports every problem with its location. The JSON Schema is published in [`schema/`](../schema/netoxide-config-1.schema.json). |
| Rule compiler | Turns a config into an nftables ruleset built from sets and verdict maps, loaded as one atomic transaction. IPv4 and IPv6 in the same rules. |
| Daemon `oxd` | Owns the config. Stores candidates, applies commits to the kernel through the `nft` program, runs the confirm clock, and serves an HTTP and JSON API on a Unix socket. |
| Commit-confirm | A commit made with a confirm window reverts by itself unless confirmed. The revert replays the previous commit. It does not reboot. A daemon restart with a commit still unconfirmed also reverts it. |
| Rollback and history | The last 100 commits are kept with author, time, reason and the SHA-256 of the config. Rollback is a new commit with an old config. |
| DNS and DHCP | The box answers DNS for its inside networks, with DNSSEC checking and local names, and hands out IPv4 addresses with fixed addresses per device. They are applied and reverted together with the firewall rules. Served by dnsmasq, which the daemon starts and restarts. |
| Lockdown | With `oxd --lockdown`, a box with no config drops inbound and forwarded traffic until the first commit. |
| Web UI | The daemon serves a browser interface over HTTPS: what the box does in plain sentences, rules with packet counts, NAT, network and leases, changes with plan, approve and commit with an undo timer, explain, audit, and settings. Forward a port, block a device or edit the config from it. |
| Access control | The local socket identifies the caller from the kernel. The HTTPS listener needs an access token with a role. A role is a set of actions and can be held to parts of the config, so a network admin cannot change firewall rules and a helpdesk can only add VPN devices. Four-eyes approval can require a second person before a commit. |
| Remote management | `ox --remote <name>` and the terminal UI manage a box from another machine over HTTPS. A box's own certificate is checked by a saved fingerprint, as SSH does with host keys. |
| Health | Prometheus metrics at `/metrics`, and a hygiene report of rules that never apply, add nothing, allow everything, or have seen no packets. |
| VLANs | An interface with `vlan = { parent = "eth1", id = 20 }` is created by the box as a tagged network on that port, and removed when the config drops it. An interface something else made is used and never removed. |
| Simple by default | The web interface opens on Home, Live, Access and Settings. Access is a grid of who can reach what, computed from the real config; a pair with rules of its own is read-only there. Every change is reviewed in a sentence and applied with a two-minute undo timer. The detailed screens are switches in Settings. `ox --help` shows a dozen everyday commands and `ox more` the rest. The terminal UI has the same four plain screens and the same tasks, with its detailed screens as switches on its Settings screen. |
| Live view | Home, Live, Access and Settings are the plain screens. Live shows download, upload, traffic per network, tracked connections and blocked packets, one reading a second for the last two minutes, in the browser and the terminal. Every number is a kernel counter: interface byte counters over netlink, the connection-tracking count, and the packet counters of the rules that drop. Each pair of networks with no rules between them now has a counted drop of its own, so a block is named by network. Readings are taken only while someone is watching. |
| Install script | `dist/install.sh` installs the programs and the service on a systemd Linux machine, turns on the web interface, and prints the setup code. `--remove` takes it off. The VM test installs and removes with it. [`proxmox.md`](proxmox.md) has the steps for a VM on Proxmox, which nobody has followed on Proxmox itself. |
| Packages | A `.deb` and an `.rpm` for x86-64, built by `dist/package.sh`. Installing one starts the daemon; removing it stops the daemon and takes its rules out of the kernel. CI installs both in clean containers of Debian 12 and 13, Ubuntu 22.04 and 24.04, Fedora and AlmaLinux 9, loads a real ruleset with each distribution\'s own `nft`, and removes them. `dist/package-systemd-test.sh` installs each under a real systemd in a container. |
| Block a website | `ox block example.com`, or the web task, makes the box's resolver refuse a name and everything under it. `ox unblock` lifts it. Checked with real DNS queries over IPv4 and IPv6. |
| Add a network | One step (`ox network add`, or the web task) makes a network of its own for guests or cameras: a VLAN in its own zone, an address pool and DNS if the box serves them, and internet access if asked for. It reaches none of the other networks until that is allowed in the grid. |
| Setup from a browser | A box with no config can be set up from its web page with a code that only someone on the box can read. Setup answers only private and local addresses, shuts after ten wrong codes and shuts for good once a config runs. |
| Backup and restore | `ox backup` saves the running config together with what is deliberately not in the config: the VPN private keys, the roles made on the box and the four-eyes setting. `ox restore` on another box puts those in place and saves the config as a candidate, so devices that already trust the old box's VPN key keep connecting. Access tokens are not carried over. |
| Addresses and routes | On a commit the daemon puts the config's addresses on their interfaces, brings those links up, sets the default route through the `gateway` you name, and turns on packet forwarding, over netlink. It takes an address or route off again when a later config drops it or a commit fails, and only ever the ones it added itself. |
| Port forwards that follow the address | A forward with no `address` applies to whatever address the box has, so it keeps working when the provider changes it. `ox forward` and the web form write that when the internet port has no fixed address. |
| VPN | WireGuard tunnels, using the kernel's own implementation over netlink. A tunnel is an interface in a zone, so ordinary policies decide what crosses it. `ox vpn add laptop --endpoint home.example.net` sets a VPN up, adds the device and prints the config file for its WireGuard app. Two boxes can join their networks the same way. The box's private key never leaves its state directory. |
| Internet-side address | With `dhcp_client = true` the box asks the provider's network for its IPv4 address and router, renews the lease, and asks for the same address after a restart. `ox init` sets this up when you say the provider assigns the address. |
| IPv6 and own traffic | The box can announce its IPv6 network so devices configure themselves, and policies from `self` filter what the box itself sends. |
| Audit log | Every candidate save, commit, confirm and revert is appended to a hash-chained log. Editing or deleting a line breaks the chain, and the log says which line. Entries cut off the end are noticed too. A damaged log never stops the firewall loading: it is repaired or set aside, and the damage becomes the next entry. |
| Plan | Lists what a candidate changes, and replays observed flows through both configs to show which would get a different verdict. |
| Explain | Says what happens to one packet and which rule decides: port forward, route, zone pair, rule, source NAT. Works for the running config and for a candidate that is not applied. |
| pfSense import | Translates a `config.xml` backup into a config and a report, then checks its own translation against a model of the pfSense ruleset. |
| CLI `ox` | Drives all of the above. |
| TUI | Eleven live screens backed by the daemon. Five plain ones fit an 80×24 terminal: Home with a menu of tasks, Live with braille plots of traffic and blocks, Access as a grid you can change, Review with a two-minute safe apply, and Settings. The tasks are the web UI's: add a network, let something in, add a VPN device, block a device or a website, and check whether something is blocked. Six detailed ones are switches on Settings: Policy with kernel packet counters, NAT, Interfaces, Changes, Explain and Audit. It cannot edit a single rule and has no first-run setup. A separate mock mode shows the eleven designed screens with sample data. |

## Limits today

- **Access control is new and has had no outside audit.** Tokens, roles, four-eyes and the HTTPS listener are tested. One internal review pass found no way around them and eleven other defects, which are fixed except the two listed next. Roles held to sections and `ox` over HTTPS had one internal pass of their own. It found that a network-only role could move a port into another zone, and four smaller defects; all five are fixed with tests. Nobody outside this project has reviewed any of it. There is no single sign-on (OIDC): access is by token.
- **Known and not fixed.** Token expiry and the undo timer use the wall clock, so a box whose clock jumps backwards extends both. The audit chain has no key, so someone who can write the state directory can rewrite the log and its head together; shipping the head off the box would close that. The HTTPS listener holds at most 256 connections, 32 from one IPv4 address or IPv6 /64, gives a caller 30 seconds to send a request's headers, and closes a connection after 120 seconds with no bytes; that bounds what the daemon spends, and someone with enough addresses can still keep others out of the listener while they try.
- **Sections are coarse.** There are four, split by top-level config key. A role cannot be held to one zone pair or one interface. A role held to the VPN section chooses the networks a peer may send from, and a rule that matches on source address inside the VPN zone will trust those. A saved fingerprint is trusted without checking the certificate's dates.
- **An admin can get around four-eyes** by turning it off or making a second token. Both are in the audit log. Operators cannot.
- **An old `nft` with a much newer kernel can fail.** On a 7.1 kernel, the `nft` 1.0.2 to 1.0.9 that Debian 12 and Ubuntu 22.04 and 24.04 ship could not load the compiled rules ("Operation not supported"), while the same versions load them on the kernels those distributions ship, and AlmaLinux 9's `nft` 1.0.9 loads them on both. This matters if you run a distribution's userland on a much newer kernel. The daemon refuses the change, keeps what was running, and says to update `nftables`.
- **The packages have not been installed on hardware.** They are tested in containers, which share the test machine's kernel, and there is no apt or dnf repository yet.
- **Live shows less than its design.** There is no latency to the internet, no traffic per device and no destination names, because the box does not measure them yet. "Just blocked" names the networks and counts packets. It does not name the device or the port. Counts come from reading the ruleset once a second, so a block is seen up to a second late.
- **Live has only been watched in the namespace lab.** The traffic in the tests and the demo is real, made by a script between namespaces. Nobody has watched it on a box carrying ordinary traffic.
- **The terminal UI is driven by a script, not yet by people.** `tests/tui/run.sh` walks its plain screens against a real daemon with real rules in a namespace and checks each result with `ox`. It replays keys and reads the screen as text, so it does not show how the screens look in any particular terminal program, and nobody other than the author has used them.
- **The web UI is driven by a script, not yet by people.** `tests/web/run.sh` sets a blank box up from the setup code and walks every screen in headless Chrome and Firefox, against real rules in a namespace. Nobody other than its author has used it, and no person has been watched setting a box up for the first time.
- **Nothing is loaded before the first commit** unless you start `oxd --lockdown`, so by default the kernel's own defaults apply until then.
- **DNS and DHCP are new.** They are tested end to end in a namespace: `dig` against the resolver over IPv4 and IPv6, and a small DHCP client that gets a pool address and a fixed address through the firewall. No real device has used them. Websites can be blocked by name one at a time; there are no downloaded blocklists, and a device that uses another DNS server is not affected. There is no dynamic DNS, IPv6 is announce-only (no DHCPv6), and the daemon runs dnsmasq directly, not as a sandboxed systemd unit as the spec asks.
- **dnsmasq is the only backend.** Unbound and Kea are planned. The config does not name the program, so they can be added without changing configs.
- **Interfaces are only partly managed.** The daemon creates VLAN interfaces and removes the ones it made. It does not create bridge, bond or PPPoE interfaces; the operating system still does. VLANs cannot be stacked. Stop the operating system's own network manager on the ports you give to Netoxide, or the two will both set addresses.
- **The internet side is IPv4 DHCP or fixed addresses.** For IPv6 the box takes an address from the provider's router advertisements. It does not ask for a delegated prefix (DHCPv6-PD), so the inside network gets IPv6 only if you have a fixed prefix. The DNS servers a lease names are shown and not used; the resolver forwards to the servers in the config.
- **The box's own traffic is allowed out unless you filter it.** Write a policy from `self` to a zone to filter what the box sends there.
- **The systemd unit and the install steps have run only in the test VM**, with SELinux off and virtual network cards.
- **Long zone pairs lose per-rule counters.** A pair that needs more than 32 nftables rules is merged: neighbouring rules with the same action become one set lookup and share a counter, so the TUI shows no packet count for them. Rules that log, match ICMP or any service, or overlap a neighbour are not merged. A pair that is still over 32 after merging is refused.
- **Explain knows only connected networks and the default route.** A destination behind a static or dynamic route shows "no route".
- **The VPN is WireGuard only, and plain.** No IPsec or OpenVPN. A peer's `allowed` cannot be everything (`0.0.0.0/0`): sending all of the box's traffic through a tunnel needs policy routing, which is not built. A device can still send all of *its* traffic through the box if you add a policy from the VPN zone to the internet and an outbound NAT for it by hand. There are no preshared keys. A phone can scan the config as a QR code (`ox vpn add --qr`, or the web UI); the code was read back by a decoder library in the tests, not by a phone. The tunnel has been tested between two Netoxide daemons, not yet against the official WireGuard apps.
- **Schema 1 has no routing protocols, traffic shaping, schedules or HA.**
- **The importer reads pfSense only** and has not been tested on a real backup.
- **Nothing has run on real hardware or under real traffic.** The furthest it has been is a virtual machine on one developer's computer.

## Not built yet

Roughly in the order planned:

1. Running it on real hardware, with SELinux enforcing, and a first deployment that is watched.
2. Services as sandboxed systemd units, and Unbound and Kea as backends beside dnsmasq.
3. Rule editing and first-run setup in the terminal UI, and live trace.
4. IPsec, and for WireGuard: all traffic through a tunnel, preshared keys.
5. Single sign-on (OIDC), and roles held to single zones or interfaces.
6. Multi-WAN, routing protocols, traffic shaping, IDS.
7. OPNsense import, and the pfSense importer tested on real backups.
8. HA, the fleet controller, a Terraform provider, and the OS image with signed A/B upgrades.
9. An independent security audit before any 1.0.

There is no date for a 1.0.

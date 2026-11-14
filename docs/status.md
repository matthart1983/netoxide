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
| Daemon `oxd` | Owns the config. Stores candidates, applies commits to the kernel through libnftables, runs the confirm clock, and serves an HTTP and JSON API on a Unix socket. |
| Commit-confirm | A commit made with a confirm window reverts by itself unless confirmed. The revert replays the previous commit. It does not reboot. A daemon restart with a commit still unconfirmed also reverts it. |
| Rollback and history | The last 100 commits are kept with author, time, reason and the SHA-256 of the config. Rollback is a new commit with an old config. |
| DNS and DHCP | The box answers DNS for its inside networks, with DNSSEC checking and local names, and hands out IPv4 addresses with fixed addresses per device. They are applied and reverted together with the firewall rules. Served by dnsmasq, which the daemon starts and restarts. |
| Lockdown | With `oxd --lockdown`, a box with no config drops inbound and forwarded traffic until the first commit. |
| Web UI | The daemon serves a browser interface over HTTPS: what the box does in plain sentences, rules with packet counts, NAT, network and leases, changes with plan, approve and commit with an undo timer, explain, audit, and settings. Forward a port, block a device or edit the config from it. |
| Access control | The local socket identifies the caller from the kernel. The HTTPS listener needs an access token with a role. A role is a set of actions and can be held to parts of the config, so a network admin cannot change firewall rules and a helpdesk can only add VPN devices. Four-eyes approval can require a second person before a commit. |
| Remote management | `ox --remote <name>` and the terminal UI manage a box from another machine over HTTPS. A box's own certificate is checked by a saved fingerprint, as SSH does with host keys. |
| Health | Prometheus metrics at `/metrics`, and a hygiene report of rules that never apply, add nothing, allow everything, or have seen no packets. |
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
| TUI | Six live screens backed by the daemon: Policy with kernel packet counters, NAT, Interfaces, Changes, Explain and Audit. You can commit, confirm and undo from it. A separate mock mode shows the eleven designed screens with sample data. |

## Limits today

- **Access control is new and has had no outside audit.** Tokens, roles, four-eyes and the HTTPS listener are tested. One internal review pass found no way around them and eleven other defects, which are fixed except the two listed next. Roles held to sections and `ox` over HTTPS had one internal pass of their own. It found that a network-only role could move a port into another zone, and four smaller defects; all five are fixed with tests. Nobody outside this project has reviewed any of it. There is no single sign-on (OIDC): access is by token.
- **Known and not fixed.** Token expiry and the undo timer use the wall clock, so a box whose clock jumps backwards extends both. The audit chain has no key, so someone who can write the state directory can rewrite the log and its head together; shipping the head off the box would close that. The HTTPS listener holds at most 256 connections, 32 from one IPv4 address or IPv6 /64, gives a caller 30 seconds to send a request's headers, and closes a connection after 120 seconds with no bytes; that bounds what the daemon spends, and someone with enough addresses can still keep others out of the listener while they try.
- **Sections are coarse.** There are four, split by top-level config key. A role cannot be held to one zone pair or one interface. A role held to the VPN section chooses the networks a peer may send from, and a rule that matches on source address inside the VPN zone will trust those. A saved fingerprint is trusted without checking the certificate's dates.
- **An admin can get around four-eyes** by turning it off or making a second token. Both are in the audit log. Operators cannot.
- **The web UI has been checked by hand in one browser.** Every screen and form was exercised in Chrome against a dry-run daemon: sign-in, overview, rules, NAT, a commit with its timer, forward a port, block a device, the config editor, explain against a candidate, creating and revoking a token, and making and deleting a role. There are no automated browser tests, and no other browser has been tried.
- **Nothing is loaded before the first commit** unless you start `oxd --lockdown`, so by default the kernel's own defaults apply until then.
- **DNS and DHCP are new.** They are tested end to end in a namespace: `dig` against the resolver over IPv4 and IPv6, and a small DHCP client that gets a pool address and a fixed address through the firewall. No real device has used them. There are no DNS blocklists, IPv6 is announce-only (no DHCPv6), and the daemon runs dnsmasq directly, not as a sandboxed systemd unit as the spec asks.
- **dnsmasq is the only backend.** The spec names Unbound and Kea. The config does not name the program, so they can be added without changing configs.
- **Interfaces are only partly managed.** The daemon does not create VLAN, bridge, bond or PPPoE interfaces; the operating system still does. Stop the operating system's own network manager on the ports you give to Netoxide, or the two will both set addresses.
- **The internet side is IPv4 DHCP or fixed addresses.** For IPv6 the box takes an address from the provider's router advertisements. It does not ask for a delegated prefix (DHCPv6-PD), so the inside network gets IPv6 only if you have a fixed prefix. The DNS servers a lease names are shown and not used; the resolver forwards to the servers in the config.
- **The box's own traffic is allowed out unless you filter it.** Write a policy from `self` to a zone to filter what the box sends there.
- **The systemd unit and the install steps have run only in the test VM**, with SELinux off and virtual network cards.
- **Long zone pairs lose per-rule counters.** A pair that needs more than 32 nftables rules is merged: neighbouring rules with the same action become one set lookup and share a counter, so the TUI shows no packet count for them. Rules that log, match ICMP or any service, or overlap a neighbour are not merged. A pair that is still over 32 after merging is refused.
- **Explain knows only connected networks and the default route.** A destination behind a static or dynamic route shows "no route".
- **The VPN is WireGuard only, and plain.** No IPsec or OpenVPN. A peer's `allowed` cannot be everything (`0.0.0.0/0`): sending all of the box's traffic through a tunnel needs policy routing, which is not built. A device can still send all of *its* traffic through the box if you add a policy from the VPN zone to the internet and an outbound NAT for it by hand. There are no preshared keys, and no QR code for phones: copy the config file over. The tunnel has been tested between two Netoxide daemons, not yet against the official WireGuard apps.
- **Schema 1 has no routing protocols, traffic shaping, schedules or HA.**
- **The importer reads pfSense only** and has not been tested on a real backup.
- **Nothing has run on real hardware or under real traffic.** The furthest it has been is a virtual machine on one developer's computer.

## Not built yet

Roughly in the order planned:

1. Running it on real hardware, with SELinux enforcing, and a first deployment that is watched.
2. Services as sandboxed systemd units, and Unbound and Kea as backends beside dnsmasq.
3. More one-step actions such as "add a guest network", rule editing in the terminal UI, and live trace.
4. IPsec, and for WireGuard: all traffic through a tunnel, preshared keys, a QR code.
5. Single sign-on (OIDC), and roles held to single zones or interfaces.
6. Multi-WAN, routing protocols, traffic shaping, IDS.
7. OPNsense import, and the pfSense importer tested on real backups.
8. HA, the fleet controller, a Terraform provider, and the OS image with signed A/B upgrades.
9. An independent security audit before any 1.0.

The spec dates a 1.0 at August 2028 for a team of six. That date is a plan, not a commitment.

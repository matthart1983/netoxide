# Netoxide

Netoxide is an open-source firewall and router OS for Linux with a Rust control plane. It is meant for two groups: home-lab users who want a firewall that is easy to set up on one box, and teams that run 10 to 300 firewalls across sites, mostly people moving off pfSense or OPNsense. The aim is one product that is easy to start with and keeps the advanced features within reach.

**Status: pre-alpha.** What exists today is a single-box firewall and router: a daemon that applies a typed config to the kernel through nftables, with commit, confirm, automatic revert, rollback and an audit log, plus DNS, DHCP, a web UI, a terminal UI, a CLI and a pfSense importer. It has been tested inside network namespaces against the real kernel. It has never run on real hardware or in front of a real network, and it has had no security audit. Do not put it in front of a network you care about.

- [Who it is for](#who-it-is-for)
- [What works today](#what-works-today)
- [Try it without touching your machine](#try-it-without-touching-your-machine)
- [Start from nothing](#start-from-nothing)
- [The config](#the-config)
- [How a change reaches the kernel](#how-a-change-reaches-the-kernel)
- [The terminal UI](#the-terminal-ui)
- [The web UI](#the-web-ui)
- [Access and roles](#access-and-roles)
- [Explain a packet](#explain-a-packet)
- [Import from pfSense](#import-from-pfsense)
- [Command reference](#command-reference)
- [API reference](#api-reference)
- [How it is built](#how-it-is-built)
- [Design rules](#design-rules)
- [Tests](#tests)
- [Limits today](#limits-today)
- [Install](#install)
- [Not built yet](#not-built-yet)
- [Documents](#documents)
- [Licence and name](#licence-and-name)

## Who it is for

Two groups, with one product for both:

- **Home-lab users and small offices** running one box, who want a firewall that is quick to set up, clear about what it is doing, and free in full.
- **Teams and service providers** running 10 to 300 firewalls, who want config as code, safe changes, an audit trail and fleet management.

The design rule is "easy first, advanced within reach". Each area has an easy path and an advanced path over the same config, so the easy path writes ordinary config that the advanced tools can read and change. Nothing a single box needs depends on a controller, a login server or a fleet feature.

| Area | Easy path | Advanced path |
| --- | --- | --- |
| Setup | `ox init` asks which port faces the internet and writes a complete starter config. **Works today** | Write the config file. **Works today** |
| Rules | `ox forward` and `ox block` do it in one step and show the result first. **Work today.** "Add a guest network" is planned | Zone-pair rules, address groups, services, NAT. **Works today** |
| Changes | Apply, with automatic undo if you lock yourself out. **Works today** | Named candidates, plan with flow impact, rollback, four-eyes approval. **Work today** |
| Understanding | Press `x` on a rule in the terminal UI to see what it does to a packet. **Works today** | `ox explain` for any packet, against running and candidate. **Works today.** Live trace is planned |
| Interface | Web UI and terminal UI. **Work today** | CLI and HTTP API with tokens and roles. **Work today.** Terraform provider is planned |
| Scale | One box with no extra parts. **Works today** | Fleet controller, templates, staged rollouts. **Planned** |

**If you run a home lab, be aware of where this is today.** The pieces of a home router are here: firewall, NAT, DNS, DHCP and a web UI, from a guided setup. None of it has run on real hardware yet, and there is no installer or OS image, so you install it by hand on an existing Linux machine ([`dist/README.md`](dist/README.md)). Treat it as something to try on a spare machine or VM with console access, not to put in front of your home network.

## Why

The pitch is that a buyer can check every claim. The source is public, the config has a published schema, every change is a transaction that can undo itself, and the firewall can say why it did what it did to a packet.

The research behind this is in [`docs/research/market-gap.md`](docs/research/market-gap.md). In short, no open firewall combines free stable releases, typed config with commit-confirm, fleet management in the open core, image upgrades and tested HA. The research also found no buyer asking for Rust by name. Rust is here for two reasons: a control plane that never builds a shell command, and memory-safe code on the network-facing side. Packets stay in the Linux kernel, and this project makes no performance claim.

## What works today

| Piece | What it does |
| --- | --- |
| Config schema | One typed TOML or JSON document per box: zones, interfaces, address groups, services, zone-pair filter rules, port forwards, outbound NAT, a DNS resolver and DHCP pools. Validation reports every problem with its location. The JSON Schema is published in [`schema/`](schema/netoxide-config-1.schema.json). |
| Rule compiler | Turns a config into an nftables ruleset built from sets and verdict maps, loaded as one atomic transaction. IPv4 and IPv6 in the same rules. |
| Daemon `oxd` | Owns the config. Stores candidates, applies commits to the kernel through libnftables, runs the confirm clock, and serves an HTTP and JSON API on a Unix socket. |
| Commit-confirm | A commit made with a confirm window reverts by itself unless confirmed. The revert replays the previous commit. It does not reboot. A daemon restart with a commit still unconfirmed also reverts it. |
| Rollback and history | The last 100 commits are kept with author, time, reason and the SHA-256 of the config. Rollback is a new commit with an old config. |
| DNS and DHCP | The box answers DNS for its inside networks, with DNSSEC checking and local names, and hands out IPv4 addresses with fixed addresses per device. They are applied and reverted together with the firewall rules. Served by dnsmasq, which the daemon starts and restarts. |
| Lockdown | With `oxd --lockdown`, a box with no config drops inbound and forwarded traffic until the first commit. |
| Web UI | The daemon serves a browser interface over HTTPS: what the box does in plain sentences, rules with packet counts, NAT, network and leases, changes with plan, approve and commit with an undo timer, explain, audit, and settings. Forward a port, block a device or edit the config from it. |
| Access control | The local socket identifies the caller from the kernel. The HTTPS listener needs an access token with a role: viewer, auditor, operator or admin. Four-eyes approval can require a second person before a commit. |
| Health | Prometheus metrics at `/metrics`, and a hygiene report of rules that never apply, add nothing, allow everything, or have seen no packets. |
| Addresses and routes | On a commit the daemon puts the config's addresses on their interfaces, brings those links up, sets the default route through the `gateway` you name, and turns on packet forwarding, over netlink. It takes an address or route off again when a later config drops it or a commit fails, and only ever the ones it added itself. |
| Internet-side address | With `dhcp_client = true` the box asks the provider's network for its IPv4 address and router, renews the lease, and asks for the same address after a restart. `ox init` sets this up when you say the provider assigns the address. |
| IPv6 and own traffic | The box can announce its IPv6 network so devices configure themselves, and policies from `self` filter what the box itself sends. |
| Audit log | Every candidate save, commit, confirm and revert is appended to a hash-chained log. Editing or deleting a line breaks the chain, and the log says which line. Entries cut off the end are noticed too. A damaged log never stops the firewall loading: it is repaired or set aside, and the damage becomes the next entry. |
| Plan | Lists what a candidate changes, and replays observed flows through both configs to show which would get a different verdict. |
| Explain | Says what happens to one packet and which rule decides: port forward, route, zone pair, rule, source NAT. Works for the running config and for a candidate that is not applied. |
| pfSense import | Translates a `config.xml` backup into a config and a report, then checks its own translation against a model of the pfSense ruleset. |
| CLI `ox` | Drives all of the above. |
| TUI | Six live screens backed by the daemon: Policy with kernel packet counters, NAT, Interfaces, Changes, Explain and Audit. You can commit, confirm and undo from it. A separate mock mode shows the eleven designed screens with sample data. |

## Try it without touching your machine

You need Rust 1.88 or later, `libnftables.so.1` (part of the `nftables` package), `unshare` from util-linux, and a kernel that allows unprivileged user namespaces.

Run the daemon in a private, rootless network namespace. It loads rules into that namespace's kernel tables, not the host's.

```sh
cargo build
export OX_SOCKET=/tmp/oxd.sock
unshare -Urn ./target/debug/oxd --state-dir /tmp/ox-state --socket $OX_SOCKET &
alias ox=./target/debug/ox
```

Make the first commit:

```sh
ox candidate save base examples/branch.toml
ox commit base --reason "first config"
```

That uses a ready-made example. On a real box you would start with the guided setup instead; see [Start from nothing](#start-from-nothing).

Propose a change, look at it, then apply it with a 30-second window:

```sh
ox candidate save block-legacy-smb examples/branch-candidate.toml
ox plan block-legacy-smb --flows examples/flows.jsonl
ox commit block-legacy-smb --confirm 30s --reason CHG-2207
ox status
```

Now do nothing. After 30 seconds `ox status` shows commit #1 running again and the kernel no longer holds the new rule. Commit again and run `ox confirm` inside the window to keep it. Then:

```sh
ox rollback 1 --reason "scanner broke"
ox history
ox audit
ox kernel      # the table exactly as the kernel holds it
```

**Warning.** Outside a namespace, `oxd` replaces the host's `netoxide` nftables table, and the config's default is to drop. Use `oxd --dry-run` if you want the API and state without loading anything.

## Start from nothing

`ox init` looks at the machine's network ports, asks which one faces the internet and which face your inside network, and writes a complete config:

```
$ ox init --save starter
Ports on this machine:

  eth0           up    203.0.113.10/24  ← reaches the internet now
  eth1           up    no address

Which port faces the internet? [eth0]:
Which ports face your inside network? (separate with spaces) [eth1]:
What address should the box have on eth1? [192.168.10.1/24]:

This config will do the following:

  eth0 is in zone wan (203.0.113.10/24)
  eth1 is in zone lan (192.168.10.1/24)
  lan → wan: everything from anyone to anywhere is allowed (r-inside-out)
  lan → wan: everything else is dropped
  lan → the box itself: ssh, ping from anyone to anywhere is allowed (r-manage)
  lan → the box itself: dns, dhcp from anyone to anywhere is allowed (r-services)
  lan → the box itself: everything else is dropped
  wan → the box itself: dhcpv6-client from fe80::/10 to anywhere is allowed (r-dhcpv6)
  wan → the box itself: everything else is dropped
  traffic from 192.168.10.0/24 leaving by wan appears to come from the box's own address (n-inside-out)
  the box answers DNS for lan, forwarding to 1.1.1.1, 9.9.9.9, with DNSSEC checking
  local names end in .home.arpa
  devices on eth1 get an address from 192.168.10.100 to 192.168.10.199, kept for 12h
  wan → lan: no rules, so everything is dropped

Saved as candidate starter. Nothing has been applied.
Next: ox plan starter  then  ox commit starter --confirm 5m
```

In short: the inside network can reach the internet and is hidden behind the box's address, devices inside get an address and DNS from the box, the box can be managed over SSH from inside only, and everything arriving from the internet is dropped. DNS and DHCP need `dnsmasq` installed; `ox init --no-services` leaves them out. Pass `--wan` and `--lan` to skip the questions, and `--out <file>` to write a file instead of saving a candidate. `ox init` only reads the machine. It changes nothing until you commit.

Two everyday changes are single commands. Each reads the running config, makes the change, and saves the result as a candidate for you to commit:

```sh
ox forward --name "Home Assistant" --port tcp/443 --to 192.168.10.20:8123
ox block 192.168.10.66 --name "Smart TV"
```

`ox forward` adds the port forward and the filter rule it needs, then checks with the explain engine that a packet from outside is accepted by that rule. If an earlier rule would have decided the packet first, it places the new rule ahead of it and says so. `ox block` drops and logs everything the device sends, to other networks and to the box.

The result of all three is ordinary config. You can open it, edit it by hand, and use every advanced command on it.

## The config

One document describes the box. This is a cut-down version of [`examples/branch.toml`](examples/branch.toml):

```toml
schema = 1
hostname = "syd-br-014-a"

[zones.lan]
[zones.dmz]
[zones.wan]

[interfaces.wan0]
zone = "wan"
addresses = ["203.0.113.10/32", "2001:db8:4a00::1/64"]
default_route = true

[interfaces."lan0.20"]
zone = "lan"
addresses = ["10.20.0.1/16", "2001:db8:4a00:1::1/64"]

[interfaces."lan0.30"]
zone = "dmz"
addresses = ["10.30.0.1/24", "2001:db8:4a00:2::1/64"]

[addresses]
finance-pcs = ["10.20.4.0/24", "2001:db8:4a00:1:4::/80"]
finance-file-servers = ["10.30.0.8", "10.30.0.9", "2001:db8:4a00:2::8"]
web = ["10.30.0.10", "2001:db8:4a00:2::10"]

[services]
smb = ["tcp/445", "tcp/139"]
https = ["tcp/443"]

[[policy]]              # one entry per zone pair; rules are tried in order
from = "lan"
to = "dmz"

[[policy.rule]]
id = "r-0388"
name = "Finance to file servers"
action = "accept"       # accept, drop or reject
source = ["@finance-pcs"]
destination = ["@finance-file-servers"]
service = ["smb", "https"]
reason = "Open file share for finance, CHG-1984"

[[policy]]
from = "wan"
to = "dmz"

[[policy.rule]]
id = "r-0200"
name = "Public web"
action = "accept"
destination = ["@web"]
service = ["https"]
log = true

[[nat.forward]]
id = "n-0010"
name = "Public web"
from = "wan"
address = "203.0.113.10"
service = "tcp/443"
to = "10.30.0.10"
rule = "r-0200"         # the filter rule that lets the translated packet in

[[nat.outbound]]
id = "n-0100"
name = "Staff to the internet"
from = "lan"
to = "wan"
source = ["10.20.0.0/16"]
translate = "masquerade"
```

How to read it:

- **Zones** group interfaces. Rules are written between two zones, never on one interface. `to = "self"` is traffic addressed to the box.
- **A zone pair with no policy is dropped.** So is anything that matches no rule in its pair, and that drop is logged unless `log_default = false`.
- **Sources and destinations** are `"any"`, `"@group"`, a network in CIDR form, or one address. **Services** are `"any"`, a name from `[services]`, or `tcp/443`, `udp/137-138`, `icmp`, `icmpv6`.
- **A port forward only rewrites the destination.** The packet still has to pass the filter rule named in `rule`, so there is no hidden pass rule.
- **Rule IDs are stable.** They appear in logs, in `ox explain` and in the kernel as the rule's comment.

DNS and DHCP are two more sections. This is from [`examples/home.toml`](examples/home.toml):

```toml
[dns]
zones = ["lan"]                        # who may use the resolver
upstream = ["1.1.1.1", "9.9.9.9"]      # where it forwards to
domain = "home.arpa"                   # nas is also nas.home.arpa

[[dns.host]]
name = "nas"
address = "192.168.10.5"

[dhcp.eth1]                            # one pool per interface
first = "192.168.10.100"
last = "192.168.10.199"
lease = "12h"

[[dhcp.eth1.static]]                   # this device always gets this address
mac = "aa:bb:cc:dd:ee:01"
address = "192.168.10.5"
name = "nas"
```

DNSSEC checking is on unless you set `dnssec = false`. Clients are told to use the box as their resolver and router. A service needs a visible rule like everything else: validation refuses a config that serves DNS or DHCP to a zone without an accept rule for it in that zone's policy to `self`, and says which rule to add.

Validation catches things like unknown zones and groups, duplicate rule IDs, rules whose source and destination are different address families, and a forward that names a rule from the wrong zone. A typo such as `tcp/99999` or `10.20.4.17/16` fails with the value named and the fix suggested.

## How a change reaches the kernel

1. `ox candidate save` stores a config under a name. The daemon refuses one that does not validate and compile.
2. `ox plan` shows the diff against the running config, the compiled size, and the flows whose verdict would change.
3. `ox commit` compiles the candidate, renders it as one nftables transaction, and loads it. If the kernel refuses any part, nothing changes.
4. With `--confirm`, the commit is running but pending. `ox confirm` keeps it. `ox revert`, the deadline, or a daemon restart undoes it by loading the previous commit.
5. The commit, its author, its reason and the config's hash go into the history and the audit log.

Plan output for the example candidate:

```
✓ schema validation passed
✓ compiled 9 rules in 5 zone pairs → 19 nftables rules, 27 sets, 2 verdict maps, longest chain 6
✓ one nftables transaction, atomic swap

2 change(s)
  + rule r-0412 "Drop SMB and NetBIOS": lan → dmz: drop any → any · smb, netbios, position 1
  ~ rule r-0388 "Finance to file servers": service: smb, netbios, https → https

4 of 8 replayed flows get a different verdict
  10.20.4.17 → 10.30.0.8 tcp/445 in lan0.20  ACCEPT → DROP  by r-0412  · 1204 flows · finance-pc pool
  10.20.4.33 → 10.30.0.9 tcp/139 in lan0.20  ACCEPT → DROP  by r-0412  · 88 flows · scanner-02
  ...
```

The flows file is JSON Lines, one observed flow per line. See [`examples/flows.jsonl`](examples/flows.jsonl). Nothing collects flows yet, so you supply the file.

## The terminal UI

```sh
cargo run -p netoxide-tui --release -- --socket $OX_SOCKET
```

It needs a terminal of at least 132×34. Everything on screen comes from the daemon and is read again once a second.

| Screen | Shows | Keys |
| --- | --- | --- |
| Policy | Zone pairs and their rules from the running config, with the kernel's packet counter per rule | `←→` pair, `↑↓` rule, `x` explain a packet the rule is about |
| NAT | Port forwards and outbound NAT | |
| Interfaces | Interfaces, zones and addresses from the running config | |
| Changes | Candidates, the plan for the selected one, the running commit | `c` commit, `w` confirm window |
| Explain | A packet you type, judged by the running config and the selected candidate side by side | `e` edit, `enter` run, `m` compare on or off |
| Audit | The audit log, newest first | `↑↓` |

`y` keeps an unconfirmed commit and `r` undoes it, from any screen. A commit from the TUI always has a confirm window (30 s, 2, 5 or 10 min) and asks for a reason first.

The TUI cannot edit rules or save candidates yet. Write the config in a file and use `ox candidate save`. Run it without `--socket` to see the eleven designed screens with sample data.

## The web UI

Start the daemon with an HTTPS listener and make a token:

```sh
oxd --listen 0.0.0.0:8443 ...
ox token create laptop --role operator --days 90
```

Open `https://<box>:8443/` and sign in with the token. The daemon makes its own certificate on first start, so the browser warns until you give it a real one with `--tls-cert` and `--tls-key`.

| View | What it shows |
| --- | --- |
| Overview | The running commit, services, and what the box does in plain sentences |
| Rules | Every zone pair with its rules, packet counts and hygiene notes |
| NAT | Port forwards and outbound NAT |
| Network | Interfaces, DNS, address pools and the addresses handed out |
| Changes | Candidates with their plan; forward a port, block a device, or edit the whole config with a check before saving; approve and commit with an undo timer |
| Explain | A packet you describe, judged by the running config and a candidate side by side |
| Audit | The audit log, newest first |
| Settings | Four-eyes approval and access tokens, for admins |

A commit waiting to be kept shows a countdown with Keep and Undo on every view. The page is three static files compiled into the daemon, with no build step and nothing loaded from elsewhere.

## Access and roles

| Way in | Who you are | What you may do |
| --- | --- | --- |
| The Unix socket | The user that owns your process, as the kernel reports it | Everything. Whoever can open the socket file is an admin |
| The HTTPS listener | The access token you send | What the token's role allows |

| Role | May |
| --- | --- |
| viewer | Read the config, candidates, plans, status and metrics |
| auditor | The same, plus the audit log |
| operator | The same, plus save candidates, approve, commit, confirm and revert |
| admin | Everything, including rollback, tokens and settings |

Only the SHA-256 of a token's secret is stored, so the secret is shown once when you create it. Tokens can expire and be revoked.

With `ox four-eyes on`, a commit needs approval from someone other than the person who last saved the candidate. Saving it again drops the approval. Every one of these actions is in the audit log with the name of who did it.

## Explain a packet

```sh
ox explain --src 10.20.4.17 --dst 10.30.0.8 --proto tcp --dport 445 --in lan0.20 \
           --candidate block-legacy-smb
```

```
10.20.4.17 → 10.30.0.8 tcp/445 in lan0.20

running
verdict  ACCEPT
 1 ingress    lan0.20 → zone lan
 2 route      out lan0.30 → zone dmz
              10.30.0.0/24 is connected
 3 zone pair  lan → dmz
              3 rules, first match wins
 4 rule       r-0388 accept · Finance to file servers
              position 1 of 3 · Open file share for finance, CHG-1984

candidate block-legacy-smb
verdict  DROP
 ...
 4 rule       r-0412 drop · Drop SMB and NetBIOS
              position 1 of 4 · Retire SMBv1 shares, CHG-2207 · logged

the candidate changes this packet: ACCEPT → DROP
```

Explain evaluates the same resolved ruleset that gets rendered for the kernel, so the two cannot disagree about addresses and ports. It treats the packet as the first of a new connection. It does not read live kernel state, and it knows only the routes the config states: interface networks and the default route.

## Import from pfSense

```sh
ox import examples/pfsense-config.xml --out imported.toml
```

Every item of the backup lands in one of three lists:

- **Translated** one to one.
- **Changed**: it works but differs, and the report says how. Examples are a floating rule that becomes several zone-pair rules, automatic outbound NAT written out as explicit rules, and pfSense's implicit anti-lockout rule made visible.
- **Unsupported**: it was left out, with the manual step. Examples are negated matches, aliases with hostnames, OpenVPN, captive portal and packages.

The importer does not guess. A rule it cannot translate exactly is left out, and the report says whether that drops traffic or might now allow it.

After translating, it replays probe packets through a model of the pfSense ruleset and through the new config, and lists every packet that gets a different verdict. Pass `--verify flows.jsonl` to replay your own flows instead. On the sample backup, 123 of 124 probes agree. The one that differs is a real semantic gap, and the report names it: a pfSense port forward with "Pass" association becomes NAT plus an explicit rule, and that rule also accepts packets sent straight to the internal host.

Two cautions. The importer has only been tested on a backup written by hand for this repo, not on a real one. It reads pfSense only. OPNsense backups are refused by name.

pfSense interface names are FreeBSD names such as `igb0`. The importer keeps them, and you rename them to the Linux names of the new box.

## Command reference

Daemon commands. All take `--socket <path>` or the `OX_SOCKET` variable. The default is `/run/netoxide/oxd.sock`.

| Command | What it does |
| --- | --- |
| `ox status` | The running commit, any pending countdown, candidate names |
| `ox running` | Print the running config |
| `ox candidate save <name> <file>` | Validate a file and store it as a candidate |
| `ox candidate list` / `show <name>` / `rm <name>` | Manage candidates |
| `ox plan <name> [--flows <file>]` | What the candidate would change |
| `ox commit <name> [--confirm 5m] [--reason <text>]` | Apply a candidate |
| `ox confirm` | Keep the pending commit |
| `ox revert` | Undo the pending commit now |
| `ox rollback [N] [--confirm 5m] [--reason <text>]` | Go back N commits, as a new commit |
| `ox history` | Commits, newest first |
| `ox show <id>` | One commit and its config |
| `ox explain --src --dst --proto --dport --in [--candidate <name>]` | What happens to one packet |
| `ox audit` | The audit log, with the chain verified |
| `ox hygiene` | Rules that never apply, add nothing, allow everything or have seen no packets |
| `ox approve <candidate>` | Approve a candidate someone else saved |
| `ox four-eyes on\|off` | Require a second person's approval before a commit |
| `ox token create <name> --role <role> [--days N]` / `list` / `revoke <name>` | Access tokens for the HTTPS API and the web UI |
| `ox whoami` | Who the daemon thinks you are |
| `ox leases` | The addresses DHCP has handed out |
| `ox kernel` | The Netoxide table as the kernel holds it |
| `ox forward --name <text> --port tcp/443 --to <host>[:port] [--address <outside address>]` | Forward a port to an inside host; saved as a candidate |
| `ox block <address> [--name <text>]` | Drop everything a device sends; saved as a candidate |

Commands that need no daemon:

| Command | What it does |
| --- | --- |
| `ox file validate <file>` | Check a config and report every problem |
| `ox file compile <file> [--stats]` | Print the nftables ruleset as libnftables JSON |
| `ox file diff <running> <candidate>` | List what differs |
| `ox file hygiene <file>` | Rules in a file that never apply, add nothing or allow everything |
| `ox file plan <running> <candidate> [--flows <file>]` | Plan from two files |
| `ox file explain <file> --src ... [--candidate <file>]` | Explain from files |
| `ox import <config.xml> [--out <file>] [--verify <flows>]` | Translate a pfSense backup |
| `ox init [--wan <port>] [--lan <port>[=<addr/prefix>]] [--no-services] [--dns-upstream <addr>] [--out <file> \| --save <name>]` | Guided setup. Reads the machine's ports; with `--out` it needs no daemon |
| `ox schema` | Print the JSON Schema of the config |

The confirm window is between 10 seconds and 1 hour. Only one commit can be pending at a time.

`oxd` options:

| Option | What it does |
| --- | --- |
| `--state-dir <dir>` | Where commits, candidates, the audit log and service files live. Default `/var/lib/netoxide` |
| `--socket <path>` | The API socket. Default `/run/netoxide/oxd.sock` |
| `--dry-run` | Keep state and serve the API, but load nothing and start no services |
| `--lockdown` | Until the first commit, drop inbound and forwarded traffic. This cuts a remote session to the machine |
| `--dnsmasq <path>` | The dnsmasq program to run. Default `dnsmasq` |
| `--listen <addr:port>` | Also serve the API and the web UI over HTTPS. Every request needs an access token |
| `--tls-cert <file>`, `--tls-key <file>` | The certificate for `--listen`. Without them the daemon makes a self-signed one and keeps it in the state directory |
| `--listen-http <127.0.0.1:port>` | The same without TLS, on a loopback address only, for a TLS proxy on the same machine |
| `--keep-service-privileges` | Do not switch services to an unprivileged user. Needed inside a user namespace |

Stopping `oxd` leaves the loaded ruleset in place, so the box keeps forwarding. It does stop dnsmasq, so DNS and DHCP stop with it.

## API reference

HTTP and JSON on the Unix socket. Errors come back as `{"error": "..."}` with 404 for something missing, 422 for an invalid config or request, and 409 when a commit is pending or none is.

| Method and path | Body | Returns |
| --- | --- | --- |
| `GET /v1/status` | | Running commit, `reverts_in` seconds, candidates, applier |
| `GET /v1/running` | | Running config as TOML |
| `GET /v1/commits` | | Commits, newest first |
| `GET /v1/commits/{id}` | | The commit and its config |
| `GET /v1/candidates` | | Candidate names |
| `PUT /v1/candidates/{name}` | TOML | Stores the candidate after validating it |
| `GET /v1/candidates/{name}` | | The candidate as TOML |
| `DELETE /v1/candidates/{name}` | | |
| `POST /v1/candidates/{name}/plan` | Optional JSON Lines of flows | Changes, compiled summary, impact |
| `POST /v1/candidates/{name}/commit` | `{"confirm_secs": 300, "reason": "..."}` | The new commit |
| `POST /v1/confirm` | | The confirmed commit |
| `POST /v1/revert` | | The reverted commit |
| `POST /v1/rollback` | `{"steps": 1, "confirm_secs": null, "reason": "..."}` | The new commit |
| `POST /v1/explain` | `{"src", "dst", "proto", "dport", "in", "candidate"}` | Verdict, steps and text for running and candidate |
| `GET /v1/leases` | | Addresses DHCP has handed out |
| `GET /v1/audit` | | All entries. Fails if the hash chain is broken |
| `GET /v1/hygiene` | | Findings about rules in the running config |
| `GET /metrics` | | Prometheus metrics |
| `GET /v1/whoami` | | The caller's name and role |
| `GET /v1/running/json` | | The running config as JSON, with what it does in sentences |
| `POST /v1/check` | TOML | Validates a config without storing it |
| `POST /v1/actions/forward`, `/v1/actions/block` | JSON | One-step actions; each saves a candidate |
| `GET /v1/candidates/{name}/meta` | | Author and approval of a candidate |
| `POST /v1/candidates/{name}/approve` | | Four-eyes approval |
| `GET` / `PUT /v1/settings` | `{"four_eyes": true}` | The four-eyes setting |
| `GET` / `POST /v1/tokens`, `DELETE /v1/tokens/{name}` | `{"name", "role", "ttl_secs"}` | Access tokens. The secret is returned once |
| `GET /v1/kernel` | | The table as the kernel lists it |

On the Unix socket the caller is whoever owns the calling process, as the kernel reports it, and is an admin. On the HTTPS listener every request carries `Authorization: Bearer <token>`, and the token's role decides what it may do: 401 without a valid token, 403 when the role does not allow the action. See [Access and roles](#access-and-roles).

## How it is built

```
 ox CLI ──────────────┐            (TUI, web UI, Terraform, controller: later)
                      │ HTTP + JSON on a Unix socket
                 ┌────▼─────────────────────────────────────────┐
                 │ oxd                                          │
                 │   ox-store   candidates, commits, confirm    │
                 │              clock, rollback, audit log      │
                 │   ox-plan    diff, flow impact               │
                 │   ox-explain packet → verdict and reason     │
                 │   ox-nft     config → Ruleset → nft JSON     │
                 │   ox-schema  typed config, validation        │
                 └────┬─────────────────────────────────────────┘
                      │ one transaction through libnftables (ox-libnft)
                 ┌────▼─────────────────────────────────────────┐
                 │ Linux kernel: table inet netoxide            │
                 └──────────────────────────────────────────────┘
```

| Crate | Role |
| --- | --- |
| `ox-schema` | The config types, parsing, validation and JSON Schema |
| `ox-nft` | Compiles a config into a `Ruleset` and renders it as libnftables JSON |
| `ox-explain` | Evaluates a packet against a `Ruleset` |
| `ox-plan` | Diffs two configs and replays flows through both |
| `ox-store` | The commit engine and audit log. It never touches the kernel; it hands rulesets to an `Applier` |
| `ox-libnft` | The FFI call into libnftables. The only crate that contains `unsafe` |
| `oxd` | The daemon |
| `ox-cli` | The `ox` binary |
| `ox-import` | The pfSense importer and its model of the pfSense ruleset |
| `ox-services` | Renders the config's DNS and DHCP settings as a dnsmasq config |
| `ox-setup` | Interface detection, the starter config, and the one-step actions |
| `ox-client` | The HTTP client for the daemon's socket, shared by `ox` and the TUI |
| `tui/` | The terminal UI prototype |

What the kernel gets, for the example config:

- Base chains `input` and `forward` with policy drop, `output` with policy accept, and NAT chains `prerouting` and `postrouting`.
- Established and related connections accepted first, invalid ones dropped.
- One verdict-map lookup on the ingress and egress interface that jumps to the chain for the zone pair.
- One chain per zone pair. Each config rule becomes one nftables rule per address family it covers, matching against named sets, with a counter and the rule ID as its comment.
- A zone pair that would need more than 32 nftables rules is merged instead: neighbouring rules with the same action become one lookup in a set of (source, destination, protocol, port) entries. Neighbours only, so no rule moves past one with a different action.
- A reload adds the table, deletes it and builds it again inside one transaction, so the swap is atomic.

## Design rules

These decide design arguments. When two conflict, the earlier one wins.

1. **The box never stops forwarding.** No licence state, expired support or unreachable controller changes packet handling or blocks a security fix.
2. **Config is data.** One typed document describes the box. Every tool edits that document and nothing else.
3. **Every change is a transaction.** A commit applies fully or not at all. An unconfirmed commit reverts by itself, without a reboot.
4. **No shell.** The control plane never builds a command string.
5. **Verified before broad.** A feature ships when it has a test that runs on every release.
6. **Self-hosted first.** Management runs on your hardware, air-gapped if you need.
7. **One licence, bound by governance.** No closed edition.

Rules for the code:

- `unsafe` is forbidden in every crate except `ox-libnft`, where each block carries an audit note.
- The daemon and its libraries never start a process to change system state.
- Every rule, NAT and import test runs for IPv4 and IPv6.
- No throughput or performance claim appears anywhere until a benchmark rig publishes numbers.
- Dependency changes pass `cargo deny check`.

## Tests

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo test --workspace
cargo deny check
```

There are 136 tests. Eight of them use the real kernel inside a private, rootless network namespace:

- The compiled ruleset is loaded and the kernel's stored rules are counted, including a merged ruleset and one that filters the box's own traffic.
- The daemon goes through a commit, an automatic revert after the window, a confirm, a rollback, and a restart with a commit still pending.
- The home example's resolver is queried with `dig` over IPv4 and IPv6, a record is changed with a confirm window, and the old answer returns when the window lapses.
- A small DHCP client on the far end of a virtual cable gets an address from the pool and a fixed address through the firewall, and stops being answered when the rule is removed.
- A service that cannot start refuses the commit and leaves the kernel unchanged.
- Real packets cross the box between three namespaces, a client inside, the box, and a server outside: web and ping are allowed out and the source is rewritten, another port is dropped, a forwarded port reaches the inside server, the kernel's counters land on the right rules, and each result matches what `ox explain` says for the same packet. A change that is not kept stops blocking traffic when its window lapses. Renumbering the inside network takes the old address off the port and leaves an address someone else put there.
- The HTTPS listener is called with curl: tokens, roles, four-eyes approval and revocation.
- The web UI's endpoints and the page's security headers are checked.

A separate test boots a virtual machine and checks the installed daemon under systemd: 99 checks across install, DHCP in both directions, DNS, IPv4 and IPv6 traffic, the undo timer, a killed daemon, a reboot and removal. It needs QEMU with KVM and is not part of `cargo test`. See [`tests/vm/README.md`](tests/vm/README.md).

The importer test compares the pfSense model and the translated config on generated probes and allows only the one known difference.

The TUI tests compare every mock screen with `tui/snapshots.txt` and every live screen, drawn against a test fixture, with `tui/snapshots-live.txt`.

## Install

[`dist/README.md`](dist/README.md) has the steps for a Linux machine with systemd: build, install the unit, first start, the web UI, lockdown, monitoring and removal. The VM test runs them, under systemd, on every run. Nobody has run them on hardware.

## Limits today

- **Access control is new and has had no outside audit.** Tokens, roles, four-eyes and the HTTPS listener are tested. One internal review pass found no way around them and eleven other defects, which are fixed except the three listed next. Nobody outside this project has reviewed any of it. There is no single sign-on (OIDC), and the roles are four fixed ones.
- **Known and not fixed.** Token expiry and the undo timer use the wall clock, so a box whose clock jumps backwards extends both. The audit chain has no key, so someone who can write the state directory can rewrite the log and its head together; shipping the head off the box would close that. The HTTPS listener has no connection limit or header timeout of its own.
- **An admin can get around four-eyes** by turning it off or making a second token. Both are in the audit log. Operators cannot.
- **The web UI has been checked by hand in one browser.** Sign-in, overview, rules, changes and a commit with its timer were exercised in Chrome. The forms for forwarding, blocking, editing, explain and tokens were not; their endpoints are covered by tests.
- **Nothing is loaded before the first commit** unless you start `oxd --lockdown`, so by default the kernel's own defaults apply until then.
- **DNS and DHCP are new.** They are tested end to end in a namespace: `dig` against the resolver over IPv4 and IPv6, and a small DHCP client that gets a pool address and a fixed address through the firewall. No real device has used them. There are no DNS blocklists, IPv6 is announce-only (no DHCPv6), and the daemon runs dnsmasq directly, not as a sandboxed systemd unit as the spec asks.
- **dnsmasq is the only backend.** The spec names Unbound and Kea. The config does not name the program, so they can be added without changing configs.
- **Interfaces are only partly managed.** The daemon does not create VLAN, bridge, bond or PPPoE interfaces; the operating system still does. Stop the operating system's own network manager on the ports you give to Netoxide, or the two will both set addresses.
- **The internet side is IPv4 DHCP or fixed addresses.** For IPv6 the box takes an address from the provider's router advertisements. It does not ask for a delegated prefix (DHCPv6-PD), so the inside network gets IPv6 only if you have a fixed prefix. The DNS servers a lease names are shown and not used; the resolver forwards to the servers in the config.
- **The box's own traffic is allowed out unless you filter it.** Write a policy from `self` to a zone to filter what the box sends there.
- **The systemd unit and the install steps have run only in the test VM**, with SELinux off and virtual network cards.
- **Long zone pairs lose per-rule counters.** A pair that needs more than 32 nftables rules is merged: neighbouring rules with the same action become one set lookup and share a counter, so the TUI shows no packet count for them. Rules that log, match ICMP or any service, or overlap a neighbour are not merged. A pair that is still over 32 after merging is refused.
- **Explain knows only connected networks and the default route.** A destination behind a static or dynamic route shows "no route".
- **Schema 1 has no VPN, routing protocols, traffic shaping, schedules or HA.**
- **The importer reads pfSense only** and has not been tested on a real backup.
- **Nothing has run on real hardware or under real traffic.** The furthest it has been is a virtual machine on one developer's computer.

## Not built yet

Roughly in the order planned:

1. Running it on real hardware, with SELinux enforcing, and a first deployment that is watched.
2. Services as sandboxed systemd units, and Unbound and Kea as backends beside dnsmasq.
3. More one-step actions such as "add a guest network", rule editing in the terminal UI, and live trace.
4. WireGuard, then IPsec.
5. Single sign-on (OIDC), finer roles, and remote use of `ox` over HTTPS.
6. Multi-WAN, routing protocols, traffic shaping, IDS.
7. OPNsense import, and the pfSense importer tested on real backups.
8. HA, the fleet controller, a Terraform provider, and the OS image with signed A/B upgrades.
9. An independent security audit before any 1.0.

The spec dates a 1.0 at August 2028 for a team of six. That date is a plan, not a commitment.

## Documents

- [`docs/spec.md`](docs/spec.md): the product spec, including scope, non-goals and open questions
- [`docs/research/market-gap.md`](docs/research/market-gap.md): the market research, with a table of how strong each claim is
- [`docs/design/`](docs/design/README.md): the web UI design and a browser preview of the TUI
- [`CLAUDE.md`](CLAUDE.md): working notes for AI coding agents
- [`tui/README.md`](tui/README.md): the TUI prototype and its keys

## Licence and name

**No licence has been chosen**, so this repository carries none and nobody may yet use, copy or distribute the code. The choice on the table is AGPL-3.0-or-later for the daemon and tools with Apache-2.0 for the schema and client libraries, or Apache-2.0 throughout.

"Netoxide" is a working name. It has not been checked for trademark conflicts, and it sits close to Oxide Computer Company, which also builds networking products in Rust.

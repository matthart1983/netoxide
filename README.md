# Netoxide

Netoxide is an open-source firewall and router OS for Linux with a Rust control plane. It is meant for teams that run 10 to 300 firewalls across sites, mostly people moving off pfSense or OPNsense.

**Status: pre-alpha.** What exists today is a single-box firewall core. A daemon applies a typed config to the kernel through nftables, with commit, confirm, automatic revert, rollback and an audit log. There is a CLI and a pfSense importer. It has only been run inside network namespaces, never on a production box. Do not put it in front of a real network.

- [What works today](#what-works-today)
- [Try it without touching your machine](#try-it-without-touching-your-machine)
- [The config](#the-config)
- [How a change reaches the kernel](#how-a-change-reaches-the-kernel)
- [The terminal UI](#the-terminal-ui)
- [Explain a packet](#explain-a-packet)
- [Import from pfSense](#import-from-pfsense)
- [Command reference](#command-reference)
- [API reference](#api-reference)
- [How it is built](#how-it-is-built)
- [Design rules](#design-rules)
- [Tests](#tests)
- [Limits today](#limits-today)
- [Not built yet](#not-built-yet)
- [Documents](#documents)
- [Licence and name](#licence-and-name)

## Why

The pitch is that a buyer can check every claim. The source is public, the config has a published schema, every change is a transaction that can undo itself, and the firewall can say why it did what it did to a packet.

The research behind this is in [`docs/research/market-gap.md`](docs/research/market-gap.md). In short, no open firewall combines free stable releases, typed config with commit-confirm, fleet management in the open core, image upgrades and tested HA. The research also found no buyer asking for Rust by name. Rust is here for two reasons: a control plane that never builds a shell command, and memory-safe code on the network-facing side. Packets stay in the Linux kernel, and this project makes no performance claim.

## What works today

| Piece | What it does |
| --- | --- |
| Config schema | One typed TOML or JSON document per box: zones, interfaces, address groups, services, zone-pair filter rules, port forwards and outbound NAT. Validation reports every problem with its location. The JSON Schema is published in [`schema/`](schema/netoxide-config-1.schema.json). |
| Rule compiler | Turns a config into an nftables ruleset built from sets and verdict maps, loaded as one atomic transaction. IPv4 and IPv6 in the same rules. |
| Daemon `oxd` | Owns the config. Stores candidates, applies commits to the kernel through libnftables, runs the confirm clock, and serves an HTTP and JSON API on a Unix socket. |
| Commit-confirm | A commit made with a confirm window reverts by itself unless confirmed. The revert replays the previous commit. It does not reboot. A daemon restart with a commit still unconfirmed also reverts it. |
| Rollback and history | The last 100 commits are kept with author, time, reason and the SHA-256 of the config. Rollback is a new commit with an old config. |
| Audit log | Every candidate save, commit, confirm and revert is appended to a hash-chained log. Editing or deleting a line breaks the chain, and the log says which line. |
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
| `ox kernel` | The Netoxide table as the kernel holds it |

Commands that need no daemon:

| Command | What it does |
| --- | --- |
| `ox file validate <file>` | Check a config and report every problem |
| `ox file compile <file> [--stats]` | Print the nftables ruleset as libnftables JSON |
| `ox file diff <running> <candidate>` | List what differs |
| `ox file plan <running> <candidate> [--flows <file>]` | Plan from two files |
| `ox file explain <file> --src ... [--candidate <file>]` | Explain from files |
| `ox import <config.xml> [--out <file>] [--verify <flows>]` | Translate a pfSense backup |
| `ox schema` | Print the JSON Schema of the config |

The confirm window is between 10 seconds and 1 hour. Only one commit can be pending at a time.

`oxd` takes `--state-dir <dir>` (default `/var/lib/netoxide`), `--socket <path>` and `--dry-run`. Stopping it leaves the loaded ruleset in place, so the box keeps forwarding.

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
| `GET /v1/audit` | | All entries. Fails if the hash chain is broken |
| `GET /v1/kernel` | | The table as the kernel lists it |

The caller's name is read from the `x-ox-user` header and recorded as given. See [Limits today](#limits-today).

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
| `tui/` | The terminal UI prototype |

What the kernel gets, for the example config:

- Base chains `input` and `forward` with policy drop, `output` with policy accept, and NAT chains `prerouting` and `postrouting`.
- Established and related connections accepted first, invalid ones dropped.
- One verdict-map lookup on the ingress and egress interface that jumps to the chain for the zone pair.
- One chain per zone pair. Each config rule becomes one nftables rule per address family it covers, matching against named sets, with a counter and the rule ID as its comment.
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

There are 71 tests. Two of them use the real kernel inside a private, rootless network namespace. One loads the compiled ruleset and checks that the kernel stored every rule. The other starts the daemon and takes it through a commit, an automatic revert after the window, a confirm, a rollback, and a restart with a commit still pending. They need `unshare`, `libnftables.so.1` and unprivileged user namespaces, and skip themselves with a note when those are missing. They never touch the host's ruleset.

The importer test compares the pfSense model and the translated config on generated probes and allows only the one known difference.

The TUI tests compare every mock screen with `tui/snapshots.txt` and every live screen, drawn against a test fixture, with `tui/snapshots-live.txt`.

## Limits today

- **The API has no security.** Whoever can open the socket file has full control. There is no TLS, login, role check or four-eyes approval, and the caller's name is taken from a header as given.
- **Nothing is loaded before the first commit**, so the kernel's own defaults apply until then.
- **The box's own outbound traffic is not filtered.** There are no rules for traffic the box sends.
- **A zone pair may compile to at most 32 nftables rules.** The compiler refuses a longer one. It does not yet merge rules to fit.
- **Explain knows only connected networks and the default route.** A destination behind a static or dynamic route shows "no route".
- **Schema 1 has no VPN, DNS, DHCP, routing protocols, traffic shaping, schedules or HA.**
- **The importer reads pfSense only** and has not been tested on a real backup.
- **Nothing has run on real hardware or under real traffic.**

## Not built yet

Roughly in the order planned:

1. Editing rules and candidates from the TUI.
2. API security: TLS, OIDC or token login, roles, four-eyes approval.
3. A rule merger, so long zone pairs compile.
4. Services rendered from the config: DNS with Unbound, DHCP with Kea, then WireGuard and IPsec.
5. A locked-down default before the first commit, and rules for the box's own traffic.
6. OPNsense import, and the pfSense importer tested on real backups.
7. HA, the fleet controller, the web UI, and the OS image with signed A/B upgrades.

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

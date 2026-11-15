# How it is built and tested

The crates, the design rules, and what the tests cover.

- [How it is built](#how-it-is-built)
- [Design rules](#design-rules)
- [Tests](#tests)

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

There are 177 tests. Thirteen of them run a daemon inside a private, rootless network namespace, most of those against the real kernel:

- The compiled ruleset is loaded and the kernel's stored rules are counted, including a merged ruleset and one that filters the box's own traffic.
- The daemon goes through a commit, an automatic revert after the window, a confirm, a rollback, and a restart with a commit still pending.
- The home example's resolver is queried with `dig` over IPv4 and IPv6, a record is changed with a confirm window, and the old answer returns when the window lapses.
- A small DHCP client on the far end of a virtual cable gets an address from the pool and a fixed address through the firewall, and stops being answered when the rule is removed.
- The box makes a VLAN interface from the config and a client on the tagged network reaches it over IPv4 and IPv6. Changing the number makes the interface again, a VLAN on a port that does not exist fails the commit and leaves the old one, and an interface someone else made is never removed.
- A service that cannot start refuses the commit and leaves the kernel unchanged.
- Two boxes, each with its own daemon, swap public keys and join their inside networks with a WireGuard tunnel. A device behind one fetches a page from the other over IPv4 and IPv6, a port the rules do not allow is dropped, explain follows the route through the tunnel, both ends report the peer as connected, narrowing a peer's networks stops that traffic only, and removing the tunnel removes the interface.
- Real packets cross the box between three namespaces, a client inside, the box, and a server outside: web and ping are allowed out and the source is rewritten, another port is dropped, a forwarded port reaches the inside server, the kernel's counters land on the right rules, and each result matches what `ox explain` says for the same packet. A change that is not kept stops blocking traffic when its window lapses. Renumbering the inside network takes the old address off the port and leaves an address someone else put there.
- The HTTPS listener is called with curl: tokens, roles, four-eyes approval and revocation.
- A backup taken on one box is restored on a second: the second box has the same VPN public key and the same roles, runs nothing until the candidate is committed, and then runs the same config.
- A box with no config is set up through the setup routes: no code and a wrong code show nothing, a preview changes nothing, applying returns a token and starts an undo timer, and setup shuts once a config runs. The grid then reads and changes who can reach what, and explain places a device on its network without being told the interface.
- A headless Chrome sets a blank box up from the setup code and walks Home, Access, Review, Settings and every advanced screen, against real rules in a namespace (`tests/web/run.sh`; it runs in CI and is not part of `cargo test`).
- `ox` manages a box from a second machine over IPv4 and IPv6: a wrong fingerprint and a wrong token save nothing, a full change cycle runs, a certificate that is not the saved one stops `ox` before the token is sent, and roles held to sections are refused every change outside them, including keeping or undoing someone else's commit.
- The HTTPS listener refuses the 33rd connection from one address, still serves another address, and closes connections that say nothing.
- The web UI's endpoints and the page's security headers are checked.

A separate test boots a virtual machine and checks the installed daemon under systemd: 143 checks across install, DHCP in both directions, DNS, IPv4 and IPv6 traffic, the undo timer, a killed daemon, a VPN device that connects and reaches the inside network, `ox` run from a client on the inside network with a pinned certificate, a role refused a change outside its sections, a VLAN the box makes, a backup, the setup routes under the sandbox, a reboot and removal. It needs QEMU with KVM and is not part of `cargo test`. See [`tests/vm/README.md`](../tests/vm/README.md).

The importer test compares the pfSense model and the translated config on generated probes and allows only the one known difference.

The TUI tests compare every mock screen with `tui/snapshots.txt` and every live screen, drawn against a test fixture, with `tui/snapshots-live.txt`.

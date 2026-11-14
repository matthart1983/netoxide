# Netoxide: brief for Claude

Netoxide is an open-source firewall and router OS on Linux with a Rust control
plane. It is for teams that run 10 to 300 firewalls across sites, mostly people
moving off pfSense or OPNsense. The pitch is "every claim checkable": public
source, a published config schema, signed A/B upgrades, and published HA test
results.

The full spec is in `docs/spec.md`. Read it before any design or architecture
decision. This file gives you what you need to start working.

## Current state (14 Nov 2026)

| What | Where | State |
| --- | --- | --- |
| Spec | `docs/spec.md` | Complete draft; open questions at the end |
| Web UI design | `docs/design/` | 11 screens as Claude Design source, mock data |
| TUI prototype | `tui/` | ratatui 0.29, 11 screens, **mock data only**, not wired to `oxd` |
| Config schema | `crates/ox-schema` | Schema 1: zones, interfaces, groups, services, filter policy, NAT |
| Rule compiler | `crates/ox-nft` | Config → `Ruleset` → libnftables JSON |
| Explain | `crates/ox-explain` | One packet against a ruleset: forward, route, zone pair, rule, source NAT |
| Plan | `crates/ox-plan` | Config diff, and which observed flows change verdict |
| Commit engine | `crates/ox-store` | Candidates, commits, commit-confirm, auto revert, rollback, hash-chained audit log |
| Kernel apply | `crates/ox-libnft` | FFI to libnftables. The only crate with `unsafe` |
| Daemon | `crates/oxd` | HTTP+JSON API on a Unix socket, applies to the kernel, `--dry-run` |
| CLI | `crates/ox-cli` | `ox`: daemon commands, `ox file ...` offline commands, `ox import` |
| Importer | `crates/ox-import` | pfSense config.xml → config + report + differential verify |
| Services, VPN, HA, API auth/RBAC, web UI, controller, OS image | — | **Not started** |

The daemon has only run inside rootless network namespaces. Nobody has run it
on a real box.

`ox-nft::Ruleset` is the one resolved form of a config. `render` turns it into
nftables JSON and `ox-explain` evaluates packets against it, so an explanation
cannot drift from the loaded rules. Keep it that way: never give explain its
own copy of the matching logic.

`ox-store::Engine` never talks to the kernel. It hands rendered JSON to an
`Applier`. Tests use `NullApplier`; `oxd` uses libnftables. It applies first
and records second, so a crash in between leaves the old commit recorded and
the next start applies it again. A daemon that starts with a commit still
pending reverts it.

`ox-import` keeps a model of the pfSense ruleset (`pf.rs`) and checks its own
translation against it with generated probes. When you add a translation, the
probe test must still pass with only the known "Pass association" difference.

## Names

- Product: **Netoxide** (capital N in prose)
- Daemon: `oxd`. CLI: `ox` (`ox commit`, `ox explain`, `ox plan`, `ox import`, `ox trace`, `ox diff`, `ox rollback`)
- TUI crate: `netoxide-tui`
- The name has not been checked for trademark conflicts. It sits close to Oxide Computer Company. Don't register domains or crates.io names without asking.

## The seven principles (earlier wins when two conflict)

1. **The box never stops forwarding.** No licence state, expired support or unreachable controller changes packet handling or blocks a security fix.
2. **Config is data.** One typed document describes the box. UI, CLI, API and controller all edit that document and nothing else.
3. **Every change is a transaction.** A commit applies fully or not at all. An unconfirmed commit reverts by itself, without a reboot.
4. **No shell.** The control plane never builds a command string. It uses netlink, libnftables JSON, typed service APIs (VICI, Kea control socket) or generated config files.
5. **Verified before broad.** A feature ships when it has a test that runs on every release.
6. **Self-hosted first.** The controller runs on customer hardware, air-gapped if needed.
7. **One licence, bound by governance.** No closed edition and no CLA.

## Hard rules for code

- `#![forbid(unsafe_code)]` in every first-party crate, except one small audited FFI crate. Each `unsafe` block there gets an audit note.
- Never call `std::process::Command` with shell strings from `oxd` or its libraries. Supervised services run as systemd units.
- Every dependency change passes `cargo-deny` and `cargo-vet`. `deny.toml` is in place and `cargo deny check` passes. `cargo-vet` is not set up yet.
- The firewall ruleset swaps in one nftables transaction. The rule compiler emits sets, maps and verdict maps, never a linear chain longer than 32 rules. Today the compiler refuses a zone pair that would exceed 32. It does not yet merge rules to fit.
- Every rule, NAT and VPN test runs for both IPv4 and IPv6.
- Make no throughput or performance claim in code, docs or UI until the Phase 0 benchmark rig publishes numbers.
- Licence decision is pending: AGPL-3.0-or-later for `oxd`, CLI, UI and controller, Apache-2.0 for client libraries, schema and Terraform provider. Don't add licence headers until that is decided.

## Out of scope for 1.0 (don't build these)

App identification, TLS interception, a proprietary threat feed, a plugin system that runs third-party code as root, active/active HA, a built-in AI assistant, Wi-Fi AP features, VPP/DPDK, and a pure-Rust services stack (Unbound, Kea, FRR, strongSwan and Suricata stay embedded).

## Workspace layout

```
crates/
  ox-schema/      typed config, validation, JSON Schema (schema/netoxide-config-1.schema.json)
  ox-nft/         compile to a Ruleset, render as libnftables JSON
  ox-explain/     evaluate a packet against a Ruleset
  ox-plan/        diff two configs; replay flows through both
  ox-store/       commit engine and audit log; no kernel access
  ox-libnft/      the audited FFI crate for libnftables
  oxd/            the daemon: API on a Unix socket, commit-confirm clock
  ox-cli/         the `ox` binary
  ox-import/      pfSense backup → config, report, verify
examples/         branch.toml, branch-candidate.toml, flows.jsonl, pfsense-config.xml
tui/              netoxide-tui; replace tui/src/data.rs with an oxd API client
```

Proposed next, not decided, roughly in this order:

1. Wire the TUI to `oxd` (Policy, Changes, Explain, Audit first), replacing `tui/src/data.rs`.
2. API security: TLS listener, OIDC or token auth, the five roles, four-eyes approval. Today the socket's file permission is the only control.
3. A rule merger so a zone pair over 32 nftables rules compiles instead of being refused.
4. `ox-services`: Unbound, Kea, then WireGuard and strongSwan, each rendered from schema additions.
5. Default lockdown before the first commit, and rules for traffic the box sends.
6. OPNsense import, and testing the pfSense importer against real backups.
7. HA, the fleet controller, the OS image. These are later phases in the spec.

Run before handing work back:

```sh
cargo fmt --all && cargo clippy --workspace --all-targets && cargo test --workspace && cargo deny check
```

If the config types change, regenerate the published schema with
`cargo run -p ox-cli -- schema > schema/netoxide-config-1.schema.json`.

To run the daemon by hand without touching the host, start it under
`unshare -Urn` as the README shows. Never start `oxd` without `--dry-run`
outside a namespace on Matt's machine: it would replace the host's `netoxide`
nftables table.

## The TUI prototype

```sh
cd tui
cargo run --release                                  # needs ≥ 132×34 terminal
cargo run -- --snapshot all --size 160x46            # print screens as text
cargo run -- --snapshot changes --keys c             # replay keys first
cargo run -- --html preview.html                     # coloured static preview
```

- `src/app.rs` holds state and keys
- `src/ui.rs` has one draw function per screen
- `src/data.rs` is mock data that mirrors the web design
- `src/html.rs` handles the HTML export

Screens are: Policy, NAT, VPN, IPS, Interfaces, HA, Changes (commit-confirm with a live countdown), Explain, Admin/Audit, Fleet and Import (key `i`).

Use `--snapshot` to check layout changes without a terminal. `cargo test` compares every screen with `tui/snapshots.txt`; regenerate it with `cargo run -- --snapshot all --size 160x46 > snapshots.txt` when a layout change is intended.

The TUI's HA screen says state sync runs over an "encrypted link". The spec requires an authenticated, encrypted channel and nobody has designed the mechanism. conntrackd has no TLS of its own.

## The web design

`docs/design/README.md` lists the 11 screens and what each one shows. The `.dc.html` files are Claude Design source. They need the Design runtime to render, so treat them as a reference for layout, copy and data, not as front-end code. `docs/design/tui-preview.html` opens in any browser.

## Open decisions (ask Matt; don't assume)

- Licence: AGPL + Apache split, or Apache throughout
- Funded company with about six engineers, or a solo project. A solo scope would be the config engine plus `ox explain` on one box, with no controller.
- Whether to reuse NetWatch's diagnosis work for health verdicts. NetWatch is a separate product.
- Location of the steward entity and its board
- Trademark check on "Netoxide"

## Working style

Matt wants directness and precision. Flag inaccuracies and weak evidence explicitly rather than smoothing them over. The spec marks thin evidence (segment size, willingness to pay, all performance comparisons). Keep it marked.

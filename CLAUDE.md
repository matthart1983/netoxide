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
| TUI | `tui/` | ratatui 0.29. Live mode (`--socket`): 6 screens backed by `oxd`. Mock mode: the 11 designed screens with sample data |
| Config schema | `crates/ox-schema` | Schema 1: zones, interfaces, groups, services, filter policy, NAT |
| Rule compiler | `crates/ox-nft` | Config → `Ruleset` → libnftables JSON |
| Explain | `crates/ox-explain` | One packet against a ruleset: forward, route, zone pair, rule, source NAT |
| Plan | `crates/ox-plan` | Config diff, and which observed flows change verdict |
| Commit engine | `crates/ox-store` | Candidates, commits, commit-confirm, auto revert, rollback, hash-chained audit log |
| Kernel apply | `crates/ox-libnft` | FFI to libnftables. The only crate with `unsafe` |
| Daemon | `crates/oxd` | HTTP+JSON API on a Unix socket, applies to the kernel, `--dry-run` |
| CLI | `crates/ox-cli` | `ox`: daemon commands, `ox file ...` offline commands, `ox import` |
| Socket client | `crates/ox-client` | The small HTTP client `ox` and the TUI share |
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
- The firewall ruleset swaps in one nftables transaction. The rule compiler emits sets, maps and verdict maps, never a linear chain longer than 32 rules. A zone pair over 32 is merged (`Chain::layout` in `ox-nft`): neighbouring rules with the same action share one concatenated-set lookup. Only neighbours merge, so first-match order holds, and nftables refuses overlapping set entries, so an overlapping rule starts a new run. Merged rules share a counter. A pair still over 32 is refused.
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
  ox-client/      HTTP client for the oxd socket, shared by ox and the TUI
  ox-import/      pfSense backup → config, report, verify
examples/         branch.toml, branch-candidate.toml, flows.jsonl, pfsense-config.xml
tui/              netoxide-tui: live.rs + live_ui.rs (live mode), app.rs + ui.rs + data.rs (mock mode)
```

Proposed next, not decided, roughly in this order:

1. Rule and candidate editing in the live TUI. Today it reads, commits, confirms and reverts.
2. API security: TLS listener, OIDC or token auth, the five roles, four-eyes approval. Today the socket's file permission is the only control.
3. `ox-services`: Unbound, Kea, then WireGuard and strongSwan, each rendered from schema additions.
4. Default lockdown before the first commit, and rules for traffic the box sends.
5. OPNsense import, and testing the pfSense importer against real backups.
6. HA, the fleet controller, the OS image. These are later phases in the spec.

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

## The TUI

```sh
cd tui
cargo run --release -- --socket /path/to/oxd.sock    # live mode; needs ≥ 132×34
cargo run --release                                  # mock mode: the 11 designed screens
cargo run -- --socket S --snapshot all --size 160x46 # print live screens as text
cargo run -- --socket S --snapshot changes --keys c  # replay keys first
cargo run -- --snapshot all --size 160x46            # print mock screens as text
cargo run -- --html preview.html                     # coloured static preview of mock mode
```

Live mode:

- `src/live.rs` holds the `Backend` trait, the socket implementation, state and keys. Everything the screens show comes through `Backend`. The test fixture in the same file implements it in memory.
- `src/live_ui.rs` draws the six live screens: Policy, NAT, Interfaces, Changes, Explain, Audit.
- Never put sample data in a live screen. If the daemon cannot back something, leave the screen out of live mode.

Mock mode is the design reference and has not changed role:

- `src/app.rs` holds state and keys, `src/ui.rs` one draw function per screen, `src/data.rs` the sample data, `src/html.rs` the HTML export.
- Its HA screen says state sync runs over an "encrypted link". The spec requires an authenticated, encrypted channel and nobody has designed the mechanism. conntrackd has no TLS of its own.

`cargo test` compares mock screens with `tui/snapshots.txt` and live screens with `tui/snapshots-live.txt`. Regenerate them with `cargo run -- --snapshot all --size 160x46 > snapshots.txt` and `UPDATE_SNAPSHOTS=1 cargo test -p netoxide-tui` when a layout change is intended.

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

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
| TUI prototype | `tui/` | ratatui 0.29, builds clean, **mock data only** |
| Daemon, CLI, schema, controller | — | **Not started** |

No code talks to a real firewall yet.

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
- Every dependency change passes `cargo-deny` and `cargo-vet`.
- The firewall ruleset swaps in one nftables transaction. The rule compiler emits sets, maps and verdict maps, never a linear chain longer than 32 rules.
- Every rule, NAT and VPN test runs for both IPv4 and IPv6.
- Make no throughput or performance claim in code, docs or UI until the Phase 0 benchmark rig publishes numbers.
- Licence decision is pending: AGPL-3.0-or-later for `oxd`, CLI, UI and controller, Apache-2.0 for client libraries, schema and Terraform provider. Don't add licence headers until that is decided.

## Out of scope for 1.0 (don't build these)

App identification, TLS interception, a proprietary threat feed, a plugin system that runs third-party code as root, active/active HA, a built-in AI assistant, Wi-Fi AP features, VPP/DPDK, and a pure-Rust services stack (Unbound, Kea, FRR, strongSwan and Suricata stay embedded).

## Suggested workspace layout for the real build

This is a proposal, not decided:

```
crates/
  ox-schema/      typed config, JSON Schema generation, versioning (start here)
  ox-plan/        candidate vs running diff, dependency-ordered plan
  ox-nft/         rule compiler → libnftables JSON, atomic apply
  ox-explain/     evaluate a 5-tuple against a compiled ruleset (running or candidate)
  oxd/            daemon: API (axum + rustls), commits, commit-confirm, reconciler, audit log
  ox-cli/         `ox` binary, thin client of the oxd API
  ox-services/    renderers + supervisors for Unbound, Kea, FRR, strongSwan, Suricata, conntrackd
  ox-import/      pfSense/OPNsense config.xml → candidate + report (translated / changed / unsupported)
  ox-controller/  fleet controller (later phase)
tui/              netoxide-tui; replace tui/src/data.rs with an oxd API client
```

A good first slice, from the 0.1 alpha gate: `ox-schema` + `ox-plan` + `ox-nft` + `ox-explain` on one box. That covers filtering and NAT from a typed config, commit-confirm reverting without a reboot, and `ox explain` answering for running and candidate configs.

## The TUI prototype

```sh
cd tui
cargo run --release                                  # needs ≥ 110×30 terminal
cargo run -- --snapshot all --size 160x46            # print screens as text
cargo run -- --snapshot changes --keys c             # replay keys first
cargo run -- --html preview.html                     # coloured static preview
```

- `src/app.rs` holds state and keys
- `src/ui.rs` has one draw function per screen
- `src/data.rs` is mock data that mirrors the web design
- `src/html.rs` handles the HTML export

Screens are: Policy, NAT, VPN, IPS, Interfaces, HA, Changes (commit-confirm with a live countdown), Explain, Admin/Audit and Fleet.

Use `--snapshot` to check layout changes without a terminal.

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

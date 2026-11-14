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
| Config schema | `crates/ox-schema` | Schema 1: zones, interfaces, groups, services, filter policy, NAT, DNS resolver, DHCP pools |
| Rule compiler | `crates/ox-nft` | Config → `Ruleset` → libnftables JSON |
| Explain | `crates/ox-explain` | One packet against a ruleset: forward, route, zone pair, rule, source NAT |
| Plan | `crates/ox-plan` | Config diff, and which observed flows change verdict |
| Commit engine | `crates/ox-store` | Candidates, commits, commit-confirm, auto revert, rollback, hash-chained audit log |
| Kernel apply | `crates/ox-libnft` | FFI to libnftables. The only crate with `unsafe` |
| Daemon | `crates/oxd` | HTTP+JSON API on a Unix socket and on HTTPS (`--listen`), applies to the kernel, runs dnsmasq, serves the web UI and `/metrics` |
| Access control | `crates/ox-store/src/auth.rs`, `crates/oxd/src/api.rs` | Socket peer = admin, named from the kernel. HTTPS = bearer token with a role (viewer, auditor, operator, admin). Four-eyes approval. Every handler takes a `Caller` and calls `caller.may(Action::…)` first |
| Web UI | `crates/oxd/web/` | `index.html`, `app.js`, `app.css`, compiled in with `include_str!`. No build step, no dependencies, strict CSP, daemon text inserted with `textContent` only |
| Hygiene | `crates/ox-nft/src/hygiene.rs` | Shadowed, redundant and allow-everything rules; `oxd` adds "no packets" from kernel counters |
| Packaging | `dist/`, `.github/workflows/ci.yml`, `SECURITY.md` | systemd unit (verified for syntax only), install steps (never run), CI |
| CLI | `crates/ox-cli` | `ox`: daemon commands, `ox file ...` offline commands, `ox import` |
| Socket client | `crates/ox-client` | The small HTTP client `ox` and the TUI share |
| DNS and DHCP | `crates/ox-services` + `crates/oxd/src/services.rs` | `[dns]` and `[dhcp.<iface>]` in the schema, rendered as a dnsmasq config; `oxd` runs and restarts dnsmasq. Applied and reverted with the ruleset as one `Target` |
| Easy path | `crates/ox-setup` | `detect` (ports of this machine), `starter` (guided-setup config), `add_forward`, `block`, `describe`. Behind `ox init`, `ox forward`, `ox block` |
| Importer | `crates/ox-import` | pfSense config.xml → config + report + differential verify |
| VPN, multi-WAN, routing protocols, IDS, HA, controller, Terraform, OS image | — | **Not started** |

The daemon has only run inside rootless network namespaces. Nobody has run it
on a real box.

`ox-nft::Ruleset` is the one resolved form of a config. `render` turns it into
nftables JSON and `ox-explain` evaluates packets against it, so an explanation
cannot drift from the loaded rules. Keep it that way: never give explain its
own copy of the matching logic.

`ox-store::Engine` never talks to the kernel. It hands a `Target` (the
rendered ruleset plus each service's config text) to an `Applier`, which must
put all of it into effect or none. `oxd`'s `SystemApplier` checks the service
config, loads the ruleset, then restarts the service, and reloads the previous
ruleset if the service fails. Tests use `NullApplier`; `oxd` uses libnftables. It applies first
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

## Two audiences, one product

Matt's design goal (14 Nov 2026): Netoxide has to appeal to home-lab users and to commercial fleets. It must be easy to use and still offer the advanced features.

- **Easy first, advanced within reach.** A single box gets a working, safe setup from a short guided flow with no config file to write. A fleet operator gets the full model. Both use the same config and tools: the easy path writes ordinary config that the advanced path can read and change.
- Nothing a single box needs may depend on the controller, a login server or a fleet feature.
- When you add a feature, give it a sensible default and a one-step way to do the common case, then expose the full control. Do not add a second, simpler config format.
- Error messages and UI text are written for someone who has not read the spec.
- The research found home-lab users are the test bed and contributor pool, not the paying segment. Serve them anyway; they bring the product to work.

## Hard rules for code

- `#![forbid(unsafe_code)]` in every first-party crate, except one small audited FFI crate. Each `unsafe` block there gets an audit note.
- The only crate with `unsafe` is `ox-libnft`. `nix` gives safe wrappers for the few system calls the rest needs.
- Never call `std::process::Command` with shell strings from `oxd` or its libraries. `oxd` starts dnsmasq with a fixed argument list (`crates/oxd/src/services.rs`); that is the only process it starts. The spec wants services as systemd units; that is not done yet.
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
  ox-setup/       guided setup and one-step actions; all return ordinary Config
  ox-services/    renders [dns] and [dhcp] as a dnsmasq config; text only, no process handling
  ox-import/      pfSense backup → config, report, verify
examples/         branch.toml, branch-candidate.toml, flows.jsonl, pfsense-config.xml
tui/              netoxide-tui: live.rs + live_ui.rs (live mode), app.rs + ui.rs + data.rs (mock mode)
```

Proposed next, not decided, roughly in this order:

1. Run it on real hardware or a VM with systemd: the unit in `dist/`, the install steps, a first watched deployment. Nothing has left a network namespace yet.
2. Services as sandboxed systemd units instead of direct children of `oxd`; Unbound and Kea renderers beside dnsmasq. The schema must stay backend-neutral.
3. More one-step actions (add a guest network, allow a service) in `ox-setup`, the same actions in the TUI, rule editing there, and `ox trace`.
4. WireGuard, then IPsec.
5. OIDC sign-in, finer roles, and `ox` over HTTPS (the CLI client is Unix-socket only).
6. Multi-WAN, FRR, CAKE, Suricata.
7. OPNsense import, and testing the pfSense importer against real backups.
8. HA, the fleet controller, a Terraform provider, the OS image.
9. An independent security audit before any 1.0.

Rules for work on the API and the web UI:

- A new route takes a `Caller` and checks `caller.may(...)` before anything else. Add its case to the HTTPS test in `crates/oxd/tests/daemon.rs`.
- Never trust a name the client sends. On the socket it comes from `SO_PEERCRED`; on HTTPS from the token.
- In `app.js`, build elements with `h()` and pass daemon text as children. Never assign `innerHTML`. No inline script or style: the CSP forbids both.
- To look at the web UI, run `oxd --dry-run --listen-http 127.0.0.1:8098` with a scratch state directory and open it in a browser. `--dry-run` loads nothing into the kernel.

Run before handing work back:

```sh
cargo fmt --all && cargo clippy --workspace --all-targets && cargo test --workspace && cargo deny check
```

If the config types change, regenerate the published schema with
`cargo run -p ox-cli -- schema > schema/netoxide-config-1.schema.json`.

To run the daemon by hand without touching the host, start it under
`unshare -Urn` as the README shows. For DNS and DHCP in a namespace, add
`--keep-service-privileges` and create the inside interface first (see
`start_home` in `crates/oxd/tests/daemon.rs`). In zsh, do not put a command in
a variable and run `$VAR args`: zsh does not split it. Never start `oxd` without `--dry-run`
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

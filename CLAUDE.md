# Netoxide: brief for Claude

Netoxide is an open-source firewall and router OS on Linux with a Rust control
plane. It is for teams that run 10 to 300 firewalls across sites, mostly people
moving off pfSense or OPNsense. The pitch is "every claim checkable": public
source, a published config schema, signed A/B upgrades, and published HA test
results.

The full spec is in `docs/spec.md`. Read it before any design or architecture
decision. This file gives you what you need to start working.

## Current state (15 Nov 2026)

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
| Interfaces | `crates/oxd/src/net.rs` | On apply: add the config's addresses over netlink, bring links up, set default routes (`gateway`), enable forwarding. Remembers what it added (`managed.json`) and removes only that, when a config drops it or a commit fails. Missing interfaces are reported in status, not fatal |
| DHCP client | `crates/oxd/src/dhcp.rs` | `dhcp_client = true` on the uplink: a tokio task per interface speaks DHCP in raw Ethernet frames on a packet socket, installs address and default route, renews, and re-requests its old address after a restart. The validator requires a visible accept rule for udp/68 |
| WireGuard | `crates/ox-schema/src/vpn.rs`, `crates/oxd/src/wg.rs` | `[wireguard.<iface>]` with peers. The interface is made over rtnetlink and configured over the kernel's WireGuard generic-netlink family; no `wg` program. Private keys live in `<state>/wireguard/<iface>.key`, never in config, commits, audit log or API. Peers are updated in place so a commit does not reset sessions. Routes for peers' `allowed` networks are tracked in `managed.json`. Easy path: `add_vpn_peer` in `ox-setup`, `ox vpn add`, web form |
| VM test | `tests/vm/` | Boots the host kernel in QEMU with a root disk built from the host's `/usr`, installs per `dist/README.md`, 129 checks under real systemd including a crash and a reboot. Not in CI |
| Access control | `crates/ox-store/src/auth.rs`, `crates/oxd/src/api.rs` | Socket peer = admin, named from the kernel. HTTPS = bearer token with a role. A role is a set of actions, optionally held to sections of the config (firewall, network, services, vpn); six are built in and more are made with `ox role create`. Four-eyes approval. Every handler takes a `Caller` and calls `caller.may(Action::…)` first, and every handler that changes the config also calls `caller.within(&touched)` |
| Remote CLI | `crates/ox-client/` (`tls.rs`, `remotes.rs`), `crates/ox-cli/src/remote.rs` | `ox --remote <name>` and the TUI's `--remote` talk to the HTTPS listener. A self-signed box is pinned by certificate SHA-256 (shown by `ox status`); otherwise the machine's CA bundle decides. Tested end to end in `crates/ox-cli/tests/remote.rs` |
| Listener limits | `crates/oxd/src/limit.rs` | 256 connections, 32 per IPv4 address or IPv6 /64, 30 s for a request's headers, closed after 120 s with no bytes (`OXD_IDLE_SECS` shortens it for tests) |
| Web UI | `crates/oxd/web/` | `index.html`, `app.js`, `app.css`, compiled in with `include_str!`. No build step, no dependencies, strict CSP, daemon text inserted with `textContent` only |
| Hygiene | `crates/ox-nft/src/hygiene.rs` | Shadowed, redundant and allow-everything rules; `oxd` adds "no packets" from kernel counters |
| Packaging | `dist/`, `.github/workflows/ci.yml`, `SECURITY.md` | systemd unit (`Type=notify`; runs in the VM test), install steps (run by the VM test), CI |
| CLI | `crates/ox-cli` | `ox`: daemon commands, `ox file ...` offline commands, `ox import` |
| Socket client | `crates/ox-client` | The small HTTP client `ox` and the TUI share |
| DNS and DHCP | `crates/ox-services` + `crates/oxd/src/services.rs` | `[dns]` and `[dhcp.<iface>]` in the schema, rendered as a dnsmasq config; `oxd` runs and restarts dnsmasq. Applied and reverted with the ruleset as one `Target` |
| Easy path | `crates/ox-setup` | `detect` (ports of this machine), `starter` (guided-setup config), `add_forward`, `block`, `describe`. Behind `ox init`, `ox forward`, `ox block` |
| Importer | `crates/ox-import` | pfSense config.xml → config + report + differential verify |
| IPsec, multi-WAN, routing protocols, IDS, HA, controller, Terraform, OS image | — | **Not started** |

The daemon has run inside rootless network namespaces and in the test VM
(`tests/vm/run.sh`: real systemd, root, virtio network cards, SELinux off).
Nobody has run it on hardware.

An internal security review on 14 Nov 2026 found no auth bypass or config
injection. Its other findings are fixed, with tests, except two that are
listed under "Limits today" in `docs/status.md`: wall-clock deadlines and the unkeyed
audit chain. Section-limited roles and the remote CLI had their own internal pass on
15 Nov; its five findings are fixed. The one that mattered: zone membership of
an interface or tunnel is a firewall change (`zones_of` in `auth.rs`), because
rules are written between zones. A damaged audit
log must never stop the rules loading (`Audit::open` repairs or sets aside).

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

## Docs and releases

The top-level `README.md` is the front page: status, the terminal and browser
overviews with pictures, a short feature list, a two-minute try, limits. Keep
it short. Detail lives in `docs/`: `getting-started.md`, `config.md`,
`interfaces.md`, `access.md`, `reference.md` (every command and route),
`status.md` (what works, limits, not built), `architecture.md` (crates, design
rules, tests). `roadmap.md` is the public plan (trust-gated phases; the build order for
Phase 1 is there), `threat-model.md` and `recovery.md` are the trust pages.
The README test count and the one in `architecture.md` must match the suite.
When a feature lands, update `docs/status.md`,
`docs/reference.md` and `CHANGELOG.md`; touch the README only if the front
page is now wrong.

The pictures in `docs/images/` are made by hand: `netoxide-tui --socket <s>
--snapshot <screen> --size 132x34 --html-out <file>` writes a live screen as a
page, and the web pictures are browser captures of a `--dry-run` daemon loaded
with `examples/branch.toml` and `examples/branch-candidate.toml`. Retake them
when a screen changes.

The version is 0.1.0 and is set once, in the workspace `Cargo.toml`. Nothing
has been tagged or released. `docs/releasing.md` has the checklist and the
blockers (no licence, no name check, stacked PRs unmerged, repo private).
`.github/workflows/release.yml` builds a draft release from a `v*` tag. Do not
tag or publish; that is Matt's step.

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
  ox-client/      HTTP client for oxd, shared by ox and the TUI: the Unix socket, or HTTPS with a pinned certificate
  ox-setup/       guided setup and one-step actions; all return ordinary Config
  ox-services/    renders [dns] and [dhcp] as a dnsmasq config; text only, no process handling
  ox-import/      pfSense backup → config, report, verify
examples/         branch.toml, branch-candidate.toml, flows.jsonl, pfsense-config.xml
tui/              netoxide-tui: live.rs + live_ui.rs (live mode), app.rs + ui.rs + data.rs (mock mode)
```

Proposed next, not decided, roughly in this order:

1. Run it on real hardware with SELinux enforcing, and a first watched deployment. DHCPv6 prefix delegation for the inside network. VLAN and PPPoE interfaces.
2. Services as sandboxed systemd units instead of direct children of `oxd`; Unbound and Kea renderers beside dnsmasq. The schema must stay backend-neutral.
3. More one-step actions (add a guest network, allow a service) in `ox-setup`, the same actions in the TUI, rule editing there, and `ox trace`.
4. IPsec (strongSwan over VICI; not installed on Matt's machine). WireGuard follow-ups: full-tunnel peers (needs policy routing), preshared keys, a test against the official `wg` tools.
5. OIDC sign-in (needs an outbound HTTPS client and JWT checks in the daemon, and a test identity provider). Roles held to one zone pair or interface.
6. Multi-WAN, FRR, CAKE, Suricata.
7. OPNsense import, and testing the pfSense importer against real backups.
8. HA, the fleet controller, a Terraform provider, the OS image.
9. An independent security audit before any 1.0.

Run `tests/vm/run.sh` after touching `dist/oxd.service`, the daemon's start-up, `net.rs` or `dhcp.rs`. It caught bugs the namespace tests could not: the unit's system-call filter killed dnsmasq, a failed commit left addresses behind, `ox explain` said "no route" for an uplink with no fixed address, and the daemon hung forever on any DNS or DHCP change because the unit gave it no right to signal dnsmasq (CAP_KILL). The namespace tests run dnsmasq as the daemon's own user, so they cannot see permission problems between the two.

The strongest `cargo test` test is `packets_cross_the_box_as_the_config_and_explain_say` in `crates/oxd/tests/daemon.rs`: three namespaces, real traffic, and every result compared with explain. When you add a data-plane feature, extend that lab instead of trusting the rendered JSON alone.

Rules for work on the API and the web UI:

- A new route takes a `Caller` and checks `caller.may(...)` before anything else. Add its case to the HTTPS test in `crates/oxd/tests/daemon.rs`.
- A route that changes the config, or keeps or undoes a change, also calls `caller.within(...)` with the sections the change touches (`Engine::touched_by*`). A new top-level config key needs a case in `Section::of_key`; a test fails until it has one, and an unknown key counts as every section.
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

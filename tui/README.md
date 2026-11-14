# netoxide-tui

A terminal UI prototype for Netoxide, built with ratatui. It covers the same
screens as the design canvas, with the same mock data, so the two can be
compared side by side.

Nothing here talks to a firewall. All data lives in `src/data.rs`.

## Run

```sh
cargo run --release
```

Needs a terminal of at least 110×30 with Unicode and 256 colours.

## Keys

| Key | Does |
| --- | --- |
| `1`…`9`, `0` | Policy, NAT, VPN, IPS, Interfaces, HA, Changes, Explain, Admin/Audit, Fleet |
| `tab` / `shift-tab` | Next / previous screen |
| `↑↓` or `j k` | Move the selection |
| `←→` or `h l` | Zone pair on Policy, NAT type on NAT |
| `x` | Policy: jump to Explain |
| `c` | Changes: commit the candidate with a confirm window |
| `w` | Changes: cycle the confirm window (2, 5, 10 min) |
| `y` / `r` | Confirm or revert a pending commit, from any screen |
| `m` | Explain: switch between the running config and the candidate |
| `f` | HA: fail over (asks first) |
| `?` | Help |
| `q`, `ctrl-c` | Quit |

The commit-confirm countdown runs in real time and shows in the top bar on every
screen. If it reaches zero, the candidate reverts on its own.

## Headless snapshots

Render any screen to plain text, optionally after replaying keys:

```sh
cargo run -- --snapshot all --size 160x46
cargo run -- --snapshot changes --keys c      # pending commit-confirm
cargo run -- --snapshot ha --keys f           # failover prompt
cargo run -- --snapshot explain --keys m      # verdict against the candidate
```

## Layout

- `src/main.rs` sets up the terminal, runs the event loop and handles snapshot mode
- `src/app.rs` holds state and key handling
- `src/ui.rs` draws one function per screen
- `src/data.rs` holds the mock data

## What a real build would change

`data.rs` would become a client of the `oxd` API. Policy, NAT and the other
config screens would read the running config and write a candidate.
Changes would call plan and commit. Explain would call the compiled-ruleset
evaluator.

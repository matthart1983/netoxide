# Contributing

Netoxide is at 0.1 and has one maintainer. Bug reports, test results from real hardware and small fixes are the most useful things you can send.

Netoxide is under the [MIT licence](LICENSE). What you contribute is under the same licence. There is no contributor agreement to sign.

## Build and test

You need Rust 1.88 or later and the `nft` program (the `nftables` package). The kernel tests also use `unshare`, `nsenter`, `ip`, `curl`, `dig`, `python3`, `dnsmasq` and the kernel's WireGuard module, and they need unprivileged user namespaces.

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

A kernel test that cannot run on your machine says so and passes. Set `OX_REQUIRE_KERNEL_TESTS=1`, as CI does, to make that a failure.

`tests/vm/run.sh` boots a virtual machine and checks the installed daemon under systemd. Run it after changing the service unit, the daemon's start-up, or anything that touches interfaces. It needs QEMU with KVM. See [tests/vm/README.md](tests/vm/README.md).

## Running the daemon safely

Outside a network namespace, `oxd` replaces the host's `netoxide` nftables table and the default is to drop. While developing, run it one of two ways:

```sh
unshare -Urn ./target/debug/oxd --state-dir /tmp/ox-state --socket /tmp/oxd.sock   # real kernel, private namespace
./target/debug/oxd --dry-run --state-dir /tmp/ox-state --socket /tmp/oxd.sock      # no kernel changes at all
```

## Rules for code

- `unsafe` is forbidden in every crate.
- The daemon never builds a shell command. Programs are started with a fixed argument list.
- Every rule, NAT and VPN test covers IPv4 and IPv6.
- A new API route takes a `Caller` and checks what the caller may do before anything else. A route that changes the config also checks the caller's sections.
- No performance claims in code comments or docs. There are no measurements to back them.
- Run `cargo deny check` when you change dependencies.
- If the config types change, regenerate the schema: `cargo run -p ox-cli -- schema > schema/netoxide-config-1.schema.json`.

[docs/architecture.md](docs/architecture.md) describes the crates and the design rules.

## Reporting a security problem

Not in a public issue. See [SECURITY.md](SECURITY.md).

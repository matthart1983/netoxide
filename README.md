# Netoxide

Netoxide is an open-source firewall and router for Linux, written in Rust. You say which networks can reach each other, and it loads the rules into the kernel through nftables. Every change undoes itself after two minutes unless you keep it, so a mistake cannot lock you out.

It is built for home labs first: one box, set up in a few minutes, clear about what it is doing.

**Status: 0.1.0, a preview.** It passes its tests in network namespaces and in a virtual machine. It has never run on real hardware and has had no outside security audit. Do not put it in front of a network you care about yet. [What works and what does not](docs/status.md).

![A recording of the terminal interface: adding a guest network, applying it safely and keeping it, allowing the inside network to reach it, then asking whether a guest device can reach an inside one](docs/images/tui-demo.gif)

## What it does

- **Firewall and NAT** for IPv4 and IPv6, with port forwards, loaded as one atomic change.
- **A whole router**: DNS, DHCP, IPv6 announcements, VLANs, and a WireGuard VPN.
- **Safe changes.** You see each change in a sentence before it is applied. Applied changes undo themselves unless you keep them.
- **One-step tasks**: add a guest network, let a service in, block a device or a website, add a phone to the VPN.
- **"Is something blocked?"** Give two addresses and it says what the box would do and which rule decides.
- **Tokens and roles**, an audit log, Prometheus metrics, and a pfSense config importer.

Each feature, with how it was tested, is in [docs/status.md](docs/status.md).

## Three ways to use it

All three do the same things to the same config. Each opens on a few plain screens or commands, and the detailed ones are switched off until you want them.

| | |
| --- | --- |
| **Terminal** | `netoxide-tui` fits an 80×24 terminal, so it works over SSH. The recording above shows it. |
| **Browser** | Served by the box over HTTPS. A new box is set up here with a code shown on its console. |
| **Command line** | `ox --help` lists a dozen everyday commands, and `ox more` lists the rest. |

![The browser's Access screen: a grid of three networks with Allowed and Blocked cells, and what is let in from the internet](docs/images/web-access.png)

```sh
ox network add "Guest Wi-Fi" --port eth1 --vlan 20   # a network of its own, kept apart
ox block example.com                                 # a website, by name
ox apply                                             # undoes itself unless you run `ox keep`
```

Every screen is in [docs/interfaces.md](docs/interfaces.md) and every command in [docs/reference.md](docs/reference.md).

## Try it in two minutes

This runs the daemon in a private, rootless network namespace. It cannot touch your machine's own firewall. You need Rust 1.88 or later, the `nftables` package and `unshare`.

```sh
cargo build
export OX_SOCKET=/tmp/oxd.sock
unshare -Urn ./target/debug/oxd --state-dir /tmp/ox-state --socket $OX_SOCKET &

./target/debug/ox candidate save demo examples/branch.toml
./target/debug/ox apply demo        # undoes itself in two minutes...
./target/debug/ox keep              # ...unless you keep it
./target/debug/netoxide-tui --live
```

Run `oxd` outside a namespace only on a box you mean to turn into a firewall: it blocks by default. [docs/getting-started.md](docs/getting-started.md) continues from here.

## Install on a box

On an x86-64 Linux machine with systemd, download the archive from the [latest release](https://github.com/matthart1983/netoxide/releases), unpack it, and run in its directory:

```sh
sudo sh dist/install.sh --packages
```

It starts the daemon and prints a setup code with the address to open in a browser. `--remove` takes it off again. There is no OS image yet. Details are in [dist/README.md](dist/README.md), and [docs/proxmox.md](docs/proxmox.md) covers a VM on Proxmox.

## Limits

- **It has never run on real hardware or carried real traffic.**
- **Nobody outside the project has reviewed its security.**
- **Nobody but its author has used the interfaces.** Scripts drive them on every change.
- Not built: multi-WAN, routing protocols, traffic shaping, intrusion detection, high availability, single sign-on, fleet management.

The full list is in [docs/status.md](docs/status.md#limits-today), and what comes next is in [docs/roadmap.md](docs/roadmap.md).

## How the code is written

Most of the code, tests and documentation were written by an AI coding assistant, Claude, directed by one human maintainer who decides what gets built and merges it. No second person has reviewed it line by line.

What stands in for that today is 189 tests, some of which send real packets through the kernel and compare the result with what the firewall says it will do, and a virtual machine test of the installed system. That is evidence, not an audit. See the [threat model](docs/threat-model.md) and [how it is built and tested](docs/architecture.md).

There is no AI on the box. The firewall calls no model and sends no data anywhere.

## Documentation

- **Start:** [getting started](docs/getting-started.md) · [install](dist/README.md) · [Proxmox](docs/proxmox.md)
- **Use:** [the interfaces](docs/interfaces.md) · [the config file](docs/config.md) · [remote access, tokens and roles](docs/access.md) · [every command and API route](docs/reference.md)
- **Trust:** [status and limits](docs/status.md) · [threat model](docs/threat-model.md) · [if a change locks you out](docs/recovery.md) · [reporting a vulnerability](SECURITY.md)
- **Project:** [roadmap](docs/roadmap.md) · [architecture and tests](docs/architecture.md) · [changelog](CHANGELOG.md) · [contributing](CONTRIBUTING.md) · [releasing](docs/releasing.md) · [design](docs/design/README.md)

## Licence

MIT. See [LICENSE](LICENSE).

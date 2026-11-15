# Getting started

Try Netoxide in a private namespace, then set a box up from nothing.

- [Try it without touching your machine](#try-it-without-touching-your-machine)
- [Start from nothing](#start-from-nothing)

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

That uses a ready-made example. On a real box you would start with the guided setup instead; see [Start from nothing](#start-from-nothing).

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

## Start from nothing

`ox init` looks at the machine's network ports, asks which one faces the internet and which face your inside network, and writes a complete config:

```
$ ox init --save starter
Ports on this machine:

  eth0           up    203.0.113.10/24  ← reaches the internet now
  eth1           up    no address

Which port faces the internet? [eth0]:
Which ports face your inside network? (separate with spaces) [eth1]:
What address should the box have on eth1? [192.168.10.1/24]:

This config will do the following:

  eth0 is in zone wan (203.0.113.10/24)
  eth1 is in zone lan (192.168.10.1/24)
  lan → wan: everything from anyone to anywhere is allowed (r-inside-out)
  lan → wan: everything else is dropped
  lan → the box itself: ssh, ping from anyone to anywhere is allowed (r-manage)
  lan → the box itself: dns, dhcp from anyone to anywhere is allowed (r-services)
  lan → the box itself: everything else is dropped
  wan → the box itself: dhcpv6-client from fe80::/10 to anywhere is allowed (r-dhcpv6)
  wan → the box itself: everything else is dropped
  traffic from 192.168.10.0/24 leaving by wan appears to come from the box's own address (n-inside-out)
  the box answers DNS for lan, forwarding to 1.1.1.1, 9.9.9.9, with DNSSEC checking
  local names end in .home.arpa
  devices on eth1 get an address from 192.168.10.100 to 192.168.10.199, kept for 12h
  wan → lan: no rules, so everything is dropped

Saved as starter. Nothing has been applied.
Apply it with: ox apply starter
It undoes itself after 2 minutes unless you run `ox keep`, so a mistake cannot lock you out.
```

The same setup is in the web interface: a box with no config shows it when you open its page. See [interfaces.md](interfaces.md#getting-in).

In short: the inside network can reach the internet and is hidden behind the box's address, devices inside get an address and DNS from the box, the box can be managed over SSH from inside only, and everything arriving from the internet is dropped. DNS and DHCP need `dnsmasq` installed; `ox init --no-services` leaves them out. Pass `--wan` and `--lan` to skip the questions, and `--out <file>` to write a file instead of saving a candidate. `ox init` only reads the machine. It changes nothing until you commit.

Everyday changes are single commands. Each reads the running config, makes the change, and saves the result for you to apply:

```sh
ox forward --name "Home Assistant" --port tcp/443 --to 192.168.10.20:8123
ox block 192.168.10.66 --name "Smart TV"
ox access                          # who can reach what, as a grid
ox access block lan wan            # stop one network reaching another
ox apply                           # apply the waiting change, with a two-minute undo timer
ox keep                            # or `ox undo`
```

`ox --help` lists these everyday commands. `ox more` lists every command, including named candidates, plan, commit with a timer of your choice, rollback and the audit log.

`ox forward` adds the port forward and the filter rule it needs, then checks with the explain engine that a packet from outside is accepted by that rule. If an earlier rule would have decided the packet first, it places the new rule ahead of it and says so. `ox block` drops and logs everything the device sends, to other networks and to the box.

The result of all three is ordinary config. You can open it, edit it by hand, and use every advanced command on it.

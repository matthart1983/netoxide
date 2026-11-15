# The config and how changes work

The config file, how a change reaches the kernel, explaining a packet, and importing from pfSense.

- [The config](#the-config)
- [How a change reaches the kernel](#how-a-change-reaches-the-kernel)
- [Explain a packet](#explain-a-packet)
- [Import from pfSense](#import-from-pfsense)

## The config

One document describes the box. This is a cut-down version of [`examples/branch.toml`](../examples/branch.toml):

```toml
schema = 1
hostname = "syd-br-014-a"

[zones.lan]
[zones.dmz]
[zones.wan]

[interfaces.wan0]
zone = "wan"
addresses = ["203.0.113.10/32", "2001:db8:4a00::1/64"]
default_route = true

[interfaces."lan0.20"]
zone = "lan"
addresses = ["10.20.0.1/16", "2001:db8:4a00:1::1/64"]

[interfaces."lan0.30"]
zone = "dmz"
addresses = ["10.30.0.1/24", "2001:db8:4a00:2::1/64"]

[addresses]
finance-pcs = ["10.20.4.0/24", "2001:db8:4a00:1:4::/80"]
finance-file-servers = ["10.30.0.8", "10.30.0.9", "2001:db8:4a00:2::8"]
web = ["10.30.0.10", "2001:db8:4a00:2::10"]

[services]
smb = ["tcp/445", "tcp/139"]
https = ["tcp/443"]

[[policy]]              # one entry per zone pair; rules are tried in order
from = "lan"
to = "dmz"

[[policy.rule]]
id = "r-0388"
name = "Finance to file servers"
action = "accept"       # accept, drop or reject
source = ["@finance-pcs"]
destination = ["@finance-file-servers"]
service = ["smb", "https"]
reason = "Open file share for finance, CHG-1984"

[[policy]]
from = "wan"
to = "dmz"

[[policy.rule]]
id = "r-0200"
name = "Public web"
action = "accept"
destination = ["@web"]
service = ["https"]
log = true

[[nat.forward]]
id = "n-0010"
name = "Public web"
from = "wan"
address = "203.0.113.10"
service = "tcp/443"
to = "10.30.0.10"
rule = "r-0200"         # the filter rule that lets the translated packet in

[[nat.outbound]]
id = "n-0100"
name = "Staff to the internet"
from = "lan"
to = "wan"
source = ["10.20.0.0/16"]
translate = "masquerade"
```

How to read it:

- **Zones** group interfaces. Rules are written between two zones, never on one interface. `to = "self"` is traffic addressed to the box.
- **A zone pair with no policy is dropped.** So is anything that matches no rule in its pair, and that drop is logged unless `log_default = false`.
- **Sources and destinations** are `"any"`, `"@group"`, a network in CIDR form, or one address. **Services** are `"any"`, a name from `[services]`, or `tcp/443`, `udp/137-138`, `icmp`, `icmpv6`.
- **A port forward only rewrites the destination.** The packet still has to pass the filter rule named in `rule`, so there is no hidden pass rule.
- **Rule IDs are stable.** They appear in logs, in `ox explain` and in the kernel as the rule's comment.

DNS and DHCP are two more sections. This is from [`examples/home.toml`](../examples/home.toml):

```toml
[dns]
zones = ["lan"]                        # who may use the resolver
upstream = ["1.1.1.1", "9.9.9.9"]      # where it forwards to
domain = "home.arpa"                   # nas is also nas.home.arpa

[[dns.host]]
name = "nas"
address = "192.168.10.5"

[dhcp.eth1]                            # one pool per interface
first = "192.168.10.100"
last = "192.168.10.199"
lease = "12h"

[[dhcp.eth1.static]]                   # this device always gets this address
mac = "aa:bb:cc:dd:ee:01"
address = "192.168.10.5"
name = "nas"
```

A WireGuard tunnel is one more section. The config holds each peer's public key and never a private one:

```toml
[wireguard.wg0]
zone = "vpn"                           # policies from and to "vpn" decide what peers reach
addresses = ["10.90.0.1/24"]
listen_port = 51820                    # needs an accept rule for udp/51820 to self

[[wireguard.wg0.peer]]
name = "laptop"
public_key = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
allowed = ["10.90.0.2/32"]             # one address for a device, whole networks for a site

[[wireguard.wg0.peer]]
name = "branch"
public_key = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
allowed = ["10.90.0.3/32", "192.168.77.0/24"]
endpoint = "198.51.100.7:51820"        # this box connects out to that one
keepalive = 25
```

`ox vpn --key wg0` prints this box's public key for a tunnel, before or after the tunnel is in the config, so two sites can swap keys first.

DNSSEC checking is on unless you set `dnssec = false`. Clients are told to use the box as their resolver and router. A service needs a visible rule like everything else: validation refuses a config that serves DNS or DHCP to a zone without an accept rule for it in that zone's policy to `self`, and says which rule to add.

Validation catches things like unknown zones and groups, duplicate rule IDs, rules whose source and destination are different address families, and a forward that names a rule from the wrong zone. A typo such as `tcp/99999` or `10.20.4.17/16` fails with the value named and the fix suggested.

### VLANs

An interface is normally one the machine already has. Give it a `vlan` and the box creates it as a tagged network on another port:

```toml
[zones.guest]

[interfaces."eth1.20"]          # any name up to 15 characters
zone = "guest"
vlan = { parent = "eth1", id = 20 }
addresses = ["192.168.20.1/24", "2001:db8:20::1/64"]
```

The port named as `parent` does not need its own entry. It carries untagged traffic too if it has one. The box removes a VLAN interface it made when the config drops it, and makes it again if the port or the number changes. An interface of that name that something else made is used as it is and never removed. A VLAN cannot sit on another VLAN.

Because rules are written between zones, putting a VLAN in its own zone is how you keep guests or cameras apart from the rest: with no policy from `guest` to `lan`, nothing crosses.

## How a change reaches the kernel

1. `ox candidate save` stores a config under a name. The daemon refuses one that does not validate and compile.
2. `ox plan` shows the diff against the running config, the compiled size, and the flows whose verdict would change.
3. `ox commit` compiles the candidate, renders it as one nftables transaction, and loads it. If the kernel refuses any part, nothing changes.
4. With `--confirm`, the commit is running but pending. `ox confirm` keeps it. `ox revert`, the deadline, or a daemon restart undoes it by loading the previous commit.
5. The commit, its author, its reason and the config's hash go into the history and the audit log.

Plan output for the example candidate:

```
✓ schema validation passed
✓ compiled 9 rules in 5 zone pairs → 19 nftables rules, 27 sets, 2 verdict maps, longest chain 6
✓ one nftables transaction, atomic swap

2 change(s)
  + rule r-0412 "Drop SMB and NetBIOS": lan → dmz: drop any → any · smb, netbios, position 1
  ~ rule r-0388 "Finance to file servers": service: smb, netbios, https → https

4 of 8 replayed flows get a different verdict
  10.20.4.17 → 10.30.0.8 tcp/445 in lan0.20  ACCEPT → DROP  by r-0412  · 1204 flows · finance-pc pool
  10.20.4.33 → 10.30.0.9 tcp/139 in lan0.20  ACCEPT → DROP  by r-0412  · 88 flows · scanner-02
  ...
```

The flows file is JSON Lines, one observed flow per line. See [`examples/flows.jsonl`](../examples/flows.jsonl). Nothing collects flows yet, so you supply the file.

## Explain a packet

```sh
ox explain --src 10.20.4.17 --dst 10.30.0.8 --proto tcp --dport 445 --in lan0.20 \
           --candidate block-legacy-smb
```

```
10.20.4.17 → 10.30.0.8 tcp/445 in lan0.20

running
verdict  ACCEPT
 1 ingress    lan0.20 → zone lan
 2 route      out lan0.30 → zone dmz
              10.30.0.0/24 is connected
 3 zone pair  lan → dmz
              3 rules, first match wins
 4 rule       r-0388 accept · Finance to file servers
              position 1 of 3 · Open file share for finance, CHG-1984

candidate block-legacy-smb
verdict  DROP
 ...
 4 rule       r-0412 drop · Drop SMB and NetBIOS
              position 1 of 4 · Retire SMBv1 shares, CHG-2207 · logged

the candidate changes this packet: ACCEPT → DROP
```

Explain evaluates the same resolved ruleset that gets rendered for the kernel, so the two cannot disagree about addresses and ports. It treats the packet as the first of a new connection. It does not read live kernel state, and it knows only the routes the config states: interface networks and the default route.

## Import from pfSense

```sh
ox import examples/pfsense-config.xml --out imported.toml
```

Every item of the backup lands in one of three lists:

- **Translated** one to one.
- **Changed**: it works but differs, and the report says how. Examples are a floating rule that becomes several zone-pair rules, automatic outbound NAT written out as explicit rules, and pfSense's implicit anti-lockout rule made visible.
- **Unsupported**: it was left out, with the manual step. Examples are negated matches, aliases with hostnames, OpenVPN, captive portal and packages.

The importer does not guess. A rule it cannot translate exactly is left out, and the report says whether that drops traffic or might now allow it.

After translating, it replays probe packets through a model of the pfSense ruleset and through the new config, and lists every packet that gets a different verdict. Pass `--verify flows.jsonl` to replay your own flows instead. On the sample backup, 123 of 124 probes agree. The one that differs is a real semantic gap, and the report names it: a pfSense port forward with "Pass" association becomes NAT plus an explicit rule, and that rule also accepts packets sent straight to the internal host.

Two cautions. The importer has only been tested on a backup written by hand for this repo, not on a real one. It reads pfSense only. OPNsense backups are refused by name.

pfSense interface names are FreeBSD names such as `igb0`. The importer keeps them, and you rename them to the Linux names of the new box.

# Installing Netoxide on a Linux machine

`tests/vm/run.sh` runs these steps in a virtual machine and checks the result,
including a reboot. They have **not been run on hardware**, or on a system
with SELinux or AppArmor enforcing. Try this on a spare machine or a VM with
console access, not on a box you can only reach over the network.

## What you need

- A Linux kernel with nftables, and the `nft` program (package `nftables`)
- `dnsmasq`, if the box will answer DNS or hand out addresses
- Rust 1.88 or later to build

## Install from a package

Each release has a `.deb` and an `.rpm` for x86-64:

```sh
sudo apt install ./netoxide_*_amd64.deb      # Debian 12 or later, Ubuntu 22.04 or later
sudo dnf install ./netoxide-*.x86_64.rpm     # Fedora, RHEL 9 and its rebuilds
```

The package brings in `nftables`, puts the programs in `/usr/bin` and the
service unit in place, and starts the daemon with the web interface on port
8443. A box with no config loads no rules, so installing changes no traffic.
Run `ox status` for the setup code, then open `https://<the box>:8443/`, or
run `ox init --save starter && ox apply starter` on the box. Install
`dnsmasq` (`dnsmasq-base` on Debian and Ubuntu) if the box will answer DNS or
hand out addresses.

Removing the package stops the daemon and takes its rules out of the kernel.
`apt purge netoxide` also deletes the state in `/var/lib/netoxide`: the config
history, VPN keys and tokens. An rpm removal leaves that directory for you to
delete. Example configs and the JSON Schema are in `/usr/share/netoxide`.

CI installs both packages in clean containers of Debian 12 and 13, Ubuntu
22.04 and 24.04, Fedora and AlmaLinux 9, loads a real ruleset with each
distribution's own `nft`, and removes them. Nobody has installed one on
hardware yet.

## Install with the script

On any other systemd distribution, from an unpacked release archive or from a
source tree built with `cargo build --release`:

```sh
sudo sh dist/install.sh              # add --packages to install nftables and dnsmasq too
```

It installs the programs and the service, turns on the web interface, starts
the daemon, and prints a setup code with the addresses to open. It tells you
about anything on the machine that would conflict. `sudo sh dist/install.sh
--remove` takes it all off again. For a VM on Proxmox, see
[`docs/proxmox.md`](../docs/proxmox.md).

By hand, the same thing is:

```sh
sudo install -m 0755 target/release/oxd target/release/ox /usr/bin/
sudo install -m 0644 dist/oxd.service /etc/systemd/system/oxd.service
sudo systemctl daemon-reload
```

Netoxide sets addresses and the default route on the ports its config names.
Take those ports away from the operating system's network manager first
(NetworkManager, systemd-networkd, ifupdown), or both will configure them.

Stop anything else that manages the firewall or serves DNS and DHCP on the
same ports first, such as firewalld, a distribution's own nftables service, or
a system dnsmasq. Netoxide only touches its own nftables table, `inet
netoxide`, but two firewalls on one box is asking for confusion.

## First start

```sh
sudo systemctl enable --now oxd
sudo ox status
sudo ox init --save starter        # answer the questions: which port faces the
                                   # internet, whether the provider assigns its
                                   # address, which ports face inside
sudo ox apply starter              # applied with a two-minute undo timer
sudo ox keep                       # only once you have checked you still have access
```

`ox apply` is what keeps you from locking yourself out: if you lose access, do
nothing, and the box goes back by itself after two minutes. For a longer
window use `ox commit starter --confirm 5m` and `ox confirm`.

Or skip the command line: turn on the web interface as described below and
set the box up from a browser.

The socket is `/run/netoxide/oxd.sock`. Whoever can open it is an admin, so it
belongs to root. To let a group use `ox` without sudo, change the socket's
group with a systemd drop-in.

## The web UI

Put the listener option in `/etc/netoxide/oxd.env`:

```sh
OXD_ARGS=--listen 0.0.0.0:8443
```

Restart the daemon and open `https://<box>:8443/` from a device on the inside
network. The daemon makes its own certificate on first start, so the browser
will warn. Give it a real one with `--tls-cert` and `--tls-key`.

**On a box with no config, the page offers setup.** It asks for the setup
code, which `sudo ox status` shows on the box, then which port goes to the
internet and which are yours. It applies the result with a five-minute undo
timer and gives you an admin access token. Save the token: it is how you sign
in afterwards. Setup opens the web interface's port from the inside network
for you.

**On a box you set up with `ox init`**, allow the port yourself (a rule in the
inside zone's policy to `self` for `tcp/8443`) and make a token:

```sh
sudo ox token create laptop --role operator --days 90
```

## From another machine

With the listener on, `ox` on your own machine can manage the box. On the box:

```sh
sudo ox token create laptop --role operator --days 90
sudo ox status        # the last lines show the certificate's fingerprint
```

On your machine:

```sh
ox remote add home https://<box>:8443     # shows the fingerprint and asks for the token
ox --remote home status
```

Compare the fingerprint `ox remote add` shows with the one from the box before
you answer yes. To give someone less than an operator, see the roles in the
main README, for example `ox role create helpdesk --can edit,commit --sections vpn`.

## A VPN for your own devices

```sh
sudo ox vpn add laptop --endpoint home.example.net
sudo ox apply vpn-laptop
sudo ox keep
```

The first command sets the VPN up if there is none (a WireGuard tunnel, the
rule that lets devices connect, and rules that let them reach the inside
network), adds the device, and prints a config file. Import that file into
the WireGuard app on the device. `--endpoint` is the name or address the
device uses to find the box from outside. The printed file holds the device's
private key and is the only copy.

`sudo ox vpn` shows each device and when it was last heard from. The kernel
needs its `wireguard` module, which every current distribution kernel has.

## Locking down an unconfigured box

Add `--lockdown` to `OXD_ARGS` to drop inbound and forwarded traffic while
there is no config. Do this only when you have console access: it cuts SSH
until the first commit allows it.

## Monitoring

`GET /metrics` on either listener gives Prometheus metrics: the running
commit, whether one is waiting to be confirmed, service state, packets and
bytes per rule, and connection-tracking table use. On the HTTPS listener it
needs a token; a viewer token is enough.

## Removing it

`sudo sh dist/install.sh --remove` does all of this. By hand:

```sh
sudo systemctl disable --now oxd
sudo nft delete table inet netoxide     # the rules stay loaded until you do this
sudo rm /etc/systemd/system/oxd.service /usr/bin/oxd /usr/bin/ox
sudo rm -r /var/lib/netoxide            # commits, candidates, tokens, audit log, VPN keys
sudo ip link del wg0                    # once for each VPN tunnel, if you had any
```

Addresses the daemon put on your network ports stay until the next reboot or
until you remove them.

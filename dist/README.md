# Installing Netoxide on a Linux machine

`tests/vm/run.sh` runs these steps in a virtual machine and checks the result,
including a reboot. They have **not been run on hardware**, or on a system
with SELinux or AppArmor enforcing. Try this on a spare machine or a VM with
console access, not on a box you can only reach over the network.

## What you need

- A Linux kernel with nftables, and `libnftables.so.1` (package `nftables`)
- `dnsmasq`, if the box will answer DNS or hand out addresses
- Rust 1.88 or later to build

## Build and install

```sh
cargo build --release
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
sudo ox plan starter
sudo ox commit starter --confirm 5m
sudo ox confirm                    # only once you have checked you still have access
```

`ox commit --confirm` is what keeps you from locking yourself out: if you lose
access, do nothing, and the box goes back by itself.

The socket is `/run/netoxide/oxd.sock`. Whoever can open it is an admin, so it
belongs to root. To let a group use `ox` without sudo, change the socket's
group with a systemd drop-in.

## The web UI

Put the listener option in `/etc/netoxide/oxd.env`:

```sh
OXD_ARGS=--listen 0.0.0.0:8443
```

Restart the daemon, allow the port from where you manage the box (a rule in
the inside zone's policy to `self` for `tcp/8443`), then make a token:

```sh
sudo ox token create laptop --role operator --days 90
```

Open `https://<box>:8443/` and sign in with the token. The daemon makes its
own certificate on first start, so the browser will warn. Give it a real one
with `--tls-cert` and `--tls-key`.

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

```sh
sudo systemctl disable --now oxd
sudo nft delete table inet netoxide     # the rules stay loaded until you do this
sudo rm /etc/systemd/system/oxd.service /usr/bin/oxd /usr/bin/ox
sudo rm -r /var/lib/netoxide            # commits, candidates, tokens, audit log
```

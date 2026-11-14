# The VM test

`tests/vm/run.sh` boots a virtual machine, installs Netoxide in it the way
[`dist/README.md`](../../dist/README.md) says, and checks it as a firewall
under real systemd, as root, with real network cards. It takes about two
minutes and needs no root on the host.

```sh
cargo build --release
tests/vm/run.sh
```

## What it checks

The VM has four network cards joined in pairs. Two belong to the box. The
other two are moved into namespaces inside the VM: an inside client and an
outside server that also plays the internet provider.

- Install: the unit starts, the daemon answers, nothing is loaded before the first commit.
- The box gets its outside IPv4 address and default route from the provider by DHCP, and keeps them when the lease is renewed.
- The client gets its address from the box by DHCP and an IPv6 address from the announced network.
- Web traffic goes out over IPv4 and IPv6 with the source rewritten, to the next network and to one behind the provider's router. A port no rule allows times out. A forwarded port reaches the inside server.
- DNS: a local name, a name resolved through the upstream, and no answer for the outside.
- A commit that is not confirmed is undone when its timer ends.
- The daemon is killed: traffic keeps flowing, systemd restarts it, DNS and DHCP come back. Killed again with a commit waiting, the restart undoes that commit.
- HTTPS: a token gets in over IPv4 and IPv6, no token does not, a viewer cannot commit, the outside cannot reach the listener.
- A reboot: the daemon starts, loads the same commit, and all the traffic checks pass again.
- Removal as the install notes describe leaves no process and no rules.

## How it works

`build-rootfs.sh` makes a root disk from this machine's own `/usr` and a small
`/etc` it writes itself. Nothing is downloaded. The VM boots the host's kernel
directly, so the kernel needs virtio-blk and ext4 built in. It was written on
Fedora 44; another usr-merged systemd distribution should work and has not
been tried. The image is cached in `~/.cache/netoxide-vm`; delete it to
rebuild after a system update.

`guest.sh` runs inside the VM as a systemd service and prints one line per
check to the serial console. `run.sh` reads that log.

## What it does not cover

- SELinux and AppArmor are off in the VM. A system that enforces one may need policy the unit does not have.
- The network cards are virtual. No driver, link flap or cable is tested.
- It is not run in CI. Run it before a release and after touching the unit, the daemon's start-up or `crates/oxd/src/net.rs`.

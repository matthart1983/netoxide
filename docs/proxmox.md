# Netoxide as a virtual machine on Proxmox

How to run Netoxide in a VM with one network card to the internet and one to your own network. The same steps work on any KVM host; only the screens differ.

**How far this has been tested.** The project's VM test boots a KVM virtual machine with virtio network cards, installs Netoxide with the same script used here, and checks it end to end. That is the same hypervisor and the same kind of virtual hardware Proxmox uses. Nobody has yet followed these steps on Proxmox itself, and the test's guest is Fedora, not Debian. If a step is wrong, that is a bug worth reporting.

There is no ready-made VM image yet. You install a small Linux first and Netoxide onto it.

## What you need

- A Proxmox host with two bridges: one that reaches your modem or provider (often `vmbr0`), and one for the network the box will serve (say `vmbr1`). The second can be a bridge with no physical port if only other VMs will sit behind the box.
- A way to the VM's console, which Proxmox gives you. Use it. Do not rely on reaching the box over the network it is about to take over.
- A Netoxide release archive, or a build from source.

## 1. Make the VM

- **OS:** Debian 13 or Fedora 43 or later, minimal install, no desktop. Debian 12 is too old for the release binaries.
- **CPU and memory:** 1 core and 1 GB is plenty to start.
- **Disk:** 8 GB.
- **Network:** two virtio cards. The first on the internet-side bridge, the second on the inside bridge. Leave the Proxmox firewall off for both cards: Netoxide is the firewall.

Install the OS with the first card on DHCP so it can fetch packages. Leave the second card unconfigured.

## 2. Install Netoxide

On the VM's console, as root:

```sh
tar xzf netoxide-0.1.0-x86_64-linux.tar.gz
cd netoxide-0.1.0-x86_64-linux
sh dist/install.sh --packages
```

`--packages` installs `nftables` and `dnsmasq` with the system's package manager. Without it the script tells you what is missing and stops.

The script installs the programs and the service, turns on the web interface, starts the daemon, and prints a setup code and the addresses to open. It also tells you if something on the machine would fight Netoxide for the same job.

## 3. Hand the network cards over

Netoxide sets the addresses on the ports in its config. The installer's own network setup must let go of them, or both will configure the same card.

- **Debian with ifupdown:** remove the two cards' stanzas from `/etc/network/interfaces`, leaving `lo`.
- **Debian or Fedora with NetworkManager:** `nmcli device set <card> managed no` for both, or disable NetworkManager.
- **systemd-networkd:** remove the `.network` files that match the cards.

Do this after step 4 if the VM needs its installer-made connection to reach you. From the console it does not matter.

## 4. Set it up

From a device on the inside bridge, open `https://<the address the script printed>:8443/`. The browser warns about the certificate, which the box made itself.

Enter the setup code. Choose the first card as the one that goes to the internet and the second as your own network. Review what the box will do and apply it. You get five minutes to check things still work; if you lose the page, do nothing and the box undoes the setup by itself.

Save the access token it gives you. It is how you sign in afterwards.

Nothing is on the inside bridge yet to open a browser from? Do it on the console instead:

```sh
ox init --save starter
ox apply starter
ox keep
```

## 5. Check it

- A VM or device on the inside bridge gets an address from the box and can reach the internet.
- `ox status` on the console shows the running config and the services.
- In the web interface, Home says the firewall is running.

## If it goes wrong

- **Locked out:** use the console. `ox undo` if a change is still waiting, `ox rollback 1` if not. See [recovery.md](recovery.md).
- **No address on the inside:** check the second card is on the right bridge, and that nothing else there hands out addresses.
- **Start again:** `sh dist/install.sh --remove` takes Netoxide off the VM, with its state.

## Not covered

- Passing a physical network card through to the VM.
- VLANs on the Proxmox bridge. Netoxide can add tagged networks on a port (`ox network add`); the bridge must be VLAN-aware for the tags to pass.
- Running the box as a container. It needs its own kernel network stack and is only tested as a VM.

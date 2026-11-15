# Roadmap

Where Netoxide is going and in what order. The order is set by trust, not by features: each phase ends when there is evidence a stranger can check, such as a run on real hardware, outside users, a handled security report or a published audit. Dates are estimates for one maintainer.

Home-lab users come first. Paid things come later and are aimed at businesses.

## What stays free

The code is under the MIT licence. This is what the project commits to on top of that.

- Every feature that runs on the box.
- Every security fix, at the same time for everyone.
- Stable releases and updates.

What may cost money later: support with a response time, hosted services a business could also run itself, and hardware sold by partners.

## Phase 0. Clear the ground

No new users yet. The project gets what it needs to be used at all.

- A licence and a settled name. **Done:** MIT, and the name stays.
- 30 days on real hardware with SELinux enforcing.
- WireGuard tested against the official apps, and the importer against a real pfSense backup.
- Signed release archives.
- A threat model, a lockout recovery guide and a statement of how the code is written.

Ends when the repository can be opened and someone could legally run a release.

## Phase 1. Public preview for people with a spare VM

The first public release. It is for testers, not for the edge of a network you depend on.

The rule for this phase is **simple by default, advanced by opt-in**. Someone new sees three screens and a dozen commands. Everything else is there and stays out of the way until asked for. A feature that is not built does not appear, switched off or otherwise.

Done:

- VLAN interfaces.
- Backup and restore, including the VPN keys.
- A QR code for adding a phone to the VPN.
- Setup from a browser, with a code shown on the box.
- The simple layer of the web interface: Home, Access, Review, Settings, with the detailed screens as switches.
- Everyday commands in `ox --help`.
- The same two layers in the terminal UI.
- Adding a network (a VLAN with its own address pool) as one step.
- Blocking a website by name.
- An install script, and steps for a VM on Proxmox.
- The browser walk-through in Firefox as well as Chrome.

Next, in this order:

1. A ready-made VM image, so there is no Linux to install first.
2. Downloaded DNS blocklists, kept up to date.
3. Dynamic DNS.
4. Bridge interfaces, PPPoE and IPv6 prefix delegation.

Needs people, not code:

- A run on real hardware.
- Someone new setting a box up while being watched.
- A phone scanning the VPN QR code, and the official WireGuard apps connecting.
- The Proxmox steps followed on Proxmox.

Ends when 25 people outside the project have run it for 30 days and said how it went, and the first outside security report has been handled in public.

## Phase 2. A home-lab appliance

- An installable image: an ISO and a disk image, signed updates, and rollback to the previous version.
- DNS and DHCP as sandboxed services of their own.
- UPnP and NAT-PMP, an mDNS repeater, traffic graphs.
- OPNsense import.
- An outside security audit of the rule compiler, the access control and the HTTPS listener, published with the fixes.
- Measurements on common home-lab hardware, with the method. Until then this project makes no performance claims.

Ends when the image installs and rolls back on real hardware and the audit is public.

## Phase 3. The first paid line, for businesses

Only starts when businesses ask for it in writing.

- A fleet controller you host yourself: inventory and staged rollout of config.
- Single sign-on, and roles held to single zones.
- A yearly per-box subscription for support with a response time and hosted services.

## Phase 4. A commercial product

- Active and backup high availability, with the failover tests published.
- A Terraform provider.
- Verified boot for the image.
- A second audit, then 1.0.

## Not planned

- Features that phone home. Any update check or install count will be opt-in.
- An assistant or any AI feature on the box.
- A closed edition of the software that runs on the box.

# Roadmap

Where Netoxide is going and in what order. The order is set by trust, not by features: each phase ends when there is evidence a stranger can check, such as a run on real hardware, outside users, a handled security report or a published audit. Dates are estimates for one maintainer.

The research behind this order is summarised in [research/market-gap.md](research/market-gap.md). Home-lab users come first. Paid things come later and are aimed at businesses.

## What stays free

This is a proposal until the licence is chosen, and it will then be a commitment.

- Every feature that runs on the box.
- Every security fix, at the same time for everyone.
- Stable releases and updates.

What may cost money later: support with a response time, hosted services a business could also run itself, and hardware sold by partners.

## Phase 0. Clear the ground

No new users yet. The project gets what it needs to be used at all.

- A licence, and a name that has been checked.
- 30 days on real hardware with SELinux enforcing.
- WireGuard tested against the official apps, and the importer against a real pfSense backup.
- Signed release archives.
- A threat model, a lockout recovery guide and a statement of how the code is written.

Ends when the repository can be opened and someone could legally run a release.

## Phase 1. Public preview for people with a spare VM

The first public release. It is for testers, not for the edge of a network you depend on.

Built in this order:

1. VLAN interfaces. **Done.**
2. Bridge interfaces.
3. A VM image, with steps for Proxmox.
4. Backup and restore, including the VPN keys. **Done.**
5. DNS blocklists.
6. Dynamic DNS.
7. A QR code for adding a phone to the VPN. **Done.** Preshared keys.
8. PPPoE and IPv6 prefix delegation.

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

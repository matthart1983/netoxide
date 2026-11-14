# Netoxide web UI design

There are 11 screens, made in Claude Design with mock data. The live canvas is
<https://claude.ai/artifact/68bGaD4eiUpPPuTdvhMVjY> and needs a claude.ai login.

The files in `source/` are Claude Design components (`.dc.html`). They render
only inside the Design runtime. Read them for layout, copy and sample data.
`source/canvas.json` holds the board layout.

`tui-preview.html` is a static, coloured render of the terminal version. It
opens in any browser.

## Shared shell

Every screen has the same layout:

- **Left sidebar:** a box switcher, then three nav groups (Firewall, Operate, Fleet), then a support-status card. The card's line "A lapse never stops forwarding or security fixes" is principle 1.
- **Header:** the box name and running commit, plus any pending candidate.
- **Style:** Inter and JetBrains Mono, one accent colour (#0A5FA8, editable), light ground.

## Firewall (per box)

| File | Screen | Key content |
| --- | --- | --- |
| `Main.dc.html` | Security policy | Zone-pair list (no floating rules), rule table with objects, schedule, hits and hygiene flags (shadowed, no hits in 90 d, wider than traffic), candidate-only rule marked, default drop shown as a row |
| `Nat.dc.html` | NAT | Tabs for port forwards, outbound, 1:1 and NAT64. Every forward names its filter rule |
| `Vpn.dc.html` | VPN | WireGuard and IPsec tunnels with status and reason, remote-access portal, IdP group → rule mapping. FIPS mode means IPsec only |
| `Ips.dc.html` | Intrusion prevention | Suricata 8 inline, ET Open only, per-zone block / alert / off, fail-open or fail-closed, events |
| `Interfaces.dc.html` | Interfaces and multi-WAN | PPPoE, LACP, VLANs, DHCPv6-PD tracking, gateway group failover thresholds, policy routing |
| `Ha.dc.html` | High availability | Active and standby nodes, authenticated conntrackd sync, config sync, manual failover with confirm, published failover test results including a miss |
| `Admin.dc.html` | Admin and audit | OIDC administrators, the five roles, four-eyes approval rules, scoped API tokens, hash-chained audit log |

## Operate, migrate, fleet

| File | Screen | Key content |
| --- | --- | --- |
| `Commit.dc.html` | Changes | TOML diff, plan, "would have blocked 3 active services" impact from flow logs, four-eyes approval, commit-confirm countdown with confirm and revert (interactive) |
| `Explain.dc.html` | Explain a packet | 5-tuple in; running ↔ candidate toggle flips ACCEPT to DROP; shows each step, the matched rule's origin commit and the CLI equivalent (interactive) |
| `Import.dc.html` | pfSense import report | Translated / changed / unsupported, manual steps, `--verify` replay of flows whose verdict differs |
| `Fleet.dc.html` | Fleet controller | Template drift, approvals waiting, tunnels down, support expiry, rollout rings, firewall table |

## Not designed yet (in the 1.0 scope)

DNS and DHCP, BGP and OSPF routing, traffic shaping (CAKE), certificates
(ACME and the internal CA), live sessions and log view, and the GitOps or
Terraform setup flow.

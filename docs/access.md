# Remote management, access and roles

How to manage a box from another machine, and who may do what.

- [Manage a box from another machine](#manage-a-box-from-another-machine)
- [Access and roles](#access-and-roles)

## Manage a box from another machine

`ox` and the terminal UI can talk to a box over its HTTPS listener. On the box, make a token and read the certificate's fingerprint:

```sh
ox token create laptop --role operator --days 90
ox status          # the last lines show the listener and its certificate
```

On your machine, save the box under a name:

```sh
ox remote add home https://192.0.2.1:8443
ox --remote home status
ox -r home commit starter --confirm 5m
```

`ox remote add` shows the fingerprint of the certificate the box offered and asks whether it matches the one from `ox status`. After that `ox` accepts only that certificate, the way SSH keeps host keys. If the box later shows a different one, `ox` stops before sending the token and says so. A box with a certificate from an authority your machine trusts needs no fingerprint.

| | |
| --- | --- |
| `ox remote add <name> <url> [--fingerprint sha256:…] [--token-file <file>]` | Save a box. Without the flags it asks for both |
| `ox remote list` / `ox remote remove <name>` | The saved boxes |
| `ox --remote <name> …` or `OX_REMOTE=<name>` | Run any command against a saved box |
| `OX_URL`, `OX_TOKEN`, `OX_FINGERPRINT` | The same without a file, for scripts and CI |

Saved boxes are in `~/.config/netoxide/remotes.toml`, readable only by you, because the file holds the tokens. `ox init` is the one command that refuses a remote box: it looks at the ports of the machine it runs on. A URL without a port means 8443.

## Access and roles

| Way in | Who you are | What you may do |
| --- | --- | --- |
| The Unix socket | The user that owns your process, as the kernel reports it | Everything. Whoever can open the socket file is an admin |
| The HTTPS listener | The access token you send | What the token's role allows |

| Role | May | Where |
| --- | --- | --- |
| viewer | Read the config, candidates, plans, status and metrics | |
| auditor | The same, plus the audit log | |
| operator | The same, plus save candidates, approve, commit, confirm and revert | Any part of the config |
| network-admin | The same as an operator | Only the network, services and VPN sections |
| security-admin | The same as an operator | Only the firewall section |
| admin | Everything, including rollback, tokens, roles and settings | Any part of the config |

A role is a set of actions, and it can be held to sections of the config:

| Section | Config keys |
| --- | --- |
| firewall | `zones`, `addresses`, `services`, `policy`, `nat` |
| network | `hostname`, `interfaces`, `ipv6_autoconfig` |
| services | `dns`, `dhcp` |
| vpn | `wireguard` |

A role held to sections can save, approve, commit, confirm or revert only a change that stays inside them. The daemon compares the change with the running config, so a stale candidate that would undo someone else's work in another section is refused too. Reading is never limited.

Which zone a port or a tunnel is in decides which rules its traffic gets. So adding one, removing one or moving one to another zone counts as a firewall change as well, and a network admin cannot do it alone. They can still renumber a port, change its gateway, and edit DNS, DHCP and the peers of an existing tunnel.

Make your own roles with `ox role create`, for example a helpdesk that may add VPN devices and nothing else:

```sh
ox role create helpdesk --can edit,commit --sections vpn
ox token create desk --role helpdesk --days 90
```

The actions are `read-audit`, `edit`, `approve`, `commit`, `rollback` and `manage`. `manage` covers tokens, roles and settings, so it is full control and cannot be held to sections. Setting up the first VPN device also adds a firewall rule for the tunnel's port, so that step needs a role that may change both sections.

Only the SHA-256 of a token's secret is stored, so the secret is shown once when you create it. Tokens can expire and be revoked.

With `ox four-eyes on`, a commit needs approval from someone other than the person who last saved the candidate. Saving it again drops the approval. Every one of these actions is in the audit log with the name of who did it.

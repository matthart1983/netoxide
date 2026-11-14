# Command and API reference

Every `ox` command and every HTTP route.

- [Command reference](#command-reference)
- [API reference](#api-reference)

## Command reference

Daemon commands. All take `--socket <path>` or the `OX_SOCKET` variable. The default is `/run/netoxide/oxd.sock`.

| Command | What it does |
| --- | --- |
| `ox status` | The running commit, any pending countdown, candidate names |
| `ox running` | Print the running config |
| `ox candidate save <name> <file>` | Validate a file and store it as a candidate |
| `ox candidate list` / `show <name>` / `rm <name>` | Manage candidates |
| `ox plan <name> [--flows <file>]` | What the candidate would change |
| `ox commit <name> [--confirm 5m] [--reason <text>]` | Apply a candidate |
| `ox confirm` | Keep the pending commit |
| `ox revert` | Undo the pending commit now |
| `ox rollback [N] [--confirm 5m] [--reason <text>]` | Go back N commits, as a new commit |
| `ox history` | Commits, newest first |
| `ox show <id>` | One commit and its config |
| `ox explain --src --dst --proto --dport --in [--candidate <name>]` | What happens to one packet |
| `ox audit` | The audit log, with the chain verified |
| `ox hygiene` | Rules that never apply, add nothing, allow everything or have seen no packets |
| `ox approve <candidate>` | Approve a candidate someone else saved |
| `ox four-eyes on\|off` | Require a second person's approval before a commit |
| `ox token create <name> --role <role> [--days N]` / `list` / `revoke <name>` | Access tokens for the HTTPS API and the web UI |
| `ox role list` / `create <name> --can <actions> [--sections <sections>]` / `delete <name>` | Roles: what a token may do and in which parts of the config |
| `ox remote add <name> <url>` / `list` / `remove <name>` | Boxes to manage from this machine with `ox --remote <name>` |
| `ox whoami` | Who the daemon thinks you are, and what your role allows |
| `ox leases` | The addresses DHCP has handed out |
| `ox vpn` | Each tunnel: this box's public key, and every peer with when it was last heard from and how much it sent |
| `ox vpn add <name> --endpoint <host> [--public-key <key>]` | Add a phone or laptop to the VPN, setting the VPN up if there is none. Saves a candidate and prints the device's config |
| `ox vpn --key <interface>` | Print this box's public key for a tunnel, making the key if needed |
| `ox kernel` | The Netoxide table as the kernel holds it |
| `ox forward --name <text> --port tcp/443 --to <host>[:port] [--address <outside address>]` | Forward a port to an inside host; saved as a candidate |
| `ox block <address> [--name <text>]` | Drop everything a device sends; saved as a candidate |

Commands that need no daemon:

| Command | What it does |
| --- | --- |
| `ox file validate <file>` | Check a config and report every problem |
| `ox file compile <file> [--stats]` | Print the nftables ruleset as libnftables JSON |
| `ox file diff <running> <candidate>` | List what differs |
| `ox file hygiene <file>` | Rules in a file that never apply, add nothing or allow everything |
| `ox file plan <running> <candidate> [--flows <file>]` | Plan from two files |
| `ox file explain <file> --src ... [--candidate <file>]` | Explain from files |
| `ox import <config.xml> [--out <file>] [--verify <flows>]` | Translate a pfSense backup |
| `ox init [--wan <port>] [--lan <port>[=<addr/prefix>]] [--no-services] [--dns-upstream <addr>] [--out <file> \| --save <name>]` | Guided setup. Reads the machine's ports; with `--out` it needs no daemon |
| `ox schema` | Print the JSON Schema of the config |

The confirm window is between 10 seconds and 1 hour. Only one commit can be pending at a time.

`oxd` options:

| Option | What it does |
| --- | --- |
| `--state-dir <dir>` | Where commits, candidates, the audit log and service files live. Default `/var/lib/netoxide` |
| `--socket <path>` | The API socket. Default `/run/netoxide/oxd.sock` |
| `--dry-run` | Keep state and serve the API, but load nothing and start no services |
| `--lockdown` | Until the first commit, drop inbound and forwarded traffic. This cuts a remote session to the machine |
| `--dnsmasq <path>` | The dnsmasq program to run. Default `dnsmasq` |
| `--listen <addr:port>` | Also serve the API and the web UI over HTTPS. Every request needs an access token |
| `--tls-cert <file>`, `--tls-key <file>` | The certificate for `--listen`. Without them the daemon makes a self-signed one and keeps it in the state directory |
| `--listen-http <127.0.0.1:port>` | The same without TLS, on a loopback address only, for a TLS proxy on the same machine |
| `--keep-service-privileges` | Do not switch services to an unprivileged user. Needed inside a user namespace |

Stopping `oxd` leaves the loaded ruleset in place, so the box keeps forwarding. It does stop dnsmasq, so DNS and DHCP stop with it.

## API reference

HTTP and JSON on the Unix socket. Errors come back as `{"error": "..."}` with 404 for something missing, 422 for an invalid config or request, and 409 when a commit is pending or none is.

| Method and path | Body | Returns |
| --- | --- | --- |
| `GET /v1/status` | | Running commit, `reverts_in` seconds, candidates, applier |
| `GET /v1/running` | | Running config as TOML |
| `GET /v1/commits` | | Commits, newest first |
| `GET /v1/commits/{id}` | | The commit and its config |
| `GET /v1/candidates` | | Candidate names |
| `PUT /v1/candidates/{name}` | TOML | Stores the candidate after validating it |
| `GET /v1/candidates/{name}` | | The candidate as TOML |
| `DELETE /v1/candidates/{name}` | | |
| `POST /v1/candidates/{name}/plan` | Optional JSON Lines of flows | Changes, compiled summary, impact |
| `POST /v1/candidates/{name}/commit` | `{"confirm_secs": 300, "reason": "..."}` | The new commit |
| `POST /v1/confirm` | | The confirmed commit |
| `POST /v1/revert` | | The reverted commit |
| `POST /v1/rollback` | `{"steps": 1, "confirm_secs": null, "reason": "..."}` | The new commit |
| `POST /v1/explain` | `{"src", "dst", "proto", "dport", "in", "candidate"}` | Verdict, steps and text for running and candidate |
| `GET /v1/leases` | | Addresses DHCP has handed out |
| `GET /v1/audit` | | All entries. Fails if the hash chain is broken |
| `GET /v1/hygiene` | | Findings about rules in the running config |
| `GET /metrics` | | Prometheus metrics |
| `GET /v1/whoami` | | The caller's name and role, with the role's actions and sections |
| `GET` / `POST /v1/roles`, `DELETE /v1/roles/{name}` | `{"name", "can": [...], "sections": [...]}` | Roles. Omit `sections` for no limit |
| `GET /v1/running/json` | | The running config as JSON, with what it does in sentences |
| `POST /v1/check` | TOML | Validates a config without storing it |
| `POST /v1/actions/forward`, `/v1/actions/block`, `/v1/actions/vpn-peer` | JSON | One-step actions; each saves a candidate |
| `GET /v1/wireguard` | | Tunnels of the running config with each peer's state |
| `GET /v1/wireguard/{interface}/key` | | This box's public key for a tunnel; makes the key pair if there is none |
| `GET /v1/candidates/{name}/meta` | | Author and approval of a candidate |
| `POST /v1/candidates/{name}/approve` | | Four-eyes approval |
| `GET` / `PUT /v1/settings` | `{"four_eyes": true}` | The four-eyes setting |
| `GET` / `POST /v1/tokens`, `DELETE /v1/tokens/{name}` | `{"name", "role", "ttl_secs"}` | Access tokens. The secret is returned once |
| `GET /v1/kernel` | | The table as the kernel lists it |

On the Unix socket the caller is whoever owns the calling process, as the kernel reports it, and is an admin. On the HTTPS listener every request carries `Authorization: Bearer <token>`, and the token's role decides what it may do: 401 without a valid token, 403 when the role does not allow the action or the change reaches outside the role's sections. See [Access and roles](access.md#access-and-roles).

# Threat model

What Netoxide is built to resist, what it relies on, and what it does not defend against. Nobody outside the project has audited any of this. Read it as the design's intent and a list of where to look, not as a guarantee.

## What the box protects

- **The networks behind it.** Traffic crosses only where a rule allows it. With no rule, a zone pair drops everything.
- **Itself.** The box's own services are reachable only where a rule to `self` allows it.
- **Its own config.** Only an authenticated caller with the right role can change what the box does, and every change is recorded.

## Who can attack it, and where the lines are

| From | Can reach | What stops them |
|---|---|---|
| The internet side | Only what a rule from that zone allows. By default nothing | The compiled ruleset. A forwarded port reaches the one inside address and port it names |
| A device on an inside network | The box's DNS and DHCP if allowed, the HTTPS listener if a rule allows the port | Rules to `self`. Without an access token the listener serves only the sign-in page and its three static files |
| Someone holding an access token | What the token's role allows | Role checks on every route. A role held to sections cannot save, approve, commit, keep or undo a change outside them |
| A local user on the box | The daemon's Unix socket, if the file's permissions let them open it | File permissions on the socket. Whoever can open it is an administrator |
| Root on the box | Everything | Nothing. Root can load its own rules, read the keys and rewrite the state directory |

## What the design relies on

- **The kernel.** Packets are filtered by nftables in the Linux kernel. A kernel bug is outside what Netoxide can fix.
- **The compiler being right.** The rules loaded are whatever the compiler writes for a config. `ox explain` evaluates the same compiled form the kernel gets, so it cannot disagree with the loaded rules, but both would share a compiler mistake. Tests send real packets and compare the result with explain.
- **TLS and the token.** An access token is as powerful as its role. It is sent on every request, so a stolen token works until it expires or is revoked. Only its SHA-256 is stored on the box.
- **The fingerprint check.** `ox --remote` trusts a box by the fingerprint saved when it was added. If the wrong fingerprint is accepted at that moment, everything after is sent to the wrong machine.
- **dnsmasq.** The daemon starts it with a fixed argument list and a config it wrote. A flaw in dnsmasq is exposed to whichever zones may use DNS or DHCP.
- **The build.** Dependencies are checked against an advisory database and a licence list in CI. They have not been reviewed line by line.

## What it does not defend against

- **A compromised administrator account or token with the `manage` action.** That is full control, including turning off four-eyes approval. The audit log records it.
- **Tampering by root.** The audit log is hash-chained and its head is stored beside it. That detects an edit by someone who cannot also rewrite the head. Root can rewrite both.
- **A clock that jumps backwards.** Token expiry and the undo timer follow the wall clock, so both are extended.
- **Flooding.** The HTTPS listener caps connections per address and in total and drops quiet ones. Someone with many addresses can still keep others out of it while they try. There is no protection against traffic floods through the firewall beyond what the kernel does.
- **Malicious traffic that the rules allow.** There is no intrusion detection and no inspection of content.
- **Physical access.** There is no disk encryption and no verified boot. Keys for the VPN and for TLS sit in the state directory, readable by root.
- **A hostile box, from the client's side.** `ox` strips control characters from what a daemon sends before printing it. It otherwise trusts a box whose fingerprint matches.

## Where to look first

If you review the code, these carry the most weight:

- `crates/ox-nft`: the compiler from config to rules.
- `crates/oxd/src/api.rs`: every route, the role check and the section check.
- `crates/ox-store/src/auth.rs`: roles, and which config keys belong to which section.
- `crates/ox-client/src/tls.rs`: the certificate pinning.
- `crates/ox-libnft`: the only crate allowed `unsafe`.

Report a problem privately. See [SECURITY.md](../SECURITY.md).

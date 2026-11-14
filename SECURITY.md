# Security

Netoxide 0.1 is a preview. It has not had a security audit and has not run on
production hardware. Do not rely on it to protect a real network yet.

## Reporting a problem

Please report security problems privately, not in a public issue. Use GitHub's
"Report a vulnerability" button on the repository's Security tab. Include what
you did, what happened, and the version or commit.

You should hear back within a week. Once there is a release to fix, the aim is
to publish a fix and an advisory within 90 days of the report.

## What is in scope

- The daemon `oxd`, its API and web UI
- The `ox` tool and the terminal UI
- The rules the compiler writes for a given config
- The importer, where a translation is less strict than the report says

## What the design relies on

- Whoever can open the daemon's Unix socket is an administrator.
- An access token is as powerful as its role. Only its SHA-256 is stored.
- The audit log detects edits and deletions. It does not stop someone with
  root on the box from replacing the whole file and its chain.
- The daemon starts one other program, dnsmasq, with a fixed argument list.

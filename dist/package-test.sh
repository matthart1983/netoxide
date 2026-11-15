#!/bin/sh
# Installs the packages in clean containers of the distributions they are
# for, and checks each one end to end.
#
#   dist/package-test.sh <dir with the .deb and .rpm> [image ...]
#
# Needs podman or docker. In each container it installs the package with
# the distribution's own package manager, so the dependencies must
# resolve, then loads a real ruleset with that distribution's nft into
# the container's own network namespace, reads it back, and removes the
# package. No systemd runs in these containers, so the service unit is
# installed but not started. tests/vm/run.sh covers the daemon under
# systemd.
#
# A container uses the kernel of the machine it runs on. An older nft with
# a much newer kernel can fail where the distribution's own kernel would
# not, so the result that counts is the one from CI.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
pkgs=$(cd "$1" && pwd)
shift
[ $# -gt 0 ] || set -- \
    docker.io/library/debian:12 docker.io/library/debian:13 \
    docker.io/library/ubuntu:22.04 docker.io/library/ubuntu:24.04 \
    docker.io/library/fedora:latest docker.io/library/almalinux:9
if command -v podman >/dev/null 2>&1; then engine=podman; else engine=docker; fi

cat >"$pkgs/inside.sh" <<'INSIDE'
set -eu
ok() { echo "  ok   $*"; }
fail() {
    echo "  FAIL $*" >&2
    exit 1
}
cd /pkgs
if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq ./netoxide_*_amd64.deb >/tmp/install.log 2>&1 || { cat /tmp/install.log; fail "apt could not install the package"; }
    remove() { apt-get purge -y -qq netoxide >/dev/null 2>&1; }
else
    dnf install -y -q ./netoxide-*.x86_64.rpm >/tmp/install.log 2>&1 || { cat /tmp/install.log; fail "dnf could not install the package"; }
    remove() { dnf remove -y -q netoxide >/dev/null 2>&1; }
fi
ok "installed with its dependencies"

for f in /usr/bin/oxd /usr/bin/ox /usr/bin/netoxide-tui /usr/lib/systemd/system/oxd.service \
    /etc/netoxide/oxd.env /usr/share/netoxide/examples/branch.toml /usr/share/netoxide/netoxide-config-1.schema.json; do
    [ -e "$f" ] || fail "$f is missing"
done
ok "files are in place"
version=$(oxd --version) && ox --version >/dev/null && netoxide-tui --version >/dev/null || fail "a program does not run here"
ok "the programs run: $version"

# A real ruleset through this distribution's nft, IPv4 and IPv6 together.
mkdir -p /tmp/state
oxd --state-dir /tmp/state --socket /tmp/oxd.sock 2>/tmp/oxd.log &
daemon=$!
export OX_SOCKET=/tmp/oxd.sock
i=0
until ox status >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 50 ] || { cat /tmp/oxd.log; fail "the daemon did not start"; }
    sleep 0.2
done
ox candidate save demo /usr/share/netoxide/examples/branch.toml >/dev/null
ox apply demo >/tmp/apply.log 2>&1 || { cat /tmp/apply.log /tmp/oxd.log; fail "the ruleset did not load with $(nft --version)"; }
ox keep >/dev/null
ox kernel | grep -q '"name": "netoxide"' || fail "the table is not in the kernel"
nft list table inet netoxide | grep -q 'ip6 ' || fail "the loaded rules have no IPv6 part"
nft list table inet netoxide | grep -q 'ip ' || fail "the loaded rules have no IPv4 part"
ok "a real ruleset loaded with $(nft --version)"
answer=$(ox explain --src 10.20.4.17 --dst 10.30.0.8 --proto tcp --dport 443 2>&1 | head -n 1)
ok "explain answers: $answer"
netoxide-tui --live --snapshot home --size 80x24 | grep -q "The firewall is running" || fail "the terminal interface does not show the running firewall"
ok "the terminal interface reads the daemon"
kill "$daemon"
wait "$daemon" 2>/dev/null || true

remove || fail "the package could not be removed"
[ ! -e /usr/bin/oxd ] || fail "oxd is still there after removal"
if nft list table inet netoxide >/dev/null 2>&1; then fail "the rules are still loaded after removal"; fi
ok "removed, with its rules"
INSIDE

failed=
for image in "$@"; do
    echo "$image"
    # Privileged, so the daemon can turn on forwarding in the container's
    # own network namespace. /proc/sys is read-only otherwise.
    if ! "$engine" run --rm --privileged -v "$pkgs":/pkgs:z "$image" sh /pkgs/inside.sh; then
        failed="$failed $image"
    fi
done
rm -f "$pkgs/inside.sh"
if [ -n "$failed" ]; then
    echo "package test FAILED on:$failed" >&2
    exit 1
fi
echo "package test passed on $# distributions"

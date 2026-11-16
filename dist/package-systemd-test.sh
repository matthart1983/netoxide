#!/bin/sh
# Installs each package in a container that runs systemd, so the install
# and removal scripts and the service unit are exercised for real.
#
#   dist/package-systemd-test.sh <dir with the .deb and .rpm>
#
# Needs podman. It checks that installing starts the service, that a
# ruleset loads under the unit's sandbox, that the daemon comes back after
# a restart with its config, and that removing the package stops the
# service and takes the rules out of the kernel.
#
# Like dist/package-test.sh, the containers use this machine's kernel.
set -eu
pkgs=$(cd "$1" && pwd)

cat >"$pkgs/systemd-inside.sh" <<'INSIDE'
set -eu
ok() { echo "  ok   $*"; }
fail() {
    echo "  FAIL $*" >&2
    journalctl -u oxd -n 15 --no-pager >&2 || true
    exit 1
}
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
    apt-get install -y -qq /pkgs/netoxide_*_amd64.deb >/tmp/install.log 2>&1 || { cat /tmp/install.log; fail "install"; }
    remove() { apt-get purge -y -qq netoxide >/dev/null 2>&1; }
    purged=yes
else
    dnf install -y -q /pkgs/netoxide-*.x86_64.rpm >/tmp/install.log 2>&1 || { cat /tmp/install.log; fail "install"; }
    remove() { dnf remove -y -q netoxide >/dev/null 2>&1; }
    purged=no
fi
grep -q "Netoxide is installed and running" /tmp/install.log || fail "the install script did not say what to do next"
[ "$(systemctl is-enabled oxd)" = enabled ] || fail "the service is not enabled"
i=0
until ox status >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 50 ] || fail "the service did not start"
    sleep 0.2
done
ok "installing enabled and started the service"
ox status | grep -q "^setup *code " || fail "a new box shows no setup code"
if nft list table inet netoxide >/dev/null 2>&1; then fail "a box with no config loaded rules"; fi
ok "a new box shows its setup code and loads no rules"

ox candidate save demo /usr/share/netoxide/examples/branch.toml >/dev/null
ox apply demo >/tmp/apply.log 2>&1 || { cat /tmp/apply.log; fail "the ruleset did not load under the unit"; }
ox keep >/dev/null
nft list table inet netoxide | grep -q 'ip6 ' || fail "no IPv6 rules in the kernel"
nft list table inet netoxide | grep -q 'ip ' || fail "no IPv4 rules in the kernel"
ok "a ruleset loaded under the unit's sandbox, IPv4 and IPv6"

systemctl restart oxd
i=0
until ox status >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 50 ] || fail "the service did not come back"
    sleep 0.2
done
ox status | grep -q "candidate demo" || fail "the config did not survive a restart"
nft list table inet netoxide >/dev/null 2>&1 || fail "the rules did not survive a restart"
ok "the service restarts with its config and rules"

remove || fail "the package could not be removed"
if systemctl is-active --quiet oxd; then fail "the service still runs after removal"; fi
if nft list table inet netoxide >/dev/null 2>&1; then fail "the rules are still loaded after removal"; fi
[ ! -e /usr/bin/oxd ] || fail "oxd is still there"
if [ "$purged" = yes ]; then
    [ ! -e /var/lib/netoxide ] || fail "purge left the state behind"
    ok "purged: service stopped, rules gone, state gone"
else
    [ -e /var/lib/netoxide ] || fail "removal took the state, which an rpm should leave"
    ok "removed: service stopped, rules gone, state left in /var/lib/netoxide"
fi
INSIDE

run() {
    image=$1
    prepare=$2
    echo "$image"
    podman rm -f netoxide-pkg-test >/dev/null 2>&1 || true
    podman run -d --name netoxide-pkg-test --privileged --systemd=always \
        -v "$pkgs":/pkgs:z "$image" sh -c "$prepare >/dev/null 2>&1; exec /sbin/init" >/dev/null
    i=0
    until podman exec netoxide-pkg-test systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded'; do
        i=$((i + 1))
        [ "$i" -lt 90 ] || {
            echo "  FAIL systemd did not start in the container" >&2
            podman rm -f netoxide-pkg-test >/dev/null 2>&1
            return 1
        }
        sleep 2
    done
    result=0
    podman exec netoxide-pkg-test sh /pkgs/systemd-inside.sh || result=1
    podman rm -f netoxide-pkg-test >/dev/null 2>&1
    return $result
}

failed=
run docker.io/library/fedora:latest "dnf install -y -q systemd procps-ng iproute" || failed="$failed fedora"
run docker.io/library/debian:13 "apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq systemd systemd-sysv procps iproute2" || failed="$failed debian"
if [ -n "$failed" ]; then
    echo "systemd package test FAILED on:$failed" >&2
    exit 1
fi
echo "systemd package test passed"

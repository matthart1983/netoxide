#!/bin/sh
# Runs the browser walk-through against a fresh daemon, in a private network
# namespace with two ports, so it touches nothing on this machine.
#
#   tests/web/run.sh [out-dir]
#
# Needs Node 22 or later, Chrome (set CHROME to its path if it is not
# `google-chrome`) or Firefox with BROWSER=firefox, unshare(1) and
# unprivileged user namespaces. The daemon
# runs with --dry-run unless OX_WEB_KERNEL=1. Pictures of every step are left
# in the out directory.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=${1:-$(mktemp -d)}
# With OX_WEB_KERNEL=1 the daemon loads real rules into the namespace's
# kernel and runs dnsmasq there. Without it, it runs with --dry-run.
# Inside a user namespace Chrome cannot build its own sandbox.
if [ "${BROWSER:-chrome}" = chrome ]; then browser_args=--no-sandbox; else browser_args=; fi
if [ "${OX_WEB_KERNEL:-}" = 1 ]; then mode=--keep-service-privileges; else mode=--dry-run; fi
work=$(mktemp -d)
[ -x "$repo/target/debug/oxd" ] || (cd "$repo" && cargo build -p oxd)
cat >"$work/inside.sh" <<INSIDE
set -eu
ip link set lo up
# Two cables. The far ends go into a second namespace, so the box has
# exactly two ports: eth0 towards a provider's router, eth1 for the inside.
(unshare -n sleep 300 & echo \$! >"$work/far")
sleep 0.3
far=\$(cat "$work/far")
ip link add eth0 type veth peer name isp0 && ip link set isp0 netns \$far
ip link add eth1 type veth peer name cli0 && ip link set cli0 netns \$far
nsenter -t \$far -n sh -c 'ip link set isp0 up; ip addr add 203.0.113.1/24 dev isp0; ip link set cli0 up'
ip addr add 203.0.113.10/24 dev eth0 && ip link set eth0 up && ip route add default via 203.0.113.1
ip addr add 192.168.10.1/24 dev eth1 && ip link set eth1 up
"$repo/target/debug/oxd" --state-dir "$work/state" --socket "$work/oxd.sock" \\
    --listen-http 127.0.0.1:8098 $mode 2>"$work/oxd.log" &
daemon=\$!
trap 'kill \$daemon \$far 2>/dev/null' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$work/state/setup-code" ] && break; sleep 0.3; done
BROWSER_ARGS="$browser_args" HOME="$work" node "$here/drive.mjs" http://127.0.0.1:8098 "\$(cat "$work/state/setup-code")" "$out"
INSIDE
unshare -Urn sh "$work/inside.sh"

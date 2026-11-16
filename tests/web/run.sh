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
# Two cables, each into a namespace of its own, so traffic between them
# has to cross the box: eth0 goes to a provider's router, eth1 to a client
# on the inside network.
(unshare -n sleep 600 & echo \$! >"$work/isp")
(unshare -n sleep 600 & echo \$! >"$work/client")
sleep 0.3
isp=\$(cat "$work/isp")
client=\$(cat "$work/client")
ip link add eth0 type veth peer name isp0 && ip link set isp0 netns \$isp
ip link add eth1 type veth peer name cli0 && ip link set cli0 netns \$client
nsenter -t \$isp -n sh -c 'ip link set lo up; ip link set isp0 up; ip addr add 203.0.113.1/24 dev isp0'
nsenter -t \$client -n sh -c 'ip link set lo up; ip link set cli0 up; ip addr add 192.168.10.50/24 dev cli0; ip route add default via 192.168.10.1'
ip addr add 203.0.113.10/24 dev eth0 && ip link set eth0 up && ip route add default via 203.0.113.1
ip addr add 192.168.10.1/24 dev eth1 && ip link set eth1 up
# Real traffic for the Live screen: a server on the provider's side, a
# device inside that uses it once the box lets it, and something outside
# that keeps trying ports the box should block.
nsenter -t \$isp -n python3 "$repo/tests/tui/traffic.py" serve 203.0.113.1 8080 >/dev/null 2>&1 &
traffic="\${traffic:-} \$!"
nsenter -t \$isp -n python3 "$repo/tests/tui/traffic.py" knock 203.0.113.10 22 23 3389 >/dev/null 2>&1 &
traffic="\${traffic:-} \$!"
nsenter -t \$client -n python3 "$repo/tests/tui/traffic.py" use http://203.0.113.1:8080 >/dev/null 2>&1 &
traffic="\${traffic:-} \$!"
"$repo/target/debug/oxd" --state-dir "$work/state" --socket "$work/oxd.sock" \\
    --listen-http 127.0.0.1:8098 $mode 2>"$work/oxd.log" &
daemon=\$!
trap 'kill \$daemon \$isp \$client \$traffic 2>/dev/null || true' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$work/state/setup-code" ] && break; sleep 0.3; done
BROWSER_ARGS="$browser_args" HOME="$work" node "$here/drive.mjs" http://127.0.0.1:8098 "\$(cat "$work/state/setup-code")" "$out"
INSIDE
unshare -Urn sh "$work/inside.sh"

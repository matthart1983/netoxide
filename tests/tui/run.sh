#!/bin/sh
# Walks the terminal interface through its plain screens against a fresh
# daemon, in a private network namespace with two ports, so it touches
# nothing on this machine.
#
#   tests/tui/run.sh [out-dir]
#
# Needs unshare(1) and unprivileged user namespaces. The daemon runs with
# --dry-run unless OX_TUI_KERNEL=1, which loads real rules into the
# namespace's kernel and runs dnsmasq there. Every screen it looked at is
# left in the out directory as text.
#
# OX_TUI_INSIDE names another script to run in place of the walk, with the
# same two arguments. tests/tui/demo.sh records the README's demo that way.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=${1:-$(mktemp -d)}
mkdir -p "$out"
if [ "${OX_TUI_KERNEL:-}" = 1 ]; then mode=--keep-service-privileges; else mode=--dry-run; fi
inside=${OX_TUI_INSIDE:-$here/walk.sh}
work=$(mktemp -d)
(cd "$repo" && cargo build -q -p oxd -p ox-cli -p netoxide-tui)
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
"$repo/target/debug/oxd" --state-dir "$work/state" --socket "$work/oxd.sock" $mode 2>"$work/oxd.log" &
daemon=\$!
trap 'kill \$daemon \$isp \$client 2>/dev/null || true' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -S "$work/oxd.sock" ] && break; sleep 0.3; done
# The walk reaches the two far ends with: nsenter -t <pid> -n
export OX_SOCKET="$work/oxd.sock" HOME="$work" OX_LAB_ISP=\$isp OX_LAB_CLIENT=\$client
sh "$inside" "$repo/target/debug" "$out"
INSIDE
if unshare -Urn sh "$work/inside.sh"; then
    echo "output is in $out"
else
    echo "FAILED; the daemon's log:" >&2
    tail -n 20 "$work/oxd.log" >&2
    exit 1
fi

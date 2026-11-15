#!/bin/sh
# Records the README's terminal demo. Run through run.sh, so it has a real
# daemon in a namespace, a client on the inside and a provider outside:
#
#   OX_TUI_KERNEL=1 OX_TUI_INSIDE=tests/tui/demo.sh tests/tui/run.sh docs/images
#
# Needs vhs (github.com/charmbracelet/vhs) with ttyd and ffmpeg. It writes
# tui-demo.gif into the out directory, and the still pictures the README
# shows: tui-live, tui-home, tui-access, tui-review and tui-task.
#
# Everything in the recording is measured. The traffic is real: a web
# server on the provider's side, a device on the inside network using it,
# a device on the guest network once that exists, and probes from outside
# and from the guest network that the box blocks.
set -eu
bin=$1
out=$(cd "$2" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
"$bin/ox" init --wan eth0 --lan eth1=192.168.10.1/24 --gateway 203.0.113.1 --hostname home-box --save starter >/dev/null
"$bin/ox" apply starter >/dev/null
"$bin/ox" keep >/dev/null

# The client is also a device on VLAN 30, where the demo adds a guest
# network. Traffic from that address leaves by that VLAN.
nsenter -t "$OX_LAB_CLIENT" -n sh -c 'ip link add link cli0 name cli0.30 type vlan id 30 && ip link set cli0.30 up &&
    ip addr add 192.168.30.50/24 dev cli0.30 &&
    ip rule add from 192.168.30.50 table 30 && ip route add default via 192.168.30.1 dev cli0.30 table 30'
# Each is started as nsenter itself, which becomes the program, so the
# trap below can stop it. A program left running would keep this script's
# output open and whatever waits on it would wait for ever.
nsenter -t "$OX_LAB_ISP" -n python3 "$here/traffic.py" serve 203.0.113.1 8080 >/dev/null 2>&1 &
nsenter -t "$OX_LAB_ISP" -n python3 "$here/traffic.py" knock 203.0.113.10 22 23 3389 >/dev/null 2>&1 &
nsenter -t "$OX_LAB_CLIENT" -n python3 "$here/traffic.py" use http://203.0.113.1:8080 from=192.168.10.50 >/dev/null 2>&1 &
nsenter -t "$OX_LAB_CLIENT" -n python3 "$here/traffic.py" use http://203.0.113.1:8080 from=192.168.30.50 >/dev/null 2>&1 &
nsenter -t "$OX_LAB_CLIENT" -n python3 "$here/traffic.py" knock 192.168.10.77 445 from=192.168.30.50 >/dev/null 2>&1 &
# The box takes readings only while it is asked. Ask for a while first, so
# the recording opens on a chart with some history in it.
marker=$(mktemp)
(while [ -e "$marker" ] && "$bin/netoxide-tui" --live --snapshot live >/dev/null 2>&1; do sleep 1; done) >/dev/null 2>&1 &
trap 'rm -f "$marker"; kill $(jobs -p) 2>/dev/null' EXIT
sleep 50

work=$(mktemp -d)
cp "$here/demo.tape" "$work/demo.tape"
cd "$work"
# Chrome cannot build its own sandbox inside a user namespace.
PATH="$bin:$PATH" VHS_NO_SANDBOX=true vhs demo.tape
cp demo.gif "$out/tui-demo.gif"
cp tui-*.png "$out/"
echo "wrote $out/tui-demo.gif and the still pictures"

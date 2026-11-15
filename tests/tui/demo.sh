#!/bin/sh
# Records the README's terminal demo. Run through run.sh, so it has a real
# daemon in a namespace:
#
#   OX_TUI_KERNEL=1 OX_TUI_INSIDE=tests/tui/demo.sh tests/tui/run.sh docs/images
#
# Needs vhs (github.com/charmbracelet/vhs) with ttyd and ffmpeg. It writes
# tui-demo.gif into the out directory, and the still pictures the README
# shows: tui-home, tui-access, tui-review and tui-task.
set -eu
bin=$1
out=$(cd "$2" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
"$bin/ox" init --wan eth0 --lan eth1=192.168.10.1/24 --gateway 203.0.113.1 --hostname home-box --save starter >/dev/null
"$bin/ox" apply starter >/dev/null
"$bin/ox" keep >/dev/null
work=$(mktemp -d)
cp "$here/demo.tape" "$work/demo.tape"
cd "$work"
# Chrome cannot build its own sandbox inside a user namespace.
PATH="$bin:$PATH" VHS_NO_SANDBOX=true vhs demo.tape
cp demo.gif "$out/tui-demo.gif"
cp tui-*.png "$out/"
echo "wrote $out/tui-demo.gif and the still pictures"

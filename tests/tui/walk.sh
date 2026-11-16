#!/bin/sh
# The walk itself. Run by run.sh inside the namespace, with OX_SOCKET set.
#
#   walk.sh <dir with ox and netoxide-tui> <out-dir>
#
# Each step starts the terminal interface, replays keys, and reads the
# screen it ends on. Then `ox` says what the box really did.
set -eu
bin=$1
out=$2
ox="$bin/ox"
tui="$bin/netoxide-tui"
step=0
# What Home says when all is well: real rules, or the daemon's dry run.
if [ "${OX_TUI_KERNEL:-}" = 1 ]; then running="The firewall is running"; else running="Dry run"; fi
tab=$(printf '\t')
esc=$(printf '\033')
nl='
'

# screen <name> <start screen> <keys> [size]: the screen after the keys.
screen() {
    step=$((step + 1))
    last="$out/$(printf '%02d' $step)-$1.txt"
    "$tui" --socket "$OX_SOCKET" --snapshot "$2" --keys "$3" --size "${4:-80x24}" >"$last"
}

# has <text>: the last screen shows it.
has() {
    grep -qF -- "$1" "$last" || {
        echo "FAILED at $last: expected to see: $1" >&2
        cat "$last" >&2
        exit 1
    }
}

# lacks <text>: the last screen does not show it.
lacks() {
    if grep -qF -- "$1" "$last"; then
        echo "FAILED at $last: did not expect: $1" >&2
        cat "$last" >&2
        exit 1
    fi
}

# says <text> <command...>: the command's output has the text.
says() {
    want=$1
    shift
    got=$("$@" 2>&1) || true
    case $got in
    *"$want"*) ;;
    *)
        echo "FAILED: '$*' did not say: $want" >&2
        echo "$got" >&2
        exit 1
        ;;
    esac
}

# Before setup the plain screens say what to do and offer nothing else.
screen not-set-up home ""
has "This box is not set up yet"
lacks "needs at least"

"$ox" init --wan eth0 --lan eth1=192.168.10.1/24 --gateway 203.0.113.1 --save starter >/dev/null
screen first-review review ""
has "This is the first config for the box."
has "apply safely"
# Enter applies it with the timer; y keeps it.
screen first-apply review "$nl"
has "Your change is applied. It undoes itself in"
screen first-keep home "y"
has "Kept."
has "$running"

# Live: real traffic through the box, read from the kernel's counters. A
# server on the provider's side, a device inside that uses it, and
# something outside that keeps trying ports the box should block.
here=$(cd "$(dirname "$0")" && pwd)
# Their process IDs are kept, because `jobs -p` in a trap is not something
# every sh can do, and a failing trap would fail the walk.
nsenter -t "$OX_LAB_ISP" -n python3 "$here/traffic.py" serve 203.0.113.1 8080 >/dev/null 2>&1 &
traffic=$!
nsenter -t "$OX_LAB_ISP" -n python3 "$here/traffic.py" knock 203.0.113.10 22 23 3389 >/dev/null 2>&1 &
traffic="$traffic $!"
nsenter -t "$OX_LAB_CLIENT" -n python3 "$here/traffic.py" use http://203.0.113.1:8080 >/dev/null 2>&1 &
traffic="$traffic $!"
trap 'kill $traffic 2>/dev/null || true' EXIT
# The box takes readings only while it is asked, so ask for a few seconds.
for _ in 1 2 3 4 5 6 7 8; do
    "$tui" --socket "$OX_SOCKET" --snapshot live --size 80x24 >/dev/null
    sleep 1
done
screen live live ""
has "live · one reading a second"
has "internet traffic"
has "your networks"
has "Inside network"
lacks "needs at least"
if [ "${OX_TUI_KERNEL:-}" = 1 ]; then
    has "connections"
    has "just blocked"
    has "Internet tried to reach the box itself"
    grep -qE 'peak [1-9][0-9.]* [kMG]b/s' "$last" || {
        echo "FAILED at $last: no download was measured" >&2
        cat "$last" >&2
        exit 1
    }
else
    # A dry run has no rules in a kernel, so nothing is counted as blocked
    # and the screen must not pretend otherwise.
    lacks "just blocked"
fi
# Paused, it says so.
screen live-paused live "p"
has "paused"

# Home: plain words, and nothing from the detailed screens.
screen home home ""
has "$running"
has "A change undoes itself after 2 minutes"
has "your networks"
has "what would you like to do?"
lacks "candidate"
lacks "commit"
lacks "Policy"

# Add a network for guests: menu line 1, three answers, enter.
screen network-form home "$nl"
has "add a network"
has "VLAN number"
screen network-saved home "${nl}Guest Wi-Fi${tab}${tab}30${nl}"
has "Nothing is applied yet."
has "what will change"
says "network-guest-wi-fi" "$ox" status
screen network-apply review "${nl}"
has "It undoes itself in"
screen network-keep home "y"
has "Kept."
has "Guest Wi-Fi"
says "Guest Wi-Fi" "$ox" access

# Access: the grid, and one pair flipped. The cursor opens on the first
# network's row, second column.
screen access access ""
has "who can reach what"
has "Press enter to"
cp "$last" "$out/access-before.txt"
screen access-flip access "$nl"
has "Nothing is applied yet."
screen access-apply review "$nl"
has "It undoes itself in"
# r undoes it at once, and the change is still waiting afterwards.
screen access-undo home "r"
has "Undone."
has "1 change is waiting"
# Thrown away with two presses of d.
screen access-discard review "d"
has "Press d again"
screen access-discarded review "dd"
has "Discarded. Nothing was changed."
has "Nothing is waiting"

# Let something in from the internet: menu line 2.
screen forward home "j${nl}Web server${tab}tcp/443${tab}192.168.10.20${nl}"
has "Nothing is applied yet."
screen forward-keep review "${nl}y"
has "Kept."
screen forward-shown access ""
has "Web server"
has "tcp/443"
screen home-let-in home ""
has "1 thing is let in from the internet"

# Block a website, then a device: menu line 4.
screen block-site home "jjj${nl}ads.example.com${nl}"
has "Nothing is applied yet."
screen block-site-keep review "${nl}y"
has "Kept."
says "ads.example.com" "$ox" running
# Guided setup gives the inside network no IPv6 address, so an IPv6 device
# is on none of the box's networks. The box says so and the form stays open.
screen block-v6 home "jjj${nl}2001:db8::66${tab}Smart TV${nl}"
has "2001:db8::66 is not on any network of this box"
lacks "Nothing is applied yet."
screen block-v4 home "jjj${nl}192.168.10.66${tab}Old camera${nl}"
has "Nothing is applied yet."
screen block-v4-keep review "${nl}y"
has "Kept."
says "192.168.10.66" "$ox" running
# A wrong answer stays in the form with the reason, and saves nothing.
screen block-refused home "jjj${nl}not an address or a name${nl}"
has "block a device or a website"
lacks "Nothing is applied yet."

# Is something blocked? The last menu line. IPv4 and IPv6.
screen check-v4 home "k${nl}192.168.10.50${tab}1.1.1.1${nl}"
has "is it blocked?"
has "Allowed"
screen check-blocked home "k${nl}192.168.10.66${tab}1.1.1.1${nl}"
has "Blocked"
has "Old camera"
screen check-v6 home "k${nl}2001:db8::66${tab}2001:db8:1::1${nl}"
has "is it blocked?"

# Remote access for a phone: menu line 3. The settings are shown once.
screen vpn home "jj${nl}phone${tab}home.example.net${nl}"
has "set up the device"
has "PrivateKey"
has "A code to scan needs a window"
# A change is waiting now, so the menu has a review line above the rest.
screen vpn-big home "jjj${nl}laptop${tab}home.example.net${nl}" 170x60
has "set up the device"
has "PrivateKey"
has "▀"
lacks "A code to scan needs a window"
# Esc closes it and the change is there to review.
screen vpn-closed home "jjj${nl}tablet${tab}home.example.net${nl}${esc}"
has "what will change"
lacks "PrivateKey"

# Settings: one switch adds one tab.
screen settings settings ""
has "detailed screens"
lacks "6 Policy"
screen settings-on settings "$nl" 132x34
has "6 Policy"
has "[x] The full rule list"

echo "terminal walk-through passed: $step screens"

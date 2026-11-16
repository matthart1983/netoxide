#!/bin/sh
# Installs Netoxide on this machine, or removes it.
#
#   sudo sh dist/install.sh              install and start
#   sudo sh dist/install.sh --packages   also install nftables and dnsmasq with
#                                        the system's package manager
#   sudo sh dist/install.sh --remove     stop and remove, including its state
#
# Run it from an unpacked release archive or from a source tree that has been
# built with `cargo build --release`. It needs systemd.
#
# After it finishes, the box has no config: it filters nothing and routes
# nothing until you set it up, from a browser with the setup code this script
# prints, or with `ox init`.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
packages=no
remove=no
bin_dir=
for arg in "$@"; do
    case $arg in
    --packages) packages=yes ;;
    --remove) remove=yes ;;
    --bin-dir=*) bin_dir=${arg#--bin-dir=} ;;
    -h | --help)
        sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "install.sh: unknown option $arg" >&2
        exit 2
        ;;
    esac
done

say() { printf '%s\n' "$*"; }
stop() {
    say "install.sh: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || stop "run this as root, for example with sudo"
command -v systemctl >/dev/null 2>&1 || stop "this machine has no systemd, which the service needs"

if [ "$remove" = yes ]; then
    systemctl disable --now oxd 2>/dev/null || true
    if command -v nft >/dev/null 2>&1; then nft delete table inet netoxide 2>/dev/null || true; fi
    for tunnel in /var/lib/netoxide/wireguard/*.key; do
        [ -e "$tunnel" ] || continue
        ip link del "$(basename "$tunnel" .key)" 2>/dev/null || true
    done
    rm -f /etc/systemd/system/oxd.service /usr/bin/oxd /usr/bin/ox /usr/bin/netoxide-tui
    rm -rf /var/lib/netoxide /etc/netoxide
    systemctl daemon-reload
    say "Netoxide is removed: the service, the programs, its rules and its state."
    say "Addresses it put on interfaces stay until the next reboot."
    exit 0
fi

# Where the programs are: beside this script's directory in a release
# archive, or in target/release in a source tree.
if [ -z "$bin_dir" ]; then
    for dir in "$here/.." "$here/../target/release"; do
        if [ -x "$dir/oxd" ] && [ -x "$dir/ox" ]; then
            bin_dir=$dir
            break
        fi
    done
fi
[ -n "$bin_dir" ] && [ -x "$bin_dir/oxd" ] && [ -x "$bin_dir/ox" ] ||
    stop "cannot find the oxd and ox programs. Unpack a release archive, or build with: cargo build --release"

has_nftables() { [ -x /usr/sbin/nft ] || [ -x /usr/bin/nft ] || [ -x /sbin/nft ] || [ -x /usr/local/sbin/nft ]; }
has_dnsmasq() { command -v dnsmasq >/dev/null 2>&1; }
if ! has_nftables || ! has_dnsmasq; then
    if command -v apt-get >/dev/null 2>&1; then
        how="apt-get install -y nftables dnsmasq-base"
    elif command -v dnf >/dev/null 2>&1; then
        how="dnf install -y nftables dnsmasq"
    else
        how=
    fi
    if [ "$packages" = yes ] && [ -n "$how" ]; then
        say "Installing what Netoxide needs: $how"
        $how
    fi
    has_nftables || stop "the nft program is missing. Install the nftables package${how:+ ($how)}, or run this script with --packages"
    has_dnsmasq || say "Note: dnsmasq is not installed, so the box cannot answer DNS or hand out addresses yet${how:+. Install it with: $how}"
fi

# Things that would fight Netoxide for the same job.
for unit in firewalld ufw nftables dnsmasq; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        say "Note: $unit is running. Two firewalls, or two DNS and DHCP servers, on one box will conflict. Stop it with: systemctl disable --now $unit"
    fi
done
for unit in NetworkManager systemd-networkd; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        say "Note: $unit is running. Netoxide sets addresses on the ports in its config, so take those ports away from $unit, or both will configure them."
    fi
done

install -m 0755 "$bin_dir/oxd" "$bin_dir/ox" /usr/bin/
[ -x "$bin_dir/netoxide-tui" ] && install -m 0755 "$bin_dir/netoxide-tui" /usr/bin/
install -m 0644 "$here/oxd.service" /etc/systemd/system/oxd.service
mkdir -p /etc/netoxide
if [ ! -e /etc/netoxide/oxd.env ]; then
    # Turns on the web interface, so the box can be set up from a browser.
    install -m 0644 "$here/oxd.env" /etc/netoxide/oxd.env
fi
systemctl daemon-reload
systemctl enable --now oxd

i=0
until /usr/bin/ox status >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -lt 50 ] || stop "the daemon did not start. Look at: journalctl -u oxd -n 50"
    sleep 0.2
done

say
say "Netoxide $(/usr/bin/oxd --version | cut -d' ' -f2) is installed and running."
code=$(/usr/bin/ox status | sed -n 's/^setup *code //p')
if [ -n "$code" ]; then
    say
    say "This box has no config yet. Set it up one of two ways:"
    say
    say "  From a browser on the same network: open https://<this box>:8443/"
    for addr in $(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1); do
        say "      https://$addr:8443/"
    done
    say "    and enter the setup code:  $code"
    say "    The browser will warn about the certificate, which the box made itself."
    say
    say "  Or here, on the command line:  ox init --save starter && ox apply starter"
else
    say "It already has a config. See what it is doing with: ox status"
fi

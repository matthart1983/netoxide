#!/bin/sh
# Builds the .deb and .rpm packages from programs that are already built.
#
#   dist/package.sh <dir with oxd, ox and netoxide-tui> <out-dir>
#
# Needs dpkg-deb, rpmbuild and objdump. On Debian or Ubuntu that is the
# packages dpkg, rpm and binutils. The release workflow runs it.
#
# Both packages put the same files in the same places and behave like
# dist/install.sh: the service is enabled and started, with the web
# interface on port 8443 so a new box can be set up from a browser. A box
# with no config loads no rules, so starting it changes no traffic.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
bin=$(cd "$1" && pwd)
mkdir -p "$2"
out=$(cd "$2" && pwd)
for program in oxd ox netoxide-tui; do
    [ -x "$bin/$program" ] || {
        echo "package.sh: $bin/$program is missing" >&2
        exit 1
    }
done
version=$("$bin/oxd" --version | cut -d' ' -f2)
# The oldest C library the programs can run on, read from the programs.
glibc=$(objdump -T "$bin/oxd" "$bin/ox" "$bin/netoxide-tui" | grep -o 'GLIBC_[0-9.]*' | cut -d_ -f2 | sort -V | tail -n 1)
summary="Firewall and router for Linux, simple by default"
url="https://github.com/matthart1983/netoxide"
maintainer="Matt Hartley <matthart1983@users.noreply.github.com>"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The files, laid out as they are installed. Both packages are made from this.
root="$work/root"
install -D -m 0755 "$bin/oxd" "$root/usr/bin/oxd"
install -D -m 0755 "$bin/ox" "$root/usr/bin/ox"
install -D -m 0755 "$bin/netoxide-tui" "$root/usr/bin/netoxide-tui"
install -D -m 0644 "$here/oxd.service" "$root/usr/lib/systemd/system/oxd.service"
install -D -m 0644 "$here/oxd.env" "$root/etc/netoxide/oxd.env"
doc="$root/usr/share/doc/netoxide"
install -D -m 0644 "$repo/README.md" "$doc/README.md"
install -m 0644 "$repo/CHANGELOG.md" "$repo/SECURITY.md" "$repo/LICENSE" "$doc/"
install -m 0644 "$here/README.md" "$doc/INSTALL.md"
# Not under doc: minimal systems leave documentation out, and the example
# configs are things people use.
share="$root/usr/share/netoxide"
install -D -m 0644 "$repo/schema/netoxide-config-1.schema.json" "$share/netoxide-config-1.schema.json"
mkdir -p "$share/examples"
install -m 0644 "$repo"/examples/*.toml "$share/examples/"

# What the packages do when they are installed and removed. The same
# script serves both, told which moment it is by its first argument.
cat >"$work/after-install" <<'EOF'
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    if [ "$1" = first ]; then
        systemctl enable --now oxd.service || true
        echo "Netoxide is installed and running. It has no config yet, so it filters nothing."
        echo "  From a browser on the same network: open https://<this box>:8443/"
        echo "  and enter the setup code that this prints:  ox status"
        echo "  Or set it up here:  ox init --save starter && ox apply starter"
        for unit in firewalld ufw nftables dnsmasq; do
            if systemctl is-active --quiet "$unit" 2>/dev/null; then
                echo "Note: $unit is running and will conflict. Stop it with: systemctl disable --now $unit"
            fi
        done
    else
        # An upgrade. The rules stay loaded while the daemon restarts.
        systemctl try-restart oxd.service || true
    fi
fi
EOF
cat >"$work/before-remove" <<'EOF'
if [ -d /run/systemd/system ]; then
    systemctl disable --now oxd.service || true
fi
# A firewall nobody is running must not keep filtering.
for nft in /usr/sbin/nft /usr/bin/nft /sbin/nft; do
    if [ -x "$nft" ]; then
        "$nft" delete table inet netoxide 2>/dev/null || true
        break
    fi
done
for key in /var/lib/netoxide/wireguard/*.key; do
    [ -e "$key" ] || continue
    ip link del "$(basename "$key" .key)" 2>/dev/null || true
done
EOF

# ── .deb ────────────────────────────────────────────────────────────────
deb="$work/deb"
cp -a "$root" "$deb"
mkdir -p "$deb/DEBIAN"
size=$(du -sk "$root" | cut -f1)
cat >"$deb/DEBIAN/control" <<EOF
Package: netoxide
Version: $version
Architecture: amd64
Maintainer: $maintainer
Installed-Size: $size
Depends: libc6 (>= $glibc), libgcc-s1, nftables, iproute2
Recommends: dnsmasq-base
Section: net
Priority: optional
Homepage: $url
Description: $summary
 Netoxide loads firewall and NAT rules into the kernel through nftables
 from one config, and runs DNS, DHCP and a WireGuard VPN. Every change
 undoes itself after two minutes unless it is kept.
 .
 This is a preview. It has not run on real hardware and has had no
 outside security audit.
EOF
echo /etc/netoxide/oxd.env >"$deb/DEBIAN/conffiles"
{
    echo '#!/bin/sh'
    echo 'set -e'
    echo '[ "$1" = configure ] || exit 0'
    # dpkg passes the version that was configured before, or nothing.
    echo 'if [ -z "$2" ]; then set -- first; else set -- upgrade; fi'
    cat "$work/after-install"
} >"$deb/DEBIAN/postinst"
{
    echo '#!/bin/sh'
    echo 'set -e'
    echo '[ "$1" = remove ] || exit 0'
    cat "$work/before-remove"
} >"$deb/DEBIAN/prerm"
cat >"$deb/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
# Purge takes the state too: the config history, keys and tokens.
if [ "$1" = purge ]; then rm -rf /var/lib/netoxide /etc/netoxide; fi
EOF
chmod 0755 "$deb/DEBIAN/postinst" "$deb/DEBIAN/prerm" "$deb/DEBIAN/postrm"
dpkg-deb --build --root-owner-group "$deb" "$out/netoxide_${version}_amd64.deb" >/dev/null

# ── .rpm ────────────────────────────────────────────────────────────────
rpm="$work/rpm"
mkdir -p "$rpm/SPECS"
{
    cat <<EOF
Name: netoxide
Version: $version
Release: 1
Summary: $summary
License: MIT
URL: $url
BuildArch: x86_64
Requires: nftables
Requires: iproute
Recommends: dnsmasq
# The programs are built already. Leave them exactly as they are.
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none
%global __strip /bin/true

%description
Netoxide loads firewall and NAT rules into the kernel through nftables
from one config, and runs DNS, DHCP and a WireGuard VPN. Every change
undoes itself after two minutes unless it is kept.

This is a preview. It has not run on real hardware and has had no
outside security audit.

%install
cp -a "$root/." "%{buildroot}/"

%files
/usr/bin/oxd
/usr/bin/ox
/usr/bin/netoxide-tui
/usr/lib/systemd/system/oxd.service
%dir /etc/netoxide
%config(noreplace) /etc/netoxide/oxd.env
/usr/share/doc/netoxide
/usr/share/netoxide

%post
# rpm passes 1 on a first install and 2 on an upgrade.
if [ "\$1" -eq 1 ]; then set -- first; else set -- upgrade; fi
EOF
    cat "$work/after-install"
    cat <<'EOF'

%preun
# 0 means the package is going, not being upgraded.
[ "$1" -eq 0 ] || exit 0
EOF
    cat "$work/before-remove"
    cat <<'EOF'

%postun
if [ -d /run/systemd/system ]; then systemctl daemon-reload || true; fi
EOF
} >"$rpm/SPECS/netoxide.spec"
rpmbuild -bb --quiet --define "_topdir $rpm" --define "_rpmdir $out" \
    --define "_rpmfilename netoxide-%{VERSION}-%{RELEASE}.%{ARCH}.rpm" \
    "$rpm/SPECS/netoxide.spec"

ls -1 "$out"/netoxide_"$version"_amd64.deb "$out"/netoxide-"$version"-1.x86_64.rpm

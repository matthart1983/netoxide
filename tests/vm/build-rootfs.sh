#!/usr/bin/env bash
# Build a bootable root filesystem image from this machine's own /usr.
#
# Nothing is downloaded. The image holds the host's programs and libraries and
# a small /etc written here, and boots with the host's kernel under QEMU. It
# needs no root: the files are copied as the calling user and `unshare -Ur`
# makes mkfs.ext4 record them as owned by root.
#
# Needs: a usr-merged systemd distribution (written on Fedora), a kernel with
# virtio-blk and ext4 built in, mkfs.ext4, and about 8 GB of disk. On btrfs
# or XFS the copy is a reflink and takes no extra space.
#
# Usage: build-rootfs.sh <work-dir>
set -euo pipefail

work=${1:?usage: build-rootfs.sh <work-dir>}
root=$work/rootfs
image=$work/root.img

[ -d "$root" ] && find "$root" -type d ! -perm -u+w -exec chmod u+w {} +
rm -rf "$root"
mkdir -p "$root"/{usr/share,etc,var/lib,var/log,var/tmp,var/cache,run,proc,sys,dev,root,home,mnt,srv,tmp,boot}
chmod 1777 "$root/tmp" "$root/var/tmp"
chmod 0700 "$root/root"
for d in bin sbin lib lib64; do ln -s "usr/$d" "$root/$d"; done

echo "copying /usr" >&2
for d in bin sbin lib lib64 libexec; do
    cp -a --reflink=auto "/usr/$d" "$root/usr/" 2>/dev/null || true
done
for d in dbus-1 terminfo zoneinfo polkit-1 factory; do
    [ -e "/usr/share/$d" ] && cp -a --reflink=auto "/usr/share/$d" "$root/usr/share/" 2>/dev/null || true
done

# /usr directories are read-only on some distributions; the copy is ours.
find "$root/usr" -type d ! -perm -u+w -exec chmod u+w {} +

# Drop what a firewall test never touches.
kernel=$(uname -r)
find "$root/usr/lib/modules" -mindepth 1 -maxdepth 1 ! -name "$kernel" -exec rm -rf {} +
rm -rf "$root"/usr/lib/{debug,firmware,jvm,rustlib,node_modules,sysimage,locale} \
       "$root"/usr/lib64/{firefox,thunderbird,libreoffice,chromium-browser,llvm*,dri,gstreamer-1.0,qt5,qt6,ghc*,R,libLLVM*,libclang*,librustc*,libwebkit*,libQt*} \
       "$root"/usr/lib/python3*/site-packages "$root"/usr/lib64/python3*/site-packages \
       "$root"/usr/libexec/{gcc,webkit*,git-core}

echo "writing /etc" >&2
e=$root/etc
for f in ld.so.conf ld.so.conf.d ld.so.cache alternatives services protocols \
         crypto-policies dbus-1 pki ssl localtime; do
    [ -e "/etc/$f" ] && cp -a --reflink=auto "/etc/$f" "$e/" 2>/dev/null || true
done
ln -s ../usr/lib/os-release "$e/os-release"
echo vmtest > "$e/hostname"
echo 5e5e5e5e5e5e4e5e8e5e5e5e5e5e5e5e > "$e/machine-id"
printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\nservices: files\nprotocols: files\n' > "$e/nsswitch.conf"
printf '127.0.0.1 localhost\n::1 localhost\n' > "$e/hosts"
printf 'root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/:/usr/sbin/nologin\n' > "$e/passwd"
printf 'root:x:0:\nnobody:x:65534:\n' > "$e/group"
printf 'root:*:19000:0:99999:7:::\n' > "$e/shadow"
chmod 0600 "$e/shadow"
# The packages' own system users (dnsmasq, dbus, systemd-network and so on).
systemd-sysusers --root="$root" >/dev/null 2>&1 || echo "warning: systemd-sysusers failed" >&2

# Units: only what the test needs. A fixed machine-id above stops systemd
# from applying the distribution's presets on first boot.
s=$e/systemd/system
mkdir -p "$s/multi-user.target.wants" "$s/sockets.target.wants"
ln -s /usr/lib/systemd/system/multi-user.target "$s/default.target"
ln -s /usr/lib/systemd/system/dbus-broker.service "$s/dbus.service"
ln -s /usr/lib/systemd/system/dbus.socket "$s/sockets.target.wants/dbus.socket"
cat > "$s/vmtest.service" <<'UNIT'
[Unit]
Description=Netoxide VM test
After=multi-user.target systemd-udev-settle.service
Wants=systemd-udev-settle.service

[Service]
Type=oneshot
ExecStartPre=/usr/bin/mkdir -p /mnt/t
ExecStartPre=/usr/bin/mount -o ro /dev/vdb /mnt/t
ExecStart=/usr/bin/bash /mnt/t/guest.sh
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=600
UNIT
ln -s ../vmtest.service "$s/multi-user.target.wants/vmtest.service"
# Units the host's /usr brings along that have no place in the test.
for u in firewalld NetworkManager NetworkManager-wait-online sshd systemd-resolved \
         systemd-networkd systemd-homed systemd-oomd auditd chronyd getty@tty1 \
         systemd-logind plymouth-start systemd-vconsole-setup serial-getty@ttyS0; do
    ln -sf /dev/null "$s/$u.service"
done

size=$(( $(du -sm "$root" | cut -f1) + 1200 ))
echo "making ${size}M image" >&2
rm -f "$image"
unshare -Ur mkfs.ext4 -q -F -L root -d "$root" "$image" "${size}M"
echo "$image"

#!/usr/bin/env bash
# Boot the test VM and run guest.sh inside it as root under systemd.
#
# The VM has four network cards joined in pairs by QEMU: lan0 to cli0 and
# wan0 to srv0. guest.sh installs Netoxide the way dist/README.md says, moves
# cli0 and srv0 into namespaces to play an inside client and an outside
# server, and checks the box between them. Writes to the root disk are kept
# only while QEMU runs, so every run starts from the same image, and a reboot
# inside one run keeps its state.
#
# Usage: run.sh [work-dir]     (default ~/.cache/netoxide-vm)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=${1:-$HOME/.cache/netoxide-vm}
kernel=${KERNEL:-/boot/vmlinuz-$(uname -r)}
log=$work/console.log

[ -f "$work/root.img" ] || "$here/build-rootfs.sh" "$work"
[ -x "$repo/target/release/oxd" ] || (cd "$repo" && cargo build --release)

stage=$work/stage
rm -rf "$stage"
mkdir -p "$stage/bin"
cp "$repo/target/release/oxd" "$repo/target/release/ox" "$stage/bin/"
cp -r "$repo/dist" "$stage/dist"
cp "$here/guest.sh" "$here"/*.toml "$repo/crates/oxd/tests/dhcp_client.py" "$stage/"
rm -f "$work/test.img"
unshare -Ur mkfs.ext4 -q -F -L test -d "$stage" "$work/test.img" 64M

nic() { echo "-netdev hubport,hubid=$1,id=$2 -device virtio-net-pci,netdev=$2,mac=$3"; }
rm -f "$log"
# shellcheck disable=SC2046
timeout "${VM_TIMEOUT:-600}" qemu-system-x86_64 \
    -enable-kvm -cpu host -m 2G -smp 2 -display none -monitor none \
    -kernel "$kernel" \
    -append "root=/dev/vda rw console=ttyS0 selinux=0 audit=0 net.ifnames=0 panic=-1 systemd.show_status=0 quiet" \
    -drive "file=$work/root.img,if=virtio,format=raw,snapshot=on" \
    -drive "file=$work/test.img,if=virtio,format=raw,readonly=on" \
    -nic none \
    $(nic 0 lan0 52:54:00:00:00:01) $(nic 0 cli0 52:54:00:00:00:02) \
    $(nic 1 wan0 52:54:00:00:01:01) $(nic 1 srv0 52:54:00:00:01:02) \
    -serial "file:$log" || true

grep -a -E '^(ok|FAIL|#) ' "$log" || true
if grep -a -q '^VMTEST PASS' "$log"; then
    echo "VM test passed. Console log: $log"
else
    echo "VM test FAILED. Console log: $log" >&2
    exit 1
fi

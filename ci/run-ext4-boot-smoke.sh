#!/usr/bin/env bash
# Boot an initramfs using CrabEFI's native Linux loader, with no ESP or GRUB.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "Usage: $0 <x86-64 bzImage> <static x86-64 busybox> [ext2|ext3|ext4]" >&2
    exit 2
fi
fs=${3:-ext4}
case $fs in ext2|ext3|ext4) ;; *) echo "Unsupported filesystem: $fs" >&2; exit 2 ;; esac

repo=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/root/boot/loader/entries" "$work/root/loader/entries" "$work/initrd/bin"
cp "$1" "$work/root/boot/vmlinuz"
cp "$2" "$work/initrd/bin/busybox"
chmod +x "$work/initrd/bin/busybox"
cat > "$work/initrd/init" <<'INIT'
#!/bin/busybox sh
echo CRABEFI_EXT_BOOT_SMOKE_OK
exec /bin/busybox poweroff -f
INIT
chmod +x "$work/initrd/init"
(cd "$work/initrd" && find . | cpio --quiet -o -H newc | gzip -1) > "$work/root/boot/initrd.img"
cat > "$work/root/boot/loader/entries/test.conf" <<'BLS'
title CrabEFI ext boot smoke
linux /vmlinuz
initrd /initrd.img
options console=ttyS0 rdinit=/init
BLS

# A stale but parseable BLS entry must not hide the working /boot entry.
printf 'default stale.conf\n' > "$work/root/loader/loader.conf"
cat > "$work/root/loader/entries/stale.conf" <<'BLS'
title Stale entry
linux /boot/vmlinuz
initrd /missing.img
BLS

# Larger than the FAT candidate heuristic; BLS paths are relative to /boot.
truncate -s 544M "$work/ext.img"
mke2fs -q -t "$fs" -F -d "$work/root" "$work/ext.img"
truncate -s 546M "$work/disk.img"
printf 'label: gpt\nstart=2048,size=1114112,type=linux\n' | sfdisk --quiet "$work/disk.img"
dd if="$work/ext.img" of="$work/disk.img" bs=1M seek=1 conv=notrunc,sparse status=none

if ! timeout "${SMOKE_TIMEOUT:-300}" "$repo/crabefi" run --ext4 --ahci --headless --disable-kvm \
    --disk "$work/disk.img" > "$work/qemu.log" 2>&1 ||
    ! grep -q '^CRABEFI_EXT_BOOT_SMOKE_OK' "$work/qemu.log"; then
    tail -n 100 "$work/qemu.log" >&2
    exit 1
fi
echo "CrabEFI booted Linux and ran the initramfs from $fs."

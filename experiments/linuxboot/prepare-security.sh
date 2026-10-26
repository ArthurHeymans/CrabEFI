#!/usr/bin/env bash
# Patch an unencrypted installed test image using a disposable WinPE guest.
set -euo pipefail
if [[ $# != 5 ]]; then
    echo "usage: $0 INSTALLED_IMAGE WINPE_IMAGE WINPE_BOOT_WIM LINUXBOOT_ROM OUTPUT_DIRECTORY" >&2
    exit 2
fi
script=$(cd "$(dirname "$0")" && pwd)
for input in "$1" "$2" "$3" "$4"; do
    [[ -f $input ]] || { echo "Not a regular image file: $input" >&2; exit 1; }
done
installed=$(realpath "$1")
pe=$(realpath "$2")
wim=$(realpath "$3")
rom=$(realpath "$4")
mkdir -p "$5"
out=$(realpath "$5")
[[ ! -e $out/windows.img && ! -e $out/pe.img ]] || { echo 'Use a fresh output directory' >&2; exit 1; }
cp --reflink=auto --sparse=always "$installed" "$out/windows.img"
cp --reflink=auto --sparse=always "$pe" "$out/pe.img"
cp --reflink=auto "$wim" "$out/boot.wim"
printf '[LaunchApps]\r\n%%SYSTEMROOT%%\\System32\\cmd.exe, /c X:\\Windows\\System32\\patch-security.cmd\r\n' > "$out/winpeshl.ini"
{
    printf 'add "%s/winpeshl.ini" /Windows/System32/winpeshl.ini\n' "$out"
    for name in patch-security.cmd security-smoke.cmd security-probe.ps1; do
        printf 'add "%s/%s" /Windows/System32/%s\n' "$script" "$name" "$name"
    done
    printf 'add "%s/installed-smoke.cmd" /Windows/System32/desktop-smoke.cmd\n' "$script"
} > "$out/update.txt"
wimlib-imagex update "$out/boot.wim" 2 < "$out/update.txt"
mcopy -o -i "$out/pe.img@@1048576" "$out/boot.wim" ::/sources/boot.wim
mdel -i "$out/pe.img@@1048576" ::/patched.txt 2>/dev/null || true
timeout 180 qemu-system-x86_64 -machine q35 -enable-kvm -cpu host -m 4G -nic none -bios "$rom" \
    -drive "file=$out/pe.img,format=raw,if=none,id=pe" -device nvme,drive=pe,serial=CRABEFI_WINPE,addr=0x3 \
    -drive "file=$out/windows.img,format=raw,if=none,id=os" -device nvme,drive=os,serial=CRABEFI_INSTALLED,addr=0x4 \
    -display none -serial "file:$out/serial.log" -monitor none -no-reboot
mtype -i "$out/pe.img@@1048576" ::/patched.txt | grep -q WINDOWS_SECURITY_PROBE_INSTALLED
echo "Patched private installed image: $out/windows.img"

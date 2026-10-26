#!/usr/bin/env bash
# Patch a private copy of the existing WinPE smoke media into a deployment shell.
set -euo pipefail
if [[ $# != 3 ]]; then
    echo "usage: $0 WINPE_TEMPLATE_IMAGE WINPE_BOOT_WIM OUTPUT_DIRECTORY" >&2
    exit 2
fi
script=$(cd "$(dirname "$0")" && pwd)
image=$(realpath "$1")
wim=$(realpath "$2")
mkdir -p "$3"
out=$(realpath "$3")
[[ ! -e $out/installer.img ]] || { echo 'Refusing to overwrite installer.img' >&2; exit 1; }
cp --reflink=auto --sparse=always "$image" "$out/installer.img"
cp --reflink=auto "$wim" "$out/boot.wim"
printf '[LaunchApps]\r\n%%SYSTEMROOT%%\\System32\\cmd.exe, /c X:\\Windows\\System32\\deploy-installed.cmd\r\n' > "$out/winpeshl.ini"
{
    printf 'add "%s/winpeshl.ini" /Windows/System32/winpeshl.ini\n' "$out"
    for file in deploy-installed.cmd installed-smoke.cmd installed-unattend.xml; do
        printf 'add "%s/%s" /Windows/System32/%s\n' "$script" "$file" "$file"
    done
} > "$out/update.txt"
wimlib-imagex update "$out/boot.wim" 2 < "$out/update.txt"
mcopy -o -i "$out/installer.img@@1048576" "$out/boot.wim" ::/sources/boot.wim
echo "Deployment media: $out/installer.img"

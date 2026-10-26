#!/usr/bin/env bash
# Requires PATH from tools.nix. MODULES is a Nix kernel-modules root, or 'builtin'.
set -euo pipefail
if [[ $# != 3 ]]; then
    echo "usage: $0 CRABEFI_ELF MODULES_OR_builtin OUTPUT_DIRECTORY" >&2
    exit 2
fi
script=$(cd "$(dirname "$0")" && pwd)
payload=$(realpath "$1")
modules=$2
mkdir -p "$3"
out=$(realpath "$3")
root="$out/initramfs"
mkdir -p "$root"/{bin,dev,proc,sys,tmp,modules}
cp --remove-destination -L "$(command -v busybox)" "$root/bin/busybox"
cp --remove-destination -L "$(command -v kexec)" "$root/bin/kexec"
for applet in sh mount ls insmod sync; do
    ln -sf busybox "$root/bin/$applet"
done
musl-cc -static -O2 -Wall -Wextra -Werror "$script/handoff.c" -o "$root/handoff"
python3 "$script/pack.py" "$payload" "$root/crabefi-multiboot.elf"
cp "$script/init" "$root/init"
chmod +x "$root/init"
printf '#!/bin/sh\nset -e\n' > "$root/modules/load"
if [[ $modules != builtin ]]; then
    modules=$(realpath "$modules")
    mapfile -t versions < <(find "$modules/lib/modules" -mindepth 1 -maxdepth 1 -type d -printf '%f\n')
    [[ ${#versions[@]} == 1 ]] || { echo 'Expected one kernel module version' >&2; exit 1; }
    modprobe --show-depends -d "$modules" -S "${versions[0]}" nvme > "$out/module-dependencies.txt"
    while read -r action path _; do
        [[ $action == insmod ]] || continue
        name=$(basename "${path%.xz}")
        case "$path" in
            *.xz) xz -dc "$path" > "$root/modules/$name" ;;
            *.ko) cp --remove-destination "$path" "$root/modules/$name" ;;
            *) echo "Unsupported module compression: $path" >&2; exit 1 ;;
        esac
        printf 'insmod /modules/%s\n' "$name" >> "$root/modules/load"
    done < "$out/module-dependencies.txt"
fi
(cd "$root"; find . -print0 | sort -z | cpio --null -o --format=newc 2>/dev/null | gzip -1) > "$out/initramfs.cpio.gz"
echo "Built $out/initramfs.cpio.gz"

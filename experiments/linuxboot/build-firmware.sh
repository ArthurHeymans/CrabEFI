#!/usr/bin/env bash
# Run in a coreboot/Linux build SDK, with tools.nix's bin directory on PATH.
# Uses separate output directories; never cleans or changes either source tree.
set -euo pipefail
if [[ $# != 3 ]]; then
    echo "usage: $0 CLEAN_LINUX_SOURCE COREBOOT_SOURCE OUTPUT_DIRECTORY" >&2
    exit 2
fi
script=$(cd "$(dirname "$0")" && pwd)
project=$(realpath "$script/../..")
linux=$(realpath "$1")
coreboot=$(realpath "$2")
mkdir -p "$3"
out=$(realpath "$3")
if [[ -f $linux/.config || -d $linux/include/config || -d $linux/arch/x86/include/generated ]]; then
    echo 'Linux requires a clean source tree for an out-of-tree build; source was not changed.' >&2
    exit 1
fi
make -C "$linux" O="$out/linux" KCONFIG_ALLCONFIG="$script/linux.config" allnoconfig
make -C "$linux" O="$out/linux" -j"$(nproc)" bzImage
bash "$script/build-initramfs.sh" "$project/target/x86_64-unknown-none/release/crabefi" builtin "$out"
cp "$script/coreboot.config" "$out/coreboot.config"
make -C "$coreboot" obj="$out/coreboot" DOTCONFIG="$out/coreboot.config" olddefconfig
make -C "$coreboot" obj="$out/coreboot" DOTCONFIG="$out/coreboot.config" -j"$(nproc)"
cp "$out/coreboot/coreboot.rom" "$out/linuxboot.rom"
cbfstool "$out/linuxboot.rom" add-payload -n fallback/payload \
    -f "$out/linux/arch/x86/boot/bzImage" -I "$out/initramfs.cpio.gz" \
    -C 'console=ttyS0,115200 rdinit=/init nokaslr maxcpus=1 panic=-1' -c none
echo "LinuxBoot ROM: $out/linuxboot.rom"

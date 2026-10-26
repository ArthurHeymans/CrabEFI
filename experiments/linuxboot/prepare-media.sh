#!/usr/bin/env bash
# Build disposable WinPE media from a user-supplied Windows 11 amd64 ISO.
set -euo pipefail
if [[ $# != 2 ]]; then
    echo "usage: $0 WINDOWS_ISO OUTPUT_DIRECTORY" >&2
    exit 2
fi
iso=$(realpath "$1")
mkdir -p "$2"
cd "$2"
[[ ! -e windows.img ]] || { echo 'Refusing to overwrite windows.img' >&2; exit 1; }
mkdir -p media customize
7z x -y -omedia "$iso" boot efi sources/boot.wim
# The retail installation ISO boots image 2 (Windows Setup). Replace its shell,
# not just startnet.cmd, so Windows Setup cannot hide the test result.
printf '[LaunchApps]\r\n%%SYSTEMROOT%%\\System32\\cmd.exe, /c X:\\Windows\\System32\\crabefi-smoke.cmd\r\n' > customize/winpeshl.ini
printf '%s\r\n' \
    '@echo off' \
    'wpeinit' \
    '(echo select disk 0&echo select partition 1&echo assign letter=S&echo exit)>X:\crabefi-diskpart.txt' \
    'diskpart /s X:\crabefi-diskpart.txt >X:\crabefi-diskpart.log' \
    'mkdir S:\crabefi-smoke' \
    'ver >S:\crabefi-smoke\version.txt' \
    'copy X:\crabefi-diskpart.log S:\crabefi-smoke\diskpart.txt' \
    'echo CRABEFI_WINDOWS_BOOT_SMOKE_SUCCESS>S:\crabefi-smoke\success.txt' \
    'wpeutil shutdown' > customize/crabefi-smoke.cmd
printf 'add "%s/customize/winpeshl.ini" /Windows/System32/winpeshl.ini\nadd "%s/customize/crabefi-smoke.cmd" /Windows/System32/crabefi-smoke.cmd\n' \
    "$PWD" "$PWD" > customize/update.txt
wimlib-imagex update media/sources/boot.wim 2 < customize/update.txt
# A real GPT/ESP is needed: CrabEFI's boot discovery does not scan a bare FAT
# superfloppy here. Only this new regular file is partitioned/formatted.
truncate -s 2052M windows.img
parted -s windows.img mklabel gpt mkpart ESP fat32 1MiB 2049MiB set 1 esp on
mkfs.vfat -F32 -n CRABEFI_WIN --offset=2048 windows.img 2097152
mcopy -s -i windows.img@@1048576 media/* ::/
echo "WinPE template: $PWD/windows.img"

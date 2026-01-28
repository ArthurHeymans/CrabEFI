#!/bin/bash
# Run CrabEFI in QEMU with coreboot
#
# Usage: ./scripts/run-qemu.sh [coreboot.rom] [disk.img]
#
# Prerequisites:
#   - Build coreboot with CrabEFI as payload (see README)
#   - Create test disk with ./scripts/create-test-disk.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Default paths
COREBOOT_ROM="${1:-$HOME/src/coreboot/build/coreboot.rom}"
DISK_IMG="${2:-$PROJECT_DIR/test-disk.img}"

# Check for coreboot ROM
if [ ! -f "$COREBOOT_ROM" ]; then
    echo "Error: coreboot ROM not found: $COREBOOT_ROM"
    echo ""
    echo "Build coreboot with CrabEFI payload first. See instructions below."
    echo ""
    cat << 'EOF'
=== Building coreboot with CrabEFI ===

1. Clone coreboot (if not already):
   git clone https://review.coreboot.org/coreboot.git ~/src/coreboot
   cd ~/src/coreboot
   git submodule update --init --checkout

2. Build CrabEFI:
   cd ~/src/CrabEFI
   cargo build --release --bin crabefi

3. Configure coreboot for QEMU:
   cd ~/src/coreboot
   make menuconfig
   
   Settings:
   - Mainboard -> Mainboard vendor: Emulation
   - Mainboard -> Mainboard model: QEMU x86 i440fx/piix4
   - Payload -> Add a payload: An ELF executable payload
   - Payload -> Payload path: ~/src/CrabEFI/target/x86_64-unknown-none/release/crabefi

4. Build coreboot:
   make -j$(nproc)

The ROM will be at: ~/src/coreboot/build/coreboot.rom
EOF
    exit 1
fi

# Check for disk image
if [ ! -f "$DISK_IMG" ]; then
    echo "Error: Disk image not found: $DISK_IMG"
    echo ""
    echo "Create one with: ./scripts/create-test-disk.sh"
    exit 1
fi

echo "=== CrabEFI QEMU Test ==="
echo "coreboot ROM: $COREBOOT_ROM"
echo "Disk image:   $DISK_IMG"
echo ""
echo "Serial output will appear below. Press Ctrl+A X to exit QEMU."
echo "=========================================="
echo ""

# Run QEMU
# -bios: Use coreboot ROM instead of SeaBIOS
# -drive: Attach NVMe disk (CrabEFI has NVMe driver)
# -serial mon:stdio: Serial output to terminal with monitor
# -nographic: No graphical window
# -m: Memory size
# -cpu: CPU model (host for KVM, qemu64 otherwise)

QEMU_ARGS=(
    -bios "$COREBOOT_ROM"
    -m 512M
    -serial mon:stdio
    -nographic
    -no-reboot
)

# Use NVMe for the disk (CrabEFI has NVMe driver)
QEMU_ARGS+=(
    -drive "file=$DISK_IMG,if=none,id=nvme0,format=raw"
    -device "nvme,serial=deadbeef,drive=nvme0"
)

# Add debug options
QEMU_ARGS+=(
    -d guest_errors
)

# Use KVM if available
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    echo "[Using KVM acceleration]"
    QEMU_ARGS+=(-enable-kvm -cpu host)
else
    echo "[KVM not available, using software emulation]"
    QEMU_ARGS+=(-cpu qemu64)
fi

exec qemu-system-x86_64 "${QEMU_ARGS[@]}"

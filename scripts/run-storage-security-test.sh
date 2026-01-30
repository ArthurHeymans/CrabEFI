#!/bin/bash
# Run the Storage Security Protocol test application in QEMU
#
# This script:
# 1. Builds CrabEFI (if needed)
# 2. Builds the storage security test EFI application
# 3. Creates a test disk with the application
# 4. Runs QEMU with USB storage
#
# Usage: ./scripts/run-storage-security-test.sh [coreboot.rom]
#
# Prerequisites:
#   - Build coreboot with CrabEFI as payload (see AGENTS.md)
#   - Install: parted, dosfstools, mtools

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Default paths
COREBOOT_ROM="${1:-$HOME/src/coreboot/build/coreboot.rom}"
DISK_IMG="$PROJECT_DIR/test-security-disk.img"
TEST_APP_DIR="$PROJECT_DIR/test/storage-security-test"
TEST_APP="$TEST_APP_DIR/target/x86_64-unknown-uefi/release/storage-security-test.efi"

echo "=== CrabEFI Storage Security Test ==="
echo ""

# Step 1: Build the storage security test application
echo "[1/4] Building storage security test application..."
cd "$TEST_APP_DIR"
cargo build --release 2>&1 | grep -v "^   Compiling" || true

if [ ! -f "$TEST_APP" ]; then
    echo "Error: Failed to build test application"
    exit 1
fi
echo "      Built: $TEST_APP"
ls -lh "$TEST_APP" | awk '{print "      Size: " $5}'
echo ""

# Step 2: Check for coreboot ROM
echo "[2/4] Checking coreboot ROM..."
if [ ! -f "$COREBOOT_ROM" ]; then
    echo "Error: coreboot ROM not found: $COREBOOT_ROM"
    echo ""
    echo "Build coreboot with CrabEFI payload:"
    echo "  1. cp target/x86_64-unknown-none/release/crabefi.elf ~/src/coreboot/payloads/external/crabefi/"
    echo "  2. cd ~/src/coreboot && make -j\$(nproc)"
    echo ""
    echo "Or specify path: $0 /path/to/coreboot.rom"
    exit 1
fi
echo "      Found: $COREBOOT_ROM"
echo ""

# Step 3: Create test disk
echo "[3/4] Creating test disk with security test application..."

# Check for required tools
for tool in dd parted mkfs.fat; do
    if ! command -v $tool &> /dev/null; then
        echo "Error: $tool is required but not installed"
        echo "  On Fedora/RHEL: sudo dnf install parted dosfstools mtools"
        echo "  On Debian/Ubuntu: sudo apt install parted dosfstools mtools"
        exit 1
    fi
done

# Create disk image
dd if=/dev/zero of="$DISK_IMG" bs=1M count=64 status=none

# Create GPT partition table and ESP partition
parted -s "$DISK_IMG" mklabel gpt
parted -s "$DISK_IMG" mkpart ESP fat32 1MiB 100%
parted -s "$DISK_IMG" set 1 esp on

# Set up loop device
LOOP_DEV=$(sudo losetup --find --show --partscan "$DISK_IMG")
PART_DEV="${LOOP_DEV}p1"

# Wait for partition device
sleep 1

# Format as FAT32
sudo mkfs.fat -F 32 -n "SECTEST" "$PART_DEV" > /dev/null

# Mount and install
MOUNT_POINT=$(mktemp -d)
sudo mount "$PART_DEV" "$MOUNT_POINT"

# Create EFI directory structure
sudo mkdir -p "$MOUNT_POINT/EFI/BOOT"

# Install the test application as the default boot entry
sudo cp "$TEST_APP" "$MOUNT_POINT/EFI/BOOT/BOOTX64.EFI"

# Create a startup script
cat << 'EOF' | sudo tee "$MOUNT_POINT/startup.nsh" > /dev/null
@echo -off
echo Storage Security Protocol Test
echo ==============================
echo.
\EFI\BOOT\BOOTX64.EFI
EOF

# Unmount and clean up
sudo umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"
sudo losetup -d "$LOOP_DEV"

echo "      Created: $DISK_IMG"
echo ""

# Step 4: Run QEMU
echo "[4/4] Starting QEMU..."
echo ""
echo "=========================================="
echo "Serial output (Ctrl+A X to exit QEMU):"
echo "=========================================="
echo ""

# Build QEMU arguments
QEMU_ARGS=(
    -machine q35
    -bios "$COREBOOT_ROM"
    -m 512M
    -serial mon:stdio
    -nographic
    -no-reboot
)

# Add xHCI controller and USB mass storage device
QEMU_ARGS+=(
    -device qemu-xhci,id=xhci
    -drive "file=$DISK_IMG,if=none,id=usbdisk,format=raw"
    -device "usb-storage,drive=usbdisk,bus=xhci.0"
)

# Use KVM if available
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    QEMU_ARGS+=(-enable-kvm -cpu host)
fi

exec qemu-system-x86_64 "${QEMU_ARGS[@]}"

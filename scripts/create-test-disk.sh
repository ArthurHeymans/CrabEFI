#!/bin/bash
# Create a test disk image with GPT, ESP partition, and test EFI application
#
# Usage: ./scripts/create-test-disk.sh [output.img]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT="${1:-$PROJECT_DIR/test-disk.img}"
DISK_SIZE="64M"
ESP_SIZE="60M"

echo "Creating test disk image: $OUTPUT"

# Check for required tools
for tool in dd parted mkfs.fat mcopy; do
    if ! command -v $tool &> /dev/null; then
        echo "Error: $tool is required but not installed"
        echo "  On Fedora/RHEL: sudo dnf install parted dosfstools mtools"
        echo "  On Debian/Ubuntu: sudo apt install parted dosfstools mtools"
        exit 1
    fi
done

# Create empty disk image
dd if=/dev/zero of="$OUTPUT" bs=1M count=64 status=none

# Create GPT partition table and ESP partition
parted -s "$OUTPUT" mklabel gpt
parted -s "$OUTPUT" mkpart ESP fat32 1MiB 100%
parted -s "$OUTPUT" set 1 esp on

# Set up loop device to format the partition
LOOP_DEV=$(sudo losetup --find --show --partscan "$OUTPUT")
PART_DEV="${LOOP_DEV}p1"

# Wait for partition device to appear
sleep 1

# Format as FAT32
sudo mkfs.fat -F 32 -n "ESP" "$PART_DEV"

# Create mount point and mount
MOUNT_POINT=$(mktemp -d)
sudo mount "$PART_DEV" "$MOUNT_POINT"

# Create EFI directory structure
sudo mkdir -p "$MOUNT_POINT/EFI/BOOT"

# Check if we have a test EFI application
TEST_APP="$PROJECT_DIR/test/hello.efi"
if [ -f "$TEST_APP" ]; then
    echo "Installing test application: $TEST_APP"
    sudo cp "$TEST_APP" "$MOUNT_POINT/EFI/BOOT/BOOTX64.EFI"
else
    # Try to use UEFI Shell if available
    SHELL_PATHS=(
        "/usr/share/edk2/ovmf/Shell.efi"
        "/usr/share/OVMF/Shell.efi"
        "/usr/share/edk2-ovmf/x64/Shell.efi"
        "$HOME/src/edk2/Build/Shell/RELEASE_GCC5/X64/Shell.efi"
    )
    
    SHELL_FOUND=""
    for shell_path in "${SHELL_PATHS[@]}"; do
        if [ -f "$shell_path" ]; then
            SHELL_FOUND="$shell_path"
            break
        fi
    done
    
    if [ -n "$SHELL_FOUND" ]; then
        echo "Installing UEFI Shell from: $SHELL_FOUND"
        sudo cp "$SHELL_FOUND" "$MOUNT_POINT/EFI/BOOT/BOOTX64.EFI"
    else
        echo "WARNING: No test EFI application found!"
        echo "  Create test/hello.efi or install edk2-ovmf package"
        echo "  Creating a placeholder file..."
        # Create a minimal valid PE header (will fail gracefully)
        echo "MZ_PLACEHOLDER" | sudo tee "$MOUNT_POINT/EFI/BOOT/BOOTX64.EFI" > /dev/null
    fi
fi

# Create a startup script for UEFI Shell
cat << 'EOF' | sudo tee "$MOUNT_POINT/startup.nsh" > /dev/null
@echo -off
echo CrabEFI Test Disk
echo.
map -r
EOF

# Unmount and clean up
sudo umount "$MOUNT_POINT"
rmdir "$MOUNT_POINT"
sudo losetup -d "$LOOP_DEV"

echo "Test disk created: $OUTPUT"
echo ""
echo "Partition layout:"
parted -s "$OUTPUT" print

# Also show the size
ls -lh "$OUTPUT"

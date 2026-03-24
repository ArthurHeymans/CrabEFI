#!/bin/bash
# Build boot-test assets: a minimal Linux kernel (bzImage) and a GRUB
# standalone EFI binary.  Results are placed in OUTPUT_DIR (default:
# boot-assets/ under the project root).
#
# The script is intentionally self-contained so that its content hash
# can serve as the GitHub Actions cache key -- any change to the kernel
# version, config tweaks, or GRUB module list automatically invalidates
# the cache.
#
# Dependencies (Ubuntu):
#   apt-get install -y build-essential bc flex bison libelf-dev \
#       curl xz-utils grub-common grub-efi-amd64-bin

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────
KERNEL_VERSION="6.13.7"
KERNEL_MAJOR="${KERNEL_VERSION%%.*}"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/linux-${KERNEL_VERSION}.tar.xz"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-${PROJECT_DIR}/boot-assets}"

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

# ── Build Linux kernel ────────────────────────────────────────────────
if [ -f "$OUTPUT_DIR/vmlinuz" ]; then
    echo "==> vmlinuz already exists, skipping kernel build"
else
    echo "==> Building Linux ${KERNEL_VERSION} (minimal config)..."

    WORK="$(mktemp -d)"
    cleanup() { rm -rf "$WORK"; }
    trap cleanup EXIT

    echo "    Downloading kernel source..."
    curl -sL "$KERNEL_URL" | tar xJ -C "$WORK"

    KSRC="$WORK/linux-${KERNEL_VERSION}"

    # Start from tinyconfig (smallest possible base)
    make -C "$KSRC" -s tinyconfig

    # Layer on the options we need for EFI-stub serial boot in QEMU.
    # scripts/config handles Kconfig tristate/bool properly and
    # make olddefconfig resolves transitive dependencies.
    "$KSRC/scripts/config" --file "$KSRC/.config" \
        --enable  64BIT                 \
        --enable  PRINTK                \
        --enable  TTY                   \
        --enable  SERIAL_8250           \
        --enable  SERIAL_8250_CONSOLE   \
        --enable  EFI                   \
        --enable  EFI_STUB              \
        --enable  EARLY_PRINTK          \
        --enable  X86_X2APIC            \
        --enable  RELOCATABLE           \
        --enable  X86_64                \
        --enable  ACPI

    make -C "$KSRC" -s olddefconfig

    echo "    Compiling (this takes 1-3 minutes)..."
    make -C "$KSRC" -j"$(nproc)" -s bzImage

    cp "$KSRC/arch/x86/boot/bzImage" "$OUTPUT_DIR/vmlinuz"
    echo "    Kernel: $OUTPUT_DIR/vmlinuz ($(stat -c%s "$OUTPUT_DIR/vmlinuz") bytes)"
fi

# ── Build GRUB EFI binary ────────────────────────────────────────────
if [ -f "$OUTPUT_DIR/grubx64.efi" ]; then
    echo "==> grubx64.efi already exists, skipping GRUB build"
else
    echo "==> Building GRUB EFI binary (grub-mkimage)..."

    # Write the early config that gets *embedded* inside the core image.
    # We deliberately skip the 'normal' module because its module-probing
    # behaviour tries to load .mod files from disk/memdisk.  Without
    # 'normal' GRUB runs the embedded config as a flat command script,
    # which is exactly what we want for an automated boot test.
    GRUB_CFG="$(mktemp)"
    cat > "$GRUB_CFG" <<'GRUBCFG'
serial --unit=0 --speed=115200
terminal_input serial
terminal_output serial
search --no-floppy --set=root --file /vmlinuz
linux /vmlinuz console=ttyS0,115200 nokaslr panic=5
boot
GRUBCFG

    grub-mkimage                                        \
        --format=x86_64-efi                             \
        --output="$OUTPUT_DIR/grubx64.efi"              \
        --prefix=''                                     \
        --config="$GRUB_CFG"                            \
        linux fat part_gpt                              \
        search search_fs_file                           \
        serial terminal echo boot

    rm -f "$GRUB_CFG"
    echo "    GRUB:   $OUTPUT_DIR/grubx64.efi ($(stat -c%s "$OUTPUT_DIR/grubx64.efi") bytes)"
fi

# ── Write on-disk grub.cfg ────────────────────────────────────────────
# This copy lives on the ESP at /boot/grub/grub.cfg so that CrabEFI's
# own GRUB-config parser can discover the Linux entry in its boot menu.
cat > "$OUTPUT_DIR/grub.cfg" <<'GRUBCFG'
serial --unit=0 --speed=115200
terminal_input serial
terminal_output serial

set timeout=0
set default=0

menuentry "Linux" {
    linux /vmlinuz console=ttyS0,115200 nokaslr panic=5
}
GRUBCFG

echo "==> Boot assets ready in $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"

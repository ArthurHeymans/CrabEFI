#!/bin/bash
# Build boot-test assets: a minimal Linux kernel, a GRUB EFI binary,
# and a u-root initramfs for a given architecture.  Results are placed
# in OUTPUT_DIR (default: boot-assets/<arch>/ under the project root).
#
# Usage:
#   ci/build-boot-assets.sh [--arch x86_64|aarch64] [output-dir]
#
# The script is intentionally self-contained so that its content hash
# can serve as the GitHub Actions cache key -- any change to the kernel
# version, config tweaks, or GRUB module list automatically invalidates
# the cache.
#
# Dependencies (Ubuntu, x86_64):
#   apt-get install -y build-essential bc flex bison libelf-dev \
#       curl xz-utils grub-common grub-efi-amd64-bin golang-go
#
# Dependencies (Ubuntu, aarch64 cross):
#   apt-get install -y build-essential bc flex bison libelf-dev \
#       curl xz-utils grub-common gcc-aarch64-linux-gnu golang-go
#
# Note: grub-efi-arm64-bin is an arm64-only package on Ubuntu and is
# not installable on amd64 hosts without multi-arch setup.  This script
# automatically downloads and extracts the arm64 GRUB modules from
# Ubuntu ports when cross-compiling.

set -euo pipefail

# ── Parse arguments ───────────────────────────────────────────────────
ARCH="x86_64"
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)  ARCH="$2"; shift 2 ;;
        *)       OUTPUT_DIR="$1"; shift ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-${PROJECT_DIR}/boot-assets/${ARCH}}"

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

# ── Per-architecture settings ─────────────────────────────────────────
KERNEL_VERSION="6.13.7"
KERNEL_MAJOR="${KERNEL_VERSION%%.*}"
KERNEL_URL="https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_MAJOR}.x/linux-${KERNEL_VERSION}.tar.xz"

case "$ARCH" in
    x86_64)
        KERN_ARCH="x86"
        KERN_CROSS=""
        KERN_IMAGE="arch/x86/boot/bzImage"
        GRUB_FORMAT="x86_64-efi"
        GRUB_OUTPUT="grubx64.efi"
        GOARCH="amd64"
        CONSOLE="ttyS0,115200"
        EARLYCON=""
        # GRUB serial module for 8250 UART
        GRUB_SERIAL_MODULES="serial"
        GRUB_SERIAL_CFG=$(cat <<'EOF'
serial --unit=0 --speed=115200
terminal_input serial
terminal_output serial
EOF
)
        ;;
    aarch64)
        KERN_ARCH="arm64"
        # Detect cross-compiler: Debian/Ubuntu use "aarch64-linux-gnu-",
        # NixOS and some distros use "aarch64-unknown-linux-gnu-".
        if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
            KERN_CROSS="aarch64-linux-gnu-"
        elif command -v aarch64-unknown-linux-gnu-gcc >/dev/null 2>&1; then
            KERN_CROSS="aarch64-unknown-linux-gnu-"
        else
            echo "Error: no aarch64 cross-compiler found" >&2
            exit 1
        fi
        KERN_IMAGE="arch/arm64/boot/Image"
        GRUB_FORMAT="arm64-efi"
        GRUB_OUTPUT="grubaa64.efi"
        GOARCH="arm64"
        CONSOLE="ttyAMA0,115200"
        # earlycon provides serial output before ACPI/DTB device
        # discovery; QEMU sbsa-ref has PL011 at 0x60000000.
        EARLYCON="earlycon=pl011,mmio32,0x60000000"
        # aarch64 QEMU uses PL011 UART which works through EFI console;
        # no GRUB serial module needed.
        GRUB_SERIAL_MODULES=""
        GRUB_SERIAL_CFG=""
        ;;
    *)
        echo "Error: unsupported architecture: $ARCH" >&2
        echo "Supported: x86_64, aarch64" >&2
        exit 1
        ;;
esac

echo "==> Architecture: $ARCH"

# ── Build Linux kernel ────────────────────────────────────────────────
if [ -f "$OUTPUT_DIR/vmlinuz" ]; then
    echo "==> vmlinuz already exists, skipping kernel build"
else
    echo "==> Building Linux ${KERNEL_VERSION} (${ARCH}, minimal config)..."

    WORK="$(mktemp -d)"
    cleanup() { chmod -R u+w "$WORK" 2>/dev/null || true; rm -rf "$WORK"; }
    trap cleanup EXIT

    echo "    Downloading kernel source..."
    curl -sL "$KERNEL_URL" | tar xJ -C "$WORK"

    KSRC="$WORK/linux-${KERNEL_VERSION}"
    KMAKE=(make -C "$KSRC" -s ARCH="$KERN_ARCH")
    if [ -n "$KERN_CROSS" ]; then
        KMAKE+=(CROSS_COMPILE="$KERN_CROSS")
    fi

    # Start from tinyconfig (smallest possible base)
    "${KMAKE[@]}" tinyconfig

    # Layer on the options we need for EFI-stub serial boot in QEMU.
    # scripts/config handles Kconfig tristate/bool properly and
    # make olddefconfig resolves transitive dependencies.
    KCFG="$KSRC/scripts/config"
    KCFG_ARGS=(--file "$KSRC/.config")

    # Common options
    "$KCFG" "${KCFG_ARGS[@]}" \
        --enable  PRINTK                \
        --enable  TTY                   \
        --enable  EFI                   \
        --enable  EFI_STUB              \
        --enable  ACPI                  \
        --enable  BLK_DEV_INITRD        \
        --enable  TMPFS                 \
        --enable  DEVTMPFS             \
        --enable  DEVTMPFS_MOUNT       \
        --enable  PROC_FS              \
        --enable  SYSFS                \
        --enable  BINFMT_ELF           \
        --enable  FUTEX                \
        --enable  EVENTFD              \
        --enable  EPOLL                \
        --enable  SIGNALFD             \
        --enable  TIMERFD              \
        --enable  VT                   \
        --enable  VT_CONSOLE           \
        --enable  UNIX98_PTYS          \
        --enable  MULTIUSER

    # Architecture-specific options
    case "$ARCH" in
        x86_64)
            "$KCFG" "${KCFG_ARGS[@]}" \
                --enable  64BIT                 \
                --enable  X86_64                \
                --enable  SERIAL_8250           \
                --enable  SERIAL_8250_CONSOLE   \
                --enable  EARLY_PRINTK          \
                --enable  X86_X2APIC            \
                --enable  RELOCATABLE
            ;;
        aarch64)
            "$KCFG" "${KCFG_ARGS[@]}" \
                --enable  ARM64                 \
                --enable  SERIAL_AMBA_PL011     \
                --enable  SERIAL_AMBA_PL011_CONSOLE \
                --enable  SERIAL_EARLYCON       \
                --enable  EARLY_PRINTK          \
                --enable  IRQCHIP               \
                --enable  ARM_GIC_V3            \
                --enable  ARM_ARCH_TIMER        \
                --disable ARM64_GCS
            ;;
    esac

    "${KMAKE[@]}" olddefconfig

    echo "    Compiling (this takes 1-3 minutes)..."
    "${KMAKE[@]}" -j"$(nproc)" "${KERN_IMAGE##*/}"

    cp "$KSRC/$KERN_IMAGE" "$OUTPUT_DIR/vmlinuz"
    echo "    Kernel: $OUTPUT_DIR/vmlinuz ($(stat -c%s "$OUTPUT_DIR/vmlinuz") bytes)"
fi

# ── Build u-root initramfs ────────────────────────────────────────────
if [ -f "$OUTPUT_DIR/initramfs.cpio" ]; then
    echo "==> initramfs.cpio already exists, skipping u-root build"
else
    echo "==> Building u-root initramfs (${GOARCH})..."

    # Clone u-root and build from its workspace.  Newer u-root (v0.16+)
    # uses Go workspaces for package resolution, so we must run the tool
    # from within the repo.
    UROOT_DIR="$(mktemp -d)"

    echo "    Cloning u-root..."
    git clone --depth 1 -q https://github.com/u-root/u-root.git "$UROOT_DIR/src"

    echo "    Building u-root tool..."
    (cd "$UROOT_DIR/src" && go build -o "$UROOT_DIR/bin/u-root" .)

    # Build the initramfs for the target arch.
    # We include u-root's core commands but use rdinit=/bbin/echo on
    # the kernel command line (see GRUB config below) to bypass u-root's
    # normal init, which blocks on /dev/tty0 OpenConsole in headless
    # QEMU.  The kernel passes unrecognised command-line tokens as
    # argv to the rdinit binary, so "UROOT_BOOT_SUCCESS" ends up as an
    # argument to echo, printing the marker the test harness looks for.
    echo "    Building initramfs (GOARCH=$GOARCH)..."
    (cd "$UROOT_DIR/src" && \
        GOARCH="$GOARCH" "$UROOT_DIR/bin/u-root"    \
            -o "$OUTPUT_DIR/initramfs.cpio"          \
            -format cpio                             \
            -defaultsh ""                            \
            -initcmd ""                              \
            ./cmds/core/echo                         \
            ./cmds/core/cat                          \
            ./cmds/core/ls                           \
    )

    # Go module cache files are read-only; fix permissions before rm.
    chmod -R u+w "$UROOT_DIR" 2>/dev/null || true
    rm -rf "$UROOT_DIR"
    echo "    Initrd: $OUTPUT_DIR/initramfs.cpio ($(stat -c%s "$OUTPUT_DIR/initramfs.cpio") bytes)"
fi

# ── Build GRUB EFI binary ────────────────────────────────────────────
if [ -f "$OUTPUT_DIR/$GRUB_OUTPUT" ]; then
    echo "==> $GRUB_OUTPUT already exists, skipping GRUB build"
else
    echo "==> Building GRUB EFI binary ($GRUB_FORMAT, grub-mkimage)..."

    # ── Ensure GRUB modules for the target arch are available ─────────
    # On amd64 hosts the arm64-efi modules aren't in the default repos
    # (grub-efi-arm64-bin is an arm64 package).  When the system module
    # directory is absent we fetch the .deb from Ubuntu ports and extract
    # the modules to a temporary directory.
    GRUB_MODULE_DIR="/usr/lib/grub/${GRUB_FORMAT}"
    GRUB_DIR_ARG=""

    if [ ! -d "$GRUB_MODULE_DIR" ]; then
        echo "    GRUB modules for ${GRUB_FORMAT} not found at ${GRUB_MODULE_DIR}"
        echo "    Downloading from Ubuntu ports..."
        GRUB_TMP="$(mktemp -d)"

        # Look up the .deb path from the Packages index (try noble-updates
        # first, then fall back to the noble release pocket).
        # Note: awk must NOT use 'exit' here -- under set -o pipefail an
        # early exit causes zcat to receive SIGPIPE and fail the pipeline.
        for SUITE in noble-updates noble; do
            PACKAGES_URL="http://ports.ubuntu.com/ubuntu-ports/dists/${SUITE}/main/binary-arm64/Packages.gz"
            DEB_PATH=$(curl -sL "$PACKAGES_URL" | zcat | \
                awk '/^Package: grub-efi-arm64-bin$/{found=1} found && /^Filename:/ && !done{print $2; done=1}')
            [ -n "$DEB_PATH" ] && break
        done

        if [ -z "$DEB_PATH" ]; then
            echo "Error: could not find grub-efi-arm64-bin in Ubuntu ports" >&2
            exit 1
        fi

        curl -sL "http://ports.ubuntu.com/ubuntu-ports/${DEB_PATH}" \
            -o "$GRUB_TMP/grub-arm64.deb"
        dpkg-deb -x "$GRUB_TMP/grub-arm64.deb" "$GRUB_TMP/root"
        GRUB_MODULE_DIR="$GRUB_TMP/root/usr/lib/grub/arm64-efi"

        if [ ! -d "$GRUB_MODULE_DIR" ]; then
            echo "Error: GRUB modules not found in extracted package" >&2
            exit 1
        fi
        echo "    Extracted GRUB modules to ${GRUB_MODULE_DIR}"
        GRUB_DIR_ARG="-d ${GRUB_MODULE_DIR}"
    fi

    # Write the early config that gets *embedded* inside the core image.
    # We deliberately skip the 'normal' module because its module-probing
    # behaviour tries to load .mod files from disk/memdisk.  Without
    # 'normal' GRUB runs the embedded config as a flat command script,
    # which is exactly what we want for an automated boot test.
    GRUB_CFG="$(mktemp)"
    {
        if [ -n "$GRUB_SERIAL_CFG" ]; then
            echo "$GRUB_SERIAL_CFG"
        fi
        cat <<GRUBCFG
search --no-floppy --set=root --file /vmlinuz
linux /vmlinuz console=${CONSOLE} ${EARLYCON} nokaslr panic=5 rdinit=/bbin/echo UROOT_BOOT_SUCCESS
initrd /initramfs.cpio
boot
GRUBCFG
    } > "$GRUB_CFG"

    # shellcheck disable=SC2086
    grub-mkimage                                        \
        --format="$GRUB_FORMAT"                         \
        --output="$OUTPUT_DIR/$GRUB_OUTPUT"             \
        --prefix=''                                     \
        --config="$GRUB_CFG"                            \
        $GRUB_DIR_ARG                                   \
        linux fat part_gpt                              \
        search search_fs_file                           \
        terminal echo boot                              \
        $GRUB_SERIAL_MODULES

    rm -f "$GRUB_CFG"
    echo "    GRUB:   $OUTPUT_DIR/$GRUB_OUTPUT ($(stat -c%s "$OUTPUT_DIR/$GRUB_OUTPUT") bytes)"
fi

# ── Write on-disk grub.cfg ────────────────────────────────────────────
# This copy lives on the ESP at /boot/grub/grub.cfg so that CrabEFI's
# own GRUB-config parser can discover the Linux entry in its boot menu.
{
    if [ -n "$GRUB_SERIAL_CFG" ]; then
        echo "$GRUB_SERIAL_CFG"
    fi
    cat <<GRUBCFG

set timeout=0
set default=0

menuentry "Linux" {
    linux /vmlinuz console=${CONSOLE} ${EARLYCON} nokaslr panic=5 rdinit=/bbin/echo UROOT_BOOT_SUCCESS
    initrd /initramfs.cpio
}
GRUBCFG
} > "$OUTPUT_DIR/grub.cfg"

echo "==> Boot assets ready in $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"

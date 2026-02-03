# Building CrabEFI

This document describes how to build CrabEFI and run tests.

## Prerequisites

### Using Nix (Recommended)

The easiest way to get all dependencies is using Nix:

```bash
# Enter the development shell
nix develop
```

This provides:
- Rust nightly toolchain with `x86_64-unknown-none` target
- QEMU for testing
- mtools and dosfstools for disk image creation
- cbfstool for coreboot ROM manipulation
- zstd for ROM decompression

### Manual Setup

If not using Nix, install the following:

**Rust Toolchain:**
```bash
# Install Rust nightly
rustup toolchain install nightly
rustup default nightly

# Add the bare-metal target
rustup target add x86_64-unknown-none
```

**System Packages (Debian/Ubuntu):**
```bash
sudo apt install \
    qemu-system-x86 \
    mtools \
    dosfstools \
    zstd
```

**cbfstool:** Build from coreboot source or install `coreboot-utils` if available.

## Building

### Basic Build

```bash
# Build CrabEFI (release mode, required for firmware)
cargo build --release
```

The output ELF is at: `target/x86_64-unknown-none/release/crabefi.elf`

### Using the Build Tool

The `./crabefi` tool (implemented in `xtask/`) provides convenient build commands:

```bash
# Build CrabEFI
./crabefi build

# Clean build
cargo clean && ./crabefi build

# Check without building
cargo check
```

### Build Configuration

Key files:

- **`Cargo.toml`**: Crate manifest with dependencies
- **`.cargo/config.toml`**: Build configuration (target, linker)
- **`x86_64-coreboot.ld`**: Linker script for memory layout

## Testing

### Available Test Applications

```bash
# List available test apps
./crabefi list-test-apps
```

Test applications are in `test-apps/`:

| Application | Description |
|-------------|-------------|
| `hello` | Simple hello world, tests basic EFI services |
| `storage-security-test` | Tests BlockIO and storage protocols |
| `secure-boot-test` | Tests Secure Boot verification |

### Running Tests

```bash
# Build a test application
./crabefi build-test-app hello

# Run integration test (builds app, creates disk, runs QEMU, checks output)
./crabefi test --app hello
```

### Interactive QEMU

```bash
# Run with USB storage (default)
./crabefi run --app hello

# Run with AHCI/SATA storage
./crabefi run --app hello --ahci

# Run with NVMe storage
./crabefi run --app hello --nvme

# Disable KVM (for running inside VMs)
./crabefi run --app hello --disable-kvm
```

### Creating Disk Images

```bash
# Create a disk image with an EFI application
./crabefi create-disk --output test.img --efi-app path/to/app.efi
```

## QEMU Testing Environment

The test environment uses a pre-built coreboot ROM (`firmware/coreboot-qemu-q35.rom.zst`) configured for the Q35 chipset. CrabEFI is added as the payload automatically.

### QEMU Arguments

When running with `./crabefi run`, QEMU is launched with:

- Q35 machine type with appropriate storage controllers
- Serial console on stdio
- 1GB RAM
- KVM acceleration (if available and not disabled)

### Debugging

Serial output goes to the console. For more detailed debugging:

```bash
# Enable verbose logging (in the code)
# Logs go to serial port and CBMEM console

# View QEMU monitor
# Press Ctrl+A, C to enter monitor
# Type 'quit' to exit
```

## Building Test Applications

Test applications are separate crates targeting `x86_64-unknown-uefi`:

```bash
cd test-apps/hello
cargo build --release
```

Output: `test-apps/hello/target/x86_64-unknown-uefi/release/hello.efi`

### Creating New Test Applications

1. Create a new directory in `test-apps/`
2. Add `Cargo.toml` with target `x86_64-unknown-uefi`
3. Implement the EFI entry point

Example `Cargo.toml`:
```toml
[package]
name = "my-test"
version = "0.1.0"
edition = "2021"

[dependencies]
r-efi = "5.3"

[profile.release]
panic = "abort"
```

## Deployment

### Using with Coreboot

To use CrabEFI as a coreboot payload:

1. Build CrabEFI: `cargo build --release`
2. Add to coreboot ROM using cbfstool:
   ```bash
   cbfstool coreboot.rom add-payload \
       -f target/x86_64-unknown-none/release/crabefi.elf \
       -n fallback/payload \
       -c lzma
   ```

### Real Hardware

When flashing to real hardware:

1. Ensure coreboot is working on your board first
2. Keep a backup of working firmware
3. Test in QEMU with similar configuration first
4. Have a recovery method (external flash programmer)

## Troubleshooting

### Common Issues

**"can't find crate for test"**

This LSP error is expected. CrabEFI targets bare-metal (`#![no_std]`) and doesn't have the test harness. The code compiles correctly.

**QEMU fails to start**

- Check KVM availability: `ls /dev/kvm`
- Try `--disable-kvm` if running inside a VM

**Disk image creation fails**

- Ensure `mtools` and `dosfstools` are installed
- Check disk space for temporary files

**Build fails with linker errors**

- Ensure you're using the correct Rust nightly version
- Check that `x86_64-unknown-none` target is installed

### Debug Output

CrabEFI logs to:
1. Serial port (COM1, 0x3F8)
2. CBMEM console (viewable in coreboot)
3. Framebuffer (if `fb-log` feature is enabled)

Enable the framebuffer logging feature for visual debugging:

```bash
cargo build --release --features fb-log
```

Note: Framebuffer logging is very slow and should only be used for debugging.

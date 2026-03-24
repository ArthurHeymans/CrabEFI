# Building CrabEFI

## Prerequisites

### Using Nix (Recommended)

```bash
nix develop
```

This provides the Rust nightly toolchain, QEMU, mtools, dosfstools, cbfstool, and zstd.

### Manual Setup

**Rust Toolchain:**
```bash
rustup toolchain install nightly
rustup default nightly
rustup target add x86_64-unknown-none aarch64-unknown-none
rustup component add rust-src llvm-tools-preview
```

**System Packages (Debian/Ubuntu):**
```bash
sudo apt install qemu-system-x86 qemu-system-arm mtools dosfstools zstd coreboot-utils
```

## Building

### Using the Build Tool (Recommended)

The `./crabefi` wrapper invokes the xtask build system:

```bash
# Build for x86_64 (default)
./crabefi build

# Build for aarch64 (QEMU SBSA)
./crabefi build --arch aarch64

# Build for aarch64 (QEMU virt)
./crabefi build --arch aarch64 --machine virt
```

The output ELF is at `target/<triple>/release/crabefi`.

### Using Cargo Directly

```bash
# Build the coreboot payload binary
cargo build -p crabefi-coreboot --release --target x86_64-unknown-none

# Build only the library (for external integration)
cargo build -p crabefi --release --target x86_64-unknown-none

# Build the drivers crate
cargo build -p crabefi-drivers --release --target x86_64-unknown-none

# aarch64
cargo build -p crabefi-coreboot --release --target aarch64-unknown-none

# aarch64 with custom payload base (QEMU virt)
PAYLOAD_BASE=0x62000000 cargo build -p crabefi-coreboot --release --target aarch64-unknown-none
```

### Build Configuration

| File | Purpose |
|------|---------|
| `Cargo.toml` | Workspace root + core library manifest |
| `crabefi-coreboot/Cargo.toml` | Coreboot binary manifest |
| `crabefi-drivers/Cargo.toml` | Drivers library manifest |
| `.cargo/config.toml` | `build-std` settings, target-specific rustflags |
| `crabefi-coreboot/build.rs` | Linker script selection, `PAYLOAD_BASE` |
| `x86_64-coreboot.ld` | x86_64 linker script |
| `aarch64-coreboot.ld` | aarch64 linker script |
| `rust-toolchain.toml` | Nightly toolchain with `rust-src` |

### Cargo Features

| Feature | Default | Description |
|---------|---------|-------------|
| `platform-entry` | off | Include CrabEFI's own `_start` entry point, EL2 page table setup, and exception vectors. Disable when integrating CrabEFI as a library into firmware that provides its own entry point. |
| `global-allocator` | off | Register the built-in bump allocator as `#[global_allocator]` |
| `fb-log` | off | Log to framebuffer (very slow, debugging only) |
| `rt-debug` | off | Serial debug after `SetVirtualAddressMap` |
| `rt-log` | off | Warm-reboot-persistent ring buffer for runtime service logging |

The `crabefi-coreboot` binary enables both `platform-entry` and `global-allocator` automatically. External firmware that provides its own entry point and allocator should not enable these features.

## Testing

### Integration Tests

```bash
# Run with USB storage (default)
./crabefi test --app hello

# Run with different storage backends
./crabefi test --app hello --nvme
./crabefi test --app hello --ahci
./crabefi test --app hello --sdhci

# Run RNG protocol test
./crabefi test --app rng-test

# Run directory enumeration test
./crabefi test --app directory-test

# Disable KVM (when running inside a VM)
./crabefi test --app hello --disable-kvm

# aarch64 tests
./crabefi test --arch aarch64 --machine sbsa --app hello --nvme --disable-kvm
./crabefi test --arch aarch64 --machine virt --app hello --nvme --disable-kvm
```

### Interactive QEMU

```bash
./crabefi run --app hello
./crabefi run --app hello --nvme
./crabefi run --app hello --ahci --headless
```

### Test Applications

Test apps live in `test-apps/` and target `x86_64-unknown-uefi` / `aarch64-unknown-uefi`:

| Application | Description |
|-------------|-------------|
| `hello` | Basic EFI services smoke test |
| `rng-test` | `EFI_RNG_PROTOCOL` validation |
| `directory-test` | Filesystem and long filename tests |
| `storage-security-test` | Storage security command tests |
| `secure-boot-test` | Secure Boot verification tests |
| `fw-dump` | Firmware info dump utility |

```bash
# List available test apps
./crabefi list-test-apps

# Build a single test app
./crabefi build-test-app hello

# Create a disk image with a custom EFI app
./crabefi create-disk --output test.img --efi-app path/to/app.efi
```

### CI Checks

The CI pipeline runs (replicate locally before pushing):

```bash
# Formatting
cargo fmt --all --check

# Clippy (both architectures)
cargo clippy --workspace --release --target x86_64-unknown-none -- -D warnings
cargo clippy --workspace --release --target aarch64-unknown-none -- -D warnings

# Build
cargo build -p crabefi-coreboot --release --target x86_64-unknown-none
cargo build -p crabefi-coreboot --release --target aarch64-unknown-none
PAYLOAD_BASE=0x62000000 cargo build -p crabefi-coreboot --release --target aarch64-unknown-none
```

## Deployment

### Using with Coreboot

1. Build: `./crabefi build`
2. Add to a coreboot ROM:
   ```bash
   cbfstool coreboot.rom remove -n fallback/payload
   cbfstool coreboot.rom add-payload \
       -f target/x86_64-unknown-none/release/crabefi \
       -n fallback/payload \
       -c lzma
   ```

### Real Hardware

- Ensure coreboot works on your board first.
- Keep a backup of working firmware.
- Test in QEMU with a similar configuration first.
- Have a recovery method (external flash programmer).

## Troubleshooting

**QEMU fails to start** -- Check KVM: `ls /dev/kvm`. Use `--disable-kvm` inside VMs.

**Disk image creation fails** -- Ensure `mtools` and `dosfstools` are installed.

**Build fails with linker errors** -- Check the nightly toolchain and `rust-src` component.

**Debug output** -- CrabEFI logs to serial (COM1 / PL011), CBMEM console, and optionally the framebuffer (`--features fb-log`).

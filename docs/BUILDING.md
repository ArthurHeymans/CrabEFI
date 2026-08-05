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

### Direct Cargo build

`crabefi-coreboot` uses the checked-in, architecture-matched runtime bundle by
default, so external build systems such as coreboot can invoke Cargo directly:

```bash
cargo build -p crabefi-coreboot --release --target x86_64-unknown-none
```

This mode supports the normal `ui` feature and does not require runtime-image
environment variables.

### Fresh audited runtime build

The wrapper rebuilds and audits the Runtime Services image, then selects
`crabefi-coreboot`'s `external-runtime-image` mode to bind that exact artifact:

```bash
./crabefi build --arch x86-64
./crabefi build --arch aarch64 --machine sbsa
./crabefi build --arch aarch64 --machine virt
./crabefi build --arch riscv64
```

Payload ELFs remain under `target/<triple>/release/crabefi`. Runtime ELF/image,
map, symbols, disassembly, stack report, digest, and JSON audits are under
`target/runtime/<arch>/`.

### Build Configuration

| File | Purpose |
|------|---------|
| `Cargo.toml` | Virtual workspace root |
| `crabefi-core/Cargo.toml` | Core library manifest |
| `crabefi-coreboot/Cargo.toml` | Coreboot binary manifest |
| `crabefi-drivers/Cargo.toml` | Drivers library manifest |
| `.cargo/config.toml` | `build-std` settings, target-specific rustflags |
| `crabefi-coreboot/build.rs` | Runtime embedding, linker selection, `PAYLOAD_BASE` |
| `crabefi-runtime-image/.cargo/config.toml` | Isolated runtime build with image-local bounded scratch allocation |
| `crabefi-runtime-image/link/*.ld` | ET_DYN runtime image linker scripts |
| `crabefi-coreboot/*-coreboot.ld` | Boot-lifetime payload linker scripts |
| `rust-toolchain.toml` | Nightly toolchain with `rust-src` |

### Cargo Features

| Feature | Default | Description |
|---------|---------|-------------|
| `bundled-runtime-image` | off | Embed the architecture-matched normalized Runtime Services image for Cargo-only library integration |
| `platform-entry` | off | Include CrabEFI's own `_start` entry point, EL2 page table setup, and exception vectors. Disable when integrating CrabEFI as a library into firmware that provides its own entry point. |
| `global-allocator` | off | Register the built-in bump allocator as `#[global_allocator]` |
| `fb-log` | off | Log to framebuffer (very slow, debugging only) |

The `crabefi-coreboot` binary enables both `platform-entry` and `global-allocator` automatically. External firmware that provides its own entry point and allocator should not enable these features.

For the `crabefi-coreboot` package itself, `bundled-runtime-image` is enabled by
default. `external-runtime-image` is mutually exclusive and is selected by the
wrapper with `--no-default-features` when embedding a freshly audited artifact.

### Updating the Cargo runtime bundle

Maintainers regenerate a bundled image from the audited runtime build with:

```bash
./crabefi bundle-runtime --arch x86-64
./crabefi bundle-runtime --arch aarch64
./crabefi bundle-runtime --arch riscv64
```

The generated normalized images and raw SHA-256 digests are stored under
`crabefi-runtime-bundle/images/`. Library consumers should not need to run
these commands; they consume the checked-in image selected by Cargo.

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

# Validate separate-image ownership, variables, EBS, transactional SVAM,
# ConvertPointer, and post-SVAM reset (x86-64)
./crabefi test --app runtime-image-test --disable-kvm

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

# Complete release builds (each creates and binds the matching runtime image)
./crabefi build --arch x86-64
./crabefi build --arch aarch64 --machine sbsa
./crabefi build --arch aarch64 --machine virt
./crabefi build --arch riscv64

# Direct workspace diagnostics use the image path and digest produced above.
RUNTIME_IMAGE_PATH="$PWD/target/runtime/x86_64/runtime.img" \
RUNTIME_IMAGE_SHA256="$(tr -d '\n' < target/runtime/x86_64/sha256)" \
cargo +nightly -Z build-std=core,compiler_builtins,alloc \
  -Z build-std-features=compiler-builtins-mem \
  clippy --workspace --release --target x86_64-unknown-none -- -D warnings
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

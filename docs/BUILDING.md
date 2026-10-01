# Building CrabEFI

## Prerequisites

### Using Nix (Recommended)

```bash
nix develop
```

This provides the Rust nightly toolchain, QEMU, mtools, dosfstools, cbfstool, zstd, and p7zip.

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
sudo apt install curl qemu-system-x86 qemu-system-arm mtools dosfstools zstd coreboot-utils p7zip-full
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

# Run directory enumeration, writable USB mutation and persistence checks
./crabefi test --app directory-test --disable-kvm

# Verify mutation is rejected on read-only backends
./crabefi test --app directory-test --ahci --disable-kvm
./crabefi test --app directory-test --nvme --disable-kvm

# Disable KVM (when running inside a VM)
./crabefi test --app hello --disable-kvm

# aarch64 tests
./crabefi test --arch aarch64 --machine sbsa --app hello --nvme --disable-kvm
./crabefi test --arch aarch64 --machine virt --app hello --nvme --disable-kvm
```

The directory test uses a disposable disk. USB runs must exercise writes,
shared handles, truncation and deletion; AHCI/NVMe runs must reject creation.
After QEMU exits, the harness runs `fsck.fat -n` on a copy of the ESP and uses
`mtype` to verify the USB run's flushed payload and zero-filled gap independently.
Both tools come from the existing dosfstools/mtools test dependencies. CI gates
all three backends; this is not physical-media or power-loss qualification.

### Interactive QEMU

```bash
./crabefi run --app hello
./crabefi run --app hello --nvme
./crabefi run --app hello --ahci --headless
```

### UEFI SCT smoke subset

CrabEFI can run a small public UEFI Self-Certification Test subset in QEMU. The
test uses prebuilt public artifacts from `tianocore/edk2-test` and an EDK2 UEFI
Shell binary from `pbatard/UEFI-Shell`; hashes are pinned in
`ci/build-sct-assets.sh`.

```bash
# Download and verify SCT + UEFI Shell assets
ci/build-sct-assets.sh --arch x86_64

# Run the SCT smoke sequence
./crabefi test --app uefi-sct-smoke \
    --sct-assets-dir sct-assets/x86_64 \
    --disable-kvm \
    --timeout 300
```

The default `ci/sct/smoke.seq` retains the original six Boot Services cases.
CI additionally gates 46 distinct cases across seven subsystem sequences:

```bash
./crabefi test --app uefi-sct-smoke --disable-kvm --timeout 900 \
    --sct-sequence ci/sct/boot-memory.seq \
    --sct-report-dir target/sct-reports/boot-memory
```

The selected sequence is the validation manifest; every dispatched instance
must explicitly pass with zero assertion errors or warnings. Reports are
retained in a unique directory under the requested report root (default:
`target/sct-reports/smoke`), including failed runs. See
[UEFI conformance priorities](UEFI_CONFORMANCE.md) for exact scopes, required
interface gaps, and why these results are not a complete compliance claim.

### Windows Boot Manager smoke test

CrabEFI can also run a Windows/WinPE boot smoke test in QEMU. The preferred
public-source path builds WinPE media from Microsoft's official Windows ADK and
Windows PE add-on, then boots that media through CrabEFI and Windows Boot
Manager. The generated WinPE image writes a deterministic marker to COM1 after
`startnet.cmd` runs.

The default marker is `CRABEFI_WINDOWS_BOOT_SMOKE_SUCCESS`. Generated WinPE
markers must be nonempty printable ASCII. Success markers must not contain a
failure marker such as `Recovery`, `Access Denied`, or `Status: 0xc000`.

Build the WinPE media on Windows:

```powershell
ci/build-winpe-smoke-media.ps1 `
    -Arch x86_64 `
    -OutputDir windows-assets/x86_64/media `
    -SuccessMarker CRABEFI_WINDOWS_BOOT_SMOKE_SUCCESS
```

Then run the smoke test from Linux:

```bash
./crabefi test --app windows-boot-smoke \
    --windows-media-dir windows-assets/x86_64/media \
    --windows-success-marker CRABEFI_WINDOWS_BOOT_SMOKE_SUCCESS \
    --nvme \
    --disable-kvm \
    --timeout 900
```

For custom Windows or WinPE images, you can also pass a raw disk image instead:

```bash
./crabefi test --app windows-boot-smoke --windows-disk path/to/windows-smoke.img
```

If no explicit path is passed, the xtask looks for
`windows-assets/x86_64/media` first, then `windows-assets/x86_64/windows-smoke.img`.
Raw disk images are copied into a temporary directory before boot so the source
artifact is not modified by QEMU.

The GitHub Actions job is intentionally optional and runs only on pushes to
`main` or `master`, never on PRs. Build and validate the media locally first,
then package its contents (not the enclosing `media` directory):

```bash
tar -czf winpe-media.tar.gz -C windows-assets/x86_64/media .
```

Store this archive on an authenticated private HTTPS endpoint. Configure
repository secrets `WINDOWS_SMOKE_MEDIA_URL` and `WINDOWS_SMOKE_MEDIA_TOKEN`
(the endpoint must accept `Authorization: Bearer <token>`), then opt in with
`ENABLE_WINDOWS_SMOKE=true`. The job fails if either secret is missing. The
optional `WINDOWS_SMOKE_SUCCESS_MARKER` repository variable overrides the
default serial marker and must match the provisioned media.

WinPE media is **never stored in GitHub Actions caches or artifacts**: fork PRs
can restore base-branch caches, regardless of the producing job's event guard.
If upgrading from the earlier cache-based workflow, delete all
`winpe-smoke-x86_64-*` caches before relying on this policy. Operators remain
responsible for the media's licensing and private-storage access controls.
Keep the job disabled until an actual successful Windows boot is obtained;
a skipped job is not Windows validation.

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

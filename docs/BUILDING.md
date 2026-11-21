# Building CrabEFI

## Repository layout & build/test gotchas

**Which workspace?** Run `cargo test --workspace` at the repository root for
`crabefi-core`, the coreboot payload and their shared crates. It does not run
tests for `xtask`, `ui-harness`, `crabefi-runtime-abi`, `crabefi-runtime-image`
or `test-apps/*`. Use `./crabefi` for firmware and guest app builds. The root
`.cargo/config.toml` scopes its `rustflags` to firmware targets, so host tests
need not leave the repo. To bypass repo config as CI does for excluded crates,
run Cargo from `$HOME`: config discovery starts at the working directory, not
at `--manifest-path`. For example, starting at the repo root:

```bash
repo=$PWD
toolchain=$(rustup show active-toolchain | cut -d' ' -f1)
(cd "$HOME" && cargo +"$toolchain" test --manifest-path "$repo/crabefi-runtime-abi/Cargo.toml")
```

**Which `crabefi`?** `./crabefi` is the shell wrapper for `xtask`.
`cargo test -p crabefi-core` selects the boot library, imported in Rust as
`crabefi` (`[lib] name = "crabefi"`). The `crabefi-coreboot` package builds the
firmware **binary** named `crabefi`; its `[lib]` at `src/table_tests.rs` lets
host tests exercise payload modules without linking the firmware entry point.

**Which runtime image?** `crabefi-runtime-abi` defines the image format and
handoff; `crabefi-runtime-image` implements Runtime Services. The boot-side
loader and client live in `crabefi-core/src/efi/runtime_image/`. Direct
`crabefi-coreboot` builds default to `bundled-runtime-image`, which embeds a
checked-in image from `crabefi-runtime-bundle`. Editing `crabefi-runtime-image`
will not change that payload. Use `./crabefi build` to test your edits with a
fresh image (`external-runtime-image`), or [regenerate the bundle](#updating-the-cargo-runtime-bundle).

**Borrowing firmware state.** [`Local<T>` and `LocalCell<T>`](../crabefi-core/src/cell.rs)
assume a single hart and no access from interrupt context. `LocalCell<T>` copies
values; `Local<T>` checks borrows at runtime. Copy out what you need and drop
the borrow **before** calling foreign EFI code, an event callback or a platform
trait method. These can re-enter firmware; a conflicting borrow panics, and
firmware uses `panic = "abort"`.

## Prerequisites

### Using Nix (Recommended)

```bash
nix develop
```

This provides rustup, QEMU, mtools, dosfstools, cbfstool, zstd, and p7zip. The Rust
toolchain itself is pinned by the workspace `rust-toolchain.toml` and installed by
rustup on first use.

### Manual Setup

**Rust Toolchain:**

The workspace builds on nightly Rust, pinned by date in `rust-toolchain.toml`
(currently nightly-2026-10-08). A nightly is required because the runtime
image builds `core`/`alloc` from source (`-Z build-std`) with a small PIC code
model, while the prebuilt `x86_64-unknown-none` std uses the kernel code model.
Everything else also builds on stable. From the repository root:

```bash
rustup toolchain install   # installs the pinned toolchain, targets, and components
```

Inside the repository, `cargo`/`rustc` automatically use the workspace pin;
no `rustup default` change is needed. An explicit `+toolchain`,
`RUSTUP_TOOLCHAIN`, or directory override can take precedence over the file.

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

The default x86 build keeps coreboot's **32-bit protected-mode entry** and
works with unmodified coreboot and the existing Q35 firmware fixture.

For u-root/LinuxBoot, explicitly select the [64-bit entry](X86_ENTRY_ABI.md):

```bash
./crabefi build --arch x86-64 --entry64
```

This writes `target/entry64/x86_64-unknown-none/release/crabefi`, separately from
the default coreboot payload. Native `run`, `test` and `screenshot` commands
continue to build the default coreboot entry; they do not accept `--entry64`.

### Native Linux-only payload (x86-64)

Use `--native-only` to boot Linux directly from BLS Type #1 or supported
`grub.cfg` entries on FAT, without running an EFI application. This mode uses
CrabEFI's text boot menu. If a kernel fails to load, the menu returns with
autoboot disabled so you can choose another entry. Add `--ext4` for BLS entries
on supported fixed ext2/3/4 disks.

```bash
./crabefi build --native-only
./crabefi run --native-only --disk disk.img --ahci
```

The ELF is written to `target/native-only/x86_64-unknown-none/release/crabefi`,
separate from the default UEFI payload. For a direct Cargo build:

```bash
cargo build -p crabefi-coreboot --release --target x86_64-unknown-none \
    --no-default-features --features native-only
```

This mode does not build or embed a Runtime Services image. It cannot launch
EFI binaries (including shim, GRUB EFI, systemd-boot, and UKIs), and does not
provide UEFI variables, Secure Boot, measured boot, or capsule updates. It
does not measure the kernel, initrd, or command line into the TPM. Do not rely
on TPM policies in this mode to bind secrets to those boot inputs. Use it only
with trusted boot media. The default UEFI build is unchanged.

### Direct Cargo build

`crabefi-coreboot` uses the checked-in, architecture-matched runtime bundle by
default, so external build systems such as coreboot can invoke Cargo directly:

```bash
cargo build -p crabefi-coreboot --release --target x86_64-unknown-none
```

This mode supports the normal `ui` feature and does not require runtime-image
environment variables. To select the entry for u-root instead of coreboot:

```bash
cargo build -p crabefi-coreboot --release --target x86_64-unknown-none --features entry64
```

Unlike the wrapper's separate output directory, direct Cargo builds use the
usual target path; enabling/disabling the feature replaces that output ELF.

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

On AArch64, boot-time image hashing and measured boot use SHA-256 instructions
when the CPU advertises them and the firmware execution level permits SIMD.
Otherwise they use software SHA-256. No build flag is needed. The isolated
UEFI runtime image keeps software SHA-256 because it runs in an OS-owned CPU
context after `ExitBootServices()`.

### Build Configuration

| File | Purpose |
|------|---------|
| `Cargo.toml` | Virtual workspace root |
| `crabefi-core/Cargo.toml` | Core library manifest |
| `crabefi-coreboot/Cargo.toml` | Coreboot binary manifest |
| `.cargo/config.toml` | target-specific rustflags |
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
| `ui` | off | Graphical UI, mouse cursor and EFI Simple Pointer |
| `elan-i2c` | off | Native ELAN I2C touchpad driver for platform-described peripherals (implies `ui`) |
| `hid-i2c` | off | HID-over-I2C touchpads, mice and keyboards for platform-described peripherals (implies `ui`) |

The `crabefi-coreboot` binary enables both `platform-entry` and `global-allocator` automatically. External firmware that provides its own entry point and allocator should not enable these features.

For the `crabefi-coreboot` package itself, `bundled-runtime-image` is enabled by
default. `external-runtime-image` is mutually exclusive and is selected by the
wrapper with `--no-default-features` when embedding a freshly audited artifact.
The `entry64` feature is off by default, applies only to x86-64, and changes
only the payload entry contract for u-root/LinuxBoot.

`CRABEFI_CAPSULE_TRUST_CERTS` names the DER certificates (`:`-separated paths)
that firmware capsule signatures must chain to; the coreboot payload embeds them
at build time. Without it the trust store is empty and every capsule is refused.

### Platform peripherals

A platform hands CrabEFI the devices on buses it owns. It keeps the
controller, clocks, pads and power; CrabEFI picks a driver by the device's
identifiers, in order of preference. Bus and interrupt line are any
embedded-hal `I2c` and `InputPin`:

```rust,ignore
use crabefi::peripheral::{I2cBus, I2cPeripheral, InputLine, Interrupt, Peripheral};

let touchpad = Peripheral::I2c(I2cPeripheral {
    ids: vec!["ELAN0000".into()],
    bus: I2cBus::new(i2c_controller),
    address: 0x15,
    interrupt: Some(Interrupt::Level { line: InputLine::new(gpio_pin), active_low: true }),
});
let config = crabefi::PlatformConfigBuilder::new(/* ... */)
    .peripheral(touchpad)
    .build();
```

`crabefi::peripheral::i2c_supported(ids)` tells whether the build has a
matching driver, so a platform can leave unused controllers alone. Devices are
stopped at ExitBootServices.

### Platform peripherals

A platform hands CrabEFI the devices on buses it owns. It keeps the
controller, clocks, pads and power; CrabEFI picks a driver by the device's
identifiers, in order of preference. Bus and interrupt line are any
embedded-hal `I2c` and `InputPin`:

```rust,ignore
use crabefi::peripheral::{I2cBus, I2cPeripheral, InputLine, Interrupt, Peripheral};

let touchpad = Peripheral::I2c(I2cPeripheral {
    ids: vec!["ELAN0000".into()],
    bus: I2cBus::new(i2c_controller),
    address: 0x15,
    interrupt: Some(Interrupt::Level { line: InputLine::new(gpio_pin), active_low: true }),
    hid_descriptor_register: None,
});
let config = crabefi::PlatformConfigBuilder::new(/* ... */)
    .peripheral(touchpad)
    .build();
```

Memory-mapped SoC devices are described the same way, as
`Peripheral::Mmio(MmioPeripheral { ids, base, size })`; AMD eMMC controllers
(`AMDI0040`, `AMDI0041`) bind this way.

`crabefi::peripheral::i2c_supported(ids)` and `mmio_supported(ids)` tell
whether the build has a matching driver, so a platform can leave unused
controllers alone. Devices are
stopped at ExitBootServices.

The coreboot payload describes ACPI MMIO and I2C devices that a built-in
driver supports. It follows their `I2cSerialBus` and `GpioInt` resource sources to
the controllers and takes those over as coreboot left them. Supported
controllers are AMD DesignWare I2C (`AMDI0010`) and AMD GPIO (`AMD0030`).
Disabled or powered-down devices and controllers are skipped. With `--ui`, the
payload includes the ELAN and HID-over-I2C (`PNP0C50`, descriptor register
from `_DSM`) drivers. A Google security chip TPM
(`GOOG0005`) backs measured boot; its edge-triggered ready interrupt is read
from the pad's latched interrupt status.

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

# Reboot to firmware UI: real persistent flash, EFI ResetSystem, manual menu
# selection, subsequent normal boots, post-EBS request, and no-media setup
./crabefi test --app fwui-test --disable-kvm --timeout 120

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

### Firmware UI reset regression

`fwui-test` is an x86-64 Q35 regression using an EFI application equivalent to
GRUB `fwsetup`/systemd-boot, not those bootloaders themselves. It checks the global
`OsIndicationsSupported` bit and attributes, ORs a request into persistent
`OsIndications`, and calls `ResetSystem`. The host verifies the menu bypasses
BootNext/BootOrder and remains interactive for eight seconds (beyond both the
configured two-second and default five-second timeouts), then sends Enter.
The app checks that only the request bit was cleared and BootNext was preserved;
further resets verify distinct BootNext and BootOrder options through BootCurrent.
The host also rejects a misleading “Booting now” message during setup. A second
request is written after ExitBootServices and replayed from retained memory on
warm reset. The host repeats with the disk removed between QEMU processes, tests
empty-menu Enter, requires the text-menu header and firmware settings navigation,
and checks the next reboot is normal. The temporary SMMSTORE flash is file-backed
and writable, not a volatile
variable mock or a QEMU snapshot. Serial logs, stderr and QEMU commands are kept
under `target/fwui-reports/` on success and failure.

The checked-in Q35 ROM currently supplies no framebuffer, so this tests the
interactive serial/text menu (also with `--ui`'s text fallback), not graphical
rendering. Runtime requests use retained-memory warm-reset staging, not
power-loss-safe runtime flash writes. See [capabilities](capabilities.md).

### Secure Boot key hierarchy and image verification

`secure-boot-auth-test` boots three times on file-backed SMMSTORE that starts
with keys cleared and Secure Boot requested. It enrolls a test PKI, then checks
time-based authenticated writes, the PK/KEK/db/dbx signer rules, persistence
across cold boots and `LoadImage` against db/dbx. Every check prints
`SBAUTH PASS|FAIL <id>`; logs are kept under `target/sb-auth-reports/`.

```bash
./crabefi test --app secure-boot-auth-test --timeout 300   # needs sbsign
```

The fixtures and the plan the app executes come from
`test-apps/secure-boot-auth-test/gen_fixtures.py` (python3-cryptography,
sbsign). Its keys under `fixtures/keys` are test-only.

Ubuntu 24.04's signed shim is opt-in, as it is not redistributed here:

```bash
python3 -I test-apps/secure-boot-auth-test/fetch_ubuntu_shim.py /tmp/ubuntu-shim
CRABEFI_SB_SHIM_DIR=/tmp/ubuntu-shim ./crabefi test --app secure-boot-auth-test
```

`CRABEFI_SB_POWER_LOSS_TRIALS=<n>` adds n opt-in trials that kill QEMU while
the app rewrites a 2 KiB NV variable, then check on the next boot that
PK/KEK/db/dbx are unchanged and the variable holds the old or the new value.
SMMSTORE updates are not claimed to be power-fail safe, so CI does not run them.

### Interactive QEMU

```bash
./crabefi run --app hello
./crabefi run --app hello --nvme
./crabefi run --app hello --ahci --headless
```

To debug the two-boot runtime test using a disk image you already prepared,
use `./crabefi run --headless --disk path/to/test.img --runtime-replay` on
x86-64. Replay enables writable snapshot flash and warm reset without
changing the source ROM. The disk filename does not influence the run.

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
CI additionally gates 48 distinct cases across seven subsystem sequences:

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

### Native Linux boot from ext smoke test

On x86-64, enable experimental ext support with `./crabefi build --ext4`
or `./crabefi run --ext4 --ahci`. It is not part of `full`. The smoke test
builds a GPT disk with no FAT ESP, boots a BLS entry from `/boot`, and checks
that the initramfs ran. It reuses the `vmlinuz` and `initramfs.cpio` from the
GRUB boot test and requires `mke2fs` (e2fsprogs). It defaults to AHCI storage.

```sh
ci/build-boot-assets.sh --arch x86_64
./crabefi test --app ext4-linux --disable-kvm --timeout 180
```

Use `ext2-linux` or `ext3-linux` to test the other ext formats. Use
`native-only-linux` to run the ext4 test with the native-only payload and
verify that it boots without an EFI System Table.

### Linux boot from LUKS2 tests

`./crabefi build --luks` (with or without `--native-only`) adds LUKS2 below
ext. `luks-linux` boots a UEFI payload after a wrong and a right passphrase;
`native-only-luks-tpm-linux` unlocks with `systemd-tpm2` tokens enrolled
into a fresh swtpm state. Both need `cryptsetup` and run without root; the
TPM test also needs `swtpm`, `systemd-cryptenroll` and the tpm2-tss `swtpm`
TCTI. See [LUKS2](LUKS.md).

```sh
./crabefi test --app luks-linux --disable-kvm --timeout 300
./crabefi test --app luks-tpm-linux --disable-kvm --timeout 300
./crabefi test --app native-only-luks-tpm-linux --disable-kvm --timeout 300
```

The `native-only-fat-linux` test requires `busybox-static` and `cpio` and uses
USB storage by default. It checks
that a disk's EFI fallback is ignored, a broken default BLS entry returns to an
interactive menu, and selecting the GRUB entry boots Linux with ACPI but no EFI.

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
| `fwui-test` | x86-64 persistent reboot-to-setup and subsequent normal boot |
| `storage-security-test` | Storage security command tests |
| `secure-boot-test` | Secure Boot verification tests |
| `secure-boot-auth-test` | Authenticated variables, PK/KEK/db/dbx hierarchy and LoadImage verification over three cold boots |
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
cargo -Z build-std=core,compiler_builtins,alloc \
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

**Build fails with linker errors** -- Check the pinned toolchain is installed (`rustup toolchain install` in the repository root) and that no stale `RUSTUP_TOOLCHAIN` override is set.

**Debug output** -- CrabEFI logs to serial (COM1 / PL011), CBMEM console, and optionally the framebuffer (`--features fb-log`).

# Library capabilities and bounded persistent variables

`crabefi-core` has no default capabilities. Consumers select positive, additive
features; there is no global `minimal` switch whose meaning changes under Cargo
feature unification. Build/check the consumer package, not the entire workspace,
when measuring its dependency closure.

| Feature | Includes |
| --- | --- |
| `bundled-runtime-image` | Architecture-matched, digest-bound mandatory runtime image |
| `variable-store` | EDK2 variable persistence through a host-owned bounded backend |
| `spi-flash` | `variable-store` plus the standalone SPI/rflasher adapter |
| `tpm` | TPM transport, TCG protocols, event tables and boot measurements |
| `xhci` | USB 3 host controller implementation and dependency |
| `secure-boot` | UEFI image/key verification and authenticated-variable runtime |
| `capsule-update` | Signed firmware capsule application and bounded variable-store result persistence (no SPI dependency) |
| `pkcs7` | Shared verifier dependencies, used by Secure Boot and capsules |
| `ui` | Graphical setup, mouse support and multi-size monospace bitmap fonts |
| `full` | Existing standalone non-graphical capabilities (all above except `ui`) |

The coreboot binary explicitly selects `full`; its existing `ui` switch adds the
GUI. Boot services, executable loading, FAT/simple filesystem, console, ordinary
runtime variables, time/reset and virtual-address conversion remain available
without optional authentication. SHA-256 used to bind the runtime image is **not**
UEFI Secure Boot and remains in the boot loader. Firmware/FFS signatures supplied
by an embedding host are independent of CrabEFI's UEFI authentication capability.

For a host-provided variable region, use `default-features = false` and
`features = ["bundled-runtime-image", "variable-store"]`. Without `tpm` the TCG
protocols, measurements and final-event table are not compiled/registered; without
`xhci` its PCI probe does not claim that controller. With authentication omitted,
key/enabling writes and authenticated envelopes return errors, standard status
variables remain read-only (`SecureBoot=0`, `SetupMode=1`), and no verifier or
crypto scratch allocator is compiled into the runtime. Previously persisted `PK`
may remain readable in the basic profile; it does not enable enforcement or
change the reported `SecureBoot=0`/`SetupMode=1`. Protected key/auth-history writes
remain denied. This is not an authenticated-variable implementation.

Storage drivers are currently retained: AHCI, NVMe, SDHCI and USB 1/2 storage;
PS/2 and serial console also remain. There is **no IDE/ATA driver** in CrabEFI.
A platform that exposes an IDE-class controller needs a host `BlockDevice` or a
real ATA implementation, not an AHCI feature assumption. No hardware support or
512 KiB whole-ROM fit is established by library/runtime measurements.

## Runtime bundle identity

The normalized image format is version 2. Its mandatory feature bits represent
variables, time, reset and virtual maps; an additional bit identifies Secure Boot.
The normalizer reads a kept source-owned capability marker from the linked ELF,
checks it against the requested profile, and records it in the digest-bound image.
The boot loader rejects capability mismatches **before allocating/calling the
image**. Version 1 images cannot be mistaken for basic images: they are rejected.

`secure-boot` propagates to the optional bundle dependency. Both profiles are
checked in for x86-64, AArch64 and RISC-V so an external Cargo-only consumer does
not need a hidden path patch or a local generated file:

```sh
./crabefi bundle-runtime --arch x86-64                # basic
./crabefi bundle-runtime --arch x86-64 --secure-boot  # authenticated
# Repeat for --arch aarch64 and --arch riscv64.
```

These commands build, normalize and audit the actual runtime executable. Full
standalone payload builds continue to request the authenticated image explicitly.
After changing runtime/ABI sources, regenerate both profiles for all three
architectures and run `ci/check-capabilities.sh`.

The variable cache and transaction arrays are runtime RAM, not persistent media.
Their zero-initialized `user_mode` polarity allows the linker to place them in
BSS; `setup_mode()` still initially returns true. No store capacity, section
memory size or initialization obligation is removed. The loader already zeroes
all allocated image RAM before copying initialized sections and relocating it.

## Bounded boot-time variable region

`PlatformConfig.variable_storage` selects:

- `VariableStorage::None`: no persistent backend; durable writes fail.
- `VariableStorage::Platform(&mut backend)`: a host-owned bounded region. The
  builder shorthand is `.variable_storage(&mut backend)`.
- `VariableStorage::Spi(&locator)`: the optional standalone `spi-flash` adapter.
  This is not required for hosts that provide their own region/backend.

There is one `StorageBackend` contract, re-exported at the crate root. It exposes
name, exact size, program/erase granularity, current protection state and
region-relative `read`, `program`, `erase`. It has **no unlock/enable-writes or
whole-device access method**. `VariableStorage::Platform` and its builder method
are unavailable without `variable-store`, so forgetting the feature is a compile
error rather than a silent backend downgrade. Trusted platform metadata determines the region;
mutable variable contents never determine device addresses or region bounds.
Operations are bounded and checked for overflow/alignment. EDK2 variable state
updates require byte programming: a backend advertising a larger minimum must
provide a safe byte-program adapter or is rejected. Erase requests are never
rounded into adjacent firmware. A protected backend stays protected, and partial
I/O errors propagate rather than being reported as successful durable writes.
EFI callers receive `WRITE_PROTECTED` for protection failures, distinct from
`DEVICE_ERROR` for hardware I/O failures, including EDK2 callback operations.
The standalone SPI adapter retains its explicit controller policy separately.

Every region, including standalone SPI, is initialized only if its **entire
contents are erased** (`0xff`, as required by the backend's NOR-compatible erase
contract). Bounded chunk reads inspect the whole declared region; zero bytes are
not blank. Invalid non-erased headers/checksums/partial formats return
`InvalidHeader` unchanged. Read failures and protected/unknown protection states
never authorize formatting. Valid existing stores mount normally. Selecting SPI
is not permission to reset corrupted storage; there is no automatic factory
reset or destructive-format opt-in. Configured bounded-backend mount failures
stop boot rather than silently selecting volatile storage. An explicitly absent
backend (or unavailable optional standalone SPI transport) remains distinct.
This approved initialization policy does not select an OS NV persistence policy.

An fstart integration should reserve an explicit mutable FFS/image region and
exclude its contents from outer image/directory hashes, signatures and checksums.
CrabEFI does not implement that host layout. EDK2's local FV-header checksum is
retained; it is not an image signature or variable-payload authentication. All
record lengths and ranges still require validation because the bytes are mutable
and untrusted. Compaction erases/rebuilds the selected region; **no atomic or
power-fail-safe update protocol is claimed**.

## Lifetime and post-ExitBootServices policy

A borrowed platform backend is used only while `init_platform() -> !` is active
and boot services remain live. The separate image receives a boot bridge address,
not a backend trait object. Sealing clears the bridge and boot-service pointers;
the core then detaches its backend before OS ownership of boot memory. Runtime
code must never dereference a boot stack, backend vtable or reclaimed boot image.

The current runtime image has **no native persistent flash driver or SMM storage
service**. With a configured retained buffer it can queue NV writes in a CRC-bound
RAM journal for replay at a later boot. Journal format v3 binds the exact runtime
capability bits into the local header CRC. A different profile returns
`UNSUPPORTED` before changing retained bytes, staging a transaction, or invoking
a replay callback. Same-profile warm-reset replay remains supported; old wire
versions retain their explicit discard-on-preparation behavior. This capability
binding is compatibility checking, not cryptographic authentication. That is retained-memory/warm-reset staging,
not power-loss durability. `DeferredBufferConfig::disabled()` explicitly passes
zero base and size together: the loader/ABI accept absence, reserve/map nothing,
and SVAM never translates address zero. Mixed-zero, overflow, alignment and
range-overlap failures remain errors. Disabled post-EBS NV writes (including
deletion) and capsule requests return `UNSUPPORTED` before staging or variable
mutation. Existing-variable reads, volatile writes, time/reset and SVAM remain
available; active boot-time NV backends still perform real writes. Disabling the
retained journal is **not** native runtime persistence, and is independent of
Secure Boot and of fstart's final runtime-persistence policy. Full coreboot keeps
its explicit nonzero retained-buffer configuration. A host must explicitly decide
whether retained staging is acceptable or implement a genuinely runtime-safe
bounded persistent service. Selecting final fstart post-EBS persistence policy is
not implied by selecting Secure Boot or a basic feature profile.

## Toolchain and validation scope

The development validation uses the existing `nightly` compiler:
`rustc 1.100.0-nightly (e457a7b0d 2026-08-27)`, LLVM 23. This is newer than fstart's
1.95 nightly pin; compatibility with that older pin is not established. Align
source/toolchain pins deliberately rather than silently substituting compilers.
Host tests and release builds are not hardware boot tests. Report normalized,
compressed, linked-payload and complete-ROM sizes separately.

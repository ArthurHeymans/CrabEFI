# Separate Runtime Image Architecture

## Completed transition

Runtime Services run from a mandatory, separately linked `no_std` image on
x86-64, AArch64, and RV64. There is no boot-side Runtime Services fallback,
dispatch hybrid, runtime variable cache, or post-EBS boot callback.

`./crabefi build --arch <arch>` builds the image, validates its normalized
format, embeds its SHA-256-pinned bytes in the payload, and builds the payload.
The generated image is loaded into independent RuntimeServicesCode and
RuntimeServicesData allocations; the embedded payload copy is boot-only.

The normalized format has page-aligned non-overlapping load sections, explicit
Absolute64 relocation slots, zero-fill section flags, and checked export
offsets. The loader validates every range before copying, zeroes zero-fill
bytes, applies physical relocations, and performs architecture cache
synchronization. ELF normalization rejects missing, zero, or inconsistent
`DT_RELASZ`/`DT_RELACOUNT` relocation metadata.

## Ownership and lifetime

The runtime image owns all Runtime Services entry points and unsupported stubs,
Runtime/System Tables, configuration storage, Runtime Properties, Memory
Attributes Table (MAT), ESRT storage, variable metadata/payload arena,
transaction buffer, manifests, phase machine, and image-local time/reset code.
The packed variable arena is 128 KiB; its per-variable limit remains 16 KiB.
Large zero-initialized store state is in `.bss`, not ROM data.

Boot code owns drivers, persistence hardware, heap, logging, protocols, and
Boot Services. Before EBS, one typed BootActive persistence bridge may write
nonvolatile variables. It is erased during seal. A retained RuntimeServicesData
buffer holds deferred nonvolatile records and capsule staging metadata across a
warm reset; the next boot replays the journal through the temporary bridge.

The image phase sequence is:

```text
Uninitialized -> BootActive -> SealedPhysical -> Virtual
```

Initialization and import completion are one-shot. Imports after
`finish_import` are rejected. Seal clears all console, Boot Services, and
bridge pointers, recalculates table CRCs, and has a fallible client API: a seal
failure is fatal rather than silently leaving boot pointers live.

## Variables and Secure Boot policy

The image is the sole variable authority. It implements bounded create,
replace, append, delete, enumeration, and capacity queries without `alloc`.
Deletes of absent variables return `EFI_NOT_FOUND`; ordinary attribute changes
on existing variables return `EFI_INVALID_PARAMETER`; `QueryVariableInfo`
reports packed-arena capacity and validates its requested attribute class.

During BootActive, nonvolatile writes are committed to persistent storage
before their image-store commit. The EDK2 append area compacts live records
when it fills, so ordinary variable churn does not permanently exhaust the
persistent region. The one-region coreboot store cannot make that erase cycle
power-failure atomic; it rebuilds records with the standard staged EDK2
`VAR_ADDED` protocol.

After EBS, runtime-accessible nonvolatile writes are serialized into the
retained journal before the image store commits them. Replay on the next boot
persists each record exactly once and acknowledges it only after the bridge and
image-store updates succeed.

SecureBoot and SetupMode under the EFI global variable GUID are derived,
read-only status variables. PK, KEK, db, and dbx time-based authenticated
updates, appends, and deletions are verified inside the runtime image using its
authoritative key databases, replay timestamps, and bounded BSS scratch
allocator. Boot enrollment uses the same standard `SetVariable` entry point.

The split intentionally has two narrowly scoped certificate verifiers. The
runtime image uses the bounded, allocation-free, hand-rolled PKCS#7/X.509
verifier in `crabefi-runtime-image/src/auth/crypto.rs`; boot retains the
`cms`/`x509_cert`-based verifier solely for Authenticode image verification.
Both deliberately skip certificate `notBefore`/`notAfter` checks. This
preserves the pre-split `check_validity_period = false` behavior and matches
EDK2 and U-Boot Secure Boot handling, where firmware time does not gate trust
in an enrolled certificate.

The allocation-free `crabefi-efi-types` crate single-sources the EFI time
comparison, authenticated-variable and signature-list structures, and the
Secure Boot variable names and GUIDs used by boot and the runtime image. This
keeps parsing and policy identifiers identical across the image boundary.

## Virtual addressing and memory permissions

`SetVirtualAddressMap` is validate-then-commit and remains retryable after a
failed validation. It accepts legal runtime descriptors of any UEFI memory
type, rejects overlap/arithmetic errors, and requires a nonzero virtual mapping
only for image-owned sections or retained MMIO ranges it must resolve.

It resolves independent section/range deltas; converts image table pointers;
calculates Runtime Services CRCs against the final virtual function pointers;
and then publishes the virtual phase. Relocation destinations are reconstructed
from loader-exposed, range-validated firmware addresses with Rust's explicit
exposed-provenance API and are fenced before CRC calculation. Relocations to
executable code, transition atomics, the reset snapshot, and the image-local variable store are
committed in a no-inline tail after release, so physically executing code never
calls through a GOT slot that was changed to a virtual address.

The MAT contains only RuntimeServicesCode/Data entries and only UEFI permission
attributes. Code is RO/executable; writable data is XP; immutable data is
RO/XP. Runtime MMIO is retained for architecture mechanisms but is not emitted
as a MAT entry. Runtime allocation requests remain spec-legal during boot;
they are not globally frozen by image loading.

## Architecture mechanisms

- **x86-64:** consistent CMOS snapshots with checked BCD decoding and a
  platform-configured CF9-compatible reset port (i8042 fallback).
- **AArch64:** PSCI SMC/HVC reset and PL031 time when a retained MMIO range is
  supplied.
- **RV64:** SBI SRST reset and Goldfish RTC time when a retained MMIO range is
  supplied.

## Build and verification

The wrapper is required because a payload must be bound to the exact normalized
runtime artifact:

```bash
./crabefi build --arch x86-64
./crabefi build --arch aarch64 --machine sbsa
./crabefi build --arch aarch64 --machine virt
./crabefi build --arch riscv64
```

Artifacts under `target/runtime/<arch>/` include the ELF/image, map, symbols,
section and relocation manifests, digest, size report, disassembly, and stack
report. The reports are derived from the built image: undefined imports,
relocation metadata/counts, indirect-call bounds, native relocation domains,
and stack budget are enforced rather than represented by placeholder JSON.

The repository verifies ABI parsing/relocation fixtures, authenticated-variable
and deferred-journal host tests, adversarial host tests for the bounded PKCS#7
DER parser and its certificate/signer/chain limits, format/lint/check/build
coverage for all supported architectures, and QEMU boot paths including
two-boot replay and capsule consumption. The only remaining verification gap is physical-board
boot coverage (including board-specific reset, RTC, SPI compaction,
warm-reset retention, and platform MMIO wiring); no physical hardware is
available in this environment.

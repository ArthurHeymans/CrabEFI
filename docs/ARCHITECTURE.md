# Architecture

## Crates

- `crabefi-core`: boot-time UEFI implementation and hardware drivers
- `crabefi-coreboot`: coreboot payload and platform discovery
- `crabefi-efi-types`: shared, allocation-free EFI time, signature-list, and Secure Boot definitions
- `crabefi-runtime-abi`: excluded, host-testable pointer-free format/handoff ABI
- `crabefi-runtime-image`: excluded, separately linked `no_std` Runtime Services image
- `xtask`: host build, normalization, audit, ROM, and QEMU automation

The runtime image shares pointer-free handoff definitions through
`crabefi-runtime-abi` and EFI authentication definitions through
`crabefi-efi-types`. It has no dependency on `crabefi-core`, `log`, drivers, or
platform traits. Cryptographic operations use only fixed stack buffers,
not an unbounded or post-seal general-purpose heap.

## Boot flow

1. Platform code discovers memory, tables, mechanisms, devices, and variable storage.
2. The core allocator marks the entire payload and heap as BootServices memory.
3. The runtime loader validates the payload-bound digest and normalized format.
4. It allocates independent RuntimeServicesCode/Data pages, copies sections,
   applies physical relocations, and synchronizes instruction caches.
5. It initializes image state and publishes image-owned Runtime/System tables.
6. Persistent records and firmware-created boot values are imported directly into the image store before untrusted boot applications run.
7. Boot applications run using the image's Runtime Services table.
8. EBS cleans up boot state and seals the image last.
9. Image-local SVAM validates and physically commits per-section virtual mappings.

## Runtime ownership

All 14 Runtime Services table slots point into the runtime image. Unsupported
services are image-local stubs. The image owns all mutable post-EBS state,
configuration survivor storage, operation synchronization, CRC/panic support,
variables and value-only platform mechanisms.

Boot Secure Boot databases are disposable verification snapshots rebuilt from
image variables. They are not a variable authority and are unreachable after
EBS. EFI time comparison, signature-list structures, and Secure Boot variable
names/GUIDs are single-sourced in `crabefi-efi-types` on both sides of the image
boundary.

Certificate verification shares one allocation-free implementation,
`crabefi-pkcs7`: DER, X.509 and PKCS#7 `SignedData` views plus RSA PKCS#1 v1.5
SHA-256 verification with stack-backed schoolbook Montgomery exponentiation
(worst runtime frame ~4 KiB against the 16 KiB link-time stack budget). Each
side keeps its own policy on top: the runtime image's authenticated-variable
policy lives in `crabefi-runtime-image/src/auth/crypto.rs`, and boot's chain
building, revocation and Authenticode policy in `efi::auth`. Signed-data
hashing is incremental, so the runtime image requires no global allocator.
Neither path enforces certificate `notBefore`/`notAfter` for Secure Boot,
preserving the old `check_validity_period = false` policy and matching EDK2 and
U-Boot.

See [Separate Runtime Image Architecture](RUNTIME_IMAGE_PLAN.md) for detailed
invariants and current mechanism limitations.

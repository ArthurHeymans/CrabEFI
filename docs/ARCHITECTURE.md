# Architecture

## Crates

- `crabefi-core`: boot-time, platform-independent UEFI implementation
- `crabefi-coreboot`: coreboot payload and platform discovery
- `crabefi-drivers`: reusable boot-time drivers
- `crabefi-efi-types`: shared, allocation-free EFI time, signature-list, and Secure Boot definitions
- `crabefi-runtime-abi`: excluded, host-testable pointer-free format/handoff ABI
- `crabefi-runtime-image`: excluded, separately linked `no_std` Runtime Services image
- `xtask`: host build, normalization, audit, ROM, and QEMU automation

The runtime image shares pointer-free handoff definitions through
`crabefi-runtime-abi` and EFI authentication definitions through
`crabefi-efi-types`. It has no dependency on `crabefi-core`, `log`, drivers, or
platform traits. Cryptographic operations use only the bounded image-local BSS
scratch arena, not an unbounded or post-seal general-purpose heap.

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

Certificate verification remains intentionally split by execution domain. The
runtime image's authenticated-variable path uses a hand-rolled PKCS#7/X.509
parser and allocator-aware `crypto-bigint` RSA exponentiation whose temporaries
are lifetime-scoped to the bounded image-local BSS scratch arena. Signed-data
hashing is incremental, so the runtime image requires no global allocator;
boot uses `cms`/`x509_cert` only for Authenticode. Neither path enforces certificate `notBefore`/`notAfter`,
preserving the old `check_validity_period = false` policy and matching EDK2 and
U-Boot.

See [Separate Runtime Image Architecture](RUNTIME_IMAGE_PLAN.md) for detailed
invariants and current mechanism limitations.

# Architecture

## Crates

- `crabefi-core`: boot-time, platform-independent UEFI implementation
- `crabefi-coreboot`: coreboot payload and platform discovery
- `crabefi-drivers`: reusable boot-time drivers
- `crabefi-runtime-abi`: excluded, host-testable pointer-free format/handoff ABI
- `crabefi-runtime-image`: excluded, separately linked `no_std` Runtime Services image
- `xtask`: host build, normalization, audit, ROM, and QEMU automation

The runtime image depends only on `core`, compiler builtins, and the ABI crate.
It has no dependency on `crabefi-core`, `alloc`, `log`, drivers, platform traits,
or a global allocator.

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
EBS.

See [Separate Runtime Image Architecture](RUNTIME_IMAGE_PLAN.md) for detailed
invariants and current mechanism limitations.

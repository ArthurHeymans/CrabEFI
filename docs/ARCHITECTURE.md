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

## Cooperative firmware tasks

`crabefi-core/src/exec.rs` implements cooperative polling without interrupts
or wakers. Idle menu loops and EFI event/input polls give background tasks a
turn. A hardware wait yields between polls; controller borrows never cross
an await. The same USB port tasks drive boot discovery and hotplug, including
ports behind external hubs. Individual control and bulk transfers still use
synchronous controller waits. At OS handoff, polling stops without freeing
pending tasks or changing the accepted EFI memory map.

## Boot filesystems

`BlockRange` gives the filesystem reader byte access bounded to its partition.
Boot discovery, the BLS/GRUB readers, and direct Linux loading use the small
read-only `BootFilesystem` interface: size, offset reads and bounded directory
listings. FAT borrows a storage device for the operation. `ext4-view` owns its
reader, so its adapter retains a storage ID and borrows the device per read.
A future layer such as LUKS would supply decrypted bytes below the filesystem,
not add operations to `BootFilesystem`.

The experimental x86-64 `ext4` feature is opt-in and intended for trusted
fixed disks. After FAT and El Torito discovery, it scans ext2/3/4 partitions
for BLS entries. BLS can use `/loader/entries` on a separate boot partition
or `/boot/loader/entries` on an ext root; the latter resolves kernel and
initrd paths relative to `/boot`. GRUB config discovery remains FAT-only.
Direct boot remains disabled under Secure Boot.

Ext discovery caps I/O and directory iteration, and rejects volumes that
need journal replay or exceed its block-size or block-group limits. These
checks do not put a hard heap limit on every allocation in `ext4-view`.

EFI Simple File System stays FAT-only. If ext volumes are later exposed to EFI
applications, give each volume handle its own mount context and share the read
operations without emulating writes. Keep FAT's allocation state, flush/error
handling, and file-record identity out of the common read interface.

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

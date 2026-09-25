# Platform compatibility

This page lists what the repository's QEMU CI actually exercises on each
platform, and the known limits of the implementation. A row means the listed
paths run in CI; it is not a claim of support for other machines or boards.
Every platform uses CrabEFI as a coreboot payload with the separate, bundled
runtime image. The base firmware images are described in
[firmware/README.md](../firmware/README.md).

| Platform / machine | Firmware | Storage in CI | Other QEMU CI coverage | RTC |
| --- | --- | --- | --- | --- |
| x86_64 / Q35 | coreboot | USB, AHCI, NVMe, SD | GRUB + Linux, runtime image, image exit, RNG, protocol notify, capsule update, TCG with swtpm | CMOS |
| AArch64 / SBSA | TF-A + coreboot | NVMe | GRUB + Linux, RNG | None |
| AArch64 / virt | coreboot | NVMe | None | None |
| RISC-V / virt | coreboot with OpenSBI | USB | GRUB + Linux | None |

"None" in the RTC column means the coreboot payload configures no time
source: boot-time certificate code has no clock, and `GetTime()` returns an
error. The runtime image can read PL031 and Goldfish RTCs, but the payload
does not describe one yet.

Secure Boot has no QEMU CI coverage on any platform. Signature and
certificate-chain verification, revocation and the enrollment timestamp are
covered only by host unit tests of `crabefi-core` with the `secure-boot`
feature.

## Authentication and time

- Secure Boot image verification does not enforce certificate
  `notBefore`/`notAfter`, matching EDK2 and U-Boot. Validity checks that are
  requested elsewhere fail when no current time is available; CrabEFI does not
  substitute a date.
- Key databases enrolled by the firmware itself get the RTC time, but never
  less than 2025-01-01. This timestamp is the floor that later authenticated
  writes must exceed, so enrollment works without an RTC.
- The RTC is not authenticated. Anything that can set it can move the clock
  used for these checks.
- Revocation is checked only against CRLs already in the in-memory cache.
  The boot path does not load any, so revocation checks currently soft-fail.
  CRL distribution points are logged for diagnostics only, as there is no
  network stack.

## Not supported

- USB hotplug; restart after attaching a device
- USB alternate interface settings other than the default
- xHCI interrupt queues
- SMBus/I²C-only touchpads
- IDE/ATA
- OCSP
- Power-loss-safe variable-store compaction

Runtime NV writes through the deferred buffer are warm-reset staging, not a
power-loss durability guarantee. See [capabilities](capabilities.md) for the
variable-store and runtime-image contracts.

## Hardware qualification

QEMU coverage does not establish physical-board support. Board-specific reset,
RTC, SPI flash geometry/protection, interrupt wiring, retained MMIO, and
memory-map behavior still require hardware validation before deployment.

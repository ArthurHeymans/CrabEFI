# CrabEFI Documentation

CrabEFI is a UEFI implementation written in Rust. It has a platform-agnostic
boot library, reusable hardware drivers, coreboot payloads for x86-64,
AArch64, and RV64, and a separately linked Runtime Services image with bounded
scratch allocation used on every architecture.

## Contents

- [Building](BUILDING.md) — build and test commands
- [Architecture](ARCHITECTURE.md) — workspace and component organization
- [Integration](INTEGRATION.md) — embedding the boot library and mandatory runtime image
- [Memory Management](MEMORY.md) — boot/runtime ownership and EFI memory map
- [Separate Runtime Image Architecture](RUNTIME_IMAGE_PLAN.md) — implemented runtime boundary, loader, SVAM transaction, and current platform limitations

Use `./crabefi build --arch <arch>` rather than invoking the payload package
directly: the wrapper builds, audits, normalizes, and binds the matching runtime
artifact before compiling the payload. Direct payload Cargo commands intentionally
require `RUNTIME_IMAGE_PATH` and `RUNTIME_IMAGE_SHA256` from that wrapper.

The remaining verification work is physical-board coverage for board-specific
reset, RTC, SPI compaction, and retained-MMIO wiring; no hardware is available
in this environment.

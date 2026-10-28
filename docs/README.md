# CrabEFI Documentation

CrabEFI is a UEFI implementation written in Rust. It has a platform-agnostic
boot library, reusable hardware drivers, coreboot payloads for x86-64,
AArch64, and RV64, and a separately linked Runtime Services image with bounded
scratch allocation used on every architecture.

## Contents

- [Building](BUILDING.md) — build and test commands
- [Architecture](ARCHITECTURE.md) — workspace and component organization
- [Integration](INTEGRATION.md) — embedding the boot library and mandatory runtime image
- [x86 Entry ABIs](X86_ENTRY_ABI.md) — default coreboot entry and opt-in entry64 for u-root
- [Memory Management](MEMORY.md) — boot/runtime ownership and EFI memory map
- [Separate Runtime Image Architecture](RUNTIME_IMAGE_PLAN.md) — implemented runtime boundary, loader, SVAM transaction, and current platform limitations
- [Platform Compatibility](COMPATIBILITY.md) — QEMU CI coverage per platform, time/authentication policy, and known limitations

Use `./crabefi build --arch <arch>` to build, audit, normalize and bind a fresh
Runtime Services image. Direct payload Cargo builds instead use the checked-in
runtime bundle by default. On x86, both commands retain coreboot's 32-bit entry
unless `--entry64` (wrapper) or `--features entry64` (Cargo) is explicitly selected
for u-root/LinuxBoot. See [Building](BUILDING.md) for output paths.

The remaining verification work is physical-board coverage for board-specific
reset, RTC, SPI compaction, and retained-MMIO wiring; no hardware is available
in this environment.

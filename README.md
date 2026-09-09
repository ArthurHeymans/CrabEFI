# CrabEFI

A UEFI implementation written in Rust, designed as a reusable library with dependency injection for platform-specific hardware.

CrabEFI implements enough UEFI to boot Linux via shim/GRUB2 or systemd-boot on real hardware. It ships as a coreboot payload, a platform-agnostic boot library, and a separately linked Runtime Services image with bounded scratch allocation.

![CrabEFI graphical boot menu](docs/screenshot.jpg)

*Graphical boot menu (`--features ui`), captured headlessly with
`./crabefi screenshot --app hello --out screenshot.png`. The command writes PPM
directly or converts to PNG with ImageMagick; the referenced JPG was produced
from that PNG with ImageMagick.*

## Documentation

See the [docs/](docs/README.md) directory:

- [Building](docs/BUILDING.md) - How to build CrabEFI and run tests
- [Architecture](docs/ARCHITECTURE.md) - Workspace layout and code organization
- [Integration](docs/INTEGRATION.md) - Using CrabEFI as a library in external firmware
- [Capabilities](docs/capabilities.md) - Minimal/full feature sets, runtime identity and bounded variable storage
- [Memory Management](docs/MEMORY.md) - Memory layout, allocators, and EFI memory map

## Quick Start

```bash
# Enter nix development environment (provides QEMU, mtools, etc.)
nix develop

# Build the coreboot payload
./crabefi build

# Run integration tests
./crabefi test --app hello

# Run interactively in QEMU
./crabefi run --app hello

# Build for aarch64
./crabefi build --arch aarch64
```

## USB and pointing devices

Connect USB boot drives and input devices **before starting CrabEFI**. USB
hotplug/rescanning is not currently supported; restart after attaching a device.
Native 4K logical sectors are supported, including GPT-partitioned USB storage.
Hybrid ISO partitions must start and end on native logical-block boundaries;
unaligned or out-of-device GPT ranges are rejected instead of rounded.

USB configuration descriptors are bounded to 4 KiB, eight active interfaces,
and four endpoints per interface. Alternate setting zero is used; CrabEFI does
not activate other settings. SuperSpeed HID bursts and extended service payloads
are explicitly unsupported rather than configured as single-packet endpoints.

USB input uses HID boot-protocol keyboards and mice. The built-in PS/2 driver
supports standard relative mice and Synaptics touchpads with PS/2 compatibility;
SMBus/I²C-only touchpads and replacement trackpads using other protocols are not
supported. `--features ui` enables the graphical menu, not additional touchpad
protocols. When reporting a non-working replacement trackpad, include its model,
Linux input-device identification, and CrabEFI's PS/2/USB initialization logs.

## Workspace Structure

| Crate | Description |
|-------|-------------|
| `crabefi-core` | Core library -- UEFI implementation and boot-time hardware drivers |
| `crabefi-coreboot` | Coreboot payload binary (arch entry points, table parsing) |
| `crabefi-runtime-abi` | Pointer-free normalized image/handoff ABI |
| `crabefi-runtime-image` | Separate EFI Runtime Services image with image-local bounded scratch allocation |

External firmware implements boot-only platform traits, provides a normalized runtime image plus value-only runtime mechanisms in `PlatformConfig`, and calls `crabefi::init_platform()`. See [docs/INTEGRATION.md](docs/INTEGRATION.md) for details.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.

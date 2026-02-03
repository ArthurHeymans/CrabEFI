# CrabEFI

A minimal UEFI implementation written in Rust, designed to run as a coreboot payload.

## Documentation

For detailed documentation, see the [docs/](docs/README.md) directory:

- [Building](docs/BUILDING.md) - How to build CrabEFI and run tests
- [Architecture](docs/ARCHITECTURE.md) - Repository layout and code organization
- [Memory Management](docs/MEMORY.md) - Memory layout, allocators, and EFI memory map

## Goals

CrabEFI implements just enough UEFI to boot Linux via shim/GRUB2 or systemd-boot on real hardware. It is not intended to be a full UEFI implementation. 
Maybe booting windows is also a possibility.

### Planned Features

- **Secure Boot** - Signature verification for bootloaders and kernels
- **Variable Store** - Persistent EFI variables for saving boot menu entries and configuration

## Building

```bash
cargo build --release
```

The output ELF is at `target/x86_64-unknown-none/release/crabefi.elf`, ready to be used as a coreboot payload.

## Testing

Use the `./crabefi` tool for building, testing, and running in QEMU:

```bash
# Enter nix development environment (provides QEMU, mtools, etc.)
nix develop

# Build CrabEFI
./crabefi build

# Run integration tests
./crabefi test --app hello

# Run interactively in QEMU
./crabefi run --app hello

# See all commands
./crabefi --help
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.

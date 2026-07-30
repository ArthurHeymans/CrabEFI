# CrabEFI Documentation

CrabEFI is a UEFI implementation written in Rust. It is structured as a platform-agnostic library with dependency injection, shipping with a coreboot payload binary and standard hardware drivers.

## Contents

- [Building](BUILDING.md) - How to build CrabEFI and run tests
- [Architecture](ARCHITECTURE.md) - Workspace layout and code organization
- [Integration](INTEGRATION.md) - Using CrabEFI as a library in external firmware
- [Memory Management](MEMORY.md) - Memory layout, allocators, and EFI memory map
- [SetVirtualAddressMap](SVAM.md) - Runtime relocation design and comparison with EDK2

# CrabEFI Architecture

This document describes the repository layout, code organization, and key architectural decisions in CrabEFI.

## Repository Layout

```
CrabEFI/
├── src/                    # Main firmware source code
│   ├── arch/               # Architecture-specific (x86_64 entry, paging, IDT)
│   ├── coreboot/           # Coreboot table parsing, memory map, FMAP
│   ├── drivers/            # Hardware drivers (PCI, NVMe, AHCI, USB, SDHCI, SPI)
│   ├── efi/                # UEFI implementation
│   │   ├── protocols/      # Protocol implementations (console, GOP, filesystem, etc.)
│   │   ├── auth/           # Secure Boot (signature verification, key management)
│   │   └── varstore/       # Variable storage and SPI persistence
│   ├── fs/                 # Filesystem support (GPT, FAT, ISO9660)
│   ├── pe/                 # PE/COFF image loader
│   ├── linux_boot/         # Direct Linux kernel boot
│   ├── bls/                # Boot Loader Specification entry parsing
│   └── payload/            # Coreboot payload chainloading
├── test-apps/              # EFI test applications (hello, storage-test, etc.)
├── xtask/                  # Build automation tool (./crabefi command)
├── firmware/               # Prebuilt coreboot ROM for QEMU testing
├── docs/                   # Documentation
├── x86_64-coreboot.ld      # Linker script defining memory layout
├── Cargo.toml              # Crate manifest
└── AGENTS.md               # Development guidelines
```

## Key Components

### Firmware State (`state.rs`)

CrabEFI uses a centralized state management approach. Instead of scattered `static Mutex<T>` variables, all mutable firmware state is consolidated into a single `FirmwareState` struct allocated on the stack in the entry point.

```
FirmwareState
├── efi: EfiState
│   ├── handles[]           # Handle database
│   ├── events[]            # Event tracking
│   ├── loaded_images[]     # Loaded PE images
│   ├── config_tables[]     # Configuration tables (ACPI, SMBIOS)
│   ├── variables[]         # EFI variables
│   └── allocator           # Memory allocator state
├── drivers: DriverState
│   ├── pci_devices[]       # Discovered PCI devices
│   ├── keyboard            # Keyboard state
│   ├── framebuffer         # Display info
│   └── storage             # SPI flash backend
└── console: ConsoleState
    ├── cursor_pos          # Text cursor position
    └── input               # Input state/escape sequences
```

### Entry Flow

1. **32-bit Entry** (`entry.rs`): Coreboot calls the payload in 32-bit protected mode
2. **64-bit Transition**: Set up page tables, enable long mode, switch to 64-bit
3. **Rust Entry** (`main.rs`): Call `rust_main()` which calls `lib::init()`
4. **Initialization** (`lib.rs::init()`):
   - Parse coreboot tables
   - Initialize serial logging
   - Set up paging and IDT
   - Initialize EFI environment
   - Initialize storage drivers
5. **Boot Menu**: Discover boot entries, display menu, boot selected entry

### UEFI Implementation

CrabEFI implements the following UEFI services:

**Boot Services:**
- Memory allocation (`AllocatePages`, `FreePages`, `AllocatePool`, `FreePool`)
- Handle/Protocol management (`InstallProtocol`, `OpenProtocol`, `LocateHandle`)
- Image loading (`LoadImage`, `StartImage`, `UnloadImage`)
- Event services (`CreateEvent`, `SetTimer`, `WaitForEvent`)
- Memory map (`GetMemoryMap`, `ExitBootServices`)

**Runtime Services:**
- Variable access (`GetVariable`, `SetVariable`, `GetNextVariableName`)
- Time services (`GetTime`, `SetTime`)
- Reset (`ResetSystem`)

**Protocols:**
- `SimpleTextInput` / `SimpleTextOutput` - Console I/O
- `GraphicsOutput` - GOP for framebuffer access
- `SimpleFileSystem` / `FileProtocol` - FAT filesystem access
- `BlockIO` - Raw block device access
- `LoadedImage` - Image information
- `DevicePath` - Device identification

### Storage Stack

```
Application (GRUB, systemd-boot, etc.)
        │
        ▼
   BlockIO Protocol
        │
        ▼
  Storage Abstraction (storage.rs)
        │
        ├──► NVMe Driver
        ├──► AHCI Driver
        ├──► USB Mass Storage
        └──► SDHCI Driver
        │
        ▼
   PCI Enumeration
```

### Secure Boot

The Secure Boot implementation follows the UEFI specification:

```
Image Load Request
        │
        ▼
  Is Secure Boot Enabled?
        │
    No ─┴─ Yes
    │      │
    │      ▼
    │  Verify Authenticode Signature
    │      │
    │      ▼
    │  Check against db (allowed)
    │      │
    │      ▼
    │  Check against dbx (revoked)
    │      │
    │      ▼
    │  Valid? ─── No ──► Reject
    │      │
    │     Yes
    │      │
    └──────┴──► Load Image
```

Key variables:
- **PK** (Platform Key): Controls KEK modifications
- **KEK** (Key Exchange Key): Controls db/dbx modifications
- **db** (Signature Database): Allowed signatures
- **dbx** (Forbidden Signatures): Revoked hashes/certificates

### Variable Storage

Variables are stored in SPI flash using coreboot's SMMSTORE region:

```
SPI Flash
├── SMMSTORE Region (from FMAP)
│   ├── Header (magic, version)
│   └── Variable Records[]
│       ├── GUID
│       ├── Name (UTF-16)
│       ├── Attributes
│       ├── Data Size
│       └── Data
└── Other Regions (BIOS, ME, etc.)
```

Runtime variable writes (after `ExitBootServices`) are deferred to a reserved memory buffer and applied on the next boot.

## Build System

CrabEFI uses a custom build tool (`./crabefi`) implemented in `xtask/`:

- `./crabefi build` - Build the firmware
- `./crabefi test --app <name>` - Run integration tests
- `./crabefi run --app <name>` - Interactive QEMU session
- `./crabefi create-disk` - Create bootable disk images

The tool handles:
- Decompressing the base coreboot ROM
- Adding CrabEFI as a CBFS payload
- Creating FAT disk images with test applications
- Launching QEMU with appropriate arguments

## Dependencies

Key Rust crates used:

| Crate | Purpose |
|-------|---------|
| `r-efi` | UEFI type definitions and GUIDs |
| `heapless` | Stack-allocated collections |
| `spin` | Spinlock for synchronization |
| `log` | Logging facade |
| `sha2`, `rsa`, `x509-cert` | Cryptography for Secure Boot |
| `zerocopy` | Safe transmutation for hardware structures |

## Coding Conventions

See [AGENTS.md](../AGENTS.md) for detailed coding guidelines including:

- Import organization
- Documentation requirements
- Error handling patterns
- UEFI protocol implementation patterns
- Naming conventions

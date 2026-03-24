# CrabEFI Architecture

## Workspace Layout

CrabEFI is structured as a Cargo workspace with three crates:

```
CrabEFI/
├── Cargo.toml                  # Workspace root + core library manifest
├── src/                        # Core library source
│   ├── platform.rs             # Platform abstraction traits (public API)
│   ├── lib.rs                  # Library entry points (init, init_platform)
│   ├── state.rs                # Centralized FirmwareState
│   ├── heap.rs                 # Bump allocator (opt-in #[global_allocator])
│   ├── efi/                    # UEFI implementation
│   │   ├── boot_services.rs    # EFI_BOOT_SERVICES
│   │   ├── runtime_services.rs # EFI_RUNTIME_SERVICES
│   │   ├── system_table.rs     # EFI_SYSTEM_TABLE
│   │   ├── allocator.rs        # Page-granular memory allocator
│   │   ├── protocols/          # Protocol implementations (20 files)
│   │   ├── auth/               # Secure Boot (authenticode, x509, key mgmt)
│   │   └── varstore/           # Variable persistence
│   │       ├── edk2.rs         # EDK2 Firmware Volume format parser
│   │       ├── edk2_backend.rs # Edk2VarStore (VariableBackend for raw flash)
│   │       ├── persistence.rs  # Legacy SPI persistence layer
│   │       ├── deferred.rs     # Warm-reboot deferred write buffer
│   │       └── storage.rs      # SpiStorageBackend
│   ├── drivers/                # Hardware drivers (will move to crabefi-drivers)
│   │   ├── block.rs            # BlockDevice trait + implementations
│   │   ├── storage.rs          # StorageRegistry
│   │   ├── pci/                # PCI enumeration + driver model
│   │   ├── nvme/               # NVMe controller driver
│   │   ├── ahci/               # AHCI/SATA driver
│   │   ├── usb/                # USB host controllers + device classes
│   │   ├── sdhci/              # SD Host Controller driver
│   │   ├── spi/                # SPI flash (Intel, AMD, QEMU)
│   │   ├── serial.rs           # 16550 UART + PL011
│   │   └── keyboard.rs         # PS/2 keyboard
│   ├── arch/                   # Architecture-specific code
│   │   ├── x86_64/             # Entry, IDT, port I/O, cache, reset, RNG
│   │   └── aarch64/            # Entry, exceptions, cache, reset, RNG
│   ├── coreboot/               # Coreboot table parsing
│   ├── fs/                     # FAT, GPT, ISO9660
│   ├── pe/                     # PE/COFF image loader
│   ├── boot.rs                 # Boot manager
│   ├── menu.rs                 # Interactive boot menu
│   └── ...
│
├── crabefi-coreboot/           # Coreboot payload binary
│   ├── Cargo.toml
│   ├── build.rs                # Linker script selection, PAYLOAD_BASE
│   └── src/main.rs             # rust_main, #[panic_handler]
│
├── crabefi-drivers/            # Standard hardware drivers (placeholder)
│   ├── Cargo.toml
│   └── src/lib.rs
│
├── test-apps/                  # EFI test applications (separate workspaces)
│   ├── hello/
│   ├── rng-test/
│   ├── directory-test/
│   ├── secure-boot-test/
│   ├── storage-security-test/
│   └── fw-dump/
│
├── xtask/                      # Build automation (separate workspace)
├── firmware/                   # Pre-built coreboot ROMs for QEMU
├── x86_64-coreboot.ld          # x86_64 linker script
├── aarch64-coreboot.ld         # aarch64 linker script
└── docs/                       # Documentation
```

## Platform Abstraction Layer

The core library defines platform traits in `src/platform.rs`. External firmware implements these traits and passes them to CrabEFI via `PlatformConfig`:

```
┌─────────────────────────────────────────────┐
│           External Firmware                  │
│  (coreboot, custom SoC firmware, ...)        │
│                                              │
│  Implements: BlockDevice, VariableBackend,   │
│  Timer, ResetHandler, DebugOutput, ...       │
└───────────────┬─────────────────────────────┘
                │  PlatformConfig
                ▼
┌─────────────────────────────────────────────┐
│           CrabEFI Library                    │
│                                              │
│  UEFI Boot/Runtime Services, Secure Boot,   │
│  Boot Manager, Filesystem, PE Loader         │
└─────────────────────────────────────────────┘
```

### Platform Traits

| Trait | Purpose | Required |
|-------|---------|----------|
| `BlockDevice` | Block-level storage I/O | At least one for booting |
| `VariableBackend` | Persistent EFI variables | No (volatile fallback) |
| `StorageBackend` | Raw byte-level flash | No (used by `Edk2VarStore`) |
| `Timer` | Monotonic clock | Yes |
| `ResetHandler` | System reset/shutdown | Yes |
| `Rng` | Hardware RNG | No |
| `DebugOutput` | Serial/log output | No |
| `ConsoleInput` | Keyboard input | No |

See [Integration](INTEGRATION.md) for how to implement these traits.

## Firmware State (`state.rs`)

All mutable firmware state lives in a single `FirmwareState` struct allocated on the stack in the entry point:

```
FirmwareState
├── efi: EfiState
│   ├── handles[]           # Handle database (max 64)
│   ├── events[]            # Event tracking (max 32)
│   ├── loaded_images[]     # Loaded PE images (max 16)
│   ├── config_tables[]     # ACPI, SMBIOS, FDT, etc. (max 24)
│   ├── variables[]         # In-memory variable cache (max 64)
│   └── allocator           # Page-granular memory allocator
├── drivers: DriverState
│   ├── pci                 # PCI device list + access method
│   ├── serial              # Serial port driver + EFI mode
│   ├── timing              # Counter frequency + boot timestamp
│   ├── platform            # Framebuffer, SPI, SMMSTORE info
│   └── storage_registry    # Block device registry
└── console: ConsoleState
    ├── cursor_pos          # Text cursor position
    └── input               # Escape sequence parser
```

## Boot Flow

### Coreboot Target

1. **Architecture entry** (assembly): 32-to-64 mode switch (x86) or MMU setup (aarch64)
2. **`rust_main()`** (`crabefi-coreboot/src/main.rs`): calls `crabefi::init()`
3. **`init()`** (`src/lib.rs`):
   - Parse coreboot tables (memory map, serial, framebuffer, SMMSTORE)
   - Initialize serial, logging, keyboard, timing
   - Initialize EFI (allocator, system table, services, protocols)
   - Initialize heap, PCI, variable persistence, Secure Boot
   - Run boot manager (BootNext -> BootOrder -> fallback -> interactive menu)

### Library Target (External Firmware)

1. External firmware initializes hardware, discovers devices
2. Builds `PlatformConfig` with trait object references
3. Calls `crabefi::init_platform(config)` — never returns (`-> !`)
4. CrabEFI runs the UEFI boot manager using the provided services
5. On successful OS handoff, `ExitBootServices` is called and CrabEFI halts
6. If no bootable media is found or all boot attempts fail, CrabEFI halts the CPU

## Variable Persistence

CrabEFI supports three variable backend strategies:

| Strategy | Trait | `runtime_capable()` | Post-EBS Writes |
|----------|-------|---------------------|-----------------|
| Direct flash | `Edk2VarStore` wrapping `StorageBackend` | `false` | Deferred buffer, committed next boot |
| SMM | Custom `VariableBackend` | `true` | Direct via SMI |
| TF-A MM | Custom `VariableBackend` | `true` | Direct via FF-A/SPM |

The `VariableBackend` trait operates at variable level (`load`/`write`/`delete`), not raw bytes, so SMM and TF-A MM backends can issue RPCs to the privileged agent without CrabEFI knowing the storage format.

## UEFI Implementation

### Boot Services

Memory allocation, handle/protocol management, image loading, event services, memory map, `ExitBootServices`.

### Runtime Services

Variable access (`GetVariable`, `SetVariable`, `GetNextVariableName`), time services, `ResetSystem`, `SetVirtualAddressMap`.

### Protocols

| Protocol | Description |
|----------|-------------|
| `SimpleTextInput` / `SimpleTextOutput` | Console I/O |
| `SimpleTextInputEx` | Extended keyboard (modifier keys) |
| `GraphicsOutput` | GOP framebuffer |
| `SimpleFileSystem` / `FileProtocol` | FAT filesystem access |
| `BlockIO` / `DiskIO` | Block and byte-level disk I/O |
| `LoadedImage` | Image information |
| `DevicePath` | Device identification |
| `RNG` | Random number generation |
| `SerialIO` | Serial port access |
| `UnicodeCollation` | String comparison |
| `ConsoleControl` | Console mode switching |
| `MemoryAttribute` | Page permission control |
| `NvmePassThru` / `AtaPassThru` / `ScsiPassThru` | Storage passthrough |
| `StorageSecurity` | TCG Opal |

## Storage Stack

```
Application (GRUB, systemd-boot, etc.)
        │
        ▼
   BlockIO Protocol
        │
        ▼
  dyn BlockDevice (platform-provided)
        │
        ├── NVMe Driver
        ├── AHCI Driver
        ├── USB Mass Storage
        ├── SDHCI Driver
        └── Custom (external firmware)
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `r-efi` | UEFI type definitions and GUIDs |
| `heapless` | Stack-allocated collections (`no_std`) |
| `spin` | Spinlock for global controller arrays |
| `log` | Logging facade |
| `tock-registers` | Type-safe MMIO register access |
| `zerocopy` | Safe transmutation for hardware structures |
| `sha2`, `rsa`, `x509-cert`, `cms` | Secure Boot cryptography |
| `serde`, `postcard` | Deferred variable serialization |

## Coding Conventions

See [AGENTS.md](../AGENTS.md) for coding guidelines.

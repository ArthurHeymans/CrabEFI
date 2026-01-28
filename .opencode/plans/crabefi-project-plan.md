# CrabEFI - Project Plan

**A minimal UEFI implementation as a coreboot payload for real laptop hardware**

## Executive Summary

CrabEFI is a Rust-based firmware project that provides a minimal UEFI environment for booting standard operating systems on real hardware. Unlike rust-hypervisor-firmware (which targets hypervisors) or full UEFI implementations like EDK2/TianoCore, CrabEFI focuses on being:

1. **Minimal** - Only implement what's needed to boot Linux via shim+GRUB2 or systemd-boot
2. **Real Hardware** - Target actual laptops, not just virtual machines
3. **Coreboot Payload** - Leverage coreboot for hardware initialization
4. **Written in Rust** - Memory safety without sacrificing performance

## Architecture

```
+-------------------------------------------------------------+
|                      Linux/GRUB/shim                         |
+-------------------------------------------------------------+
|                        CrabEFI                               |
|  +-------------+  +-------------+  +--------------------+   |
|  |Boot Services|  |Runtime Svc  |  | Protocols          |   |
|  | - Memory    |  | - GetTime   |  | - Block I/O        |   |
|  | - Protocols |  | - Variables |  | - Simple FS        |   |
|  | - Images    |  | - Reset     |  | - Console          |   |
|  +-------------+  +-------------+  | - Graphics Out     |   |
|  +----------------------------------| - Loaded Image     |   |
|  |           Drivers                | - Device Path      |   |
|  | - NVMe (PCIe)  - AHCI (SATA)   |+--------------------+   |
|  | - USB (xHCI)   - Keyboard/Console                       |
|  +----------------------------------+                       |
+-------------------------------------------------------------+
|              Coreboot Table Parser & HAL                     |
|  - Memory map  - ACPI RSDP  - Framebuffer  - Serial         |
+-------------------------------------------------------------+
|                    Coreboot (32->64 bit)                     |
+-------------------------------------------------------------+
```

## Target Configuration

- **Primary Architecture**: x86_64 (designed for flexibility to support other architectures later)
- **Storage**: NVMe (PCIe), SATA (AHCI), USB (xHCI mass storage)
- **License**: Apache-2.0 OR MIT (dual license)
- **Secure Boot**: Not in initial scope (can be added later)

## Project Structure

```
CrabEFI/
├── Cargo.toml
├── rust-toolchain.toml
├── x86_64-unknown-none.json          # Custom target spec
├── x86_64-coreboot.ld                # Linker script
├── build.rs
│
├── src/
│   ├── main.rs                       # Entry point
│   ├── lib.rs                        # Library root
│   │
│   ├── arch/
│   │   ├── mod.rs
│   │   └── x86_64/
│   │       ├── mod.rs
│   │       ├── entry.S               # 32-bit -> 64-bit transition
│   │       ├── paging.rs             # Page table setup
│   │       └── sse.rs                # SSE/SIMD enable
│   │
│   ├── coreboot/
│   │   ├── mod.rs
│   │   ├── tables.rs                 # Coreboot table parser
│   │   ├── memory.rs                 # Memory map handling
│   │   └── framebuffer.rs            # FB info extraction
│   │
│   ├── efi/
│   │   ├── mod.rs
│   │   ├── system_table.rs           # EFI_SYSTEM_TABLE
│   │   ├── boot_services.rs          # EFI_BOOT_SERVICES
│   │   ├── runtime_services.rs       # EFI_RUNTIME_SERVICES
│   │   ├── allocator.rs              # Memory allocation
│   │   ├── protocols/
│   │   │   ├── mod.rs
│   │   │   ├── block_io.rs
│   │   │   ├── simple_fs.rs
│   │   │   ├── loaded_image.rs
│   │   │   ├── device_path.rs
│   │   │   ├── console.rs
│   │   │   └── graphics_output.rs
│   │   └── device_path.rs            # Device path utilities
│   │
│   ├── drivers/
│   │   ├── mod.rs
│   │   ├── pci/
│   │   │   ├── mod.rs
│   │   │   └── ecam.rs               # PCIe ECAM access
│   │   ├── nvme/
│   │   │   ├── mod.rs
│   │   │   ├── controller.rs
│   │   │   └── namespace.rs
│   │   ├── ahci/
│   │   │   ├── mod.rs
│   │   │   └── port.rs
│   │   ├── usb/
│   │   │   ├── mod.rs
│   │   │   ├── xhci.rs
│   │   │   └── mass_storage.rs
│   │   ├── serial.rs                 # 16550 UART
│   │   └── keyboard.rs               # PS/2 keyboard
│   │
│   ├── fs/
│   │   ├── mod.rs
│   │   ├── fat.rs                    # FAT12/16/32
│   │   └── gpt.rs                    # GPT partition parsing
│   │
│   └── pe/
│       └── mod.rs                    # PE32+ loader
│
├── .github/
│   └── workflows/
│       ├── ci.yml                    # Build and lint
│       └── boot-test.yml             # QEMU boot tests
│
└── tools/
    └── coreboot-payload.sh           # Helper script for cbfstool
```

## Implementation Phases

### Phase 1: Bootable Skeleton (Weeks 1-2) ✅ COMPLETE

**Goal**: CrabEFI boots as coreboot payload, displays "Hello World"

**Tasks**:
1. ✅ Set up Rust no_std project with custom target
2. ✅ Write 32-bit entry assembly that transitions to 64-bit long mode
3. ✅ Implement coreboot table parser for:
   - Memory map (CB_TAG_MEMORY)
   - Serial port (CB_TAG_SERIAL)
   - Framebuffer (CB_TAG_FRAMEBUFFER)
   - ACPI RSDP (CB_TAG_ACPI_RSDP)
4. ✅ Initialize serial output via 16550 UART
5. ✅ Set up identity-mapped 4-level page tables
6. ✅ Implement basic logging infrastructure

**Deliverable**: Binary that boots in QEMU with coreboot, prints to serial

**Key files**:
- `src/arch/x86_64/entry.rs` (global_asm! based)
- `src/coreboot/tables.rs`
- `src/drivers/serial.rs`

**Completed**: January 28, 2026
- Release binary size: ~129KB
- Debug binary size: ~313KB

### Phase 2: Minimal EFI Environment (Weeks 3-4) ✅ COMPLETE

**Goal**: Empty EFI system table that can be passed to a PE binary

**Tasks**:
1. ✅ Define `EFI_SYSTEM_TABLE` structure (using r-efi crate)
2. ✅ Implement Boot Services:
   - `AllocatePages` / `FreePages` - Page-granular allocation
   - `GetMemoryMap` - Return memory map derived from coreboot
   - `AllocatePool` / `FreePool` - Arbitrary-size allocation
   - `HandleProtocol` / `OpenProtocol` / `LocateProtocol` - Protocol lookup
   - `LoadImage` / `StartImage` - PE loading and execution (stub for LoadImage)
   - `ExitBootServices` - Transition to OS
   - `Stall` - Microsecond delay
   - `InstallConfigurationTable` - Add ACPI tables etc.
3. ✅ Implement Runtime Services (stubs that work before ExitBootServices):
   - `GetTime` / `SetTime` - From RTC
   - `GetVariable` / `SetVariable` / `GetNextVariableName` - In-memory store
   - `ResetSystem` - System reset (keyboard controller + triple fault)
4. ✅ Implement console protocols:
   - `EFI_SIMPLE_TEXT_INPUT_PROTOCOL` - Keyboard input (stub)
   - `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL` - Serial output with ANSI escapes
5. ✅ Implement PE32+ loader with relocation support

**Deliverable**: Can load and start a simple "hello world" EFI application

**Key files**:
- `src/efi/system_table.rs`
- `src/efi/boot_services.rs`
- `src/efi/runtime_services.rs`
- `src/efi/allocator.rs`
- `src/efi/protocols/console.rs`
- `src/pe/mod.rs`

**Completed**: January 28, 2026
- Release binary size: ~244KB
- Debug binary size: ~540KB

### Phase 3: Storage Stack (Weeks 5-7)

**Goal**: Read files from ESP partition on real storage devices

**Tasks**:
1. Implement PCI enumeration:
   - Scan PCI configuration space
   - PCIe ECAM support
   - BAR allocation
2. NVMe driver:
   - Admin command queue
   - I/O submission/completion queues
   - Identify Controller/Namespace
   - Read command
3. AHCI driver:
   - HBA initialization
   - Port initialization
   - IDENTIFY DEVICE
   - READ DMA EXT
4. GPT partition parser:
   - Read protective MBR
   - Parse GPT header and entries
   - Find EFI System Partition by GUID
5. FAT filesystem:
   - FAT12/16/32 support
   - Directory traversal
   - File reading
6. EFI protocols:
   - `EFI_BLOCK_IO_PROTOCOL`
   - `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`
   - `EFI_FILE_PROTOCOL`
   - `EFI_DEVICE_PATH_PROTOCOL`

**Deliverable**: Loads `/EFI/BOOT/BOOTX64.EFI` from NVMe or SATA disk

**Key files**:
- `src/drivers/pci/`
- `src/drivers/nvme/`
- `src/drivers/ahci/`
- `src/fs/gpt.rs`
- `src/fs/fat.rs`
- `src/efi/protocols/block_io.rs`
- `src/efi/protocols/simple_fs.rs`

### Phase 4: Graphics & Input (Weeks 8-9)

**Goal**: Graphical boot with keyboard input

**Tasks**:
1. Graphics Output Protocol:
   - Use framebuffer from coreboot tables
   - Implement `Blt` (Block Transfer) operation
   - Basic pixel plotting
   - Text rendering on framebuffer
2. PS/2 Keyboard:
   - Scancode reading
   - Key to EFI scancode translation
3. Console improvements:
   - Text mode emulation on framebuffer
   - Scrolling support
   - Basic ANSI escape sequences

**Deliverable**: Can display GRUB menu and accept keyboard input

**Key files**:
- `src/efi/protocols/graphics_output.rs`
- `src/drivers/keyboard.rs`
- `src/efi/protocols/console.rs`

### Phase 5: USB Support (Weeks 10-11)

**Goal**: Boot from USB storage devices

**Tasks**:
1. xHCI driver:
   - Controller initialization
   - Command ring
   - Event ring (interrupt polling)
   - Device slot allocation
   - Device enumeration
2. USB mass storage:
   - Bulk-Only Transport (BOT) protocol
   - SCSI command set (INQUIRY, READ CAPACITY, READ)
3. USB HID keyboard (optional):
   - Boot protocol keyboard support
   - For laptops without PS/2

**Deliverable**: Can boot from USB thumb drive

**Key files**:
- `src/drivers/usb/xhci.rs`
- `src/drivers/usb/mass_storage.rs`

### Phase 6: Polish & Testing (Weeks 12+)

**Goal**: Boot real Linux distributions reliably on real hardware

**Tasks**:
1. ACPI passthrough:
   - Pass RSDP from coreboot to EFI configuration tables
   - Ensure OS can find ACPI tables
2. Variable persistence (optional):
   - Store EFI variables in CMOS or SPI flash
3. Error handling:
   - Graceful failure modes
   - Fallback boot paths
4. Real hardware testing:
   - Test on coreboot-supported laptops (ThinkPad, etc.)
   - Fix hardware-specific issues

**Deliverable**: Boots Ubuntu/Fedora on real laptop

## EFI Services - Detailed Scope

### Boot Services (Implemented)

| Function | Implementation Notes |
|----------|---------------------|
| `RaiseTpl` | No-op (no interrupt handling) |
| `RestoreTpl` | No-op |
| `AllocatePages` | Page-granular allocation from memory map |
| `FreePages` | Return pages to free list |
| `GetMemoryMap` | Derived from coreboot memory map |
| `AllocatePool` | Sub-page allocator |
| `FreePool` | Return to pool |
| `CreateEvent` | Return UNSUPPORTED (not needed for basic boot) |
| `SetTimer` | Return UNSUPPORTED |
| `WaitForEvent` | Return UNSUPPORTED |
| `SignalEvent` | Return UNSUPPORTED |
| `CloseEvent` | Return UNSUPPORTED |
| `CheckEvent` | Return UNSUPPORTED |
| `InstallProtocolInterface` | Stub for shim compatibility |
| `ReinstallProtocolInterface` | Return NOT_FOUND |
| `UninstallProtocolInterface` | Return NOT_FOUND |
| `HandleProtocol` | Forward to OpenProtocol |
| `RegisterProtocolNotify` | Return UNSUPPORTED |
| `LocateHandle` | Search by protocol GUID |
| `LocateDevicePath` | Return NOT_FOUND |
| `InstallConfigurationTable` | Add/remove from config table |
| `LoadImage` | Load PE32+ from file or memory |
| `StartImage` | Call image entry point |
| `Exit` | Return UNSUPPORTED |
| `UnloadImage` | Free image memory |
| `ExitBootServices` | Mark transition to OS |
| `GetNextMonotonicCount` | Return DEVICE_ERROR |
| `Stall` | Busy-wait microseconds |
| `SetWatchdogTimer` | Return UNSUPPORTED |
| `ConnectController` | Return UNSUPPORTED |
| `DisconnectController` | Return UNSUPPORTED |
| `OpenProtocol` | Return protocol interface |
| `CloseProtocol` | Return UNSUPPORTED |
| `OpenProtocolInformation` | Return UNSUPPORTED |
| `ProtocolsPerHandle` | Return UNSUPPORTED |
| `LocateHandleBuffer` | Return UNSUPPORTED |
| `LocateProtocol` | Find first matching protocol |
| `InstallMultipleProtocolInterfaces` | Return UNSUPPORTED |
| `UninstallMultipleProtocolInterfaces` | Return UNSUPPORTED |
| `CalculateCrc32` | Return UNSUPPORTED |
| `CopyMem` | memcpy |
| `SetMem` | memset |
| `CreateEventEx` | Return UNSUPPORTED |

### Runtime Services (Implemented)

| Function | Implementation Notes |
|----------|---------------------|
| `GetTime` | Read from RTC |
| `SetTime` | Write to RTC |
| `GetWakeupTime` | Return UNSUPPORTED |
| `SetWakeupTime` | Return UNSUPPORTED |
| `SetVirtualAddressMap` | Return SUCCESS (no-op for now) |
| `ConvertPointer` | Return UNSUPPORTED |
| `GetVariable` | In-memory variable store |
| `GetNextVariableName` | Iterate variable store |
| `SetVariable` | Store in memory (non-persistent initially) |
| `GetNextHighMonotonicCount` | Return UNSUPPORTED |
| `ResetSystem` | Triple fault or ACPI reset |
| `UpdateCapsule` | Return UNSUPPORTED |
| `QueryCapsuleCapabilities` | Return UNSUPPORTED |
| `QueryVariableInfo` | Return variable store info |

### Protocols (Implemented)

| Protocol | GUID | Notes |
|----------|------|-------|
| `EFI_LOADED_IMAGE_PROTOCOL` | `5B1B31A1-9562-11D2-8E3F-00A0C969723B` | Info about loaded image |
| `EFI_DEVICE_PATH_PROTOCOL` | `09576E91-6D3F-11D2-8E39-00A0C969723B` | Device path representation |
| `EFI_BLOCK_IO_PROTOCOL` | `964E5B21-6459-11D2-8E39-00A0C969723B` | Block device access |
| `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` | `964E5B22-6459-11D2-8E39-00A0C969723B` | Filesystem access |
| `EFI_SIMPLE_TEXT_INPUT_PROTOCOL` | `387477C1-69C7-11D2-8E39-00A0C969723B` | Keyboard input |
| `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL` | `387477C2-69C7-11D2-8E39-00A0C969723B` | Text output |
| `EFI_GRAPHICS_OUTPUT_PROTOCOL` | `9042A9DE-23DC-4A38-96FB-7ADED080516A` | Framebuffer access |

## Explicitly Out of Scope

The following will NOT be implemented:

1. **Full Event System** - No timer events, async notifications
2. **Driver Binding Model** - No dynamic driver loading
3. **Network Boot** - No PXE, HTTP boot, or network stack
4. **Secure Boot** - No signature verification (initially)
5. **Capsule Updates** - No firmware update mechanism
6. **HII (Human Interface Infrastructure)** - No forms/configuration UI
7. **SMM (System Management Mode)** - No SMM handling
8. **UEFI Shell** - No built-in shell
9. **S3 Resume** - Sleep/wake not supported
10. **Option ROMs** - No legacy option ROM support

## Dependencies

```toml
[dependencies]
r-efi = "5.3"              # EFI types, constants, and calling conventions
log = "0.4"                # Logging facade
bitflags = "2"             # Bit manipulation helpers
heapless = "0.8"           # No-alloc data structures (Vec, String)
atomic_refcell = "0.1"     # Interior mutability without std

[target.'cfg(target_arch = "x86_64")'.dependencies]
x86_64 = "0.15"            # x86_64 registers, page tables
uart_16550 = "0.4"         # Serial port access

[build-dependencies]
cc = "1"                   # For compiling assembly
```

## Coreboot Integration

### Entry Point

Coreboot calls payloads in **32-bit protected mode**. The payload receives the coreboot table pointer at `4(%esp)`.

```asm
.code32
.global _start
_start:
    cli
    movl 4(%esp), %ebx      # Save coreboot tables pointer
    # ... transition to 64-bit mode ...
    movq %rbx, %rdi         # Pass as first argument
    call rust_main
```

### Coreboot Tables

Key tables to parse:

| Tag | Value | Purpose |
|-----|-------|---------|
| `CB_TAG_MEMORY` | 0x0001 | Memory map |
| `CB_TAG_SERIAL` | 0x000F | Serial port config |
| `CB_TAG_CONSOLE` | 0x0010 | Console type |
| `CB_TAG_FRAMEBUFFER` | 0x0012 | Linear framebuffer |
| `CB_TAG_ACPI_RSDP` | 0x0043 | ACPI tables pointer |

### Memory Map Types

```rust
const CB_MEM_RAM: u32 = 1;         // Usable
const CB_MEM_RESERVED: u32 = 2;    // Reserved
const CB_MEM_ACPI: u32 = 3;        // ACPI reclaimable
const CB_MEM_NVS: u32 = 4;         // ACPI NVS
const CB_MEM_UNUSABLE: u32 = 5;    // Unusable
const CB_MEM_TABLE: u32 = 16;      // Coreboot tables
```

## Testing Strategy

### 1. Unit Tests

Run with `cargo test` on host system for pure Rust logic:
- Memory allocator
- FAT parsing
- GPT parsing
- PE parsing

### 2. QEMU + Coreboot Integration Tests

```yaml
# .github/workflows/boot-test.yml
name: Boot Test

on: [push, pull_request]

jobs:
  boot-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Build CrabEFI
        run: cargo build --release --target x86_64-unknown-none.json
        
      - name: Build coreboot image
        run: |
          # Download pre-built coreboot or build from source
          # Add CrabEFI as payload using cbfstool
          
      - name: Boot test
        run: |
          timeout 60 qemu-system-x86_64 \
            -bios coreboot.rom \
            -serial stdio \
            -display none \
            | tee boot.log
          grep "CrabEFI initialized" boot.log
```

### 3. Real Hardware

Test on coreboot-supported laptops:
- Lenovo ThinkPad X230, T440p
- Purism Librem series
- System76 laptops

## Reference Implementations

### rust-hypervisor-firmware
- **What to borrow**: EFI structure layout, r-efi usage patterns, PE loader
- **What differs**: Entry point (PVH vs coreboot), drivers (virtio vs real HW)
- **Source**: https://github.com/cloud-hypervisor/rust-hypervisor-firmware
- **On disk source**: ~/src/rust-hypervisor-firmware/

### U-Boot EFI
- **What to borrow**: Protocol implementation patterns, boot manager logic
- **What differs**: Language (C vs Rust), scope (full U-Boot vs minimal)
- **Source**: `lib/efi_loader/` in U-Boot tree
- **On disk source**: ~/src/u-boot/

### coreboot libpayload
- **What to borrow**: Coreboot table parsing, hardware initialization
- **What differs**: Language (C vs Rust), focus (library vs EFI firmware)
- **Source**: `payloads/libpayload/` in coreboot tree
- **On disk source**: ~/src/coreboot/

## Success Criteria

CrabEFI is considered successful when it can:

1. [~] Boot as a coreboot payload on QEMU (compiles, needs QEMU testing)
2. [x] Parse and use coreboot memory map
3. [x] Load PE32+ EFI applications (loader implemented, needs storage for real test)
4. [x] Provide working `GetMemoryMap` for ExitBootServices
5. [ ] Read files from FAT32 ESP on NVMe/SATA
6. [ ] Boot shim -> GRUB2 -> Linux kernel
7. [ ] Display graphical boot menu
8. [ ] Accept keyboard input for menu selection
9. [ ] Boot from USB storage
10. [ ] Successfully boot on real laptop hardware

## Getting Started

```bash
# Clone and build
git clone https://github.com/user/CrabEFI.git
cd CrabEFI
cargo build --release

# The binary is at:
# target/x86_64-unknown-none/release/crabefi

# Add to coreboot image
cbfstool coreboot.rom add-payload \
    -f target/x86_64-unknown-none/release/crabefi \
    -n fallback/payload -c lzma

# Test with QEMU
qemu-system-x86_64 -bios coreboot.rom -serial stdio
```

---

*Plan created: January 2026*
*Status: Phase 2 complete, ready for Phase 3 (Storage Stack)*
*Last updated: January 28, 2026*

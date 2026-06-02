# Integrating CrabEFI into External Firmware

This guide explains how to use CrabEFI as a library in firmware other than coreboot.

## Overview

CrabEFI's core is a platform-agnostic UEFI implementation. Your firmware provides hardware-specific services via trait implementations, packs them into a `PlatformConfig`, and calls `crabefi::init_platform()`.

```rust
// Your firmware's main function
fn firmware_main() -> ! {
    // 1. Initialize your hardware
    let mut emmc = MyEmmcDriver::new(EMMC_BASE);
    let timer = MyTimer::new();

    // 2. Build PlatformConfig
    let config = crabefi::PlatformConfig {
        memory_map: &MY_MEMORY_MAP,
        timer: &timer,
        reset: &MyReset,
        block_devices: &mut [&mut emmc as &mut dyn crabefi::BlockDevice],
        variable_backend: None,       // direct VariableBackend routing is not wired yet
        variable_store_locator: None, // variables are volatile without a locator
        debug_output: None,
        console_input: None,
        framebuffer: None,
        acpi_rsdp: None,
        smbios: None,
        fdt: None,
        rng: None,
        deferred_buffer: None,
        runtime_region: None,
    };

    // 3. Hand off to CrabEFI — never returns (-> !)
    crabefi::init_platform(config);
}
```

## Cargo Setup

Add CrabEFI as a dependency in your firmware crate:

```toml
[dependencies]
crabefi = { git = "https://github.com/user/CrabEFI", features = ["global-allocator"] }
```

Omit `global-allocator` if your firmware provides its own `#[global_allocator]`. CrabEFI requires the `alloc` crate for Secure Boot cryptography.

Your firmware must provide:
- `#[panic_handler]`
- `#[global_allocator]` (either CrabEFI's via the feature, or your own)

Build for a bare-metal target (`*-unknown-none`) with `build-std`:

```toml
# .cargo/config.toml
[unstable]
build-std = ["core", "compiler_builtins", "alloc"]
build-std-features = ["compiler-builtins-mem"]
```

## Platform Traits

### BlockDevice (Required for Booting)

Implement this for each storage device CrabEFI should boot from:

```rust
use crabefi::{BlockDevice, BlockDeviceInfo, BlockError};

struct MyEmmc { base_addr: u64, sectors: u64 }

impl BlockDevice for MyEmmc {
    fn info(&self) -> BlockDeviceInfo {
        BlockDeviceInfo {
            num_blocks: self.sectors,
            block_size: 512,
            media_id: 0,
            removable: false,
            read_only: false,
        }
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8])
        -> Result<(), BlockError>
    {
        self.validate_read(lba, count, buffer)?;
        // ... your hardware read ...
        Ok(())
    }

    fn name(&self) -> &str { "eMMC" }
}
```

CrabEFI installs an `EFI_BLOCK_IO_PROTOCOL` handle for each device, discovers GPT partitions and ESP filesystems, and makes them available to UEFI applications.

### Timer (Required)

```rust
use crabefi::Timer;

struct ArmGenericTimer { freq: u64 }

impl Timer for ArmGenericTimer {
    fn current_ticks(&self) -> u64 {
        // Read CNTPCT_EL0
        let val: u64;
        unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) val); }
        val
    }

    fn ticks_per_second(&self) -> u64 { self.freq }

    // Default stall() implementation uses current_ticks + spin loop.
    // Override if your platform has a better mechanism.
}
```

### ResetHandler (Required)

Must not return. Used by `ResetSystem` runtime service.

```rust
use crabefi::{ResetHandler, ResetType};

struct PsciReset;

impl ResetHandler for PsciReset {
    fn reset(&self, reset_type: ResetType) -> ! {
        match reset_type {
            ResetType::Shutdown => psci_system_off(),
            _ => psci_system_reset(),
        }
    }
}
```

The `ResetHandler` implementation must reside in memory marked as runtime-safe, since `ResetSystem` is a UEFI runtime service.

### Variable Persistence (Optional)

Without a platform-provided persistence path, EFI variables work in-memory but
are lost on reset. The direct `VariableBackend` field is API scaffolding for
future SMM/TF-A MM-style routing and is not currently connected by
`init_platform()`.

#### Option A: Raw Flash via Edk2VarStore

If you have byte-level access to a NOR flash or similar:

```rust
use crabefi::{StorageBackend, StorageError};

struct MyFlash { /* ... */ }

impl StorageBackend for MyFlash {
    fn name(&self) -> &str { "SPI Flash" }
    fn size(&self) -> u32 { 256 * 1024 }
    fn is_write_protected(&self) -> bool { false }
    fn enable_writes(&mut self) -> Result<(), StorageError> { Ok(()) }
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), StorageError> { /* ... */ Ok(()) }
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError> { /* ... */ Ok(()) }
    fn erase(&mut self, offset: u32, size: u32) -> Result<(), StorageError> { /* ... */ Ok(()) }
}
```

Then wrap it with `Edk2VarStore`:

```rust
let mut flash = MyFlash::new();
let mut var_store = crabefi::efi::varstore::Edk2VarStore::new(&mut flash);

// NOTE: Edk2VarStore implements the future VariableBackend API, but
// init_platform() does not route variable_backend yet.
let config = crabefi::PlatformConfig {
    variable_backend: None,
    variable_store_locator: None,
    // For post-ExitBootServices writes (flash locked), provide a deferred buffer:
    deferred_buffer: Some(crabefi::DeferredBufferConfig {
        base: 0x8_0000,    // Must survive warm reboot
        size: 64 * 1024,
    }),
    ..
};
```

#### Option B: SMM Backend

If your platform has an SMM handler that manages variables:

```rust
use crabefi::{VariableBackend, VariableVisitor, VarBackendError};
use r_efi::efi::Guid;

struct SmmVarStore { smi_port: u16 }

impl VariableBackend for SmmVarStore {
    fn load(&mut self, visitor: &mut dyn VariableVisitor) -> Result<(), VarBackendError> {
        // Trigger SMI to enumerate variables, call visitor.visit() for each
        Ok(())
    }

    fn write(&mut self, name: &[u16], vendor: &Guid, attrs: u32, data: &[u8])
        -> Result<(), VarBackendError>
    {
        // Trigger SMI with SetVariable command
        Ok(())
    }

    fn delete(&mut self, name: &[u16], vendor: &Guid) -> Result<(), VarBackendError> {
        // Trigger SMI with delete command
        Ok(())
    }

    fn runtime_capable(&self) -> bool { true }  // SMM can write after ExitBootServices
}
```

When direct `VariableBackend` routing is implemented, no deferred buffer will be needed for runtime-capable SMM backends.

#### Option C: TF-A MM (StandaloneMM)

Future direct `VariableBackend` routing is expected to use the same pattern as SMM, with FF-A or SVC calls to communicate with the secure partition:

```rust
struct MmVarStore { /* FF-A comm buffer */ }

impl VariableBackend for MmVarStore {
    fn load(&mut self, visitor: &mut dyn VariableVisitor) -> Result<(), VarBackendError> {
        // MM_COMMUNICATE to StandaloneMM
        Ok(())
    }
    fn write(&mut self, name: &[u16], vendor: &Guid, attrs: u32, data: &[u8])
        -> Result<(), VarBackendError>
    {
        // MM_COMMUNICATE with write command
        Ok(())
    }
    fn delete(&mut self, name: &[u16], vendor: &Guid) -> Result<(), VarBackendError> {
        // MM_COMMUNICATE with delete command
        Ok(())
    }
    fn runtime_capable(&self) -> bool { true }
}
```

### Other Optional Traits

**DebugOutput** -- Serial or equivalent for log output and `EFI_SERIAL_IO_PROTOCOL`:

```rust
impl crabefi::DebugOutput for MyUart {
    fn write_byte(&mut self, byte: u8) { /* ... */ }
    fn try_read_byte(&self) -> Option<u8> { /* ... */ None }
    fn has_input(&self) -> bool { false }
}
// Also implement core::fmt::Write
```

**ConsoleInput** -- Keyboard for the boot menu and `SimpleTextInput`:

```rust
impl crabefi::ConsoleInput for MyKeyboard {
    fn read_key(&mut self) -> Option<crabefi::Key> { /* ... */ None }
    fn has_key(&self) -> bool { false }
    fn poll(&mut self) { /* e.g., poll USB controllers */ }
}
```

**Rng** -- Hardware RNG for `EFI_RNG_PROTOCOL`:

```rust
impl crabefi::Rng for HwRng {
    fn get_random(&self, buf: &mut [u8]) -> Result<(), crabefi::RngError> { /* ... */ Ok(()) }
}
```

## Memory Map

Provide a `&[MemoryRegion]` describing the physical address space:

```rust
use crabefi::{MemoryRegion, MemoryType};

static MEMORY_MAP: &[MemoryRegion] = &[
    MemoryRegion { base: 0x0000_0000, size: 0x0010_0000, region_type: MemoryType::Reserved },
    MemoryRegion { base: 0x0010_0000, size: 0x3FF0_0000, region_type: MemoryType::Ram },
    MemoryRegion { base: 0x4000_0000, size: 0x0100_0000, region_type: MemoryType::Mmio },
    // ...
];
```

## Framebuffer

If your platform has a framebuffer for the GOP protocol and boot menu:

```rust
let fb = crabefi::FramebufferConfig {
    physical_address: 0xFD00_0000,
    width: 1920,
    height: 1080,
    stride: 1920 * 4,  // bytes per scanline
    bits_per_pixel: 32,
    red_mask_pos: 16, red_mask_size: 8,
    green_mask_pos: 8, green_mask_size: 8,
    blue_mask_pos: 0, blue_mask_size: 8,
};
```

## Runtime Services

For runtime services to work after `ExitBootServices`:

1. Set `runtime_region` in `PlatformConfig` so CrabEFI marks its code/data as `RuntimeServicesCode`/`RuntimeServicesData`.
2. The `ResetHandler` implementation and its vtable must be in runtime-safe memory.
3. If using a non-runtime-capable `VariableBackend`, provide a `deferred_buffer` in memory that survives warm reboot.

## Using crabefi-drivers

The `crabefi-drivers` crate provides standard hardware drivers that implement the platform traits. If your platform has standard PCI hardware, you can use these instead of writing your own:

```toml
[dependencies]
crabefi = { git = "..." }
crabefi-drivers = { git = "..." }
```

The drivers crate provides implementations for NVMe, AHCI, USB, SDHCI, SPI flash, 16550 UART, PL011, and PS/2 keyboard (migration from the core library is in progress).

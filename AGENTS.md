# CrabEFI Agent Guidelines

CrabEFI is a minimal UEFI implementation written in Rust, designed to run as a coreboot payload. It boots Linux via shim/GRUB2 or systemd-boot on real hardware.

## Build Commands

```bash
# Build (release is the default/required mode for firmware)
cargo build --release

# The output ELF is at: target/x86_64-unknown-none/release/crabefi.elf

# Clean build
cargo clean && cargo build --release

# Check without building
cargo check

# Format code
cargo fmt

# Lint (note: many warnings are expected in firmware code)
cargo clippy
```

## Testing

There are no unit tests - this is firmware that must be tested in QEMU or on real hardware.

```bash
# 1. Copy the built ELF to coreboot payload directory
cp target/x86_64-unknown-none/release/crabefi.elf ~/src/coreboot/payloads/external/crabefi/

# 2. Build coreboot (from coreboot directory)
cd ~/src/coreboot && make -j$(nproc)

# 3. Run in QEMU with USB storage
./scripts/run-qemu-usb.sh ~/src/coreboot/build/coreboot.rom [disk.img]

# Or with a Fedora ISO:
qemu-system-x86_64 -machine q35 \
  -bios ~/src/coreboot/build/coreboot.rom \
  -m 512M -serial stdio \
  -device qemu-xhci,id=xhci \
  -drive file=~/Downloads/Fedora.iso,if=none,id=usbdisk,format=raw \
  -device usb-storage,drive=usbdisk,bus=xhci.0 \
  -enable-kvm -cpu host
```

## Project Structure

```
src/
  lib.rs           # Main entry, init, boot logic
  main.rs          # Binary entry point (calls lib::init)
  arch/x86_64/     # x86_64-specific: entry, paging, SSE
  coreboot/        # Coreboot table parsing, memory map
  drivers/         # Hardware drivers (PCI, NVMe, AHCI, USB/xHCI, serial)
  efi/             # UEFI implementation
    allocator.rs   # Page/pool allocator
    boot_services.rs   # EFI Boot Services
    runtime_services.rs
    system_table.rs
    protocols/     # UEFI protocols (console, loaded_image, simple_file_system)
  fs/              # Filesystems (GPT, FAT12/16/32)
  pe/              # PE/COFF loader for EFI applications
  logger.rs        # Serial logging
```

## Code Style

### Imports
- Group imports: `std`/`core` first, then external crates, then local modules
- Use explicit imports, avoid glob imports except for preludes
- Prefer `use crate::module::Type` over relative paths in nested modules

```rust
use core::ffi::c_void;
use r_efi::efi::{Guid, Handle, Status};
use spin::Mutex;

use crate::efi::allocator::{allocate_pool, MemoryType};
```

### Module Documentation
Every module must have a doc comment explaining its purpose:

```rust
//! EFI Memory Allocator
//!
//! This module implements page-granular memory allocation compatible with the
//! EFI AllocatePages/FreePages API.
```

### Function Documentation
Public functions need doc comments with `# Arguments`, `# Returns`, and `# Safety` (for unsafe):

```rust
/// Create a new Loaded Image Protocol instance
///
/// # Arguments
/// * `parent_handle` - Handle of the image that loaded this image
/// * `image_base` - Base address where the image is loaded
///
/// # Returns
/// A pointer to the LoadedImageProtocol, or null on failure
```

### Types and Structs
- Use `#[repr(C, packed)]` for hardware/protocol structures
- Derive `Clone, Copy, Debug` where appropriate
- Use `const fn` for compile-time initialization

```rust
#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct GptHeader {
    pub signature: u64,
    pub revision: u32,
    // ...
}
```

### Error Handling
- Define domain-specific error enums for each module
- Use `Result<T, ErrorType>` for fallible operations
- Use `r_efi::efi::Status` for UEFI protocol functions

```rust
#[derive(Debug)]
pub enum FatError {
    InvalidBpb,
    ReadError,
    NotFound,
    NotAFile,
}
```

### Logging
Use the `log` crate macros. Levels:
- `log::error!` - Unrecoverable errors
- `log::warn!` - Recoverable issues
- `log::info!` - Important milestones
- `log::debug!` - Detailed debugging (protocol calls, state changes)
- `log::trace!` - Very verbose (every function entry)

```rust
log::info!("FAT filesystem mounted on ESP");
log::debug!("BS.OpenProtocol(handle={:?}, protocol={})", handle, guid_name);
```

### Unsafe Code
- Minimize unsafe blocks to the smallest scope possible
- Document why the unsafe code is sound
- Use `unsafe impl Send` with a safety comment

```rust
// Safety: ProtocolEntry contains raw pointers but we only access them
// while holding the HANDLES lock, ensuring thread safety.
unsafe impl Send for ProtocolEntry {}
```

### Global State
- Use `spin::Mutex<T>` for mutable global state
- Use `static mut` only when absolutely necessary (e.g., UEFI tables)
- Use `const { ... }` for array initialization in statics

```rust
static HANDLES: Mutex<[HandleEntry; MAX_HANDLES]> =
    Mutex::new([const { HandleEntry::empty() }; MAX_HANDLES]);
```

### UEFI Protocol Implementation
- Match r-efi protocol signatures exactly
- Use `extern "efiapi"` calling convention
- Return `Status::SUCCESS` or appropriate error status

```rust
extern "efiapi" fn sfs_open_volume(
    _this: *mut efi_sfs::Protocol,
    root: *mut *mut efi_file::Protocol,
) -> Status {
    // Implementation...
    Status::SUCCESS
}
```

### Naming Conventions
- Types: `PascalCase` (e.g., `FatFilesystem`, `GptHeader`)
- Functions: `snake_case` (e.g., `read_sector`, `find_esp`)
- Constants: `SCREAMING_SNAKE_CASE` (e.g., `PAGE_SIZE`, `GPT_SIGNATURE`)
- UEFI GUIDs: `PROTOCOL_NAME_GUID` (e.g., `SIMPLE_FILE_SYSTEM_GUID`)

### Feature Flags
The project uses nightly Rust features:
- `#![feature(abi_x86_interrupt)]` - For interrupt handlers
- `#![no_std]` - No standard library (firmware environment)

### Common Patterns

**Allocating protocol structures:**
```rust
let ptr = match allocate_pool(MemoryType::BootServicesData, size) {
    Ok(p) => p as *mut Protocol,
    Err(_) => return core::ptr::null_mut(),
};
```

**Installing protocols on handles:**
```rust
let handle = boot_services::create_handle().ok_or(Status::OUT_OF_RESOURCES)?;
boot_services::install_protocol(handle, &PROTOCOL_GUID, protocol_ptr);
```

**Reading from disk:**
```rust
impl SectorRead for MyDisk {
    fn read_sector(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), GptError> {
        // Implementation
    }
}
```

## Reference Implementations
- U-Boot EFI loader: `~/src/u-boot/lib/efi_loader/`
- coreboot libpayload: `~/src/coreboot/payloads/libpayload/`
- rust-hypervisor-firmware: `~/src/rust-hypervisor-firmware`
- EDK2: `~/src/edk2/` 

//! Hardware Drivers for CrabEFI
//!
//! This module contains drivers for hardware devices needed to boot.
//!
//! # Driver Model
//!
//! PCI-based drivers implement the `pci::driver::PciDriver` trait with lifecycle
//! methods (`probe`, `init`, `shutdown`). During PCI enumeration, the driver
//! registry automatically binds matching drivers to discovered devices.
//!
//! Platform drivers (serial, keyboard, SPI) are initialized directly from
//! hardware info provided by coreboot tables.
//!
//! # Storage Abstraction
//!
//! All storage drivers provide:
//! - `init_device(&PciDevice)` — Initialize from a discovered PCI device
//! - `shutdown()` — Clean shutdown for OS handoff
//! - `BlockDevice` trait implementation for unified I/O
//!
//! The `block` module provides the `BlockDevice` trait and `AnyBlockDevice`
//! enum for type-safe dispatch across storage types.

pub mod ahci;

// ---------------------------------------------------------------------------
// Generic Controller Registry
// ---------------------------------------------------------------------------

use spin::Mutex;

/// Send-able wrapper for a raw controller pointer.
///
/// # Safety
///
/// The wrapped pointer must remain valid for the firmware lifetime.
/// All access must be serialized through the parent `ControllerRegistry` mutex.
/// CrabEFI is single-threaded, so this is trivially satisfied.
struct ControllerPtr<T>(*mut T);

// SAFETY: CrabEFI is single-threaded firmware. Controller pointers are allocated
// via the EFI page allocator and remain valid for the firmware's lifetime. All
// access is serialized through the ControllerRegistry's Mutex.
//
// The blanket impl (not bounded on `T: Send`) is intentional: controller types
// like NvmeController contain raw pointers (making them `!Send` by default),
// but in this single-threaded firmware context sharing across "threads" cannot
// occur. The ControllerPtr wrapper is module-private, limiting the scope.
unsafe impl<T> Send for ControllerPtr<T> {}

/// Generic registry for PCI-based hardware controllers.
///
/// Encapsulates the common pattern of:
/// 1. Allocating controller structs via the EFI page allocator
/// 2. Storing pointers in a `Mutex<heapless::Vec>`
/// 3. Looking up controllers by index
///
/// This eliminates ~100 lines of near-identical boilerplate per driver
/// (NVMe, AHCI, SDHCI all previously had their own copy).
pub struct ControllerRegistry<T, const N: usize> {
    controllers: Mutex<heapless::Vec<ControllerPtr<T>, N>>,
    name: &'static str,
}

impl<T, const N: usize> ControllerRegistry<T, N> {
    /// Create a new empty registry.
    pub const fn new(name: &'static str) -> Self {
        Self {
            controllers: Mutex::new(heapless::Vec::new()),
            name,
        }
    }

    /// Register a newly-initialized controller.
    ///
    /// Allocates EFI pages for the controller struct, moves it there, and
    /// stores the pointer. Returns `Err(())` on allocation failure or if
    /// the registry is full.
    pub fn register(&self, controller: T) -> Result<(), ()> {
        let size = core::mem::size_of::<T>();
        let pages = size.div_ceil(4096);
        log::debug!(
            "{}: Allocating {} pages ({} bytes) for controller",
            self.name,
            pages,
            size
        );

        let mem = crate::efi::allocate_pages(pages as u64).ok_or_else(|| {
            log::error!("{}: Failed to allocate memory for controller", self.name);
        })?;

        let controller_box = mem.as_mut_ptr() as *mut T;
        // Safety: we just allocated `pages` pages (>= size_of::<T>() bytes),
        // so `controller_box` is valid, aligned, and non-overlapping.
        unsafe {
            core::ptr::write(controller_box, controller);
        }

        let mut controllers = self.controllers.lock();
        if controllers.push(ControllerPtr(controller_box)).is_err() {
            log::warn!("{}: controller list full — freeing allocation", self.name);
            // Note: the `T` value written via ptr::write is not dropped here. This
            // is acceptable because current controller types do not implement Drop.
            // If T ever gains Drop glue, this path must call ptr::drop_in_place first.
            crate::efi::free_pages(mem, pages as u64);
            return Err(());
        }

        Ok(())
    }

    /// Get a raw pointer to a controller by index.
    ///
    /// The returned pointer is valid for the firmware lifetime. Callers must
    /// convert to `&mut` only for the duration of their immediate operation
    /// and must not hold the reference across calls that may also access
    /// the same controller.
    pub fn get(&self, index: usize) -> Option<*mut T> {
        let controllers = self.controllers.lock();
        controllers.get(index).map(|ptr| ptr.0)
    }

    /// Number of registered controllers.
    pub fn count(&self) -> usize {
        self.controllers.lock().len()
    }

    /// Log the controller count during shutdown / handoff.
    pub fn shutdown_log(&self) {
        let controllers = self.controllers.lock();
        if !controllers.is_empty() {
            log::info!(
                "{}: {} controllers ready for OS handoff",
                self.name,
                controllers.len()
            );
        }
    }
}
pub mod block;
#[cfg(target_arch = "x86_64")]
pub mod keyboard;
pub mod keyboard_common;
pub mod mmio;
#[cfg(all(feature = "ui", target_arch = "x86_64"))]
pub mod mouse;
#[cfg(feature = "ui")]
pub mod mouse_cursor;
pub mod nvme;
pub mod pci;
pub mod sdhci;
pub mod serial;
pub mod serial_regs;
pub mod spi;
pub mod storage;
pub mod usb;

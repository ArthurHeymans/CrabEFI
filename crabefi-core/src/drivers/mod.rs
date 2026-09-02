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
//! platform-provided hardware information.
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

/// Registry-owned handle to one controller allocation.
///
/// # Safety
///
/// The wrapped pointer must remain valid for the firmware lifetime.
/// All access must be serialized through the parent `ControllerRegistry` mutex.
/// CrabEFI is single-threaded, so this is trivially satisfied.
struct ControllerPtr<T>(core::ptr::NonNull<T>);

// SAFETY: ownership may cross the mutex boundary only when the controller type
// itself explicitly satisfies `Send`.
unsafe impl<T: Send> Send for ControllerPtr<T> {}

/// Generic registry for PCI-based hardware controllers.
///
/// Encapsulates the common pattern of:
/// 1. Allocating controller structs via the EFI page allocator
/// 2. Storing owned allocation handles in a `Mutex<heapless::Vec>`
/// 3. Providing lock-scoped controller access by index
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

        let controller_box = core::ptr::NonNull::new(mem.as_mut_ptr().cast::<T>()).ok_or(())?;
        // Safety: we just allocated `pages` pages (>= size_of::<T>() bytes),
        // so `controller_box` is valid, aligned, and non-overlapping.
        unsafe {
            controller_box.as_ptr().write(controller);
        }

        let mut controllers = self.controllers.lock();
        if controllers.push(ControllerPtr(controller_box)).is_err() {
            log::warn!("{}: controller list full — freeing allocation", self.name);
            // Safety: `controller_box` was initialized with `ptr::write` above and
            // has not been moved into the registry. Drop it before freeing pages so
            // future controller types with Drop glue are handled correctly.
            unsafe { core::ptr::drop_in_place(controller_box.as_ptr()) };
            crate::efi::free_pages(mem, pages as u64);
            return Err(());
        }

        Ok(())
    }

    /// Mutably access one controller while retaining the registry lock.
    pub fn with_mut<R>(&self, index: usize, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let mut controllers = self.controllers.lock();
        let controller = controllers.get_mut(index)?;
        // SAFETY: registration creates one allocation per entry and the mutex
        // retains exclusive access for the complete closure invocation.
        Some(f(unsafe { controller.0.as_mut() }))
    }

    /// Mutably visit every registered controller under one registry lock.
    pub fn for_each_mut(&self, mut f: impl FnMut(&mut T)) {
        let mut controllers = self.controllers.lock();
        for controller in controllers.iter_mut() {
            // SAFETY: each entry owns a distinct allocation and the mutex is held.
            f(unsafe { controller.0.as_mut() });
        }
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
pub(crate) mod mmio_bounds;
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

/// Stop firmware-owned DMA before transferring control to an operating system.
///
/// Driver shutdown handles controller-specific teardown. Clearing bus mastering
/// afterwards is the final safety net for devices without complete shutdown
/// coverage or for controllers that failed to quiesce cleanly.
pub fn quiesce_dma_for_os_handoff() {
    pci::shutdown_drivers();
    pci::disable_all_bus_mastering_for_handoff();
}

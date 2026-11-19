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
//! The `block` module defines the `BlockDevice` trait. The `storage` module
//! identifies every disk by a `StorageId`, enumerates them with
//! `storage::devices()` and lends one out as `&mut dyn BlockDevice` through
//! `storage::with_disk()`.

pub mod ahci;

// ---------------------------------------------------------------------------
// Generic Controller Registry
// ---------------------------------------------------------------------------

use alloc::vec::Vec;
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

/// Why [`ControllerRegistry::register`] could not keep a controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// No EFI pages were left for the controller structure.
    OutOfPages,
    /// The heap could not grow the controller list.
    OutOfHeap,
}

impl core::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RegisterError::OutOfPages => write!(f, "out of pages for the controller"),
            RegisterError::OutOfHeap => write!(f, "out of heap for the controller list"),
        }
    }
}

/// Generic registry for PCI-based hardware controllers.
///
/// Encapsulates the common pattern of:
/// 1. Allocating controller structs via the EFI page allocator
/// 2. Storing owned allocation handles in a `Mutex<Vec>`
/// 3. Providing lock-scoped controller access by index
///
/// The list grows from the boot-services heap, so a board has as many
/// controllers as it has memory for; there is no per-driver cap. Controllers
/// are indexed by registration order and never removed, so an index stays
/// valid for the firmware lifetime.
///
/// Both the list and the controller pages are boot-services memory: only boot
/// services and the `ExitBootServices` DMA quiesce (which runs before the OS
/// owns that memory) may touch them. Runtime services never do.
pub struct ControllerRegistry<T> {
    controllers: Mutex<Vec<ControllerPtr<T>>>,
    name: &'static str,
}

impl<T> ControllerRegistry<T> {
    /// Create a new empty registry.
    pub const fn new(name: &'static str) -> Self {
        Self {
            controllers: Mutex::new(Vec::new()),
            name,
        }
    }

    /// Register a newly-initialized controller.
    ///
    /// Allocates EFI pages for the controller struct, moves it there, and
    /// stores the pointer.
    ///
    /// # Errors
    ///
    /// Fails only when memory runs out: [`RegisterError::OutOfPages`] for the
    /// controller pages, [`RegisterError::OutOfHeap`] for the list entry. On
    /// either failure, `discard` takes ownership outside the registry lock and
    /// must stop further DMA before releasing any controller-owned buffers.
    pub fn register(&self, controller: T, discard: impl FnOnce(T)) -> Result<(), RegisterError> {
        // Grow the list first, so a full heap never strands controller pages.
        let mut controllers = self.controllers.lock();
        if controllers.try_reserve(1).is_err() {
            drop(controllers);
            discard(controller);
            return Err(RegisterError::OutOfHeap);
        }

        const { assert!(core::mem::align_of::<T>() <= 4096) };
        let size = core::mem::size_of::<T>();
        let pages = size.div_ceil(4096).max(1);
        log::debug!(
            "{}: Allocating {} pages ({} bytes) for controller",
            self.name,
            pages,
            size
        );

        let Some(mem) = crate::efi::allocate_pages(pages as u64) else {
            drop(controllers);
            discard(controller);
            return Err(RegisterError::OutOfPages);
        };
        // SAFETY: the page allocator returned a nonempty mutable slice.
        let controller_box =
            unsafe { core::ptr::NonNull::new_unchecked(mem.as_mut_ptr().cast::<T>()) };
        // Safety: we just allocated `pages` pages (>= size_of::<T>() bytes),
        // so `controller_box` is valid, page-aligned, and non-overlapping.
        unsafe {
            controller_box.as_ptr().write(controller);
        }

        // Capacity was reserved above, so this cannot reallocate or fail.
        controllers.push(ControllerPtr(controller_box));
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
#[cfg(feature = "elan-i2c")]
pub(crate) mod elan;
pub(crate) mod hid_descriptor;
#[cfg(feature = "hid-i2c")]
pub(crate) mod hid_i2c;
pub(crate) mod hid_report;
#[cfg(target_arch = "x86_64")]
mod i8042;
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
#[cfg(feature = "ui")]
pub mod pointer;
pub mod sdhci;
pub mod serial;
pub mod serial_regs;
#[cfg(feature = "spi-flash")]
pub mod spi;
pub mod storage;
pub mod usb;

/// Stop firmware-owned DMA before transferring control to an operating system.
///
/// The platform first stops the devices it owns ([`crate::PlatformHooks::quiesce_dma`]).
/// Driver shutdown handles controller-specific teardown. Clearing bus mastering
/// afterwards is the final safety net for devices without complete shutdown
/// coverage or for controllers that failed to quiesce cleanly.
pub fn quiesce_dma_for_os_handoff() {
    if let Some(hooks) = crate::handoff::callbacks().hooks {
        hooks.quiesce_dma();
    }
    pci::shutdown_drivers();
    pci::disable_all_bus_mastering_for_handoff();
}

#[cfg(test)]
mod registry_tests;

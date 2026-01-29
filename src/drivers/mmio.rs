//! Memory-Mapped I/O (MMIO) Register Abstraction
//!
//! This module provides type-safe access to hardware MMIO registers using
//! tock-registers. It encapsulates volatile pointer operations and provides
//! bounds checking for register accesses.
//!
//! # Example
//!
//! ```rust,ignore
//! use crate::drivers::mmio::MmioRegion;
//!
//! let mmio = MmioRegion::new(0xFED0_0000, 0x1000);
//! let value = mmio.read32(0x00);  // Read 32-bit register at offset 0
//! mmio.write32(0x04, 0x1234);     // Write 32-bit register at offset 4
//! ```

use core::ptr::NonNull;
use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::registers::{ReadOnly, ReadWrite, WriteOnly};

/// A memory-mapped I/O region providing safe register access.
///
/// This struct wraps a base address and size, providing methods to read and
/// write registers at specific offsets. In debug builds, bounds checking is
/// performed to catch out-of-bounds accesses.
#[derive(Clone, Copy)]
pub struct MmioRegion {
    /// Base address of the MMIO region
    base: NonNull<u8>,
    /// Size of the MMIO region in bytes (used for bounds checking)
    #[cfg(debug_assertions)]
    size: usize,
}

// SAFETY: MmioRegion only contains a pointer to hardware MMIO space.
// The MMIO region is mapped at initialization and remains valid for the
// firmware's lifetime. Register accesses are inherently single-threaded
// per-device (each device has its own MMIO space).
unsafe impl Send for MmioRegion {}
unsafe impl Sync for MmioRegion {}

impl MmioRegion {
    /// Create a new MMIO region from a base address and size.
    ///
    /// # Arguments
    ///
    /// * `base` - Physical base address of the MMIO region
    /// * `size` - Size of the MMIO region in bytes
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `base` is a valid physical address mapped for MMIO access
    /// - The region `[base, base + size)` is valid for the device
    /// - The region remains valid for the lifetime of this struct
    ///
    /// # Panics
    ///
    /// Panics if `base` is null.
    pub fn new(base: u64, #[allow(unused_variables)] size: usize) -> Self {
        let ptr = NonNull::new(base as *mut u8).expect("MMIO base address cannot be null");
        Self {
            base: ptr,
            #[cfg(debug_assertions)]
            size,
        }
    }

    /// Get the base address of this MMIO region.
    #[inline]
    pub fn base(&self) -> u64 {
        self.base.as_ptr() as u64
    }

    /// Create a sub-region at a specific offset.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset from the base address
    /// * `size` - Size of the sub-region in bytes
    ///
    /// # Returns
    ///
    /// A new `MmioRegion` starting at `base + offset` with the given size.
    #[inline]
    pub fn subregion(&self, offset: u64, size: usize) -> Self {
        #[cfg(debug_assertions)]
        {
            assert!(
                (offset as usize).saturating_add(size) <= self.size,
                "MMIO subregion out of bounds: offset={:#x}, size={:#x}, region_size={:#x}",
                offset,
                size,
                self.size
            );
        }
        Self::new(self.base() + offset, size)
    }

    /// Check if an access at the given offset and size is within bounds.
    #[cfg(debug_assertions)]
    #[inline]
    fn check_bounds(&self, offset: u64, access_size: usize) {
        let end = (offset as usize).saturating_add(access_size);
        assert!(
            end <= self.size,
            "MMIO access out of bounds: offset={:#x}, access_size={}, region_size={:#x}",
            offset,
            access_size,
            self.size
        );
    }

    /// Read an 8-bit register at the given offset.
    #[inline]
    pub fn read8(&self, offset: u64) -> u8 {
        #[cfg(debug_assertions)]
        self.check_bounds(offset, 1);

        let reg = unsafe { &*(self.base.as_ptr().add(offset as usize) as *const ReadOnly<u8>) };
        reg.get()
    }

    /// Write an 8-bit register at the given offset.
    #[inline]
    pub fn write8(&self, offset: u64, value: u8) {
        #[cfg(debug_assertions)]
        self.check_bounds(offset, 1);

        let reg = unsafe { &*(self.base.as_ptr().add(offset as usize) as *const WriteOnly<u8>) };
        reg.set(value);
    }

    /// Read a 16-bit register at the given offset.
    #[inline]
    pub fn read16(&self, offset: u64) -> u16 {
        #[cfg(debug_assertions)]
        self.check_bounds(offset, 2);

        let reg = unsafe { &*(self.base.as_ptr().add(offset as usize) as *const ReadOnly<u16>) };
        reg.get()
    }

    /// Write a 16-bit register at the given offset.
    #[inline]
    pub fn write16(&self, offset: u64, value: u16) {
        #[cfg(debug_assertions)]
        self.check_bounds(offset, 2);

        let reg = unsafe { &*(self.base.as_ptr().add(offset as usize) as *const WriteOnly<u16>) };
        reg.set(value);
    }

    /// Read a 32-bit register at the given offset.
    #[inline]
    pub fn read32(&self, offset: u64) -> u32 {
        #[cfg(debug_assertions)]
        self.check_bounds(offset, 4);

        let reg = unsafe { &*(self.base.as_ptr().add(offset as usize) as *const ReadOnly<u32>) };
        reg.get()
    }

    /// Write a 32-bit register at the given offset.
    #[inline]
    pub fn write32(&self, offset: u64, value: u32) {
        #[cfg(debug_assertions)]
        self.check_bounds(offset, 4);

        let reg = unsafe { &*(self.base.as_ptr().add(offset as usize) as *const WriteOnly<u32>) };
        reg.set(value);
    }

    /// Read-modify-write a 32-bit register at the given offset.
    ///
    /// This is a convenience method for the common pattern of reading a
    /// register, modifying some bits, and writing it back.
    #[inline]
    pub fn modify32<F>(&self, offset: u64, f: F)
    where
        F: FnOnce(u32) -> u32,
    {
        #[cfg(debug_assertions)]
        self.check_bounds(offset, 4);

        let reg = unsafe { &*(self.base.as_ptr().add(offset as usize) as *const ReadWrite<u32>) };
        let old = reg.get();
        reg.set(f(old));
    }

    /// Read a 64-bit register at the given offset.
    #[inline]
    pub fn read64(&self, offset: u64) -> u64 {
        #[cfg(debug_assertions)]
        self.check_bounds(offset, 8);

        let reg = unsafe { &*(self.base.as_ptr().add(offset as usize) as *const ReadOnly<u64>) };
        reg.get()
    }

    /// Write a 64-bit register at the given offset.
    #[inline]
    pub fn write64(&self, offset: u64, value: u64) {
        #[cfg(debug_assertions)]
        self.check_bounds(offset, 8);

        let reg = unsafe { &*(self.base.as_ptr().add(offset as usize) as *const WriteOnly<u64>) };
        reg.set(value);
    }

    /// Read-modify-write a 64-bit register at the given offset.
    #[inline]
    pub fn modify64<F>(&self, offset: u64, f: F)
    where
        F: FnOnce(u64) -> u64,
    {
        #[cfg(debug_assertions)]
        self.check_bounds(offset, 8);

        let reg = unsafe { &*(self.base.as_ptr().add(offset as usize) as *const ReadWrite<u64>) };
        let old = reg.get();
        reg.set(f(old));
    }

    /// Get a raw pointer to a register at the given offset.
    ///
    /// This is useful for cases where the caller needs direct access to the
    /// register address (e.g., for DMA descriptor setup).
    ///
    /// # Safety
    ///
    /// The caller must ensure proper volatile access semantics.
    #[inline]
    pub unsafe fn ptr<T>(&self, offset: u64) -> *mut T {
        #[cfg(debug_assertions)]
        self.check_bounds(offset, core::mem::size_of::<T>());

        self.base.as_ptr().add(offset as usize) as *mut T
    }
}

impl core::fmt::Debug for MmioRegion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        #[cfg(debug_assertions)]
        {
            f.debug_struct("MmioRegion")
                .field("base", &format_args!("{:#x}", self.base()))
                .field("size", &format_args!("{:#x}", self.size))
                .finish()
        }
        #[cfg(not(debug_assertions))]
        {
            f.debug_struct("MmioRegion")
                .field("base", &format_args!("{:#x}", self.base()))
                .finish()
        }
    }
}

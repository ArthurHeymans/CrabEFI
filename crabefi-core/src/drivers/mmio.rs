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
//! let mmio = MmioRegion::try_new(0xFED0_0000, 0x1000).expect("valid MMIO region");
//! let value = mmio.read32(0x00);  // Read 32-bit register at offset 0
//! mmio.write32(0x04, 0x1234);     // Write 32-bit register at offset 4
//! ```

use core::ptr::NonNull;
use tock_registers::interfaces::{Readable, Writeable};
use tock_registers::registers::{ReadOnly, ReadWrite, WriteOnly};

use crate::drivers::mmio_bounds::{checked_access, checked_region};

/// Failure to construct or narrow an [`MmioRegion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmioError {
    /// Base address was null.
    NullBase,
    /// Range was empty or wrapped the address space.
    EmptyOrWrapping { base: u64, size: usize },
    /// Subregion leaves the parent region.
    OutOfBounds {
        offset: u64,
        size: usize,
        region_size: usize,
    },
    /// `base + offset` overflowed.
    Overflow,
}

impl core::fmt::Display for MmioError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MmioError::NullBase => write!(f, "MMIO base address cannot be null"),
            MmioError::EmptyOrWrapping { base, size } => write!(
                f,
                "MMIO region must be nonempty and non-wrapping: base={base:#x}, size={size:#x}"
            ),
            MmioError::OutOfBounds {
                offset,
                size,
                region_size,
            } => write!(
                f,
                "MMIO subregion out of bounds: offset={offset:#x}, size={size:#x}, region_size={region_size:#x}"
            ),
            MmioError::Overflow => write!(f, "MMIO subregion address overflow"),
        }
    }
}

/// A memory-mapped I/O region providing safe register access.
///
/// This struct wraps a base address and size, providing methods to read and
/// write registers at specific offsets. Bounds and alignment checks remain
/// effective in release builds because safe accessors construct references.
#[derive(Clone, Copy)]
pub struct MmioRegion {
    /// Base address of the MMIO region
    base: NonNull<u8>,
    /// Size of the MMIO region in bytes.
    size: usize,
}

// SAFETY: MmioRegion only contains a pointer to hardware MMIO space.
// The MMIO region is mapped at initialization and remains valid for the
// firmware's lifetime. Register accesses are inherently single-threaded
// per-device (each device has its own MMIO space).
unsafe impl Send for MmioRegion {}
unsafe impl Sync for MmioRegion {}

impl MmioRegion {
    /// Create a new MMIO region from a base address and size, checked.
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
    /// # Errors
    ///
    /// Returns [`MmioError`] when `base` is null or the range is empty or
    /// wraps the address space. Use this from fallible init paths instead of
    /// the panicking [`MmioRegion::new`].
    pub unsafe fn try_new(base: u64, size: usize) -> Result<Self, MmioError> {
        if checked_region(base, size).is_none() {
            return Err(MmioError::EmptyOrWrapping { base, size });
        }
        let Some(ptr) = NonNull::new(base as *mut u8) else {
            return Err(MmioError::NullBase);
        };
        Ok(Self { base: ptr, size })
    }

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
    /// Panics if `base` is null or the range is empty/wrapping. This is a
    /// programmer bug (device tree/PCI BAR decoding went wrong), not a
    /// runtime EFI error, so aborting with a serial message is intentional.
    /// Fallible callers should use [`MmioRegion::try_new`] instead.
    pub unsafe fn new(base: u64, size: usize) -> Self {
        // SAFETY: validated by try_new; panic message preserves the old text
        // so existing serial-log triage keeps working.
        unsafe { Self::try_new(base, size).expect("MMIO region must be nonempty and non-wrapping") }
    }

    /// Get the base address of this MMIO region.
    #[inline]
    pub fn base(&self) -> u64 {
        self.base.as_ptr() as u64
    }

    /// Create a fallible sub-region at a specific offset.
    ///
    /// # Arguments
    ///
    /// * `offset` - Offset from the base address
    /// * `size` - Size of the sub-region in bytes
    ///
    /// # Errors
    ///
    /// Returns [`MmioError::OutOfBounds`] when the subrange leaves this
    /// region, or [`MmioError::Overflow`] when `base + offset` overflows.
    pub fn try_subregion(&self, offset: u64, size: usize) -> Result<Self, MmioError> {
        let Some(offset) = checked_access(self.base(), self.size, offset, size, 1) else {
            return Err(MmioError::OutOfBounds {
                offset,
                size,
                region_size: self.size,
            });
        };
        let Some(base) = self.base().checked_add(offset as u64) else {
            return Err(MmioError::Overflow);
        };
        // SAFETY: the checked subrange is contained in the caller-validated region.
        unsafe { Self::try_new(base, size) }
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
    ///
    /// # Panics
    ///
    /// Panics on out-of-bounds ranges (driver bug). Fallible callers should
    /// use [`MmioRegion::try_subregion`].
    #[inline]
    pub fn subregion(&self, offset: u64, size: usize) -> Self {
        self.try_subregion(offset, size).unwrap_or_else(|_| {
            panic!(
                "MMIO subregion out of bounds: offset={offset:#x}, size={size:#x}, region_size={:#x}",
                self.size
            )
        })
    }

    #[inline]
    fn check_access(&self, offset: u64, width: usize, alignment: usize) -> usize {
        checked_access(self.base(), self.size, offset, width, alignment).unwrap_or_else(|| {
            panic!(
                "invalid MMIO access: offset={:#x}, width={}, alignment={}, region_size={:#x}",
                offset, width, alignment, self.size
            )
        })
    }

    /// Read an 8-bit register at the given offset.
    #[inline]
    pub fn read8(&self, offset: u64) -> u8 {
        let offset = self.check_access(offset, 1, 1);
        let reg = unsafe { &*(self.base.as_ptr().add(offset) as *const ReadOnly<u8>) };
        reg.get()
    }

    /// Write an 8-bit register at the given offset.
    #[inline]
    pub fn write8(&self, offset: u64, value: u8) {
        let offset = self.check_access(offset, 1, 1);
        let reg = unsafe { &*(self.base.as_ptr().add(offset) as *const WriteOnly<u8>) };
        reg.set(value);
    }

    /// Read a 16-bit register at the given offset.
    #[inline]
    pub fn read16(&self, offset: u64) -> u16 {
        let offset = self.check_access(offset, 2, 2);
        let reg = unsafe { &*(self.base.as_ptr().add(offset) as *const ReadOnly<u16>) };
        reg.get()
    }

    /// Write a 16-bit register at the given offset.
    #[inline]
    pub fn write16(&self, offset: u64, value: u16) {
        let offset = self.check_access(offset, 2, 2);
        let reg = unsafe { &*(self.base.as_ptr().add(offset) as *const WriteOnly<u16>) };
        reg.set(value);
    }

    /// Read a 32-bit register at the given offset.
    #[inline]
    pub fn read32(&self, offset: u64) -> u32 {
        let offset = self.check_access(offset, 4, 4);
        let reg = unsafe { &*(self.base.as_ptr().add(offset) as *const ReadOnly<u32>) };
        reg.get()
    }

    /// Write a 32-bit register at the given offset.
    #[inline]
    pub fn write32(&self, offset: u64, value: u32) {
        let offset = self.check_access(offset, 4, 4);
        let reg = unsafe { &*(self.base.as_ptr().add(offset) as *const WriteOnly<u32>) };
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
        let offset = self.check_access(offset, 4, 4);
        let reg = unsafe { &*(self.base.as_ptr().add(offset) as *const ReadWrite<u32>) };
        let old = reg.get();
        reg.set(f(old));
    }

    /// Read a 64-bit register at the given offset.
    #[inline]
    pub fn read64(&self, offset: u64) -> u64 {
        let offset = self.check_access(offset, 8, 8);
        let reg = unsafe { &*(self.base.as_ptr().add(offset) as *const ReadOnly<u64>) };
        reg.get()
    }

    /// Write a 64-bit register at the given offset.
    #[inline]
    pub fn write64(&self, offset: u64, value: u64) {
        let offset = self.check_access(offset, 8, 8);
        let reg = unsafe { &*(self.base.as_ptr().add(offset) as *const WriteOnly<u64>) };
        reg.set(value);
    }

    /// Write a 64-bit register as two 32-bit writes (low dword first, then high).
    ///
    /// Some hardware (notably xHCI) requires that 64-bit MMIO registers be
    /// written as two separate 32-bit writes rather than a single 64-bit write.
    /// The xHCI specification mandates low-dword-first ordering. On many PCI/PCIe
    /// implementations, a single 64-bit MMIO write may be split arbitrarily by
    /// the bus, causing the controller to see partial updates.
    ///
    /// This follows the Linux kernel's `lo_hi_writeq()` pattern.
    #[inline]
    pub fn write64_lo_hi(&self, offset: u64, value: u64) {
        let offset = self.check_access(offset, 8, 4);
        let lo = value as u32;
        let hi = (value >> 32) as u32;
        let lo_reg = unsafe { &*(self.base.as_ptr().add(offset) as *const WriteOnly<u32>) };
        let hi_reg = unsafe { &*(self.base.as_ptr().add(offset + 4) as *const WriteOnly<u32>) };
        lo_reg.set(lo);
        hi_reg.set(hi);
    }

    /// Read-modify-write a 64-bit register at the given offset.
    #[inline]
    pub fn modify64<F>(&self, offset: u64, f: F)
    where
        F: FnOnce(u64) -> u64,
    {
        let offset = self.check_access(offset, 8, 8);
        let reg = unsafe { &*(self.base.as_ptr().add(offset) as *const ReadWrite<u64>) };
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
        let offset = self.check_access(
            offset,
            core::mem::size_of::<T>(),
            core::mem::align_of::<T>(),
        );
        // SAFETY: caller ensures proper volatile access semantics; bounds and
        // alignment were validated before constructing the pointer.
        unsafe { self.base.as_ptr().add(offset) as *mut T }
    }
}

impl core::fmt::Debug for MmioRegion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MmioRegion")
            .field("base", &format_args!("{:#x}", self.base()))
            .field("size", &format_args!("{:#x}", self.size))
            .finish()
    }
}

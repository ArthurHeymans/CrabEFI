//! Mask-aware DMA buffers with explicit translation and ownership synchronization.
//!
//! PCI callers provide a firmware-described DMA domain. Buffers retain both
//! the CPU physical allocation and translated device address, and page backing
//! keeps non-coherent cache-line maintenance exclusive to the allocation.

use core::ops::Range;

use r_efi::efi::Status;

use crate::arch::{DmaCacheOperation, DmaSyncError};
use crate::efi::allocator::{self, AllocateType, MemoryType, PAGE_SIZE, PAGE_SIZE_USIZE};
use crate::efi::dma_range::{
    allocation_fits_mask, checked_subrange, pages_for_len, translate_dma_range,
};

/// Inclusive highest address visible to a DMA-capable device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaMask(u64);

impl DmaMask {
    /// A 32-bit DMA address mask.
    pub const fn bits32() -> Self {
        Self(u32::MAX as u64)
    }

    /// A 48-bit DMA address mask.
    pub const fn bits48() -> Self {
        Self((1u64 << 48) - 1)
    }

    /// A full 64-bit DMA address mask.
    pub const fn bits64() -> Self {
        Self(u64::MAX)
    }

    /// Construct a mask from its inclusive highest visible address.
    pub const fn from_max_address(max_address: u64) -> Self {
        Self(max_address)
    }

    /// Return the inclusive highest visible address.
    pub const fn max_address(self) -> u64 {
        self.0
    }
}

/// Whether CPU caches are coherent with a DMA-capable device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaCoherency {
    /// Hardware maintains CPU/device cache coherency.
    Coherent,
    /// Software cache maintenance is required at ownership transitions.
    NonCoherent,
}

/// One contiguous CPU-to-device DMA translation window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DmaDomain {
    /// First CPU physical address in the window.
    pub cpu_base: u64,
    /// Device-visible address corresponding to `cpu_base`.
    pub device_base: u64,
    /// Window size in bytes.
    pub size: u64,
    /// Cache ownership model for devices in this domain.
    pub coherency: DmaCoherency,
}

impl DmaDomain {
    fn cpu_end(self) -> Option<u64> {
        self.cpu_base.checked_add(self.size)
    }

    fn device_address(self, cpu_address: u64, byte_len: u64) -> Option<u64> {
        translate_dma_range(
            cpu_address,
            byte_len,
            self.cpu_base,
            self.device_base,
            self.size,
        )
    }
}

/// Direction of data movement relative to the CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// The device reads data produced by the CPU.
    ToDevice,
    /// The device writes data consumed by the CPU.
    FromDevice,
    /// Both CPU and device may produce data.
    Bidirectional,
}

/// DMA buffer allocation or synchronization failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    /// A zero-sized, overflowing, or out-of-bounds request was supplied.
    InvalidRange,
    /// No allocation fitting the device mask was available.
    OutOfResources,
    /// Non-coherent cache maintenance is unavailable on this architecture.
    UnsupportedCoherency,
}

impl From<DmaSyncError> for DmaError {
    fn from(error: DmaSyncError) -> Self {
        match error {
            DmaSyncError::Unsupported => Self::UnsupportedCoherency,
            DmaSyncError::InvalidRange => Self::InvalidRange,
        }
    }
}

/// Exclusively owned, page-backed identity-DMA allocation.
pub struct DmaBuffer {
    address: u64,
    device_address: u64,
    byte_len: usize,
    pages: u64,
    coherency: DmaCoherency,
}

impl DmaBuffer {
    /// Allocate a zeroed DMA buffer whose entire page allocation fits `mask`.
    pub fn allocate(
        byte_len: usize,
        mask: DmaMask,
        coherency: DmaCoherency,
    ) -> Result<Self, DmaError> {
        let pages = pages_for_len(byte_len, PAGE_SIZE).ok_or(DmaError::InvalidRange)?;
        let allocation_len = pages
            .checked_mul(PAGE_SIZE)
            .and_then(|len| usize::try_from(len).ok())
            .ok_or(DmaError::InvalidRange)?;
        let mut address = mask.max_address();
        let status = allocator::allocate_pages(
            AllocateType::AllocateMaxAddress,
            MemoryType::BootServicesData,
            pages,
            &mut address,
        );
        if status != Status::SUCCESS {
            return Err(DmaError::OutOfResources);
        }
        if !allocation_fits_mask(address, pages, PAGE_SIZE, mask.max_address()) {
            let _ = allocator::free_pages(address, pages);
            return Err(DmaError::OutOfResources);
        }

        // SAFETY: the page allocator returned exclusive identity-mapped memory
        // covering `allocation_len` bytes, retained by this object until Drop.
        unsafe { core::slice::from_raw_parts_mut(address as *mut u8, allocation_len) }.fill(0);
        Ok(Self {
            address,
            device_address: address,
            byte_len,
            pages,
            coherency,
        })
    }

    /// Allocate inside an explicitly described DMA translation window.
    pub fn allocate_in_domain(
        byte_len: usize,
        mask: DmaMask,
        domain: DmaDomain,
    ) -> Result<Self, DmaError> {
        let pages = pages_for_len(byte_len, PAGE_SIZE).ok_or(DmaError::InvalidRange)?;
        let allocation_len = pages.checked_mul(PAGE_SIZE).ok_or(DmaError::InvalidRange)?;
        let allocation_len_usize =
            usize::try_from(allocation_len).map_err(|_| DmaError::InvalidRange)?;
        let cpu_end = domain.cpu_end().ok_or(DmaError::InvalidRange)?;
        let device_mask_offset = mask
            .max_address()
            .checked_sub(domain.device_base)
            .ok_or(DmaError::OutOfResources)?;
        let device_limited_cpu_last = domain.cpu_base.saturating_add(device_mask_offset);
        let max_address = cpu_end.saturating_sub(1).min(device_limited_cpu_last);
        let mut address = 0;
        let status = allocator::allocate_pages_in_range(
            MemoryType::BootServicesData,
            pages,
            domain.cpu_base,
            max_address,
            &mut address,
        );
        if status != Status::SUCCESS {
            return Err(DmaError::OutOfResources);
        }
        let Some(device_address) = domain.device_address(address, allocation_len) else {
            let _ = allocator::free_pages(address, pages);
            return Err(DmaError::OutOfResources);
        };
        if !allocation_fits_mask(device_address, pages, PAGE_SIZE, mask.max_address()) {
            let _ = allocator::free_pages(address, pages);
            return Err(DmaError::OutOfResources);
        }
        // SAFETY: the allocator returned an exclusive CPU mapping covering the
        // complete page-rounded allocation retained by this owner.
        unsafe { core::slice::from_raw_parts_mut(address as *mut u8, allocation_len_usize) }
            .fill(0);
        Ok(Self {
            address,
            device_address,
            byte_len,
            pages,
            coherency: domain.coherency,
        })
    }

    /// Return the CPU physical address of the owned allocation.
    pub const fn cpu_address(&self) -> u64 {
        self.address
    }

    /// Return the device-visible address after domain translation.
    pub const fn dma_address(&self) -> u64 {
        self.device_address
    }

    /// Return the requested byte length (excluding page-rounding padding).
    pub const fn len(&self) -> usize {
        self.byte_len
    }

    /// Return whether the requested length is zero (always false for a buffer).
    pub const fn is_empty(&self) -> bool {
        self.byte_len == 0
    }

    /// Borrow the requested DMA bytes.
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: DmaBuffer uniquely owns at least `byte_len` bytes at address.
        unsafe { core::slice::from_raw_parts(self.address as *const u8, self.byte_len) }
    }

    /// Mutably borrow the requested DMA bytes.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` guarantees exclusive CPU access to the allocation.
        unsafe { core::slice::from_raw_parts_mut(self.address as *mut u8, self.byte_len) }
    }

    /// Mutably borrow a checked half-open subrange.
    pub fn range_mut(&mut self, range: Range<usize>) -> Result<&mut [u8], DmaError> {
        let (start, len) = checked_subrange(&range, self.byte_len).ok_or(DmaError::InvalidRange)?;
        Ok(&mut self.as_mut_slice()[start..start + len])
    }

    fn sync_range(&self, range: Range<usize>) -> Result<(u64, usize), DmaError> {
        let (start, len) = checked_subrange(&range, self.byte_len).ok_or(DmaError::InvalidRange)?;
        if self.coherency == DmaCoherency::NonCoherent && (start != 0 || len != self.byte_len) {
            // Cache maintenance rounds to cache-line boundaries. Until the API
            // tracks cache-line ownership, only the whole exclusively-owned
            // buffer is safe to synchronize on non-coherent systems.
            return Err(DmaError::InvalidRange);
        }
        let address = self
            .address
            .checked_add(start as u64)
            .ok_or(DmaError::InvalidRange)?;
        Ok((address, len))
    }

    /// Synchronize a checked range before device ownership.
    pub fn sync_for_device(
        &self,
        range: Range<usize>,
        direction: DmaDirection,
    ) -> Result<(), DmaError> {
        let (address, len) = self.sync_range(range)?;
        if self.coherency == DmaCoherency::Coherent {
            crate::barrier::publish_to_device();
            return Ok(());
        }
        let operation = match direction {
            DmaDirection::ToDevice => DmaCacheOperation::Clean,
            DmaDirection::FromDevice => DmaCacheOperation::Invalidate,
            DmaDirection::Bidirectional => DmaCacheOperation::CleanInvalidate,
        };
        crate::arch::dma_cache_for_device(address, len, operation).map_err(Into::into)
    }

    /// Synchronize a checked range after CPU ownership resumes.
    pub fn sync_for_cpu(
        &self,
        range: Range<usize>,
        direction: DmaDirection,
    ) -> Result<(), DmaError> {
        let (address, len) = self.sync_range(range)?;
        if self.coherency == DmaCoherency::Coherent {
            crate::barrier::consume_from_device();
            return Ok(());
        }
        if direction == DmaDirection::ToDevice {
            crate::barrier::consume_from_device();
            return Ok(());
        }
        let operation = match direction {
            // CPU acquisition must never clean stale CPU data over bytes the
            // device may have written.
            DmaDirection::FromDevice | DmaDirection::Bidirectional => DmaCacheOperation::Invalidate,
            DmaDirection::ToDevice => unreachable!(),
        };
        crate::arch::dma_cache_for_cpu(address, len, operation).map_err(Into::into)
    }
}

impl Drop for DmaBuffer {
    fn drop(&mut self) {
        let status = allocator::free_pages(self.address, self.pages);
        if status != Status::SUCCESS {
            log::warn!(
                "Failed to free DMA allocation at {:#x} ({} pages): {:?}",
                self.address,
                self.pages,
                status
            );
        }
    }
}

// Keep the page-size conversion tied to the allocator's public constants.
const _: () = assert!(PAGE_SIZE_USIZE as u64 == PAGE_SIZE);

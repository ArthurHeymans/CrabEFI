//! AArch64 data-cache maintenance for non-coherent DMA.
//!
//! DMA buffers are page-backed and exclusively owned, so rounding a requested
//! subrange out to complete cache lines cannot touch unrelated allocations.

use crate::arch::{DmaCacheOperation, DmaSyncError};
use crate::efi::dma_range::cache_line_range;

/// Discover the minimum data-cache line size from `CTR_EL0.DminLine`.
#[inline]
pub fn data_cache_line_size() -> usize {
    let ctr: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, CTR_EL0",
            out(reg) ctr,
            options(nomem, nostack, preserves_flags)
        );
    }
    4usize << ((ctr >> 16) & 0xf)
}

#[inline]
fn maintain_range(
    addr: u64,
    size: usize,
    operation: DmaCacheOperation,
) -> Result<(), DmaSyncError> {
    if size == 0 {
        return Ok(());
    }
    let line_size = data_cache_line_size();
    let range = cache_line_range(addr, size, line_size).ok_or(DmaSyncError::InvalidRange)?;

    for line in (range.start..range.end).step_by(line_size) {
        unsafe {
            match operation {
                DmaCacheOperation::Clean => core::arch::asm!(
                    "dc cvac, {}",
                    in(reg) line,
                    options(nostack, preserves_flags)
                ),
                DmaCacheOperation::Invalidate => core::arch::asm!(
                    "dc ivac, {}",
                    in(reg) line,
                    options(nostack, preserves_flags)
                ),
                DmaCacheOperation::CleanInvalidate => core::arch::asm!(
                    "dc civac, {}",
                    in(reg) line,
                    options(nostack, preserves_flags)
                ),
            }
        }
    }
    super::dsb_sy();
    Ok(())
}

/// Perform cache maintenance before transferring ownership to a device.
#[inline]
pub fn sync_for_device(
    addr: u64,
    size: usize,
    operation: DmaCacheOperation,
) -> Result<(), DmaSyncError> {
    maintain_range(addr, size, operation)?;
    crate::barrier::publish_to_device();
    Ok(())
}

/// Perform cache maintenance after ownership returns to the CPU.
#[inline]
pub fn sync_for_cpu(
    addr: u64,
    size: usize,
    operation: DmaCacheOperation,
) -> Result<(), DmaSyncError> {
    maintain_range(addr, size, operation)?;
    crate::barrier::consume_from_device();
    Ok(())
}

/// Clean a memory range to the point of coherency.
#[inline]
pub fn flush_cache_range(addr: u64, size: usize) {
    let _ = maintain_range(addr, size, DmaCacheOperation::Clean);
}

/// Invalidate a memory range without writing dirty CPU data back over device output.
#[inline]
pub fn invalidate_cache_range(addr: u64, size: usize) {
    let _ = maintain_range(addr, size, DmaCacheOperation::Invalidate);
}

/// Clean and invalidate a bidirectional DMA range.
#[inline]
pub fn clean_invalidate_cache_range(addr: u64, size: usize) {
    let _ = maintain_range(addr, size, DmaCacheOperation::CleanInvalidate);
}

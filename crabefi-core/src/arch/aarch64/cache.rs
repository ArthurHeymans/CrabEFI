//! AArch64 data-cache maintenance for non-coherent DMA.
//!
//! DMA buffers are page-backed and exclusively owned, so rounding a requested
//! subrange out to complete cache lines cannot touch unrelated allocations.

use crate::arch::{DmaCacheOperation, DmaSyncError};
use crate::efi::dma_range::cache_line_range;

/// Discover the minimum data-cache line size from `CTR_EL0.DminLine`.
#[inline]
pub fn data_cache_line_size() -> usize {
    cache_line_sizes(read_ctr_el0()).0 as usize
}

/// Read `CTR_EL0`, the cache type register.
#[inline]
fn read_ctr_el0() -> u64 {
    let ctr: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, CTR_EL0",
            out(reg) ctr,
            options(nomem, nostack, preserves_flags)
        );
    }
    ctr
}

/// Decode the (data, instruction) minimum cache line sizes from `CTR_EL0`.
///
/// `DminLine` (bits 19:16) and `IminLine` (bits 3:0) each encode the line
/// size in words as a log2, so the byte size is `4 << field`.
pub(crate) const fn cache_line_sizes(ctr_el0: u64) -> (u64, u64) {
    let instruction = 4u64 << (ctr_el0 & 0x0f);
    let data = 4u64 << ((ctr_el0 >> 16) & 0x0f);
    (data, instruction)
}

/// Data synchronization barrier (inner shareable), sufficient for
/// point-of-unification cache maintenance.
#[inline]
fn dsb_ish() {
    unsafe {
        core::arch::asm!("dsb ish", options(nomem, nostack, preserves_flags));
    }
}

/// Make freshly written code executable: clean the data cache to the point
/// of unification, invalidate the instruction cache to the point of
/// unification, then synchronize both and flush the pipeline.
///
/// This is the Arm ARM sequence for self-modifying/generated code. Line
/// iteration may round out to containing cache lines; cache maintenance
/// by VA does not read or write the bytes, so touching a line that is
/// shared with neighbouring data is safe (clean/invalidate only).
pub fn sync_instruction_cache(addr: u64, size: usize) {
    if size == 0 {
        return;
    }
    let (data_stride, instruction_stride) = cache_line_sizes(read_ctr_el0());
    let (Some(data), Some(instruction)) = (
        cache_line_range(addr, size, data_stride as usize),
        cache_line_range(addr, size, instruction_stride as usize),
    ) else {
        // Only a range wrapping the address space overflows, which no
        // loaded image does. There is no by-VA fallback for the data side.
        debug_assert!(false, "code range {addr:#x}+{size:#x} wraps");
        return;
    };
    for line in data.step_by(data_stride as usize) {
        // SAFETY: cache maintenance by VA; does not dereference `line`.
        unsafe {
            core::arch::asm!("dc cvau, {}", in(reg) line, options(nostack, preserves_flags));
        }
    }
    dsb_ish();
    for line in instruction.step_by(instruction_stride as usize) {
        // SAFETY: cache maintenance by VA; does not dereference `line`.
        unsafe {
            core::arch::asm!("ic ivau, {}", in(reg) line, options(nostack, preserves_flags));
        }
    }
    dsb_ish();
    super::isb();
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

#[cfg(test)]
mod tests {
    use super::cache_line_sizes;

    #[test]
    fn decodes_independent_cache_line_sizes() {
        assert_eq!(cache_line_sizes(3 | (3 << 16)), (32, 32));
        assert_eq!(cache_line_sizes(4 | (5 << 16)), (128, 64));
        assert_eq!(cache_line_sizes(5 | (4 << 16)), (64, 128));
    }
}

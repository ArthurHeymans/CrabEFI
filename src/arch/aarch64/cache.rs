//! AArch64 Cache Management
//!
//! This module provides cache management functions for DMA operations.
//! On AArch64, cache maintenance is done via system instructions
//! operating on virtual addresses.

use core::sync::atomic::{fence, Ordering};

/// Cache line size (typically 64 bytes on most AArch64 implementations)
pub const CACHE_LINE_SIZE: usize = 64;

/// Flush (clean) a memory range from CPU cache to main memory
///
/// Uses `dc cvac` (Data Cache Clean by Virtual Address to Point of Coherency)
/// to ensure DMA-capable devices see the data written by the CPU.
///
/// # Arguments
///
/// * `addr` - Starting address of the memory range
/// * `size` - Size of the memory range in bytes
#[inline]
pub fn flush_cache_range(addr: u64, size: usize) {
    let start = addr as usize & !(CACHE_LINE_SIZE - 1);
    let end = (addr as usize + size + CACHE_LINE_SIZE - 1) & !(CACHE_LINE_SIZE - 1);

    for line in (start..end).step_by(CACHE_LINE_SIZE) {
        unsafe {
            core::arch::asm!(
                "dc cvac, {}",
                in(reg) line,
                options(nostack, preserves_flags)
            );
        }
    }
    // Data synchronization barrier to ensure all cache operations complete
    fence(Ordering::SeqCst);
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
}

/// Invalidate a memory range in CPU cache
///
/// Uses `dc civac` (Data Cache Clean and Invalidate by Virtual Address to
/// Point of Coherency) to ensure the CPU sees data written by DMA devices.
///
/// # Arguments
///
/// * `addr` - Starting address of the memory range
/// * `size` - Size of the memory range in bytes
#[inline]
pub fn invalidate_cache_range(addr: u64, size: usize) {
    let start = addr as usize & !(CACHE_LINE_SIZE - 1);
    let end = (addr as usize + size + CACHE_LINE_SIZE - 1) & !(CACHE_LINE_SIZE - 1);

    for line in (start..end).step_by(CACHE_LINE_SIZE) {
        unsafe {
            core::arch::asm!(
                "dc civac, {}",
                in(reg) line,
                options(nostack, preserves_flags)
            );
        }
    }
    // Data synchronization barrier to ensure all cache operations complete
    fence(Ordering::SeqCst);
    unsafe {
        core::arch::asm!("dsb sy", options(nostack, preserves_flags));
    }
}

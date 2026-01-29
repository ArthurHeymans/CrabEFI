//! x86_64 Cache Management
//!
//! This module provides cache management functions for DMA operations.
//! These are essential when the CPU and hardware devices (like USB controllers)
//! share memory regions.

use core::sync::atomic::{Ordering, fence};

/// Cache line size (typically 64 bytes on modern x86)
pub const CACHE_LINE_SIZE: usize = 64;

/// Flush a memory range from CPU cache to main memory
///
/// This ensures that DMA-capable devices see the data written by the CPU.
/// Uses the CLFLUSH instruction to write back and invalidate cache lines.
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
                "clflush [{}]",
                in(reg) line,
                options(nostack, preserves_flags)
            );
        }
    }
    // Memory fence to ensure flushes complete before continuing
    fence(Ordering::SeqCst);
}

/// Invalidate a memory range in CPU cache
///
/// This ensures the CPU sees data written by DMA-capable devices.
/// On x86, CLFLUSH both writes back and invalidates, so we use the same
/// instruction as flush_cache_range.
///
/// # Arguments
///
/// * `addr` - Starting address of the memory range
/// * `size` - Size of the memory range in bytes
#[inline]
pub fn invalidate_cache_range(addr: u64, size: usize) {
    flush_cache_range(addr, size);
}

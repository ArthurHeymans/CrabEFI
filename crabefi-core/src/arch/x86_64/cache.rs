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

    // Memory fence before loop for proper CLFLUSH ordering on older AMD processors
    fence(Ordering::SeqCst);

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

/// Synchronize before reading a DMA-written memory range.
///
/// x86 cache coherency makes device writes visible to CPU loads without an
/// explicit invalidation instruction. Do not use `CLFLUSH` here: it is a
/// write-back invalidate operation, so polling code can race a device DMA
/// update and write an older CPU cache line back over the device's completion
/// status. A full fence is sufficient to order subsequent descriptor reads.
///
/// # Arguments
///
/// * `_addr` - Starting address of the memory range
/// * `_size` - Size of the memory range in bytes
#[inline]
pub fn invalidate_cache_range(_addr: u64, _size: usize) {
    fence(Ordering::SeqCst);
}

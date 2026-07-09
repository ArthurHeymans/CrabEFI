//! RISC-V Cache Management
//!
//! RISC-V cache management is relatively simple compared to ARM:
//! - `fence.i` ensures instruction fetch coherence
//! - `fence` (with appropriate ordering bits) ensures memory ordering
//!
//! The base ISA does not have cache-line flush/invalidate instructions.
//! The Zicbom extension adds `cbo.clean`, `cbo.flush`, `cbo.inval` but
//! is optional. For QEMU virt (which is cache-coherent), simple fences
//! are sufficient.

use crate::barrier;

/// Cache line size (64 bytes is typical for RISC-V implementations).
pub const CACHE_LINE_SIZE: usize = 64;

/// Flush (clean) a memory range from CPU cache to main memory.
///
/// On RISC-V without Zicbom, this is a full fence which ensures all
/// prior stores are visible to DMA / other harts.
#[inline]
pub fn flush_cache_range(_addr: u64, _size: usize) {
    barrier::dma_write();
}

/// Invalidate a memory range in CPU cache.
///
/// On RISC-V without Zicbom, this is a full fence.
#[inline]
pub fn invalidate_cache_range(_addr: u64, _size: usize) {
    barrier::dma_read();
}

/// Instruction fence — ensure subsequent instruction fetches see
/// stores that have already completed.
#[inline]
pub fn fence_i() {
    unsafe {
        core::arch::asm!("fence.i", options(nostack, preserves_flags));
    }
}

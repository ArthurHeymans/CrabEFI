//! RISC-V cache synchronization.
//!
//! Base RISC-V fences order memory but do not clean or invalidate cache data.
//! Until Zicbom is discovered and configured, explicitly non-coherent DMA must
//! fail closed. Existing QEMU-virt paths use coherent DMA and need ordering only.

use crate::arch::{DmaCacheOperation, DmaSyncError};

/// Reject non-coherent device ownership without a cache-block mechanism.
#[inline]
pub fn sync_for_device(
    _addr: u64,
    _size: usize,
    _operation: DmaCacheOperation,
) -> Result<(), DmaSyncError> {
    Err(DmaSyncError::Unsupported)
}

/// Reject non-coherent CPU ownership without a cache-block mechanism.
#[inline]
pub fn sync_for_cpu(
    _addr: u64,
    _size: usize,
    _operation: DmaCacheOperation,
) -> Result<(), DmaSyncError> {
    Err(DmaSyncError::Unsupported)
}

/// Compatibility ordering for existing coherent DMA submission paths.
#[inline]
pub fn flush_cache_range(_addr: u64, _size: usize) {
    crate::barrier::publish_to_device();
}

/// Compatibility ordering for existing coherent DMA completion paths.
#[inline]
pub fn invalidate_cache_range(_addr: u64, _size: usize) {
    crate::barrier::consume_from_device();
}

/// Instruction fence — ensure subsequent instruction fetches see completed stores.
#[inline]
pub fn fence_i() {
    unsafe {
        core::arch::asm!("fence.i", options(nostack, preserves_flags));
    }
}

/// Synchronize instruction fetch with freshly written code on this hart.
///
/// `fence.i` is the architecturally required operation. As with the DMA
/// paths above, a non-coherent data cache would additionally need Zicbom
/// cleans, which are not discovered yet; coherent implementations (QEMU
/// virt included) are fully covered by the fence.
#[inline]
pub fn sync_instruction_cache(_addr: u64, _size: usize) {
    fence_i();
}

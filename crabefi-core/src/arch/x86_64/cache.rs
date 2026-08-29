//! x86_64 DMA cache synchronization.
//!
//! Normal PCI DMA is hardware coherent on x86. Ownership transitions therefore
//! need ordering, not cache eviction; in particular, unconditional `clflush`
//! can discard useful data and is not a substitute for DMA ownership rules.

use crate::arch::{DmaCacheOperation, DmaSyncError};

/// Order writes before transferring ownership to a coherent device.
#[inline]
pub fn sync_for_device(
    _addr: u64,
    _size: usize,
    _operation: DmaCacheOperation,
) -> Result<(), DmaSyncError> {
    crate::barrier::publish_to_device();
    Ok(())
}

/// Order reads after a coherent device returns ownership to the CPU.
#[inline]
pub fn sync_for_cpu(
    _addr: u64,
    _size: usize,
    _operation: DmaCacheOperation,
) -> Result<(), DmaSyncError> {
    crate::barrier::consume_from_device();
    Ok(())
}

/// Compatibility helper for existing coherent DMA submission paths.
#[inline]
pub fn flush_cache_range(_addr: u64, _size: usize) {
    crate::barrier::publish_to_device();
}

/// Compatibility helper for existing coherent DMA completion paths.
#[inline]
pub fn invalidate_cache_range(_addr: u64, _size: usize) {
    crate::barrier::consume_from_device();
}

/// Compatibility helper for bidirectional coherent DMA paths.
#[inline]
pub fn clean_invalidate_cache_range(_addr: u64, _size: usize) {
    crate::barrier::publish_to_device();
    crate::barrier::consume_from_device();
}

//! Architecture-specific code
//!
//! This module provides arch-agnostic re-exports for functionality that
//! has different implementations per architecture. Code outside `arch/`
//! should use these re-exports rather than referencing a specific arch
//! module directly.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

// Arch-agnostic re-exports
#[cfg(target_arch = "x86_64")]
pub use x86_64::halt;
#[cfg(target_arch = "x86_64")]
pub use x86_64::reset;
#[cfg(target_arch = "x86_64")]
pub use x86_64::rng;

#[cfg(target_arch = "aarch64")]
pub use aarch64::halt;
#[cfg(target_arch = "aarch64")]
pub use aarch64::reset;
#[cfg(target_arch = "aarch64")]
pub use aarch64::rng;

#[cfg(target_arch = "riscv64")]
pub use riscv64::halt;
#[cfg(target_arch = "riscv64")]
pub use riscv64::reset;
#[cfg(target_arch = "riscv64")]
pub use riscv64::rng;

/// Cache operation required for a non-coherent DMA ownership transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaCacheOperation {
    /// Write dirty CPU cache lines back to the point of coherency.
    Clean,
    /// Discard CPU cache lines so subsequent loads observe device writes.
    Invalidate,
    /// Write back and discard cache lines for bidirectional ownership.
    CleanInvalidate,
}

/// Architecture DMA synchronization failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaSyncError {
    /// The architecture has no discovered cache-maintenance mechanism.
    Unsupported,
    /// The requested range overflowed while being aligned.
    InvalidRange,
}

/// Compatibility cache synchronization before existing DMA submission paths.
#[inline]
pub fn flush_cache_range(addr: u64, size: usize) {
    #[cfg(target_arch = "x86_64")]
    x86_64::cache::flush_cache_range(addr, size);
    #[cfg(target_arch = "aarch64")]
    aarch64::cache::flush_cache_range(addr, size);
    #[cfg(target_arch = "riscv64")]
    riscv64::cache::flush_cache_range(addr, size);
}

/// Compatibility cache synchronization after existing DMA completion paths.
#[inline]
pub fn invalidate_cache_range(addr: u64, size: usize) {
    #[cfg(target_arch = "x86_64")]
    x86_64::cache::invalidate_cache_range(addr, size);
    #[cfg(target_arch = "aarch64")]
    aarch64::cache::invalidate_cache_range(addr, size);
    #[cfg(target_arch = "riscv64")]
    riscv64::cache::invalidate_cache_range(addr, size);
}

/// Perform non-coherent cache maintenance before device ownership.
#[inline]
pub fn dma_cache_for_device(
    addr: u64,
    size: usize,
    operation: DmaCacheOperation,
) -> Result<(), DmaSyncError> {
    #[cfg(target_arch = "x86_64")]
    return x86_64::cache::sync_for_device(addr, size, operation);
    #[cfg(target_arch = "aarch64")]
    return aarch64::cache::sync_for_device(addr, size, operation);
    #[cfg(target_arch = "riscv64")]
    return riscv64::cache::sync_for_device(addr, size, operation);
}

/// Perform non-coherent cache maintenance after CPU ownership resumes.
#[inline]
pub fn dma_cache_for_cpu(
    addr: u64,
    size: usize,
    operation: DmaCacheOperation,
) -> Result<(), DmaSyncError> {
    #[cfg(target_arch = "x86_64")]
    return x86_64::cache::sync_for_cpu(addr, size, operation);
    #[cfg(target_arch = "aarch64")]
    return aarch64::cache::sync_for_cpu(addr, size, operation);
    #[cfg(target_arch = "riscv64")]
    return riscv64::cache::sync_for_cpu(addr, size, operation);
}

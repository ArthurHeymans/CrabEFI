//! Hardware memory barriers used by CrabEFI's DMA and MMIO handoffs.
//!
//! Keeping the barrier policy here makes the distinction between ordinary
//! atomic synchronization and ordering visible to devices explicit at call
//! sites. Cache maintenance remains the responsibility of the architecture
//! cache modules; these helpers only order accesses around that maintenance.

use mem_barrier::{BarrierKind, BarrierType, mem_barrier};

/// Publish CPU writes before transferring ownership to a DMA-capable device.
#[inline]
pub fn publish_to_device() {
    mem_barrier(BarrierKind::Dma, BarrierType::Write);
}

/// Consume memory after a DMA-capable device has transferred ownership to the CPU.
#[inline]
pub fn consume_from_device() {
    mem_barrier(BarrierKind::Dma, BarrierType::Read);
}

/// Compatibility alias for existing DMA completion paths.
#[inline]
pub fn dma_read() {
    consume_from_device();
}

/// Compatibility alias for existing DMA submission paths.
#[inline]
pub fn dma_write() {
    publish_to_device();
}

/// Order writes before notifying a device through MMIO.
#[inline]
pub fn mmio_write() {
    mem_barrier(BarrierKind::Mmio, BarrierType::Write);
}

/// Order both reads and writes across an MMIO handoff.
#[cfg(target_arch = "riscv64")]
#[inline]
pub fn mmio_general() {
    mem_barrier(BarrierKind::Mmio, BarrierType::General);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_hardware_barrier_helpers_are_callable() {
        publish_to_device();
        consume_from_device();
        dma_read();
        dma_write();
        mmio_write();
        #[cfg(target_arch = "riscv64")]
        mmio_general();
    }
}

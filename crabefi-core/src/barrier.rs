//! Hardware memory barriers used by CrabEFI's DMA and MMIO handoffs.
//!
//! Keeping the barrier policy here makes the distinction between ordinary
//! atomic synchronization and ordering visible to devices explicit at call
//! sites. Cache maintenance remains the responsibility of the architecture
//! cache modules; these helpers only order accesses around that maintenance.

use mem_barrier::{BarrierKind, BarrierType, mem_barrier};

/// Order CPU reads of memory owned or updated by a DMA-capable device.
#[inline]
pub fn dma_read() {
    mem_barrier(BarrierKind::Dma, BarrierType::Read);
}

/// Order CPU writes before transferring ownership to a DMA-capable device.
#[inline]
pub fn dma_write() {
    mem_barrier(BarrierKind::Dma, BarrierType::Write);
}

/// Order writes before notifying a device through MMIO.
#[inline]
pub fn mmio_write() {
    mem_barrier(BarrierKind::Mmio, BarrierType::Write);
}

/// Order both reads and writes across an MMIO handoff.
#[inline]
pub fn mmio_general() {
    mem_barrier(BarrierKind::Mmio, BarrierType::General);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_hardware_barrier_helpers_are_callable() {
        dma_read();
        dma_write();
        mmio_write();
        mmio_general();
    }
}

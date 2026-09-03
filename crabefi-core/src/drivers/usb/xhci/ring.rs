//! xHCI transfer/event ring buffer.

use super::RawTrb;
use crate::barrier;
use core::ptr;
use xhci::ring::trb::{self, Link};

/// Ring buffer for TRBs
pub struct TrbRing {
    /// Base address of the ring
    pub(super) base: u64,
    /// Current enqueue pointer index
    pub(super) enqueue_idx: usize,
    /// Current dequeue pointer index
    pub(super) dequeue_idx: usize,
    /// Number of TRBs in the ring
    pub(super) size: usize,
    /// Current cycle bit
    pub(super) cycle: bool,
}

impl TrbRing {
    /// Create an empty/uninitialized TrbRing (for placeholder use)
    pub(super) const fn empty() -> Self {
        Self {
            base: 0,
            enqueue_idx: 0,
            dequeue_idx: 0,
            size: 0,
            cycle: true,
        }
    }

    /// Create a new command/transfer ring with a link TRB at the end
    pub(super) fn new(base: u64, size: usize) -> Self {
        if size == 0 {
            return Self::empty();
        }

        // Initialize all TRBs to 0
        unsafe { core::slice::from_raw_parts_mut(base as *mut u8, size * 16).fill(0) };

        // Set up the upstream Link TRB at the end to wrap around.
        let mut link = Link::new();
        link.set_ring_segment_pointer(base).set_toggle_cycle();
        let link_addr = (base + ((size - 1) * trb::BYTES) as u64) as *mut RawTrb;
        // SAFETY: the ring allocation contains `size` TRBs.
        unsafe { ptr::write(link_addr, link.into_raw()) };

        Self {
            base,
            enqueue_idx: 0,
            dequeue_idx: 0,
            size,
            cycle: true,
        }
    }

    /// Create a new event ring (no link TRB, consumer-side cycle tracking)
    pub(super) fn new_event_ring(base: u64, size: usize) -> Self {
        if size == 0 {
            return Self::empty();
        }

        // Initialize all TRBs to 0 (cycle bits = 0)
        // Hardware will write with cycle = 1 initially
        unsafe { core::slice::from_raw_parts_mut(base as *mut u8, size * 16).fill(0) };

        Self {
            base,
            enqueue_idx: 0,
            dequeue_idx: 0,
            size,
            cycle: true, // Expect cycle = 1 from hardware initially
        }
    }

    /// Enqueue a TRB onto the ring.
    ///
    /// Writes are ordered per the xHCI spec: param and status are written first,
    /// then a write barrier, then control (which contains the cycle bit). This
    /// ensures the HC sees complete TRB data when it checks the cycle bit.
    ///
    /// If `defer_cycle` is true, the TRB is written with an **inverted** cycle bit.
    /// The caller must later call `commit_deferred_trb()` to flip it live. This
    /// implements the "deferred first TRB" technique to prevent the HC from
    /// processing a partially-built multi-TRB TD.
    pub(super) fn enqueue<T: Into<RawTrb>>(&mut self, trb: T, defer_cycle: bool) -> u64 {
        let raw = trb.into();
        let addr = self.base + (self.enqueue_idx * trb::BYTES) as u64;
        let entry = addr as *mut u32;

        let cycle_bit = u32::from(if defer_cycle { !self.cycle } else { self.cycle });

        // Preserve CrabEFI's publication policy: parameter and status first.
        unsafe {
            ptr::write_volatile(
                entry as *mut u64,
                u64::from(raw[0]) | (u64::from(raw[1]) << 32),
            );
            ptr::write_volatile(entry.add(2), raw[2]);
        }
        barrier::dma_write();
        // Publish ownership through the cycle-bearing control dword last.
        unsafe { ptr::write_volatile(entry.add(3), (raw[3] & !1) | cycle_bit) };

        self.enqueue_idx += 1;

        if self.enqueue_idx >= self.size - 1 {
            let link_control = (self.base + ((self.size - 1) * trb::BYTES + 12) as u64) as *mut u32;
            barrier::dma_write();
            let control = unsafe { ptr::read_volatile(link_control) };
            unsafe {
                ptr::write_volatile(
                    link_control,
                    if self.cycle {
                        control | 1
                    } else {
                        control & !1
                    },
                )
            };
            barrier::dma_write();

            self.enqueue_idx = 0;
            self.cycle = !self.cycle;
        }

        addr
    }

    /// Commit a deferred TRB by flipping its cycle bit to the correct value.
    ///
    /// This is the second half of the "deferred first TRB" technique. After all
    /// TRBs in a TD have been enqueued, call this on the first TRB's address
    /// (returned by `enqueue(..., defer_cycle=true)`) to atomically make the
    /// entire TD visible to the HC.
    ///
    /// The `cycle_at_enqueue` parameter is the ring's cycle state at the time
    /// the deferred TRB was enqueued.
    pub(super) fn commit_deferred_trb(trb_addr: u64, cycle_at_enqueue: bool) {
        let control_ptr = (trb_addr + 12) as *mut u32;

        // Ensure the whole TD is visible before publishing its first TRB.
        barrier::dma_write();

        let control = unsafe { ptr::read_volatile(control_ptr) };
        let new_control = if cycle_at_enqueue {
            control | 1
        } else {
            control & !1
        };
        unsafe { ptr::write_volatile(control_ptr, new_control) };
    }
}

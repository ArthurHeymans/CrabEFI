//! Pure NVMe queue, namespace, timeout, and PRP calculations.

/// Maximum number of commands tracked by the polling driver per queue.
pub const MAX_TRACKED_COMMANDS: usize = 64;

/// One pending NVMe command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingCommand {
    /// Command identifier assigned to the submission.
    pub cid: u16,
    /// Whether the original waiter expired before completion.
    pub timed_out: bool,
}

/// Pure queue bookkeeping for one NVMe submission/completion queue pair.
#[derive(Debug)]
pub struct QueueState {
    /// Actual controller-supported queue depth.
    pub depth: u16,
    /// Submission queue head last reported by a completion.
    pub sq_head: u16,
    /// Next submission queue slot.
    pub sq_tail: u16,
    /// Next completion queue entry.
    pub cq_head: u16,
    /// Expected completion phase.
    pub cq_phase: bool,
    next_cid: u16,
    pending: [Option<PendingCommand>; MAX_TRACKED_COMMANDS],
}

impl QueueState {
    /// Construct empty queue state for a validated depth.
    pub const fn new(depth: u16) -> Self {
        Self {
            depth,
            sq_head: 0,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: true,
            next_cid: 0,
            pending: [None; MAX_TRACKED_COMMANDS],
        }
    }

    /// Number of commands that have been submitted but not completed.
    pub fn pending_count(&self) -> usize {
        self.pending.iter().flatten().count()
    }

    /// Return the tracked pending commands.
    pub fn pending(&self) -> impl Iterator<Item = PendingCommand> + '_ {
        self.pending.iter().flatten().copied()
    }

    /// Reserve a collision-free CID and submission slot.
    pub fn reserve(&mut self) -> Option<(u16, u16)> {
        if self.depth < 2
            || self.depth as usize > MAX_TRACKED_COMMANDS
            || self.pending_count() >= self.depth as usize - 1
            || advance_index(self.sq_tail, self.depth) == self.sq_head
        {
            return None;
        }
        let cid = (0..=u16::MAX).find_map(|_| {
            let candidate = self.next_cid;
            self.next_cid = self.next_cid.wrapping_add(1);
            (!self
                .pending
                .iter()
                .flatten()
                .any(|entry| entry.cid == candidate))
            .then_some(candidate)
        })?;
        let pending = self.pending.iter_mut().find(|entry| entry.is_none())?;
        *pending = Some(PendingCommand {
            cid,
            timed_out: false,
        });
        let slot = self.sq_tail;
        self.sq_tail = advance_index(self.sq_tail, self.depth);
        Some((cid, slot))
    }

    /// Mark the command as timed out without freeing its CID or queue capacity.
    pub fn mark_timed_out(&mut self, cid: u16) -> bool {
        if let Some(entry) = self
            .pending
            .iter_mut()
            .flatten()
            .find(|entry| entry.cid == cid)
        {
            entry.timed_out = true;
            true
        } else {
            false
        }
    }

    /// Return whether a completion can safely update this queue's state.
    pub fn accepts_completion(&self, cid: u16, sq_head: u16) -> bool {
        sq_head < self.depth
            && self
                .pending
                .iter()
                .flatten()
                .any(|pending| pending.cid == cid)
    }

    /// Retire a completed CID and record controller-reported SQ progress.
    pub fn retire(&mut self, cid: u16, sq_head: u16) -> Option<PendingCommand> {
        if !self.accepts_completion(cid, sq_head) {
            return None;
        }
        self.sq_head = sq_head;
        let entry = self
            .pending
            .iter_mut()
            .find(|entry| entry.is_some_and(|pending| pending.cid == cid))?;
        entry.take()
    }

    /// Advance the completion head and toggle phase on wrap.
    pub fn advance_cq(&mut self) {
        self.cq_head = advance_index(self.cq_head, self.depth);
        if self.cq_head == 0 {
            self.cq_phase = !self.cq_phase;
        }
    }
}

/// Return whether a controller capability range accepts CrabEFI's 4 KiB page.
pub const fn supports_4k_page(mps_min: u8, mps_max: u8) -> bool {
    mps_min == 0 && mps_min <= mps_max
}

/// Clamp a desired queue depth to CAP.MQES + 1 and the tracker capacity.
pub const fn effective_queue_depth(driver_limit: u16, mqes_zero_based: u16) -> u16 {
    let controller_limit = mqes_zero_based.saturating_add(1);
    let limit = if driver_limit < controller_limit {
        driver_limit
    } else {
        controller_limit
    };
    if limit < MAX_TRACKED_COMMANDS as u16 {
        limit
    } else {
        MAX_TRACKED_COMMANDS as u16
    }
}

/// Advance a ring index for a nonzero depth.
pub const fn advance_index(index: u16, depth: u16) -> u16 {
    if index + 1 == depth { 0 } else { index + 1 }
}

/// Decode and validate one namespace LBA format.
pub const fn decode_lba_size(flbas: u8, nlbaf: u8, formats: &[u32; 16]) -> Option<u32> {
    let index = (flbas & 0x0f) as usize;
    // This IdentifyNamespace representation contains only LBAF 0..15. Reject
    // the NVMe 2.x upper format-index bits rather than aliasing formats 16..63.
    if index > nlbaf as usize || index >= formats.len() || flbas & 0x70 != 0 {
        return None;
    }
    let format = formats[index];
    let metadata_size = format as u16;
    let exponent = (format >> 16) & 0xff;
    if metadata_size != 0 || exponent < 9 || exponent > 31 {
        return None;
    }
    1u32.checked_shl(exponent)
}

/// Maximum bytes addressable by PRP1 plus one PRP-list page.
pub const fn max_prp_transfer(page_size: usize) -> Option<usize> {
    page_size.checked_mul(1 + page_size / 8)
}

/// Return a progressing sector chunk bounded by the staging allocation and NLB field.
pub const fn sectors_per_chunk(block_size: usize, staging_len: usize) -> Option<u32> {
    if block_size == 0 || staging_len < block_size {
        return None;
    }
    let sectors = staging_len / block_size;
    Some(if sectors > 65536 {
        65536
    } else {
        sectors as u32
    })
}

/// PRP pointers for an aligned contiguous transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrpPointers {
    /// First data page.
    pub prp1: u64,
    /// Zero, the second data page, or the PRP-list page.
    pub prp2: u64,
    /// Number of entries written to the PRP list.
    pub list_entries: usize,
}

/// Build PRP pointers for a page-aligned contiguous staging buffer.
pub fn build_prps(
    data_address: u64,
    transfer_len: usize,
    page_size: usize,
    prp_list_address: u64,
    prp_list: &mut [u64],
) -> Option<PrpPointers> {
    if transfer_len == 0
        || page_size == 0
        || !page_size.is_power_of_two()
        || !data_address.is_multiple_of(page_size as u64)
        || !prp_list_address.is_multiple_of(page_size as u64)
    {
        return None;
    }
    prp_list.fill(0);
    let pages = transfer_len.checked_add(page_size - 1)? / page_size;
    if pages == 1 {
        return Some(PrpPointers {
            prp1: data_address,
            prp2: 0,
            list_entries: 0,
        });
    }
    let second = data_address.checked_add(page_size as u64)?;
    if pages == 2 {
        return Some(PrpPointers {
            prp1: data_address,
            prp2: second,
            list_entries: 0,
        });
    }
    let entries = pages - 1;
    if entries > prp_list.len() {
        return None;
    }
    for (index, entry) in prp_list[..entries].iter_mut().enumerate() {
        let offset = index.checked_mul(page_size)?;
        *entry = second.checked_add(offset as u64)?;
    }
    Some(PrpPointers {
        prp1: data_address,
        prp2: prp_list_address,
        list_entries: entries,
    })
}

/// Convert CAP.TO units to a nonzero millisecond controller timeout.
pub const fn cap_timeout_ms(cap_to: u64) -> u64 {
    if cap_to == 0 { 500 } else { cap_to * 500 }
}

/// Convert CRTO units to milliseconds while retaining the CAP.TO minimum.
pub const fn ready_timeout_ms(cap_to: u64, crto: Option<u64>) -> u64 {
    let cap = cap_timeout_ms(cap_to);
    match crto {
        Some(units) if units != 0 && units.saturating_mul(500) > cap => units.saturating_mul(500),
        _ => cap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_wrap_phase_timeout_and_collision_safety() {
        let mut queue = QueueState::new(4);
        let (late, _) = queue.reserve().expect("test fixture should be valid");
        let (requested, _) = queue.reserve().expect("test fixture should be valid");
        let (other, _) = queue.reserve().expect("test fixture should be valid");
        assert!(queue.reserve().is_none());
        assert!(queue.mark_timed_out(late));
        let original_head = queue.sq_head;
        assert!(!queue.accepts_completion(u16::MAX, 1));
        assert!(!queue.accepts_completion(late, queue.depth));
        assert!(queue.retire(u16::MAX, 1).is_none());
        assert!(queue.retire(late, queue.depth).is_none());
        assert_eq!(queue.sq_head, original_head);

        // A poll batch must be able to retire a stale completion before the
        // requested CID and continue through another completion after it.
        let completions = [(late, 1), (requested, 2), (other, 3)];
        let mut found_requested = false;
        for (cid, sq_head) in completions {
            let retired = queue
                .retire(cid, sq_head)
                .expect("test fixture should be valid");
            found_requested |= retired.cid == requested;
            queue.advance_cq();
        }
        assert!(found_requested);
        assert_eq!(queue.pending_count(), 0);
        assert_eq!((queue.cq_head, queue.cq_phase), (3, true));
        queue.advance_cq();
        assert_eq!((queue.cq_head, queue.cq_phase), (0, false));
    }

    #[test]
    fn mqes_mps_and_lba_validation() {
        assert!(supports_4k_page(0, 0));
        assert!(supports_4k_page(0, 15));
        assert!(!supports_4k_page(1, 1));
        assert!(!supports_4k_page(2, 1));
        assert_eq!(effective_queue_depth(64, 0), 1);
        assert_eq!(effective_queue_depth(64, 7), 8);
        assert_eq!(effective_queue_depth(128, u16::MAX), 64);
        let mut formats = [0u32; 16];
        formats[0] = 12 << 16;
        assert_eq!(decode_lba_size(0, 0, &formats), Some(4096));
        formats[0] = 8 << 16;
        assert_eq!(decode_lba_size(0, 0, &formats), None);
        formats[0] = (12 << 16) | 8;
        assert_eq!(decode_lba_size(0, 0, &formats), None);
        assert_eq!(decode_lba_size(1, 0, &formats), None);
        formats[0] = 12 << 16;
        assert_eq!(decode_lba_size(0x20, 0, &formats), None);
        assert_eq!(decode_lba_size(0x40, 0, &formats), None);
    }

    #[test]
    fn prps_cover_4_to_16k_and_reject_overflow() {
        let mut list = [0u64; 512];
        let base = 0x1000_0000;
        let list_base = 0x2000_0000;
        assert_eq!(
            build_prps(base, 4096, 4096, list_base, &mut list)
                .expect("test fixture should be valid"),
            PrpPointers {
                prp1: base,
                prp2: 0,
                list_entries: 0
            }
        );
        assert_eq!(
            build_prps(base, 8192, 4096, list_base, &mut list)
                .expect("test fixture should be valid")
                .prp2,
            base + 4096
        );
        let twelve = build_prps(base, 12288, 4096, list_base, &mut list)
            .expect("test fixture should be valid");
        assert_eq!(
            (twelve.prp2, twelve.list_entries, list[0], list[1]),
            (list_base, 2, base + 4096, base + 8192)
        );
        let sixteen = build_prps(base, 16384, 4096, list_base, &mut list)
            .expect("test fixture should be valid");
        assert_eq!((sixteen.list_entries, list[2]), (3, base + 12288));
        assert!(build_prps(u64::MAX - 4095, 8192, 4096, list_base, &mut list).is_none());
        assert!(build_prps(base, 12288, 4096, list_base, &mut list[..1]).is_none());
        assert_eq!(sectors_per_chunk(8192, 8192), Some(1));
    }

    #[test]
    fn timeout_conversions_are_bounded() {
        assert_eq!(cap_timeout_ms(0), 500);
        assert_eq!(cap_timeout_ms(4), 2000);
        assert_eq!(ready_timeout_ms(4, Some(8)), 4000);
        assert_eq!(ready_timeout_ms(4, Some(1)), 2000);
    }
}

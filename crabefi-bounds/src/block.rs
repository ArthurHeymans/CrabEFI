//! Checked block-address arithmetic shared by storage protocols.

/// Validate a relative block range and translate it to an absolute LBA.
///
/// # Arguments
/// * `start_lba` - Absolute start of the exposed device or partition.
/// * `lba` - Caller-provided LBA relative to `start_lba`.
/// * `num_blocks` - Number of blocks requested.
/// * `total_blocks` - Number of blocks exposed by the protocol instance.
///
/// # Returns
/// The absolute starting LBA, or `None` when the absolute range does not fit
/// in a `u64` or the requested range extends beyond the exposed device.
pub fn checked_absolute_lba(
    start_lba: u64,
    lba: u64,
    num_blocks: u64,
    total_blocks: u64,
) -> Option<u64> {
    let end_lba = lba.checked_add(num_blocks)?;
    if end_lba > total_blocks {
        return None;
    }
    let absolute = start_lba.checked_add(lba)?;
    // The last requested block must be addressable, not only the first. The
    // exclusive end may be 2^64: a range can end at the last LBA.
    if num_blocks > 0 {
        absolute.checked_add(num_blocks - 1)?;
    }
    Some(absolute)
}

#[cfg(test)]
mod tests {
    use super::checked_absolute_lba;

    #[test]
    fn accepts_range_ending_at_device_boundary() {
        assert_eq!(checked_absolute_lba(100, 8, 2, 10), Some(108));
    }

    #[test]
    fn rejects_relative_range_overflow() {
        assert_eq!(checked_absolute_lba(0, u64::MAX - 1, 4, u64::MAX), None);
    }

    #[test]
    fn rejects_absolute_lba_overflow() {
        assert_eq!(checked_absolute_lba(u64::MAX - 4, 8, 1, 16), None);
    }

    #[test]
    fn accepts_the_last_addressable_block() {
        assert_eq!(checked_absolute_lba(u64::MAX, 0, 1, 1), Some(u64::MAX));
        assert_eq!(checked_absolute_lba(u64::MAX, 0, 2, 2), None);
    }

    #[test]
    fn rejects_range_past_device_boundary() {
        assert_eq!(checked_absolute_lba(100, 9, 2, 10), None);
    }
}

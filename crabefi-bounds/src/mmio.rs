//! Dependency-free MMIO bounds and alignment checks.

/// Validate a half-open access within a region.
pub fn checked_access(
    region_base: u64,
    region_size: usize,
    offset: u64,
    width: usize,
    alignment: usize,
) -> Option<usize> {
    if width == 0 || alignment == 0 || !alignment.is_power_of_two() {
        return None;
    }
    let Ok(offset) = usize::try_from(offset) else {
        return None;
    };
    let address = region_base.checked_add(offset as u64)?;
    if !address.is_multiple_of(alignment as u64) {
        return None;
    }
    match offset.checked_add(width) {
        Some(end) if end <= region_size => Some(offset),
        _ => None,
    }
}

/// Validate construction of the half-open address range `[base, base + size)`.
pub fn checked_region(base: u64, size: usize) -> Option<u64> {
    if base == 0 || size == 0 {
        return None;
    }
    base.checked_add(size as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_last_valid_access() {
        assert_eq!(checked_access(0x8000, 0x1000, 0xffc, 4, 4), Some(0xffc));
        assert_eq!(checked_access(0x8000, 0x1000, 0xff8, 8, 8), Some(0xff8));
    }

    #[test]
    fn rejects_end_straddles_misalignment_and_overflow() {
        assert_eq!(checked_access(0x8000, 0x1000, 0x1000, 1, 1), None);
        assert_eq!(checked_access(0x8000, 0x1000, 0xffe, 4, 4), None);
        assert_eq!(checked_access(0x8000, 0x1000, 3, 4, 4), None);
        assert_eq!(checked_access(u64::MAX, usize::MAX, 1, 8, 8), None);
    }

    #[test]
    fn validates_effective_address_alignment() {
        assert_eq!(checked_access(0x8001, 0x1000, 3, 4, 4), Some(3));
        assert_eq!(checked_access(0x8001, 0x1000, 4, 4, 4), None);
    }

    #[test]
    fn region_construction_rejects_empty_null_and_wrapping_ranges() {
        assert_eq!(checked_region(0, 0x1000), None);
        assert_eq!(checked_region(0x1000, 0), None);
        assert_eq!(checked_region(u64::MAX - 1, 4), None);
        assert_eq!(checked_region(0x1000, 0x1000), Some(0x2000));
    }
}

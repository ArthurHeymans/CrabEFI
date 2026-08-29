//! Dependency-free PCI configuration and ECAM bounds arithmetic.

/// Validate an aligned config-space access against an inclusive maximum offset.
pub const fn valid_config_access(max_offset: u16, offset: u16, width: u16) -> bool {
    if width == 0 || !width.is_power_of_two() || !offset.is_multiple_of(width) {
        return false;
    }
    matches!(offset.checked_add(width - 1), Some(last) if last <= max_offset)
}

/// Reject standard absent/error PCI vendor/device ID responses.
pub const fn valid_device_id(id: u32) -> bool {
    !matches!(id, 0xffff_ffff | 0x0000_0000 | 0x0000_ffff | 0xffff_0000)
}

/// Calculate an ECAM byte offset relative to a region's physical base.
pub const fn ecam_offset(
    region_segment: u16,
    bus_start: u8,
    bus_end: u8,
    segment: u16,
    bus: u8,
    device: u8,
    function: u8,
    offset: u16,
    width: u16,
) -> Option<u64> {
    if segment != region_segment
        || bus < bus_start
        || bus > bus_end
        || device >= 32
        || function >= 8
        || !valid_config_access(4095, offset, width)
    {
        return None;
    }
    Some(
        ((bus - bus_start) as u64) << 20
            | (device as u64) << 15
            | (function as u64) << 12
            | offset as u64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_bounds_cover_cam_and_ecam_edges() {
        assert!(valid_config_access(255, 252, 4));
        assert!(!valid_config_access(255, 254, 4));
        assert!(!valid_config_access(255, 256, 4));
        assert!(!valid_config_access(4095, 4094, 4));
        assert!(valid_config_access(4095, 4092, 4));
        assert!(!valid_config_access(4095, 3, 4));
    }

    #[test]
    fn rejects_absent_and_half_invalid_device_ids() {
        assert!(!valid_device_id(0xffff_ffff));
        assert!(!valid_device_id(0x0000_0000));
        assert!(!valid_device_id(0x0000_ffff));
        assert!(!valid_device_id(0xffff_0000));
        assert!(valid_device_id(0x1234_8086));
    }

    #[test]
    fn ecam_preserves_nonzero_bus_start_and_segment() {
        assert_eq!(
            ecam_offset(7, 0x40, 0x4f, 7, 0x40, 2, 1, 0x100, 4),
            Some((2 << 15) | (1 << 12) | 0x100)
        );
        assert_eq!(
            ecam_offset(7, 0x40, 0x4f, 7, 0x41, 0, 0, 0, 4),
            Some(1 << 20)
        );
        assert_eq!(ecam_offset(7, 0x40, 0x4f, 0, 0x40, 0, 0, 0, 4), None);
        assert_eq!(ecam_offset(7, 0x40, 0x4f, 7, 0x3f, 0, 0, 0, 4), None);
        assert_eq!(ecam_offset(7, 0x40, 0x4f, 7, 0x50, 0, 0, 0, 4), None);
    }
}

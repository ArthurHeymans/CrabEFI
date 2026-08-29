//! Dependency-free bounded PCI conventional-capability walking.

/// Maximum number of conventional capability nodes that can fit in config space.
pub const MAX_CAPABILITY_HOPS: usize = 48;

/// Select the header-specific conventional capability-pointer register.
pub const fn capability_pointer_offset(status: u16, header_type: u8) -> Option<u16> {
    if status & (1 << 4) == 0 {
        return None;
    }
    match header_type & 0x7f {
        0x00 | 0x01 => Some(0x34),
        0x02 => Some(0x14),
        _ => None,
    }
}

/// Walk a conventional capability chain beginning at `start`.
pub fn find_capability_from<F, E>(
    start: u8,
    target_id: u8,
    max_offset: u16,
    mut read: F,
) -> Result<Option<u8>, E>
where
    F: FnMut(u16) -> Result<u32, E>,
{
    let mut offset = start & !0x3;
    let mut visited = 0u64;

    for _ in 0..MAX_CAPABILITY_HOPS {
        if !(0x40..=0xfc).contains(&offset) || offset as u16 > max_offset.saturating_sub(3) {
            return Ok(None);
        }
        let bit = 1u64 << (offset / 4);
        if visited & bit != 0 {
            return Ok(None);
        }
        visited |= bit;

        let value = read(offset as u16)?;
        if value as u8 == target_id {
            return Ok(Some(offset));
        }
        let next = ((value >> 8) as u8) & !0x3;
        if next == 0 || next == offset {
            return Ok(None);
        }
        offset = next;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(entries: &[(u8, u32)], offset: u16) -> u32 {
        entries
            .iter()
            .find_map(|(entry_offset, value)| (*entry_offset as u16 == offset).then_some(*value))
            .unwrap_or(u32::MAX)
    }

    #[test]
    fn capability_pointer_requires_status_bit_and_known_header() {
        assert_eq!(capability_pointer_offset(0, 0), None);
        assert_eq!(capability_pointer_offset(1 << 4, 0), Some(0x34));
        assert_eq!(capability_pointer_offset(1 << 4, 1), Some(0x34));
        assert_eq!(capability_pointer_offset(1 << 4, 2), Some(0x14));
        assert_eq!(capability_pointer_offset(1 << 4, 3), None);
    }

    #[test]
    fn finds_node_and_masks_reserved_pointer_bits() {
        let entries = [(0x40, 0x0000_4501), (0x44, 0x0000_0010)];
        assert_eq!(
            find_capability_from(0x43, 0x10, 0xff, |o| Ok::<_, ()>(config(&entries, o))),
            Ok(Some(0x44))
        );
    }

    #[test]
    fn terminates_zero_self_and_multi_node_cycles() {
        assert_eq!(
            find_capability_from(0x40, 2, 0xff, |_| Ok::<_, ()>(1)),
            Ok(None)
        );
        assert_eq!(
            find_capability_from(0x40, 2, 0xff, |_| Ok::<_, ()>(0x0000_4001)),
            Ok(None)
        );
        let cycle = [(0x40, 0x0000_4401), (0x44, 0x0000_4001)];
        assert_eq!(
            find_capability_from(0x40, 2, 0xff, |o| Ok::<_, ()>(config(&cycle, o))),
            Ok(None)
        );
    }

    #[test]
    fn rejects_out_of_range_and_truncated_nodes() {
        assert_eq!(
            find_capability_from(0x3c, 1, 0xff, |_| Ok::<_, ()>(1)),
            Ok(None)
        );
        assert_eq!(
            find_capability_from(0xfc, 1, 0xfb, |_| Ok::<_, ()>(1)),
            Ok(None)
        );
    }

    #[test]
    fn propagates_config_access_failure() {
        assert_eq!(
            find_capability_from(0x40, 1, 0xff, |_| Err::<u32, _>("access")),
            Err("access")
        );
    }

    #[test]
    fn hop_limit_terminates_long_malformed_chains() {
        // There are exactly 48 representable dword nodes; a target absent from
        // a chain spanning all of them must terminate without another access.
        let mut reads = 0;
        assert_eq!(
            find_capability_from(0x40, 0xfe, 0xff, |offset| {
                reads += 1;
                let next = (offset + 4) as u8;
                Ok::<_, ()>(1 | ((next as u32) << 8))
            }),
            Ok(None)
        );
        assert_eq!(reads, MAX_CAPABILITY_HOPS);
    }
}

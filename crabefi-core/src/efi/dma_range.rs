//! Pure range arithmetic for page-backed DMA buffers.

use core::ops::Range;

/// Return the number of `page_size` pages needed for `byte_len` bytes.
pub const fn pages_for_len(byte_len: usize, page_size: u64) -> Option<u64> {
    if byte_len == 0 || page_size == 0 {
        return None;
    }
    match (byte_len as u64).checked_add(page_size - 1) {
        Some(rounded) => Some(rounded / page_size),
        None => None,
    }
}

/// Return whether every byte of a page allocation is visible through `mask`.
pub const fn allocation_fits_mask(base: u64, pages: u64, page_size: u64, mask: u64) -> bool {
    if pages == 0 || page_size == 0 {
        return false;
    }
    let Some(size) = pages.checked_mul(page_size) else {
        return false;
    };
    let Some(last_byte) = base.checked_add(size - 1) else {
        return false;
    };
    last_byte <= mask
}

/// Translate a complete CPU range through one half-open DMA window.
pub const fn translate_dma_range(
    cpu_address: u64,
    byte_len: u64,
    cpu_base: u64,
    device_base: u64,
    window_size: u64,
) -> Option<u64> {
    let Some(offset) = cpu_address.checked_sub(cpu_base) else {
        return None;
    };
    let Some(end) = offset.checked_add(byte_len) else {
        return None;
    };
    if byte_len == 0 || end > window_size {
        return None;
    }
    device_base.checked_add(offset)
}

/// Validate a half-open subrange against a buffer length.
pub const fn checked_subrange(range: &Range<usize>, len: usize) -> Option<(usize, usize)> {
    if range.start > range.end || range.end > len {
        None
    } else {
        Some((range.start, range.end - range.start))
    }
}

/// Round a nonempty address range out to complete cache lines.
#[cfg_attr(not(target_arch = "aarch64"), allow(dead_code))]
pub const fn cache_line_range(addr: u64, size: usize, line_size: usize) -> Option<Range<u64>> {
    if size == 0 || line_size == 0 || !line_size.is_power_of_two() {
        return None;
    }
    let mask = line_size as u64 - 1;
    let start = addr & !mask;
    let end_unaligned = match addr.checked_add(size as u64) {
        Some(end) => end,
        None => return None,
    };
    let end = match end_unaligned.checked_add(mask) {
        Some(end) => end & !mask,
        None => return None,
    };
    Some(start..end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_count_rejects_zero_and_overflow() {
        assert_eq!(pages_for_len(0, 4096), None);
        assert_eq!(pages_for_len(1, 4096), Some(1));
        assert_eq!(pages_for_len(4097, 4096), Some(2));
        assert_eq!(pages_for_len(usize::MAX, 4096), None);
    }

    #[test]
    fn inclusive_dma_masks_cover_the_entire_allocation() {
        assert!(allocation_fits_mask(0xffff_f000, 1, 4096, 0xffff_ffff));
        assert!(!allocation_fits_mask(0xffff_f001, 1, 4096, 0xffff_ffff));
        assert!(allocation_fits_mask(0, 1, 4096, u64::MAX));
        assert!(!allocation_fits_mask(u64::MAX - 4095, 2, 4096, u64::MAX));
        assert!(!allocation_fits_mask(0, u64::MAX, 4096, u64::MAX));
        assert!(!allocation_fits_mask(0, 0, 4096, u64::MAX));
        assert!(!allocation_fits_mask(0, 1, 0, u64::MAX));
    }

    #[test]
    fn dma_translation_requires_the_complete_range() {
        assert_eq!(
            translate_dma_range(0x8000_1000, 0x1000, 0x8000_0000, 0x4000_0000, 0x20_0000),
            Some(0x4000_1000)
        );
        assert_eq!(
            translate_dma_range(0x7fff_f000, 0x1000, 0x8000_0000, 0x4000_0000, 0x20_0000),
            None
        );
        assert_eq!(
            translate_dma_range(0x801f_f000, 0x2000, 0x8000_0000, 0x4000_0000, 0x20_0000),
            None
        );
        assert_eq!(translate_dma_range(0, 0, 0, 0, u64::MAX), None);
    }

    #[test]
    fn subranges_are_half_open_and_bounded() {
        assert_eq!(checked_subrange(&(0..4096), 4096), Some((0, 4096)));
        assert_eq!(checked_subrange(&(4096..4096), 4096), Some((4096, 0)));
        assert_eq!(checked_subrange(&(4096..4097), 4096), None);
        assert_eq!(checked_subrange(&(2..1), 4096), None);
    }

    #[test]
    fn cache_ranges_handle_line_sizes_empty_and_overflow() {
        assert_eq!(cache_line_range(0x1041, 1, 64), Some(0x1040..0x1080));
        assert_eq!(cache_line_range(0x107f, 2, 64), Some(0x1040..0x10c0));
        assert_eq!(cache_line_range(0x1081, 127, 128), Some(0x1080..0x1100));
        assert_eq!(cache_line_range(0x1000, 0, 64), None);
        assert_eq!(cache_line_range(u64::MAX - 1, 4, 64), None);
        assert_eq!(cache_line_range(0x1000, 4, 96), None);
    }
}

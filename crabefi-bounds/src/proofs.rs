//! Each function against an independent specification over all inputs.
//!
//! Specifications use `u128`, where none of the arithmetic can overflow, so
//! they state the intended range directly instead of repeating the checked
//! `u64` operations under test.

use crate::{block, dma, mmio};

fn wide(value: u64) -> u128 {
    u128::from(value)
}

// Division by a symbolic page size is beyond the solver, and the firmware
// only uses 4 KiB pages, so the page size is fixed and the length is not.
#[kani::proof]
fn pages_cover_exactly_the_length() {
    const PAGE: u64 = 4096;
    let len: usize = kani::any();
    assert_eq!(dma::pages_for_len(len, 0), None);
    let pages = dma::pages_for_len(len, PAGE);
    // Accepted exactly when nonempty and rounding up to a page stays in `u64`.
    let fits = len > 0 && len as u128 + wide(PAGE) - 1 <= wide(u64::MAX);
    assert_eq!(pages.is_some(), fits);
    if let Some(pages) = pages {
        let (len, page, pages) = (len as u128, wide(PAGE), wide(pages));
        // Enough pages, and no spare one.
        assert!(pages * page >= len && (pages - 1) * page < len);
    }
}

#[kani::proof]
fn mask_admits_only_allocations_whose_last_byte_is_visible() {
    let (base, pages, page, mask): (u64, u64, u64, u64) = kani::any();
    let fits = dma::allocation_fits_mask(base, pages, page, mask);
    let size = wide(pages) * wide(page);
    let spec = size > 0 && size <= wide(u64::MAX) && wide(base) + size - 1 <= wide(mask);
    assert_eq!(fits, spec);
}

#[kani::proof]
fn dma_translation_maps_every_byte_into_the_window() {
    let (cpu, len, cpu_base, device_base, window): (u64, u64, u64, u64, u64) = kani::any();
    let translated = dma::translate_dma_range(cpu, len, cpu_base, device_base, window);
    // Every byte of the range, the last included, is addressable both as a
    // CPU address and after translation.
    let inside = len > 0
        && cpu >= cpu_base
        && wide(cpu) + wide(len) <= wide(cpu_base) + wide(window)
        && wide(cpu) + wide(len) - 1 <= wide(u64::MAX)
        && wide(device_base) + wide(cpu - cpu_base) + wide(len) - 1 <= wide(u64::MAX);
    assert_eq!(translated.is_some(), inside);
    if let Some(device) = translated {
        // The first byte keeps its offset; so does the last, which still
        // lies inside the device window.
        assert_eq!(wide(device) - wide(device_base), wide(cpu) - wide(cpu_base));
        assert!(wide(device) + wide(len) <= wide(device_base) + wide(window));
    }
}

#[kani::proof]
fn subrange_is_half_open_and_inside_the_buffer() {
    let (start, end, len): (usize, usize, usize) = kani::any();
    let result = dma::checked_subrange(&(start..end), len);
    assert_eq!(result.is_some(), start <= end && end <= len);
    if let Some((offset, count)) = result {
        assert_eq!(offset, start);
        assert_eq!(offset + count, end);
    }
}

#[kani::proof]
fn cache_maintenance_covers_the_buffer_and_at_most_one_extra_line_each_side() {
    let (addr, size, line): (u64, usize, usize) = kani::any();
    let range = dma::cache_line_range(addr, size, line);
    let valid = size > 0 && line > 0 && line.is_power_of_two();
    if !valid {
        assert!(range.is_none());
        return;
    }
    let (end, line) = (wide(addr) + size as u128, line as u128);
    match range {
        Some(range) => {
            let (start, stop) = (wide(range.start), wide(range.end));
            assert!(start % line == 0 && stop % line == 0);
            assert!(start <= wide(addr) && wide(addr) - start < line);
            assert!(stop >= end && stop - end < line);
        }
        // Only a range whose rounded end leaves the address space is refused.
        None => assert!(end.div_ceil(line) * line > wide(u64::MAX)),
    }
}

#[kani::proof]
fn block_range_stays_inside_the_device() {
    let (start, lba, blocks, total): (u64, u64, u64, u64) = kani::any();
    let absolute = block::checked_absolute_lba(start, lba, blocks, total);
    // The first and, for a nonempty request, the last block are addressable.
    let last = wide(start) + wide(lba) + wide(blocks.max(1)) - 1;
    let inside = wide(lba) + wide(blocks) <= wide(total) && last <= wide(u64::MAX);
    assert_eq!(absolute.is_some(), inside);
    if let Some(absolute) = absolute {
        assert_eq!(wide(absolute), wide(start) + wide(lba));
        // The last requested block is one the device exposes.
        assert!(wide(absolute) + wide(blocks) <= wide(start) + wide(total));
    }
}

#[kani::proof]
fn mmio_access_is_aligned_and_inside_the_region() {
    let (base, size, offset, width, alignment): (u64, usize, u64, usize, usize) = kani::any();
    let access = mmio::checked_access(base, size, offset, width, alignment);
    let inside = width > 0
        && alignment.is_power_of_two()
        && wide(offset) + width as u128 <= size as u128
        && wide(base) + wide(offset) <= wide(u64::MAX)
        && (wide(base) + wide(offset)) % alignment as u128 == 0;
    assert_eq!(access.is_some(), inside);
    if let Some(checked) = access {
        assert_eq!(checked as u64, offset);
        // Composed with a region `checked_region` accepted, the whole access
        // lies inside the address space.
        if mmio::checked_region(base, size).is_some() {
            assert!(wide(base) + wide(offset) + width as u128 <= wide(u64::MAX));
        }
    }
}

#[kani::proof]
fn mmio_region_is_nonempty_nonnull_and_does_not_wrap() {
    let (base, size): (u64, usize) = kani::any();
    let end = mmio::checked_region(base, size);
    let valid = base != 0 && size > 0 && wide(base) + size as u128 <= wide(u64::MAX);
    assert_eq!(end.is_some(), valid);
    if let Some(end) = end {
        assert_eq!(wide(end), wide(base) + size as u128);
    }
}

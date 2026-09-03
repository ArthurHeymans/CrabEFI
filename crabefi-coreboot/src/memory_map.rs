//! Coreboot platform memory-map transformations.
//!
//! The framebuffer overlay is independent from coreboot table parsing so its
//! interval handling can be exercised by host-side unit tests.

/// Region operations needed by the framebuffer overlay.
pub trait Region: Copy {
    /// Memory-type discriminator carried by the region.
    type Kind: Copy + Eq;

    /// Starting physical address.
    fn base(self) -> u64;
    /// Region size in bytes.
    fn size(self) -> u64;
    /// Memory type.
    fn kind(self) -> Self::Kind;
    /// Construct a region from its components.
    fn from_parts(base: u64, size: u64, kind: Self::Kind) -> Self;
}

/// Failure while overlaying an MMIO range on the platform memory map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlayError {
    /// The supplied map length exceeds its backing array.
    InvalidRegionCount,
    /// The framebuffer has no physical extent.
    EmptyFramebuffer,
    /// The page-aligned framebuffer range overflows physical address space.
    FramebufferOverflow,
    /// An existing platform memory region overflows physical address space.
    RegionOverflow(u64),
    /// Two input regions overlap with different memory types.
    ///
    /// Same-kind overlaps are coalesced (they describe the same memory).
    /// Different-kind overlaps have no safe resolution — guessing whether
    /// RAM, reserved, or MMIO wins risks handing the OS a corrupt map — so
    /// the overlay refuses instead of propagating the corruption.
    OverlappingRegions(u64),
    /// Splitting and filling the map requires more descriptors than available.
    CapacityExceeded,
}

#[derive(Clone, Copy)]
struct MapRegion<K> {
    base: u64,
    size: u64,
    kind: K,
}

fn push_memory_region<K: Copy + Eq, const N: usize>(
    out: &mut [MapRegion<K>; N],
    count: &mut usize,
    region: MapRegion<K>,
) -> Result<(), OverlayError> {
    if region.size == 0 {
        return Ok(());
    }

    if let Some(previous) = count.checked_sub(1).map(|index| &mut out[index])
        && previous.kind == region.kind
        && previous.base.checked_add(previous.size) == Some(region.base)
    {
        previous.size = previous
            .size
            .checked_add(region.size)
            .ok_or(OverlayError::RegionOverflow(previous.base))?;
        return Ok(());
    }

    if *count == out.len() {
        return Err(OverlayError::CapacityExceeded);
    }
    out[*count] = region;
    *count += 1;
    Ok(())
}

/// Overlay a page-aligned framebuffer range as MMIO.
///
/// Gaps in the platform map that fall inside the active framebuffer are also
/// reported as MMIO. Coreboot commonly omits PCI BAR apertures entirely, so an
/// unreported gap cannot safely remain absent from the EFI memory map.
///
/// The operation is transactional: `out` is unchanged when an error occurs.
pub fn overlay_framebuffer_region<R: Region, const N: usize>(
    out: &mut [R; N],
    count: usize,
    physical_address: u64,
    framebuffer_size: u64,
    mmio_kind: R::Kind,
) -> Result<usize, OverlayError> {
    const PAGE_SIZE: u64 = 4096;

    if count > out.len() {
        return Err(OverlayError::InvalidRegionCount);
    }
    if framebuffer_size == 0 {
        return Err(OverlayError::EmptyFramebuffer);
    }

    let end = physical_address
        .checked_add(framebuffer_size)
        .and_then(|end| end.checked_add(PAGE_SIZE - 1))
        .map(|end| end & !(PAGE_SIZE - 1))
        .ok_or(OverlayError::FramebufferOverflow)?;
    let base = physical_address & !(PAGE_SIZE - 1);

    let empty = MapRegion {
        base: 0,
        size: 0,
        kind: mmio_kind,
    };
    let mut existing = [empty; N];
    for (destination, source) in existing.iter_mut().zip(out[..count].iter().copied()) {
        *destination = MapRegion {
            base: source.base(),
            size: source.size(),
            kind: source.kind(),
        };
    }
    existing[..count].sort_unstable_by_key(|region| region.base);

    // Normalize the input map before overlaying: coalesce same-kind overlaps
    // (identical memory described twice) and reject different-kind overlaps,
    // which have no safe precedence policy. Runs in the scratch copy, so the
    // caller's map is still untouched on error.
    let mut merged_count = 0usize;
    for index in 0..count {
        let region = existing[index];
        if region.size == 0 {
            continue;
        }
        if merged_count > 0 {
            let previous = existing[merged_count - 1];
            let previous_end = previous
                .base
                .checked_add(previous.size)
                .ok_or(OverlayError::RegionOverflow(previous.base))?;
            if region.base < previous_end {
                if previous.kind == region.kind {
                    let region_end = region
                        .base
                        .checked_add(region.size)
                        .ok_or(OverlayError::RegionOverflow(region.base))?;
                    existing[merged_count - 1].size = previous_end.max(region_end) - previous.base;
                    continue;
                }
                return Err(OverlayError::OverlappingRegions(region.base));
            }
        }
        existing[merged_count] = region;
        merged_count += 1;
    }
    let count = merged_count;

    let mut updated = [empty; N];
    let mut updated_count = 0usize;
    let mut framebuffer_cursor = base;

    for region in existing[..count].iter().copied() {
        let region_end = region
            .base
            .checked_add(region.size)
            .ok_or(OverlayError::RegionOverflow(region.base))?;

        if region_end <= base {
            push_memory_region(&mut updated, &mut updated_count, region)?;
            continue;
        }

        if region.base >= end {
            if framebuffer_cursor < end {
                push_memory_region(
                    &mut updated,
                    &mut updated_count,
                    MapRegion {
                        base: framebuffer_cursor,
                        size: end - framebuffer_cursor,
                        kind: mmio_kind,
                    },
                )?;
                framebuffer_cursor = end;
            }
            push_memory_region(&mut updated, &mut updated_count, region)?;
            continue;
        }

        if region.base < base {
            push_memory_region(
                &mut updated,
                &mut updated_count,
                MapRegion {
                    base: region.base,
                    size: base - region.base,
                    kind: region.kind,
                },
            )?;
        }

        let overlap_start = region.base.max(base);
        if framebuffer_cursor < overlap_start {
            push_memory_region(
                &mut updated,
                &mut updated_count,
                MapRegion {
                    base: framebuffer_cursor,
                    size: overlap_start - framebuffer_cursor,
                    kind: mmio_kind,
                },
            )?;
            framebuffer_cursor = overlap_start;
        }

        let overlap_end = region_end.min(end);
        let mmio_start = framebuffer_cursor.max(overlap_start);
        if mmio_start < overlap_end {
            push_memory_region(
                &mut updated,
                &mut updated_count,
                MapRegion {
                    base: mmio_start,
                    size: overlap_end - mmio_start,
                    kind: mmio_kind,
                },
            )?;
        }
        framebuffer_cursor = framebuffer_cursor.max(overlap_end);

        if region_end > end {
            push_memory_region(
                &mut updated,
                &mut updated_count,
                MapRegion {
                    base: end,
                    size: region_end - end,
                    kind: region.kind,
                },
            )?;
        }
    }

    if framebuffer_cursor < end {
        push_memory_region(
            &mut updated,
            &mut updated_count,
            MapRegion {
                base: framebuffer_cursor,
                size: end - framebuffer_cursor,
                kind: mmio_kind,
            },
        )?;
    }

    for (destination, source) in out.iter_mut().zip(updated[..updated_count].iter().copied()) {
        *destination = R::from_parts(source.base, source.size, source.kind);
    }
    Ok(updated_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Kind {
        Ram,
        Reserved,
        AcpiReclaimable,
        Mmio,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct TestRegion {
        base: u64,
        size: u64,
        kind: Kind,
    }

    impl Region for TestRegion {
        type Kind = Kind;

        fn base(self) -> u64 {
            self.base
        }

        fn size(self) -> u64 {
            self.size
        }

        fn kind(self) -> Self::Kind {
            self.kind
        }

        fn from_parts(base: u64, size: u64, kind: Self::Kind) -> Self {
            Self { base, size, kind }
        }
    }

    const EMPTY: TestRegion = TestRegion {
        base: 0,
        size: 0,
        kind: Kind::Reserved,
    };

    const fn region(base: u64, size: u64, kind: Kind) -> TestRegion {
        TestRegion { base, size, kind }
    }

    fn overlay<const N: usize>(
        map: &mut [TestRegion; N],
        count: usize,
        base: u64,
        size: u64,
    ) -> Result<usize, OverlayError> {
        overlay_framebuffer_region(map, count, base, size, Kind::Mmio)
    }

    #[test]
    fn splits_a_region_covering_the_framebuffer() {
        let mut map = [EMPTY; 8];
        map[0] = region(0x1000, 0x8000, Kind::Ram);
        let count = overlay(&mut map, 1, 0x3001, 0x1800).unwrap();
        assert_eq!(
            &map[..count],
            &[
                region(0x1000, 0x2000, Kind::Ram),
                region(0x3000, 0x2000, Kind::Mmio),
                region(0x5000, 0x4000, Kind::Ram),
            ]
        );
    }

    #[test]
    fn fills_holes_and_overlaps_both_edges() {
        let mut map = [EMPTY; 8];
        map[0] = region(0x1000, 0x2000, Kind::Reserved);
        map[1] = region(0x4000, 0x3000, Kind::Ram);
        let count = overlay(&mut map, 2, 0x2000, 0x4000).unwrap();
        assert_eq!(
            &map[..count],
            &[
                region(0x1000, 0x1000, Kind::Reserved),
                region(0x2000, 0x4000, Kind::Mmio),
                region(0x6000, 0x1000, Kind::Ram),
            ]
        );
    }

    #[test]
    fn inserts_a_framebuffer_contained_in_an_unreported_gap() {
        let mut map = [EMPTY; 8];
        map[0] = region(0x1000, 0x1000, Kind::Ram);
        map[1] = region(0x6000, 0x1000, Kind::AcpiReclaimable);
        let count = overlay(&mut map, 2, 0x3000, 0x2000).unwrap();
        assert_eq!(
            &map[..count],
            &[
                region(0x1000, 0x1000, Kind::Ram),
                region(0x3000, 0x2000, Kind::Mmio),
                region(0x6000, 0x1000, Kind::AcpiReclaimable),
            ]
        );
    }

    #[test]
    fn sorts_input_and_merges_adjacent_output() {
        let mut map = [EMPTY; 8];
        map[0] = region(0x5000, 0x1000, Kind::Ram);
        map[1] = region(0x1000, 0x1000, Kind::Ram);
        map[2] = region(0x2000, 0x1000, Kind::Mmio);
        let count = overlay(&mut map, 3, 0x3000, 0x2000).unwrap();
        assert_eq!(
            &map[..count],
            &[
                region(0x1000, 0x1000, Kind::Ram),
                region(0x2000, 0x3000, Kind::Mmio),
                region(0x5000, 0x1000, Kind::Ram),
            ]
        );
    }

    #[test]
    fn same_kind_overlaps_are_coalesced() {
        let mut map = [EMPTY; 8];
        map[0] = region(0x1000, 0x2000, Kind::Ram);
        map[1] = region(0x2000, 0x2000, Kind::Ram);
        let count = overlay(&mut map, 2, 0x8000, 0x1000).unwrap();
        assert_eq!(
            &map[..count],
            &[
                region(0x1000, 0x3000, Kind::Ram),
                region(0x8000, 0x1000, Kind::Mmio),
            ]
        );
    }

    #[test]
    fn different_kind_overlaps_are_rejected_untouched() {
        let mut map = [EMPTY; 8];
        map[0] = region(0x1000, 0x2000, Kind::Ram);
        map[1] = region(0x2000, 0x2000, Kind::Reserved);
        let original = map;
        assert_eq!(
            overlay(&mut map, 2, 0x8000, 0x1000),
            Err(OverlayError::OverlappingRegions(0x2000))
        );
        assert_eq!(map, original);
    }

    #[test]
    fn capacity_failure_leaves_the_original_map_untouched() {
        let mut map = [
            region(0x1000, 0x1000, Kind::Ram),
            region(0x4000, 0x1000, Kind::Reserved),
        ];
        let original = map;
        assert_eq!(
            overlay(&mut map, 2, 0x2800, 0x100),
            Err(OverlayError::CapacityExceeded)
        );
        assert_eq!(map, original);
    }

    #[test]
    fn overflowing_ranges_leave_the_original_map_untouched() {
        let mut framebuffer_map = [region(0x1000, 0x1000, Kind::Ram); 2];
        let framebuffer_original = framebuffer_map;
        assert_eq!(
            overlay(&mut framebuffer_map, 1, u64::MAX - 7, 8),
            Err(OverlayError::FramebufferOverflow)
        );
        assert_eq!(framebuffer_map, framebuffer_original);

        let mut region_map = [region(u64::MAX - 7, 16, Kind::Ram); 2];
        let region_original = region_map;
        assert_eq!(
            overlay(&mut region_map, 1, 0x1000, 0x1000),
            Err(OverlayError::RegionOverflow(u64::MAX - 7))
        );
        assert_eq!(region_map, region_original);
    }
}

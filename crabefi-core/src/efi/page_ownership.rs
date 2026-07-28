//! Page-allocation ownership primitives.
//!
//! Addresses and sizes here are counted in *pages*, never in bytes. Byte values
//! are converted at the boundary ([`PageAddr::from_bytes`], [`PageRange::from_bytes`])
//! and the conversion is where overflow and misalignment are rejected, so the
//! interior arithmetic needs no `checked_mul`/`checked_add` and no `/ PAGE_SIZE`.
//!
//! This module is dependency-free so ownership behavior can be tested directly
//! with `rustc --test` in the host regression job.

/// Page size (4KB)
pub const PAGE_SIZE: u64 = 4096;

/// Largest page index whose byte address still fits in a `u64`.
const MAX_PAGE_INDEX: u64 = u64::MAX / PAGE_SIZE;

/// A page-aligned physical address, stored as a page index.
///
/// Constructing one proves the address is page-aligned and that its byte form
/// fits in a `u64`, so [`PageAddr::bytes`] is infallible.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PageAddr(u64);

impl PageAddr {
    /// Convert a byte address, rejecting anything not page-aligned.
    pub const fn from_bytes(address: u64) -> Option<Self> {
        if address.is_multiple_of(PAGE_SIZE) {
            Some(Self(address / PAGE_SIZE))
        } else {
            None
        }
    }

    /// Byte address of the start of this page.
    pub const fn bytes(self) -> u64 {
        self.0 * PAGE_SIZE
    }

    /// Advance by `count` pages, rejecting addresses beyond the `u64` byte space.
    pub const fn checked_add(self, count: PageCount) -> Option<Self> {
        match self.0.checked_add(count.0) {
            Some(index) if index <= MAX_PAGE_INDEX => Some(Self(index)),
            _ => None,
        }
    }

    /// Pages from `earlier` to `self`, or zero when `self` is not later.
    pub const fn pages_since(self, earlier: Self) -> PageCount {
        PageCount(self.0.saturating_sub(earlier.0))
    }
}

/// A number of pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PageCount(u64);

impl PageCount {
    pub const fn new(pages: u64) -> Self {
        Self(pages)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Size in bytes, or `None` when it does not fit in a `u64`.
    pub const fn bytes(self) -> Option<u64> {
        self.0.checked_mul(PAGE_SIZE)
    }

    /// Pages needed to cover `bytes`, rounding up.
    pub const fn covering_bytes(bytes: u64) -> Self {
        Self(bytes.div_ceil(PAGE_SIZE))
    }
}

/// A half-open range of pages: `start` inclusive, `end` exclusive.
///
/// The `start <= end` invariant is established at construction, so `pages()`,
/// `head_before()`, and `tail_after()` never underflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageRange {
    start: PageAddr,
    end: PageAddr,
}

impl PageRange {
    /// Build a range from a start page and a length.
    pub const fn new(start: PageAddr, count: PageCount) -> Option<Self> {
        match start.checked_add(count) {
            Some(end) => Some(Self { start, end }),
            None => None,
        }
    }

    /// Build a range from its bounds, rejecting an inverted pair.
    pub const fn spanning(start: PageAddr, end: PageAddr) -> Option<Self> {
        if start.0 <= end.0 {
            Some(Self { start, end })
        } else {
            None
        }
    }

    /// Build a range from a byte address and a page count.
    ///
    /// Rejects misaligned addresses, zero-length ranges, and ranges whose end
    /// would leave the `u64` byte space.
    pub const fn from_bytes(address: u64, number_of_pages: u64) -> Option<Self> {
        if number_of_pages == 0 {
            return None;
        }
        match PageAddr::from_bytes(address) {
            Some(start) => Self::new(start, PageCount::new(number_of_pages)),
            None => None,
        }
    }

    pub const fn start(self) -> PageAddr {
        self.start
    }

    pub const fn end(self) -> PageAddr {
        self.end
    }

    pub const fn pages(self) -> PageCount {
        self.end.pages_since(self.start)
    }

    pub const fn start_bytes(self) -> u64 {
        self.start.bytes()
    }

    pub const fn end_bytes(self) -> u64 {
        self.end.bytes()
    }

    pub const fn is_empty(self) -> bool {
        self.pages().is_zero()
    }

    /// Whether `other` lies entirely within `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.start.0 <= other.start.0 && self.end.0 >= other.end.0
    }

    /// The pages shared by both ranges, or `None` when they are disjoint.
    pub const fn intersection(self, other: Self) -> Option<Self> {
        let start = if self.start.0 > other.start.0 {
            self.start
        } else {
            other.start
        };
        let end = if self.end.0 < other.end.0 {
            self.end
        } else {
            other.end
        };
        if start.0 < end.0 {
            Some(Self { start, end })
        } else {
            None
        }
    }

    /// Whether the two ranges share at least one page.
    pub const fn overlaps(self, other: Self) -> bool {
        self.intersection(other).is_some()
    }

    /// Whether `later` begins exactly where `self` ends.
    pub const fn is_adjacent_to(self, later: Self) -> bool {
        self.end.0 == later.start.0
    }

    /// Split `self` around the contained range `inner`.
    ///
    /// Returns `None` when `inner` is not contained, so callers cannot compute
    /// a residual from ranges that do not nest.
    pub const fn split_around(self, inner: Self) -> Option<RangeSplit> {
        if !self.contains(inner) {
            return None;
        }
        let head = if self.start.0 < inner.start.0 {
            Some(Self {
                start: self.start,
                end: inner.start,
            })
        } else {
            None
        };
        let tail = if self.end.0 > inner.end.0 {
            Some(Self {
                start: inner.end,
                end: self.end,
            })
        } else {
            None
        };
        Some(RangeSplit {
            head,
            middle: inner,
            tail,
        })
    }
}

/// The ranges that replace a range when a contained subrange is carved out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RangeSplit {
    pub head: Option<PageRange>,
    pub middle: PageRange,
    pub tail: Option<PageRange>,
}

impl RangeSplit {
    /// How many ranges replace the original one.
    pub const fn replacement_count(self) -> usize {
        1 + self.head.is_some() as usize + self.tail.is_some() as usize
    }

    /// The replacements in ascending address order.
    pub fn parts(self) -> impl Iterator<Item = PageRange> {
        self.head
            .into_iter()
            .chain(core::iter::once(self.middle))
            .chain(self.tail)
    }
}

/// Whether a fixed-capacity table still fits after a replacement.
///
/// Written as checked arithmetic so an inconsistent `removed` count can never
/// wrap the subtraction into a spuriously successful capacity check.
pub const fn fits_after_replacement(
    len: usize,
    removed: usize,
    inserted: usize,
    capacity: usize,
) -> bool {
    match len.checked_sub(removed) {
        Some(remaining) => match remaining.checked_add(inserted) {
            Some(total) => total <= capacity,
            None => false,
        },
        None => false,
    }
}

/// Ownership record parameterized by memory type so this leaf module remains
/// independent of the allocator's EFI `MemoryType` definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageAllocation<T: Copy> {
    pub range: PageRange,
    pub memory_type: T,
    pub restore_attribute: u64,
}

impl<T: Copy> PageAllocation<T> {
    pub const fn contains(self, range: PageRange) -> bool {
        self.range.contains(range)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitError {
    RangeNotContained,
    ReplacementRangeMismatch,
}

/// Find records whose exact, gap-free union covers `range`.
///
/// All records in the cover must share one memory type and one set of restore
/// attributes, because the caller retypes the union through a single memory
/// map descriptor. A range spanning records that differ in either field (for
/// example a loader image holding a subclaim of a different memory type) has
/// no single descriptor to retype and is therefore not coverable.
///
/// The returned synthesized record describes the full union.
///
/// Records are expected to be disjoint. That invariant is verified here rather
/// than assumed: the caller drops every record inside `range`, so an unnoticed
/// overlap would retype pages that another record still claims.
pub fn exact_cover<T: Copy + Eq>(
    allocations: &[PageAllocation<T>],
    range: PageRange,
) -> Option<PageAllocation<T>> {
    let mut cursor = range.start();
    let first = allocations.iter().find(|allocation| {
        allocation.range.start() == cursor && range.contains(allocation.range)
    })?;
    let memory_type = first.memory_type;
    let restore_attribute = first.restore_attribute;
    let mut chain_len = 0usize;

    while cursor < range.end() {
        let allocation = allocations.iter().find(|allocation| {
            allocation.range.start() == cursor
                && !allocation.range.is_empty()
                && range.contains(allocation.range)
                && allocation.memory_type == memory_type
                && allocation.restore_attribute == restore_attribute
        })?;
        cursor = allocation.range.end();
        chain_len += 1;
    }

    // The chain tiles `range` exactly, so any further record touching `range`
    // is a duplicate or a partial overlap and the table cannot be trusted.
    let touching = allocations
        .iter()
        .filter(|allocation| allocation.range.overlaps(range))
        .count();

    (cursor == range.end() && touching == chain_len).then_some(PageAllocation {
        range,
        memory_type,
        restore_attribute,
    })
}

/// Split one ownership record around a subrange.
///
/// The output is ordered as residual prefix, optional replacement, and residual
/// suffix. Empty slots are omitted from the returned array.
pub fn split_allocation<T: Copy>(
    allocation: PageAllocation<T>,
    range: PageRange,
    replacement: Option<PageAllocation<T>>,
) -> Result<[Option<PageAllocation<T>>; 3], SplitError> {
    // The residuals are computed around `range`, so a replacement covering
    // anything else would leave a gap or an overlap in the ownership table.
    if replacement.is_some_and(|replacement| replacement.range != range) {
        return Err(SplitError::ReplacementRangeMismatch);
    }
    let split = allocation
        .range
        .split_around(range)
        .ok_or(SplitError::RangeNotContained)?;

    let residual = |range| PageAllocation {
        range,
        ..allocation
    };
    let mut output = [None; 3];
    let parts = [
        split.head.map(residual),
        replacement,
        split.tail.map(residual),
    ];
    for (slot, part) in output.iter_mut().zip(parts.into_iter().flatten()) {
        *slot = Some(part);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;

    fn range(start: u64, end: u64) -> PageRange {
        PageRange::from_bytes(start, (end - start) / PAGE_SIZE).unwrap()
    }

    fn original() -> PageAllocation<u32> {
        PageAllocation {
            range: range(0x1000, 0x9000),
            memory_type: 2,
            restore_attribute: 0x8008,
        }
    }

    #[test]
    fn byte_conversion_rejects_misaligned_and_overflowing_ranges() {
        assert_eq!(PageAddr::from_bytes(0x1001), None);
        assert_eq!(PageAddr::from_bytes(0x1000).unwrap().bytes(), 0x1000);
        assert_eq!(PageRange::from_bytes(0x1000, 0), None);
        assert_eq!(PageRange::from_bytes(PAGE_SIZE, u64::MAX), None);
        assert_eq!(range(0x1000, 0x9000).pages(), PageCount::new(8));
        assert_eq!(range(0x1000, 0x9000).end_bytes(), 0x9000);
        assert_eq!(PageCount::covering_bytes(PAGE_SIZE + 1).get(), 2);
    }

    #[test]
    fn split_around_yields_residual_ranges_without_page_arithmetic() {
        let split = range(0x1000, 0x9000)
            .split_around(range(0x3000, 0x6000))
            .unwrap();
        assert_eq!(split.head, Some(range(0x1000, 0x3000)));
        assert_eq!(split.middle, range(0x3000, 0x6000));
        assert_eq!(split.tail, Some(range(0x6000, 0x9000)));
        assert_eq!(split.replacement_count(), 3);

        let whole = range(0x1000, 0x9000)
            .split_around(range(0x1000, 0x9000))
            .unwrap();
        assert_eq!((whole.head, whole.tail), (None, None));
        assert_eq!(whole.replacement_count(), 1);

        assert_eq!(range(0x1000, 0x9000).split_around(range(0, 0x2000)), None);
    }

    #[test]
    fn split_parts_are_contiguous_and_cover_the_original() {
        let split = range(0x1000, 0x9000)
            .split_around(range(0x3000, 0x6000))
            .unwrap();
        let parts: std::vec::Vec<_> = split.parts().collect();
        assert_eq!(parts.len(), 3);
        assert!(parts.windows(2).all(|pair| pair[0].is_adjacent_to(pair[1])));
        assert_eq!(parts[0].start(), range(0x1000, 0x9000).start());
        assert_eq!(parts[2].end(), range(0x1000, 0x9000).end());
    }

    #[test]
    fn intersection_clips_to_the_shared_pages() {
        let region = range(0x2000, 0x8000);
        assert_eq!(
            region.intersection(range(0x1000, 0x4000)),
            Some(range(0x2000, 0x4000))
        );
        assert_eq!(
            region.intersection(range(0x4000, 0x9000)),
            Some(range(0x4000, 0x8000))
        );
        assert_eq!(region.intersection(range(0x1000, 0x9000)), Some(region));
        assert_eq!(region.intersection(range(0x8000, 0x9000)), None);
        assert!(!region.overlaps(range(0x8000, 0x9000)));
        assert!(region.overlaps(range(0x7000, 0x9000)));
    }

    #[test]
    fn capacity_check_never_wraps() {
        assert!(fits_after_replacement(10, 1, 3, 12));
        assert!(!fits_after_replacement(10, 1, 4, 12));
        assert!(!fits_after_replacement(0, 1, 1, 12));
    }

    #[test]
    fn cover_rejects_records_that_overlap_the_chain() {
        // A parent plus a still-live subclaim of the same metadata: the chain
        // walk alone would accept the parent and drop both records.
        let records = [
            original(),
            PageAllocation {
                range: range(0x3000, 0x5000),
                ..original()
            },
        ];
        assert_eq!(exact_cover(&records, original().range), None);

        // Two records claiming the same start are equally untrustworthy.
        let duplicates = [original(), original()];
        assert_eq!(exact_cover(&duplicates, original().range), None);
    }

    #[test]
    fn split_rejects_a_replacement_that_does_not_cover_the_split_range() {
        for bad in [range(0x3000, 0x5000), range(0x2000, 0x6000)] {
            let replacement = PageAllocation {
                range: bad,
                ..original()
            };
            assert_eq!(
                split_allocation(original(), range(0x3000, 0x6000), Some(replacement)),
                Err(SplitError::ReplacementRangeMismatch)
            );
        }
    }

    #[test]
    fn partial_free_preserves_both_residual_records_and_metadata() {
        let parts = split_allocation(original(), range(0x3000, 0x6000), None).unwrap();
        assert_eq!(parts[0].unwrap().range, range(0x1000, 0x3000));
        assert_eq!(parts[1].unwrap().range, range(0x6000, 0x9000));
        assert_eq!(parts[0].unwrap().memory_type, original().memory_type);
        assert_eq!(
            parts[1].unwrap().restore_attribute,
            original().restore_attribute
        );
        assert!(parts[2].is_none());
    }

    #[test]
    fn whole_parent_is_freeable_after_loader_subclaim() {
        let replacement = PageAllocation {
            range: range(0x3000, 0x5000),
            ..original()
        };
        let parts = split_allocation(original(), replacement.range, Some(replacement)).unwrap();
        assert!(
            parts[0]
                .unwrap()
                .range
                .is_adjacent_to(parts[1].unwrap().range)
        );
        assert!(
            parts[1]
                .unwrap()
                .range
                .is_adjacent_to(parts[2].unwrap().range)
        );
        assert_eq!(parts[1].unwrap(), replacement);

        let records = parts.into_iter().flatten().collect::<alloc::vec::Vec<_>>();
        assert_eq!(exact_cover(&records, original().range), Some(original()));
    }

    #[test]
    fn whole_parent_cover_rejects_gaps_or_mismatched_metadata() {
        let mut records = [
            PageAllocation {
                range: range(0x1000, 0x3000),
                ..original()
            },
            PageAllocation {
                range: range(0x3000, 0x9000),
                ..original()
            },
        ];
        assert_eq!(exact_cover(&records, original().range), Some(original()));

        records[1].range = range(0x4000, 0x9000);
        assert_eq!(exact_cover(&records, original().range), None);
        records[1].range = range(0x3000, 0x9000);
        records[1].memory_type = 4;
        assert_eq!(exact_cover(&records, original().range), None);
        records[1].memory_type = original().memory_type;
        records[1].restore_attribute = 0;
        assert_eq!(exact_cover(&records, original().range), None);
    }

    #[test]
    fn cover_ignores_records_that_leave_the_requested_range() {
        let records = [
            PageAllocation {
                range: range(0x1000, 0x3000),
                ..original()
            },
            PageAllocation {
                range: range(0x3000, 0xA000),
                ..original()
            },
        ];
        assert_eq!(exact_cover(&records, original().range), None);
    }

    #[test]
    fn whole_range_free_produces_no_residual_records() {
        assert_eq!(
            split_allocation(original(), original().range, None).unwrap(),
            [None; 3]
        );
    }

    #[test]
    fn rejects_ranges_outside_the_owned_allocation() {
        assert_eq!(
            split_allocation(original(), range(0, 0x2000), None),
            Err(SplitError::RangeNotContained)
        );
    }
}

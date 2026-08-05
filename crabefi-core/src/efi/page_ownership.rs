//! Page-allocation ownership range primitives.
//!
//! This module is dependency-free so subrange ownership behavior can be tested
//! directly with `rustc --test` in the host regression job.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRange {
    pub start: u64,
    pub end: u64,
}

impl MemoryRange {
    pub fn from_pages(start: u64, number_of_pages: u64, page_size: u64) -> Option<Self> {
        let size = number_of_pages.checked_mul(page_size)?;
        let end = start.checked_add(size)?;
        Some(Self { start, end })
    }

    pub const fn contains(self, other: Self) -> bool {
        self.start <= other.start && self.end >= other.end
    }

    pub const fn number_of_pages(self, page_size: u64) -> u64 {
        (self.end - self.start) / page_size
    }

    /// Whether the two ranges share at least one byte.
    pub const fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Ownership record parameterized by memory type so this leaf module remains
/// independent of the allocator's EFI `MemoryType` definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageAllocation<T: Copy> {
    pub range: MemoryRange,
    pub memory_type: T,
    pub restore_attribute: u64,
}

impl<T: Copy> PageAllocation<T> {
    pub const fn contains(self, range: MemoryRange) -> bool {
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
    range: MemoryRange,
) -> Option<PageAllocation<T>> {
    let mut cursor = range.start;
    let first = allocations
        .iter()
        .find(|allocation| allocation.range.start == cursor && range.contains(allocation.range))?;
    let memory_type = first.memory_type;
    let restore_attribute = first.restore_attribute;
    let mut chain_len = 0usize;

    while cursor < range.end {
        let allocation = allocations.iter().find(|allocation| {
            allocation.range.start == cursor
                && range.contains(allocation.range)
                && allocation.memory_type == memory_type
                && allocation.restore_attribute == restore_attribute
        })?;
        // A zero-length record would leave the cursor in place and spin here.
        if allocation.range.end <= cursor {
            return None;
        }
        cursor = allocation.range.end;
        chain_len += 1;
    }

    // The chain tiles `range` exactly, so any further record touching `range`
    // is a duplicate or a partial overlap and the table cannot be trusted.
    let touching = allocations
        .iter()
        .filter(|allocation| allocation.range.overlaps(range))
        .count();

    (cursor == range.end && touching == chain_len).then_some(PageAllocation {
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
    range: MemoryRange,
    replacement: Option<PageAllocation<T>>,
) -> Result<[Option<PageAllocation<T>>; 3], SplitError> {
    if !allocation.contains(range) {
        return Err(SplitError::RangeNotContained);
    }
    // The residuals are computed around `range`, so a replacement covering
    // anything else would leave a gap or an overlap in the ownership table.
    if replacement.is_some_and(|replacement| replacement.range != range) {
        return Err(SplitError::ReplacementRangeMismatch);
    }

    let mut output = [None; 3];
    let mut index = 0;
    if allocation.range.start < range.start {
        output[index] = Some(PageAllocation {
            range: MemoryRange {
                start: allocation.range.start,
                end: range.start,
            },
            ..allocation
        });
        index += 1;
    }
    if let Some(replacement) = replacement {
        output[index] = Some(replacement);
        index += 1;
    }
    if allocation.range.end > range.end {
        output[index] = Some(PageAllocation {
            range: MemoryRange {
                start: range.end,
                end: allocation.range.end,
            },
            ..allocation
        });
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;

    const ORIGINAL: PageAllocation<u32> = PageAllocation {
        range: MemoryRange {
            start: 0x1000,
            end: 0x9000,
        },
        memory_type: 2,
        restore_attribute: 0x8008,
    };

    #[test]
    fn cover_rejects_records_that_overlap_the_chain() {
        // A parent plus a still-live subclaim of the same metadata: the chain
        // walk alone would accept the parent and drop both records.
        let records = [
            ORIGINAL,
            PageAllocation {
                range: MemoryRange {
                    start: 0x3000,
                    end: 0x5000,
                },
                ..ORIGINAL
            },
        ];
        assert_eq!(exact_cover(&records, ORIGINAL.range), None);

        // Two records claiming the same start are equally untrustworthy.
        let duplicates = [ORIGINAL, ORIGINAL];
        assert_eq!(exact_cover(&duplicates, ORIGINAL.range), None);
    }

    #[test]
    fn split_rejects_a_replacement_that_does_not_cover_the_split_range() {
        let range = MemoryRange {
            start: 0x3000,
            end: 0x6000,
        };
        for bad in [
            MemoryRange {
                start: 0x3000,
                end: 0x5000,
            },
            MemoryRange {
                start: 0x2000,
                end: 0x6000,
            },
        ] {
            let replacement = PageAllocation {
                range: bad,
                ..ORIGINAL
            };
            assert_eq!(
                split_allocation(ORIGINAL, range, Some(replacement)),
                Err(SplitError::ReplacementRangeMismatch)
            );
        }
    }

    #[test]
    fn partial_free_preserves_both_residual_records_and_metadata() {
        let parts = split_allocation(
            ORIGINAL,
            MemoryRange {
                start: 0x3000,
                end: 0x6000,
            },
            None,
        )
        .unwrap();
        assert_eq!(
            parts[0].unwrap().range,
            MemoryRange {
                start: 0x1000,
                end: 0x3000
            }
        );
        assert_eq!(
            parts[1].unwrap().range,
            MemoryRange {
                start: 0x6000,
                end: 0x9000
            }
        );
        assert_eq!(parts[0].unwrap().memory_type, ORIGINAL.memory_type);
        assert_eq!(
            parts[1].unwrap().restore_attribute,
            ORIGINAL.restore_attribute
        );
        assert!(parts[2].is_none());
    }

    #[test]
    fn whole_parent_is_freeable_after_loader_subclaim() {
        let replacement = PageAllocation {
            range: MemoryRange {
                start: 0x3000,
                end: 0x5000,
            },
            memory_type: ORIGINAL.memory_type,
            restore_attribute: ORIGINAL.restore_attribute,
        };
        let parts = split_allocation(ORIGINAL, replacement.range, Some(replacement)).unwrap();
        assert_eq!(parts[0].unwrap().range.end, parts[1].unwrap().range.start);
        assert_eq!(parts[1].unwrap().range.end, parts[2].unwrap().range.start);
        assert_eq!(parts[1].unwrap(), replacement);

        let records = parts.into_iter().flatten().collect::<alloc::vec::Vec<_>>();
        assert_eq!(exact_cover(&records, ORIGINAL.range), Some(ORIGINAL));
    }

    #[test]
    fn whole_parent_cover_rejects_gaps_or_mismatched_metadata() {
        let mut records = [
            PageAllocation {
                range: MemoryRange {
                    start: 0x1000,
                    end: 0x3000,
                },
                ..ORIGINAL
            },
            PageAllocation {
                range: MemoryRange {
                    start: 0x3000,
                    end: 0x9000,
                },
                ..ORIGINAL
            },
        ];
        assert_eq!(exact_cover(&records, ORIGINAL.range), Some(ORIGINAL));

        records[1].range.start = 0x4000;
        assert_eq!(exact_cover(&records, ORIGINAL.range), None);
        records[1].range.start = 0x3000;
        records[1].memory_type = 4;
        assert_eq!(exact_cover(&records, ORIGINAL.range), None);
        records[1].memory_type = ORIGINAL.memory_type;
        records[1].restore_attribute = 0;
        assert_eq!(exact_cover(&records, ORIGINAL.range), None);
    }

    #[test]
    fn cover_ignores_records_that_leave_the_requested_range() {
        let records = [
            PageAllocation {
                range: MemoryRange {
                    start: 0x1000,
                    end: 0x3000,
                },
                ..ORIGINAL
            },
            PageAllocation {
                range: MemoryRange {
                    start: 0x3000,
                    end: 0xA000,
                },
                ..ORIGINAL
            },
        ];
        assert_eq!(exact_cover(&records, ORIGINAL.range), None);
    }

    #[test]
    fn whole_range_free_produces_no_residual_records() {
        assert_eq!(
            split_allocation(ORIGINAL, ORIGINAL.range, None).unwrap(),
            [None; 3]
        );
    }

    #[test]
    fn rejects_ranges_outside_the_owned_allocation() {
        assert_eq!(
            split_allocation(
                ORIGINAL,
                MemoryRange {
                    start: 0,
                    end: 0x2000,
                },
                None,
            ),
            Err(SplitError::RangeNotContained)
        );
    }
}

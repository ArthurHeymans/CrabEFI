//! Bounded proofs of the page-ownership arithmetic over all 64-bit inputs.
//!
//! Whole operations on [`MemoryMap`] are too large for CBMC: one symbolic
//! AllocatePages from a single concrete descriptor takes six minutes, and from
//! an arbitrary three-descriptor map it exceeds 45 GB. The operations are
//! checked against a page-level oracle by the property tests in
//! `tests/sequences.rs`; these harnesses prove the range arithmetic those
//! operations are built from, including at the top of the address space.

use super::*;
use MemoryType::*;
use page_ownership::PageAddr;

fn any_range() -> Option<PageRange> {
    PageRange::from_bytes(kani::any(), kani::any())
}

fn any_owner() -> PageAllocation {
    let range = any_range();
    kani::assume(range.is_some());
    PageAllocation {
        range: range.unwrap(),
        memory_type: if kani::any() { LoaderCode } else { LoaderData },
        restore_attribute: if kani::any() {
            0
        } else {
            attributes::EFI_MEMORY_RAM_CAPS
        },
    }
}

fn holds(range: PageRange, page: PageAddr) -> bool {
    range.start() <= page && page < range.end()
}

fn any_page() -> PageAddr {
    let page = PageAddr::from_bytes(kani::any());
    kani::assume(page.is_some());
    page.unwrap()
}

/// The split geometry used by descriptors and ownership records agrees for
/// every symbolic range, up to the top of the address space.
#[kani::proof]
#[kani::unwind(4)]
#[kani::solver(cadical)]
fn descriptor_and_owner_splits_agree() {
    let outer = any_range();
    let inner = any_range();
    kani::assume(outer.is_some() && inner.is_some());
    let (outer, inner) = (outer.unwrap(), inner.unwrap());
    let owner = PageAllocation {
        range: outer,
        memory_type: LoaderData,
        restore_attribute: kani::any(),
    };
    let split = outer.split_around(inner);
    let residuals = split_allocation(owner, inner, None);
    assert_eq!(split.is_some(), residuals.is_ok());
    if let (Some(split), Ok(residuals)) = (split, residuals) {
        let mut owned = residuals.into_iter().flatten();
        assert_eq!(split.middle, inner);
        for part in [split.head, split.tail].into_iter().flatten() {
            assert_eq!(owned.next().map(|o| o.range), Some(part));
        }
        assert!(owned.next().is_none());
        let parts = split.parts();
        let mut cursor = outer.start();
        for part in parts {
            assert_eq!(part.start(), cursor);
            assert!(!part.is_empty());
            cursor = part.end();
        }
        assert_eq!(cursor, outer.end());
    }
}

/// Splitting an ownership record keeps every page it owned, owned once, with
/// the same metadata outside the split range and the replacement's inside.
#[kani::proof]
#[kani::unwind(4)]
fn owner_split_keeps_every_page_owned_once() {
    let owner = any_owner();
    let range = any_range();
    kani::assume(range.is_some());
    let range = range.unwrap();
    let replacement = if kani::any() {
        Some(PageAllocation {
            range: if kani::any() {
                range
            } else {
                any_owner().range
            },
            ..any_owner()
        })
    } else {
        None
    };
    let Ok(parts) = split_allocation(owner, range, replacement) else {
        assert!(!owner.range.contains(range) || replacement.is_some_and(|r| r.range != range));
        return;
    };
    assert!(owner.range.contains(range));
    let page = any_page();
    let holders = parts
        .iter()
        .flatten()
        .filter(|part| holds(part.range, page))
        .count();
    let holder = parts.iter().flatten().find(|part| holds(part.range, page));
    if !holds(owner.range, page) {
        assert_eq!(holders, 0);
    } else if holds(range, page) {
        assert_eq!(holder.copied(), replacement);
        assert_eq!(holders, usize::from(replacement.is_some()));
    } else {
        assert_eq!(holders, 1);
        let holder = holder.unwrap();
        assert_eq!(
            (holder.memory_type, holder.restore_attribute),
            (owner.memory_type, owner.restore_attribute)
        );
    }
    // Parts are in address order and never empty.
    let mut previous: Option<PageRange> = None;
    for part in parts.iter().flatten() {
        assert!(!part.range.is_empty());
        assert!(previous.is_none_or(|p| p.end() <= part.range.start()));
        previous = Some(part.range);
    }
}

/// A whole-range free across several records succeeds exactly when the
/// records tile the range, share one type and restore attribute, and no other
/// record touches it. Otherwise freeing would release another owner's pages,
/// or a legitimate free would be refused.
#[kani::proof]
#[kani::unwind(5)]
fn exact_cover_requires_an_exact_tiling() {
    let owners = [any_owner(), any_owner(), any_owner()];
    let count: usize = kani::any();
    kani::assume(count <= owners.len());
    let owners = &owners[..count];
    let range = any_range();
    kani::assume(range.is_some());
    let range = range.unwrap();
    let cover = exact_cover(owners, range);
    // Completeness: any prefix of a permutation of `owners` that tiles `range`
    // with uniform type and restore attribute, while every remaining record is
    // disjoint from `range`, must produce a cover.
    let order: [usize; 3] = match kani::any::<u8>() {
        0 => [0, 1, 2],
        1 => [0, 2, 1],
        2 => [1, 0, 2],
        3 => [1, 2, 0],
        4 => [2, 0, 1],
        _ => [2, 1, 0],
    };
    let mut perm = [0usize; 3];
    let mut perm_len = 0usize;
    for index in order {
        if index < owners.len() {
            perm[perm_len] = index;
            perm_len += 1;
        }
    }
    let chain_len: usize = kani::any();
    kani::assume(chain_len <= perm_len);
    let mut cursor = range.start();
    let mut tiles = chain_len > 0;
    let mut uniform = true;
    let mut first_meta = None;
    for &index in &perm[..chain_len] {
        let owner = owners[index];
        tiles &= owner.range.start() == cursor;
        cursor = owner.range.end();
        let meta = (owner.memory_type, owner.restore_attribute);
        if let Some(expected) = first_meta {
            uniform &= meta == expected;
        } else {
            first_meta = Some(meta);
        }
    }
    tiles &= cursor == range.end();
    let mut others_disjoint = true;
    for &index in &perm[chain_len..perm_len] {
        others_disjoint &= !owners[index].range.overlaps(range);
    }
    kani::cover!(tiles && uniform && others_disjoint && chain_len < perm_len);
    if tiles && uniform && others_disjoint {
        assert!(cover.is_some());
    }
    let page = any_page();
    let holders = || owners.iter().filter(|o| holds(o.range, page));
    if let Some(cover) = cover {
        assert_eq!(cover.range, range);
        if holds(range, page) {
            // Exactly one record owns each page, with the cover's metadata.
            assert_eq!(holders().count(), 1);
            let holder = holders().next().unwrap();
            assert!(range.contains(holder.range));
            assert_eq!(
                (holder.memory_type, holder.restore_attribute),
                (cover.memory_type, cover.restore_attribute)
            );
        }
    }
}

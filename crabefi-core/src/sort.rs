//! Compact stable sorting for small firmware collections.
//!
//! `core::slice::sort*` monomorphizes Rust's full driftsort/ipnsort/heapsort
//! machinery per element and key type (~3-4 KiB per call site). The tables and
//! device lists sorted in CrabEFI are small (typically a handful to at most
//! ~100 entries), where an in-place stable insertion sort avoids both that
//! code-size cost and driftsort's heap scratch allocation.

use core::cmp::Ordering;

/// Sort `slice` stably in-place using `compare`.
pub fn sort_by<T>(slice: &mut [T], mut compare: impl FnMut(&T, &T) -> Ordering) {
    for i in 1..slice.len() {
        let mut j = i;
        while j > 0 && compare(&slice[j - 1], &slice[j]) == Ordering::Greater {
            slice.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// Sort `slice` stably in-place by a key extracted with `key`.
pub fn sort_by_key<T, K: Ord>(slice: &mut [T], mut key: impl FnMut(&T) -> K) {
    sort_by(slice, |a, b| key(a).cmp(&key(b)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_empty_singleton_and_reversed() {
        let mut empty: [u32; 0] = [];
        sort_by_key(&mut empty, |&x| x);
        assert_eq!(empty, []);

        let mut single = [42u32];
        sort_by_key(&mut single, |&x| x);
        assert_eq!(single, [42]);

        let mut rev = [5u32, 4, 3, 2, 1];
        sort_by_key(&mut rev, |&x| x);
        assert_eq!(rev, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn preserves_relative_order_of_equal_keys() {
        let mut items = [(1u8, 'a'), (0, 'b'), (1, 'c'), (0, 'd'), (1, 'e'), (0, 'f')];
        sort_by_key(&mut items, |&(k, _)| k);
        assert_eq!(
            items,
            [(0, 'b'), (0, 'd'), (0, 'f'), (1, 'a'), (1, 'c'), (1, 'e')]
        );
    }
}

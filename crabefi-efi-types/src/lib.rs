//! Allocation-free EFI authentication types and helpers.

#![no_std]

pub mod authentication;
pub mod crc32;
pub mod secure_boot;

/// Compare byte strings without data-dependent early returns.
#[inline(never)]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let difference = left.len() ^ right.len();
    let mut result = difference as u8
        | (difference >> 8) as u8
        | (difference >> 16) as u8
        | (difference >> 24) as u8;
    for (left, right) in left.iter().zip(right) {
        result |= left ^ right;
    }
    result == 0
}

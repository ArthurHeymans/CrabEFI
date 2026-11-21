//! Checked address arithmetic at hardware and protocol boundaries.
//!
//! Every function here turns caller- or device-provided numbers into a range
//! that is either proven to fit or rejected. They have no dependencies, so
//! Kani checks each one against a specification over all 64-bit inputs (see
//! `proofs`), and drivers share one implementation instead of each repeating
//! the overflow and boundary cases.

#![no_std]
#![deny(unsafe_code)]

pub mod block;
pub mod dma;
pub mod mmio;

#[cfg(kani)]
mod proofs;

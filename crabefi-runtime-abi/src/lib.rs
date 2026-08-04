//! Pointer-free ABI shared by the CrabEFI boot and runtime images.
//!
//! All persistent records use fixed-width integers and byte arrays. Rust
//! references, slices, enums, trait objects, and function pointers are not part
//! of the ABI. Parsing copies fields from little-endian bytes, so records have
//! no alignment requirement and untrusted input is never reinterpreted as a
//! Rust structure.

#![no_std]
#![deny(unsafe_code)]

pub mod format;
pub mod handoff;

pub use format::*;
pub use handoff::*;

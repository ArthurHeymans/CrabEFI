//! Build-bound normalized Runtime Services image.
//!
//! The blob exists only in boot-image read-only data. The core loader copies
//! its sections into independent RuntimeServicesCode/Data allocations before
//! publishing the image-owned EFI tables.

pub static RUNTIME_IMAGE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/runtime.img"));
include!(concat!(env!("OUT_DIR"), "/runtime_digest.rs"));

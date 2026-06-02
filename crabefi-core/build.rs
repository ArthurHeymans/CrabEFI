//! Build script for CrabEFI core library
//!
//! The library itself has no link-time requirements.
//! Linker scripts and PAYLOAD_BASE are handled by crabefi-coreboot/build.rs.

fn main() {
    // No-op for the library crate.
    // Coreboot-specific build logic is in crabefi-coreboot/build.rs.
}

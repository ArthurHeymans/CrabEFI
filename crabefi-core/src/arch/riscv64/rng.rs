//! RISC-V Hardware Random Number Generation
//!
//! RISC-V does not have a standard RNG instruction in the base ISA.
//! The Zkr extension adds `seed` CSR (0x015) but it is optional and
//! not commonly available in QEMU.
//!
//! For now, we provide a stub that reports no hardware RNG.  Platforms
//! that have an RNG can provide one via the `PlatformConfig::rng` trait.

/// Initialize RNG support.
///
/// On RISC-V this currently just logs that no hardware RNG is available.
pub fn init() {
    log::warn!("RNG: No hardware RNG available on RISC-V (Zkr not probed)");
}

/// Check if hardware RNG is available.
pub fn is_supported() -> bool {
    false
}

/// Fill a byte buffer with random data.
///
/// Always returns `false` on RISC-V (no hardware RNG).
pub fn fill_random(_buffer: &mut [u8]) -> bool {
    false
}

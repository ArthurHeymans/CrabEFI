//! Architecture-specific code
//!
//! This module provides arch-agnostic re-exports for functionality that
//! has different implementations per architecture. Code outside `arch/`
//! should use these re-exports rather than referencing a specific arch
//! module directly.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

// Arch-agnostic re-exports
#[cfg(target_arch = "x86_64")]
pub use x86_64::halt;
#[cfg(target_arch = "x86_64")]
pub use x86_64::reset;
#[cfg(target_arch = "x86_64")]
pub use x86_64::rng;

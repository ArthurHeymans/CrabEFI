//! Architecture-specific code
//!
//! This module provides arch-agnostic re-exports for functionality that
//! has different implementations per architecture. Code outside `arch/`
//! should use these re-exports rather than referencing a specific arch
//! module directly.

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

// Arch-agnostic re-exports
#[cfg(target_arch = "x86_64")]
pub use x86_64::halt;
#[cfg(target_arch = "x86_64")]
pub use x86_64::reset;
#[cfg(target_arch = "x86_64")]
pub use x86_64::rng;

#[cfg(target_arch = "aarch64")]
pub use aarch64::halt;
#[cfg(target_arch = "aarch64")]
pub use aarch64::reset;
#[cfg(target_arch = "aarch64")]
pub use aarch64::rng;

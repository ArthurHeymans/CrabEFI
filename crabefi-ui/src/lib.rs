//! Portable framebuffer and Ledger setup UI. No hardware access.
//!
//! Firmware and the test harness supply input, a clock, frame scheduling and
//! privileged actions through [`Backend`]. The screens and pixels are shared.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod boot;
#[cfg(feature = "cfr")]
pub mod cfr;
mod framebuffer;
mod input;
pub mod log_level;
#[cfg(feature = "cfr")]
pub mod settings;
pub use boot::*;
pub use framebuffer::FramebufferConfig;
pub use input::KeyPress;

#[cfg(feature = "screens")]
pub mod cursor;
#[cfg(feature = "screens")]
mod host;
#[cfg(feature = "screens")]
pub mod screens;
#[cfg(feature = "screens")]
pub use host::*;

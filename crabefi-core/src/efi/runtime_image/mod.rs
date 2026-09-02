//! Boot-side loader and client for the separate Runtime Services image.

pub mod bridge;
pub mod client;
mod loader;

pub use client::{RuntimeImageClient, install, installed};
pub use loader::{LoadError, load};

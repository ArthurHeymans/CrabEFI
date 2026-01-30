//! Filesystem support
//!
//! This module provides FAT, GPT, and ISO9660/El Torito support for reading
//! the EFI System Partition and booting from installation media.

pub mod fat;
pub mod gpt;
pub mod iso9660;

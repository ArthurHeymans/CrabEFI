//! EFI Protocol implementations
//!
//! This module contains implementations of the EFI protocols needed for booting.

pub mod console;
pub mod device_path;
pub mod loaded_image;
pub mod memory_attribute;
pub mod serial_io;
pub mod simple_file_system;
pub mod unicode_collation;

// TODO: Implement in Phase 3-4
// pub mod block_io;
// pub mod graphics_output;

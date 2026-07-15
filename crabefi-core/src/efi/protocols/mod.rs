//! EFI Protocol implementations
//!
//! This module contains implementations of the EFI protocols needed for booting.

pub mod ata_pass_thru;
pub mod block_io;
pub mod console;
pub mod console_control;
pub mod context_map;
pub mod device_path;
pub mod device_path_from_text;
pub mod device_path_to_text;
pub mod device_path_utilities;
pub mod disk_io;
pub mod graphics_output;
pub mod hii;
pub mod loaded_image;
pub mod memory_attribute;
pub mod nvme_pass_thru;
pub mod pass_thru_init;
pub mod rng;
pub mod scsi_pass_thru;
pub mod serial_io;
pub mod simple_file_system;
#[cfg(feature = "ui")]
pub mod simple_pointer;
pub mod simple_text_input_ex;
pub mod storage_security;
pub mod tcg;
pub mod tcg2;
pub mod unicode_collation;

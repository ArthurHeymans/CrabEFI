//! Coreboot table parsing and system information
//!
//! This module parses the coreboot tables to extract information about
//! the system hardware, including memory map, serial port, framebuffer,
//! and ACPI tables.

pub mod framebuffer;
pub mod memory;
pub mod tables;

pub use framebuffer::FramebufferInfo;
pub use memory::{MemoryRegion, MemoryType};
pub use tables::{CorebootInfo, SerialInfo};

//! Memory map handling for coreboot
//!
//! This module defines the memory region types and provides utilities
//! for working with the memory map from coreboot.

/// Memory region types from coreboot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MemoryType {
    /// Usable RAM
    Ram = 1,
    /// Reserved memory
    Reserved = 2,
    /// ACPI reclaimable memory
    AcpiReclaimable = 3,
    /// ACPI NVS (Non-Volatile Storage)
    AcpiNvs = 4,
    /// Unusable memory
    Unusable = 5,
    /// Coreboot tables
    Table = 16,
}

/// A memory region descriptor
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// Starting physical address
    pub start: u64,
    /// Size in bytes
    pub size: u64,
    /// Type of memory
    pub region_type: MemoryType,
}

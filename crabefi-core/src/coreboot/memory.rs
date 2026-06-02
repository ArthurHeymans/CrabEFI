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

impl TryFrom<u32> for MemoryType {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(MemoryType::Ram),
            2 => Ok(MemoryType::Reserved),
            3 => Ok(MemoryType::AcpiReclaimable),
            4 => Ok(MemoryType::AcpiNvs),
            5 => Ok(MemoryType::Unusable),
            16 => Ok(MemoryType::Table),
            other => Err(other),
        }
    }
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

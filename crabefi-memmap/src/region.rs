/// Physical memory region descriptor.
///
/// The platform provides a list of these to describe the system's physical
/// address space. CrabEFI converts them into the EFI memory map.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// Starting physical address (must be page-aligned, 4 KiB).
    pub base: u64,
    /// Size in bytes (must be page-aligned, 4 KiB).
    pub size: u64,
    /// Type of memory in this region.
    pub region_type: RegionType,
}

/// Memory region types.
///
/// These map directly to EFI memory types. The platform uses them to describe
/// which physical address ranges are usable RAM, reserved, MMIO, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegionType {
    /// Usable RAM (becomes `EfiConventionalMemory`).
    Ram,
    /// Reserved by firmware (becomes `EfiReservedMemoryType`).
    Reserved,
    /// ACPI tables, reclaimable after OS reads them (becomes `EfiACPIReclaimMemory`).
    AcpiReclaimable,
    /// ACPI Non-Volatile Storage (becomes `EfiACPINvsMemory`).
    AcpiNvs,
    /// Memory-mapped I/O registers (becomes `EfiMemoryMappedIO`).
    Mmio,
    /// Boot services data (becomes `EfiBootServicesData`).
    ///
    /// Reclaimed as ConventionalMemory after `ExitBootServices`. Use for
    /// firmware regions that are not needed at runtime (e.g., firmware
    /// BSS/stack when CrabEFI is called as a library).
    BootServicesData,
}

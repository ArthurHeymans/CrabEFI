//! EFI System Table
//!
//! This module provides the EFI System Table structure that is passed to
//! loaded UEFI applications and drivers.

use core::ffi::c_void;
use r_efi::efi::{self, Guid, Handle, TableHeader};
use r_efi::protocols::simple_text_input::Protocol as SimpleTextInputProtocol;
use r_efi::protocols::simple_text_output::Protocol as SimpleTextOutputProtocol;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use crate::state::{self, ConfigurationTable, MAX_CONFIG_TABLES};

/// EFI System Table signature "IBI SYST"
const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453595320494249;

/// EFI System Table revision (2.100 = UEFI 2.10)
const EFI_SYSTEM_TABLE_REVISION: u32 = (2 << 16) | 100;

/// ACPI 2.0 RSDP GUID
pub const ACPI_20_TABLE_GUID: Guid = Guid::from_fields(
    0x8868e871,
    0xe4f1,
    0x11d3,
    0xbc,
    0x22,
    &[0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
);

/// ACPI 1.0 RSDP GUID
pub const ACPI_TABLE_GUID: Guid = Guid::from_fields(
    0xeb9d2d30,
    0x2d88,
    0x11d3,
    0x9a,
    0x16,
    &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
);

/// SMBIOS Table GUID
pub const SMBIOS_TABLE_GUID: Guid = Guid::from_fields(
    0xeb9d2d31,
    0x2d88,
    0x11d3,
    0x9a,
    0x16,
    &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
);

/// SMBIOS 3.0 Table GUID
pub const SMBIOS3_TABLE_GUID: Guid = Guid::from_fields(
    0xf2fd1544,
    0x9794,
    0x4a2c,
    0x99,
    0x2e,
    &[0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94],
);

/// EFI Runtime Properties Table GUID (UEFI 2.8+)
///
/// This configuration table tells the OS which runtime services are available.
/// Linux uses this to determine if SetVariable is supported (needed for efi_pstore).
pub const EFI_RT_PROPERTIES_TABLE_GUID: Guid = Guid::from_fields(
    0xeb66918a,
    0x7eef,
    0x402a,
    0x84,
    0x2e,
    &[0x93, 0x1d, 0x21, 0xc3, 0x8a, 0xe9],
);

// ============================================================================
// EFI Runtime Services Supported Flags (from UEFI Specification)
// ============================================================================

/// GetTime() is supported
pub const EFI_RT_SUPPORTED_GET_TIME: u32 = 0x0001;
/// SetTime() is supported
pub const EFI_RT_SUPPORTED_SET_TIME: u32 = 0x0002;
/// GetWakeupTime() is supported
pub const EFI_RT_SUPPORTED_GET_WAKEUP_TIME: u32 = 0x0004;
/// SetWakeupTime() is supported
pub const EFI_RT_SUPPORTED_SET_WAKEUP_TIME: u32 = 0x0008;
/// GetVariable() is supported
pub const EFI_RT_SUPPORTED_GET_VARIABLE: u32 = 0x0010;
/// GetNextVariableName() is supported
pub const EFI_RT_SUPPORTED_GET_NEXT_VARIABLE_NAME: u32 = 0x0020;
/// SetVariable() is supported
pub const EFI_RT_SUPPORTED_SET_VARIABLE: u32 = 0x0040;
/// SetVirtualAddressMap() is supported
pub const EFI_RT_SUPPORTED_SET_VIRTUAL_ADDRESS_MAP: u32 = 0x0080;
/// ConvertPointer() is supported
pub const EFI_RT_SUPPORTED_CONVERT_POINTER: u32 = 0x0100;
/// GetNextHighMonotonicCount() is supported
pub const EFI_RT_SUPPORTED_GET_NEXT_HIGH_MONOTONIC_COUNT: u32 = 0x0200;
/// ResetSystem() is supported
pub const EFI_RT_SUPPORTED_RESET_SYSTEM: u32 = 0x0400;
/// UpdateCapsule() is supported
pub const EFI_RT_SUPPORTED_UPDATE_CAPSULE: u32 = 0x0800;
/// QueryCapsuleCapabilities() is supported
pub const EFI_RT_SUPPORTED_QUERY_CAPSULE_CAPABILITIES: u32 = 0x1000;
/// QueryVariableInfo() is supported
pub const EFI_RT_SUPPORTED_QUERY_VARIABLE_INFO: u32 = 0x2000;

/// All runtime services supported
pub const EFI_RT_SUPPORTED_ALL: u32 = 0x3fff;

/// EFI Runtime Properties Table version
pub const EFI_RT_PROPERTIES_TABLE_VERSION: u16 = 0x1;

/// EFI Runtime Properties Table
///
/// This table advertises which EFI Runtime Services are supported.
/// Reference: UEFI Specification 2.8+, Section 4.6
#[repr(C)]
pub struct EfiRtPropertiesTable {
    /// Version of the table (must be EFI_RT_PROPERTIES_TABLE_VERSION)
    pub version: u16,
    /// Length of the table in bytes
    pub length: u16,
    /// Bitmask of supported runtime services
    pub runtime_services_supported: u32,
}

/// Static RT Properties Table
///
/// CrabEFI supports:
/// - GetTime (reads from CMOS RTC)
/// - GetVariable, GetNextVariableName, SetVariable, QueryVariableInfo (full variable services)
/// - SetVirtualAddressMap (accepts but identity-maps)
/// - ResetSystem (keyboard controller reset or triple fault)
///
/// CrabEFI does NOT support:
/// - SetTime (not implemented)
/// - GetWakeupTime/SetWakeupTime (not implemented)
/// - ConvertPointer (not implemented)
/// - GetNextHighMonotonicCount (not implemented)
/// - UpdateCapsule/QueryCapsuleCapabilities (not implemented)
static RT_PROPERTIES_TABLE: EfiRtPropertiesTable = EfiRtPropertiesTable {
    version: EFI_RT_PROPERTIES_TABLE_VERSION,
    length: core::mem::size_of::<EfiRtPropertiesTable>() as u16,
    runtime_services_supported: EFI_RT_SUPPORTED_GET_TIME
        | EFI_RT_SUPPORTED_GET_VARIABLE
        | EFI_RT_SUPPORTED_GET_NEXT_VARIABLE_NAME
        | EFI_RT_SUPPORTED_SET_VARIABLE
        | EFI_RT_SUPPORTED_SET_VIRTUAL_ADDRESS_MAP
        | EFI_RT_SUPPORTED_RESET_SYSTEM
        | EFI_RT_SUPPORTED_QUERY_VARIABLE_INFO,
};

/// SMBIOS 2.1 Entry Point structure (32-bit)
///
/// Reference: SMBIOS Reference Specification, Chapter 5.2.1
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct Smbios21Entry {
    /// Anchor string "_SM_"
    anchor: [u8; 4],
    /// Checksum of entry point structure
    checksum: u8,
    /// Length of entry point structure (0x1F for 2.1)
    length: u8,
    /// SMBIOS major version
    major_version: u8,
    /// SMBIOS minor version
    minor_version: u8,
    /// Maximum structure size
    max_struct_size: u16,
    /// Entry point revision
    entry_point_rev: u8,
    /// Formatted area (reserved)
    formatted_area: [u8; 5],
    /// Intermediate anchor "_DMI_"
    intermediate_anchor: [u8; 5],
    /// Intermediate checksum
    intermediate_checksum: u8,
    /// Total length of structure table
    struct_table_length: u16,
    /// 32-bit physical address of structure table
    struct_table_address: u32,
    /// Number of SMBIOS structures
    struct_count: u16,
    /// BCD revision
    bcd_revision: u8,
}

/// SMBIOS 3.0 Entry Point structure (64-bit)
///
/// Reference: SMBIOS Reference Specification, Chapter 5.2.2
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct Smbios30Entry {
    /// Anchor string "_SM3_"
    anchor: [u8; 5],
    /// Checksum of entry point structure
    checksum: u8,
    /// Length of entry point structure (0x18 for 3.0)
    length: u8,
    /// SMBIOS major version
    major_version: u8,
    /// SMBIOS minor version
    minor_version: u8,
    /// SMBIOS docrev
    docrev: u8,
    /// Entry point revision
    entry_point_rev: u8,
    /// Reserved
    reserved: u8,
    /// Maximum size of structure table
    struct_table_max_size: u32,
    /// 64-bit physical address of structure table
    struct_table_address: u64,
}

/// EFI System Table
///
/// This is the main entry point structure passed to EFI applications.
/// It provides access to boot services, runtime services, and configuration tables.
#[repr(C)]
pub struct SystemTable {
    /// Table header
    pub hdr: TableHeader,
    /// Firmware vendor string (null-terminated UCS-2)
    pub firmware_vendor: *const u16,
    /// Firmware revision
    pub firmware_revision: u32,
    /// Console input handle
    pub console_in_handle: Handle,
    /// Console input protocol
    pub con_in: *mut SimpleTextInputProtocol,
    /// Console output handle
    pub console_out_handle: Handle,
    /// Console output protocol
    pub con_out: *mut SimpleTextOutputProtocol,
    /// Standard error handle
    pub standard_error_handle: Handle,
    /// Standard error protocol
    pub std_err: *mut SimpleTextOutputProtocol,
    /// Runtime services table
    pub runtime_services: *mut efi::RuntimeServices,
    /// Boot services table
    pub boot_services: *mut efi::BootServices,
    /// Number of configuration tables
    pub number_of_table_entries: usize,
    /// Array of configuration tables
    pub configuration_table: *mut ConfigurationTable,
}

/// Static storage for the system table
static mut SYSTEM_TABLE: SystemTable = SystemTable {
    hdr: TableHeader {
        signature: EFI_SYSTEM_TABLE_SIGNATURE,
        revision: EFI_SYSTEM_TABLE_REVISION,
        header_size: core::mem::size_of::<SystemTable>() as u32,
        crc32: 0,
        reserved: 0,
    },
    firmware_vendor: core::ptr::null(),
    firmware_revision: 0,
    console_in_handle: core::ptr::null_mut(),
    con_in: core::ptr::null_mut(),
    console_out_handle: core::ptr::null_mut(),
    con_out: core::ptr::null_mut(),
    standard_error_handle: core::ptr::null_mut(),
    std_err: core::ptr::null_mut(),
    runtime_services: core::ptr::null_mut(),
    boot_services: core::ptr::null_mut(),
    number_of_table_entries: 0,
    configuration_table: core::ptr::null_mut(),
};

/// Firmware vendor string "CrabEFI" in UCS-2
static FIRMWARE_VENDOR: [u16; 8] = [
    'C' as u16, 'r' as u16, 'a' as u16, 'b' as u16, 'E' as u16, 'F' as u16, 'I' as u16, 0,
];

/// CrabEFI firmware revision (0.1.0 = 0x00010000)
const CRABEFI_REVISION: u32 = 0x00010000;

/// Initialize the system table
///
/// # Safety
///
/// This function must only be called once during initialization.
pub unsafe fn init(
    boot_services: *mut efi::BootServices,
    runtime_services: *mut efi::RuntimeServices,
) {
    SYSTEM_TABLE.firmware_vendor = FIRMWARE_VENDOR.as_ptr();
    SYSTEM_TABLE.firmware_revision = CRABEFI_REVISION;
    SYSTEM_TABLE.boot_services = boot_services;
    SYSTEM_TABLE.runtime_services = runtime_services;

    // Set up configuration table pointer
    let efi = state::efi();
    SYSTEM_TABLE.configuration_table = efi.config_tables.as_ptr() as *mut ConfigurationTable;

    log::debug!("EFI System Table initialized");
}

/// Get a pointer to the system table
pub fn get_system_table() -> *mut SystemTable {
    &raw mut SYSTEM_TABLE
}

/// Get a pointer to the system table as EFI type
pub fn get_system_table_efi() -> *mut efi::SystemTable {
    // Safety: SystemTable has the same layout as efi::SystemTable
    get_system_table() as *mut efi::SystemTable
}

/// Set the console input protocol
///
/// # Safety
///
/// The protocol pointer must remain valid for the lifetime of boot services.
pub unsafe fn set_console_in(handle: Handle, protocol: *mut SimpleTextInputProtocol) {
    SYSTEM_TABLE.console_in_handle = handle;
    SYSTEM_TABLE.con_in = protocol;
}

/// Set the console output protocol
///
/// # Safety
///
/// The protocol pointer must remain valid for the lifetime of boot services.
pub unsafe fn set_console_out(handle: Handle, protocol: *mut SimpleTextOutputProtocol) {
    SYSTEM_TABLE.console_out_handle = handle;
    SYSTEM_TABLE.con_out = protocol;
}

/// Set the standard error protocol
///
/// # Safety
///
/// The protocol pointer must remain valid for the lifetime of boot services.
pub unsafe fn set_std_err(handle: Handle, protocol: *mut SimpleTextOutputProtocol) {
    SYSTEM_TABLE.standard_error_handle = handle;
    SYSTEM_TABLE.std_err = protocol;
}

/// Install a configuration table
///
/// If a table with the same GUID already exists, it will be updated.
/// If vendor_table is null, the table entry will be removed.
pub fn install_configuration_table(guid: &Guid, table: *mut c_void) -> efi::Status {
    state::with_efi_mut(|efi| {
        let tables = &mut efi.config_tables;
        let count = &mut efi.config_table_count;

        // First, check if this GUID already exists
        if let Some(i) = tables[..*count].iter().position(|t| t.vendor_guid == *guid) {
            if table.is_null() {
                // Remove the entry by shifting others down
                tables.copy_within(i + 1..*count, i);
                *count -= 1;
                update_table_count(*count);
                return efi::Status::SUCCESS;
            } else {
                // Update existing entry
                tables[i].vendor_table = table;
                return efi::Status::SUCCESS;
            }
        }

        // Adding a new entry
        if table.is_null() {
            return efi::Status::NOT_FOUND;
        }

        if *count >= MAX_CONFIG_TABLES {
            return efi::Status::OUT_OF_RESOURCES;
        }

        tables[*count] = ConfigurationTable {
            vendor_guid: *guid,
            vendor_table: table,
        };
        *count += 1;
        update_table_count(*count);

        efi::Status::SUCCESS
    })
}

/// Update the table count in the system table
fn update_table_count(count: usize) {
    unsafe {
        SYSTEM_TABLE.number_of_table_entries = count;
    }
}

/// ACPI RSDP structure (Root System Description Pointer)
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct AcpiRsdp {
    signature: [u8; 8], // "RSD PTR "
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    // ACPI 2.0+ fields
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

/// ACPI SDT header (common to all tables)
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct AcpiSdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// Maximum number of ACPI regions we can track
const MAX_ACPI_REGIONS: usize = 32;

/// An ACPI memory region (page-aligned)
#[derive(Clone, Copy)]
struct AcpiRegion {
    start: u64,
    end: u64,
}

/// Collect all ACPI table regions, merge overlapping ones, then mark them
fn mark_acpi_tables_memory(rsdp_addr: u64) {
    use super::allocator::{PAGE_SIZE, mark_as_acpi_reclaim};

    log::info!("Marking ACPI table memory regions as AcpiReclaimMemory...");

    // Collect all ACPI regions first
    let mut regions: [AcpiRegion; MAX_ACPI_REGIONS] =
        [AcpiRegion { start: 0, end: 0 }; MAX_ACPI_REGIONS];
    let mut region_count = 0;

    // Helper to add a region (page-aligned)
    let mut add_region = |addr: u64, size: u64| {
        if region_count >= MAX_ACPI_REGIONS || size == 0 {
            return;
        }
        let page_start = addr & !(PAGE_SIZE - 1);
        let page_end = (addr + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        regions[region_count] = AcpiRegion {
            start: page_start,
            end: page_end,
        };
        region_count += 1;
    };

    let rsdp = unsafe { &*(rsdp_addr as *const AcpiRsdp) };

    // Validate RSDP signature
    if &rsdp.signature != b"RSD PTR " {
        log::error!("Invalid RSDP signature, cannot mark ACPI memory");
        return;
    }

    let revision = rsdp.revision;

    // Add RSDP
    // With zerocopy's Unaligned derive, we can safely access packed fields
    let rsdp_size = if revision >= 2 {
        rsdp.length as u64
    } else {
        20 // ACPI 1.0 RSDP is 20 bytes
    };
    log::debug!(
        "RSDP at {:#x}, size {} bytes, revision {}",
        rsdp_addr,
        rsdp_size,
        revision
    );
    add_region(rsdp_addr, rsdp_size);

    // Get RSDT or XSDT address
    // With zerocopy's Unaligned derive, we can safely access packed fields
    let (root_table_addr, is_xsdt) = if revision >= 2 && rsdp.xsdt_address != 0 {
        (rsdp.xsdt_address, true)
    } else {
        (rsdp.rsdt_address as u64, false)
    };

    if root_table_addr == 0 {
        log::warn!("No RSDT/XSDT address in RSDP");
        return;
    }

    // Add root table (RSDT or XSDT)
    let root_header = unsafe { &*(root_table_addr as *const AcpiSdtHeader) };
    // With zerocopy's Unaligned derive, we can safely access packed fields
    let root_length = root_header.length;
    let root_sig = &root_header.signature;
    log::debug!(
        "{} at {:#x}, length {} bytes",
        core::str::from_utf8(root_sig).unwrap_or("????"),
        root_table_addr,
        root_length
    );
    add_region(root_table_addr, root_length as u64);

    // Parse each table entry
    let header_size = core::mem::size_of::<AcpiSdtHeader>();
    let entry_size = if is_xsdt { 8 } else { 4 };
    let num_entries = (root_length as usize - header_size) / entry_size;
    log::debug!(
        "  {} has {} table entries",
        if is_xsdt { "XSDT" } else { "RSDT" },
        num_entries
    );

    let entries_base = root_table_addr + header_size as u64;
    for i in 0..num_entries {
        let table_addr = if is_xsdt {
            unsafe { *((entries_base + (i * 8) as u64) as *const u64) }
        } else {
            unsafe { *((entries_base + (i * 4) as u64) as *const u32) as u64 }
        };

        if table_addr == 0 {
            continue;
        }

        let table_header = unsafe { &*(table_addr as *const AcpiSdtHeader) };
        // With zerocopy's Unaligned derive, we can safely access packed fields
        let table_length = table_header.length;
        let table_sig = &table_header.signature;
        let sig_str = core::str::from_utf8(table_sig).unwrap_or("????");

        log::debug!(
            "  Table[{}]: {} at {:#x}, length {} bytes",
            i,
            sig_str,
            table_addr,
            table_length
        );
        add_region(table_addr, table_length as u64);

        // If this is FADT, also add DSDT and FACS
        if table_sig == b"FACP" {
            let fadt_ptr = table_addr as *const u8;

            // Get DSDT address
            let dsdt_addr = if table_length >= 148 {
                let x_dsdt = unsafe { *(fadt_ptr.add(140) as *const u64) };
                if x_dsdt != 0 {
                    x_dsdt
                } else {
                    unsafe { *(fadt_ptr.add(40) as *const u32) as u64 }
                }
            } else {
                unsafe { *(fadt_ptr.add(40) as *const u32) as u64 }
            };

            if dsdt_addr != 0 {
                let dsdt_header = unsafe { &*(dsdt_addr as *const AcpiSdtHeader) };
                // With zerocopy's Unaligned derive, we can safely access packed fields
                let dsdt_length = dsdt_header.length;
                log::debug!("    DSDT at {:#x}, length {} bytes", dsdt_addr, dsdt_length);
                add_region(dsdt_addr, dsdt_length as u64);
            }

            // Get FACS address
            let facs_addr = if table_length >= 140 {
                let x_facs = unsafe { *(fadt_ptr.add(132) as *const u64) };
                if x_facs != 0 {
                    x_facs
                } else {
                    unsafe { *(fadt_ptr.add(36) as *const u32) as u64 }
                }
            } else {
                unsafe { *(fadt_ptr.add(36) as *const u32) as u64 }
            };

            if facs_addr != 0 {
                // FACS has length at offset 4
                let facs_len = unsafe { *((facs_addr + 4) as *const u32) };
                log::debug!("    FACS at {:#x}, length {} bytes", facs_addr, facs_len);
                add_region(facs_addr, facs_len as u64);
            }
        }
    }

    // Sort regions by start address
    regions[..region_count].sort_unstable_by_key(|r| r.start);

    // Merge overlapping/adjacent regions
    let mut merged: [AcpiRegion; MAX_ACPI_REGIONS] =
        [AcpiRegion { start: 0, end: 0 }; MAX_ACPI_REGIONS];
    let mut merged_count = 0;

    for region in regions.iter().take(region_count) {
        if region.start == 0 && region.end == 0 {
            continue;
        }

        if merged_count == 0 {
            merged[0] = *region;
            merged_count = 1;
        } else {
            let last = &mut merged[merged_count - 1];
            // Check if this region overlaps or is adjacent to the last merged region
            if region.start <= last.end {
                // Merge: extend the end if needed
                if region.end > last.end {
                    last.end = region.end;
                }
            } else {
                // No overlap, add as new region
                if merged_count < MAX_ACPI_REGIONS {
                    merged[merged_count] = *region;
                    merged_count += 1;
                }
            }
        }
    }

    // Now mark each merged region once
    log::info!("Marking {} merged ACPI memory regions:", merged_count);
    for region in merged.iter().take(merged_count) {
        let num_pages = (region.end - region.start) / PAGE_SIZE;

        match mark_as_acpi_reclaim(region.start, num_pages) {
            Ok(()) => {
                log::info!(
                    "  Marked {:#x}-{:#x} ({} pages) as AcpiReclaimMemory",
                    region.start,
                    region.end,
                    num_pages
                );
            }
            Err(e) => {
                log::warn!(
                    "  Failed to mark {:#x}-{:#x} as AcpiReclaimMemory: {:?}",
                    region.start,
                    region.end,
                    e
                );
            }
        }
    }

    log::info!("ACPI table memory marking complete");
}

/// Install ACPI tables from coreboot
pub fn install_acpi_tables(rsdp: u64) {
    use super::allocator::{MemoryType, get_memory_type_at};

    if rsdp == 0 {
        log::warn!("ACPI RSDP address is null, skipping ACPI table installation");
        return;
    }

    // Validate RSDP signature first
    let rsdp_ptr = rsdp as *const u8;
    let signature = unsafe { core::slice::from_raw_parts(rsdp_ptr, 8) };
    if signature != b"RSD PTR " {
        log::error!("Invalid RSDP signature at {:#x}: {:?}", rsdp, signature);
        return;
    }

    // Read revision field at offset 15
    let revision = unsafe { *rsdp_ptr.add(15) };
    log::info!(
        "ACPI RSDP at {:#x}: signature valid, revision {}",
        rsdp,
        revision
    );

    // Check what memory type the RSDP is in and mark ACPI regions if needed
    let needs_marking = match get_memory_type_at(rsdp) {
        Some(MemoryType::AcpiReclaimMemory) => {
            log::info!("RSDP is already in AcpiReclaimMemory (correct)");
            false
        }
        Some(MemoryType::AcpiMemoryNvs) => {
            log::info!("RSDP is in AcpiMemoryNvs (acceptable)");
            false
        }
        Some(mem_type) => {
            log::info!(
                "RSDP at {:#x} is in {:?} memory - will mark ACPI regions",
                rsdp,
                mem_type
            );
            true
        }
        None => {
            log::info!(
                "RSDP at {:#x} is not in any known memory region - will mark ACPI regions",
                rsdp
            );
            true
        }
    };

    // Mark all ACPI tables as AcpiReclaimMemory if needed
    if needs_marking {
        mark_acpi_tables_memory(rsdp);
    }

    // Install in EFI configuration table
    if revision >= 2 {
        // ACPI 2.0+
        let status = install_configuration_table(&ACPI_20_TABLE_GUID, rsdp as *mut c_void);
        if status == efi::Status::SUCCESS {
            log::info!("Installed ACPI 2.0 configuration table");
        } else {
            log::error!("Failed to install ACPI 2.0 table: {:?}", status);
        }
    }

    // Also install as ACPI 1.0 for compatibility
    let status = install_configuration_table(&ACPI_TABLE_GUID, rsdp as *mut c_void);
    if status == efi::Status::SUCCESS {
        log::info!("Installed ACPI 1.0 configuration table");
    } else {
        log::error!("Failed to install ACPI 1.0 table: {:?}", status);
    }

    // Log final configuration table state
    let count = state::efi().config_table_count;
    log::info!(
        "Configuration table has {} entries, SystemTable.number_of_table_entries = {}",
        count,
        unsafe { SYSTEM_TABLE.number_of_table_entries }
    );
}

/// Install SMBIOS tables from coreboot
///
/// Coreboot provides SMBIOS tables via a CBMEM entry. The address points to
/// the SMBIOS entry point structure(s). Coreboot may provide:
/// - SMBIOS 2.1 entry point (32-bit, anchor "_SM_") - if tables are below 4GB
/// - SMBIOS 3.0 entry point (64-bit, anchor "_SM3_") - always present
///
/// We install the appropriate configuration table(s) based on what we find.
pub fn install_smbios_tables(smbios_addr: u64) {
    if smbios_addr == 0 {
        log::warn!("SMBIOS address is null, skipping SMBIOS table installation");
        return;
    }

    log::info!("Installing SMBIOS tables from {:#x}", smbios_addr);

    let mut found_21 = false;
    let mut found_30 = false;
    let mut addr_21: u64 = 0;
    let mut addr_30: u64 = 0;

    // Try to find SMBIOS 2.1 entry point ("_SM_")
    let ptr = smbios_addr as *const u8;
    let bytes_21 = unsafe { core::slice::from_raw_parts(ptr, 4) };

    if bytes_21 == b"_SM_" {
        // This is an SMBIOS 2.1 entry point
        let entry_bytes =
            unsafe { core::slice::from_raw_parts(ptr, core::mem::size_of::<Smbios21Entry>()) };

        if let Ok((entry, _)) = Smbios21Entry::read_from_prefix(entry_bytes) {
            // Copy packed struct fields to avoid misaligned references
            let major = entry.major_version;
            let minor = entry.minor_version;
            let length = entry.length;
            let table_addr = entry.struct_table_address;
            let struct_count = entry.struct_count;
            let table_length = entry.struct_table_length;

            // Validate intermediate anchor
            if &entry.intermediate_anchor == b"_DMI_" {
                log::info!(
                    "Found SMBIOS {}.{} entry point at {:#x} (32-bit)",
                    major,
                    minor,
                    smbios_addr
                );
                log::debug!(
                    "  Structure table at {:#x}, {} structures, {} bytes",
                    table_addr,
                    struct_count,
                    table_length
                );
                found_21 = true;
                addr_21 = smbios_addr;

                // SMBIOS 3.0 entry point typically follows after the 2.1 entry
                // It's usually at the next 16-byte aligned address after the 2.1 entry
                let entry_30_offset = (length as usize).div_ceil(16) * 16;
                let ptr_30 = unsafe { ptr.add(entry_30_offset) };
                let bytes_30 = unsafe { core::slice::from_raw_parts(ptr_30, 5) };

                if bytes_30 == b"_SM3_" {
                    let entry30_bytes = unsafe {
                        core::slice::from_raw_parts(ptr_30, core::mem::size_of::<Smbios30Entry>())
                    };

                    if let Ok((entry30, _)) = Smbios30Entry::read_from_prefix(entry30_bytes) {
                        // Copy packed struct fields to avoid misaligned references
                        let major30 = entry30.major_version;
                        let minor30 = entry30.minor_version;
                        let table_addr30 = entry30.struct_table_address;
                        let table_max_size = entry30.struct_table_max_size;
                        let entry30_addr = smbios_addr + entry_30_offset as u64;

                        log::info!(
                            "Found SMBIOS {}.{} entry point at {:#x} (64-bit)",
                            major30,
                            minor30,
                            entry30_addr
                        );
                        log::debug!(
                            "  Structure table at {:#x}, max size {} bytes",
                            table_addr30,
                            table_max_size
                        );
                        found_30 = true;
                        addr_30 = entry30_addr;
                    }
                }
            } else {
                log::warn!(
                    "SMBIOS 2.1 entry has invalid intermediate anchor: {:?}",
                    &entry.intermediate_anchor
                );
            }
        }
    } else {
        // Check if it's directly an SMBIOS 3.0 entry point
        let bytes_30 = unsafe { core::slice::from_raw_parts(ptr, 5) };

        if bytes_30 == b"_SM3_" {
            let entry30_bytes =
                unsafe { core::slice::from_raw_parts(ptr, core::mem::size_of::<Smbios30Entry>()) };

            if let Ok((entry30, _)) = Smbios30Entry::read_from_prefix(entry30_bytes) {
                // Copy packed struct fields to avoid misaligned references
                let major30 = entry30.major_version;
                let minor30 = entry30.minor_version;
                let table_addr30 = entry30.struct_table_address;
                let table_max_size = entry30.struct_table_max_size;

                log::info!(
                    "Found SMBIOS {}.{} entry point at {:#x} (64-bit only)",
                    major30,
                    minor30,
                    smbios_addr
                );
                log::debug!(
                    "  Structure table at {:#x}, max size {} bytes",
                    table_addr30,
                    table_max_size
                );
                found_30 = true;
                addr_30 = smbios_addr;
            }
        } else {
            log::warn!(
                "Unknown SMBIOS signature at {:#x}: {:02x?}",
                smbios_addr,
                bytes_21
            );
            return;
        }
    }

    // Install configuration tables
    // Per UEFI spec, we install SMBIOS 3.0 with SMBIOS3_TABLE_GUID
    // and SMBIOS 2.1 with SMBIOS_TABLE_GUID for backward compatibility
    if found_30 {
        let status = install_configuration_table(&SMBIOS3_TABLE_GUID, addr_30 as *mut c_void);
        if status == efi::Status::SUCCESS {
            log::info!("Installed SMBIOS 3.0 configuration table at {:#x}", addr_30);
        } else {
            log::error!("Failed to install SMBIOS 3.0 table: {:?}", status);
        }
    }

    if found_21 {
        let status = install_configuration_table(&SMBIOS_TABLE_GUID, addr_21 as *mut c_void);
        if status == efi::Status::SUCCESS {
            log::info!("Installed SMBIOS 2.1 configuration table at {:#x}", addr_21);
        } else {
            log::error!("Failed to install SMBIOS 2.1 table: {:?}", status);
        }
    }

    if !found_21 && !found_30 {
        log::warn!("No valid SMBIOS entry point found at {:#x}", smbios_addr);
    }
}

/// Update CRC32 in a UEFI table header.
///
/// Per the UEFI spec, the CRC is computed over `header_size` bytes with the
/// `crc32` field itself zeroed during computation.
unsafe fn update_table_header_crc32(header: *mut TableHeader) {
    let hdr = &mut *header;
    hdr.crc32 = 0;
    let size = hdr.header_size as usize;
    let bytes = core::slice::from_raw_parts(header as *const u8, size);
    hdr.crc32 = super::boot_services::compute_crc32(bytes);
}

/// Recompute CRC32 checksums for the System Table, Boot Services, and Runtime Services.
///
/// Must be called after any modification to these tables (e.g., after installing
/// configuration tables, setting console pointers, etc.) and before handing the
/// system table to an EFI application.
pub fn update_crc32() {
    unsafe {
        // Update Boot Services CRC32
        if !SYSTEM_TABLE.boot_services.is_null() {
            update_table_header_crc32(&raw mut (*SYSTEM_TABLE.boot_services).hdr);
        }
        // Update Runtime Services CRC32
        if !SYSTEM_TABLE.runtime_services.is_null() {
            update_table_header_crc32(&raw mut (*SYSTEM_TABLE.runtime_services).hdr);
        }
        // Update System Table CRC32 (must be last since it covers the whole table)
        update_table_header_crc32(&raw mut SYSTEM_TABLE.hdr);
    }
    log::debug!("Updated CRC32 checksums for System/BS/RT tables");
}

/// Install the EFI Runtime Properties Table
///
/// This table (UEFI 2.8+) tells the OS which runtime services are available.
/// Linux's efi_pstore module needs this to know SetVariable is supported.
///
/// The table is installed with the EFI_RT_PROPERTIES_TABLE_GUID and contains
/// a bitmask of supported runtime services.
pub fn install_rt_properties_table() {
    let table_ptr = &RT_PROPERTIES_TABLE as *const EfiRtPropertiesTable as *mut c_void;

    let status = install_configuration_table(&EFI_RT_PROPERTIES_TABLE_GUID, table_ptr);
    if status == efi::Status::SUCCESS {
        log::info!(
            "Installed EFI RT Properties Table (supported services: {:#06x})",
            RT_PROPERTIES_TABLE.runtime_services_supported
        );

        // Log which services are advertised
        let supported = RT_PROPERTIES_TABLE.runtime_services_supported;
        log::debug!("  Runtime services supported:");
        if supported & EFI_RT_SUPPORTED_GET_TIME != 0 {
            log::debug!("    - GetTime");
        }
        if supported & EFI_RT_SUPPORTED_SET_TIME != 0 {
            log::debug!("    - SetTime");
        }
        if supported & EFI_RT_SUPPORTED_GET_VARIABLE != 0 {
            log::debug!("    - GetVariable");
        }
        if supported & EFI_RT_SUPPORTED_GET_NEXT_VARIABLE_NAME != 0 {
            log::debug!("    - GetNextVariableName");
        }
        if supported & EFI_RT_SUPPORTED_SET_VARIABLE != 0 {
            log::debug!("    - SetVariable");
        }
        if supported & EFI_RT_SUPPORTED_SET_VIRTUAL_ADDRESS_MAP != 0 {
            log::debug!("    - SetVirtualAddressMap");
        }
        if supported & EFI_RT_SUPPORTED_RESET_SYSTEM != 0 {
            log::debug!("    - ResetSystem");
        }
        if supported & EFI_RT_SUPPORTED_QUERY_VARIABLE_INFO != 0 {
            log::debug!("    - QueryVariableInfo");
        }
    } else {
        log::error!("Failed to install RT Properties Table: {:?}", status);
    }
}

/// EFI Memory Attributes Table GUID
pub const EFI_MEMORY_ATTRIBUTES_TABLE_GUID: Guid = Guid::from_fields(
    0xdcfa911d,
    0x26eb,
    0x469f,
    0xa2,
    0x20,
    &[0x38, 0xb7, 0xdc, 0x46, 0x12, 0x20],
);

/// EFI Memory Attributes Table
///
/// Describes the memory protection attributes of runtime regions.
/// Linux and Windows use this to set proper page permissions (RO for code, XP for data)
/// for EFI runtime services memory.
///
/// Reference: UEFI Specification 2.6+, Section 4.6
#[repr(C)]
pub struct EfiMemoryAttributesTable {
    /// Version of the table (must be 1)
    pub version: u32,
    /// Number of EFI_MEMORY_DESCRIPTOR entries
    pub number_of_entries: u32,
    /// Size of each EFI_MEMORY_DESCRIPTOR
    pub descriptor_size: u32,
    /// Reserved, must be zero
    pub reserved: u32,
    // Followed by number_of_entries memory descriptors
}

/// TCG2 Final Events Table GUID
pub const EFI_TCG2_FINAL_EVENTS_TABLE_GUID: Guid = Guid::from_fields(
    0x1e2ed096,
    0x30e2,
    0x4254,
    0xbd,
    0x89,
    &[0x86, 0x3b, 0xbe, 0xf8, 0x23, 0x25],
);

/// TCG2 Final Events Table structure
#[repr(C)]
pub struct Tcg2FinalEventsTable {
    /// Version (must be 1)
    pub version: u64,
    /// Number of events
    pub number_of_events: u64,
}

/// Install minimal TPM2 event log configuration tables
///
/// These tables prevent the kernel from trying to read the TPM event log
/// via ACPI (which fails with CrabEFI's memory layout). An empty log is
/// valid and indicates no measured boot events occurred.
pub fn install_tpm_event_log() {
    static FINAL_EVENTS: Tcg2FinalEventsTable = Tcg2FinalEventsTable {
        version: 1,
        number_of_events: 0,
    };

    let table_ptr = &FINAL_EVENTS as *const Tcg2FinalEventsTable as *mut c_void;
    let status = install_configuration_table(&EFI_TCG2_FINAL_EVENTS_TABLE_GUID, table_ptr);
    if status == efi::Status::SUCCESS {
        log::info!("Installed TCG2 Final Events Table (empty)");
    } else {
        log::error!("Failed to install TCG2 Final Events Table: {:?}", status);
    }
}

/// Install the EFI Memory Attributes Table
///
/// This table describes memory protection attributes for runtime regions.
/// Linux uses it to set proper page permissions (RO for code, XP for data).
/// Windows uses it to validate runtime region mappings.
///
/// Reference: UEFI Specification 2.6+, Section 4.6
pub fn install_memory_attributes_table() {
    use super::allocator::{self, MemoryDescriptor, MemoryType, attributes};

    // Query the memory map size
    let mut map_size: usize = 0;
    let mut map_key: usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_version: u32 = 0;

    let _ = allocator::get_memory_map(
        &mut map_size,
        None,
        &mut map_key,
        &mut desc_size,
        &mut desc_version,
    );

    // Allocate a stack buffer for the memory map (max 512 entries)
    let mut map_buf = [MemoryDescriptor::new(MemoryType::ReservedMemoryType, 0, 0, 0); 512];
    let num_entries = map_size / core::mem::size_of::<MemoryDescriptor>();
    let entries_to_use = num_entries.min(512);

    let status = allocator::get_memory_map(
        &mut map_size,
        Some(&mut map_buf[..entries_to_use]),
        &mut map_key,
        &mut desc_size,
        &mut desc_version,
    );

    if status != efi::Status::SUCCESS {
        log::error!("Failed to get memory map for MEMATTR table: {:?}", status);
        return;
    }

    let actual_entries = map_size / core::mem::size_of::<MemoryDescriptor>();

    // Count runtime entries
    let mut runtime_count: u32 = 0;
    for entry in map_buf[..actual_entries].iter() {
        if entry.attribute & attributes::EFI_MEMORY_RUNTIME != 0 {
            runtime_count += 1;
        }
    }

    if runtime_count == 0 {
        log::warn!("No runtime memory regions found, skipping MEMATTR table");
        return;
    }

    // Allocate memory for the table: header + runtime_count descriptors
    let descriptor_size = core::mem::size_of::<MemoryDescriptor>() as u32;
    let table_size = core::mem::size_of::<EfiMemoryAttributesTable>()
        + (runtime_count as usize) * (descriptor_size as usize);
    let table_pages = (table_size as u64).div_ceil(4096);

    let mut table_addr: u64 = 0;
    let alloc_status = allocator::allocate_pages(
        allocator::AllocateType::AllocateAnyPages,
        MemoryType::BootServicesData,
        table_pages,
        &mut table_addr,
    );

    if alloc_status != efi::Status::SUCCESS {
        log::error!(
            "Failed to allocate memory for MEMATTR table: {:?}",
            alloc_status
        );
        return;
    }

    // Fill in the header
    let header = unsafe { &mut *(table_addr as *mut EfiMemoryAttributesTable) };
    header.version = 1;
    header.number_of_entries = runtime_count;
    header.descriptor_size = descriptor_size;
    header.reserved = 0;

    // Fill in runtime descriptors after the header
    let descs_base = table_addr + core::mem::size_of::<EfiMemoryAttributesTable>() as u64;
    let mut desc_idx: u32 = 0;
    for entry in map_buf[..actual_entries].iter() {
        if entry.attribute & attributes::EFI_MEMORY_RUNTIME != 0 {
            let dest = unsafe {
                &mut *((descs_base + (desc_idx as u64) * (descriptor_size as u64))
                    as *mut MemoryDescriptor)
            };
            *dest = *entry;

            // Set memory protection attributes based on type:
            // RuntimeServicesCode: RO + executable (no XP)
            // RuntimeServicesData: XP + writable (no RO)
            if let Some(mem_type) = entry.get_memory_type() {
                match mem_type {
                    MemoryType::RuntimeServicesCode => {
                        dest.attribute |= attributes::EFI_MEMORY_RO;
                        dest.attribute &= !attributes::EFI_MEMORY_XP;
                    }
                    MemoryType::RuntimeServicesData => {
                        dest.attribute |= attributes::EFI_MEMORY_XP;
                        dest.attribute &= !attributes::EFI_MEMORY_RO;
                    }
                    _ => {
                        dest.attribute |= attributes::EFI_MEMORY_XP;
                    }
                }
            }

            desc_idx += 1;
        }
    }

    // Install as configuration table
    let status =
        install_configuration_table(&EFI_MEMORY_ATTRIBUTES_TABLE_GUID, table_addr as *mut c_void);
    if status == efi::Status::SUCCESS {
        log::info!(
            "Installed EFI Memory Attributes Table ({} runtime entries, {} bytes)",
            runtime_count,
            table_size
        );
    } else {
        log::error!(
            "Failed to install EFI Memory Attributes Table: {:?}",
            status
        );
    }
}

/// Rebuild the Memory Attributes Table in-place without allocating.
///
/// The initial `install_memory_attributes_table()` allocates a full page for the
/// table. This function overwrites that page with the current runtime entries.
/// It must be called just before ExitBootServices locks the allocator, because
/// runtime regions may have been added since init time (e.g. the deferred
/// variable buffer).
///
/// This function does NOT call allocate_pages and does NOT change the map_key.
pub fn rebuild_memory_attributes_table_in_place() {
    use super::allocator::{self, MemoryDescriptor, MemoryType, attributes};

    // Find the existing MEMATTR table pointer from the config table
    let existing_addr = {
        let efi = state::efi();
        efi.config_tables[..efi.config_table_count]
            .iter()
            .find(|t| t.vendor_guid == EFI_MEMORY_ATTRIBUTES_TABLE_GUID)
            .map(|t| t.vendor_table as u64)
    };

    let table_addr = match existing_addr {
        Some(addr) if addr != 0 => addr,
        _ => {
            log::warn!("No existing MEMATTR table to rebuild");
            return;
        }
    };

    // Query the memory map onto a stack buffer
    let mut map_size: usize = 0;
    let mut map_key: usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_version: u32 = 0;

    let _ = allocator::get_memory_map(
        &mut map_size,
        None,
        &mut map_key,
        &mut desc_size,
        &mut desc_version,
    );

    let mut map_buf = [MemoryDescriptor::new(MemoryType::ReservedMemoryType, 0, 0, 0); 512];
    let entries_to_use = (map_size / core::mem::size_of::<MemoryDescriptor>()).min(512);

    let status = allocator::get_memory_map(
        &mut map_size,
        Some(&mut map_buf[..entries_to_use]),
        &mut map_key,
        &mut desc_size,
        &mut desc_version,
    );

    if status != efi::Status::SUCCESS {
        log::error!("Failed to get memory map for MEMATTR rebuild: {:?}", status);
        return;
    }

    let actual_entries = map_size / core::mem::size_of::<MemoryDescriptor>();
    let descriptor_size = core::mem::size_of::<MemoryDescriptor>() as u32;

    // Count runtime entries
    let runtime_count = map_buf[..actual_entries]
        .iter()
        .filter(|e| e.attribute & attributes::EFI_MEMORY_RUNTIME != 0)
        .count() as u32;

    if runtime_count == 0 {
        log::warn!("No runtime regions for MEMATTR rebuild");
        return;
    }

    // Sanity: ensure the table fits in the originally allocated page
    let table_size = core::mem::size_of::<EfiMemoryAttributesTable>()
        + (runtime_count as usize) * (descriptor_size as usize);
    if table_size > 4096 {
        log::error!(
            "MEMATTR table too large for page ({} bytes, {} entries)",
            table_size,
            runtime_count
        );
        return;
    }

    // Overwrite the header
    let header = unsafe { &mut *(table_addr as *mut EfiMemoryAttributesTable) };
    header.version = 1;
    header.number_of_entries = runtime_count;
    header.descriptor_size = descriptor_size;
    header.reserved = 0;

    // Fill runtime descriptors
    let descs_base = table_addr + core::mem::size_of::<EfiMemoryAttributesTable>() as u64;
    let mut desc_idx: u32 = 0;
    for entry in map_buf[..actual_entries].iter() {
        if entry.attribute & attributes::EFI_MEMORY_RUNTIME != 0 {
            let dest = unsafe {
                &mut *((descs_base + (desc_idx as u64) * (descriptor_size as u64))
                    as *mut MemoryDescriptor)
            };
            *dest = *entry;

            if let Some(mem_type) = entry.get_memory_type() {
                match mem_type {
                    MemoryType::RuntimeServicesCode => {
                        dest.attribute |= attributes::EFI_MEMORY_RO;
                        dest.attribute &= !attributes::EFI_MEMORY_XP;
                    }
                    MemoryType::RuntimeServicesData => {
                        dest.attribute |= attributes::EFI_MEMORY_XP;
                        dest.attribute &= !attributes::EFI_MEMORY_RO;
                    }
                    _ => {
                        dest.attribute |= attributes::EFI_MEMORY_XP;
                    }
                }
            }

            desc_idx += 1;
        }
    }

    log::info!(
        "Rebuilt Memory Attributes Table in-place ({} runtime entries, {} bytes)",
        runtime_count,
        table_size
    );
}

/// Dump configuration table entries for debugging
pub fn dump_configuration_tables() {
    let efi = state::efi();
    let tables = &efi.config_tables;
    let count = efi.config_table_count;

    log::debug!("EFI Configuration Table ({} entries):", count);
    for (i, entry) in tables.iter().enumerate().take(count) {
        let guid = &entry.vendor_guid;

        // Try to identify known GUIDs
        let name = if *guid == ACPI_20_TABLE_GUID {
            "ACPI 2.0 RSDP"
        } else if *guid == ACPI_TABLE_GUID {
            "ACPI 1.0 RSDP"
        } else if *guid == SMBIOS_TABLE_GUID {
            "SMBIOS"
        } else if *guid == SMBIOS3_TABLE_GUID {
            "SMBIOS 3.0"
        } else if *guid == EFI_RT_PROPERTIES_TABLE_GUID {
            "RT Properties"
        } else if *guid == EFI_MEMORY_ATTRIBUTES_TABLE_GUID {
            "Memory Attributes"
        } else if *guid == EFI_TCG2_FINAL_EVENTS_TABLE_GUID {
            "TCG2 Final Events"
        } else {
            "Unknown"
        };

        log::debug!("  [{}] {} at {:p}", i, name, entry.vendor_table);
    }
}

/// Clear the boot services pointer
///
/// This MUST be called after ExitBootServices() succeeds, as per UEFI spec:
/// "After ExitBootServices() has been called, the EFI Boot Services Table
/// Header field BootServices is set to NULL."
///
/// # Safety
///
/// This must only be called after ExitBootServices succeeds.
pub unsafe fn clear_boot_services() {
    SYSTEM_TABLE.boot_services = core::ptr::null_mut();
    log::debug!("SystemTable.boot_services set to NULL");
}

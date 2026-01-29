//! EFI System Table
//!
//! This module provides the EFI System Table structure that is passed to
//! loaded UEFI applications and drivers.

use core::ffi::c_void;
use r_efi::efi::{self, Guid, Handle, TableHeader};
use r_efi::protocols::simple_text_input::Protocol as SimpleTextInputProtocol;
use r_efi::protocols::simple_text_output::Protocol as SimpleTextOutputProtocol;

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
    let efi = state::efi_mut();
    let tables = &mut efi.config_tables;
    let count = &mut efi.config_table_count;

    // First, check if this GUID already exists
    for i in 0..*count {
        if guid_eq(&tables[i].vendor_guid, guid) {
            if table.is_null() {
                // Remove the entry by shifting others down
                for j in i..*count - 1 {
                    tables[j] = tables[j + 1];
                }
                *count -= 1;
                update_table_count(*count);
                return efi::Status::SUCCESS;
            } else {
                // Update existing entry
                tables[i].vendor_table = table;
                return efi::Status::SUCCESS;
            }
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
}

/// Update the table count in the system table
fn update_table_count(count: usize) {
    unsafe {
        SYSTEM_TABLE.number_of_table_entries = count;
    }
}

/// Compare two GUIDs for equality
fn guid_eq(a: &Guid, b: &Guid) -> bool {
    // GUIDs are just 16 bytes
    let a_bytes = unsafe { core::slice::from_raw_parts(a as *const Guid as *const u8, 16) };
    let b_bytes = unsafe { core::slice::from_raw_parts(b as *const Guid as *const u8, 16) };
    a_bytes == b_bytes
}

/// ACPI RSDP structure (Root System Description Pointer)
#[repr(C, packed)]
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
    use super::allocator::{mark_as_acpi_reclaim, PAGE_SIZE};

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
    let rsdp_size = if revision >= 2 {
        unsafe { core::ptr::addr_of!(rsdp.length).read_unaligned() as u64 }
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
    let (root_table_addr, is_xsdt) = if revision >= 2 {
        let xsdt = unsafe { core::ptr::addr_of!(rsdp.xsdt_address).read_unaligned() };
        if xsdt != 0 {
            (xsdt, true)
        } else {
            (rsdp.rsdt_address as u64, false)
        }
    } else {
        (rsdp.rsdt_address as u64, false)
    };

    if root_table_addr == 0 {
        log::warn!("No RSDT/XSDT address in RSDP");
        return;
    }

    // Add root table (RSDT or XSDT)
    let root_header = unsafe { &*(root_table_addr as *const AcpiSdtHeader) };
    let root_length = unsafe { core::ptr::addr_of!(root_header.length).read_unaligned() };
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
        let table_length = unsafe { core::ptr::addr_of!(table_header.length).read_unaligned() };
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
                let dsdt_length =
                    unsafe { core::ptr::addr_of!(dsdt_header.length).read_unaligned() };
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

    // Sort regions by start address (simple bubble sort)
    for i in 0..region_count {
        for j in (i + 1)..region_count {
            if regions[j].start < regions[i].start {
                let tmp = regions[i];
                regions[i] = regions[j];
                regions[j] = tmp;
            }
        }
    }

    // Merge overlapping/adjacent regions
    let mut merged: [AcpiRegion; MAX_ACPI_REGIONS] =
        [AcpiRegion { start: 0, end: 0 }; MAX_ACPI_REGIONS];
    let mut merged_count = 0;

    for i in 0..region_count {
        if regions[i].start == 0 && regions[i].end == 0 {
            continue;
        }

        if merged_count == 0 {
            merged[0] = regions[i];
            merged_count = 1;
        } else {
            let last = &mut merged[merged_count - 1];
            // Check if this region overlaps or is adjacent to the last merged region
            if regions[i].start <= last.end {
                // Merge: extend the end if needed
                if regions[i].end > last.end {
                    last.end = regions[i].end;
                }
            } else {
                // No overlap, add as new region
                if merged_count < MAX_ACPI_REGIONS {
                    merged[merged_count] = regions[i];
                    merged_count += 1;
                }
            }
        }
    }

    // Now mark each merged region once
    log::info!("Marking {} merged ACPI memory regions:", merged_count);
    for i in 0..merged_count {
        let region = &merged[i];
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
    use super::allocator::{get_memory_type_at, MemoryType};

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

/// Update the system table CRC32
pub fn update_crc32() {
    // For now, we leave CRC32 as 0
    // A proper implementation would calculate CRC32 of the table
    unsafe {
        SYSTEM_TABLE.hdr.crc32 = 0;
    }
}

/// Dump configuration table entries for debugging
pub fn dump_configuration_tables() {
    let efi = state::efi();
    let tables = &efi.config_tables;
    let count = efi.config_table_count;

    log::debug!("EFI Configuration Table ({} entries):", count);
    for i in 0..count {
        let entry = &tables[i];
        let guid = &entry.vendor_guid;

        // Try to identify known GUIDs
        let name = if guid_eq(guid, &ACPI_20_TABLE_GUID) {
            "ACPI 2.0 RSDP"
        } else if guid_eq(guid, &ACPI_TABLE_GUID) {
            "ACPI 1.0 RSDP"
        } else if guid_eq(guid, &SMBIOS_TABLE_GUID) {
            "SMBIOS"
        } else if guid_eq(guid, &SMBIOS3_TABLE_GUID) {
            "SMBIOS 3.0"
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

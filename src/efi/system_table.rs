//! EFI System Table
//!
//! This module provides the EFI System Table structure that is passed to
//! loaded UEFI applications and drivers.

use core::ffi::c_void;
use r_efi::efi::{self, Guid, Handle, TableHeader};
use r_efi::protocols::simple_text_input::Protocol as SimpleTextInputProtocol;
use r_efi::protocols::simple_text_output::Protocol as SimpleTextOutputProtocol;
use spin::Mutex;

/// EFI System Table signature "IBI SYST"
const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453595320494249;

/// EFI System Table revision (2.100 = UEFI 2.10)
const EFI_SYSTEM_TABLE_REVISION: u32 = (2 << 16) | 100;

/// Maximum number of configuration tables
const MAX_CONFIG_TABLES: usize = 16;

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

/// EFI Configuration Table entry
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ConfigurationTable {
    /// GUID identifying the table
    pub vendor_guid: Guid,
    /// Pointer to the table
    pub vendor_table: *mut c_void,
}

// Safety: ConfigurationTable contains raw pointers but we only access them
// while holding the CONFIG_TABLES lock, ensuring thread safety.
unsafe impl Send for ConfigurationTable {}

impl ConfigurationTable {
    pub const fn empty() -> Self {
        Self {
            vendor_guid: Guid::from_fields(0, 0, 0, 0, 0, &[0, 0, 0, 0, 0, 0]),
            vendor_table: core::ptr::null_mut(),
        }
    }
}

/// Static storage for configuration tables
static CONFIG_TABLES: Mutex<[ConfigurationTable; MAX_CONFIG_TABLES]> =
    Mutex::new([ConfigurationTable::empty(); MAX_CONFIG_TABLES]);
static CONFIG_TABLE_COUNT: Mutex<usize> = Mutex::new(0);

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
    let tables = CONFIG_TABLES.lock();
    SYSTEM_TABLE.configuration_table = tables.as_ptr() as *mut ConfigurationTable;
    drop(tables);

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
    let mut tables = CONFIG_TABLES.lock();
    let mut count = CONFIG_TABLE_COUNT.lock();

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

/// Install ACPI tables from coreboot
pub fn install_acpi_tables(rsdp: u64) {
    if rsdp == 0 {
        return;
    }

    // Detect ACPI version from RSDP
    let rsdp_ptr = rsdp as *const u8;
    let revision = unsafe { *rsdp_ptr.add(15) }; // Revision field at offset 15

    if revision >= 2 {
        // ACPI 2.0+
        let status = install_configuration_table(&ACPI_20_TABLE_GUID, rsdp as *mut c_void);
        if status == efi::Status::SUCCESS {
            log::info!("Installed ACPI 2.0 table at {:#x}", rsdp);
        }
    }

    // Also install as ACPI 1.0 for compatibility
    let status = install_configuration_table(&ACPI_TABLE_GUID, rsdp as *mut c_void);
    if status == efi::Status::SUCCESS {
        log::debug!("Installed ACPI 1.0 table at {:#x}", rsdp);
    }
}

/// Update the system table CRC32
pub fn update_crc32() {
    // For now, we leave CRC32 as 0
    // A proper implementation would calculate CRC32 of the table
    unsafe {
        SYSTEM_TABLE.hdr.crc32 = 0;
    }
}

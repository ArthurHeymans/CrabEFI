//! Boot-time discovery and client calls for image-owned EFI tables.
//!
//! Runtime Services, System Table, vendor string, configuration entries,
//! Runtime Properties, Memory Attributes, and ESRT storage all live in the
//! separately allocated runtime image. This module retains only platform table
//! validation and immediate boot-side registration.

use core::ffi::c_void;

use crabefi_efi_types::crc32;
use crabefi_runtime_abi::{ConfigurationRegistration, ConsoleRegistration, configuration_policy};
use r_efi::efi::{self, Guid, Handle, TableHeader};
use r_efi::protocols::simple_text_input::Protocol as SimpleTextInputProtocol;
use r_efi::protocols::simple_text_output::Protocol as SimpleTextOutputProtocol;
use spin::Mutex;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use crate::efi::tcg::types::{CryptoAgileEvent, TaggedDigest, TcgError};
use crate::state;

/// ACPI 2.0 RSDP GUID.
pub const ACPI_20_TABLE_GUID: Guid = Guid::from_fields(
    0x8868e871,
    0xe4f1,
    0x11d3,
    0xbc,
    0x22,
    &[0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81],
);
/// ACPI 1.0 RSDP GUID.
pub const ACPI_TABLE_GUID: Guid = Guid::from_fields(
    0xeb9d2d30,
    0x2d88,
    0x11d3,
    0x9a,
    0x16,
    &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
);
/// SMBIOS 2.x table GUID.
pub const SMBIOS_TABLE_GUID: Guid = Guid::from_fields(
    0xeb9d2d31,
    0x2d88,
    0x11d3,
    0x9a,
    0x16,
    &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
);
/// SMBIOS 3.x table GUID.
pub const SMBIOS3_TABLE_GUID: Guid = Guid::from_fields(
    0xf2fd1544,
    0x9794,
    0x4a2c,
    0x99,
    0x2e,
    &[0xe5, 0xbb, 0xcf, 0x20, 0xe3, 0x94],
);
/// Flattened Device Tree configuration table GUID.
pub const EFI_DTB_TABLE_GUID: Guid = Guid::from_fields(
    0xb1b621d5,
    0xf19c,
    0x41a5,
    0x83,
    0x0b,
    &[0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0],
);
/// Runtime Properties table GUID, generated inside the runtime image.
pub const EFI_RT_PROPERTIES_TABLE_GUID: Guid = Guid::from_fields(
    0xeb66918a,
    0x7eef,
    0x402a,
    0x84,
    0x2e,
    &[0x93, 0x1d, 0x21, 0xc3, 0x8a, 0xe9],
);

#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct Smbios21Entry {
    anchor: [u8; 4],
    checksum: u8,
    length: u8,
    major_version: u8,
    minor_version: u8,
    max_struct_size: u16,
    entry_point_rev: u8,
    formatted_area: [u8; 5],
    intermediate_anchor: [u8; 5],
    intermediate_checksum: u8,
    struct_table_length: u16,
    struct_table_address: u32,
    struct_count: u16,
    bcd_revision: u8,
}

#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct Smbios30Entry {
    anchor: [u8; 5],
    checksum: u8,
    length: u8,
    major_version: u8,
    minor_version: u8,
    docrev: u8,
    entry_point_rev: u8,
    reserved: u8,
    struct_table_max_size: u32,
    struct_table_address: u64,
}

pub type SystemTable = efi::SystemTable;

/// Verify that the mandatory image client has already published its tables.
///
/// Called once during single-threaded EFI initialization.
pub fn init() {
    assert!(
        !get_system_table().is_null(),
        "runtime image System Table is unavailable"
    );
}

pub fn get_system_table() -> *mut SystemTable {
    super::runtime_image::client::get_system_table()
}

pub fn get_system_table_efi() -> *mut efi::SystemTable {
    get_system_table()
}

/// Set the boot-only console input fields in image-owned storage.
pub(crate) fn set_console_in(handle: Handle, protocol: *mut SimpleTextInputProtocol) {
    set_console(0, handle, protocol.cast());
}

/// Set the boot-only console output fields in image-owned storage.
pub(crate) fn set_console_out(handle: Handle, protocol: *mut SimpleTextOutputProtocol) {
    set_console(1, handle, protocol.cast());
}

/// Set the boot-only standard-error fields in image-owned storage.
pub(crate) fn set_std_err(handle: Handle, protocol: *mut SimpleTextOutputProtocol) {
    set_console(2, handle, protocol.cast());
}

fn set_console(kind: u32, handle: Handle, protocol: *mut c_void) {
    let status = state::efi()
        .runtime_image
        .ok_or(efi::Status::NOT_READY)
        .and_then(|client| {
            client.set_console(&ConsoleRegistration {
                kind,
                reserved: 0,
                handle: handle as u64,
                protocol: protocol as u64,
            })
        });
    assert!(
        status.is_ok(),
        "runtime image rejected console registration"
    );
}

/// Install a boot-created physical handoff table in image-owned configuration storage.
///
/// UEFI applications such as the Linux EFI stub install their own configuration
/// tables before EBS. Their payload storage remains at its physical address;
/// only image-owned runtime tables are converted during SVAM.
pub fn install_configuration_table(guid: &Guid, table: *mut c_void) -> efi::Status {
    let Some(client) = state::efi().runtime_image else {
        return efi::Status::NOT_READY;
    };
    let mut guid_bytes = [0u8; 16];
    guid_bytes.copy_from_slice(guid.as_bytes());
    match client.register_configuration(&ConfigurationRegistration {
        guid: guid_bytes,
        table_address: table as u64,
        policy: configuration_policy::PLATFORM_PHYSICAL,
        reserved: 0,
    }) {
        Ok(()) => efi::Status::SUCCESS,
        Err(status) => status,
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
            unsafe { ((entries_base + (i * 8) as u64) as *const u64).read_unaligned() }
        } else {
            unsafe { ((entries_base + (i * 4) as u64) as *const u32).read_unaligned() as u64 }
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

            // Get DSDT address (use read_unaligned: FADT field offsets are not naturally aligned)
            let dsdt_addr = if table_length >= 148 {
                let x_dsdt = unsafe { (fadt_ptr.add(140) as *const u64).read_unaligned() };
                if x_dsdt != 0 {
                    x_dsdt
                } else {
                    unsafe { (fadt_ptr.add(40) as *const u32).read_unaligned() as u64 }
                }
            } else {
                unsafe { (fadt_ptr.add(40) as *const u32).read_unaligned() as u64 }
            };

            if dsdt_addr != 0 {
                let dsdt_header = unsafe { &*(dsdt_addr as *const AcpiSdtHeader) };
                // With zerocopy's Unaligned derive, we can safely access packed fields
                let dsdt_length = dsdt_header.length;
                log::debug!("    DSDT at {:#x}, length {} bytes", dsdt_addr, dsdt_length);
                add_region(dsdt_addr, dsdt_length as u64);
            }

            // Get FACS address (use read_unaligned: FADT field offsets are not naturally aligned)
            let facs_addr = if table_length >= 140 {
                let x_facs = unsafe { (fadt_ptr.add(132) as *const u64).read_unaligned() };
                if x_facs != 0 {
                    x_facs
                } else {
                    unsafe { (fadt_ptr.add(36) as *const u32).read_unaligned() as u64 }
                }
            } else {
                unsafe { (fadt_ptr.add(36) as *const u32).read_unaligned() as u64 }
            };

            if facs_addr != 0 {
                // FACS has length at offset 4
                let facs_len = unsafe { ((facs_addr + 4) as *const u32).read_unaligned() };
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

    // Walk the complete table chain so RAM-backed tables are re-typed even
    // when the RSDP itself lives in platform-reserved memory. The allocator
    // preserves tables already covered by ReservedMemoryType,
    // AcpiReclaimMemory, or AcpiMemoryNvs descriptors.
    mark_acpi_tables_memory(rsdp);

    // Install in EFI configuration table.
    //
    // Publish the RSDP under exactly one GUID, chosen to match its own
    // revision. Handing an ACPI 2.0 (rev >= 2) RSDP to the OS twice via both
    // GUIDs makes it walk/reserve the table chain twice (e.g. Linux reports
    // and reserves FACS twice) and violates the expectation that the legacy
    // GUID carries a genuine rev-1 RSDP. Only use the legacy GUID when the
    // RSDP really is rev 1.
    let status = if revision >= 2 {
        install_configuration_table(&ACPI_20_TABLE_GUID, rsdp as *mut c_void)
    } else {
        install_configuration_table(&ACPI_TABLE_GUID, rsdp as *mut c_void)
    };
    if status == efi::Status::SUCCESS {
        let version = if revision >= 2 { "2.0" } else { "1.0" };
        log::info!("Installed ACPI {} configuration table", version);
    } else {
        log::error!(
            "Failed to install ACPI {} table: {:?}",
            if revision >= 2 { "2.0" } else { "1.0" },
            status
        );
    }

    let system_table = get_system_table();
    if !system_table.is_null() {
        // SAFETY: the validated runtime image owns an initialized System Table.
        log::info!("Configuration table has {} entries", unsafe {
            (*system_table).number_of_table_entries
        });
    }
}

/// Install a device tree blob (FDT) as an EFI configuration table
///
/// The FDT pointer must point to a valid flattened device tree blob in memory.
/// The OS (e.g. Linux) will use this to discover hardware on platforms without ACPI.
pub fn install_devicetree(fdt_addr: u64, fdt_size: u32) {
    if fdt_addr == 0 || fdt_size == 0 {
        log::warn!("Devicetree address/size is zero, skipping");
        return;
    }

    // Validate FDT magic (0xd00dfeed in big-endian)
    let magic = unsafe { *(fdt_addr as *const u32) };
    if u32::from_be(magic) != 0xd00dfeed {
        log::error!(
            "Invalid FDT magic at {:#x}: {:#010x}",
            fdt_addr,
            u32::from_be(magic)
        );
        return;
    }

    let status = install_configuration_table(&EFI_DTB_TABLE_GUID, fdt_addr as *mut c_void);
    if status == efi::Status::SUCCESS {
        log::info!(
            "Installed devicetree configuration table ({} bytes at {:#x})",
            fdt_size,
            fdt_addr
        );
    } else {
        log::error!("Failed to install devicetree table: {:?}", status);
    }
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
                    entry.intermediate_anchor
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
    unsafe {
        let hdr = &mut *header;
        hdr.crc32 = 0;
        let size = hdr.header_size as usize;
        let bytes = core::slice::from_raw_parts(header as *const u8, size);
        hdr.crc32 = crc32::calculate(bytes);
    }
}

/// Recompute the boot-owned Boot Services CRC.
///
/// Runtime/System CRCs are maintained by image registration and seal exports.
pub fn update_crc32() {
    let boot_services = super::boot_services::get_boot_services();
    if !boot_services.is_null() {
        // SAFETY: BOOT_SERVICES is boot-owned and initialized for this phase.
        unsafe { update_table_header_crc32(core::ptr::addr_of_mut!((*boot_services).hdr)) };
    }
}

/// Runtime Properties is constructed and registered by image activation.
pub fn install_rt_properties_table() {}

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

const TCG2_FINAL_EVENTS_CAPACITY: usize = 64 * 1024;

struct Tcg2FinalEventsStorage {
    table_addr: usize,
    used: usize,
}

static TCG2_FINAL_EVENTS: Mutex<Option<Tcg2FinalEventsStorage>> = Mutex::new(None);

/// Install the TCG2 Final Events Table configuration table.
///
/// The Final Events Table tracks events measured *after* `GetEventLog`
/// is first called. This is separate from the main TCG2 event log
/// (which is returned by `EFI_TCG2_PROTOCOL.GetEventLog`). The OS
/// kernel concatenates both to get the complete measurement history.
pub fn install_tpm_event_log() {
    use super::allocator::{self, MemoryType};

    let mut final_events = TCG2_FINAL_EVENTS.lock();
    if final_events.is_none() {
        let table_size = core::mem::size_of::<Tcg2FinalEventsTable>() + TCG2_FINAL_EVENTS_CAPACITY;
        let table_pages = (table_size as u64).div_ceil(allocator::PAGE_SIZE);
        let mut table_addr = 0u64;
        let alloc_status = allocator::allocate_pages(
            allocator::AllocateType::AllocateAnyPages,
            MemoryType::AcpiMemoryNvs,
            table_pages,
            &mut table_addr,
        );
        if alloc_status != efi::Status::SUCCESS {
            log::error!(
                "Failed to allocate TCG2 Final Events Table: {:?}",
                alloc_status
            );
            return;
        }
        *final_events = Some(Tcg2FinalEventsStorage {
            table_addr: table_addr as usize,
            used: 0,
        });
    }

    let Some(storage) = final_events.as_mut() else {
        return;
    };
    storage.used = 0;

    let table_ptr = storage.table_addr as *mut Tcg2FinalEventsTable;
    unsafe {
        core::ptr::write_bytes(
            table_ptr as *mut u8,
            0,
            core::mem::size_of::<Tcg2FinalEventsTable>() + TCG2_FINAL_EVENTS_CAPACITY,
        );
        (*table_ptr).version = 1;
        (*table_ptr).number_of_events = 0;
    }
    drop(final_events);

    let status =
        install_configuration_table(&EFI_TCG2_FINAL_EVENTS_TABLE_GUID, table_ptr as *mut c_void);
    if status == efi::Status::SUCCESS {
        log::info!("Installed TCG2 Final Events Table");
    } else {
        log::error!("Failed to install TCG2 Final Events Table: {:?}", status);
    }
}

/// Append an event to the TCG2 Final Events Table.
pub fn append_tpm_final_event(
    pcr_index: u32,
    event_type: u32,
    digests: &[TaggedDigest],
    event_data: &[u8],
) -> Result<(), TcgError> {
    let event = CryptoAgileEvent {
        pcr_index,
        event_type,
        digests,
        event_data,
    };
    let needed = event.serialized_size();

    let mut final_events = TCG2_FINAL_EVENTS.lock();
    let final_events = final_events.as_mut().ok_or(TcgError::InternalError)?;
    if final_events.used + needed > TCG2_FINAL_EVENTS_CAPACITY {
        log::warn!(
            "TCG2 Final Events Table full; truncating final event type={:#x} pcr={}",
            event_type,
            pcr_index
        );
        return Ok(());
    }

    let table_ptr = final_events.table_addr as *mut Tcg2FinalEventsTable;
    let events_ptr =
        unsafe { (table_ptr as *mut u8).add(core::mem::size_of::<Tcg2FinalEventsTable>()) };
    let used = final_events.used;
    let written = unsafe {
        let events = core::slice::from_raw_parts_mut(
            events_ptr.add(used),
            TCG2_FINAL_EVENTS_CAPACITY - used,
        );
        event.serialize(events).ok_or(TcgError::InternalError)?
    };
    final_events.used += written;
    unsafe {
        (*table_ptr).number_of_events += 1;
    }
    Ok(())
}

/// Runtime image activation already installs image-owned MAT storage.
pub fn install_memory_attributes_table() {}

/// Refresh image-owned MAT storage from the final allocator map in place.
pub fn rebuild_memory_attributes_table_in_place() -> efi::Status {
    use super::allocator::{self, MemoryDescriptor, MemoryType};
    let mut descriptors =
        [MemoryDescriptor::new(MemoryType::ReservedMemoryType as u32, 0, 0, 0); 32];
    let count = match allocator::copy_runtime_descriptors(&mut descriptors) {
        Ok(count) => count,
        Err(status) => {
            log::error!("Runtime MAT capacity exceeded: {:?}", status);
            return status;
        }
    };
    let Some(client) = state::efi().runtime_image else {
        return efi::Status::NOT_READY;
    };
    match client.prepare_ebs(&descriptors[..count]) {
        Ok(()) => efi::Status::SUCCESS,
        Err(status) => {
            log::error!("Runtime image rejected final MAT: {:?}", status);
            status
        }
    }
}

/// Dump image-owned configuration table entries for debugging.
pub fn dump_configuration_tables() {
    let system = get_system_table();
    if system.is_null() {
        return;
    }
    // SAFETY: image activation initialized the table and bounded count.
    let (table, count) = unsafe {
        (
            (*system).configuration_table,
            (*system).number_of_table_entries,
        )
    };
    if table.is_null() {
        return;
    }
    log::debug!("EFI Configuration Table ({} entries):", count);
    for index in 0..count {
        // SAFETY: count and storage are owned and bounded by the runtime image.
        let entry = unsafe { &*table.add(index) };
        log::debug!(
            "  [{}] GUID={:?} at {:p}",
            index,
            entry.vendor_guid,
            entry.vendor_table
        );
    }
}

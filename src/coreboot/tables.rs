//! Coreboot table parser
//!
//! Parses the coreboot tables to extract system information.
//! Reference: coreboot/src/commonlib/include/commonlib/coreboot_tables.h

use super::framebuffer::FramebufferInfo;
use super::memory::{MemoryRegion, MemoryType};
use heapless::Vec;

/// Maximum number of memory regions we can store
const MAX_MEMORY_REGIONS: usize = 64;

/// Coreboot table tags
mod tags {
    pub const CB_TAG_UNUSED: u32 = 0x0000;
    pub const CB_TAG_MEMORY: u32 = 0x0001;
    pub const CB_TAG_HWRPB: u32 = 0x0002;
    pub const CB_TAG_MAINBOARD: u32 = 0x0003;
    pub const CB_TAG_VERSION: u32 = 0x0004;
    pub const CB_TAG_EXTRA_VERSION: u32 = 0x0005;
    pub const CB_TAG_BUILD: u32 = 0x0006;
    pub const CB_TAG_COMPILE_TIME: u32 = 0x0007;
    pub const CB_TAG_COMPILE_BY: u32 = 0x0008;
    pub const CB_TAG_COMPILE_HOST: u32 = 0x0009;
    pub const CB_TAG_COMPILE_DOMAIN: u32 = 0x000a;
    pub const CB_TAG_COMPILER: u32 = 0x000b;
    pub const CB_TAG_LINKER: u32 = 0x000c;
    pub const CB_TAG_ASSEMBLER: u32 = 0x000d;
    pub const CB_TAG_SERIAL: u32 = 0x000f;
    pub const CB_TAG_CONSOLE: u32 = 0x0010;
    pub const CB_TAG_FORWARD: u32 = 0x0011;
    pub const CB_TAG_FRAMEBUFFER: u32 = 0x0012;
    pub const CB_TAG_TIMESTAMPS: u32 = 0x0016;
    pub const CB_TAG_CBMEM_CONSOLE: u32 = 0x0017;
    pub const CB_TAG_ACPI_RSDP: u32 = 0x0043;
}

/// Coreboot header structure
#[repr(C, packed)]
struct CbHeader {
    signature: [u8; 4],
    header_bytes: u32,
    header_checksum: u32,
    table_bytes: u32,
    table_checksum: u32,
    table_entries: u32,
}

/// Coreboot record header
#[repr(C, packed)]
struct CbRecord {
    tag: u32,
    size: u32,
}

/// Coreboot memory range
#[repr(C, packed)]
struct CbMemoryRange {
    start: u64,
    size: u64,
    mem_type: u32,
}

/// Coreboot serial port info
#[repr(C, packed)]
struct CbSerial {
    tag: u32,
    size: u32,
    serial_type: u32,
    baseaddr: u32,
    baud: u32,
    regwidth: u32,
    input_hertz: u32,
    uart_pci_addr: u32,
}

/// Coreboot framebuffer info
#[repr(C, packed)]
struct CbFramebuffer {
    tag: u32,
    size: u32,
    physical_address: u64,
    x_resolution: u32,
    y_resolution: u32,
    bytes_per_line: u32,
    bits_per_pixel: u8,
    red_mask_pos: u8,
    red_mask_size: u8,
    green_mask_pos: u8,
    green_mask_size: u8,
    blue_mask_pos: u8,
    blue_mask_size: u8,
    reserved_mask_pos: u8,
    reserved_mask_size: u8,
}

/// Forward pointer to another coreboot table
#[repr(C, packed)]
struct CbForward {
    tag: u32,
    size: u32,
    forward: u64,
}

/// ACPI RSDP pointer
#[repr(C, packed)]
struct CbAcpiRsdp {
    tag: u32,
    size: u32,
    rsdp_pointer: u64,
}

/// Serial port information
#[derive(Debug, Clone)]
pub struct SerialInfo {
    pub serial_type: u32,
    pub baseaddr: u32,
    pub baud: u32,
    pub regwidth: u32,
    pub input_hertz: u32,
}

/// Information extracted from coreboot tables
pub struct CorebootInfo {
    /// Memory map
    pub memory_map: Vec<MemoryRegion, MAX_MEMORY_REGIONS>,
    /// Serial port configuration
    pub serial: Option<SerialInfo>,
    /// Framebuffer information
    pub framebuffer: Option<FramebufferInfo>,
    /// ACPI RSDP pointer
    pub acpi_rsdp: Option<u64>,
    /// Coreboot version string
    pub version: Option<&'static str>,
}

impl CorebootInfo {
    fn new() -> Self {
        CorebootInfo {
            memory_map: Vec::new(),
            serial: None,
            framebuffer: None,
            acpi_rsdp: None,
            version: None,
        }
    }
}

/// Parse coreboot tables starting at the given pointer
///
/// # Safety
///
/// The pointer must point to valid coreboot tables.
pub fn parse(ptr: *const u8) -> CorebootInfo {
    let mut info = CorebootInfo::new();

    if ptr.is_null() {
        log::warn!("Coreboot table pointer is null");
        return info;
    }

    unsafe {
        // Try to find the coreboot header
        // It can be at the pointer directly, or we may need to search
        let header = find_header(ptr);
        if header.is_none() {
            log::warn!("Could not find coreboot header");
            return info;
        }

        let header = header.unwrap();

        // Verify signature "LBIO"
        if &(*header).signature != b"LBIO" {
            log::warn!("Invalid coreboot header signature");
            return info;
        }

        // Read fields from packed struct using read_unaligned
        let table_entries = core::ptr::addr_of!((*header).table_entries).read_unaligned();
        let table_bytes = core::ptr::addr_of!((*header).table_bytes).read_unaligned();
        let header_bytes = core::ptr::addr_of!((*header).header_bytes).read_unaligned();

        log::debug!(
            "Found coreboot header: {} table entries, {} bytes",
            table_entries,
            table_bytes
        );

        // Parse table entries
        let table_start = (header as *const u8).add(header_bytes as usize);
        let mut offset = 0u32;

        while offset < table_bytes {
            let record = table_start.add(offset as usize) as *const CbRecord;
            let record_size = core::ptr::addr_of!((*record).size).read_unaligned();

            if record_size < 8 {
                log::warn!("Invalid record size: {}", record_size);
                break;
            }

            parse_record(record, &mut info);

            offset += record_size;
        }
    }

    info
}

/// Find the coreboot header, following forward pointers if needed
unsafe fn find_header(ptr: *const u8) -> Option<*const CbHeader> {
    let header = ptr as *const CbHeader;

    // Check if this is a valid header
    if (*header).signature == *b"LBIO" {
        return Some(header);
    }

    // It might be at a different location, search common areas
    // Coreboot tables are typically at 0x0 or in high memory

    // For now, assume the pointer is correct
    // TODO: Search for the header in memory

    None
}

/// Parse a single coreboot record
unsafe fn parse_record(record: *const CbRecord, info: &mut CorebootInfo) {
    let tag = (*record).tag;

    match tag {
        tags::CB_TAG_MEMORY => {
            parse_memory(record, info);
        }
        tags::CB_TAG_SERIAL => {
            parse_serial(record, info);
        }
        tags::CB_TAG_FRAMEBUFFER => {
            parse_framebuffer(record, info);
        }
        tags::CB_TAG_FORWARD => {
            parse_forward(record, info);
        }
        tags::CB_TAG_ACPI_RSDP => {
            parse_acpi_rsdp(record, info);
        }
        tags::CB_TAG_VERSION => {
            // Version string follows the record header
            let string_ptr = (record as *const u8).add(8);
            let len = (*record).size as usize - 8;
            if len > 0 {
                let slice = core::slice::from_raw_parts(string_ptr, len);
                if let Ok(s) = core::str::from_utf8(slice) {
                    info.version = Some(s.trim_end_matches('\0'));
                    log::debug!("Coreboot version: {}", info.version.unwrap());
                }
            }
        }
        _ => {
            log::trace!("Ignoring coreboot tag: {:#x}", tag);
        }
    }
}

/// Parse memory map from coreboot table
unsafe fn parse_memory(record: *const CbRecord, info: &mut CorebootInfo) {
    let size = (*record).size;
    let data = (record as *const u8).add(8); // Skip header
    let num_entries = (size as usize - 8) / core::mem::size_of::<CbMemoryRange>();

    log::debug!("Parsing {} memory regions", num_entries);

    for i in 0..num_entries {
        let range = &*(data.add(i * core::mem::size_of::<CbMemoryRange>()) as *const CbMemoryRange);

        let region_type = match range.mem_type {
            1 => MemoryType::Ram,
            2 => MemoryType::Reserved,
            3 => MemoryType::AcpiReclaimable,
            4 => MemoryType::AcpiNvs,
            5 => MemoryType::Unusable,
            16 => MemoryType::Table,
            _ => MemoryType::Reserved,
        };

        let region = MemoryRegion {
            start: range.start,
            size: range.size,
            region_type,
        };

        if info.memory_map.push(region).is_err() {
            log::warn!("Memory map full, ignoring remaining regions");
            break;
        }
    }
}

/// Parse serial port information
unsafe fn parse_serial(record: *const CbRecord, info: &mut CorebootInfo) {
    let serial = record as *const CbSerial;

    let serial_type = core::ptr::addr_of!((*serial).serial_type).read_unaligned();
    let baseaddr = core::ptr::addr_of!((*serial).baseaddr).read_unaligned();
    let baud = core::ptr::addr_of!((*serial).baud).read_unaligned();
    let regwidth = core::ptr::addr_of!((*serial).regwidth).read_unaligned();
    let input_hertz = core::ptr::addr_of!((*serial).input_hertz).read_unaligned();

    info.serial = Some(SerialInfo {
        serial_type,
        baseaddr,
        baud,
        regwidth,
        input_hertz,
    });

    log::debug!(
        "Serial port: type={}, base={:#x}, baud={}",
        serial_type,
        baseaddr,
        baud
    );
}

/// Parse framebuffer information
unsafe fn parse_framebuffer(record: *const CbRecord, info: &mut CorebootInfo) {
    let fb = record as *const CbFramebuffer;

    let physical_address = core::ptr::addr_of!((*fb).physical_address).read_unaligned();
    let x_resolution = core::ptr::addr_of!((*fb).x_resolution).read_unaligned();
    let y_resolution = core::ptr::addr_of!((*fb).y_resolution).read_unaligned();
    let bytes_per_line = core::ptr::addr_of!((*fb).bytes_per_line).read_unaligned();
    let bits_per_pixel = core::ptr::addr_of!((*fb).bits_per_pixel).read_unaligned();
    let red_mask_pos = core::ptr::addr_of!((*fb).red_mask_pos).read_unaligned();
    let red_mask_size = core::ptr::addr_of!((*fb).red_mask_size).read_unaligned();
    let green_mask_pos = core::ptr::addr_of!((*fb).green_mask_pos).read_unaligned();
    let green_mask_size = core::ptr::addr_of!((*fb).green_mask_size).read_unaligned();
    let blue_mask_pos = core::ptr::addr_of!((*fb).blue_mask_pos).read_unaligned();
    let blue_mask_size = core::ptr::addr_of!((*fb).blue_mask_size).read_unaligned();

    info.framebuffer = Some(FramebufferInfo {
        physical_address,
        x_resolution,
        y_resolution,
        bytes_per_line,
        bits_per_pixel,
        red_mask_pos,
        red_mask_size,
        green_mask_pos,
        green_mask_size,
        blue_mask_pos,
        blue_mask_size,
    });

    log::debug!(
        "Framebuffer: {}x{} @ {:#x}, {} bpp",
        x_resolution,
        y_resolution,
        physical_address,
        bits_per_pixel
    );
}

/// Parse forward pointer and follow it
unsafe fn parse_forward(record: *const CbRecord, info: &mut CorebootInfo) {
    let forward = record as *const CbForward;
    let forward_addr = core::ptr::addr_of!((*forward).forward).read_unaligned();
    let new_ptr = forward_addr as *const u8;

    log::debug!("Following forward pointer to {:#x}", forward_addr);

    // Recursively parse the forwarded table
    *info = parse(new_ptr);
}

/// Parse ACPI RSDP pointer
unsafe fn parse_acpi_rsdp(record: *const CbRecord, info: &mut CorebootInfo) {
    let rsdp = record as *const CbAcpiRsdp;
    let rsdp_pointer = core::ptr::addr_of!((*rsdp).rsdp_pointer).read_unaligned();
    info.acpi_rsdp = Some(rsdp_pointer);

    log::debug!("ACPI RSDP: {:#x}", rsdp_pointer);
}

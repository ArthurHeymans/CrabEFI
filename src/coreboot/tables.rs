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
#[allow(dead_code)]
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

/// CBMEM reference (used for console, timestamps, etc.)
#[repr(C, packed)]
struct CbCbmemRef {
    tag: u32,
    size: u32,
    cbmem_addr: u64,
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
    /// CBMEM console address
    pub cbmem_console: Option<u64>,
}

impl CorebootInfo {
    fn new() -> Self {
        CorebootInfo {
            memory_map: Vec::new(),
            serial: None,
            framebuffer: None,
            acpi_rsdp: None,
            version: None,
            cbmem_console: None,
        }
    }
}

/// Parse coreboot tables starting at the given pointer
///
/// # Safety
///
/// The pointer must point to valid coreboot tables.
pub unsafe fn parse(ptr: *const u8) -> CorebootInfo {
    let mut info = CorebootInfo::new();

    // If pointer is null or invalid, scan for the tables in memory
    let header = if ptr.is_null() {
        log::warn!("Coreboot table pointer is null, scanning memory...");
        unsafe { scan_for_header() }
    } else {
        unsafe { find_header(ptr) }
    };

    let header = match header {
        Some(h) => h,
        None => {
            log::warn!("Could not find coreboot header, using fallback memory map");
            create_fallback_memory_map(&mut info);
            return info;
        }
    };

    unsafe {
        // Verify signature "LBIO"
        if &(*header).signature != b"LBIO" {
            log::warn!("Invalid coreboot header signature");
            create_fallback_memory_map(&mut info);
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

    // If we still have no memory map, create a fallback
    if info.memory_map.is_empty() {
        log::warn!("No memory map found in coreboot tables, using fallback");
        create_fallback_memory_map(&mut info);
    }

    info
}

/// Create a fallback memory map for when coreboot tables aren't available
/// This is mainly useful for QEMU testing
fn create_fallback_memory_map(info: &mut CorebootInfo) {
    log::info!("Creating fallback memory map for QEMU");

    // Standard QEMU/PC memory layout:
    // 0x00000000 - 0x0009FFFF: Low memory (640 KB) - usable
    // 0x000A0000 - 0x000FFFFF: VGA + ROM (384 KB) - reserved
    // 0x00100000 - 0x07FFFFFF: Extended memory (up to ~128 MB for safety) - usable
    // We reserve the first 2MB for our code and page tables

    // Low memory (below 640KB), but reserve first 4KB
    let _ = info.memory_map.push(MemoryRegion {
        start: 0x1000,
        size: 0x9F000, // 636 KB
        region_type: MemoryType::Ram,
    });

    // Extended memory: start at 2MB to avoid our payload, go up to 128MB
    // (QEMU typically has at least 128MB, we asked for 512MB)
    let _ = info.memory_map.push(MemoryRegion {
        start: 0x200000,   // 2 MB
        size: 0x1E00_0000, // 480 MB (up to ~512MB total, leaving room for MMIO)
        region_type: MemoryType::Ram,
    });

    // Add serial port info for QEMU (COM1)
    info.serial = Some(SerialInfo {
        serial_type: 1, // IO port
        baseaddr: 0x3f8,
        baud: 115200,
        regwidth: 1,
        input_hertz: 1843200,
    });

    log::info!(
        "Fallback memory map: {} regions, {} MB total",
        info.memory_map.len(),
        (0x9F000 + 0x1E00_0000) / (1024 * 1024)
    );
}

/// Find the coreboot header, following forward pointers if needed
unsafe fn find_header(ptr: *const u8) -> Option<*const CbHeader> {
    let header = ptr as *const CbHeader;

    // Check if this is a valid header
    if (*header).signature == *b"LBIO" {
        return Some(header);
    }

    // Try scanning from the given address
    scan_for_header_at(ptr, 0x1000)
}

/// Scan memory for coreboot header signature "LBIO"
unsafe fn scan_for_header() -> Option<*const CbHeader> {
    // Coreboot tables can be found at several locations:
    // 1. Low memory (0x00000 - 0x01000)
    // 2. At the top of low memory / EBDA area
    // 3. In the BIOS area (0xF0000 - 0xFFFFF)
    // 4. In high memory (where coreboot typically puts them)

    // First, try low memory
    if let Some(header) = scan_for_header_at(core::ptr::null::<u8>(), 0x1000) {
        log::debug!("Found coreboot tables in low memory");
        return Some(header);
    }

    // Try EBDA area (usually around 0x9F000)
    if let Some(header) = scan_for_header_at(0x9F000 as *const u8, 0x1000) {
        log::debug!("Found coreboot tables in EBDA area");
        return Some(header);
    }

    // Try BIOS area
    if let Some(header) = scan_for_header_at(0xF0000 as *const u8, 0x10000) {
        log::debug!("Found coreboot tables in BIOS area");
        return Some(header);
    }

    // Try common high memory locations
    for base in &[0x7EE00000u64, 0x7FE00000u64, 0xCFF00000u64] {
        if let Some(header) = scan_for_header_at(*base as *const u8, 0x100000) {
            log::debug!("Found coreboot tables at {:#x}", *base);
            return Some(header);
        }
    }

    None
}

/// Scan a memory region for the coreboot header
unsafe fn scan_for_header_at(base: *const u8, size: usize) -> Option<*const CbHeader> {
    // Scan in 16-byte increments (coreboot header is aligned)
    let mut offset = 0;
    while offset < size {
        let ptr = base.add(offset);
        let header = ptr as *const CbHeader;

        // Check for "LBIO" signature
        // We need to be careful not to read from invalid memory
        // Use a simple check that won't fault on most systems
        let sig_ptr = ptr as *const [u8; 4];
        if *sig_ptr == *b"LBIO" {
            log::debug!("Found LBIO signature at {:p}", ptr);
            return Some(header);
        }

        offset += 16;
    }

    None
}

/// Parse a single coreboot record
unsafe fn parse_record(record: *const CbRecord, info: &mut CorebootInfo) {
    let tag = core::ptr::addr_of!((*record).tag).read_unaligned();

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
        tags::CB_TAG_CBMEM_CONSOLE => {
            parse_cbmem_console(record, info);
        }
        tags::CB_TAG_VERSION => {
            // Version string follows the record header
            let string_ptr = (record as *const u8).add(8);
            let record_size = core::ptr::addr_of!((*record).size).read_unaligned();
            let len = record_size as usize - 8;
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
    let size = core::ptr::addr_of!((*record).size).read_unaligned();
    let data = (record as *const u8).add(8); // Skip header
    let num_entries = (size as usize - 8) / core::mem::size_of::<CbMemoryRange>();

    log::debug!("Parsing {} memory regions", num_entries);

    for i in 0..num_entries {
        let range_ptr = data.add(i * core::mem::size_of::<CbMemoryRange>()) as *const CbMemoryRange;

        // Read fields using read_unaligned to handle packed struct
        let start = core::ptr::addr_of!((*range_ptr).start).read_unaligned();
        let range_size = core::ptr::addr_of!((*range_ptr).size).read_unaligned();
        let mem_type = core::ptr::addr_of!((*range_ptr).mem_type).read_unaligned();

        let region_type = match mem_type {
            1 => MemoryType::Ram,
            2 => MemoryType::Reserved,
            3 => MemoryType::AcpiReclaimable,
            4 => MemoryType::AcpiNvs,
            5 => MemoryType::Unusable,
            16 => MemoryType::Table,
            _ => MemoryType::Reserved,
        };

        let region = MemoryRegion {
            start,
            size: range_size,
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

    // Parse the forwarded table directly into info (no recursion)
    let header = match find_header(new_ptr) {
        Some(h) => h,
        None => {
            log::warn!("Could not find coreboot header at forwarded location");
            return;
        }
    };

    // Verify signature "LBIO"
    if &(*header).signature != b"LBIO" {
        log::warn!("Invalid coreboot header signature at forwarded location");
        return;
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

        parse_record(record, info);

        offset += record_size;
    }
}

/// Parse ACPI RSDP pointer
unsafe fn parse_acpi_rsdp(record: *const CbRecord, info: &mut CorebootInfo) {
    let rsdp = record as *const CbAcpiRsdp;
    let rsdp_pointer = core::ptr::addr_of!((*rsdp).rsdp_pointer).read_unaligned();
    info.acpi_rsdp = Some(rsdp_pointer);

    log::debug!("ACPI RSDP: {:#x}", rsdp_pointer);
}

/// Parse CBMEM console reference
unsafe fn parse_cbmem_console(record: *const CbRecord, info: &mut CorebootInfo) {
    let cbmem_ref = record as *const CbCbmemRef;
    let cbmem_addr = core::ptr::addr_of!((*cbmem_ref).cbmem_addr).read_unaligned();
    info.cbmem_console = Some(cbmem_addr);

    log::debug!("CBMEM console: {:#x}", cbmem_addr);
}

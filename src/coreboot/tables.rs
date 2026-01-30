//! Coreboot table parser
//!
//! Parses the coreboot tables to extract system information.
//! Reference: coreboot/src/commonlib/include/commonlib/coreboot_tables.h

use super::framebuffer::FramebufferInfo;
use super::memory::{MemoryRegion, MemoryType};
use heapless::Vec;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

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
    pub const CB_TAG_CBMEM_ENTRY: u32 = 0x0031;
    pub const CB_TAG_SMMSTOREV2: u32 = 0x0039;
    pub const CB_TAG_ACPI_RSDP: u32 = 0x0043;
}

/// CBMEM IDs (used with CB_TAG_CBMEM_ENTRY)
mod cbmem_ids {
    /// SMBIOS tables CBMEM ID (ASCII "SMBT")
    pub const CBMEM_ID_SMBIOS: u32 = 0x534d4254;
}

/// Coreboot header structure
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
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
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbRecord {
    tag: u32,
    size: u32,
}

/// Coreboot memory range
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbMemoryRange {
    start: u64,
    size: u64,
    mem_type: u32,
}

/// Coreboot serial port info
///
/// Matches coreboot's `struct lb_serial` from coreboot_tables.h:
/// - tag, size: record header (8 bytes)
/// - type: LB_SERIAL_TYPE_IO_MAPPED (1) or LB_SERIAL_TYPE_MEMORY_MAPPED (2)
/// - baseaddr: I/O port or MMIO address
/// - baud: baud rate (e.g., 115200)
/// - regwidth: register width in bytes
/// - input_hertz: crystal/input frequency
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbSerial {
    tag: u32,
    size: u32,
    serial_type: u32,
    baseaddr: u32,
    baud: u32,
    regwidth: u32,
    input_hertz: u32,
}

/// Coreboot framebuffer info
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
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
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbForward {
    tag: u32,
    size: u32,
    forward: u64,
}

/// ACPI RSDP pointer
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbAcpiRsdp {
    tag: u32,
    size: u32,
    rsdp_pointer: u64,
}

/// CBMEM reference (used for console, timestamps, etc.)
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbCbmemRef {
    tag: u32,
    size: u32,
    cbmem_addr: u64,
}

/// CBMEM entry record (used for SMBIOS, etc.)
///
/// This record provides pointers to CBMEM regions by ID.
/// Reference: coreboot/src/commonlib/include/commonlib/coreboot_tables.h
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbCbmemEntry {
    tag: u32,
    size: u32,
    address: u64,
    entry_size: u32,
    id: u32,
}

/// SMMSTORE v2 record
///
/// This record contains information for accessing UEFI variable storage
/// via the coreboot SMMSTORE v2 interface.
/// Reference: coreboot/src/commonlib/include/commonlib/coreboot_tables.h
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbSmmstorev2 {
    tag: u32,
    size: u32,
    /// Number of writable blocks in SMM
    num_blocks: u32,
    /// Size of a block in bytes (default: 64 KiB)
    block_size: u32,
    /// 32-bit MMIO address (deprecated, use mmap_addr)
    mmap_addr_deprecated: u32,
    /// Physical address of the communication buffer
    com_buffer: u32,
    /// Size of the communication buffer in bytes
    com_buffer_size: u32,
    /// The command byte to write to the APM I/O port
    apm_cmd: u8,
    /// Reserved/unused bytes
    unused: [u8; 3],
    /// 64-bit MMIO address of the store for read-only access
    /// Note: Only present if record size is large enough
    mmap_addr: u64,
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

/// SMMSTORE v2 information
///
/// This provides information for accessing UEFI variable storage
/// through coreboot's SMMSTORE v2 interface.
#[derive(Debug, Clone)]
pub struct Smmstorev2Info {
    /// Number of writable blocks in SMM
    pub num_blocks: u32,
    /// Size of each block in bytes (typically 64 KiB)
    pub block_size: u32,
    /// MMIO address for read-only access to the store
    pub mmap_addr: u64,
    /// Physical address of the SMM communication buffer
    pub com_buffer: u32,
    /// Size of the communication buffer in bytes
    pub com_buffer_size: u32,
    /// APM command byte for SMM communication
    pub apm_cmd: u8,
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
    /// SMBIOS tables address (from CBMEM entry)
    pub smbios: Option<u64>,
    /// SMMSTORE v2 information for UEFI variable storage
    pub smmstorev2: Option<Smmstorev2Info>,
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
            smbios: None,
            smmstorev2: None,
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

    // Safety: We've validated that header points to a valid coreboot table
    unsafe {
        // Verify signature "LBIO"
        if &(*header).signature != b"LBIO" {
            log::warn!("Invalid coreboot header signature");
            create_fallback_memory_map(&mut info);
            return info;
        }

        let table_bytes = (*header).table_bytes;
        let header_bytes = (*header).header_bytes;

        log::debug!("Found coreboot header: {} bytes of tables", table_bytes);

        // Parse table entries
        let table_start = (header as *const u8).add(header_bytes as usize);
        let mut offset = 0u32;

        while offset < table_bytes {
            let record_ptr = table_start.add(offset as usize);

            // Read record header to get size
            let record_header_bytes = core::slice::from_raw_parts(record_ptr, 8);
            let Ok((record_header, _)) = CbRecord::read_from_prefix(record_header_bytes) else {
                log::warn!("Failed to parse record header");
                break;
            };
            let record_size = record_header.size;

            if record_size < 8 {
                log::warn!("Invalid record size: {}", record_size);
                break;
            }

            // Create slice for the full record and call safe parse_record
            let record_bytes = core::slice::from_raw_parts(record_ptr, record_size as usize);
            parse_record(record_bytes, &mut info);

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

/// Parse a single coreboot record from a byte slice
///
/// # Arguments
/// * `record_bytes` - Byte slice containing the full record (header + data)
/// * `info` - CorebootInfo to populate
///
/// This function is safe because it uses zerocopy to validate all struct parsing.
/// The `parse_forward` case still requires unsafe internally to follow the pointer.
fn parse_record(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((header, _)) = CbRecord::read_from_prefix(record_bytes) else {
        return;
    };
    let tag = header.tag;

    match tag {
        tags::CB_TAG_MEMORY => {
            parse_memory(record_bytes, info);
        }
        tags::CB_TAG_SERIAL => {
            parse_serial(record_bytes, info);
        }
        tags::CB_TAG_FRAMEBUFFER => {
            parse_framebuffer(record_bytes, info);
        }
        tags::CB_TAG_FORWARD => {
            // This one still needs unsafe to follow the pointer
            unsafe { parse_forward(record_bytes, info) };
        }
        tags::CB_TAG_ACPI_RSDP => {
            parse_acpi_rsdp(record_bytes, info);
        }
        tags::CB_TAG_CBMEM_CONSOLE => {
            parse_cbmem_console(record_bytes, info);
        }
        tags::CB_TAG_CBMEM_ENTRY => {
            parse_cbmem_entry(record_bytes, info);
        }
        tags::CB_TAG_SMMSTOREV2 => {
            parse_smmstorev2(record_bytes, info);
        }
        tags::CB_TAG_VERSION => {
            // Version string follows the 8-byte record header
            // Note: We need 'static lifetime since coreboot tables persist
            // for the entire boot process. This is inherently unsafe as we're
            // extending the lifetime, but is correct because the tables are in
            // firmware memory.
            if record_bytes.len() > 8 {
                let len = record_bytes.len() - 8;
                // Safety: The coreboot tables are in firmware memory that persists
                // for the entire boot, so 'static lifetime is appropriate.
                let string_bytes: &'static [u8] =
                    unsafe { core::slice::from_raw_parts(record_bytes.as_ptr().add(8), len) };
                if let Ok(s) = core::str::from_utf8(string_bytes) {
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
///
/// This function is safe - it uses zerocopy to iterate through memory ranges.
fn parse_memory(record_bytes: &[u8], info: &mut CorebootInfo) {
    // Skip the 8-byte record header to get to the memory range array
    if record_bytes.len() <= 8 {
        return;
    }
    let data = &record_bytes[8..];
    let num_entries = data.len() / core::mem::size_of::<CbMemoryRange>();

    log::debug!("Parsing {} memory regions", num_entries);

    let mut remaining = data;
    while !remaining.is_empty() {
        let Ok((range, rest)) = CbMemoryRange::read_from_prefix(remaining) else {
            break;
        };

        let start = range.start;
        let range_size = range.size;
        let mem_type = range.mem_type;

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

        remaining = rest;
    }
}

/// Parse serial port information
///
/// This function is safe - it uses zerocopy to parse the serial struct.
fn parse_serial(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((serial, _)) = CbSerial::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse serial record");
        return;
    };

    let serial_type = serial.serial_type;
    let baseaddr = serial.baseaddr;
    let baud = serial.baud;
    let regwidth = serial.regwidth;
    let input_hertz = serial.input_hertz;

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
///
/// This function is safe - it uses zerocopy to parse the framebuffer struct.
fn parse_framebuffer(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((fb, _)) = CbFramebuffer::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse framebuffer record");
        return;
    };

    let physical_address = fb.physical_address;
    let x_resolution = fb.x_resolution;
    let y_resolution = fb.y_resolution;
    let bytes_per_line = fb.bytes_per_line;
    let bits_per_pixel = fb.bits_per_pixel;
    let red_mask_pos = fb.red_mask_pos;
    let red_mask_size = fb.red_mask_size;
    let green_mask_pos = fb.green_mask_pos;
    let green_mask_size = fb.green_mask_size;
    let blue_mask_pos = fb.blue_mask_pos;
    let blue_mask_size = fb.blue_mask_size;

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
///
/// # Safety
/// This function must follow a memory pointer from the coreboot tables,
/// which requires trusting that the pointer is valid.
unsafe fn parse_forward(record_bytes: &[u8], info: &mut CorebootInfo) {
    // Safely parse the forward record using zerocopy
    let Ok((forward, _)) = CbForward::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse forward record");
        return;
    };
    let forward_addr = forward.forward;
    let new_ptr = forward_addr as *const u8;

    log::debug!("Following forward pointer to {:#x}", forward_addr);

    // Parse the forwarded table directly into info (no recursion)
    // Safety: We trust the forward pointer from coreboot tables
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

    let table_bytes = (*header).table_bytes;
    let header_bytes = (*header).header_bytes;

    log::debug!(
        "Found forwarded coreboot header: {} bytes of tables",
        table_bytes
    );

    // Parse table entries
    let table_start = (header as *const u8).add(header_bytes as usize);
    let mut offset = 0u32;

    while offset < table_bytes {
        let record_ptr = table_start.add(offset as usize);

        // Read record header to get size
        let record_header_bytes = core::slice::from_raw_parts(record_ptr, 8);
        let Ok((record_header, _)) = CbRecord::read_from_prefix(record_header_bytes) else {
            log::warn!("Failed to parse record header");
            break;
        };
        let record_size = record_header.size;

        if record_size < 8 {
            log::warn!("Invalid record size: {}", record_size);
            break;
        }

        // Create slice for the full record and call safe parse_record
        let record_bytes = core::slice::from_raw_parts(record_ptr, record_size as usize);
        parse_record(record_bytes, info);

        offset += record_size;
    }
}

/// Parse ACPI RSDP pointer
///
/// This function is safe - it uses zerocopy to parse the ACPI RSDP struct.
fn parse_acpi_rsdp(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((rsdp, _)) = CbAcpiRsdp::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse ACPI RSDP record");
        return;
    };
    let rsdp_pointer = rsdp.rsdp_pointer;
    info.acpi_rsdp = Some(rsdp_pointer);

    log::debug!("ACPI RSDP: {:#x}", rsdp_pointer);
}

/// Parse CBMEM console reference
///
/// This function is safe - it uses zerocopy to parse the CBMEM ref struct.
fn parse_cbmem_console(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((cbmem_ref, _)) = CbCbmemRef::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse CBMEM console record");
        return;
    };
    let cbmem_addr = cbmem_ref.cbmem_addr;
    info.cbmem_console = Some(cbmem_addr);

    log::debug!("CBMEM console: {:#x}", cbmem_addr);
}

/// Parse CBMEM entry record
///
/// CBMEM entries provide pointers to various firmware data regions by ID.
/// We specifically look for SMBIOS tables (CBMEM_ID_SMBIOS).
///
/// This function is safe - it uses zerocopy to parse the CBMEM entry struct.
fn parse_cbmem_entry(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((entry, _)) = CbCbmemEntry::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse CBMEM entry record");
        return;
    };

    let id = entry.id;
    let address = entry.address;
    let entry_size = entry.entry_size;

    match id {
        cbmem_ids::CBMEM_ID_SMBIOS => {
            info.smbios = Some(address);
            log::info!(
                "SMBIOS tables found at {:#x} (size {} bytes)",
                address,
                entry_size
            );
        }
        _ => {
            // Log other CBMEM entries at trace level for debugging
            log::trace!(
                "CBMEM entry: id={:#x}, address={:#x}, size={}",
                id,
                address,
                entry_size
            );
        }
    }
}

/// Parse SMMSTORE v2 record
///
/// SMMSTORE v2 provides information for accessing UEFI variable storage
/// through coreboot's SMM-based interface.
///
/// This function is safe - it uses zerocopy to parse the SMMSTORE v2 struct.
fn parse_smmstorev2(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((smmstore, _)) = CbSmmstorev2::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse SMMSTORE v2 record");
        return;
    };

    let num_blocks = smmstore.num_blocks;
    let block_size = smmstore.block_size;
    let com_buffer = smmstore.com_buffer;
    let com_buffer_size = smmstore.com_buffer_size;
    let apm_cmd = smmstore.apm_cmd;

    // The 64-bit mmap_addr field was added later.
    // Check record size to determine if it's present.
    // Base struct without mmap_addr would be 28 bytes (tag+size+fields up to unused[3])
    // With mmap_addr it's 36 bytes
    let record_size = record_bytes.len();
    let mmap_addr = if record_size >= 36 {
        // 64-bit address is available
        smmstore.mmap_addr
    } else if smmstore.mmap_addr_deprecated != 0 {
        // Fall back to 32-bit address
        smmstore.mmap_addr_deprecated as u64
    } else {
        0
    };

    let total_size = num_blocks as u64 * block_size as u64;

    info.smmstorev2 = Some(Smmstorev2Info {
        num_blocks,
        block_size,
        mmap_addr,
        com_buffer,
        com_buffer_size,
        apm_cmd,
    });

    log::info!(
        "SMMSTORE v2: {} blocks x {} KB = {} KB at {:#x}",
        num_blocks,
        block_size / 1024,
        total_size / 1024,
        mmap_addr
    );
    log::debug!(
        "  COM buffer: {:#x} ({} bytes), APM cmd: {:#x}",
        com_buffer,
        com_buffer_size,
        apm_cmd
    );
}

//! Coreboot table parser
//!
//! Parses the coreboot tables to extract system information.
//! Reference: coreboot/src/commonlib/include/commonlib/coreboot_tables.h

#![allow(dead_code)]

use crate::framebuffer::FramebufferInfo;
use crate::memory::{MemoryRegion, MemoryType};
use heapless::Vec;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// Maximum number of memory regions we can store
const MAX_MEMORY_REGIONS: usize = 64;

/// Coreboot table tags
#[allow(dead_code)]
pub mod tags {
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
    pub const CB_TAG_SPI_FLASH: u32 = 0x0029;
    pub const CB_TAG_BOOT_MEDIA_PARAMS: u32 = 0x0030;
    pub const CB_TAG_CBMEM_ENTRY: u32 = 0x0031;
    pub const CB_TAG_SMMSTOREV2: u32 = 0x0039;
    pub const CB_TAG_FMAP: u32 = 0x0037;
    pub const CB_TAG_ACPI_RSDP: u32 = 0x0043;
    pub const CB_TAG_EFI_FW_INFO: u32 = 0x0045;
    pub const CB_TAG_CAPSULE: u32 = 0x0046;
    pub const CB_TAG_CFR_ROOT: u32 = 0x0047;
    pub const CB_TAG_DEVICETREE: u32 = 0x004a;
}

/// CBMEM IDs (used with CB_TAG_CBMEM_ENTRY)
pub(crate) mod cbmem_ids {
    /// SMBIOS tables CBMEM ID (ASCII "SMBT")
    pub const CBMEM_ID_SMBIOS: u32 = 0x534d4254;
    /// TPM log in coreboot-specific format (ASCII "TCPA")
    pub const CBMEM_ID_TPM_CB_LOG: u32 = 0x54435041;
    /// TPM log per TPM 1.2 specification (ASCII "TDPA")
    pub const CBMEM_ID_TCPA_TCG_LOG: u32 = 0x54445041;
    /// TPM log per TPM 2.0 specification (ASCII "TPM2")
    pub const CBMEM_ID_TPM2_TCG_LOG: u32 = 0x54504d32;
}

/// LB_TAG for TPM CB log (only the coreboot-specific format is exported via CB tables)
pub mod tpm_tags {
    pub const CB_TAG_TPM_CB_LOG: u32 = 0x0036;
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

/// Devicetree (FDT) pointer
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbDevicetree {
    tag: u32,
    size: u32,
    fdt_pointer: u64,
    fdt_size: u32,
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

/// Memory map window for translating between SPI flash and host address space
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct FlashMmapWindow {
    /// Base address in SPI flash address space
    pub flash_base: u32,
    /// Base address in host/CPU address space
    pub host_base: u32,
    /// Size of the window in bytes
    pub size: u32,
}

/// SPI flash information record
///
/// Contains information about the system's SPI flash chip.
/// Reference: coreboot/src/commonlib/include/commonlib/coreboot_tables.h
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbSpiFlash {
    tag: u32,
    size: u32,
    /// Total flash size in bytes
    flash_size: u32,
    /// Sector (erase block) size in bytes
    sector_size: u32,
    /// Erase command opcode
    erase_cmd: u8,
    /// Flags (bit 0: in 4-byte address mode)
    flags: u8,
    /// Reserved
    reserved: u16,
    /// Number of memory map windows
    mmap_count: u32,
    // Followed by mmap_count FlashMmapWindow entries
}

/// Boot media parameters record
///
/// Contains information about the boot media layout including FMAP location.
/// Reference: coreboot/src/commonlib/include/commonlib/coreboot_tables.h
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbBootMediaParams {
    tag: u32,
    size: u32,
    /// Offset of FMAP in boot media (relative to start)
    fmap_offset: u64,
    /// Offset of CBFS in boot media
    cbfs_offset: u64,
    /// Size of CBFS region
    cbfs_size: u64,
    /// Total size of boot media
    boot_media_size: u64,
}

/// EFI firmware info record from coreboot tables
///
/// Matches coreboot's `struct lb_efi_fw_info`:
///   tag, size, guid[16], version, lowest_supported_version, fw_size
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbEfiFwInfo {
    tag: u32,
    size: u32,
    guid: [u8; 16],
    version: u32,
    lowest_supported_version: u32,
    fw_size: u32,
}

/// Capsule region record from coreboot tables
///
/// Matches coreboot's `struct lb_range` used for LB_TAG_CAPSULE:
///   tag, size, range_start, range_size
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct CbCapsule {
    tag: u32,
    size: u32,
    range_start: u64,
    range_size: u32,
}

/// Coreboot serial type: I/O port mapped
pub const LB_SERIAL_TYPE_IO_MAPPED: u32 = 1;
/// Coreboot serial type: Memory mapped
pub const LB_SERIAL_TYPE_MEMORY_MAPPED: u32 = 2;

/// Serial port information
#[derive(Debug, Clone)]
pub struct SerialInfo {
    pub serial_type: u32,
    pub baseaddr: u32,
    pub baud: u32,
    pub regwidth: u32,
    pub input_hertz: u32,
}

impl SerialInfo {
    /// Returns true if the serial port is MMIO-mapped (vs I/O port mapped)
    pub fn mmio(&self) -> bool {
        self.serial_type == LB_SERIAL_TYPE_MEMORY_MAPPED
    }
}

/// SMMSTORE v2 information
///
/// This provides information for accessing UEFI variable storage
/// through coreboot's SMMSTORE v2 interface.
#[derive(Debug, Clone, Copy)]
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

/// Maximum number of flash memory map windows
pub const MAX_FLASH_MMAP_WINDOWS: usize = 4;

/// SPI flash information
///
/// Contains information about the system's SPI flash from coreboot tables.
#[derive(Debug, Clone)]
pub struct SpiFlashInfo {
    /// Total flash size in bytes
    pub flash_size: u32,
    /// Sector (erase block) size in bytes
    pub sector_size: u32,
    /// Erase command opcode
    pub erase_cmd: u8,
    /// Memory map windows for address translation
    pub mmap_windows: heapless::Vec<FlashMmapWindow, MAX_FLASH_MMAP_WINDOWS>,
}

/// Boot media parameters
///
/// Contains information about the boot media layout from coreboot tables.
#[derive(Debug, Clone, Copy)]
pub struct BootMediaInfo {
    /// Offset of FMAP in boot media (relative to start of flash)
    pub fmap_offset: u64,
    /// Offset of CBFS in boot media
    pub cbfs_offset: u64,
    /// Size of CBFS region
    pub cbfs_size: u64,
    /// Total size of boot media
    pub boot_media_size: u64,
}

/// Maximum number of capsules we track from coreboot tables
pub const MAX_CAPSULES: usize = 32;

/// EFI firmware information from coreboot's LB_TAG_EFI_FW_INFO
///
/// Contains the firmware identity and version information used for
/// ESRT (EFI System Resource Table) and capsule update validation.
/// Reference: coreboot/src/commonlib/include/commonlib/coreboot_tables.h
#[derive(Debug, Clone, Copy)]
pub struct EfiFwInfo {
    /// Firmware class GUID (identifies the firmware component for updates)
    pub guid: [u8; 16],
    /// Current firmware version (higher = more recent)
    pub version: u32,
    /// Lowest supported version (for rollback prevention)
    pub lowest_supported_version: u32,
    /// Size of the firmware image in bytes
    pub fw_size: u32,
}

/// A capsule region from coreboot's LB_TAG_CAPSULE
///
/// Points to a coalesced capsule in memory that coreboot prepared from
/// CapsuleUpdateData* EFI variables after a warm reboot.
/// Reference: coreboot/src/commonlib/include/commonlib/coreboot_tables.h
#[derive(Debug, Clone, Copy)]
pub struct CapsuleRegion {
    /// Physical base address of the capsule data
    pub base: u64,
    /// Size of the capsule data in bytes
    pub size: u32,
}

/// Information extracted from coreboot tables
pub struct CorebootInfo {
    /// Memory map
    pub memory_map: Vec<MemoryRegion, MAX_MEMORY_REGIONS>,
    /// Serial port configuration
    pub serial: Option<SerialInfo>,
    /// Framebuffer information
    pub framebuffer: Option<FramebufferInfo>,
    /// Physical address of the framebuffer record in the coreboot tables.
    /// This is stored so we can invalidate it at ExitBootServices to prevent
    /// a race condition between Linux's simplefb (coreboot) and efifb (EFI GOP).
    pub framebuffer_record_addr: Option<u64>,
    /// ACPI RSDP pointer
    pub acpi_rsdp: Option<u64>,
    /// Coreboot version string
    pub version: Option<&'static str>,
    /// CBMEM console address
    pub cbmem_console: Option<u64>,
    /// Timestamp table address (from CB_TAG_TIMESTAMPS)
    pub timestamps: Option<u64>,
    /// SMBIOS tables address (from CBMEM entry)
    pub smbios: Option<u64>,
    /// SMMSTORE v2 information for UEFI variable storage
    pub smmstorev2: Option<Smmstorev2Info>,
    /// SPI flash information
    pub spi_flash: Option<SpiFlashInfo>,
    /// Boot media parameters (includes FMAP location)
    pub boot_media: Option<BootMediaInfo>,
    /// Raw CFR data slice from coreboot tables (parsed later after heap init).
    /// The coreboot tables persist in firmware memory for the entire boot,
    /// so this 'static reference is sound.
    pub cfr_raw: Option<&'static [u8]>,
    /// Flattened device tree (FDT) pointer and size
    pub devicetree: Option<(u64, u32)>,
    /// EFI firmware info (GUID, version, LSV) for ESRT and capsule updates
    pub efi_fw_info: Option<EfiFwInfo>,
    /// Capsule regions from coreboot (coalesced capsules ready for processing)
    pub capsules: heapless::Vec<CapsuleRegion, MAX_CAPSULES>,
    /// TPM event log from CBMEM (address, size, format).
    ///
    /// Coreboot supports three log formats, each with its own CBMEM ID:
    /// - `CBMEM_ID_TPM_CB_LOG` (0x54435041): coreboot-specific format
    /// - `CBMEM_ID_TCPA_TCG_LOG` (0x54445041): TCG 1.2 SHA1-only format
    /// - `CBMEM_ID_TPM2_TCG_LOG` (0x54504d32): TCG 2.0 crypto-agile format
    pub tpm_log: Option<TpmLogInfo>,
}

/// Information about a TPM event log found in CBMEM.
#[derive(Debug, Clone, Copy)]
pub struct TpmLogInfo {
    /// Physical address of the log data.
    pub address: u64,
    /// Size of the log data in bytes.
    pub size: u32,
    /// Which CBMEM ID was matched (determines the format).
    pub cbmem_id: u32,
}

impl CorebootInfo {
    fn new() -> Self {
        CorebootInfo {
            memory_map: Vec::new(),
            serial: None,
            framebuffer: None,
            framebuffer_record_addr: None,
            acpi_rsdp: None,
            version: None,
            cbmem_console: None,
            timestamps: None,
            smbios: None,
            smmstorev2: None,
            spi_flash: None,
            boot_media: None,
            cfr_raw: None,
            devicetree: None,
            efi_fw_info: None,
            capsules: heapless::Vec::new(),
            tpm_log: None,
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

    // Prefer the table pointer supplied through the payload entry ABI. Some
    // chainloaders do not preserve that argument, so fall back to scanning the
    // standard coreboot table locations when it does not identify a table.
    let header = if ptr.is_null() {
        log::warn!("Coreboot table pointer is null, scanning memory...");
        unsafe { scan_for_header() }
    } else if let Some(header) = unsafe { find_header(ptr) } {
        Some(header)
    } else {
        log::warn!(
            "No coreboot table at entry pointer {:p}, scanning memory...",
            ptr
        );
        unsafe { scan_for_header() }
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
        log::debug!("Found coreboot header: {} bytes of tables", table_bytes);

        iterate_table_records(header, &mut info);
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

    // Safety: caller guarantees ptr points to valid coreboot tables.
    unsafe {
        // Check if this is a valid header
        if (*header).signature == *b"LBIO" {
            return Some(header);
        }

        // Try scanning from the given address
        scan_for_header_at(ptr, 0x1000)
    }
}

/// Scan memory for coreboot header signature "LBIO"
unsafe fn scan_for_header() -> Option<*const CbHeader> {
    // Coreboot tables can be found at several locations:
    // 1. Low memory (0x00000 - 0x01000)
    // 2. At the top of low memory / EBDA area
    // 3. In the BIOS area (0xF0000 - 0xFFFFF)
    // 4. In high memory (where coreboot typically puts them)

    // Safety: scanning known firmware memory regions for coreboot table signatures.
    unsafe {
        // First, try low memory
        // Use without_provenance instead of null to avoid UB with ptr::add on null
        if let Some(header) = scan_for_header_at(core::ptr::without_provenance::<u8>(0), 0x1000) {
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
    }

    None
}

/// Scan a memory region for the coreboot header
unsafe fn scan_for_header_at(base: *const u8, size: usize) -> Option<*const CbHeader> {
    // Scan in 16-byte increments (coreboot header is aligned)
    let mut offset = 0;
    while offset < size {
        // Safety: caller guarantees the memory region [base, base+size) is readable.
        unsafe {
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
        tags::CB_TAG_TIMESTAMPS => {
            parse_timestamps(record_bytes, info);
        }
        tags::CB_TAG_CBMEM_CONSOLE => {
            parse_cbmem_console(record_bytes, info);
        }
        tags::CB_TAG_CBMEM_ENTRY => {
            parse_cbmem_entry(record_bytes, info);
        }
        tpm_tags::CB_TAG_TPM_CB_LOG => {
            parse_tpm_cb_log_ref(record_bytes, info);
        }
        tags::CB_TAG_SMMSTOREV2 => {
            parse_smmstorev2(record_bytes, info);
        }
        tags::CB_TAG_SPI_FLASH => {
            parse_spi_flash(record_bytes, info);
        }
        tags::CB_TAG_BOOT_MEDIA_PARAMS => {
            parse_boot_media_params(record_bytes, info);
        }
        tags::CB_TAG_CFR_ROOT => {
            save_cfr_raw(record_bytes, info);
        }
        tags::CB_TAG_DEVICETREE => {
            parse_devicetree(record_bytes, info);
        }
        tags::CB_TAG_EFI_FW_INFO => {
            parse_efi_fw_info(record_bytes, info);
        }
        tags::CB_TAG_CAPSULE => {
            parse_capsule(record_bytes, info);
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

        let region_type = MemoryType::try_from(mem_type).unwrap_or(MemoryType::Reserved);

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

    // Store the record address so we can invalidate it at ExitBootServices.
    // This prevents Linux from trying to use both simplefb (coreboot) and efifb (EFI GOP).
    //
    // SAFETY: Coreboot tables are placed in reserved memory (LB_MEM_TABLE type) that
    // persists throughout the boot process. The address remains valid and stable until
    // the OS takes over, at which point we've already invalidated the record.
    info.framebuffer_record_addr = Some(record_bytes.as_ptr() as u64);

    log::debug!(
        "Framebuffer: {}x{} @ {:#x}, {} bpp (record at {:#x})",
        x_resolution,
        y_resolution,
        physical_address,
        bits_per_pixel,
        record_bytes.as_ptr() as u64
    );
}

/// Iterate over coreboot table records from a validated header and dispatch each
/// to [`parse_record`].
///
/// # Safety
/// `header` must point to a valid `CbHeader` with a verified `"LBIO"` signature.
unsafe fn iterate_table_records(header: *const CbHeader, info: &mut CorebootInfo) {
    // Safety: caller guarantees header points to a valid CbHeader with verified "LBIO" signature.
    unsafe {
        let table_bytes = (*header).table_bytes;
        let header_bytes = (*header).header_bytes;
        let table_start = (header as *const u8).add(header_bytes as usize);
        let mut offset = 0u32;

        while offset < table_bytes {
            let remaining = table_bytes - offset;

            if remaining < 8 {
                log::warn!("Truncated record header at offset {}", offset);
                break;
            }

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

            if record_size > remaining {
                log::warn!(
                    "Record size {} exceeds remaining table bytes {} at offset {}",
                    record_size,
                    remaining,
                    offset
                );
                break;
            }

            let record_bytes = core::slice::from_raw_parts(record_ptr, record_size as usize);
            parse_record(record_bytes, info);

            offset += record_size;
        }
    }
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

    // Safety: We trust the forward pointer from coreboot tables.
    unsafe {
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

        let table_bytes = (*header).table_bytes;
        log::debug!(
            "Found forwarded coreboot header: {} bytes of tables",
            table_bytes
        );

        iterate_table_records(header, info);
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

/// Parse devicetree (FDT) pointer
fn parse_devicetree(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((dt, _)) = CbDevicetree::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse devicetree record");
        return;
    };
    let fdt_pointer = dt.fdt_pointer;
    let fdt_size = dt.fdt_size;
    info.devicetree = Some((fdt_pointer, fdt_size));
    log::debug!("Devicetree: {:#x} ({} bytes)", fdt_pointer, fdt_size);
}

/// Parse EFI firmware info record (LB_TAG_EFI_FW_INFO)
///
/// Contains firmware GUID, version, and lowest supported version used for
/// ESRT and capsule update validation.
fn parse_efi_fw_info(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((fw_info, _)) = CbEfiFwInfo::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse EFI firmware info record");
        return;
    };

    let version = fw_info.version;
    let lsv = fw_info.lowest_supported_version;
    let fw_size = fw_info.fw_size;

    info.efi_fw_info = Some(EfiFwInfo {
        guid: fw_info.guid,
        version,
        lowest_supported_version: lsv,
        fw_size,
    });

    log::info!(
        "EFI FW info: version={:#x}, LSV={:#x}, size={} KB",
        version,
        lsv,
        fw_size / 1024
    );
}

/// Parse capsule region record (LB_TAG_CAPSULE)
///
/// Each record describes a coalesced capsule in memory that coreboot
/// prepared from CapsuleUpdateData* EFI variables.
fn parse_capsule(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((capsule, _)) = CbCapsule::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse capsule record");
        return;
    };

    let base = capsule.range_start;
    let size = capsule.range_size;

    if base == 0 || size == 0 {
        log::warn!(
            "Ignoring invalid capsule region: base={:#x}, size={}",
            base,
            size
        );
        return;
    }

    if info.capsules.push(CapsuleRegion { base, size }).is_err() {
        log::warn!("Too many capsule records (max {})", MAX_CAPSULES);
        return;
    }

    log::info!("Capsule region: base={:#x}, size={} bytes", base, size);
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

/// Parse timestamp table reference.
///
/// The CB_TAG_TIMESTAMPS record is an `lb_cbmem_ref` that points to the
/// coreboot timestamp table in CBMEM.
fn parse_timestamps(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((cbmem_ref, _)) = CbCbmemRef::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse timestamps record");
        return;
    };
    let cbmem_addr = cbmem_ref.cbmem_addr;
    info.timestamps = Some(cbmem_addr);

    log::debug!("Timestamp table: {:#x}", cbmem_addr);
}

/// Parse the legacy coreboot-specific TPM log reference.
///
/// The `LB_TAG_TPM_CB_LOG` record is a plain CBMEM reference without an entry
/// size. The coreboot-specific log starts with max/used entry counts, so derive
/// the occupied size from that header. This format is not appended to directly;
/// detecting it lets the payload make an explicit fresh-log decision.
fn parse_tpm_cb_log_ref(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((cbmem_ref, _)) = CbCbmemRef::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse TPM CB log reference");
        return;
    };

    let address = cbmem_ref.cbmem_addr;
    if address == 0 {
        log::warn!("TPM CB log reference has a null address");
        return;
    }

    // SAFETY: coreboot records point at CBMEM regions that remain valid for
    // the payload lifetime. We only read the fixed 4-byte table header here.
    let header = unsafe { core::slice::from_raw_parts(address as *const u8, 4) };
    let max_entries = u16::from_le_bytes([header[0], header[1]]) as u32;
    let num_entries = u16::from_le_bytes([header[2], header[3]]) as u32;
    let entry_count = num_entries.min(max_entries);
    let entry_size = 4 + 10 + 64 + 4 + 50;
    let size = 4 + entry_count * entry_size;

    log::info!(
        "TPM event log found: coreboot-specific format at {:#x} ({} used entries)",
        address,
        entry_count,
    );

    if info.tpm_log.is_none() {
        info.tpm_log = Some(TpmLogInfo {
            address,
            size,
            cbmem_id: cbmem_ids::CBMEM_ID_TPM_CB_LOG,
        });
    }
}

fn read_le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn compute_cbmem_tpm_log_used_size(address: u64, allocation_size: u32, id: u32) -> Option<u32> {
    if address == 0 || allocation_size == 0 {
        return None;
    }

    let allocation_size = allocation_size as usize;
    // SAFETY: coreboot's CBMEM entry describes a CBMEM allocation that remains
    // valid for the payload lifetime. We only read within the advertised
    // allocation and validate the embedded coreboot TPM log header before use.
    let data = unsafe { core::slice::from_raw_parts(address as *const u8, allocation_size) };

    let (header_end, vendor_offset, expected_magic) = match id {
        cbmem_ids::CBMEM_ID_TCPA_TCG_LOG => {
            // struct tpm_1_log_table begins with a TCG_PCClientPCREvent header:
            // pcr(4), event_type(4), digest(20), event_data_size/spec_id_size(4).
            // The event data is coreboot's spec_id_event_data (25 bytes), then
            // the 15-byte coreboot vendor area carrying num_entries/entry_size.
            let event_data_size = read_le_u32(data, 28)? as usize;
            let header_end = 32usize.checked_add(event_data_size)?;
            let vendor_info_size = *data.get(32 + 24)? as usize;
            let vendor_offset = 32 + 25;
            if vendor_info_size < 15 || header_end > allocation_size {
                return None;
            }
            (header_end, vendor_offset, 0x3154_4243u32) // "CBT1"
        }
        cbmem_ids::CBMEM_ID_TPM2_TCG_LOG => {
            // struct tpm_2_log_table begins with a TCG_PCR_EVENT wrapper. The
            // event payload contains the Spec ID Event03 header, digest_sizes,
            // a vendor_info_size byte, and the coreboot vendor area.
            let event_data_size = read_le_u32(data, 28)? as usize;
            let header_end = 32usize.checked_add(event_data_size)?;
            let alg_count = read_le_u32(data, 56)? as usize;
            let vendor_info_size_offset = 60usize.checked_add(alg_count.checked_mul(4)?)?;
            let vendor_info_size = *data.get(vendor_info_size_offset)? as usize;
            let vendor_offset = vendor_info_size_offset.checked_add(1)?;
            if vendor_info_size < 15 || header_end > allocation_size {
                return None;
            }
            (header_end, vendor_offset, 0x3254_4243u32) // "CBT2"
        }
        _ => return None,
    };

    if vendor_offset.checked_add(15)? > header_end {
        return None;
    }

    let magic = read_le_u32(data, vendor_offset + 3)?;
    let max_entries = read_le_u16(data, vendor_offset + 7)? as usize;
    let num_entries = read_le_u16(data, vendor_offset + 9)? as usize;
    let log_entry_size = read_le_u32(data, vendor_offset + 11)? as usize;

    if magic != expected_magic || num_entries > max_entries || log_entry_size == 0 {
        return None;
    }

    let entries_size = num_entries.checked_mul(log_entry_size)?;
    let used = header_end.checked_add(entries_size)?;
    if used > allocation_size || used > u32::MAX as usize {
        return None;
    }

    Some(used as u32)
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
        cbmem_ids::CBMEM_ID_TPM_CB_LOG
        | cbmem_ids::CBMEM_ID_TCPA_TCG_LOG
        | cbmem_ids::CBMEM_ID_TPM2_TCG_LOG => {
            let format_name = match id {
                cbmem_ids::CBMEM_ID_TPM_CB_LOG => "coreboot-specific",
                cbmem_ids::CBMEM_ID_TCPA_TCG_LOG => "TCG 1.2 (SHA1)",
                cbmem_ids::CBMEM_ID_TPM2_TCG_LOG => "TCG 2.0 (crypto-agile)",
                _ => "unknown",
            };
            let used_size = match id {
                cbmem_ids::CBMEM_ID_TCPA_TCG_LOG | cbmem_ids::CBMEM_ID_TPM2_TCG_LOG => {
                    match compute_cbmem_tpm_log_used_size(address, entry_size, id) {
                        Some(size) => size,
                        None => {
                            log::warn!(
                                "Ignoring invalid {} TPM event log at {:#x} (allocation {} bytes)",
                                format_name,
                                address,
                                entry_size
                            );
                            return;
                        }
                    }
                }
                _ => entry_size,
            };

            log::info!(
                "TPM event log found: {} format at {:#x} ({} used of {} bytes)",
                format_name,
                address,
                used_size,
                entry_size,
            );
            // Prefer TCG 2.0 > TCG 1.2 > coreboot-specific.
            // Only overwrite if no log found yet or if the new one is higher priority.
            let should_replace = match info.tpm_log {
                None => true,
                Some(ref existing) => matches!(
                    (existing.cbmem_id, id),
                    (cbmem_ids::CBMEM_ID_TPM_CB_LOG, _)
                        | (
                            cbmem_ids::CBMEM_ID_TCPA_TCG_LOG,
                            cbmem_ids::CBMEM_ID_TPM2_TCG_LOG,
                        )
                ),
            };
            if should_replace {
                info.tpm_log = Some(TpmLogInfo {
                    address,
                    size: used_size,
                    cbmem_id: id,
                });
            }
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

/// Parse SPI flash information
///
/// This function is safe - it uses zerocopy to parse the SPI flash struct.
fn parse_spi_flash(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((spi_flash, _)) = CbSpiFlash::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse SPI flash record");
        return;
    };

    // Copy packed fields to local variables
    let flash_size = spi_flash.flash_size;
    let sector_size = spi_flash.sector_size;
    let erase_cmd = spi_flash.erase_cmd;
    let mmap_count = spi_flash.mmap_count as usize;

    log::info!(
        "SPI flash: {} MB, sector size {} KB, {} mmap windows",
        flash_size / (1024 * 1024),
        sector_size / 1024,
        mmap_count
    );

    // Parse memory map windows
    let mut mmap_windows = heapless::Vec::new();

    if mmap_count > 0 && record_bytes.len() > core::mem::size_of::<CbSpiFlash>() {
        let windows_data = &record_bytes[core::mem::size_of::<CbSpiFlash>()..];
        let mut remaining = windows_data;

        for i in 0..mmap_count.min(MAX_FLASH_MMAP_WINDOWS) {
            let Ok((window, rest)) = FlashMmapWindow::read_from_prefix(remaining) else {
                break;
            };

            // Copy packed fields
            let flash_base = window.flash_base;
            let host_base = window.host_base;
            let win_size = window.size;

            log::debug!(
                "  mmap window {}: flash {:#x} -> host {:#x}, size {} MB",
                i,
                flash_base,
                host_base,
                win_size / (1024 * 1024)
            );

            let _ = mmap_windows.push(FlashMmapWindow {
                flash_base,
                host_base,
                size: win_size,
            });
            remaining = rest;
        }
    }

    info.spi_flash = Some(SpiFlashInfo {
        flash_size,
        sector_size,
        erase_cmd,
        mmap_windows,
    });
}

/// Save raw CFR data for deferred parsing (after heap init).
///
/// CFR parsing requires heap allocation (alloc::String, alloc::Vec), but
/// table parsing runs before the heap is initialized. We save the raw data
/// pointer here and parse it later in lib::init().
fn save_cfr_raw(record_bytes: &[u8], info: &mut CorebootInfo) {
    // Safety: coreboot tables persist in firmware memory for the entire boot.
    let static_bytes: &'static [u8] =
        unsafe { core::slice::from_raw_parts(record_bytes.as_ptr(), record_bytes.len()) };
    info.cfr_raw = Some(static_bytes);
}

/// Parse boot media parameters
///
/// This function is safe - it uses zerocopy to parse the boot media params struct.
fn parse_boot_media_params(record_bytes: &[u8], info: &mut CorebootInfo) {
    let Ok((params, _)) = CbBootMediaParams::read_from_prefix(record_bytes) else {
        log::warn!("Failed to parse boot media params record");
        return;
    };

    // Copy packed fields to local variables
    let fmap_offset = params.fmap_offset;
    let cbfs_offset = params.cbfs_offset;
    let cbfs_size = params.cbfs_size;
    let boot_media_size = params.boot_media_size;

    log::info!(
        "Boot media: {} MB, FMAP at {:#x}, CBFS at {:#x} ({} MB)",
        boot_media_size / (1024 * 1024),
        fmap_offset,
        cbfs_offset,
        cbfs_size / (1024 * 1024)
    );

    info.boot_media = Some(BootMediaInfo {
        fmap_offset,
        cbfs_offset,
        cbfs_size,
        boot_media_size,
    });
}

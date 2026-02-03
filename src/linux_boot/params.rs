//! Linux Boot Parameters (Zero Page)
//!
//! This module defines the structures required for booting Linux directly,
//! including the "zero page" (boot_params), setup header, and E820 memory map.
//!
//! Reference: https://www.kernel.org/doc/html/latest/arch/x86/boot.html

use core::mem;

use crate::coreboot::memory::{MemoryRegion, MemoryType};

/// E820 memory map entry (20 bytes)
///
/// This is the standard format used by BIOS INT 15h, AX=E820h
/// and expected by the Linux kernel.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct E820Entry {
    /// Base address of the memory region
    pub addr: u64,
    /// Size of the memory region in bytes
    pub size: u64,
    /// Type of memory region
    pub entry_type: u32,
}

impl E820Entry {
    /// Usable RAM
    pub const RAM_TYPE: u32 = 1;
    /// Reserved memory (unusable)
    pub const RESERVED_TYPE: u32 = 2;
    /// ACPI reclaimable memory
    pub const ACPI_RECLAIMABLE_TYPE: u32 = 3;
    /// ACPI NVS (Non-Volatile Storage)
    pub const ACPI_NVS_TYPE: u32 = 4;
    /// Bad memory
    pub const BAD_TYPE: u32 = 5;
    /// Vendor reserved (coreboot specific)
    pub const VENDOR_RESERVED_TYPE: u32 = 6;
    /// Coreboot table (coreboot specific)
    pub const COREBOOT_TABLE_TYPE: u32 = 16;

    /// Create a new E820 entry
    pub const fn new(addr: u64, size: u64, entry_type: u32) -> Self {
        Self {
            addr,
            size,
            entry_type,
        }
    }
}

impl From<&MemoryRegion> for E820Entry {
    fn from(region: &MemoryRegion) -> Self {
        let entry_type = match region.region_type {
            MemoryType::Ram => E820Entry::RAM_TYPE,
            MemoryType::Reserved => E820Entry::RESERVED_TYPE,
            MemoryType::AcpiReclaimable => E820Entry::ACPI_RECLAIMABLE_TYPE,
            MemoryType::AcpiNvs => E820Entry::ACPI_NVS_TYPE,
            MemoryType::Unusable => E820Entry::BAD_TYPE,
            MemoryType::Table => E820Entry::COREBOOT_TABLE_TYPE,
        };

        Self {
            addr: region.start,
            size: region.size,
            entry_type,
        }
    }
}

/// Linux setup header (at offset 0x1f1 in boot sector, 119 bytes)
///
/// This structure is read from the beginning of the bzImage and contains
/// important parameters for booting the kernel.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct SetupHeader {
    /// Number of setup sectors (0 means 4)
    pub setup_sects: u8,
    /// Root flags (obsolete)
    pub root_flags: u16,
    /// Size of protected-mode code in 16-byte paragraphs
    pub syssize: u32,
    /// RAM size (obsolete)
    pub ram_size: u16,
    /// Video mode
    pub vid_mode: u16,
    /// Root device (obsolete)
    pub root_dev: u16,
    /// Boot flag - must be 0xAA55
    pub boot_flag: u16,
    /// x86 jump instruction
    pub jump: u16,
    /// Magic signature "HdrS"
    pub header: [u8; 4],
    /// Boot protocol version
    pub version: u16,
    /// Real-mode switch
    pub realmode_swtch: u32,
    /// Start of setup.S loaded low (obsolete)
    pub start_sys_seg: u16,
    /// Pointer to kernel version string
    pub kernel_version: u16,
    /// Type of loader (0xff = unknown)
    pub type_of_loader: u8,
    /// Boot loader flags
    pub loadflags: u8,
    /// Move to high memory size (obsolete)
    pub setup_move_size: u16,
    /// 32-bit entry point (protected mode code)
    pub code32_start: u32,
    /// Initrd load address
    pub ramdisk_image: u32,
    /// Initrd size
    pub ramdisk_size: u32,
    /// Bootsect helper (obsolete)
    pub bootsect_kludge: u32,
    /// End of heap setup
    pub heap_end_ptr: u16,
    /// Extended loader version
    pub ext_loader_ver: u8,
    /// Extended loader type
    pub ext_loader_type: u8,
    /// Command line pointer
    pub cmd_line_ptr: u32,
    /// Maximum initrd address
    pub initrd_addr_max: u32,
    /// Kernel alignment requirement
    pub kernel_alignment: u32,
    /// Is kernel relocatable?
    pub relocatable_kernel: u8,
    /// Minimum alignment (power of 2)
    pub min_alignment: u8,
    /// Extended load flags
    pub xloadflags: u16,
    /// Maximum command line size
    pub cmdline_size: u32,
    /// Hardware subarchitecture
    pub hardware_subarch: u32,
    /// Hardware subarchitecture data
    pub hardware_subarch_data: u64,
    /// Compressed payload offset
    pub payload_offset: u32,
    /// Compressed payload length
    pub payload_length: u32,
    /// Pointer to linked list of setup_data
    pub setup_data: u64,
    /// Preferred load address
    pub pref_address: u64,
    /// Memory required for kernel initialization
    pub init_size: u32,
    /// Offset of EFI handover entry point
    pub handover_offset: u32,
}

impl Default for SetupHeader {
    fn default() -> Self {
        // SAFETY: Struct consists entirely of primitive integral types
        unsafe { mem::zeroed() }
    }
}

impl SetupHeader {
    /// Expected boot flag value
    pub const BOOT_FLAG_MAGIC: u16 = 0xAA55;

    /// Expected header signature
    pub const HEADER_MAGIC: [u8; 4] = *b"HdrS";

    /// Minimum boot protocol version we support
    pub const MIN_VERSION: u16 = 0x0205;

    /// XLoadFlags bit: 64-bit entry point present
    pub const XLF_KERNEL_64: u16 = 1 << 0;

    /// XLoadFlags bit: EFI handover protocol supported
    pub const XLF_EFI_HANDOVER_64: u16 = 1 << 3;

    /// LoadFlags bit: loaded high (at 0x100000)
    pub const LOADED_HIGH: u8 = 1 << 0;

    /// LoadFlags bit: keep segments for bootsector (unused)
    pub const KEEP_SEGMENTS: u8 = 1 << 6;

    /// LoadFlags bit: can use heap
    pub const CAN_USE_HEAP: u8 = 1 << 7;

    /// Check if the header has valid magic numbers
    pub fn is_valid(&self) -> bool {
        self.boot_flag == Self::BOOT_FLAG_MAGIC && self.header == Self::HEADER_MAGIC
    }

    /// Check if the kernel is relocatable
    pub fn is_relocatable(&self) -> bool {
        self.relocatable_kernel != 0
    }

    /// Check if we support this boot protocol version
    pub fn is_version_supported(&self) -> bool {
        self.version >= Self::MIN_VERSION
    }

    /// Check if 64-bit entry point is available
    pub fn has_64bit_entry(&self) -> bool {
        self.xloadflags & Self::XLF_KERNEL_64 != 0
    }

    /// Check if EFI handover is supported
    pub fn supports_efi_handover(&self) -> bool {
        self.xloadflags & Self::XLF_EFI_HANDOVER_64 != 0 && self.handover_offset != 0
    }

    /// Get the number of setup sectors (0 means 4)
    pub fn num_setup_sects(&self) -> u32 {
        match self.setup_sects {
            0 => 4,
            n => n as u32,
        }
    }

    /// Get the size of the setup code in bytes
    pub fn setup_size(&self) -> u32 {
        (self.num_setup_sects() + 1) * 512
    }

    /// Get the 64-bit entry point offset
    pub fn entry64_offset(&self) -> u64 {
        // The 64-bit entry point is at code32_start + 0x200
        0x200
    }

    /// Get the EFI handover entry point offset (64-bit)
    pub fn efi_handover_offset_64(&self) -> u32 {
        // EFI handover 64-bit entry is at handover_offset + 512
        self.handover_offset + 512
    }
}

/// Offset of the setup header in the boot sector
pub const HEADER_OFFSET: usize = 0x1f1;

/// Size of the setup header
pub const HEADER_SIZE: usize = mem::size_of::<SetupHeader>();

/// End offset of the setup header
pub const HEADER_END: usize = HEADER_OFFSET + HEADER_SIZE;

/// Screen information structure (0x40 bytes)
///
/// This provides video/framebuffer information to the Linux kernel.
/// For EFI framebuffers, we set orig_video_isVGA = VIDEO_TYPE_EFI.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct ScreenInfo {
    orig_x: u8,             // 0x00
    orig_y: u8,             // 0x01
    ext_mem_k: u16,         // 0x02 - extended memory size (obsolete)
    orig_video_page: u16,   // 0x04
    orig_video_mode: u8,    // 0x06
    orig_video_cols: u8,    // 0x07
    _flags: u8,             // 0x08
    _unused2: u8,           // 0x09
    orig_video_ega_bx: u16, // 0x0a
    _unused3: u16,          // 0x0c
    orig_video_lines: u8,   // 0x0e
    orig_video_isVGA: u8,   // 0x0f - VIDEO_TYPE_*
    orig_video_points: u16, // 0x10
    // VESA info
    lfb_width: u16,       // 0x12
    lfb_height: u16,      // 0x14
    lfb_depth: u16,       // 0x16
    lfb_base: u32,        // 0x18 - lower 32 bits of framebuffer address
    lfb_size: u32,        // 0x1c
    cl_magic: u16,        // 0x20
    cl_offset: u16,       // 0x22
    lfb_linelength: u16,  // 0x24
    red_size: u8,         // 0x26
    red_pos: u8,          // 0x27
    green_size: u8,       // 0x28
    green_pos: u8,        // 0x29
    blue_size: u8,        // 0x2a
    blue_pos: u8,         // 0x2b
    rsvd_size: u8,        // 0x2c
    rsvd_pos: u8,         // 0x2d
    vesapm_seg: u16,      // 0x2e
    vesapm_off: u16,      // 0x30
    pages: u16,           // 0x32
    vesa_attributes: u16, // 0x34
    capabilities: u32,    // 0x36
    ext_lfb_base: u32,    // 0x3a - upper 32 bits of framebuffer address
    _reserved: [u8; 2],   // 0x3e
}

impl ScreenInfo {
    /// VIDEO_TYPE_EFI - EFI/UEFI framebuffer
    pub const VIDEO_TYPE_EFI: u8 = 0x70;

    /// Create a zeroed ScreenInfo
    pub const fn new() -> Self {
        // Safety: ScreenInfo is all integer types, zero is valid
        unsafe { core::mem::zeroed() }
    }
}
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct ApmBiosInfo([u8; 0x14]);
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct IstInfo([u8; 0x10]);
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct HdInfo([u8; 0x10]);
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct SysDescTable([u8; 0x10]);
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct OlpcOfwHeader([u8; 0x10]);
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct EdidInfo([u8; 0x80]);
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct EfiInfo([u8; 0x20]);
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct EddInfo([u8; 0x52]);

/// Boot parameters structure (zero page) - 4096 bytes
///
/// This is the main structure passed to the Linux kernel at boot time.
/// It must be placed at a known location and a pointer passed in RSI.
#[derive(Clone, Copy)]
#[repr(C, packed)]
pub struct BootParams {
    screen_info: ScreenInfo,    // 0x000
    apm_bios_info: ApmBiosInfo, // 0x040
    _pad2: [u8; 4],             // 0x054
    tboot_addr: u64,            // 0x058
    ist_info: IstInfo,          // 0x060
    /// ACPI RSDP address
    pub acpi_rsdp_addr: u64, // 0x070
    _pad3: [u8; 8],             // 0x078
    hd0_info: HdInfo,           // 0x080 - obsolete
    hd1_info: HdInfo,           // 0x090 - obsolete
    sys_desc_table: SysDescTable, // 0x0a0 - obsolete
    olpc_ofw_header: OlpcOfwHeader, // 0x0b0
    ext_ramdisk_image: u32,     // 0x0c0
    ext_ramdisk_size: u32,      // 0x0c4
    ext_cmd_line_ptr: u32,      // 0x0c8
    _pad4: [u8; 0x74],          // 0x0cc
    edd_info: EdidInfo,         // 0x140
    efi_info: EfiInfo,          // 0x1c0
    alt_mem_k: u32,             // 0x1e0
    scratch: u32,               // 0x1e4
    /// Number of E820 entries
    e820_entries: u8, // 0x1e8
    eddbuf_entries: u8,         // 0x1e9
    edd_mbr_sig_buf_entries: u8, // 0x1ea
    kbd_status: u8,             // 0x1eb
    secure_boot: u8,            // 0x1ec
    _pad5: [u8; 2],             // 0x1ed
    sentinel: u8,               // 0x1ef
    _pad6: [u8; 1],             // 0x1f0
    /// Setup header
    pub hdr: SetupHeader, // 0x1f1
    _pad7: [u8; 0x290 - HEADER_END],
    edd_mbr_sig_buffer: [u32; 16], // 0x290
    /// E820 memory map
    e820_table: [E820Entry; 128], // 0x2d0
    _pad8: [u8; 0x30],             // 0xcd0
    eddbuf: [EddInfo; 6],          // 0xd00
    _pad9: [u8; 0x114],            // 0xeec
}

impl Default for BootParams {
    fn default() -> Self {
        // SAFETY: Struct consists entirely of primitive integral types
        unsafe { mem::zeroed() }
    }
}

impl BootParams {
    /// Create new boot params with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the E820 memory map from coreboot memory regions
    ///
    /// # Arguments
    ///
    /// * `regions` - Slice of coreboot memory regions
    pub fn set_memory_map(&mut self, regions: &[MemoryRegion]) {
        let count = regions.len().min(128);
        self.e820_entries = count as u8;

        for (i, region) in regions.iter().take(count).enumerate() {
            self.e820_table[i] = E820Entry::from(region);
        }
    }

    /// Get the number of E820 entries
    pub fn num_e820_entries(&self) -> usize {
        self.e820_entries as usize
    }

    /// Get an E820 entry by index
    pub fn e820_entry(&self, idx: usize) -> Option<E820Entry> {
        if idx < self.num_e820_entries() {
            Some(self.e820_table[idx])
        } else {
            None
        }
    }

    /// Set the ACPI RSDP address
    pub fn set_acpi_rsdp(&mut self, addr: u64) {
        self.acpi_rsdp_addr = addr;
    }

    /// Set the command line pointer
    pub fn set_cmdline(&mut self, addr: u32) {
        self.hdr.cmd_line_ptr = addr;
    }

    /// Set the initrd address and size
    pub fn set_initrd(&mut self, addr: u32, size: u32) {
        self.hdr.ramdisk_image = addr;
        self.hdr.ramdisk_size = size;
    }

    /// Set the kernel load address (code32_start)
    pub fn set_kernel_addr(&mut self, addr: u32) {
        self.hdr.code32_start = addr;
    }

    /// Mark the loader as unknown (0xff)
    pub fn set_loader_type(&mut self) {
        self.hdr.type_of_loader = 0xff;
    }

    /// Set framebuffer information for Linux console
    ///
    /// # Arguments
    ///
    /// * `fb` - Framebuffer info from coreboot
    pub fn set_framebuffer(&mut self, fb: &crate::coreboot::FramebufferInfo) {
        // Set video type to EFI framebuffer
        self.screen_info.orig_video_isVGA = ScreenInfo::VIDEO_TYPE_EFI;

        // Set framebuffer dimensions
        self.screen_info.lfb_width = fb.x_resolution as u16;
        self.screen_info.lfb_height = fb.y_resolution as u16;
        self.screen_info.lfb_depth = fb.bits_per_pixel as u16;
        self.screen_info.lfb_linelength = fb.bytes_per_line as u16;

        // Set framebuffer address (split into lower and upper 32 bits)
        self.screen_info.lfb_base = fb.physical_address as u32;
        self.screen_info.ext_lfb_base = (fb.physical_address >> 32) as u32;

        // Calculate framebuffer size in 64KB units
        let fb_size = fb.bytes_per_line as u64 * fb.y_resolution as u64;
        self.screen_info.lfb_size = ((fb_size + 0xFFFF) / 0x10000) as u32;

        // Set color mask information
        self.screen_info.red_size = fb.red_mask_size;
        self.screen_info.red_pos = fb.red_mask_pos;
        self.screen_info.green_size = fb.green_mask_size;
        self.screen_info.green_pos = fb.green_mask_pos;
        self.screen_info.blue_size = fb.blue_mask_size;
        self.screen_info.blue_pos = fb.blue_mask_pos;

        // Reserved/alpha - assume 8 bits if 32bpp, 0 otherwise
        if fb.bits_per_pixel == 32 {
            self.screen_info.rsvd_size = 8;
            self.screen_info.rsvd_pos = 24;
        }

        log::debug!(
            "Framebuffer: {}x{}x{} @ {:#x}, {} bytes/line",
            fb.x_resolution,
            fb.y_resolution,
            fb.bits_per_pixel,
            fb.physical_address,
            fb.bytes_per_line
        );
    }

    /// Get a pointer to this structure for passing to the kernel
    pub fn as_ptr(&self) -> *const Self {
        self as *const Self
    }

    /// Get a mutable pointer to this structure
    pub fn as_mut_ptr(&mut self) -> *mut Self {
        self as *mut Self
    }
}

// Ensure correct sizes at compile time
const _: () = assert!(mem::size_of::<ScreenInfo>() == 0x40);
const _: () = assert!(mem::size_of::<SetupHeader>() == 119);
const _: () = assert!(mem::size_of::<E820Entry>() == 20);
const _: () = assert!(mem::size_of::<BootParams>() == 4096);

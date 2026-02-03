//! bzImage Loader
//!
//! This module handles loading and validating Linux bzImage kernels.
//! It parses the setup header, loads the protected-mode kernel code,
//! and prepares for direct boot or EFI handover.
//!
//! Reference: https://www.kernel.org/doc/html/latest/arch/x86/boot.html

use super::params::{BootParams, HEADER_OFFSET, SetupHeader};

/// Errors that can occur during bzImage loading
#[derive(Debug)]
pub enum BzImageError {
    /// File is too small to contain a valid header
    FileTooSmall,
    /// Invalid magic number in boot sector
    InvalidMagic,
    /// Boot protocol version too old
    UnsupportedVersion,
    /// Kernel is not relocatable
    NotRelocatable,
    /// Failed to read from disk
    ReadError,
    /// Kernel too large to fit in memory
    KernelTooLarge,
    /// No suitable memory region for initrd
    NoInitrdMemory,
    /// Command line too long
    CmdLineTooLong,
}

/// Default kernel load address (16 MB)
///
/// For 64-bit relocatable kernels, we load at 16MB to avoid conflicts with:
/// - CrabEFI itself (loaded at 1MB by coreboot)
/// - Legacy BIOS data areas
///
/// Note: 1MB (0x100000) is the traditional address for 32-bit kernels, but
/// CrabEFI occupies that space, so we use the 64-bit preferred address.
pub const DEFAULT_KERNEL_ADDR: u64 = 0x1000000;

/// Boot parameters address (zero page)
///
/// This must be at a fixed, low memory address that won't be overwritten.
/// Traditional location is around 0x10000 (64KB).
pub const BOOT_PARAMS_ADDR: u64 = 0x10000;

/// Default command line address
pub const CMDLINE_ADDR: u32 = 0x4b000;

/// Maximum command line size (64 KB)
pub const CMDLINE_MAX_SIZE: usize = 0x10000;

/// bzImage kernel information
#[derive(Debug)]
pub struct BzImage {
    /// Setup header from the kernel
    pub header: SetupHeader,
    /// Size of setup code (boot sector + setup sectors)
    pub setup_size: u32,
    /// Size of protected-mode kernel code
    pub kernel_size: u32,
    /// Total file size
    pub file_size: u32,
}

impl BzImage {
    /// Parse bzImage header from the first 1KB of the kernel file
    ///
    /// # Arguments
    ///
    /// * `data` - First 1024 bytes of the bzImage file
    /// * `total_size` - Total size of the bzImage file
    ///
    /// # Returns
    ///
    /// `BzImage` containing parsed header and size information
    pub fn parse_header(data: &[u8], total_size: u32) -> Result<Self, BzImageError> {
        if data.len() < 1024 {
            return Err(BzImageError::FileTooSmall);
        }

        // Read the setup header at offset 0x1f1
        let header = unsafe {
            let ptr = data.as_ptr().add(HEADER_OFFSET) as *const SetupHeader;
            ptr.read_unaligned()
        };

        // Validate magic numbers
        if !header.is_valid() {
            // Copy packed fields to local variables to avoid unaligned access
            let boot_flag = header.boot_flag;
            let hdr = header.header;
            log::error!(
                "Invalid bzImage magic: boot_flag={:#x}, header={:?}",
                boot_flag,
                hdr
            );
            return Err(BzImageError::InvalidMagic);
        }

        // Check protocol version
        if !header.is_version_supported() {
            // Copy packed field to local variable
            let version = header.version;
            log::error!(
                "Unsupported boot protocol version: {:#x} (need >= {:#x})",
                version,
                SetupHeader::MIN_VERSION
            );
            return Err(BzImageError::UnsupportedVersion);
        }

        // Check if kernel is relocatable
        if !header.is_relocatable() {
            log::error!("Kernel is not relocatable");
            return Err(BzImageError::NotRelocatable);
        }

        let setup_size = header.setup_size();
        let kernel_size = total_size.saturating_sub(setup_size);

        // Copy packed fields to local variables
        let version = header.version;
        let relocatable = header.is_relocatable();
        log::info!(
            "bzImage: version={:#x}, setup={}B, kernel={}B, relocatable={}",
            version,
            setup_size,
            kernel_size,
            relocatable
        );

        if header.supports_efi_handover() {
            log::info!(
                "  EFI handover supported at offset {:#x}",
                header.efi_handover_offset_64()
            );
        }

        Ok(Self {
            header,
            setup_size,
            kernel_size,
            file_size: total_size,
        })
    }

    /// Get the 64-bit entry point address
    ///
    /// # Arguments
    ///
    /// * `kernel_addr` - Address where kernel was loaded
    pub fn entry_point_64(&self, kernel_addr: u64) -> u64 {
        kernel_addr + self.header.entry64_offset()
    }

    /// Get the EFI handover entry point address (64-bit)
    ///
    /// # Arguments
    ///
    /// * `kernel_addr` - Address where kernel was loaded
    pub fn efi_handover_entry(&self, kernel_addr: u64) -> Option<u64> {
        if self.header.supports_efi_handover() {
            Some(kernel_addr + self.header.efi_handover_offset_64() as u64)
        } else {
            None
        }
    }
}

/// Copy command line to low memory
///
/// # Arguments
///
/// * `cmdline` - Command line string (will be null-terminated)
/// * `addr` - Destination address (default: CMDLINE_ADDR)
///
/// # Safety
///
/// Caller must ensure the destination address is valid and writable.
/// The caller should validate that the address is in usable RAM before calling.
pub unsafe fn set_cmdline(cmdline: &str, addr: u32) -> Result<(), BzImageError> {
    if cmdline.len() >= CMDLINE_MAX_SIZE {
        return Err(BzImageError::CmdLineTooLong);
    }

    // Note: Memory validation should be done by the caller with the full memory map
    // We can't easily validate here without access to boot_params

    let dst = addr as *mut u8;
    let bytes = cmdline.as_bytes();

    // Copy command line
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, bytes.len());

    // Null terminate
    *dst.add(bytes.len()) = 0;

    log::debug!("Command line at {:#x}: {}", addr, cmdline);

    Ok(())
}

/// Prepare boot parameters for direct Linux boot
///
/// # Arguments
///
/// * `bzimage` - Parsed bzImage information
/// * `memory_regions` - Coreboot memory map
/// * `acpi_rsdp` - ACPI RSDP address (optional)
/// * `framebuffer` - Framebuffer info (optional)
/// * `kernel_addr` - Address where kernel is loaded
/// * `cmdline_addr` - Address of command line
///
/// # Returns
///
/// Initialized boot parameters structure
pub fn prepare_boot_params(
    bzimage: &BzImage,
    memory_regions: &[crate::coreboot::memory::MemoryRegion],
    acpi_rsdp: Option<u64>,
    framebuffer: Option<&crate::coreboot::FramebufferInfo>,
    kernel_addr: u32,
    cmdline_addr: u32,
) -> BootParams {
    let mut params = BootParams::new();

    // Copy the setup header from the bzImage
    params.hdr = bzimage.header;

    // Set memory map
    params.set_memory_map(memory_regions);

    // Set ACPI RSDP if available
    if let Some(rsdp) = acpi_rsdp {
        params.set_acpi_rsdp(rsdp);
    }

    // Set framebuffer info if available
    if let Some(fb) = framebuffer {
        params.set_framebuffer(fb);
    }

    // Set loader type (unknown)
    params.set_loader_type();

    // Set kernel address
    params.set_kernel_addr(kernel_addr);

    // Set command line pointer
    params.set_cmdline(cmdline_addr);

    params
}

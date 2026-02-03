//! Direct Linux Boot Support
//!
//! This module provides direct Linux kernel booting capabilities, bypassing
//! the need for a UEFI bootloader like GRUB or systemd-boot. It supports:
//!
//! - Loading bzImage format kernels
//! - Loading initrd/initramfs
//! - Setting up the boot parameters (zero page)
//! - Direct 64-bit entry or EFI handover protocol
//!
//! # Boot Methods
//!
//! ## Direct Boot
//!
//! The traditional Linux boot protocol:
//! 1. Load protected-mode kernel to 0x100000 (1MB)
//! 2. Load initrd near top of memory (below 4GB, 2MB aligned)
//! 3. Copy command line to low memory (~0x4b000)
//! 4. Set up boot_params with memory map, ACPI info
//! 5. Jump to entry point with boot_params pointer in RSI
//!
//! ## EFI Handover
//!
//! For kernels with CONFIG_EFI_STUB:
//! 1. Load kernel and initrd as above
//! 2. Set up boot_params
//! 3. Call EFI handover entry point with:
//!    - RDI: EFI handle
//!    - RSI: EFI system table pointer
//!    - RDX: boot_params pointer
//!
//! The kernel can then use EFI runtime services.

pub mod bzimage;
pub mod params;

pub use bzimage::{BOOT_PARAMS_ADDR, BzImage, BzImageError, CMDLINE_ADDR, DEFAULT_KERNEL_ADDR};
pub use params::{BootParams, E820Entry, SetupHeader};

use crate::coreboot::memory::MemoryRegion;
use crate::drivers::block::BlockDevice;

/// Maximum kernel size we support (64 MB)
const MAX_KERNEL_SIZE: usize = 64 * 1024 * 1024;

/// Maximum initrd size we support (256 MB)
const MAX_INITRD_SIZE: usize = 256 * 1024 * 1024;

/// Errors that can occur during Linux boot
#[derive(Debug)]
pub enum LinuxBootError {
    /// Failed to load kernel
    KernelLoad(BzImageError),
    /// Failed to read file from filesystem
    FileRead,
    /// File not found
    FileNotFound,
    /// Kernel does not support EFI handover
    NoEfiHandover,
    /// Memory allocation failed
    MemoryError,
    /// Kernel too large
    KernelTooLarge,
    /// Initrd too large
    InitrdTooLarge,
}

impl From<BzImageError> for LinuxBootError {
    fn from(e: BzImageError) -> Self {
        LinuxBootError::KernelLoad(e)
    }
}

/// Linux boot configuration
#[derive(Debug, Clone)]
pub struct LinuxBootConfig<'a> {
    /// Path to the kernel (bzImage)
    pub kernel_path: &'a str,
    /// Path to the initrd (optional)
    pub initrd_path: Option<&'a str>,
    /// Kernel command line
    pub cmdline: &'a str,
    /// Use EFI handover protocol if available
    pub use_efi_handover: bool,
}

/// Loaded Linux kernel ready for boot
pub struct LoadedLinux {
    /// Boot parameters (zero page)
    pub boot_params: BootParams,
    /// Address where kernel is loaded
    pub kernel_addr: u64,
    /// Kernel entry point (64-bit)
    pub entry_point: u64,
    /// EFI handover entry point (if available)
    pub efi_handover_entry: Option<u64>,
    /// Initrd address (if loaded)
    pub initrd_addr: Option<u64>,
    /// Initrd size
    pub initrd_size: u32,
}

impl LoadedLinux {
    /// Boot the loaded Linux kernel using direct boot protocol
    ///
    /// This function does not return on success.
    ///
    /// # Safety
    ///
    /// The kernel and boot parameters must be properly set up.
    pub unsafe fn boot_direct(&mut self) -> ! {
        log::info!(
            "Booting Linux via direct 64-bit entry at {:#x}",
            self.entry_point
        );

        // Copy boot_params to fixed address (0x10000) so it survives the jump
        // The stack-allocated boot_params would be corrupted when Linux sets up its own stack
        let boot_params_ptr = BOOT_PARAMS_ADDR as *mut BootParams;
        core::ptr::copy_nonoverlapping(&self.boot_params as *const BootParams, boot_params_ptr, 1);

        log::info!("Boot params copied to {:#x}", BOOT_PARAMS_ADDR);

        // Disable interrupts
        core::arch::asm!("cli");

        // Jump to kernel entry point
        // The x86-64 calling convention puts first argument in RDI, second in RSI
        // Linux expects boot_params in RSI and a dummy value in RDI
        core::arch::asm!(
            "xor rdi, rdi",           // Clear RDI (dummy value)
            "mov rsi, {boot_params}", // boot_params pointer in RSI
            "xor rdx, rdx",           // Clear other registers
            "xor rcx, rcx",
            "xor r8, r8",
            "xor r9, r9",
            "jmp {entry}",
            boot_params = in(reg) BOOT_PARAMS_ADDR,
            entry = in(reg) self.entry_point,
            options(noreturn)
        );
    }

    /// Boot the loaded Linux kernel using EFI handover protocol
    ///
    /// This allows the kernel to use EFI runtime services.
    ///
    /// # Arguments
    ///
    /// * `image_handle` - EFI image handle
    /// * `system_table` - EFI system table pointer
    ///
    /// # Safety
    ///
    /// The kernel, boot parameters, and EFI structures must be valid.
    pub unsafe fn boot_efi_handover(
        &mut self,
        image_handle: *mut core::ffi::c_void,
        system_table: *mut core::ffi::c_void,
    ) -> ! {
        let entry = match self.efi_handover_entry {
            Some(e) => e,
            None => panic!("Kernel does not support EFI handover"),
        };

        log::info!("Booting Linux via EFI handover at {:#x}", entry);

        let boot_params_ptr = self.boot_params.as_mut_ptr();

        // EFI handover protocol:
        // - RDI: EFI image handle
        // - RSI: EFI system table
        // - RDX: boot_params pointer
        core::arch::asm!("cli");

        core::arch::asm!(
            "mov rdi, {handle}",
            "mov rsi, {systab}",
            "mov rdx, {boot_params}",
            "xor rcx, rcx",
            "xor r8, r8",
            "xor r9, r9",
            "jmp {entry}",
            handle = in(reg) image_handle as u64,
            systab = in(reg) system_table as u64,
            boot_params = in(reg) boot_params_ptr as u64,
            entry = in(reg) entry,
            options(noreturn)
        );
    }
}

/// Load a Linux kernel directly to memory
///
/// This function reads the kernel file and loads it directly to the target
/// memory address (DEFAULT_KERNEL_ADDR = 0x100000).
///
/// # Arguments
///
/// * `disk` - Block device to read from
/// * `partition_start` - Starting LBA of the partition containing the kernel
/// * `kernel_path` - Path to the kernel file (FAT path format)
/// * `initrd_path` - Optional path to initrd file
/// * `cmdline` - Kernel command line
/// * `memory_regions` - Coreboot memory map
/// * `acpi_rsdp` - ACPI RSDP address (optional)
/// * `framebuffer` - Framebuffer info (optional)
/// * `use_efi_handover` - Whether to use EFI handover if available
///
/// # Returns
///
/// `LoadedLinux` ready to boot
pub fn load_linux_from_disk<D: BlockDevice>(
    disk: &mut D,
    partition_start: u64,
    kernel_path: &str,
    initrd_path: Option<&str>,
    cmdline: &str,
    memory_regions: &[MemoryRegion],
    acpi_rsdp: Option<u64>,
    framebuffer: Option<&crate::coreboot::FramebufferInfo>,
    use_efi_handover: bool,
) -> Result<LoadedLinux, LinuxBootError> {
    use crate::fs::fat::FatFilesystem;

    log::info!("Loading Linux kernel: {}", kernel_path);

    // Mount FAT filesystem
    let mut fs = FatFilesystem::new(disk, partition_start).map_err(|e| {
        log::error!("Failed to mount FAT filesystem: {:?}", e);
        LinuxBootError::FileRead
    })?;

    // Get kernel file size
    let kernel_size = fs.file_size(kernel_path).map_err(|e| {
        log::error!("Failed to get kernel file size: {:?}", e);
        LinuxBootError::FileNotFound
    })?;

    log::info!(
        "Kernel file size: {} bytes ({} KB)",
        kernel_size,
        kernel_size / 1024
    );

    if kernel_size as usize > MAX_KERNEL_SIZE {
        log::error!(
            "Kernel too large: {} > {} bytes",
            kernel_size,
            MAX_KERNEL_SIZE
        );
        return Err(LinuxBootError::KernelTooLarge);
    }

    // Find the kernel file entry
    let kernel_entry = fs.find_file(kernel_path).map_err(|e| {
        log::error!("Failed to find kernel file: {:?}", e);
        LinuxBootError::FileNotFound
    })?;

    // Read the first 1KB to parse the header
    let mut header_buf = [0u8; 1024];
    let bytes_read = fs
        .read_file(&kernel_entry, 0, &mut header_buf)
        .map_err(|e| {
            log::error!("Failed to read kernel header: {:?}", e);
            LinuxBootError::FileRead
        })?;

    if bytes_read < 1024 {
        return Err(LinuxBootError::KernelLoad(BzImageError::FileTooSmall));
    }

    // Parse the bzImage header
    let bzimage = BzImage::parse_header(&header_buf, kernel_size)?;

    // Check if EFI handover is requested but not available
    if use_efi_handover && !bzimage.header.supports_efi_handover() {
        log::warn!("EFI handover requested but kernel doesn't support it");
        return Err(LinuxBootError::NoEfiHandover);
    }

    // Read full kernel to temp buffer, then copy protected-mode portion to target
    // We use a temp buffer because bzImage format requires skipping setup sectors
    log::info!(
        "Loading kernel to {:#x} (file size: {} bytes)",
        DEFAULT_KERNEL_ADDR,
        kernel_size
    );

    // Use high memory for temp buffer to avoid conflicts
    let temp_addr = 0x8000000u64; // 128MB - well above kernel destination (16MB)
    let kernel_buffer =
        unsafe { core::slice::from_raw_parts_mut(temp_addr as *mut u8, kernel_size as usize) };

    // Re-mount filesystem (previous borrow ended)
    let mut fs = FatFilesystem::new(disk, partition_start).map_err(|_| LinuxBootError::FileRead)?;

    // Read entire kernel file (uses optimized batch reads)
    let bytes_read = fs.read_file_all(kernel_path, kernel_buffer).map_err(|e| {
        log::error!("Failed to read kernel: {:?}", e);
        LinuxBootError::FileRead
    })?;

    if bytes_read != kernel_size as usize {
        log::error!(
            "Kernel read size mismatch: {} != {}",
            bytes_read,
            kernel_size
        );
        return Err(LinuxBootError::FileRead);
    }

    log::info!("Kernel file read, loading to {:#x}...", DEFAULT_KERNEL_ADDR);

    // Load the protected-mode kernel code to memory (skips setup sectors)
    unsafe {
        bzimage.load_kernel(kernel_buffer, DEFAULT_KERNEL_ADDR)?;
    }

    // Prepare boot parameters
    let mut boot_params = bzimage::prepare_boot_params(
        &bzimage,
        memory_regions,
        acpi_rsdp,
        framebuffer,
        DEFAULT_KERNEL_ADDR as u32,
        CMDLINE_ADDR,
    );

    // Set up command line
    unsafe {
        bzimage::set_cmdline(cmdline, CMDLINE_ADDR)?;
    }

    // Calculate entry points
    let entry_point = bzimage.entry_point_64(DEFAULT_KERNEL_ADDR);
    let efi_handover_entry = bzimage.efi_handover_entry(DEFAULT_KERNEL_ADDR);

    log::info!(
        "Entry points: direct={:#x}, handover={:?}",
        entry_point,
        efi_handover_entry
    );

    // Load initrd if specified
    let mut initrd_addr = None;
    let mut initrd_size = 0u32;

    if let Some(initrd_path) = initrd_path
        && !initrd_path.is_empty()
    {
        log::info!("Loading initrd: {}", initrd_path);

        // Re-mount filesystem
        let mut fs =
            FatFilesystem::new(disk, partition_start).map_err(|_| LinuxBootError::FileRead)?;

        // Get initrd size
        let initrd_file_size = fs.file_size(initrd_path).map_err(|e| {
            log::error!("Failed to get initrd file size: {:?}", e);
            LinuxBootError::FileNotFound
        })?;

        log::info!(
            "Initrd file size: {} bytes ({} MB)",
            initrd_file_size,
            initrd_file_size / (1024 * 1024)
        );

        if initrd_file_size as usize > MAX_INITRD_SIZE {
            log::error!(
                "Initrd too large: {} > {} bytes",
                initrd_file_size,
                MAX_INITRD_SIZE
            );
            return Err(LinuxBootError::InitrdTooLarge);
        }

        // Find a suitable address for the initrd
        // Use a temporary buffer to read, then call load_initrd to find placement
        // For simplicity, we'll place it at a fixed high address
        // Real implementation would use boot_params memory map

        // Place initrd at 0x10000000 (256 MB) - should be safe for most systems
        // This is below the 4GB limit and should be identity-mapped
        let initrd_load_addr = find_initrd_address(&boot_params, initrd_file_size as u64)?;

        log::info!("Loading initrd to {:#x}", initrd_load_addr);

        let initrd_buffer = unsafe {
            core::slice::from_raw_parts_mut(initrd_load_addr as *mut u8, initrd_file_size as usize)
        };

        // Re-mount filesystem
        let mut fs =
            FatFilesystem::new(disk, partition_start).map_err(|_| LinuxBootError::FileRead)?;

        let bytes_read = fs.read_file_all(initrd_path, initrd_buffer).map_err(|e| {
            log::error!("Failed to read initrd: {:?}", e);
            LinuxBootError::FileRead
        })?;

        if bytes_read != initrd_file_size as usize {
            log::error!(
                "Initrd read size mismatch: {} != {}",
                bytes_read,
                initrd_file_size
            );
            return Err(LinuxBootError::FileRead);
        }

        // Update boot params with initrd info
        boot_params.set_initrd(initrd_load_addr as u32, initrd_file_size);
        initrd_addr = Some(initrd_load_addr);
        initrd_size = initrd_file_size;

        log::info!("Initrd loaded successfully");
    }

    log::info!("Linux kernel loaded successfully");
    log::info!("  Kernel address: {:#x}", DEFAULT_KERNEL_ADDR);
    log::info!("  Entry point: {:#x}", entry_point);
    if let Some(handover) = efi_handover_entry {
        log::info!("  EFI handover: {:#x}", handover);
    }
    if let Some(addr) = initrd_addr {
        log::info!("  Initrd: {:#x} ({} bytes)", addr, initrd_size);
    }
    log::info!("  Command line: {}", cmdline);

    Ok(LoadedLinux {
        boot_params,
        kernel_addr: DEFAULT_KERNEL_ADDR,
        entry_point,
        efi_handover_entry,
        initrd_addr,
        initrd_size,
    })
}

/// Find a suitable address for the initrd
///
/// Searches the memory map for a RAM region that can hold the initrd,
/// preferring high addresses (below initrd_addr_max).
fn find_initrd_address(boot_params: &BootParams, size: u64) -> Result<u64, LinuxBootError> {
    // Get maximum initrd address from header, default to 0x37FFFFFF
    let initrd_addr_max = match boot_params.hdr.initrd_addr_max {
        0 => 0x37FF_FFFF,
        a => a as u64,
    };

    // Limit to 4GB identity-mapped area
    let initrd_addr_max = initrd_addr_max.min((4u64 << 30) - 1);

    // Find highest suitable RAM region
    let mut best_addr: Option<u64> = None;

    for i in 0..boot_params.num_e820_entries() {
        if let Some(entry) = boot_params.e820_entry(i) {
            // Only consider RAM regions
            if entry.entry_type != E820Entry::RAM_TYPE {
                continue;
            }

            // Skip regions that start beyond max
            if entry.addr > initrd_addr_max {
                continue;
            }

            // Skip regions that are too small
            if entry.size < size {
                continue;
            }

            // Skip low memory (need to be above kernel)
            if entry.addr < 0x1000000 {
                // 16 MB
                continue;
            }

            // Calculate highest address in this region that fits
            let region_end = entry.addr + entry.size;
            let potential_addr = region_end.saturating_sub(size);

            // Align to 2MB boundary
            let potential_addr = potential_addr & !((2u64 << 20) - 1);

            // Clamp to max
            let potential_addr = potential_addr.min(initrd_addr_max + 1 - size);

            // Must still be within the region
            if potential_addr < entry.addr {
                continue;
            }

            // Use the highest address we can find
            if let Some(current) = best_addr {
                if potential_addr > current {
                    best_addr = Some(potential_addr);
                }
            } else {
                best_addr = Some(potential_addr);
            }
        }
    }

    // Fallback: use 0x10000000 (256 MB) if no suitable region found
    // This should work on most systems with >= 512 MB RAM
    let addr = best_addr.unwrap_or(0x1000_0000);

    log::debug!("Selected initrd address: {:#x}", addr);

    Ok(addr)
}

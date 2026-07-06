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

use crate::drivers::block::BlockDevice;
use crate::platform::MemoryRegion;

/// Maximum kernel size we support (64 MB)
const MAX_KERNEL_SIZE: usize = 64 * 1024 * 1024;

/// Maximum initrd size we support (256 MB)
const MAX_INITRD_SIZE: usize = 256 * 1024 * 1024;

/// Linux initrd placement alignment.
const INITRD_ALIGN: u64 = 2 * 1024 * 1024;

/// Check if an address range is usable RAM according to the boot params memory map
///
/// # Arguments
///
/// * `boot_params` - Boot parameters containing the E820 memory map
/// * `addr` - Start address of the region to check
/// * `size` - Size of the region in bytes
///
/// # Returns
///
/// `true` if the entire address range falls within a usable RAM region
fn is_valid_ram_region(boot_params: &BootParams, addr: u64, size: u64) -> bool {
    for i in 0..boot_params.num_e820_entries() {
        if let Some(entry) = boot_params.e820_entry(i)
            && entry.entry_type == E820Entry::RAM_TYPE
        {
            let region_end = entry.addr.saturating_add(entry.size);
            let range_end = addr.saturating_add(size);

            // Check if our range is fully contained in this RAM region
            if addr >= entry.addr && range_end <= region_end {
                return true;
            }
        }
    }
    false
}

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

        // Validate that the boot params address is in usable RAM
        let boot_params_size = core::mem::size_of::<BootParams>() as u64;
        if !is_valid_ram_region(&self.boot_params, BOOT_PARAMS_ADDR, boot_params_size) {
            panic!(
                "Boot params address {:#x} (size {}) is not in usable RAM",
                BOOT_PARAMS_ADDR, boot_params_size
            );
        }

        // Copy boot_params to fixed address (0x10000) so it survives the jump
        // The stack-allocated boot_params would be corrupted when Linux sets up its own stack
        let boot_params_ptr = BOOT_PARAMS_ADDR as *mut BootParams;
        // SAFETY: Caller guarantees kernel and boot parameters are properly set up.
        // BOOT_PARAMS_ADDR was validated above to be in usable RAM.
        unsafe {
            core::ptr::copy_nonoverlapping(
                &self.boot_params as *const BootParams,
                boot_params_ptr,
                1,
            );
        }

        log::info!("Boot params copied to {:#x}", BOOT_PARAMS_ADDR);

        // SAFETY: Disabling interrupts and jumping to kernel entry point.
        // The caller guarantees the kernel is properly loaded and boot params are valid.
        unsafe {
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

        // SAFETY: Caller guarantees the kernel, boot parameters, and EFI structures are valid.
        unsafe {
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
/// * `memory_regions` - Platform memory map
/// * `acpi_rsdp` - ACPI RSDP address (optional)
/// * `framebuffer` - Framebuffer info (optional)
/// * `use_efi_handover` - Whether to use EFI handover if available
///
/// # Returns
///
/// `LoadedLinux` ready to boot
pub fn load_linux_from_disk(
    disk: &mut dyn BlockDevice,
    partition_start: u64,
    kernel_path: &str,
    initrd_path: Option<&str>,
    cmdline: &str,
    memory_regions: &[MemoryRegion],
    acpi_rsdp: Option<u64>,
    framebuffer: Option<&crate::platform::FramebufferConfig>,
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

    // DMA the protected-mode kernel directly to the target address
    // We skip the setup sectors by using the offset parameter in read_file
    // This avoids an intermediate buffer and extra memcpy
    let setup_size = bzimage.setup_size;
    let pm_kernel_size = bzimage.kernel_size as usize;

    log::info!(
        "Loading kernel to {:#x} (skip {} setup bytes, {} kernel bytes)",
        DEFAULT_KERNEL_ADDR,
        setup_size,
        pm_kernel_size
    );

    // Prepare boot parameters first so we can validate addresses BEFORE writing
    let mut boot_params = bzimage::prepare_boot_params(
        &bzimage,
        memory_regions,
        acpi_rsdp,
        framebuffer,
        DEFAULT_KERNEL_ADDR as u32,
        CMDLINE_ADDR,
    );

    // Validate that all hardcoded addresses are in usable RAM BEFORE writing to them
    let cmdline_size = cmdline.len() as u64 + 1; // +1 for null terminator
    if !is_valid_ram_region(&boot_params, CMDLINE_ADDR as u64, cmdline_size) {
        log::error!(
            "Command line address {:#x} (size {}) is not in usable RAM",
            CMDLINE_ADDR,
            cmdline_size
        );
        return Err(LinuxBootError::MemoryError);
    }

    // Validate kernel load address before loading
    if !is_valid_ram_region(&boot_params, DEFAULT_KERNEL_ADDR, pm_kernel_size as u64) {
        log::error!(
            "Kernel address {:#x} (size {}) is not in usable RAM",
            DEFAULT_KERNEL_ADDR,
            pm_kernel_size
        );
        return Err(LinuxBootError::MemoryError);
    }

    // Create a slice pointing directly to the kernel load address
    // This allows DMA to go directly to the target memory
    let kernel_dest =
        unsafe { core::slice::from_raw_parts_mut(DEFAULT_KERNEL_ADDR as *mut u8, pm_kernel_size) };

    // Re-mount filesystem (previous borrow ended)
    let mut fs = FatFilesystem::new(disk, partition_start).map_err(|_| LinuxBootError::FileRead)?;

    // Read kernel directly to target address, skipping setup sectors
    // The FAT read_file function with offset will DMA directly to our buffer
    let bytes_read = fs
        .read_file(&kernel_entry, setup_size, kernel_dest)
        .map_err(|e| {
            log::error!("Failed to read kernel: {:?}", e);
            LinuxBootError::FileRead
        })?;

    if bytes_read != pm_kernel_size {
        log::error!(
            "Kernel read size mismatch: {} != {}",
            bytes_read,
            pm_kernel_size
        );
        return Err(LinuxBootError::FileRead);
    }

    log::info!(
        "Kernel loaded directly to {:#x} ({} bytes via DMA)",
        DEFAULT_KERNEL_ADDR,
        bytes_read
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

        // Place the initrd in usable RAM above the loaded kernel, respecting
        // the kernel-provided initrd_addr_max limit.
        let min_initrd_addr = DEFAULT_KERNEL_ADDR
            .checked_add(pm_kernel_size as u64)
            .ok_or(LinuxBootError::MemoryError)?;
        let initrd_load_addr =
            find_initrd_address(&boot_params, initrd_file_size as u64, min_initrd_addr)?;

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

    crate::efi::boot_services::measure_efi_application_start(true);
    crate::efi::tcg::measured_boot::measure_event_all(
        4,
        crate::efi::tcg::types::EV_IPL,
        kernel_dest,
        b"linux kernel",
        "linux kernel",
    );
    if let Some(addr) = initrd_addr {
        // Safety: initrd_addr/initrd_size were set only after read_file_all filled this RAM range.
        let initrd =
            unsafe { core::slice::from_raw_parts(addr as *const u8, initrd_size as usize) };
        crate::efi::tcg::measured_boot::measure_event_all(
            4,
            crate::efi::tcg::types::EV_IPL,
            initrd,
            b"linux initrd",
            "linux initrd",
        );
    }
    crate::efi::tcg::measured_boot::measure_event_all(
        4,
        crate::efi::tcg::types::EV_IPL,
        cmdline.as_bytes(),
        b"linux command line",
        "linux command line",
    );

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
fn find_initrd_address(
    boot_params: &BootParams,
    size: u64,
    min_addr: u64,
) -> Result<u64, LinuxBootError> {
    if size == 0 {
        return Err(LinuxBootError::MemoryError);
    }

    // Get maximum initrd address from header, default to 0x37FFFFFF
    let initrd_addr_max = match boot_params.hdr.initrd_addr_max {
        0 => 0x37FF_FFFF,
        a => a as u64,
    };

    // Limit to 4GB identity-mapped area
    let initrd_addr_max = initrd_addr_max.min((4u64 << 30) - 1);
    let max_exclusive = initrd_addr_max
        .checked_add(1)
        .ok_or(LinuxBootError::MemoryError)?;
    let max_start = max_exclusive
        .checked_sub(size)
        .ok_or(LinuxBootError::MemoryError)?;

    // Find highest suitable RAM region
    let mut best_addr: Option<u64> = None;

    for i in 0..boot_params.num_e820_entries() {
        let Some(entry) = boot_params.e820_entry(i) else {
            continue;
        };

        // Only consider RAM regions
        if entry.entry_type != E820Entry::RAM_TYPE {
            continue;
        }

        // Skip regions that start beyond max
        if entry.addr > initrd_addr_max {
            continue;
        }

        // Calculate the usable portion of this region. Coreboot commonly
        // reports the main RAM range as starting at 1 MiB, so do not reject a
        // whole region just because its base is below the kernel/initrd floor.
        // Instead, clamp the start upward and use the high part of the range.
        // Treat malformed wrapping E820 regions as unusable.
        let Some(region_end) = entry.addr.checked_add(entry.size) else {
            continue;
        };

        let usable_start = entry.addr.max(min_addr);
        let usable_end = region_end.min(max_exclusive);

        let Some(required_end) = usable_start.checked_add(size) else {
            continue;
        };
        if required_end > usable_end {
            continue;
        }

        // Calculate the highest aligned address in this clipped region that
        // can hold the whole initrd.
        let mut potential_addr = usable_end - size;
        potential_addr = potential_addr.min(max_start);
        potential_addr &= !(INITRD_ALIGN - 1);

        // Must still be within the region
        if potential_addr < usable_start {
            continue;
        }

        // Use the highest address we can find
        best_addr = Some(best_addr.map_or(potential_addr, |current| current.max(potential_addr)));
    }

    let addr = best_addr.ok_or_else(|| {
        log::error!(
            "No suitable RAM region found for initrd ({} bytes, min_addr={:#x}, max_addr={:#x})",
            size,
            min_addr,
            initrd_addr_max
        );
        LinuxBootError::MemoryError
    })?;

    log::debug!("Selected initrd address: {:#x}", addr);

    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::MemoryType;

    fn boot_params_with_regions(regions: &[MemoryRegion]) -> BootParams {
        let mut boot_params = BootParams::new();
        boot_params.set_memory_map(regions);
        boot_params
    }

    #[test]
    fn initrd_uses_high_part_of_ram_region_starting_below_kernel() {
        let regions = [MemoryRegion {
            base: 0x0010_0000,
            size: 0x1ff0_0000,
            region_type: MemoryType::Ram,
        }];
        let boot_params = boot_params_with_regions(&regions);
        let initrd_size = 43_000_445;
        let min_addr = DEFAULT_KERNEL_ADDR + 13_824_512;

        let addr = find_initrd_address(&boot_params, initrd_size, min_addr)
            .expect("main RAM region should fit initrd above kernel");

        assert_eq!(addr & (INITRD_ALIGN - 1), 0);
        assert!(addr >= min_addr);
        assert!(addr + initrd_size <= regions[0].base + regions[0].size);
    }

    #[test]
    fn initrd_does_not_overlap_loaded_kernel() {
        let regions = [MemoryRegion {
            base: 0x0010_0000,
            size: 0x02f0_0000,
            region_type: MemoryType::Ram,
        }];
        let boot_params = boot_params_with_regions(&regions);
        let min_addr = 0x01e0_0000;

        let result = find_initrd_address(&boot_params, 43_000_445, min_addr);

        assert!(matches!(result, Err(LinuxBootError::MemoryError)));
    }
}

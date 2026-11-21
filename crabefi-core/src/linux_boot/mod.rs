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
//! 1. Load protected-mode kernel to 0x1000000 (16 MiB)
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
pub use params::{BootParams, E820Entry, E820MapError};

use crate::drivers::block::BlockDevice;
use crate::efi::allocator::{self, AllocateType, MemoryType, PAGE_SIZE};
#[cfg(test)]
use crate::platform::MemoryRegion;
use r_efi::efi::Status;

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
    /// Effective firmware memory map exceeds the Linux E820 table
    MemoryMapTooLarge,
}

impl From<BzImageError> for LinuxBootError {
    fn from(e: BzImageError) -> Self {
        LinuxBootError::KernelLoad(e)
    }
}

impl From<E820MapError> for LinuxBootError {
    fn from(error: E820MapError) -> Self {
        match error {
            E820MapError::TooManyEntries => LinuxBootError::MemoryMapTooLarge,
        }
    }
}

/// Keep each Linux destination out of the firmware allocator until handoff.
/// On error (or if a loaded kernel is discarded), release it for the next boot.
struct BootPages {
    base: u64,
    count: u64,
}

impl BootPages {
    fn claim(mut base: u64, size: u64) -> Result<Self, LinuxBootError> {
        let count = size.div_ceil(PAGE_SIZE);
        let status = allocator::allocate_pages(
            AllocateType::AllocateAddress,
            MemoryType::BootServicesData,
            count,
            &mut base,
        );
        if status != Status::SUCCESS {
            log::error!("Cannot claim Linux boot pages at {base:#x} ({count} pages): {status:?}");
            return Err(LinuxBootError::MemoryError);
        }
        Ok(Self { base, count })
    }
}

impl Drop for BootPages {
    fn drop(&mut self) {
        let status = allocator::free_pages(self.base, self.count);
        if status != Status::SUCCESS {
            log::warn!(
                "Could not release Linux boot pages at {:#x}: {status:?}",
                self.base
            );
        }
    }
}

/// Loaded Linux kernel ready for boot
pub struct LoadedLinux {
    /// Boot parameters (zero page)
    pub boot_params: BootParams,
    /// Address where kernel is loaded
    kernel_addr: u64,
    /// Kernel entry point (64-bit)
    pub entry_point: u64,
    /// EFI handover entry point (if available)
    pub efi_handover_entry: Option<u64>,
    /// Initrd address (if loaded)
    initrd_addr: Option<u64>,
    /// Initrd size
    initrd_size: u32,
    /// Bytes of protected-mode kernel loaded at `kernel_addr`. Private like
    /// the address fields: [`Self::measure_start`] reads memory through them.
    kernel_size: usize,
    // Retain the reservations across the filesystem borrow and DMA shutdown.
    _boot_pages: [Option<BootPages>; 4],
}

impl LoadedLinux {
    /// Signal ReadyToBoot and measure the kernel, initrd and command line.
    ///
    /// Call this after the filesystem borrow ends: ReadyToBoot runs image
    /// callbacks and measurement reads variables through the runtime image,
    /// and no firmware borrow may be live across either.
    pub fn measure_start(&self, cmdline: &str) {
        crate::efi::boot_services::measure_efi_application_start(true);
        #[cfg(feature = "tpm")]
        {
            use crate::efi::tcg::{measured_boot::measure_event_all, types::EV_IPL};

            // SAFETY: the loader filled these ranges, and the boot pages it
            // retains keep them reserved until handoff.
            let kernel = unsafe {
                core::slice::from_raw_parts(self.kernel_addr as *const u8, self.kernel_size)
            };
            measure_event_all(4, EV_IPL, kernel, b"linux kernel", "linux kernel");
            if let Some(addr) = self.initrd_addr {
                // SAFETY: as above.
                let initrd = unsafe {
                    core::slice::from_raw_parts(addr as *const u8, self.initrd_size as usize)
                };
                measure_event_all(4, EV_IPL, initrd, b"linux initrd", "linux initrd");
            }
            measure_event_all(
                4,
                EV_IPL,
                cmdline.as_bytes(),
                b"linux command line",
                "linux command line",
            );
        }
        #[cfg(not(feature = "tpm"))]
        let _ = cmdline;
    }

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

        // Direct boot bypasses EFI ExitBootServices, so perform the same DMA
        // shutdown before Linux can reclaim firmware-owned buffers. Without
        // this, active USB/storage controllers can corrupt pages after the jump.
        crate::drivers::quiesce_dma_for_os_handoff();
        crate::drivers::keyboard_common::cleanup();

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
/// * `initrd_paths` - The initrd files, loaded back to back in order
/// * `cmdline` - Kernel command line
/// * `acpi_rsdp` - ACPI RSDP address (optional)
/// * `framebuffer` - Framebuffer info (optional)
/// * `use_efi_handover` - Whether to use EFI handover if available
///
/// # Returns
///
/// `LoadedLinux` ready to boot. Call [`LoadedLinux::measure_start`] after
/// releasing the disk.
// Boot inputs span disk, kernel, and platform concerns; callers pass them
// straight through from handoff data, so a parameter struct adds no clarity.
#[allow(clippy::too_many_arguments)]
pub fn load_linux_from_disk(
    disk: &mut dyn BlockDevice,
    partition_start: u64,
    kernel_path: &str,
    initrd_paths: &[&str],
    cmdline: &str,
    acpi_rsdp: Option<u64>,
    framebuffer: Option<&crate::platform::FramebufferConfig>,
    use_efi_handover: bool,
) -> Result<LoadedLinux, LinuxBootError> {
    let mut fs = crate::fs::fat::FatFilesystem::new(disk, partition_start).map_err(|e| {
        log::error!("Failed to mount FAT filesystem: {:?}", e);
        LinuxBootError::FileRead
    })?;
    load_linux_from_fs::<false>(
        &mut fs,
        kernel_path,
        initrd_paths,
        cmdline,
        acpi_rsdp,
        framebuffer,
        use_efi_handover,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn load_linux_from_fs<const NATIVE: bool>(
    fs: &mut dyn crate::fs::boot::BootFilesystem,
    kernel_path: &str,
    initrd_paths: &[&str],
    cmdline: &str,
    acpi_rsdp: Option<u64>,
    framebuffer: Option<&crate::platform::FramebufferConfig>,
    use_efi_handover: bool,
) -> Result<LoadedLinux, LinuxBootError> {
    log::info!("Loading Linux kernel: {}", kernel_path);

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

    if kernel_size > MAX_KERNEL_SIZE as u64 {
        log::error!(
            "Kernel too large: {} > {} bytes",
            kernel_size,
            MAX_KERNEL_SIZE
        );
        return Err(LinuxBootError::KernelTooLarge);
    }

    // Read the first 1KB to parse the header
    let mut header_buf = [0u8; 1024];
    let bytes_read = fs
        .read_file_at(kernel_path, 0, &mut header_buf)
        .map_err(|e| {
            log::error!("Failed to read kernel header: {:?}", e);
            LinuxBootError::FileRead
        })?;

    if bytes_read < 1024 {
        return Err(LinuxBootError::KernelLoad(BzImageError::FileTooSmall));
    }

    // Parse the bzImage header
    let bzimage = BzImage::parse_header(&header_buf, kernel_size as u32)?;

    let entry_point = bzimage.entry_point_64(DEFAULT_KERNEL_ADDR);
    let efi_handover_entry = bzimage.efi_handover_entry(DEFAULT_KERNEL_ADDR);
    if use_efi_handover && efi_handover_entry.is_none() {
        log::warn!("EFI handover requested but kernel doesn't support it");
        return Err(LinuxBootError::NoEfiHandover);
    }

    // Read the protected-mode kernel into the destination, skipping setup sectors.
    let setup_size = bzimage.setup_size;
    let pm_kernel_size = bzimage.kernel_size as usize;

    log::info!(
        "Loading kernel to {:#x} (skip {} setup bytes, {} kernel bytes)",
        DEFAULT_KERNEL_ADDR,
        setup_size,
        pm_kernel_size
    );

    // Snapshot E820 before claiming Linux-owned buffers. They must appear as
    // usable RAM to Linux, unlike the firmware's own heap and DMA allocations.
    let mut boot_params = bzimage::prepare_boot_params(
        &bzimage,
        acpi_rsdp,
        framebuffer,
        DEFAULT_KERNEL_ADDR as u32,
        CMDLINE_ADDR,
    )?;

    let cmdline_size = cmdline.len() as u64 + 1; // +1 for null terminator
    let params_size = core::mem::size_of::<BootParams>() as u64;
    let kernel_span = (pm_kernel_size as u64).max(u64::from(bzimage.header.init_size));
    let boot_ranges = [
        (BOOT_PARAMS_ADDR, params_size),
        (u64::from(CMDLINE_ADDR), cmdline_size),
        (DEFAULT_KERNEL_ADDR, kernel_span),
    ];
    let mut boot_pages = [None, None, None, None];
    for (slot, (addr, size)) in boot_pages.iter_mut().zip(boot_ranges) {
        if !is_valid_ram_region(&boot_params, addr, size) {
            log::error!("Linux boot range at {addr:#x} ({size} bytes) is not in usable RAM");
            return Err(LinuxBootError::MemoryError);
        }
        *slot = Some(BootPages::claim(addr, size)?);
    }

    // SAFETY: The allocator holds the destination exclusively until handoff.
    let kernel_dest =
        unsafe { core::slice::from_raw_parts_mut(DEFAULT_KERNEL_ADDR as *mut u8, pm_kernel_size) };

    let bytes_read = fs
        .read_file_at(kernel_path, u64::from(setup_size), kernel_dest)
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

    // The kernel text was just written by DMA/copy; make it visible to
    // instruction fetch before any jump to the entry point.
    crate::arch::sync_instruction_cache(DEFAULT_KERNEL_ADDR, pm_kernel_size);

    log::info!(
        "Kernel loaded directly to {:#x} ({} bytes)",
        DEFAULT_KERNEL_ADDR,
        bytes_read
    );

    // Set up command line
    unsafe {
        bzimage::set_cmdline(cmdline, CMDLINE_ADDR)?;
    }

    log::info!(
        "Entry points: direct={:#x}, handover={:?}",
        entry_point,
        efi_handover_entry
    );

    // Load the initrds back to back, each padded to 4 bytes, as one range:
    // the kernel unpacks concatenated cpio archives (e.g. microcode first,
    // then the initramfs).
    let mut initrd_addr = None;
    let mut initrd_size = 0u32;

    if !initrd_paths.is_empty() {
        let mut sizes: heapless::Vec<usize, { crate::bls::MAX_INITRDS }> = heapless::Vec::new();
        for path in initrd_paths {
            let size = fs.file_size(path).map_err(|e| {
                log::error!("Failed to get initrd file size of {}: {:?}", path, e);
                LinuxBootError::FileNotFound
            })?;
            if size > MAX_INITRD_SIZE as u64 {
                return Err(LinuxBootError::InitrdTooLarge);
            }
            log::info!("Initrd {}: {} bytes", path, size);
            sizes
                .push(size as usize)
                .map_err(|_| LinuxBootError::InitrdTooLarge)?;
        }
        let total = sizes
            .iter()
            .try_fold(0usize, |total, &size| {
                total.checked_add(size.next_multiple_of(4))
            })
            .filter(|&total| total <= MAX_INITRD_SIZE)
            .ok_or_else(|| {
                log::error!("Initrds too large (limit {} bytes)", MAX_INITRD_SIZE);
                LinuxBootError::InitrdTooLarge
            })?;

        // Place the initrds in usable RAM above the loaded kernel, respecting
        // the kernel-provided initrd_addr_max limit.
        let min_initrd_addr = DEFAULT_KERNEL_ADDR + kernel_span;
        let span = (total as u64).next_multiple_of(PAGE_SIZE);
        let initrd_load_addr = find_initrd_address(&boot_params, span, min_initrd_addr)?;
        boot_pages[3] = Some(BootPages::claim(initrd_load_addr, span)?);

        log::info!(
            "Loading {} byte(s) of initrd to {:#x}",
            total,
            initrd_load_addr
        );

        let initrd_buffer =
            unsafe { core::slice::from_raw_parts_mut(initrd_load_addr as *mut u8, total) };
        let mut offset = 0;
        for (path, &size) in initrd_paths.iter().zip(&sizes) {
            let bytes_read = fs
                .read_file_all(path, &mut initrd_buffer[offset..offset + size])
                .map_err(|e| {
                    log::error!("Failed to read initrd {}: {:?}", path, e);
                    LinuxBootError::FileRead
                })?;
            if bytes_read != size {
                log::error!(
                    "Initrd {} read size mismatch: {} != {}",
                    path,
                    bytes_read,
                    size
                );
                return Err(LinuxBootError::FileRead);
            }
            let padded = offset + size.next_multiple_of(4);
            initrd_buffer[offset + size..padded].fill(0);
            offset = padded;
        }

        // Update boot params with initrd info
        boot_params.set_initrd(initrd_load_addr as u32, total as u32);
        initrd_addr = Some(initrd_load_addr);
        initrd_size = total as u32;

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
        kernel_size: pm_kernel_size,
        _boot_pages: boot_pages,
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
    use crate::platform::MemoryType as PlatformMemoryType;

    fn boot_params_with_regions(regions: &[MemoryRegion]) -> BootParams {
        let mut boot_params = BootParams::new();
        boot_params.set_memory_map(regions);
        boot_params
    }

    #[test]
    fn boot_pages_exclude_other_allocations_and_release_on_error() {
        allocator::with_host_pages(|| {
            let (base, size) = allocator::with_descriptors(|map| {
                let free = map
                    .iter()
                    .find(|e| {
                        e.memory_type == MemoryType::ConventionalMemory as u32
                            && e.number_of_pages >= 2
                    })
                    .unwrap();
                (free.physical_start, free.number_of_pages * PAGE_SIZE)
            });
            let last_page = base + size - PAGE_SIZE;
            let attempt = || -> Result<(), LinuxBootError> {
                let _initrd = BootPages::claim(last_page, PAGE_SIZE)?;
                let mut dma = 0;
                assert_eq!(
                    allocator::allocate_pages_in_range(
                        MemoryType::BootServicesData,
                        1,
                        base,
                        base + size - 1,
                        &mut dma
                    ),
                    Status::SUCCESS
                );
                assert_eq!(dma, last_page - PAGE_SIZE);
                assert_eq!(allocator::free_pages(dma, 1), Status::SUCCESS);
                Err(LinuxBootError::FileRead)
            };
            assert!(matches!(attempt(), Err(LinuxBootError::FileRead)));
            assert_eq!(
                allocator::get_memory_type_at(last_page),
                Some(MemoryType::ConventionalMemory)
            );
        });
    }

    #[test]
    fn initrd_uses_high_part_of_ram_region_starting_below_kernel() {
        let regions = [MemoryRegion {
            base: 0x0010_0000,
            size: 0x1ff0_0000,
            region_type: PlatformMemoryType::Ram,
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
            region_type: PlatformMemoryType::Ram,
        }];
        let boot_params = boot_params_with_regions(&regions);
        let min_addr = 0x01e0_0000;

        let result = find_initrd_address(&boot_params, 43_000_445, min_addr);

        assert!(matches!(result, Err(LinuxBootError::MemoryError)));
    }
}

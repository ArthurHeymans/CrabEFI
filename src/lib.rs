//! CrabEFI - A minimal UEFI implementation as a coreboot payload
//!
//! This library provides the core functionality for a minimal UEFI environment
//! that can boot Linux via shim+GRUB2 or systemd-boot on real laptop hardware.

#![no_std]
#![feature(never_type)] // Used for -> ! return type in payload chainloading
#![deny(unsafe_op_in_unsafe_fn)]
// Allow common firmware code patterns
#![allow(clippy::result_unit_err)] // Result<(), ()> is common in embedded code
#![allow(clippy::too_many_arguments)] // USB/hardware APIs often require many parameters
#![allow(clippy::field_reassign_with_default)] // Clearer than complex struct initializers

// Enable alloc crate for heap allocations (needed for RustCrypto)
extern crate alloc;

pub mod arch;
pub mod bls;
pub mod boot;
mod boot_manager;
pub mod boot_vars;
pub mod cfr_menu;
pub mod coreboot;
#[cfg(feature = "ui")]
pub mod cursor;
pub mod drivers;
pub mod efi;
#[cfg(feature = "fb-log")]
pub mod fb_log;
pub mod fdt;
pub mod framebuffer_console;
pub mod fs;
pub mod grub;
pub mod heap;
#[cfg(target_arch = "x86_64")]
pub mod linux_boot;
pub mod logger;
pub mod menu;
pub(crate) mod menu_common;
pub mod payload;
pub mod pe;
pub mod platform;
pub mod secure_boot_menu;
pub mod state;
pub mod time;
#[cfg(feature = "ui")]
pub mod ui;

use crate::drivers::block::{AhciDisk, NvmeDisk, SdhciDisk, UsbDisk};

// Re-export the public platform API at the crate root for ergonomic access.
pub use platform::{
    BlockDevice, BlockDeviceInfo, BlockError, BootResult, ConsoleInput, DebugOutput,
    DeferredBufferConfig, FramebufferConfig, Key, KeyState, MemoryRegion, MemoryType,
    PlatformConfig, ResetHandler, ResetType, Rng, RngError, RuntimeRegion, StorageBackend,
    StorageError, Timer, VarBackendError, VariableBackend, VariableVisitor,
};

/// Display a Secure Boot violation error on screen
///
/// This function displays a prominent red error message in the center of the screen
/// when Secure Boot verification fails. It also outputs to the serial console.
/// The display persists for a few seconds so the user can see it.
pub fn display_secure_boot_error() {
    use framebuffer_console::{Color, DEFAULT_BG, FramebufferConsole};

    const ERROR_MESSAGE: &str = "SECURE BOOT VIOLATION: Image not authorized";

    // Output to serial console with red color (ANSI escape codes)
    drivers::serial::write_str("\r\n\x1b[1;31m"); // Bold red
    drivers::serial::write_str(
        "================================================================================\r\n",
    );
    drivers::serial::write_str(
        "                    SECURE BOOT VIOLATION: Image not authorized                 \r\n",
    );
    drivers::serial::write_str(
        "================================================================================\r\n",
    );
    drivers::serial::write_str("\x1b[0m\r\n"); // Reset color

    // Output to framebuffer if available
    if let Some(fb_info) = state::get_framebuffer() {
        let mut console = FramebufferConsole::new(&fb_info);

        // Calculate center position
        let rows = console.rows();
        let center_row = rows / 2;

        // Set red foreground color
        let error_color = Color::new(255, 0, 0); // Bright red

        // Draw a border above the message
        console.set_colors(error_color, DEFAULT_BG);
        console.write_centered(center_row - 2, "========================================");

        // Draw the error message
        console.write_centered(center_row, ERROR_MESSAGE);

        // Draw a border below the message
        console.write_centered(center_row + 2, "========================================");

        console.reset_colors();
    }

    // Wait 3 seconds so the user can see the message
    time::delay_ms(3000);
}

/// Common boot tail: variable persistence, Secure Boot, and boot manager.
///
/// This is the shared sequence executed by both [`init_platform()`] and
/// [`init()`] after architecture/platform-specific initialization is done.
/// Extracting it eliminates ~40 lines of near-identical code between the
/// two entry points.
fn init_persistence_and_boot() -> ! {
    // ---- Variable persistence ----
    match efi::varstore::init_persistence() {
        Ok(()) => {
            log::info!("Variable store persistence initialized");

            let pending_count = efi::varstore::check_deferred_pending();
            if pending_count > 0 {
                log::info!(
                    "{} pending deferred writes from previous boot",
                    pending_count
                );
                match efi::varstore::process_deferred_pending() {
                    Ok(n) => log::info!("Applied {} deferred variable writes", n),
                    Err(e) => log::warn!("Failed to process deferred writes: {:?}", e),
                }
            }

            match efi::auth::boot::init_secure_boot_default() {
                Ok(status) => {
                    log::info!(
                        "Secure Boot: mode={}, enabled={}",
                        if status.setup_mode { "Setup" } else { "User" },
                        status.secure_boot_enabled
                    );
                }
                Err(e) => log::warn!("Secure Boot init failed: {:?}", e),
            }
        }
        Err(e) => log::info!("Variable persistence not available: {:?}", e),
    }

    efi::varstore::init_deferred_buffer();

    // ---- Boot manager ----
    let boot_var_state = boot_vars::read_boot_var_state();
    boot_manager::run(boot_var_state);

    log::info!("Boot manager finished — halting");

    loop {
        arch::halt();
    }
}

/// Initialize CrabEFI with a platform configuration.
///
/// This is the primary entry point for the CrabEFI library. External firmware
/// builds a [`PlatformConfig`] with platform-specific trait implementations
/// and calls this function to start the UEFI boot manager.
///
/// # Pre-initialized state
///
/// If the caller has already called [`state::init()`] before this function
/// (e.g., to store coreboot-specific data in [`state::DriverState`]), this
/// function detects the pre-initialized state and skips creating a new
/// [`state::FirmwareState`]. The caller's `FirmwareState` must live on a
/// stack frame that never returns (e.g., `rust_main() -> !`).
///
/// # Never returns
///
/// This function never returns (`-> !`). When a UEFI application calls
/// `ExitBootServices`, the OS takes control. If no boot device is found or
/// all boot attempts fail, CrabEFI halts the CPU.
///
/// Because `init_platform` never returns, all references in [`PlatformConfig`]
/// remain valid for the entire firmware lifetime. This allows CrabEFI to use
/// platform-provided drivers (e.g., `debug_output`) directly — no `'static`
/// bounds required at the call site.
///
/// # Example
///
/// ```ignore
/// let config = crabefi::PlatformConfig {
///     memory_map: &memory_regions,
///     timer: &my_timer,
///     reset: &my_reset,
///     block_devices: &mut [],
///     debug_output: Some(&mut my_uart),
///     // ...remaining fields..
/// };
/// crabefi::init_platform(config); // never returns
/// ```
pub fn init_platform(config: PlatformConfig) -> ! {
    if state::is_initialized() {
        // Caller pre-initialized state (e.g., coreboot payload storing
        // SMMSTORE/SPI/CBMEM info before calling us). Their FirmwareState
        // lives on a -> ! frame so it outlives us.
        init_platform_impl(config)
    } else {
        // Fresh start: allocate FirmwareState on this stack frame.
        init_with_local_state(config)
    }
}

/// Allocate a fresh [`state::FirmwareState`] on this stack frame and
/// delegate to [`init_platform_impl`].
///
/// Separated from [`init_platform`] so the ~2 MB `FirmwareState` is only
/// on the stack when the caller didn't pre-initialize.
#[inline(never)]
fn init_with_local_state(config: PlatformConfig) -> ! {
    let mut firmware_state = state::FirmwareState::new();
    // SAFETY: Single-threaded firmware entry point. The state lives on this
    // stack frame which never returns (-> !).
    unsafe {
        state::init(&mut firmware_state);
    }
    init_platform_impl(config)
}

/// Core initialization logic shared by all callers of [`init_platform`].
fn init_platform_impl(mut config: PlatformConfig) -> ! {
    // ---- 1. Install exception / interrupt vectors ----
    //
    // On aarch64: without this, VBAR_ELx defaults to 0x0 and any exception
    // during shim/GRUB execution would vector to address 0x0 (fstart's
    // _start), causing silent infinite loops instead of a diagnostic halt.
    //
    // On x86_64: install the IDT for exception handling.
    //
    // On riscv64: the stvec is set by the entry assembly. Nothing extra
    // needed here since the trap vector was already installed at entry.
    #[cfg(target_arch = "aarch64")]
    unsafe {
        arch::aarch64::exceptions::install_exception_vectors_auto();
    }
    #[cfg(target_arch = "x86_64")]
    arch::x86_64::idt::init();

    // ---- 2. Initialize serial output from platform debug_output ----
    //
    // Store the platform's DebugOutput in CrabEFI's serial subsystem so the
    // logger (a 'static global) can access it. This requires erasing the 'a
    // lifetime on the trait object reference.
    //
    // SAFETY: init_platform() is -> ! (never returns). The caller's stack
    // frame — where the DebugOutput lives — is never unwound, so the
    // reference remains valid for the entire firmware lifetime.
    //
    // We need to convert &'a mut dyn DebugOutput → *mut dyn DebugOutput
    // (erasing lifetime 'a). A plain `as` cast does not compile because
    // the borrow checker requires 'a: 'static for the coercion. The
    // transmute preserves the fat pointer (data + vtable) identically
    // and is sound because 'a is effectively 'static (-> !).
    if let Some(ref mut debug_out) = config.debug_output {
        let raw: *mut dyn crate::platform::DebugOutput = unsafe {
            core::mem::transmute::<
                &mut dyn crate::platform::DebugOutput,
                *mut dyn crate::platform::DebugOutput,
            >(*debug_out)
        };
        unsafe {
            drivers::serial::init_from_platform_raw(raw);
        }
    }

    // ---- 3. Initialize logging ----
    //
    // Idempotent: safe even if the caller already called logger::init()
    // for early debug output.
    logger::init();

    log::info!(
        "CrabEFI v{} starting (platform path)...",
        env!("CARGO_PKG_VERSION")
    );

    // ---- 4. Store ACPI RSDP in driver state ----
    if let Some(rsdp) = config.acpi_rsdp {
        state::with_drivers_mut(|d| d.platform.acpi_rsdp = Some(rsdp));
        log::info!("ACPI RSDP: {:#x}", rsdp);
    }

    // ---- 5. Parse FDT if provided ----
    //
    // Must happen before efi::init_from_platform() which uses fdt_info for
    // MMIO regions on aarch64 (GIC, PCIe windows, UART).
    if let Some(fdt_bytes) = config.fdt {
        let fdt_addr = fdt_bytes.as_ptr() as u64;
        let fdt_size = fdt_bytes.len() as u32;
        log::info!("FDT: {:#x} ({} bytes)", fdt_addr, fdt_size);

        if let Some(plat) = unsafe { fdt::parse(fdt_addr, fdt_size) } {
            log::info!(
                "FDT parsed: ECAM={:?}, GIC={:?}, UART={:?}",
                plat.ecam_base,
                plat.gicd,
                plat.uart_base
            );
            state::with_drivers_mut(|d| d.fdt_info = plat);
        }
    }

    // ---- 6. Initialize timing subsystem from platform timer ----
    //
    // In library mode the platform-provided Timer is the source of truth.
    // This works on any architecture (x86, aarch64, riscv64) without
    // architecture-specific hardware detection inside the library.
    time::init_from_platform(config.timer);

    // Print memory summary
    let total_ram: u64 = config
        .memory_map
        .iter()
        .filter(|r| r.region_type == MemoryType::Ram)
        .map(|r| r.size)
        .sum();
    log::info!("Total RAM: {} MB", total_ram / (1024 * 1024));

    // ---- 7. Initialize keyboard subsystem ----
    drivers::keyboard_common::init();

    // ---- 8. Initialize EFI environment ----
    //
    // Always runs — sets up the EFI memory map, system table, ACPI/SMBIOS
    // configuration tables, and runtime region reservations.  The page
    // allocator is idempotent: if the caller already bootstrapped it
    // (to get a heap before entry), re-initialization is skipped.
    efi::init_from_platform(&config);

    // Initialize mouse cursor system (ui feature only).
    // Must come after efi::init_from_platform(), which stores the framebuffer
    // in global state via state::store_framebuffer().
    #[cfg(feature = "ui")]
    if let Some(fb) = crate::state::get_framebuffer() {
        drivers::mouse_cursor::init(fb.width, fb.height);
    }

    log::info!("CrabEFI initialized successfully!");
    log::info!("EFI System Table at: {:p}", efi::get_system_table());

    // ---- 9. Initialize heap ----
    //
    // Skipped when the platform already set up the heap before entry
    // (heap_pre_initialized == true).  The rest of the init sequence is
    // identical regardless of this flag.
    if !config.heap_pre_initialized && !heap::init() {
        log::error!("Failed to initialize heap allocator!");
    }

    // ---- 10. Runtime log support ----
    #[cfg(feature = "rt-log")]
    {
        efi::rtlog::register_region();
        efi::rtlog::dump();
    }

    // ---- 11. Discover PCI ECAM and initialize PCI ----
    //
    // Priority: config.ecam_base > acpi_info.ecam_base > fdt_info.ecam_base.
    // acpi_info is populated by the platform before entry (when
    // heap_pre_initialized is true) or left empty for library consumers
    // that provide ecam_base directly.
    if let Some(ecam) = config.ecam_base {
        log::info!("PCI ECAM base from platform: {:#x}", ecam);
        drivers::pci::set_ecam_base(ecam);
    } else if let Some(ecam) = state::drivers().acpi_info.ecam_base {
        log::info!("PCI ECAM base from ACPI MCFG: {:#x}", ecam);
        drivers::pci::set_ecam_base(ecam);
    } else if let Some(ecam) = state::drivers().fdt_info.ecam_base {
        log::info!("PCI ECAM base from FDT: {:#x}", ecam);
        drivers::pci::set_ecam_base(ecam);
    }

    drivers::pci::init();

    // ---- 12. Register deferred variable buffer if provided ----
    if let Some(buf) = config.deferred_buffer {
        use efi::allocator::{MemoryType as AllocMemType, PAGE_SIZE};
        efi::varstore::deferred::configure_buffer_with_size(buf.base, buf.size);
        let buf_pages = (buf.size as u64).div_ceil(PAGE_SIZE);
        if let Err(e) =
            efi::allocator::force_add_region(buf.base, buf_pages, AllocMemType::RuntimeServicesData)
        {
            log::warn!(
                "Could not register deferred buffer at {:#x}: {:?}",
                buf.base,
                e
            );
        }
    } else {
        // No deferred buffer in config — use linker-symbol-based discovery.
        // The deferred module automatically uses the linker symbols for the
        // buffer location, so no explicit configure_buffer_with_size() needed.
        use efi::varstore::deferred;
        let buf_base = deferred::deferred_buffer_base();
        let buf_size = deferred::deferred_buffer_size();
        if buf_size > 0 {
            // When platform-entry is active, the deferred buffer lives inside
            // the linker's __runtime_data_start..__runtime_data_end range which
            // reserve_runtime_region() already carved as RuntimeServicesData.
            // Adding it again via force_add_region creates a duplicate,
            // overlapping memory map entry that confuses the Linux kernel's
            // efi_memattr_apply_permissions / efi_create_mapping and can leave
            // parts of the RuntimeServicesData region unmapped in efi_mm.
            #[cfg(not(feature = "platform-entry"))]
            {
                use efi::allocator::{MemoryType as AllocMemType, PAGE_SIZE};
                let buf_pages = (buf_size as u64).div_ceil(PAGE_SIZE);
                if let Err(e) = efi::allocator::force_add_region(
                    buf_base,
                    buf_pages,
                    AllocMemType::RuntimeServicesData,
                ) {
                    log::warn!(
                        "Could not register deferred buffer at {:#x}: {:?}",
                        buf_base,
                        e
                    );
                } else {
                    log::info!(
                        "Deferred buffer at {:#x} ({} pages) registered as RuntimeServicesData",
                        buf_base,
                        buf_pages
                    );
                }
            }

            #[cfg(feature = "platform-entry")]
            {
                use efi::allocator::PAGE_SIZE;
                log::info!(
                    "Deferred buffer at {:#x} ({} pages) already in runtime data region",
                    buf_base,
                    (buf_size as u64).div_ceil(PAGE_SIZE)
                );
            }
        }
    }

    // ---- 13. Register platform block devices ----
    if !config.block_devices.is_empty() {
        // SAFETY: init_platform() is -> !, so the block device references in
        // config.block_devices live forever.
        unsafe {
            drivers::storage::register_platform_block_devices(config.block_devices);
        }
    }

    // ---- 14. Runtime log init ----
    #[cfg(feature = "rt-log")]
    efi::rtlog::init();

    // ---- 15. Variable persistence, Secure Boot, and boot manager ----
    init_persistence_and_boot();
}

/// Store a device globally for SimpleFileSystem reads.
///
/// Each device type has its own `store_global_device()` with different parameters.
/// This dispatches to the right one based on the device type.
pub(crate) fn store_device_globally(device_type: &menu::DeviceType) -> bool {
    match *device_type {
        menu::DeviceType::Nvme {
            controller_id,
            nsid,
        } => drivers::nvme::store_global_device(controller_id, nsid),
        menu::DeviceType::Ahci {
            controller_id,
            port,
        } => drivers::ahci::store_global_device(controller_id, port),
        // USB devices are stored globally during enumeration, not here
        menu::DeviceType::Usb { .. } => true,
        menu::DeviceType::Sdhci { controller_id } => {
            drivers::sdhci::store_global_device(controller_id)
        }
        menu::DeviceType::Platform { .. } => true, // platform devices are always globally accessible
    }
}

/// Create a block device from a device type and call the provided closure with it.
///
/// This centralizes the per-device-type controller acquisition and disk creation
/// so that callers only need the generic `&mut dyn BlockDevice` interface.
///
/// # Returns
/// `Some(R)` if the device was created and the closure returned a value,
/// `None` if the device could not be created.
pub(crate) fn with_disk<R>(
    device_type: &menu::DeviceType,
    f: impl FnOnce(&mut dyn drivers::block::BlockDevice) -> R,
) -> Option<R> {
    match *device_type {
        menu::DeviceType::Nvme {
            controller_id,
            nsid,
        } => {
            let controller = unsafe { &mut *drivers::nvme::get_controller(controller_id)? };
            let mut disk = NvmeDisk::new(controller, nsid);
            Some(f(&mut disk))
        }
        menu::DeviceType::Ahci {
            controller_id,
            port,
        } => {
            let controller = unsafe { &mut *drivers::ahci::get_controller(controller_id)? };
            let mut disk = AhciDisk::new(controller, port);
            Some(f(&mut disk))
        }
        menu::DeviceType::Usb {
            controller_id,
            device_addr: _,
        } => {
            let controller_ptr = drivers::usb::get_controller_ptr(controller_id)?;
            let controller = unsafe { &mut *controller_ptr };
            let usb_device = drivers::usb::mass_storage::get_global_device()?;
            let mut disk = UsbDisk::new(usb_device, controller);
            Some(f(&mut disk))
        }
        menu::DeviceType::Sdhci { controller_id } => {
            let controller = unsafe { &mut *drivers::sdhci::get_controller(controller_id)? };
            let mut disk = SdhciDisk::new(controller);
            Some(f(&mut disk))
        }
        menu::DeviceType::Platform { index } => {
            drivers::storage::with_platform_block_device(index, |dev| {
                let mut shim = PlatformBlockShim(dev);
                f(&mut shim)
            })
        }
    }
}

/// Shim that adapts a [`platform::BlockDevice`] to the internal
/// [`drivers::block::BlockDevice`] trait used by the boot path.
struct PlatformBlockShim<'a>(&'a mut dyn platform::BlockDevice);

impl drivers::block::BlockDevice for PlatformBlockShim<'_> {
    fn info(&self) -> drivers::block::BlockDeviceInfo {
        let i = self.0.info();
        drivers::block::BlockDeviceInfo {
            num_blocks: i.num_blocks,
            block_size: i.block_size,
            media_id: 0,
            removable: false,
            read_only: false,
        }
    }

    fn read_blocks(
        &mut self,
        lba: u64,
        count: u32,
        buffer: &mut [u8],
    ) -> Result<(), drivers::block::BlockError> {
        // `BlockError` is #[non_exhaustive]; the `_` arm covers future variants.
        #[allow(unreachable_patterns)]
        self.0.read_blocks(lba, count, buffer).map_err(|e| match e {
            platform::BlockError::DeviceError => drivers::block::BlockError::DeviceError,
            platform::BlockError::InvalidParameter => drivers::block::BlockError::InvalidParameter,
            platform::BlockError::OutOfRange => drivers::block::BlockError::OutOfRange,
            platform::BlockError::NoMedia => drivers::block::BlockError::NoMedia,
            platform::BlockError::MediaChanged => drivers::block::BlockError::MediaChanged,
            _ => drivers::block::BlockError::DeviceError,
        })
    }
}

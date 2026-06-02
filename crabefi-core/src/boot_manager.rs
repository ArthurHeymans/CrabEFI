//! UEFI Boot Manager
//!
//! Implements the UEFI boot dispatch sequence (Specification Section 3.1):
//!
//! 1. Initialize storage subsystem (PCI drivers)
//! 2. **BootNext** — try the designated one-shot boot option
//! 3. **BootOrder** — iterate Boot#### entries in order
//! 4. **Fallback** — discover boot entries from ESPs, show interactive menu
//!
//! The individual boot paths (UEFI, direct Linux, payload chainload) are
//! dispatched from [`boot_selected_entry`].

use crate::boot_vars;
use crate::drivers;
use crate::efi;
use crate::menu;

/// Initialize storage subsystem (PCI drivers, USB keyboards, etc.)
///
/// This is called once before the boot manager starts trying boot options.
fn init_storage_subsystem() {
    log::info!("Initializing storage subsystem...");

    // Print PCI devices (already initialized earlier for SPI detection)
    drivers::pci::print_devices();

    // Bind PCI drivers to discovered devices (NVMe, AHCI, USB, SDHCI)
    // This uses the table-driven driver model instead of hardcoded init calls
    drivers::pci::bind_drivers();

    // Rescan UHCI/OHCI companion controller ports for devices that EHCI
    // released after the initial scan (ICH8/9/10 chipsets initialize UHCI
    // before EHCI due to PCI BDF ordering)
    drivers::usb::rescan_companion_ports();

    // Initialize USB keyboards (needs to happen after USB controllers are bound)
    drivers::usb::init_keyboards_public();

    // Initialize USB mice (needs to happen after USB controllers are bound)
    #[cfg(feature = "ui")]
    drivers::usb::init_mice();

    // Initialize pass-through protocols for TCG Opal support
    efi::protocols::pass_thru_init::init();

    log::info!("Storage subsystem initialized");
}

/// Run the UEFI boot manager.
///
/// Implements the boot dispatch sequence from UEFI Specification Section 3.1:
///
/// 1. Initialize storage subsystem (PCI drivers)
/// 2. **BootNext** — if set, delete it and try that Boot#### entry
/// 3. **BootOrder** — iterate Boot#### entries in order, try each active one
/// 4. **Fallback** — discover boot entries from ESPs (removable media path)
/// 5. Show interactive boot menu if nothing booted automatically
pub(crate) fn run(boot_var_state: boot_vars::BootVarState) {
    init_storage_subsystem();

    // Apply timeout from the Timeout variable (if set) to the boot menu default
    let timeout_seconds = boot_var_state.timeout.unwrap_or(5) as u32;

    // ---- Phase 1: BootNext ----
    if let Some(boot_next_num) = boot_var_state.boot_next {
        log::info!("=== BootNext: attempting Boot{:04X} ===", boot_next_num);

        // Delete BootNext BEFORE attempting boot (prevents infinite loops)
        boot_vars::delete_boot_next();

        if let Some(load_option) = boot_vars::read_boot_option(boot_next_num) {
            // Match edk2 (BdsLibBootNext): skip if not active or not boot category
            if !load_option.should_boot() {
                log::warn!(
                    "BootNext Boot{:04X}: skipped (active={}, category_boot={})",
                    boot_next_num,
                    load_option.is_active(),
                    load_option.is_boot_category()
                );
            } else if let Some(file_path) = boot_vars::extract_file_path(&load_option) {
                log::info!("BootNext: '{}' -> {}", load_option.description, file_path);
                let result = try_boot_load_option(&load_option, &file_path);
                if result == boot_vars::BootAttemptResult::Success {
                    log::info!("BootNext succeeded, returning to boot manager");
                    // edk2 would show BootManagerMenu here; we fall through to menu
                }
            } else {
                log::warn!(
                    "BootNext Boot{:04X}: no file path found in device path list",
                    boot_next_num
                );
            }
        } else {
            log::warn!("BootNext Boot{:04X}: variable not found", boot_next_num);
        }
    }

    // ---- Phase 2: BootOrder ----
    if !boot_var_state.boot_order.is_empty() {
        log::info!(
            "=== BootOrder: trying {} entries ===",
            boot_var_state.boot_order.len()
        );

        for &option_num in boot_var_state.boot_order.iter() {
            let Some(load_option) = boot_vars::read_boot_option(option_num) else {
                log::debug!("Boot{:04X}: not found, skipping", option_num);
                continue;
            };

            if !load_option.should_boot() {
                log::debug!(
                    "Boot{:04X}: skipped (active={}, category_boot={})",
                    option_num,
                    load_option.is_active(),
                    load_option.is_boot_category()
                );
                continue;
            }

            let Some(file_path) = boot_vars::extract_file_path(&load_option) else {
                log::debug!("Boot{:04X}: no file path, skipping", option_num);
                continue;
            };

            log::info!(
                "BootOrder: trying Boot{:04X} '{}' -> {}",
                option_num,
                load_option.description,
                file_path
            );

            let result = try_boot_load_option(&load_option, &file_path);
            match result {
                boot_vars::BootAttemptResult::Success => {
                    log::info!("Boot{:04X} succeeded", option_num);
                    // edk2 retries the whole loop if boot succeeded then returned;
                    // we fall through to the menu instead
                    break;
                }
                boot_vars::BootAttemptResult::Failed => {
                    log::warn!(
                        "Boot{:04X} '{}' failed, trying next",
                        option_num,
                        load_option.description
                    );
                }
                boot_vars::BootAttemptResult::Skipped => {}
            }
        }
    }

    // ---- Phase 3: Fallback to device discovery and interactive menu ----
    log::info!("=== Fallback: discovering boot entries from storage ===");

    let mut boot_menu = menu::discover_boot_entries();

    if boot_menu.entry_count() == 0 {
        log::warn!("No bootable media found!");

        #[cfg(feature = "ui")]
        crate::ui::show_no_media_screen();

        return;
    }

    // Apply Timeout variable to the menu
    boot_menu.set_timeout(timeout_seconds);

    log::debug!("Showing boot menu...");

    // Use graphical UI when feature is enabled, text menu otherwise
    #[cfg(feature = "ui")]
    let selected = crate::ui::show_graphical_menu(&mut boot_menu);
    #[cfg(not(feature = "ui"))]
    let selected = menu::show_menu(&mut boot_menu);
    log::info!("Menu returned: {:?}", selected);

    if let Some(selected_index) = selected {
        log::info!("Selected index: {}", selected_index);
        if let Some(entry) = boot_menu.get_entry(selected_index) {
            log::info!("Booting: {} from {}", entry.name, entry.path);
            log::info!("Entry kind: {:?}", entry.kind);
            log::info!("Device type: {:?}", entry.device_type);
            boot_selected_entry(entry);
            log::warn!("boot_selected_entry returned - boot failed!");
        } else {
            log::error!("Failed to get entry at index {}", selected_index);
        }
    } else {
        log::warn!("No entry selected from menu");
    }

    log::info!("Boot manager finished");
}

/// Attempt to boot a Boot#### load option.
///
/// This resolves the file path from the load option's device path list and
/// attempts to find and boot the referenced EFI application from discovered
/// storage devices. Sets BootCurrent before booting and clears it after.
///
/// Currently this matches the file path against ESPs found on storage devices.
/// Full device path matching (resolving the exact disk/partition from the
/// device path) is a future enhancement.
fn try_boot_load_option(
    load_option: &boot_vars::LoadOption,
    file_path: &str,
) -> boot_vars::BootAttemptResult {
    // Set BootCurrent before attempting boot
    boot_vars::set_boot_current(load_option.option_number);

    // Try to find this file on any discovered ESP
    let result = try_boot_file_from_esps(file_path);

    // Clear BootCurrent after boot returns
    boot_vars::clear_boot_current();

    result
}

/// Try to boot a specific file path from any discovered ESP.
///
/// Scans all storage devices, looks for ESPs, and tries to find and boot
/// the specified file. This is the fallback path when we don't have full
/// device path resolution yet.
fn try_boot_file_from_esps(file_path: &str) -> boot_vars::BootAttemptResult {
    // Convert forward slashes to backslashes for FAT
    let fat_path = if file_path.contains('/') {
        match crate::fs::linux_path_to_fat(file_path) {
            Ok(p) => p,
            Err(_) => {
                let mut p = heapless::String::<128>::new();
                if p.push_str(file_path).is_err() {
                    log::warn!("boot file path truncated ({} > 128 chars)", file_path.len());
                }
                p
            }
        }
    } else {
        let mut p = heapless::String::<128>::new();
        if p.push_str(file_path).is_err() {
            log::warn!("boot file path truncated ({} > 128 chars)", file_path.len());
        }
        p
    };

    // Try NVMe devices
    if try_boot_file_on_nvme(&fat_path) {
        return boot_vars::BootAttemptResult::Success;
    }

    // Try AHCI devices
    if try_boot_file_on_ahci(&fat_path) {
        return boot_vars::BootAttemptResult::Success;
    }

    // Try USB devices
    if try_boot_file_on_usb(&fat_path) {
        return boot_vars::BootAttemptResult::Success;
    }

    // Try SDHCI devices
    if try_boot_file_on_sdhci(&fat_path) {
        return boot_vars::BootAttemptResult::Success;
    }

    boot_vars::BootAttemptResult::Failed
}

/// Try to boot a file from NVMe ESPs
fn try_boot_file_on_nvme(file_path: &str) -> bool {
    use crate::drivers::nvme;

    for controller_id in 0.. {
        let Some(controller_ptr) = nvme::get_controller(controller_id) else {
            break;
        };
        let controller = unsafe { &mut *controller_ptr };
        let Some(ns) = controller.default_namespace() else {
            continue;
        };
        let nsid = ns.nsid;
        let pci_addr = controller.pci_address();

        if !nvme::store_global_device(controller_id, nsid) {
            continue;
        }

        let device_type = menu::DeviceType::Nvme {
            controller_id,
            nsid,
        };

        if try_boot_file_on_device(&device_type, pci_addr.device, pci_addr.function, file_path) {
            return true;
        }
    }
    false
}

/// Try to boot a file from AHCI ESPs
fn try_boot_file_on_ahci(file_path: &str) -> bool {
    use crate::drivers::ahci;

    for controller_id in 0.. {
        let Some(controller_ptr) = ahci::get_controller(controller_id) else {
            break;
        };
        let controller = unsafe { &mut *controller_ptr };
        let pci_addr = controller.pci_address();
        let num_ports = controller.num_active_ports();

        for port_index in 0..num_ports {
            if !ahci::store_global_device(controller_id, port_index) {
                continue;
            }
            let device_type = menu::DeviceType::Ahci {
                controller_id,
                port: port_index,
            };
            if try_boot_file_on_device(&device_type, pci_addr.device, pci_addr.function, file_path)
            {
                return true;
            }
        }
    }
    false
}

/// Try to boot a file from USB ESPs
fn try_boot_file_on_usb(file_path: &str) -> bool {
    use crate::drivers::usb::{self, UsbMassStorage, mass_storage};

    let Some((controller_id, device_addr)) = usb::find_mass_storage() else {
        return false;
    };
    let Some(controller_ptr) = usb::get_controller_ptr(controller_id) else {
        return false;
    };

    let device_created =
        usb::with_controller(controller_id, |controller| {
            match UsbMassStorage::new(controller, device_addr) {
                Ok(usb_device) => {
                    if usb_device.num_blocks == 0 {
                        return false;
                    }
                    unsafe {
                        mass_storage::store_global_device_with_controller_ptr(
                            usb_device,
                            controller_ptr,
                        )
                    }
                }
                Err(_) => false,
            }
        });

    if device_created != Some(true) {
        return false;
    }

    let device_type = menu::DeviceType::Usb {
        controller_id,
        device_addr,
    };
    try_boot_file_on_device(&device_type, 0, 0, file_path)
}

/// Try to boot a file from SDHCI ESPs
fn try_boot_file_on_sdhci(file_path: &str) -> bool {
    use crate::drivers::sdhci;

    for controller_id in 0..sdhci::controller_count() {
        let Some(controller_ptr) = sdhci::get_controller(controller_id) else {
            continue;
        };
        let controller = unsafe { &mut *controller_ptr };
        if !controller.is_ready() {
            continue;
        }
        let pci_addr = controller.pci_address();

        if !sdhci::store_global_device(controller_id) {
            continue;
        }

        let device_type = menu::DeviceType::Sdhci { controller_id };
        if try_boot_file_on_device(&device_type, pci_addr.device, pci_addr.function, file_path) {
            return true;
        }
    }
    false
}

/// Try to boot a specific file from ESPs on a given device.
///
/// Reads GPT/MBR partitions, finds ESP partitions, mounts FAT, checks if the file exists,
/// and if so, boots it through the standard UEFI boot path.
fn try_boot_file_on_device(
    device_type: &menu::DeviceType,
    pci_device: u8,
    pci_function: u8,
    file_path: &str,
) -> bool {
    use crate::fs::{fat::FatFilesystem, gpt};

    // Read GPT/MBR partitions
    let partitions =
        crate::with_disk(device_type, |disk| gpt::read_partitions_auto(disk).ok()).flatten();

    let partitions = match partitions {
        Some(p) => p,
        None => return false,
    };

    // Look for ESPs containing the target file
    for (i, partition) in partitions.iter().enumerate() {
        if !partition.is_esp {
            continue;
        }

        let partition_num = (i + 1) as u32;

        // Try to mount FAT and check for the file
        let found = crate::with_disk(device_type, |disk| {
            if let Ok(mut fat) = FatFilesystem::new(disk, partition.first_lba) {
                fat.file_size(file_path).is_ok()
            } else {
                false
            }
        })
        .unwrap_or(false);

        if !found {
            continue;
        }

        log::info!(
            "Found '{}' on {} partition {}",
            file_path,
            device_type.description(),
            partition_num
        );

        // Build a synthetic BootEntry and boot it through the standard path
        let entry = menu::BootEntry::new(
            file_path,
            file_path,
            *device_type,
            partition_num,
            partition.clone(),
            pci_device,
            pci_function,
        );

        boot_uefi_entry(&entry);

        // If boot_uefi_entry returned, the boot failed
        return false;
    }

    false
}

/// Boot a selected menu entry
///
/// Dispatches to the appropriate boot method based on the entry kind:
/// - UEFI/UKI entries: Load and execute EFI application
/// - BLS/GRUB Linux entries: Direct Linux boot via linux_boot module
/// - Payload entries: Chainload coreboot payload
fn boot_selected_entry(entry: &menu::BootEntry) {
    log::info!("boot_selected_entry called");

    // First, dispatch based on entry kind
    match &entry.kind {
        // UEFI entries use the existing EFI boot path
        menu::BootEntryKind::Uefi | menu::BootEntryKind::BlsUki => {
            log::info!("Dispatching to UEFI boot path");
            boot_uefi_entry(entry);
        }

        // Direct Linux boot entries (BLS Type #1 or GRUB)
        menu::BootEntryKind::BlsLinux {
            linux_path,
            initrd_path,
            cmdline,
        }
        | menu::BootEntryKind::GrubLinux {
            linux_path,
            initrd_path,
            cmdline,
        } => {
            #[cfg(target_arch = "x86_64")]
            {
                log::info!("Dispatching to direct Linux boot");
                boot_linux_entry(entry, linux_path, initrd_path, cmdline);
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                let _ = (linux_path, initrd_path, cmdline);
                log::warn!("Direct Linux boot not supported on this architecture");
            }
        }

        // Coreboot payload chainloading
        menu::BootEntryKind::Payload { path, format } => {
            log::info!("Dispatching to payload chainload");
            boot_payload_entry(entry, path, *format);
        }
    }
}

/// Boot a UEFI entry (EFI application or UKI)
///
/// Uses the unified boot module to handle all storage types generically.
/// Device-specific logic is encapsulated in `crate::store_device_globally()` and
/// `crate::with_disk()`, keeping this function device-agnostic.
fn boot_uefi_entry(entry: &menu::BootEntry) {
    use crate::boot;
    use crate::drivers::storage;

    let path_info = boot::device_path_info_from_entry(entry);

    // Phase 1: Store device globally and install BlockIO protocols
    if !crate::store_device_globally(&entry.device_type) {
        log::error!("Failed to store device globally");
        return;
    }

    let phase1_ok = crate::with_disk(&entry.device_type, |disk| {
        let info = disk.info();
        let storage_id =
            match storage::register_device(entry.device_type, info.num_blocks, info.block_size) {
                Some(id) => id,
                None => {
                    log::error!("Failed to register device");
                    return false;
                }
            };
        let _ = boot::install_block_io_protocols(
            disk,
            storage_id,
            info.block_size,
            info.num_blocks,
            &path_info,
        );
        true
    });

    if phase1_ok != Some(true) {
        log::error!("Failed to create disk for BlockIO installation");
        return;
    }

    // Phase 2: Re-create disk for ESP boot (previous borrows ended)
    let booted = crate::with_disk(&entry.device_type, |disk| {
        let info = disk.info();
        boot::try_boot_from_esp(
            disk,
            &entry.partition,
            entry.partition_num,
            &path_info,
            &entry.device_type,
            info.num_blocks,
            info.block_size,
        )
    });

    if booted == Some(true) {
        return;
    }
    log::error!("Failed to boot UEFI entry");
}

/// Boot Linux from a block device (shared logic for all device types)
///
/// Loads the kernel, optional initrd, and command line from a FAT partition
/// on the given block device, then boots Linux directly.
///
/// This is x86-only as it uses the bzImage/x86 boot protocol.
/// On aarch64, Linux boot uses a different protocol (not yet implemented).
#[cfg(target_arch = "x86_64")]
fn boot_linux_from_device(
    disk: &mut dyn crate::drivers::block::BlockDevice,
    partition_first_lba: u64,
    kernel_path: &str,
    initrd_fat_path: Option<&str>,
    cmdline: &str,
    memory_regions: &[crate::platform::MemoryRegion],
    acpi_rsdp: Option<u64>,
    framebuffer: Option<&crate::platform::FramebufferConfig>,
) -> bool {
    match crate::linux_boot::load_linux_from_disk(
        disk,
        partition_first_lba,
        kernel_path,
        initrd_fat_path,
        cmdline,
        memory_regions,
        acpi_rsdp,
        framebuffer,
        false, // Don't use EFI handover for direct boot
    ) {
        Ok(mut loaded) => {
            log::info!("Linux loaded successfully, booting...");
            unsafe {
                loaded.boot_direct();
            }
        }
        Err(e) => {
            log::error!("Failed to load Linux: {:?}", e);
            false
        }
    }
}

/// Boot a direct Linux entry (BLS Type #1 or GRUB)
///
/// This uses the linux_boot module to load and boot the kernel directly,
/// bypassing UEFI bootloaders like GRUB or systemd-boot.
///
/// x86-only: uses bzImage boot protocol.
#[cfg(target_arch = "x86_64")]
fn boot_linux_entry(
    entry: &menu::BootEntry,
    linux_path: &heapless::String<128>,
    initrd_path: &heapless::String<128>,
    cmdline: &heapless::String<512>,
) {
    use crate::fs;
    use crate::state;

    // Defense in depth: Direct Linux boot entries should not appear in the menu
    // when Secure Boot is active (filtered in scan_partition_for_entries), but
    // check here as well in case an entry somehow makes it through.
    // Direct boot bypasses signature verification which violates Secure Boot.
    if efi::auth::is_secure_boot_enabled() {
        log::warn!("Direct Linux boot disabled: Secure Boot is active");
        log::info!("Falling back to UEFI boot path for secure verification");
        // Fall back to UEFI boot which will verify the bootloader signature
        boot_uefi_entry(entry);
        return;
    }

    log::info!("Direct Linux boot: {}", entry.name);
    log::info!("  Kernel: {}", linux_path);
    if !initrd_path.is_empty() {
        log::info!("  Initrd: {}", initrd_path);
    }
    log::info!("  Cmdline: {}", cmdline);

    // Convert Linux-style paths (forward slashes) to FAT-style paths (backslashes)
    let kernel_path = match fs::linux_path_to_fat(linux_path) {
        Ok(p) => p,
        Err(e) => {
            log::error!("Invalid kernel path '{}': {:?}", linux_path, e);
            return;
        }
    };
    let initrd_fat_path = if !initrd_path.is_empty() {
        match fs::linux_path_to_fat(initrd_path) {
            Ok(p) => Some(p),
            Err(e) => {
                log::error!("Invalid initrd path '{}': {:?}", initrd_path, e);
                return;
            }
        }
    } else {
        None
    };

    log::debug!("FAT kernel path: {}", kernel_path);
    if let Some(ref p) = initrd_fat_path {
        log::debug!("FAT initrd path: {}", p);
    }

    // Get memory regions and ACPI RSDP from state
    let (memory_regions, acpi_rsdp) = {
        let state = state::get();
        // Copy memory regions to a local buffer (we can't borrow across the disk operations)
        let mut regions = heapless::Vec::<crate::platform::MemoryRegion, 64>::new();
        for region in state.drivers.platform.memory_regions.iter() {
            let _ = regions.push(*region);
        }
        (regions, state.drivers.platform.acpi_rsdp)
    };

    // Get framebuffer info for Linux console
    let framebuffer = crate::state::get_framebuffer();

    if memory_regions.is_empty() {
        log::error!("No memory regions available for Linux boot");
        return;
    }

    log::debug!(
        "Memory regions: {}, ACPI RSDP: {:?}, Framebuffer: {}",
        memory_regions.len(),
        acpi_rsdp,
        if framebuffer.is_some() { "yes" } else { "no" }
    );

    // Store device globally for SimpleFileSystem reads, then create a disk
    // and delegate to boot_linux_from_device for the shared load+boot logic.
    if !crate::store_device_globally(&entry.device_type) {
        log::error!("Failed to store device globally");
        return;
    }

    if crate::with_disk(&entry.device_type, |disk| {
        boot_linux_from_device(
            disk,
            entry.partition.first_lba,
            &kernel_path,
            initrd_fat_path.as_deref(),
            cmdline,
            &memory_regions,
            acpi_rsdp,
            framebuffer.as_ref(),
        );
    })
    .is_none()
    {
        log::error!("Failed to create disk for Linux boot");
    }

    // Note: We intentionally don't fall back to UEFI boot here.
    // If the user selected a direct Linux boot entry, they want Linux,
    // not a UEFI bootloader. If it fails, show an error and return to menu.
    log::error!("Direct Linux boot failed - returning to menu");
}

/// Boot a coreboot payload entry
///
/// This uses the payload module to load and chainload another coreboot payload.
fn boot_payload_entry(
    entry: &menu::BootEntry,
    path: &heapless::String<128>,
    format: crate::payload::PayloadFormat,
) {
    log::info!("Chainloading payload: {}", entry.name);
    log::info!("  Path: {}", path);
    log::info!("  Format: {:?}", format);

    // TODO: Implement full payload chainloading
    // This requires:
    // 1. Mount FAT filesystem on the partition
    // 2. Create PayloadEntry from the menu entry
    // 3. Call payload::chainload_payload()
    //
    // For now, log the attempt and return
    log::warn!("Payload chainloading not yet fully implemented");
}

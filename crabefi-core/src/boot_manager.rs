//! UEFI Boot Manager
//!
//! Implements the UEFI boot dispatch sequence (Specification Section 3.1):
//!
//! 1. Initialize storage subsystem (PCI drivers)
//! 2. Honor a consumed firmware-UI request, bypassing automatic boot
//! 3. **BootNext** — try the designated one-shot boot option
//! 4. **BootOrder** — iterate Boot#### entries in order
//! 5. **Fallback** — discover boot entries from ESPs, show interactive menu
//!
//! The individual boot paths (UEFI, direct Linux, payload chainload) are
//! dispatched from [`boot_selected_entry`].

use crate::boot_vars;
use crate::drivers;
use crate::efi;
use crate::menu;
use crate::timestamp;

/// Initialize storage subsystem (PCI drivers, USB keyboards, etc.)
///
/// Called once before firmware-UI capability checks and boot dispatch, so USB
/// input is enumerated before an indefinite setup session can be accepted.
pub(crate) fn init_storage_subsystem() {
    log::info!("Initializing storage subsystem...");
    timestamp::record(timestamp::TS_CRABEFI_STORAGE_INIT_START);

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
    timestamp::record(timestamp::TS_CRABEFI_STORAGE_INIT_DONE);
}

/// Keep ordinary headless boot bounded. An explicit setup request has already
/// been gated on an interactive console and must never autoboot.
fn menu_configuration(
    ui: bool,
    framebuffer: bool,
    timeout: u32,
    firmware_ui_requested: bool,
) -> (bool, u32) {
    let timeout = if firmware_ui_requested {
        0
    } else if !framebuffer && timeout == 0 {
        5
    } else {
        timeout
    };
    (ui && framebuffer, timeout)
}

/// Run the UEFI boot manager.
///
/// Implements the boot dispatch sequence from UEFI Specification Section 3.1:
///
/// 1. Initialize storage subsystem (PCI drivers)
/// 2. On an explicit firmware-UI request, skip directly to an indefinite menu
/// 3. **BootNext** — if set, delete it and try that Boot#### entry
/// 4. **BootOrder** — iterate Boot#### entries in order, try each active one
/// 5. **Fallback** — discover boot entries from ESPs (removable media path)
/// 6. Show interactive boot menu if nothing booted automatically
pub(crate) fn run(boot_var_state: boot_vars::BootVarState, firmware_ui_requested: bool) {
    // Apply timeout from the Timeout variable (if set) to the boot menu default
    let timeout_seconds = boot_var_state.timeout.unwrap_or(5) as u32;

    if !firmware_ui_requested {
        try_automatic_boot(&boot_var_state);
    }

    show_boot_menu(timeout_seconds, firmware_ui_requested);
}

/// Automatic boot is deliberately separate: setup must not even delete BootNext.
fn try_automatic_boot(boot_var_state: &boot_vars::BootVarState) {
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
}

/// Discover boot entries and show setup indefinitely only on an explicit request.
fn show_boot_menu(timeout_seconds: u32, firmware_ui_requested: bool) {
    // ---- Phase 3: Fallback to device discovery and interactive menu ----
    log::info!("=== Fallback: discovering boot entries from storage ===");

    let mut boot_menu = menu::discover_boot_entries();

    if boot_menu.entry_count() == 0 && !firmware_ui_requested {
        log::warn!("No bootable media found!");

        #[cfg(feature = "ui")]
        crate::ui::show_no_media_screen();

        return;
    }

    let (graphical, timeout_seconds) = menu_configuration(
        cfg!(feature = "ui"),
        crate::handoff::framebuffer().is_some(),
        timeout_seconds,
        firmware_ui_requested,
    );
    boot_menu.set_timeout(timeout_seconds);

    log::info!(
        "Showing {}boot menu (autoboot timeout: {}s)",
        if firmware_ui_requested {
            "firmware UI: "
        } else {
            ""
        },
        boot_menu.timeout_seconds
    );
    if firmware_ui_requested && boot_menu.entry_count() == 0 {
        #[cfg(feature = "ui")]
        if graphical {
            crate::ui::show_no_media_screen();
            return;
        }
        // The text menu also exposes firmware/security settings without media.
    }

    log::debug!("Showing boot menu..."); // Also used by the screenshot harness.

    // The graphical menu requires a framebuffer; the text menu also works
    // headlessly and will boot the selected entry when its timeout expires.
    #[cfg(feature = "ui")]
    let selected = if graphical {
        crate::ui::show_graphical_menu(&mut boot_menu)
    } else {
        menu::show_menu(&mut boot_menu)
    };
    #[cfg(not(feature = "ui"))]
    let selected = {
        let _ = graphical;
        menu::show_menu(&mut boot_menu)
    };
    log::info!("Menu returned: {:?}", selected);

    if let Some(selected_index) = selected {
        log::info!("Selected index: {}", selected_index);
        // Boot a clone so a one-shot command-line edit applies to this
        // attempt only and never sticks to the menu's entry.
        if let Some(entry) = boot_menu.entry_for_boot(selected_index) {
            log::info!("Booting: {} from {}", entry.name, entry.path);
            log::info!("Entry kind: {:?}", entry.kind);
            log::info!("Storage: {:?}", entry.storage);
            boot_selected_entry(&entry);
            log::warn!("boot_selected_entry returned - boot failed!");
        } else {
            log::error!("Failed to get entry at index {}", selected_index);
        }
    } else {
        log::warn!("No entry selected from menu");
    }

    log::info!("Boot manager finished");
}

#[cfg(test)]
mod menu_configuration_tests {
    use super::menu_configuration;

    #[test]
    fn graphical_menu_requires_a_framebuffer() {
        assert_eq!(menu_configuration(true, true, 0, false), (true, 0));
        assert_eq!(menu_configuration(true, false, 7, false), (false, 7));
        assert_eq!(menu_configuration(false, true, 0, false), (false, 0));
    }

    #[test]
    fn explicit_setup_never_autoboots() {
        for ui in [false, true] {
            for framebuffer in [false, true] {
                for timeout in [0, 2, 5, 65535] {
                    assert_eq!(
                        menu_configuration(ui, framebuffer, timeout, true),
                        (ui && framebuffer, 0)
                    );
                }
            }
        }
    }

    #[test]
    fn ordinary_headless_menu_never_waits_indefinitely() {
        assert_eq!(menu_configuration(true, false, 0, false), (false, 5));
        assert_eq!(menu_configuration(false, false, 0, false), (false, 5));
        assert_eq!(menu_configuration(true, false, 12, false), (false, 12));
    }
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

    if crate::drivers::storage::devices()
        .iter()
        .any(|device| try_boot_file_on_device(device, &fat_path))
    {
        return boot_vars::BootAttemptResult::Success;
    }

    boot_vars::BootAttemptResult::Failed
}

/// Try to boot a specific file from ESPs on a given device.
///
/// Reads GPT/MBR partitions, finds ESP partitions, mounts FAT, checks if the file exists,
/// and if so, boots it through the standard UEFI boot path.
fn try_boot_file_on_device(
    device: &crate::drivers::storage::StorageDevice,
    file_path: &str,
) -> bool {
    use crate::drivers::storage;
    use crate::fs::{fat::FatFilesystem, gpt};

    // Read GPT/MBR partitions
    let Some(partitions) =
        storage::with_disk(device.id, |disk| gpt::read_partitions_auto(disk).ok())
            .ok()
            .flatten()
    else {
        return false;
    };

    // Look for ESPs containing the target file
    for (i, partition) in partitions.iter().enumerate() {
        if !partition.is_esp {
            continue;
        }

        let partition_num = (i + 1) as u32;

        // Try to mount FAT and check for the file
        let found = storage::with_disk(device.id, |disk| {
            FatFilesystem::new(disk, partition.first_lba)
                .is_ok_and(|mut fat| fat.file_size(file_path).is_ok())
        })
        .unwrap_or(false);

        if !found {
            continue;
        }

        log::info!(
            "Found '{}' on {} partition {}",
            file_path,
            device.id.description(),
            partition_num
        );

        // Build a synthetic BootEntry and boot it through the standard path
        let entry = menu::BootEntry::new(
            file_path,
            file_path,
            device,
            partition_num,
            partition.clone(),
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
            initrd_paths,
            cmdline,
        }
        | menu::BootEntryKind::GrubLinux {
            linux_path,
            initrd_paths,
            cmdline,
        } => {
            #[cfg(target_arch = "x86_64")]
            {
                log::info!("Dispatching to direct Linux boot");
                boot_linux_entry(entry, linux_path, initrd_paths, cmdline);
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                let _ = (linux_path, initrd_paths, cmdline);
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
/// Installs BlockIO protocols for the entry's disk, then boots from its ESP
/// through the storage-agnostic boot module.
fn boot_uefi_entry(entry: &menu::BootEntry) {
    use crate::boot;
    use crate::drivers::storage;

    let path_info = boot::device_path_info_from_entry(entry);

    let info = match storage::with_disk(entry.storage, |disk| disk.info()) {
        Ok(info) => info,
        Err(error) => {
            log::error!("Failed to access {:?}: {}", entry.storage, error);
            return;
        }
    };
    boot::install_block_io_protocols(entry.storage, info, &path_info);

    if boot::try_boot_path_from_esp(
        &entry.partition,
        entry.partition_num,
        &path_info,
        entry.storage,
        info.block_size,
        &entry.path,
    ) {
        return;
    }
    log::error!("Failed to boot UEFI entry");
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
    initrd_paths: &crate::bls::Initrds,
    cmdline: &heapless::String<512>,
) {
    use crate::fs;

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
    for initrd_path in initrd_paths {
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
    let mut initrd_fat_paths: crate::bls::Initrds = heapless::Vec::new();
    for initrd_path in initrd_paths {
        match fs::linux_path_to_fat(initrd_path) {
            Ok(p) => {
                let _ = initrd_fat_paths.push(p);
            }
            Err(e) => {
                log::error!("Invalid initrd path '{}': {:?}", initrd_path, e);
                return;
            }
        }
    }

    log::debug!("FAT kernel path: {}", kernel_path);
    for p in &initrd_fat_paths {
        log::debug!("FAT initrd path: {}", p);
    }

    let acpi_rsdp = crate::handoff::get().acpi_rsdp;
    let framebuffer = crate::handoff::framebuffer();

    log::debug!(
        "ACPI RSDP: {:?}, Framebuffer: {}",
        acpi_rsdp,
        if framebuffer.is_some() { "yes" } else { "no" }
    );

    let loaded = crate::drivers::storage::with_disk(entry.storage, |disk| {
        crate::linux_boot::load_linux_from_disk(
            disk,
            entry.partition.first_lba,
            &kernel_path,
            &initrd_fat_paths
                .iter()
                .map(|p| p.as_str())
                .collect::<heapless::Vec<&str, { crate::bls::MAX_INITRDS }>>(),
            cmdline,
            acpi_rsdp,
            framebuffer.as_ref(),
            false, // Don't use EFI handover for direct boot
        )
    });

    match loaded {
        Ok(Ok(mut loaded)) => {
            // The disk/controller borrow must be released before shutdown:
            // direct boot quiesces every firmware-owned DMA engine.
            log::info!("Linux loaded successfully, booting...");
            unsafe {
                loaded.boot_direct();
            }
        }
        Ok(Err(e)) => log::error!("Failed to load Linux: {:?}", e),
        Err(e) => log::error!("Failed to access disk for Linux boot: {}", e),
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

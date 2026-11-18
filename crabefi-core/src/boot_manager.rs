//! UEFI Boot Manager
//!
//! Implements the UEFI boot dispatch sequence (Specification Section 3.1):
//!
//! 1. Initialize storage subsystem (PCI drivers; USB possibly on demand)
//! 2. Honor a consumed firmware-UI request, bypassing automatic boot
//! 3. **BootNext** — try the designated one-shot boot option
//! 4. **BootOrder** — iterate Boot#### entries in order
//! 5. **Fallback** — discover boot entries from ESPs, show interactive menu
//!
//! The individual boot paths (UEFI, direct Linux, payload chainload) are
//! dispatched from [`boot_selected_entry`].

use crate::boot_policy;
use crate::boot_vars;
use crate::cell::LocalCell;
use crate::drivers;
use crate::drivers::pci::PciDevice;
use crate::drivers::storage::{StorageDevice, StorageId};
use crate::efi;
use crate::menu;
use crate::timestamp;

/// Set once USB host controllers have been bound.
static USB_READY: LocalCell<bool> = LocalCell::new(false);

/// Initialize storage subsystem (PCI drivers, USB keyboards, etc.)
///
/// Called once before firmware-UI capability checks and boot dispatch, so USB
/// input is enumerated before an indefinite setup session can be accepted.
/// Without `with_usb`, USB controllers stay untouched until [`ensure_usb`].
pub(crate) fn init_storage_subsystem(with_usb: bool) {
    log::info!("Initializing storage subsystem...");
    timestamp::record(timestamp::TS_CRABEFI_STORAGE_INIT_START);

    // Print PCI devices (already initialized earlier for SPI detection)
    drivers::pci::print_devices();

    // Bind PCI drivers to discovered devices (NVMe, AHCI, USB, SDHCI)
    // This uses the table-driven driver model instead of hardcoded init calls
    drivers::pci::bind_drivers(|device| with_usb || !device.is_usb_controller());
    if with_usb {
        USB_READY.set(true);
        init_usb_devices();
    } else {
        log::info!("USB: initialization deferred");
    }

    // Initialize pass-through protocols for TCG Opal support
    efi::protocols::pass_thru_init::init();

    log::info!("Storage subsystem initialized");
    timestamp::record(timestamp::TS_CRABEFI_STORAGE_INIT_DONE);
}

/// Enumerate input devices behind freshly bound USB controllers.
fn init_usb_devices() {
    // Rescan UHCI/OHCI companion controller ports for devices that EHCI
    // released after the initial scan (ICH8/9/10 chipsets initialize UHCI
    // before EHCI due to PCI BDF ordering)
    drivers::usb::rescan_companion_ports();

    // Initialize USB keyboards (needs to happen after USB controllers are bound)
    drivers::usb::init_keyboards_public();

    // Initialize USB mice (needs to happen after USB controllers are bound)
    #[cfg(feature = "ui")]
    drivers::usb::init_mice();
}

/// Whether USB controllers have been bound.
pub(crate) fn usb_ready() -> bool {
    USB_READY.get()
}

/// Whether deferred USB controllers could still provide input devices.
pub(crate) fn usb_deferred() -> bool {
    !usb_ready()
        && drivers::pci::with_devices(|devices| devices.iter().any(PciDevice::is_usb_controller))
}

/// Bring up USB controllers, keyboards and mass storage on first need.
pub(crate) fn ensure_usb(reason: &str) {
    if usb_ready() {
        return;
    }
    USB_READY.set(true);
    log::info!("USB: initializing on demand ({})", reason);
    drivers::pci::bind_drivers(PciDevice::is_usb_controller);
    init_usb_devices();
    efi::protocols::pass_thru_init::init_usb_pass_thru();
}

/// Variables that make shim start MokManager, which needs a keyboard.
const SHIM_MOK_REQUESTS: [&str; 10] = [
    "MokNew",
    "MokDel",
    "MokSB",
    "MokPW",
    "MokAuth",
    "MokDB",
    "MokXNew",
    "MokXDel",
    "MokXAuth",
    "MokListTrustedNew",
];

/// Whether shim will start MokManager on this boot.
fn shim_mok_request_pending() -> bool {
    use crate::efi::runtime_image::client::variables;

    let shim_lock = r_efi::efi::Guid::from_fields(
        0x605dab50,
        0xe046,
        0x4300,
        0xab,
        0xb6,
        &[0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23],
    );
    SHIM_MOK_REQUESTS.iter().any(|name| {
        let name: alloc::vec::Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
        variables::get(&shim_lock, &name).is_some()
    })
}

/// Devices an automatic boot pass may start an image from.
#[derive(Clone, Copy)]
enum Scope {
    /// Every device found so far.
    Available,
    /// Only USB devices, after on-demand USB initialization.
    Usb,
}

impl Scope {
    fn includes(self, device: &StorageDevice) -> bool {
        let in_scope = match self {
            Scope::Available => true,
            Scope::Usb => matches!(device.id, StorageId::Usb { .. }),
        };
        in_scope && boot_policy::automatic_boot_allowed(device)
    }
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
        if !usb_ready() && shim_mok_request_pending() {
            ensure_usb("shim MokManager request pending");
        }
        try_automatic_boot(&boot_var_state);
    }

    // The menu and the removable-media path need USB keyboards and disks.
    ensure_usb(if firmware_ui_requested {
        "firmware UI requested"
    } else {
        "no boot option started"
    });
    show_boot_menu(timeout_seconds, firmware_ui_requested);
}

/// Automatic boot is deliberately separate: setup must not even delete BootNext.
///
/// With USB deferred, each option is first looked for on the other devices;
/// one that none of them holds brings USB up and is retried there before the
/// next option.
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
                let result = try_boot_option_resolving_usb(&load_option, &file_path);
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
    if boot_var_state.boot_order.is_empty() {
        return;
    }
    log::info!(
        "=== BootOrder: trying {} entries ===",
        boot_var_state.boot_order.len()
    );
    try_boot_order(boot_var_state);
}

/// Try a load option on the devices that are up. With USB deferred, an
/// option that none of them holds brings USB up and is retried there before
/// the next option, so BootOrder keeps its priority.
fn try_boot_option_resolving_usb(
    load_option: &boot_vars::LoadOption,
    file_path: &str,
) -> boot_vars::BootAttemptResult {
    let result = try_boot_load_option(load_option, file_path, Scope::Available);
    // A file-only option may be on any device, so look on USB unless it
    // started. One bound to a partition only if that partition was not found.
    let unbound = boot_vars::partition_target(load_option) == boot_vars::PartitionTarget::Any;
    let look_on_usb = match result {
        boot_vars::BootAttemptResult::Success | boot_vars::BootAttemptResult::Skipped => false,
        boot_vars::BootAttemptResult::Failed => unbound,
        boot_vars::BootAttemptResult::NotFound => true,
    };
    if !look_on_usb || usb_ready() {
        return result;
    }
    if !boot_policy::automatic_external_allowed() {
        log::info!(
            "Boot policy: not looking for Boot{:04X} on USB",
            load_option.option_number
        );
        return result;
    }
    ensure_usb("a boot option did not start without USB");
    log::info!("Boot{:04X}: retrying on USB", load_option.option_number);
    try_boot_load_option(load_option, file_path, Scope::Usb)
}

/// Try each active BootOrder option in order.
///
/// Returns whether an image started (and returned).
fn try_boot_order(boot_var_state: &boot_vars::BootVarState) -> bool {
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

        let result = try_boot_option_resolving_usb(&load_option, &file_path);
        match result {
            boot_vars::BootAttemptResult::Success => {
                log::info!("Boot{:04X} succeeded", option_num);
                // edk2 retries the whole loop if boot succeeded then returned;
                // we fall through to the menu instead
                return true;
            }
            boot_vars::BootAttemptResult::Failed | boot_vars::BootAttemptResult::NotFound => {
                log::warn!(
                    "Boot{:04X} '{}' failed, trying next",
                    option_num,
                    load_option.description
                );
            }
            boot_vars::BootAttemptResult::Skipped => {}
        }
    }
    false
}

/// Discover boot entries and show setup indefinitely only on an explicit request.
fn show_boot_menu(timeout_seconds: u32, firmware_ui_requested: bool) {
    // A choice the boot policy refuses (the setup menu may have tightened it
    // since the entries were listed) shows the menu again, rebuilt under the
    // current policy and waiting for the user.
    let mut countdown = Some(timeout_seconds);
    while show_boot_menu_once(countdown, firmware_ui_requested) == MenuOutcome::Refused {
        countdown = None;
    }
}

#[derive(PartialEq, Eq)]
enum MenuOutcome {
    Done,
    Refused,
}

/// `countdown` is the configured timeout, or `None` to wait for the user.
fn show_boot_menu_once(countdown: Option<u32>, firmware_ui_requested: bool) -> MenuOutcome {
    // ---- Phase 3: Fallback to device discovery and interactive menu ----
    log::info!("=== Fallback: discovering boot entries from storage ===");

    let mut boot_menu = menu::discover_boot_entries();
    // After a refused choice the user is in the menu on purpose, like an
    // explicit setup request: keep the menu even without media.
    let keep_menu = firmware_ui_requested || countdown.is_none();

    if boot_menu.entry_count() == 0 && !keep_menu {
        log::warn!("No bootable media found!");

        #[cfg(feature = "ui")]
        crate::ui::show_no_media_screen();

        return MenuOutcome::Done;
    }

    let (graphical, timeout_seconds) = menu_configuration(
        cfg!(feature = "ui"),
        crate::handoff::framebuffer().is_some(),
        countdown.unwrap_or(0),
        firmware_ui_requested,
    );
    // A headless menu normally never waits forever; after a refused choice
    // it must, or its countdown would start an entry nobody chose.
    let timeout_seconds = if countdown.is_some() {
        timeout_seconds
    } else {
        0
    };
    boot_menu.set_timeout(timeout_seconds);
    // A timeout is an automatic boot: default to an entry it may start (a
    // BLS default can point at external media), or make the user pick.
    if timeout_seconds != 0
        && !boot_policy::automatic_external_allowed()
        && boot_menu
            .get_entry(boot_menu.selected)
            .is_some_and(|entry| boot_policy::storage_is_external(entry.storage))
    {
        match boot_menu
            .entries
            .iter()
            .position(|entry| !boot_policy::storage_is_external(entry.storage))
        {
            Some(internal) => {
                log::info!("Boot policy: default entry is external; defaulting to an internal one");
                boot_menu.selected = internal;
            }
            None => {
                log::info!("Boot policy: every entry is external; disabling the menu timeout");
                boot_menu.set_timeout(0);
            }
        }
    }

    log::info!(
        "Showing {}boot menu (autoboot timeout: {}s)",
        if firmware_ui_requested {
            "firmware UI: "
        } else {
            ""
        },
        boot_menu.timeout_seconds
    );
    if keep_menu && boot_menu.entry_count() == 0 {
        #[cfg(feature = "ui")]
        if graphical {
            crate::ui::show_no_media_screen();
            return MenuOutcome::Done;
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
            // Both menus clear the timeout on any input, so one still set
            // means the countdown chose this entry. Check the live policy:
            // setup may have tightened it while the menu was open.
            let automatic = boot_menu.timeout_seconds != 0;
            if !boot_policy::dispatch_allowed(entry.storage, automatic) {
                log::warn!(
                    "Boot policy: refusing external entry '{}'{}",
                    entry.name,
                    if automatic { " on timeout" } else { "" }
                );
                return MenuOutcome::Refused;
            }
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
    MenuOutcome::Done
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
/// This matches the file path against ESPs found on storage devices. An
/// option that names a GPT partition (a hard-drive media node) only matches
/// that partition, so a copy of the same file on other media, such as a USB
/// stick tried after the internal disk failed, cannot stand in for it.
fn try_boot_load_option(
    load_option: &boot_vars::LoadOption,
    file_path: &str,
    scope: Scope,
) -> boot_vars::BootAttemptResult {
    // Set BootCurrent before attempting boot
    boot_vars::set_boot_current(load_option.option_number);

    // Try to find this file on the named partition, or on any discovered ESP
    let target = boot_vars::partition_target(load_option);
    let result = if target == boot_vars::PartitionTarget::Unsupported {
        log::warn!(
            "Boot{:04X}: its device path cannot be matched; not booting it",
            load_option.option_number
        );
        boot_vars::BootAttemptResult::Skipped
    } else {
        try_boot_file_from_esps(file_path, target, scope)
    };

    // Clear BootCurrent after boot returns
    boot_vars::clear_boot_current();

    result
}

/// Try to boot a specific file path from any ESP on the devices in `scope`.
///
/// Scans the storage devices, looks for ESPs, and tries to find and boot
/// the specified file. This is the fallback path when we don't have full
/// device path resolution yet.
fn try_boot_file_from_esps(
    file_path: &str,
    target: boot_vars::PartitionTarget,
    scope: Scope,
) -> boot_vars::BootAttemptResult {
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

    // Internal storage first, then other external media, USB last: the copy
    // that starts must not depend on whether USB came up early.
    let mut devices = crate::drivers::storage::devices();
    devices.retain(|device| scope.includes(device));
    devices.sort_by_key(|device| {
        (
            device.external,
            matches!(device.id, crate::drivers::storage::StorageId::Usb { .. }),
        )
    });
    let mut result = boot_vars::BootAttemptResult::NotFound;
    for device in &devices {
        match try_boot_file_on_device(device, &fat_path, target) {
            boot_vars::BootAttemptResult::NotFound => {}
            boot_vars::BootAttemptResult::Success => {
                return boot_vars::BootAttemptResult::Success;
            }
            other => result = other,
        }
    }
    result
}

/// Try to boot a specific file from ESPs on a given device.
///
/// Reads GPT/MBR partitions, finds ESP partitions, mounts FAT, checks if the file exists,
/// Boot `file_path` from the partition `target` names on `device`, or from
/// any ESP holding it for a file-only option.
///
/// `NotFound` means the device does not hold the target: no matching
/// partition, or for a file-only option no ESP with the file. A bound target
/// that is here but fails to boot is `Failed`.
fn try_boot_file_on_device(
    device: &crate::drivers::storage::StorageDevice,
    file_path: &str,
    target: boot_vars::PartitionTarget,
) -> boot_vars::BootAttemptResult {
    use crate::drivers::storage;
    use crate::fs::{fat::FatFilesystem, gpt};
    use boot_vars::{BootAttemptResult, PartitionTarget};

    // An MBR target is matched against the MBR itself, also on a hybrid disk
    // whose GPT would otherwise win.
    let partitions = storage::with_disk(device.id, |disk| match target {
        PartitionTarget::Mbr { .. } => gpt::read_mbr_partitions(disk)
            .ok()
            .map(|partitions| partitions.into_iter().collect::<heapless::Vec<_, 16>>()),
        _ => gpt::read_partitions_auto(disk).ok(),
    })
    .ok()
    .flatten();
    let Some(partitions) = partitions else {
        return BootAttemptResult::NotFound;
    };

    for partition in partitions.iter() {
        let bound = match target {
            PartitionTarget::Any => false,
            PartitionTarget::Gpt(guid) => {
                if guid != partition.partition_guid {
                    continue;
                }
                true
            }
            PartitionTarget::Mbr {
                number,
                disk_signature,
                start_lba,
            } => {
                if partition.mbr_disk_signature != Some(disk_signature)
                    || partition.first_lba != start_lba
                    || number != partition.number
                {
                    continue;
                }
                true
            }
            PartitionTarget::Unsupported => return BootAttemptResult::NotFound,
        };
        if !partition.is_esp && !bound {
            continue;
        }

        let partition_num = partition.number;

        // Try to mount FAT and check for the file
        let found = storage::with_disk(device.id, |disk| {
            FatFilesystem::new(disk, partition.first_lba)
                .is_ok_and(|mut fat| fat.file_size(file_path).is_ok())
        })
        .unwrap_or(false);

        if !found {
            if bound {
                log::warn!(
                    "'{}' is not readable on the partition {} names",
                    file_path,
                    device.id.description()
                );
                return BootAttemptResult::Failed;
            }
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

        return if boot_uefi_entry(&entry) {
            BootAttemptResult::Success
        } else {
            BootAttemptResult::Failed
        };
    }

    BootAttemptResult::NotFound
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
/// Boot a UEFI entry; `true` when the image ran and returned EFI_SUCCESS.
fn boot_uefi_entry(entry: &menu::BootEntry) -> bool {
    boot_uefi_path(entry, &entry.path)
}

fn boot_uefi_path(entry: &menu::BootEntry, path: &str) -> bool {
    use crate::boot;
    use crate::drivers::storage;

    let path_info = boot::device_path_info_from_entry(entry);

    let info = match storage::with_disk(entry.storage, |disk| disk.info()) {
        Ok(info) => info,
        Err(error) => {
            log::error!("Failed to access {:?}: {}", entry.storage, error);
            return false;
        }
    };
    boot::install_block_io_protocols(entry.storage, info, &path_info);

    if boot::try_boot_path_from_esp(
        &entry.partition,
        entry.partition_num,
        &path_info,
        entry.storage,
        info.block_size,
        path,
    ) {
        return true;
    }
    log::error!("Failed to boot UEFI entry");
    false
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
        // The entry path is the direct kernel, not a UEFI loader. Start the
        // architecture fallback loader on this same ESP under verification.
        boot_uefi_path(entry, menu::EFI_BOOT_PATH);
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

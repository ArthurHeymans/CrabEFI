//! Boot Menu Module
//!
//! This module provides a boot menu that displays on both serial console and
//! framebuffer, allowing users to select from discovered boot entries.
//!
//! # Features
//!
//! - Discovers boot entries on every storage device (`storage::devices()`)
//! - Supports multiple boot entry types:
//!   - UEFI bootloaders (EFI\\BOOT\\BOOTX64.EFI or BOOTAA64.EFI)
//!   - BLS (Boot Loader Specification) entries in /loader/entries/
//!   - GRUB configuration entries from grub.cfg
//!   - Coreboot payload chainloading
//! - Displays menu on serial (with ANSI escape codes) and framebuffer
//! - Arrow key navigation and Enter to select
//! - Configurable auto-boot timeout with countdown

use crate::drivers::block::BlockDevice;
use crate::drivers::pci::PciAddress;
use crate::drivers::serial as serial_driver;
use crate::drivers::storage::{self, StorageDevice, StorageId};
use crate::framebuffer_console::{
    Color, DEFAULT_BG, DEFAULT_FG, FramebufferConsole, HIGHLIGHT_BG, HIGHLIGHT_FG, TITLE_COLOR,
};
use crate::fs::{fat::FatFilesystem, gpt, iso9660};
use crate::time::{Timeout, delay_ms};
use core::fmt::Write;
use heapless::String;

/// Update the mouse cursor on the framebuffer.
///
/// Call this in the menu event loop to render the cursor at its current position.
#[cfg(feature = "ui")]
fn update_cursor(
    cursor_renderer: &mut crate::cursor::CursorRenderer,
    fb_info: &Option<crate::FramebufferConfig>,
) {
    if let Some(fb) = fb_info
        && crate::drivers::mouse_cursor::is_initialized()
    {
        let (x, y) = crate::drivers::mouse_cursor::position();
        cursor_renderer.update(fb, x, y);
    }
}

/// Default timeout in seconds for auto-boot
const DEFAULT_TIMEOUT_SECONDS: u32 = 5;

/// Architecture-specific EFI boot path
#[cfg(target_arch = "x86_64")]
pub const EFI_BOOT_PATH: &str = "EFI\\BOOT\\BOOTX64.EFI";
#[cfg(target_arch = "aarch64")]
pub const EFI_BOOT_PATH: &str = "EFI\\BOOT\\BOOTAA64.EFI";
#[cfg(target_arch = "riscv64")]
pub const EFI_BOOT_PATH: &str = "EFI\\BOOT\\BOOTRISCV64.EFI";

/// Menu title
const MENU_TITLE: &str = "CrabEFI Boot Menu";

/// Help text
#[cfg(feature = "secure-boot")]
const HELP_TEXT: &str = "Enter: Boot | F: Firmware | C: Cmdline | S: Secure Boot | R: Reset";
/// Help text without the Secure Boot entry.
#[cfg(not(feature = "secure-boot"))]
const HELP_TEXT: &str = "Enter: Boot | F: Firmware | C: Cmdline | R: Reset";

pub use crabefi_ui::{BootCategory, BootEntryKind};

/// A boot entry discovered on storage media
#[derive(Debug, Clone)]
pub struct BootEntry {
    /// What the menu shows: name, path, kind and partition number
    pub entry: crabefi_ui::BootEntry,
    /// Storage device holding the entry
    pub storage: StorageId,
    /// PCI address of the storage controller, if any
    pub pci: Option<PciAddress>,
    /// Partition information
    pub partition: gpt::Partition,
}

impl core::ops::Deref for BootEntry {
    type Target = crabefi_ui::BootEntry;
    fn deref(&self) -> &Self::Target {
        &self.entry
    }
}

impl core::ops::DerefMut for BootEntry {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entry
    }
}

impl crabefi_ui::MenuEntry for BootEntry {
    fn disk_name(&self) -> alloc::string::String {
        let n = match self.storage {
            StorageId::Nvme { controller_id, .. } | StorageId::Sdhci { controller_id } => {
                controller_id
            }
            StorageId::Ahci { port, .. } => port,
            StorageId::Usb { device_addr, .. } => device_addr as usize,
            StorageId::Platform { index } => index,
        };
        alloc::format!("{} {n}", self.storage.description())
    }
    fn disk_detail(&self) -> alloc::string::String {
        storage_identity(self.storage)
    }
    fn same_disk(&self, other: &Self) -> bool {
        self.storage == other.storage
    }
}

fn storage_identity(id: StorageId) -> alloc::string::String {
    match id {
        StorageId::Nvme {
            controller_id,
            nsid,
        } => alloc::format!("NVMe controller {controller_id}, namespace {nsid}"),
        StorageId::Ahci {
            controller_id,
            port,
        } => alloc::format!("SATA controller {controller_id}, port {port}"),
        StorageId::Usb {
            controller_id,
            device_addr,
        } => alloc::format!("USB controller {controller_id}, device {device_addr}"),
        StorageId::Sdhci { controller_id } => {
            alloc::format!("{} {controller_id}", id.description())
        }
        StorageId::Platform { index } => alloc::format!("{} {index}", id.description()),
    }
}

impl BootEntry {
    /// Create a new boot entry (defaults to UEFI type)
    pub fn new(
        name: &str,
        path: &str,
        device: &StorageDevice,
        partition_num: u32,
        partition: gpt::Partition,
    ) -> Self {
        Self::new_with_kind(
            name,
            path,
            device,
            partition_num,
            partition,
            BootEntryKind::Uefi,
            BootCategory::Uefi,
        )
    }

    /// Create a new boot entry with specific kind and category
    pub fn new_with_kind(
        name: &str,
        path: &str,
        device: &StorageDevice,
        partition_num: u32,
        partition: gpt::Partition,
        kind: BootEntryKind,
        category: BootCategory,
    ) -> Self {
        BootEntry {
            entry: crabefi_ui::BootEntry::new(name, path, partition_num, kind, category),
            storage: device.id,
            pci: device.pci,
            partition,
        }
    }

    /// Format a description for display
    pub fn format_description(&self, buf: &mut String<128>) {
        buf.clear();
        let _ = write!(
            buf,
            "{} ({}, partition {})",
            self.name,
            self.storage.description(),
            self.partition_num
        );
    }
}

/// Boot menu state
pub struct BootMenu {
    /// Entries, selection and timeout, as the menus show them
    pub(crate) menu: crabefi_ui::BootMenu<BootEntry>,
    /// `selected` is a `loader.conf` default, which the first one sets
    default_chosen: bool,
}

impl core::ops::Deref for BootMenu {
    type Target = crabefi_ui::BootMenu<BootEntry>;
    fn deref(&self) -> &Self::Target {
        &self.menu
    }
}

impl core::ops::DerefMut for BootMenu {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.menu
    }
}

impl Default for BootMenu {
    fn default() -> Self {
        Self::new()
    }
}

impl BootMenu {
    /// Create a new boot menu
    pub fn new() -> Self {
        let mut menu = crabefi_ui::BootMenu::new();
        menu.timeout_seconds = DEFAULT_TIMEOUT_SECONDS;
        BootMenu {
            menu,
            default_chosen: false,
        }
    }
}

/// Discover boot entries from all storage devices
///
/// Scans every storage device for ESPs containing the arch-specific EFI
/// bootloader, falling back to El Torito on disks without a partition table.
///
/// # Returns
///
/// A `BootMenu` containing all discovered boot entries.
pub fn discover_boot_entries() -> BootMenu {
    let mut menu = BootMenu::new();

    log::info!("Discovering boot entries...");

    let mut devices = storage::devices();
    devices.retain(crate::boot_policy::menu_boot_allowed);
    if !crate::boot_policy::automatic_external_allowed() {
        // Internal entries first, so the default entry is internal.
        devices.sort_by_key(crate::boot_policy::device_is_external);
    }
    for device in devices {
        let partitions = storage::with_disk(device.id, |disk| gpt::read_partitions_auto(disk).ok())
            .ok()
            .flatten();
        match partitions {
            Some(partitions) => discover_entries_on_disk(&device, &partitions, &mut menu),
            None => try_el_torito_fallback(&device, &mut menu),
        }
    }

    log::info!("Found {} boot entries", menu.entry_count());

    menu
}

/// Discover boot entries on the partitions of one disk.
///
/// For each ESP (or potential ESP) partition, mounts the FAT filesystem,
/// checks for the arch-specific EFI bootloader, and scans for additional
/// BLS/GRUB/payload entries.
///
/// # Arguments
///
/// * `device` - Disk holding the partitions
/// * `partitions` - Partition table of the disk
/// * `menu` - Boot menu to add entries to
fn discover_entries_on_disk(
    device: &StorageDevice,
    partitions: &[gpt::Partition],
    menu: &mut BootMenu,
) {
    for (i, partition) in partitions.iter().enumerate() {
        let partition_num = (i + 1) as u32;

        if !partition.is_esp && !is_potential_esp(partition) {
            continue;
        }

        let _ = storage::with_disk(device.id, |disk| {
            let mut fat = match FatFilesystem::new(disk, partition.first_lba) {
                Ok(f) => f,
                Err(_) => return,
            };

            // Check for UEFI bootloader
            if fat.file_size(EFI_BOOT_PATH).is_ok() {
                let mut name: String<64> = String::new();
                let _ = write!(name, "Boot Entry ({})", device.label);

                let entry = BootEntry::new(
                    &name,
                    EFI_BOOT_PATH,
                    device,
                    partition_num,
                    partition.clone(),
                );

                if !menu.add_entry(entry) {
                    return; // Menu full
                }
            }

            // Scan for additional entries (BLS, GRUB, payloads)
            scan_partition_for_entries(&mut fat, device, partition_num, partition, menu);
        });
    }
}

/// Try El Torito (ISO9660) boot on a disk without a partition table
fn try_el_torito_fallback(device: &StorageDevice, menu: &mut BootMenu) {
    let _ = storage::with_disk(device.id, |disk| {
        let efi_image = match iso9660::find_efi_boot_image(disk) {
            Ok(img) => img,
            Err(_) => return,
        };

        if efi_image.sector_count == 0 {
            log::warn!("El Torito: EFI image has unknown size, skipping");
            return;
        }

        log::info!(
            "El Torito: boot image start_sector={}, sector_count={}, size_bytes={}",
            efi_image.start_sector,
            efi_image.sector_count,
            efi_image.size_bytes
        );

        // Create a synthetic partition for the El Torito boot image
        let block_size = disk.info().block_size;
        let partition = gpt::Partition {
            type_guid: [0u8; 16],
            partition_guid: [0u8; 16],
            first_lba: efi_image.start_sector,
            last_lba: efi_image.start_sector + efi_image.sector_count as u64 - 1,
            attributes: 0,
            is_esp: true,
            block_size,
        };

        if !check_bootloader_exists(disk, efi_image.start_sector) {
            return;
        }

        let mut name: String<64> = String::new();
        let _ = write!(name, "ISO Boot ({})", device.label);

        let entry = BootEntry::new(
            &name,
            EFI_BOOT_PATH,
            device,
            0, // No partition number for El Torito
            partition,
        );

        menu.add_entry(entry);
    });
}

/// Check if a partition might be an ESP (fallback heuristic)
fn is_potential_esp(partition: &gpt::Partition) -> bool {
    // Small partitions (< 512 MB) are more likely to be boot partitions
    let size_mb = partition.size_bytes() / (1024 * 1024);
    size_mb > 0 && size_mb < 512 && partition.first_lba > 0
}

/// Convert a Linux-style path to FAT-style path
///
/// Wrapper around fs::linux_path_to_fat that returns an empty string on error
/// for backward compatibility in menu scanning (errors are logged but not fatal).
fn linux_path_to_fat(path: &str) -> String<128> {
    match crate::fs::linux_path_to_fat(path) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("Invalid path '{}': {:?}", path, e);
            String::new()
        }
    }
}

/// Check if a bootloader exists on the given partition
fn check_bootloader_exists(disk: &mut dyn BlockDevice, partition_start: u64) -> bool {
    match FatFilesystem::new(disk, partition_start) {
        Ok(mut fat) => match fat.file_size(EFI_BOOT_PATH) {
            Ok(size) => {
                log::info!(
                    "Found {} ({} bytes) at LBA {}",
                    EFI_BOOT_PATH,
                    size,
                    partition_start
                );
                size > 0
            }
            Err(e) => {
                log::debug!("Bootloader not found at LBA {}: {:?}", partition_start, e);
                false
            }
        },
        Err(e) => {
            log::debug!("FAT mount failed at LBA {}: {:?}", partition_start, e);
            false
        }
    }
}

/// Scan a partition for additional boot entries (BLS, GRUB, payloads)
///
/// This function scans the given FAT filesystem for:
/// - BLS (Boot Loader Specification) entries in /loader/entries/
/// - GRUB configuration entries in grub.cfg
/// - Coreboot payloads in common payload directories
///
/// Note: When Secure Boot is enabled, direct Linux boot entries (BLS Type #1
/// and GRUB Linux entries) are not added because they bypass signature
/// verification. Only UEFI boot entries are shown in that case.
///
/// # Arguments
///
/// * `fat` - Mounted FAT filesystem
/// * `device` - Storage device for the boot entries
/// * `partition_num` - 1-based partition number
/// * `partition` - Partition info
/// * `menu` - Boot menu to add entries to
fn scan_partition_for_entries(
    fat: &mut FatFilesystem<'_>,
    device: &StorageDevice,
    partition_num: u32,
    partition: &gpt::Partition,
    menu: &mut BootMenu,
) {
    // Check if Secure Boot is active - if so, skip direct Linux boot entries
    // because they bypass signature verification
    let secure_boot_active = crate::efi::auth::is_secure_boot_enabled();
    if secure_boot_active {
        log::debug!("Secure Boot active: skipping direct Linux boot entry discovery");
    }

    // 1. Scan for BLS entries - only if Secure Boot is off
    // BLS entries should have kernels on the same partition (ESP or XBOOTLDR)
    // Direct boot bypasses signature verification, so we disable it with Secure Boot
    if !secure_boot_active && let Ok(bls_discovery) = crate::bls::discover_entries(fat) {
        for bls_entry in bls_discovery.entries.iter() {
            // Convert Linux path to FAT path and check if file exists
            let fat_path = linux_path_to_fat(&bls_entry.linux);

            // Only add the entry if the kernel file exists on this partition
            if fat.file_size(&fat_path).is_ok() {
                let mut name: String<64> = String::new();
                let _ = name.push_str(bls_entry.display_title());

                // Also convert initrd path
                let initrd_fat_paths = bls_entry
                    .initrds
                    .iter()
                    .map(|path| linux_path_to_fat(path))
                    .collect();

                let entry = BootEntry::new_with_kind(
                    &name,
                    &fat_path,
                    device,
                    partition_num,
                    partition.clone(),
                    BootEntryKind::BlsLinux {
                        linux_path: fat_path.clone(),
                        initrd_paths: initrd_fat_paths,
                        cmdline: bls_entry.options.clone(),
                    },
                    BootCategory::Bls,
                );

                if !menu.add_entry(entry) {
                    return; // Menu full
                }
                // Boot the first loader.conf default that made it into the
                // menu, like systemd-boot, instead of the first entry (often
                // the removable-media fallback).
                if !menu.default_chosen && bls_discovery.is_default(bls_entry) {
                    menu.selected = menu.entry_count() - 1;
                    menu.default_chosen = true;
                    log::info!("loader.conf default: '{}'", bls_entry.display_title());
                }

                log::debug!(
                    "Added BLS entry '{}' (kernel exists on partition)",
                    bls_entry.display_title()
                );
            } else {
                log::debug!(
                    "Skipping BLS entry '{}' (kernel '{}' not found on this partition)",
                    bls_entry.display_title(),
                    fat_path
                );
            }
        }
    }

    // 2. Scan for GRUB config entries - only if Secure Boot is off
    // NOTE: GRUB entries from grub.cfg often reference kernels on the root partition,
    // not the ESP where grub.cfg lives. We only add entries if the kernel file
    // actually exists on this partition (for direct boot to work).
    // Direct boot bypasses signature verification, so we disable it with Secure Boot
    if !secure_boot_active && let Ok(grub_config) = crate::grub::parse_config(fat) {
        // If GRUB has blscfg directive, BLS entries were already added above
        // Only add GRUB entries that have explicit linux/initrd paths AND
        // where the kernel file actually exists on this partition
        for grub_entry in grub_config.entries.iter() {
            if !grub_entry.linux.is_empty() {
                // Convert Linux path to FAT path and check if file exists
                let fat_path = linux_path_to_fat(&grub_entry.linux);

                // Only add the entry if the kernel file exists on this partition
                if fat.file_size(&fat_path).is_ok() {
                    let mut name: String<64> = String::new();
                    let _ = name.push_str(&grub_entry.title);

                    // Also convert the initrd paths
                    let initrd_fat_paths = grub_entry
                        .initrds
                        .iter()
                        .map(|path| linux_path_to_fat(path))
                        .collect();

                    let entry = BootEntry::new_with_kind(
                        &name,
                        &fat_path,
                        device,
                        partition_num,
                        partition.clone(),
                        BootEntryKind::GrubLinux {
                            linux_path: fat_path.clone(),
                            initrd_paths: initrd_fat_paths,
                            cmdline: grub_entry.options.clone(),
                        },
                        BootCategory::Grub,
                    );

                    if !menu.add_entry(entry) {
                        return; // Menu full
                    }

                    log::debug!(
                        "Added GRUB entry '{}' (kernel exists on partition)",
                        grub_entry.title
                    );
                } else {
                    log::debug!(
                        "Skipping GRUB entry '{}' (kernel '{}' not found on this partition)",
                        grub_entry.title,
                        fat_path
                    );
                }
            }
        }
    }

    // 3. Scan for coreboot payloads
    // NOTE: Payload discovery is disabled until boot_payload_entry() is fully
    // implemented. Currently selecting a payload entry does nothing useful.
    // See: src/lib.rs boot_payload_entry() and src/payload/mod.rs chainload_payload()
    //
    // TODO: Re-enable once payload chainloading is implemented:
    // let payloads = crate::payload::discover_payloads(fat);
    // for payload_entry in payloads.iter() {
    //     let entry = BootEntry::new_with_kind(
    //         &payload_entry.name,
    //         &payload_entry.path,
    //         device,
    //         partition_num,
    //         partition.clone(),
    //         BootEntryKind::Payload {
    //             path: payload_entry.path.clone(),
    //             format: payload_entry.format,
    //         },
    //         BootCategory::Payload,
    //     );
    //
    //     if !menu.add_entry(entry) {
    //         return; // Menu full
    //     }
    // }
}

/// Show the boot menu and wait for user selection
///
/// # Arguments
///
/// * `menu` - The boot menu with discovered entries
///
/// # Returns
///
/// The index of the selected boot entry, or `None` if no selection was made.
/// Boot [`BootMenu::entry_for_boot`] for that index so a one-shot
/// command-line edit made in the menu applies to this boot attempt.
pub fn show_menu(menu: &mut BootMenu) -> Option<usize> {
    menu.clear_edited_cmdline();
    // An empty, indefinite menu still provides firmware/security settings.
    // The boot manager uses this for explicit setup requests without media.
    if menu.entry_count() == 0 {
        menu.set_timeout(0);
    }

    // Get framebuffer for console and cursor rendering.
    let fb_config = crate::handoff::framebuffer();
    #[cfg(feature = "ui")]
    let fb_info = fb_config;
    #[cfg(not(feature = "ui"))]
    let _ = (); // fb_info unused without ui

    // Create framebuffer console if available
    let mut fb_console = fb_config.as_ref().map(FramebufferConsole::new);

    // Clear screen
    menu_common::clear_screen(&mut fb_console);

    // Initial display
    draw_menu(menu, &mut fb_console);

    // Handle input with timeout
    let mut remaining_seconds = menu.timeout_seconds;
    let mut last_second_check = Timeout::from_ms(1000);

    // Zero disables autoboot; do not announce "Booting now..." in setup.
    if remaining_seconds > 0 {
        draw_countdown(remaining_seconds, &mut fb_console);
    }

    // Initialize cursor renderer for mouse support
    #[cfg(feature = "ui")]
    let mut cursor_renderer = crate::cursor::CursorRenderer::new();

    loop {
        // Update mouse cursor on framebuffer
        #[cfg(feature = "ui")]
        update_cursor(&mut cursor_renderer, &fb_info);
        // Check for timeout (first tick fires after 1 real second)
        if remaining_seconds > 0 && last_second_check.is_expired() {
            remaining_seconds -= 1;
            last_second_check = Timeout::from_ms(1000);

            // Update countdown display
            draw_countdown(remaining_seconds, &mut fb_console);

            if remaining_seconds == 0 {
                // Timeout - boot selected entry
                return Some(menu.selected);
            }
        }

        // Check for keypress
        if let Some(key) = menu_common::read_key() {
            // Any key resets the timeout
            remaining_seconds = menu.timeout_seconds;

            match key {
                KeyPress::Up | KeyPress::Char('k') => {
                    menu.select_previous();
                    draw_menu(menu, &mut fb_console);
                }
                KeyPress::Down | KeyPress::Char('j') => {
                    menu.select_next();
                    draw_menu(menu, &mut fb_console);
                }
                KeyPress::Enter if menu.entry_count() > 0 => {
                    // Show booting message before returning
                    if let Some(entry) = menu.entries.get(menu.selected) {
                        log::info!(
                            "Selected entry: name='{}', path='{}'",
                            entry.name,
                            entry.path
                        );
                        let mut msg: String<64> = String::new();
                        let _ = msg.push_str("Booting ");
                        let _ = msg.push_str(&entry.name);
                        let _ = msg.push_str("...");
                        draw_status(&msg, &mut fb_console);
                    } else {
                        log::error!("No entry at selected index {}", menu.selected);
                        draw_status("Error: No entry selected", &mut fb_console);
                    }
                    return Some(menu.selected);
                }
                KeyPress::Escape => {
                    // Future: file browser
                    draw_status("File browser not yet implemented", &mut fb_console);
                }
                #[cfg(feature = "secure-boot")]
                KeyPress::Char('s') | KeyPress::Char('S') => {
                    // Open Secure Boot settings menu
                    crate::secure_boot_menu::show_secure_boot_menu();
                    // Redraw boot menu after returning
                    menu_common::clear_screen(&mut fb_console);
                    draw_menu(menu, &mut fb_console);
                }
                KeyPress::Char('f') | KeyPress::Char('F') => {
                    // Open platform-provided firmware settings menu.
                    if let Some(hooks) = crate::handoff::callbacks().hooks {
                        if !hooks.show_firmware_settings() {
                            draw_status("Firmware settings not available", &mut fb_console);
                            delay_ms(500);
                        }
                    } else {
                        draw_status("Firmware settings not available", &mut fb_console);
                        delay_ms(500);
                    }
                    // Redraw boot menu after returning
                    menu_common::clear_screen(&mut fb_console);
                    draw_menu(menu, &mut fb_console);
                }
                KeyPress::Char('r') | KeyPress::Char('R') => {
                    // Reset the system
                    draw_status("Resetting system...", &mut fb_console);
                    delay_ms(500);
                    crate::reset_system();
                }
                KeyPress::Char('c') | KeyPress::Char('C') => {
                    // Edit kernel command line (one-shot: recorded on the
                    // menu, never written into the entry itself)
                    let selected = menu.selected;
                    let editing = menu
                        .entries
                        .get(selected)
                        .filter(|entry| entry.has_cmdline())
                        .and_then(|entry| {
                            menu.effective_cmdline(selected)
                                .map(|initial| (entry.name.clone(), initial))
                        });
                    if let Some((name, initial)) = editing {
                        match edit_cmdline(&name, initial, &mut fb_console) {
                            (EditResult::Boot, edited) => {
                                menu.set_edited_cmdline(selected, edited);
                                // Boot immediately with the edited command line
                                let mut msg: String<64> = String::new();
                                let _ = msg.push_str("Booting ");
                                let _ = msg.push_str(&name);
                                let _ = msg.push_str("...");
                                menu_common::clear_screen(&mut fb_console);
                                draw_status(&msg, &mut fb_console);
                                return Some(selected);
                            }
                            (EditResult::Confirmed, edited) => {
                                menu.set_edited_cmdline(selected, edited);
                                draw_status("Command line updated", &mut fb_console);
                            }
                            (EditResult::Cancelled, _) => {
                                draw_status("Edit cancelled", &mut fb_console);
                            }
                        }
                    } else {
                        draw_status("This entry has no editable command line", &mut fb_console);
                    }
                    // Redraw menu after editing (unless we're booting)
                    delay_ms(500);
                    menu_common::clear_screen(&mut fb_console);
                    draw_menu(menu, &mut fb_console);
                }
                KeyPress::Char(c) if c.is_ascii_digit() => {
                    // Direct selection by number
                    let num = (c as u8 - b'0') as usize;
                    if num > 0 && num <= menu.entry_count() {
                        menu.selected = num - 1;
                        draw_menu(menu, &mut fb_console);
                    }
                }
                // Handle mouse clicks - select entry under cursor
                #[cfg(feature = "ui")]
                KeyPress::MouseClick { y, .. } => {
                    // Map screen Y pixel to menu entry index
                    // Menu entries start at row ~5 (after header + category)
                    let row = y / crate::framebuffer_console::CHAR_HEIGHT;
                    if let Some(idx) = row_to_entry_index(
                        menu,
                        row,
                        menu_scroll_offset(menu, &fb_console),
                        menu_visible_rows(&fb_console),
                    ) {
                        menu.selected = idx;
                        draw_menu(menu, &mut fb_console);
                    }
                }
                #[cfg(feature = "ui")]
                KeyPress::MouseScroll(dz) => {
                    if dz > 0 {
                        menu.select_next();
                    } else {
                        menu.select_previous();
                    }
                    draw_menu(menu, &mut fb_console);
                }
                _ => {}
            }
        }

        // Small delay to avoid busy-waiting
        delay_ms(10);
    }
}

/// Map a screen row to a menu entry index.
///
/// Returns `Some(index)` if the row corresponds to a boot entry,
/// `None` if it's a header, separator, or out of range.
#[cfg(feature = "ui")]
fn row_to_entry_index(
    menu: &BootMenu,
    row: u32,
    scroll_offset: usize,
    visible_rows: usize,
) -> Option<usize> {
    // Menu layout: row 0-2 = header, row 3 = blank, row 4+ = visible menu rows.
    let start_row = 4usize;
    let target_row = row as usize;
    if target_row < start_row || target_row >= start_row + visible_rows {
        return None;
    }
    let mut logical_row = 0usize;
    let mut current_category: Option<BootCategory> = None;

    for (i, entry) in menu.entries.iter().enumerate() {
        if current_category != Some(entry.category) {
            if current_category.is_some() {
                logical_row += 1; // blank line
            }
            logical_row += 1; // category separator
            current_category = Some(entry.category);
        }

        if logical_row >= scroll_offset {
            let screen_row = start_row + logical_row - scroll_offset;
            if target_row == screen_row {
                return Some(i);
            }
        }
        logical_row += 1;
    }
    None
}

use crate::menu_common::{self, KeyPress, SerialWriter};

fn menu_visible_rows(fb_console: &Option<FramebufferConsole>) -> usize {
    let rows = fb_console.as_ref().map(|c| c.rows()).unwrap_or(25) as usize;
    rows.saturating_sub(10).max(1)
}

fn menu_item_count(menu: &BootMenu) -> usize {
    let mut count = 0usize;
    let mut current_category: Option<BootCategory> = None;
    for entry in &menu.entries {
        if current_category != Some(entry.category) {
            if current_category.is_some() {
                count += 1;
            }
            count += 1;
            current_category = Some(entry.category);
        }
        count += 1;
    }
    count
}

fn selected_menu_position(menu: &BootMenu) -> usize {
    let mut pos = 0usize;
    let mut current_category: Option<BootCategory> = None;
    for (i, entry) in menu.entries.iter().enumerate() {
        if current_category != Some(entry.category) {
            if current_category.is_some() {
                pos += 1;
            }
            pos += 1;
            current_category = Some(entry.category);
        }
        if i == menu.selected {
            return pos;
        }
        pos += 1;
    }
    0
}

fn menu_scroll_offset(menu: &BootMenu, fb_console: &Option<FramebufferConsole>) -> usize {
    let visible_rows = menu_visible_rows(fb_console);
    let selected_pos = selected_menu_position(menu);
    if selected_pos >= visible_rows {
        selected_pos - visible_rows + 1
    } else {
        0
    }
}

/// Draw the menu on both outputs
fn draw_menu(menu: &BootMenu, fb_console: &mut Option<FramebufferConsole>) {
    let cols = fb_console.as_ref().map(|c| c.cols()).unwrap_or(80) as usize;
    let rows = fb_console.as_ref().map(|c| c.rows()).unwrap_or(25) as usize;
    let visible_rows = menu_visible_rows(fb_console);
    let scroll_offset = menu_scroll_offset(menu, fb_console);
    let total_rows = menu_item_count(menu);

    // Draw header
    draw_header(fb_console, cols);

    // Draw entries with category separators
    let start_row = 4;
    let mut logical_row = 0usize;
    let mut screen_row = start_row;
    let mut current_category: Option<BootCategory> = None;

    for (i, entry) in menu.entries.iter().enumerate() {
        // Check if we need a category separator
        if current_category != Some(entry.category) {
            // Add blank line before separator (except for first category)
            if current_category.is_some() {
                logical_row += 1;
            }
            if logical_row >= scroll_offset && logical_row < scroll_offset + visible_rows {
                draw_category_separator(entry.category, screen_row, fb_console, cols);
                screen_row += 1;
            }
            logical_row += 1;
            current_category = Some(entry.category);
        }

        let is_selected = i == menu.selected;
        if logical_row >= scroll_offset && logical_row < scroll_offset + visible_rows {
            draw_entry(i, entry, is_selected, screen_row, fb_console, cols);
            screen_row += 1;
        }
        logical_row += 1;
    }

    clear_scroll_indicator(start_row - 1, fb_console);
    clear_scroll_indicator(start_row + visible_rows, fb_console);
    if scroll_offset > 0 {
        draw_scroll_indicator(start_row - 1, "^", fb_console);
    }
    if scroll_offset + visible_rows < total_rows {
        draw_scroll_indicator(start_row + visible_rows, "v", fb_console);
    }

    if menu.entry_count() == 0 {
        draw_status(
            "No bootable media - firmware settings are still available",
            fb_console,
        );
    }

    // Draw help text
    let help_row = rows.saturating_sub(5);
    draw_help(help_row, fb_console, cols);
}

/// Draw a category separator line
fn draw_category_separator(
    category: BootCategory,
    row: usize,
    fb_console: &mut Option<FramebufferConsole>,
    cols: usize,
) {
    let label = category.display_name();

    // Build separator: "--- Category Name ---" style
    let dashes_total = cols.saturating_sub(label.len() + 2); // 2 for spaces around label
    let dashes_left = dashes_total / 2;
    let dashes_right = dashes_total - dashes_left;

    // Serial output
    let ansi_row = row + 1; // ANSI is 1-based
    let _ = write!(SerialWriter, "\x1b[{};1H", ansi_row);
    serial_driver::write_str("\x1b[90m"); // Dark gray

    for _ in 0..dashes_left.min(40) {
        serial_driver::write_str("-");
    }
    serial_driver::write_str(" ");
    serial_driver::write_str(label);
    serial_driver::write_str(" ");
    for _ in 0..dashes_right.min(40) {
        serial_driver::write_str("-");
    }

    serial_driver::write_str("\x1b[0m\x1b[K\r\n");

    // Framebuffer output
    if let Some(console) = fb_console {
        console.set_position(0, row as u32);
        console.set_fg_color(Color::new(128, 128, 128)); // Gray

        for _ in 0..dashes_left.min(40) {
            let _ = console.write_str("-");
        }
        let _ = console.write_str(" ");
        let _ = console.write_str(label);
        let _ = console.write_str(" ");
        for _ in 0..dashes_right.min(40) {
            let _ = console.write_str("-");
        }

        // Clear rest of line
        let (col, _) = console.position();
        let term_cols = console.cols();
        for _ in col..term_cols {
            let _ = console.write_str(" ");
        }

        console.reset_colors();
    }
}

fn draw_header(fb_console: &mut Option<FramebufferConsole>, cols: usize) {
    menu_common::draw_header(MENU_TITLE, fb_console, cols);
}

/// Draw a single boot entry
fn draw_entry(
    index: usize,
    entry: &BootEntry,
    is_selected: bool,
    row: usize,
    fb_console: &mut Option<FramebufferConsole>,
    _cols: usize,
) {
    let mut desc: String<128> = String::new();
    entry.format_description(&mut desc);

    // Build the line
    let marker = if is_selected { "[*]" } else { "[ ]" };

    // Serial output
    let ansi_row = row + 1; // ANSI is 1-based
    let _ = write!(SerialWriter, "\x1b[{};1H", ansi_row); // Position cursor

    if is_selected {
        serial_driver::write_str("\x1b[7m"); // Inverse video
    }

    let _ = write!(SerialWriter, "   {}. {} {}", index + 1, marker, desc);

    if is_selected {
        serial_driver::write_str("\x1b[0m"); // Reset
    }

    // Clear rest of line
    serial_driver::write_str("\x1b[K\r\n");

    // Framebuffer output
    if let Some(console) = fb_console {
        console.set_position(3, row as u32);

        if is_selected {
            console.set_colors(HIGHLIGHT_FG, HIGHLIGHT_BG);
        } else {
            console.set_colors(DEFAULT_FG, DEFAULT_BG);
        }

        let _ = write!(console, "{}. {} {}", index + 1, marker, desc);

        // Clear rest of line with spaces
        let (col, _) = console.position();
        let cols = console.cols();
        for _ in col..cols {
            let _ = console.write_str(" ");
        }

        console.reset_colors();
    }
}

/// Clear a possible scroll indicator row.
fn clear_scroll_indicator(row: usize, fb_console: &mut Option<FramebufferConsole>) {
    let ansi_row = row + 1;
    let _ = write!(SerialWriter, "\x1b[{};40H ", ansi_row);

    if let Some(console) = fb_console {
        let cols = console.cols();
        console.set_position(cols / 2, row as u32);
        let _ = console.write_str(" ");
    }
}

/// Draw a simple scroll indicator when the menu does not fit on screen.
fn draw_scroll_indicator(row: usize, indicator: &str, fb_console: &mut Option<FramebufferConsole>) {
    let ansi_row = row + 1;
    let _ = write!(SerialWriter, "\x1b[{};40H{}", ansi_row, indicator);

    if let Some(console) = fb_console {
        let cols = console.cols();
        console.set_position(cols / 2, row as u32);
        console.set_fg_color(Color::new(128, 128, 128));
        let _ = console.write_str(indicator);
        console.reset_colors();
    }
}

/// Draw the help text
fn draw_help(row: usize, fb_console: &mut Option<FramebufferConsole>, cols: usize) {
    menu_common::draw_help(row, HELP_TEXT, fb_console, cols);
}

/// Draw the countdown timer
fn draw_countdown(seconds: u32, fb_console: &mut Option<FramebufferConsole>) {
    let mut msg: String<64> = String::new();
    if seconds > 0 {
        let _ = write!(msg, "Booting in {} seconds...", seconds);
    } else {
        let _ = write!(msg, "Booting now...");
    }

    // Serial output - position at bottom area
    serial_driver::write_str("\x1b[20;1H"); // Row 20
    serial_driver::write_str("\x1b[33m"); // Yellow
    serial_driver::write_str(&msg);
    serial_driver::write_str("\x1b[K"); // Clear rest of line
    serial_driver::write_str("\x1b[0m");

    // Framebuffer output
    if let Some(console) = fb_console {
        let row = console.rows().saturating_sub(3);
        console.set_fg_color(Color::new(255, 255, 0)); // Yellow
        console.write_centered(row, &msg);
        console.reset_colors();
    }
}

/// Draw a status message (always red — used for errors)
fn draw_status(message: &str, fb_console: &mut Option<FramebufferConsole>) {
    let row = fb_console
        .as_ref()
        .map(|c| c.rows() as usize)
        .unwrap_or(25)
        .saturating_sub(1);
    menu_common::draw_status_message(row, message, false, fb_console);
}

/// Result of command line editing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EditResult {
    /// Edit cancelled (Escape) - drop the edited buffer
    Cancelled,
    /// Edit confirmed (Enter) - keep the edited buffer, return to menu
    Confirmed,
    /// Boot now (Ctrl+X) - keep the edited buffer and boot immediately
    Boot,
}

/// Edit the command line of a boot entry
///
/// Displays a full-screen editor for the kernel command line.
///
/// # Arguments
///
/// * `entry_name` - Display name of the entry being edited
/// * `initial` - Command line to start editing from
/// * `fb_console` - Optional framebuffer console for display
///
/// # Returns
///
/// The returned buffer is the edited text; the caller records it as the
/// menu's one-shot override for `Confirmed`/`Boot` and drops it otherwise.
/// Nothing is written into the entry here.
///
/// `EditResult::Cancelled` if the user pressed Escape
/// `EditResult::Confirmed` if the user pressed Enter (return to menu)
/// `EditResult::Boot` if the user pressed Ctrl+X (boot immediately)
fn edit_cmdline(
    entry_name: &str,
    initial: &str,
    fb_console: &mut Option<FramebufferConsole>,
) -> (EditResult, String<512>) {
    // Create a working buffer for editing
    let mut buffer: String<512> = String::new();
    let _ = buffer.push_str(initial);
    let mut cursor_pos = buffer.len();

    // Calculate scroll offset for long command lines
    let cols = fb_console.as_ref().map(|c| c.cols()).unwrap_or(80) as usize;
    let edit_width = cols.saturating_sub(4); // Leave margin for decoration

    // Draw static parts once
    draw_cmdline_editor_static(entry_name, fb_console, cols);

    // Track if display needs updating
    let mut needs_redraw = true;

    loop {
        // Only redraw if something changed
        if needs_redraw {
            draw_cmdline_editor_line(&buffer, cursor_pos, edit_width, fb_console);
            needs_redraw = false;
        }

        // Wait for input
        if let Some(key) = menu_common::read_key() {
            match key {
                KeyPress::Enter => {
                    return (EditResult::Confirmed, buffer);
                }
                KeyPress::Escape => {
                    // Cancel - caller drops the buffer
                    return (EditResult::Cancelled, buffer);
                }
                KeyPress::Char(c) => {
                    // Handle special characters
                    match c {
                        '\x18' => {
                            // Ctrl+X - boot immediately
                            return (EditResult::Boot, buffer);
                        }
                        '\x08' | '\x7f' if cursor_pos > 0 => {
                            // Backspace - remove character before cursor
                            let mut new_buffer: String<512> = String::new();
                            for (i, ch) in buffer.chars().enumerate() {
                                if i != cursor_pos - 1 {
                                    let _ = new_buffer.push(ch);
                                }
                            }
                            buffer = new_buffer;
                            cursor_pos -= 1;
                            needs_redraw = true;
                        }
                        '\x01' if cursor_pos != 0 => {
                            // Ctrl+A - move to beginning
                            cursor_pos = 0;
                            needs_redraw = true;
                        }
                        '\x05' if cursor_pos != buffer.len() => {
                            // Ctrl+E - move to end
                            cursor_pos = buffer.len();
                            needs_redraw = true;
                        }
                        '\x0b' if cursor_pos < buffer.len() => {
                            // Ctrl+K - delete to end of line
                            let mut new_buffer: String<512> = String::new();
                            for (i, ch) in buffer.chars().enumerate() {
                                if i < cursor_pos {
                                    let _ = new_buffer.push(ch);
                                }
                            }
                            buffer = new_buffer;
                            needs_redraw = true;
                        }
                        '\x15' if cursor_pos > 0 => {
                            // Ctrl+U - delete to beginning of line
                            let mut new_buffer: String<512> = String::new();
                            for (i, ch) in buffer.chars().enumerate() {
                                if i >= cursor_pos {
                                    let _ = new_buffer.push(ch);
                                }
                            }
                            buffer = new_buffer;
                            cursor_pos = 0;
                            needs_redraw = true;
                        }
                        _ if (c.is_ascii_graphic() || c == ' ') && buffer.len() < 511 => {
                            // Regular printable character - insert at cursor (ASCII only)
                            let mut new_buffer: String<512> = String::new();
                            for (i, ch) in buffer.chars().enumerate() {
                                if i == cursor_pos {
                                    let _ = new_buffer.push(c);
                                }
                                let _ = new_buffer.push(ch);
                            }
                            if cursor_pos == buffer.len() {
                                let _ = new_buffer.push(c);
                            }
                            buffer = new_buffer;
                            cursor_pos += 1;
                            needs_redraw = true;
                        }
                        _ => {}
                    }
                }
                KeyPress::Left => {
                    // Move cursor left
                    if cursor_pos > 0 {
                        cursor_pos -= 1;
                        needs_redraw = true;
                    }
                }
                KeyPress::Right => {
                    // Move cursor right
                    if cursor_pos < buffer.len() {
                        cursor_pos += 1;
                        needs_redraw = true;
                    }
                }
                KeyPress::Home => {
                    cursor_pos = 0;
                    needs_redraw = true;
                }
                KeyPress::End => {
                    cursor_pos = buffer.len();
                    needs_redraw = true;
                }
                // These have no meaning in the legacy single-line editor.
                KeyPress::Up
                | KeyPress::Down
                | KeyPress::PageUp
                | KeyPress::PageDown
                | KeyPress::Tab
                | KeyPress::BackTab
                | KeyPress::Delete
                | KeyPress::F8
                | KeyPress::F10 => {}
                // Mouse events are ignored in the command line editor
                KeyPress::MouseClick { .. } | KeyPress::MouseScroll(_) => {}
            }
        }

        delay_ms(10);
    }
}

/// Draw the static parts of the command line editor UI (header, title, help)
/// This is called once when entering the editor.
fn draw_cmdline_editor_static(
    entry_name: &str,
    fb_console: &mut Option<FramebufferConsole>,
    cols: usize,
) {
    let title = "Edit Kernel Command Line";

    // Serial output - clear and draw static content
    serial_driver::write_str("\x1b[2J\x1b[H"); // Clear and home
    serial_driver::write_str("\x1b[1;33m"); // Yellow, bold

    // Draw header
    let header_line = [b'='; 128];
    let header_len = cols.min(128);
    serial_driver::write_str(core::str::from_utf8(&header_line[..header_len]).unwrap_or(""));
    serial_driver::write_str("\r\n");

    // Title
    let title_pad = (cols.saturating_sub(title.len())) / 2;
    for _ in 0..title_pad {
        serial_driver::write_str(" ");
    }
    serial_driver::write_str(title);
    serial_driver::write_str("\r\n");

    serial_driver::write_str(core::str::from_utf8(&header_line[..header_len]).unwrap_or(""));
    serial_driver::write_str("\r\n\x1b[0m");

    // Entry name
    serial_driver::write_str("\x1b[36m"); // Cyan
    serial_driver::write_str("Entry: ");
    serial_driver::write_str(entry_name);
    serial_driver::write_str("\x1b[0m\r\n\r\n");

    // Command line label
    serial_driver::write_str("Command line:\r\n");

    // Leave space for edit line (row 7)
    serial_driver::write_str("\r\n\r\n");

    // Help text (row 9-10)
    serial_driver::write_str("\x1b[36m"); // Cyan
    serial_driver::write_str(
        "Enter: Confirm | Esc: Cancel | Ctrl+X: Boot | Left/Right: Move cursor\r\n",
    );
    serial_driver::write_str(
        "Ctrl+A: Start | Ctrl+E: End | Ctrl+K: Delete to end | Ctrl+U: Delete to start",
    );
    serial_driver::write_str("\x1b[0m\r\n");

    // Framebuffer output
    if let Some(console) = fb_console {
        console.clear();

        // Header
        console.set_fg_color(TITLE_COLOR);
        let mut header: String<128> = String::new();
        for _ in 0..cols {
            let _ = header.push('=');
        }
        console.set_position(0, 0);
        let _ = console.write_str(&header);
        console.write_centered(1, title);
        console.set_position(0, 2);
        let _ = console.write_str(&header);
        console.reset_colors();

        // Entry name
        console.set_position(0, 4);
        console.set_fg_color(Color::new(0, 192, 192)); // Cyan
        let _ = console.write_str("Entry: ");
        console.reset_colors();
        let _ = console.write_str(entry_name);

        // Command line label
        console.set_position(0, 6);
        let _ = console.write_str("Command line:");

        // Help text
        console.set_position(0, 9);
        console.set_fg_color(Color::new(0, 192, 192));
        let _ = console
            .write_str("Enter: Confirm | Esc: Cancel | Ctrl+X: Boot | Left/Right: Move cursor");
        console.set_position(0, 10);
        let _ = console.write_str(
            "Ctrl+A: Start | Ctrl+E: End | Ctrl+K: Delete to end | Ctrl+U: Delete to start",
        );
        console.reset_colors();
    }
}

/// Draw just the edit line and length indicator (called on each change)
fn draw_cmdline_editor_line(
    buffer: &str,
    cursor_pos: usize,
    edit_width: usize,
    fb_console: &mut Option<FramebufferConsole>,
) {
    // Calculate visible portion of the buffer (scroll if needed)
    let buffer_len = buffer.len();
    let (visible_start, visible_end, display_cursor) = if buffer_len <= edit_width {
        (0, buffer_len, cursor_pos)
    } else if cursor_pos < edit_width / 2 {
        // Cursor near start - show from beginning
        (0, edit_width, cursor_pos)
    } else if cursor_pos > buffer_len.saturating_sub(edit_width / 2) {
        // Cursor near end - show end portion
        let start = buffer_len.saturating_sub(edit_width);
        (start, buffer_len, cursor_pos - start)
    } else {
        // Cursor in middle - center the view
        let start = cursor_pos - edit_width / 2;
        let end = start + edit_width;
        (start, end.min(buffer_len), edit_width / 2)
    };

    let visible_text = &buffer[visible_start..visible_end];

    // Serial output - position cursor at edit line (row 7)
    serial_driver::write_str("\x1b[7;1H"); // Row 7, column 1
    serial_driver::write_str("\x1b[K"); // Clear line
    serial_driver::write_str("\x1b[44m"); // Blue background

    // Show scroll indicators
    if visible_start > 0 {
        serial_driver::write_str("<");
    } else {
        serial_driver::write_str(" ");
    }

    // Draw text before cursor
    if display_cursor > 0 {
        serial_driver::write_str(&visible_text[..display_cursor]);
    }

    // Draw cursor position with inverse video
    serial_driver::write_str("\x1b[7m"); // Inverse
    if display_cursor < visible_text.len() {
        let cursor_char = &visible_text[display_cursor..display_cursor + 1];
        serial_driver::write_str(cursor_char);
    } else {
        serial_driver::write_str(" ");
    }
    serial_driver::write_str("\x1b[27m"); // Normal (but still blue bg)

    // Draw text after cursor
    if display_cursor < visible_text.len() {
        serial_driver::write_str(&visible_text[display_cursor + 1..]);
    }

    // Pad to width and show scroll indicator
    let displayed_len = visible_text.len() + 2; // +2 for scroll indicators
    for _ in displayed_len..edit_width {
        serial_driver::write_str(" ");
    }

    if visible_end < buffer_len {
        serial_driver::write_str(">");
    } else {
        serial_driver::write_str(" ");
    }

    serial_driver::write_str("\x1b[0m"); // Reset colors

    // Length indicator (row 12)
    serial_driver::write_str("\x1b[12;1H"); // Row 12
    serial_driver::write_str("\x1b[K"); // Clear line
    let _ = write!(SerialWriter, "\x1b[33mLength: {}/512\x1b[0m", buffer_len);

    // Framebuffer output - only update edit line and length
    if let Some(console) = fb_console {
        // Edit area with blue background (row 7)
        console.set_position(0, 7);
        console.set_colors(DEFAULT_FG, Color::new(0, 0, 128)); // Blue bg

        // Scroll indicator left
        if visible_start > 0 {
            let _ = console.write_str("<");
        } else {
            let _ = console.write_str(" ");
        }

        // Text before cursor
        if display_cursor > 0 {
            let _ = console.write_str(&visible_text[..display_cursor]);
        }

        // Cursor with highlight
        console.set_colors(HIGHLIGHT_FG, HIGHLIGHT_BG);
        if display_cursor < visible_text.len() {
            let _ = console.write_str(&visible_text[display_cursor..display_cursor + 1]);
        } else {
            let _ = console.write_str(" ");
        }
        console.set_colors(DEFAULT_FG, Color::new(0, 0, 128));

        // Text after cursor
        if display_cursor < visible_text.len() {
            let _ = console.write_str(&visible_text[display_cursor + 1..]);
        }

        // Pad and right scroll indicator
        let displayed_len = visible_text.len() + 2;
        for _ in displayed_len..edit_width {
            let _ = console.write_str(" ");
        }
        if visible_end < buffer_len {
            let _ = console.write_str(">");
        } else {
            let _ = console.write_str(" ");
        }
        console.reset_colors();

        // Length indicator (row 12)
        console.set_position(0, 12);
        console.set_fg_color(Color::new(255, 255, 0)); // Yellow
        let mut len_str: String<32> = String::new();
        let _ = write!(len_str, "Length: {}/512    ", buffer_len); // Extra spaces to clear old longer values
        let _ = console.write_str(&len_str);
        console.reset_colors();
    }
}

#[cfg(test)]
mod disk_detail_tests {
    use super::*;

    #[test]
    fn disk_details_distinguish_controllers_and_namespaces() {
        assert_ne!(
            storage_identity(StorageId::Ahci {
                controller_id: 0,
                port: 1
            }),
            storage_identity(StorageId::Ahci {
                controller_id: 1,
                port: 1
            })
        );
        assert!(
            storage_identity(StorageId::Nvme {
                controller_id: 2,
                nsid: 3
            })
            .contains("namespace 3")
        );
        assert!(
            storage_identity(StorageId::Usb {
                controller_id: 4,
                device_addr: 5
            })
            .contains("controller 4")
        );
    }
}

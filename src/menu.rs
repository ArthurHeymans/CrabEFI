//! Boot Menu Module
//!
//! This module provides a boot menu that displays on both serial console and
//! framebuffer, allowing users to select from discovered boot entries.
//!
//! # Features
//!
//! - Discovers boot entries from NVMe, AHCI, USB, and SD card storage devices
//! - Supports multiple boot entry types:
//!   - UEFI bootloaders (EFI\\BOOT\\BOOTX64.EFI)
//!   - BLS (Boot Loader Specification) entries in /loader/entries/
//!   - GRUB configuration entries from grub.cfg
//!   - Coreboot payload chainloading
//! - Displays menu on serial (with ANSI escape codes) and framebuffer
//! - Arrow key navigation and Enter to select
//! - Configurable auto-boot timeout with countdown

use crate::coreboot;
use crate::drivers::block::BlockDevice;
use crate::fs::{fat::FatFilesystem, gpt, iso9660};
use crate::time::{Timeout, delay_ms};
use core::fmt::Write;
use heapless::{String, Vec};

/// Maximum number of boot entries
/// Increased to accommodate BLS, GRUB, and payload entries
const MAX_BOOT_ENTRIES: usize = 16;

/// Default timeout in seconds for auto-boot
const DEFAULT_TIMEOUT_SECONDS: u32 = 5;

/// Menu title
const MENU_TITLE: &str = "CrabEFI Boot Menu";

/// Help text
const HELP_TEXT: &str =
    "Arrows: Select | Enter: Boot | F: Firmware | C: Cmdline | S: Secure Boot | R: Reset";

/// Storage device type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    /// NVMe SSD
    Nvme { controller_id: usize, nsid: u32 },
    /// AHCI/SATA disk
    Ahci { controller_id: usize, port: usize },
    /// USB mass storage (any controller type)
    Usb {
        controller_id: usize,
        device_addr: u8,
    },
    /// SDHCI (SD card)
    Sdhci { controller_id: usize },
}

/// Boot entry kind - how this entry should be booted
#[derive(Debug, Clone, Default)]
pub enum BootEntryKind {
    /// UEFI executable (EFI\BOOT\BOOTX64.EFI)
    #[default]
    Uefi,

    /// BLS Type #1 - direct Linux boot
    BlsLinux {
        /// Path to Linux kernel
        linux_path: String<128>,
        /// Path to initrd
        initrd_path: String<128>,
        /// Kernel command line
        cmdline: String<512>,
    },

    /// BLS Type #2 - Unified Kernel Image (still EFI)
    BlsUki,

    /// GRUB menu entry - direct Linux boot
    GrubLinux {
        /// Path to Linux kernel
        linux_path: String<128>,
        /// Path to initrd
        initrd_path: String<128>,
        /// Kernel command line
        cmdline: String<512>,
    },

    /// Coreboot payload (ELF or flat binary)
    Payload {
        /// Path to payload file
        path: String<128>,
        /// Payload format
        format: crate::payload::PayloadFormat,
    },
}

/// Category for menu grouping
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootCategory {
    /// UEFI boot entries (BOOTX64.EFI)
    Uefi,
    /// Boot Loader Specification entries
    Bls,
    /// GRUB configuration entries
    Grub,
    /// Coreboot payload entries
    Payload,
}

impl BootCategory {
    /// Get a display name for this category
    pub fn display_name(&self) -> &'static str {
        match self {
            BootCategory::Uefi => "UEFI Boot",
            BootCategory::Bls => "Boot Loader Spec",
            BootCategory::Grub => "GRUB Entries",
            BootCategory::Payload => "Coreboot Payloads",
        }
    }
}

impl DeviceType {
    /// Get a short description of the device type
    pub fn description(&self) -> &'static str {
        match self {
            DeviceType::Nvme { .. } => "NVMe",
            DeviceType::Ahci { .. } => "SATA",
            DeviceType::Usb { .. } => "USB",
            DeviceType::Sdhci { .. } => "SD",
        }
    }
}

/// A boot entry discovered on storage media
#[derive(Debug, Clone)]
pub struct BootEntry {
    /// Display name for the menu
    pub name: String<64>,
    /// Path to the EFI application (for UEFI entries)
    pub path: String<128>,
    /// Device type and identifier
    pub device_type: DeviceType,
    /// Partition number (1-based)
    pub partition_num: u32,
    /// Partition information
    pub partition: gpt::Partition,
    /// PCI device number
    pub pci_device: u8,
    /// PCI function number
    pub pci_function: u8,
    /// Boot entry kind (how to boot this entry)
    pub kind: BootEntryKind,
    /// Boot category (for menu grouping)
    pub category: BootCategory,
}

impl BootEntry {
    /// Create a new boot entry (defaults to UEFI type)
    pub fn new(
        name: &str,
        path: &str,
        device_type: DeviceType,
        partition_num: u32,
        partition: gpt::Partition,
        pci_device: u8,
        pci_function: u8,
    ) -> Self {
        let mut entry = BootEntry {
            name: String::new(),
            path: String::new(),
            device_type,
            partition_num,
            partition,
            pci_device,
            pci_function,
            kind: BootEntryKind::Uefi,
            category: BootCategory::Uefi,
        };
        let _ = entry.name.push_str(name);
        let _ = entry.path.push_str(path);
        entry
    }

    /// Create a new boot entry with specific kind and category
    pub fn new_with_kind(
        name: &str,
        path: &str,
        device_type: DeviceType,
        partition_num: u32,
        partition: gpt::Partition,
        pci_device: u8,
        pci_function: u8,
        kind: BootEntryKind,
        category: BootCategory,
    ) -> Self {
        let mut entry = BootEntry {
            name: String::new(),
            path: String::new(),
            device_type,
            partition_num,
            partition,
            pci_device,
            pci_function,
            kind,
            category,
        };
        let _ = entry.name.push_str(name);
        let _ = entry.path.push_str(path);
        entry
    }

    /// Format a description for display
    pub fn format_description(&self, buf: &mut String<128>) {
        buf.clear();
        let _ = write!(
            buf,
            "{} ({}, partition {})",
            self.name,
            self.device_type.description(),
            self.partition_num
        );
    }

    /// Check if this is a direct Linux boot entry
    pub fn is_linux_boot(&self) -> bool {
        matches!(
            self.kind,
            BootEntryKind::BlsLinux { .. } | BootEntryKind::GrubLinux { .. }
        )
    }

    /// Check if this is a UEFI entry
    pub fn is_uefi(&self) -> bool {
        matches!(self.kind, BootEntryKind::Uefi | BootEntryKind::BlsUki)
    }

    /// Check if this is a payload entry
    pub fn is_payload(&self) -> bool {
        matches!(self.kind, BootEntryKind::Payload { .. })
    }

    /// Check if this entry has an editable command line
    pub fn has_cmdline(&self) -> bool {
        matches!(
            self.kind,
            BootEntryKind::BlsLinux { .. } | BootEntryKind::GrubLinux { .. }
        )
    }

    /// Get a reference to the command line, if any
    pub fn get_cmdline(&self) -> Option<&String<512>> {
        match &self.kind {
            BootEntryKind::BlsLinux { cmdline, .. } | BootEntryKind::GrubLinux { cmdline, .. } => {
                Some(cmdline)
            }
            _ => None,
        }
    }

    /// Get a mutable reference to the command line, if any
    pub fn get_cmdline_mut(&mut self) -> Option<&mut String<512>> {
        match &mut self.kind {
            BootEntryKind::BlsLinux { cmdline, .. } | BootEntryKind::GrubLinux { cmdline, .. } => {
                Some(cmdline)
            }
            _ => None,
        }
    }
}

/// Boot menu state
pub struct BootMenu {
    /// Discovered boot entries
    entries: Vec<BootEntry, MAX_BOOT_ENTRIES>,
    /// Currently selected entry index
    selected: usize,
    /// Timeout in seconds (0 = no timeout)
    timeout_seconds: u32,
}

impl Default for BootMenu {
    fn default() -> Self {
        Self::new()
    }
}

impl BootMenu {
    /// Create a new boot menu
    pub fn new() -> Self {
        BootMenu {
            entries: Vec::new(),
            selected: 0,
            timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        }
    }

    /// Add a boot entry
    pub fn add_entry(&mut self, entry: BootEntry) -> bool {
        self.entries.push(entry).is_ok()
    }

    /// Get the number of entries
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get a reference to an entry
    pub fn get_entry(&self, index: usize) -> Option<&BootEntry> {
        self.entries.get(index)
    }

    /// Get the selected entry
    pub fn selected_entry(&self) -> Option<&BootEntry> {
        self.entries.get(self.selected)
    }

    /// Move selection up
    pub fn select_previous(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    /// Move selection down
    pub fn select_next(&mut self) {
        if self.selected + 1 < self.entries.len() {
            self.selected += 1;
        }
    }

    /// Set the timeout
    pub fn set_timeout(&mut self, seconds: u32) {
        self.timeout_seconds = seconds;
    }
}

/// Discover boot entries from all storage devices
///
/// Scans NVMe, AHCI, and USB devices for ESPs containing `EFI\BOOT\BOOTX64.EFI`.
///
/// # Returns
///
/// A `BootMenu` containing all discovered boot entries.
pub fn discover_boot_entries() -> BootMenu {
    let mut menu = BootMenu::new();

    log::info!("Discovering boot entries...");

    // Scan NVMe devices
    discover_nvme_entries(&mut menu);

    // Scan AHCI devices
    discover_ahci_entries(&mut menu);

    // Scan USB devices
    discover_usb_entries(&mut menu);

    // Scan SDHCI devices (SD cards)
    discover_sdhci_entries(&mut menu);

    log::info!("Found {} boot entries", menu.entry_count());

    menu
}

/// Discover boot entries on a disk that has already been stored globally.
///
/// Reads the GPT partition table, then for each ESP (or potential ESP) partition,
/// mounts the FAT filesystem, checks for `EFI\BOOT\BOOTX64.EFI`, and scans for
/// additional BLS/GRUB/payload entries.
///
/// # Arguments
///
/// * `device_type` - Device type for the boot entries
/// * `pci_device` - PCI device number
/// * `pci_function` - PCI function number
/// * `name_prefix` - Display name prefix (e.g. "NVMe ns1", "SATA port 0")
/// * `menu` - Boot menu to add entries to
fn discover_entries_on_disk(
    device_type: DeviceType,
    pci_device: u8,
    pci_function: u8,
    name_prefix: &str,
    menu: &mut BootMenu,
) {
    // Phase 1: Read GPT and clone partitions out (releases the disk borrow)
    let partitions = crate::with_disk(&device_type, |disk| {
        if let Ok(header) = gpt::read_gpt_header(disk)
            && let Ok(parts) = gpt::read_partitions(disk, &header)
        {
            Some(parts)
        } else {
            None
        }
    })
    .flatten();

    let partitions = match partitions {
        Some(p) => p,
        None => return,
    };

    // Phase 2: For each ESP partition, mount FAT and scan for entries
    for (i, partition) in partitions.iter().enumerate() {
        let partition_num = (i + 1) as u32;

        if !partition.is_esp && !is_potential_esp(partition) {
            continue;
        }

        // Create a fresh disk for FAT mounting
        crate::with_disk(&device_type, |disk| {
            let mut fat = match FatFilesystem::new(disk, partition.first_lba) {
                Ok(f) => f,
                Err(_) => return,
            };

            // Check for UEFI bootloader
            if fat.file_size("EFI\\BOOT\\BOOTX64.EFI").is_ok() {
                let mut name: String<64> = String::new();
                let _ = write!(name, "Boot Entry ({})", name_prefix);

                let entry = BootEntry::new(
                    &name,
                    "EFI\\BOOT\\BOOTX64.EFI",
                    device_type,
                    partition_num,
                    partition.clone(),
                    pci_device,
                    pci_function,
                );

                if !menu.add_entry(entry) {
                    return; // Menu full
                }
            }

            // Scan for additional entries (BLS, GRUB, payloads)
            scan_partition_for_entries(
                &mut fat,
                device_type,
                partition_num,
                partition,
                pci_device,
                pci_function,
                menu,
            );
        });
    }
}

/// Discover boot entries from NVMe devices
fn discover_nvme_entries(menu: &mut BootMenu) {
    use crate::drivers::nvme;

    let Some(controller_ptr) = nvme::get_controller(0) else {
        return;
    };
    // Safety: pointer valid for firmware lifetime; no overlapping &mut created
    let controller = unsafe { &mut *controller_ptr };
    let Some(ns) = controller.default_namespace() else {
        return;
    };
    let nsid = ns.nsid;
    let pci_addr = controller.pci_address();

    if !nvme::store_global_device(0, nsid) {
        return;
    }

    let mut name_prefix: String<32> = String::new();
    let _ = write!(name_prefix, "NVMe ns{}", nsid);
    discover_entries_on_disk(
        DeviceType::Nvme {
            controller_id: 0,
            nsid,
        },
        pci_addr.device,
        pci_addr.function,
        &name_prefix,
        menu,
    );
}

/// Discover boot entries from AHCI devices
fn discover_ahci_entries(menu: &mut BootMenu) {
    use crate::drivers::ahci;

    let Some(controller_ptr) = ahci::get_controller(0) else {
        return;
    };
    // Safety: pointer valid for firmware lifetime; no overlapping &mut created
    let controller = unsafe { &mut *controller_ptr };
    let pci_addr = controller.pci_address();
    let num_ports = controller.num_active_ports();

    for port_index in 0..num_ports {
        if !ahci::store_global_device(0, port_index) {
            continue;
        }

        let device_type = DeviceType::Ahci {
            controller_id: 0,
            port: port_index,
        };

        let mut name_prefix: String<32> = String::new();
        let _ = write!(name_prefix, "SATA port {}", port_index);

        // Try GPT-based discovery first
        let had_gpt = crate::with_disk(&device_type, |disk| gpt::read_gpt_header(disk).is_ok())
            .unwrap_or(false);

        if had_gpt {
            discover_entries_on_disk(
                device_type,
                pci_addr.device,
                pci_addr.function,
                &name_prefix,
                menu,
            );
        } else {
            // GPT failed — try El Torito (ISO9660) as fallback
            try_el_torito_fallback(device_type, pci_addr.device, pci_addr.function, menu);
        }
    }
}

/// Try El Torito (ISO9660) boot as a fallback for AHCI devices without GPT
fn try_el_torito_fallback(
    device_type: DeviceType,
    pci_device: u8,
    pci_function: u8,
    menu: &mut BootMenu,
) {
    crate::with_disk(&device_type, |disk| {
        let efi_image = match iso9660::find_efi_boot_image(disk) {
            Ok(img) => img,
            Err(_) => return,
        };

        if efi_image.sector_count == 0 {
            log::warn!("El Torito: EFI image has unknown size, skipping");
            return;
        }

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

        let name_suffix = match device_type {
            DeviceType::Ahci { port, .. } => {
                let mut s: String<32> = String::new();
                let _ = write!(s, "SATA port {}", port);
                s
            }
            _ => {
                let mut s: String<32> = String::new();
                let _ = s.push_str(device_type.description());
                s
            }
        };
        let mut name: String<64> = String::new();
        let _ = write!(name, "ISO Boot ({})", name_suffix);

        let entry = BootEntry::new(
            &name,
            "EFI\\BOOT\\BOOTX64.EFI",
            device_type,
            0, // No partition number for El Torito
            partition,
            pci_device,
            pci_function,
        );

        menu.add_entry(entry);
    });
}

/// Discover boot entries from USB devices (all controller types)
fn discover_usb_entries(menu: &mut BootMenu) {
    use crate::drivers::usb::{self, UsbMassStorage, mass_storage};

    let Some((controller_id, device_addr)) = usb::find_mass_storage() else {
        return;
    };

    log::info!(
        "Found USB mass storage on controller {}, device {}",
        controller_id,
        device_addr
    );

    let Some(controller_ptr) = usb::get_controller_ptr(controller_id) else {
        log::error!("Failed to get controller {} pointer", controller_id);
        return;
    };

    // Create and store the mass storage device
    let device_created = usb::with_controller(controller_id, |controller| {
        match UsbMassStorage::new(controller, device_addr) {
            Ok(usb_device) => {
                if usb_device.num_blocks == 0 {
                    log::info!("USB Mass Storage: no media present, skipping");
                    return false;
                }
                // SAFETY: controller_ptr is obtained from get_controller_ptr and is valid
                unsafe {
                    mass_storage::store_global_device_with_controller_ptr(
                        usb_device,
                        controller_ptr,
                    )
                }
            }
            Err(e) => {
                log::debug!("Failed to create USB mass storage: {:?}", e);
                false
            }
        }
    });

    if device_created != Some(true) {
        return;
    }

    // Get controller type for the display name
    let controller_type = usb::with_controller(controller_id, |c| c.controller_type());
    let mut name_prefix: String<32> = String::new();
    if let Some(ct) = controller_type {
        let _ = write!(name_prefix, "{} USB", ct);
    } else {
        let _ = name_prefix.push_str("USB");
    }

    let device_type = DeviceType::Usb {
        controller_id,
        device_addr,
    };

    // USB uses the same shared discovery path — with_disk handles USB via
    // mass_storage::get_global_device() + get_controller_ptr()
    discover_entries_on_disk(
        device_type,
        0, // PCI device - TODO: get from controller
        0, // PCI function - TODO: get from controller
        &name_prefix,
        menu,
    );
}

/// Discover boot entries from SDHCI devices (SD cards)
fn discover_sdhci_entries(menu: &mut BootMenu) {
    use crate::drivers::sdhci;

    for controller_id in 0..sdhci::controller_count() {
        let Some(controller_ptr) = sdhci::get_controller(controller_id) else {
            continue;
        };
        // Safety: pointer valid for firmware lifetime
        let controller = unsafe { &mut *controller_ptr };
        if !controller.is_ready() {
            continue;
        }
        let pci_addr = controller.pci_address();

        if !sdhci::store_global_device(controller_id) {
            continue;
        }

        discover_entries_on_disk(
            DeviceType::Sdhci { controller_id },
            pci_addr.device,
            pci_addr.function,
            "SD card",
            menu,
        );
    }
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
        Ok(mut fat) => match fat.file_size("EFI\\BOOT\\BOOTX64.EFI") {
            Ok(size) => size > 0,
            Err(_) => false,
        },
        Err(_) => false,
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
/// * `device_type` - Device type for the boot entries
/// * `partition_num` - 1-based partition number
/// * `partition` - Partition info
/// * `pci_device` - PCI device number
/// * `pci_function` - PCI function number
/// * `menu` - Boot menu to add entries to
fn scan_partition_for_entries(
    fat: &mut FatFilesystem<'_>,
    device_type: DeviceType,
    partition_num: u32,
    partition: &gpt::Partition,
    pci_device: u8,
    pci_function: u8,
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
                let initrd_fat_path = if !bls_entry.initrd.is_empty() {
                    linux_path_to_fat(&bls_entry.initrd)
                } else {
                    String::new()
                };

                let entry = BootEntry::new_with_kind(
                    &name,
                    &fat_path,
                    device_type,
                    partition_num,
                    partition.clone(),
                    pci_device,
                    pci_function,
                    BootEntryKind::BlsLinux {
                        linux_path: fat_path.clone(),
                        initrd_path: initrd_fat_path,
                        cmdline: bls_entry.options.clone(),
                    },
                    BootCategory::Bls,
                );

                if !menu.add_entry(entry) {
                    return; // Menu full
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

                    // Also convert initrd path
                    let initrd_fat_path = if !grub_entry.initrd.is_empty() {
                        linux_path_to_fat(&grub_entry.initrd)
                    } else {
                        String::new()
                    };

                    let entry = BootEntry::new_with_kind(
                        &name,
                        &fat_path,
                        device_type,
                        partition_num,
                        partition.clone(),
                        pci_device,
                        pci_function,
                        BootEntryKind::GrubLinux {
                            linux_path: fat_path.clone(),
                            initrd_path: initrd_fat_path,
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
    //         device_type,
    //         partition_num,
    //         partition.clone(),
    //         pci_device,
    //         pci_function,
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
pub fn show_menu(menu: &mut BootMenu) -> Option<usize> {
    use alloc::format;
    use alloc::string::ToString;
    use ratatui::Terminal;
    use ratatui::layout::{Alignment, Constraint, Layout};
    use ratatui::style::{Color as TuiColor, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{
        Block, Borders, HighlightSpacing, List, ListItem, ListState, Paragraph,
    };

    if menu.entry_count() == 0 {
        log::error!("No boot entries to display");
        return None;
    }

    // Create the dual backend (serial + framebuffer)
    let fb_info = coreboot::get_framebuffer();
    let backend = crate::tui::DualBackend::new(fb_info.as_ref());
    let mut terminal = match Terminal::new(backend) {
        Ok(t) => t,
        Err(_) => {
            log::error!("Failed to create ratatui terminal");
            return None;
        }
    };
    let _ = terminal.clear();
    let _ = terminal.hide_cursor();

    // Status message shown at the bottom (cleared on next redraw)
    let mut status_msg: Option<alloc::string::String> = None;

    // Handle input with timeout
    let mut remaining_seconds = menu.timeout_seconds;
    let mut last_second_check = Timeout::from_ms(1000);

    // Render helper closure -- builds the ratatui frame
    let render = |terminal: &mut Terminal<crate::tui::DualBackend>,
                  menu: &BootMenu,
                  remaining_seconds: u32,
                  status_msg: &Option<alloc::string::String>| {
        let _ = terminal.draw(|frame| {
            let area = frame.area();

            // Vertical layout: header(3) | entries(fill) | footer(3)
            let chunks = Layout::vertical([
                Constraint::Length(3),  // header
                Constraint::Min(4),    // entry list
                Constraint::Length(3), // countdown + help + status
            ])
            .split(area);

            // --- Header ---
            let header = Paragraph::new(Line::from(MENU_TITLE).alignment(Alignment::Center))
                .style(Style::new().fg(TuiColor::Yellow).add_modifier(Modifier::BOLD))
                .block(
                    Block::new()
                        .borders(Borders::TOP | Borders::BOTTOM)
                        .border_style(Style::new().fg(TuiColor::Yellow)),
                );
            frame.render_widget(header, chunks[0]);

            // --- Build list items with category separators ---
            let mut items: alloc::vec::Vec<ListItem> = alloc::vec::Vec::new();
            let mut entry_index_map: alloc::vec::Vec<Option<usize>> = alloc::vec::Vec::new();
            let mut current_category: Option<BootCategory> = None;

            for (i, entry) in menu.entries.iter().enumerate() {
                // Category separator
                if current_category != Some(entry.category) {
                    if current_category.is_some() {
                        items.push(ListItem::new(Line::raw("")));
                        entry_index_map.push(None);
                    }
                    let label = entry.category.display_name();
                    let sep = format!("--- {label} ---");
                    items.push(
                        ListItem::new(Line::from(sep).alignment(Alignment::Center))
                            .style(Style::new().fg(TuiColor::DarkGray)),
                    );
                    entry_index_map.push(None);
                    current_category = Some(entry.category);
                }

                let mut desc: String<128> = String::new();
                entry.format_description(&mut desc);
                let line_text = format!("  {}. {}", i + 1, desc);

                items.push(
                    ListItem::new(Line::raw(line_text)).style(Style::new().fg(TuiColor::Gray)),
                );
                entry_index_map.push(Some(i));
            }

            // Find which list position corresponds to menu.selected
            let selected_list_idx = entry_index_map
                .iter()
                .position(|e| *e == Some(menu.selected));

            let list = List::new(items)
                .highlight_style(
                    Style::new()
                        .fg(TuiColor::Black)
                        .bg(TuiColor::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol(">> ")
                .highlight_spacing(HighlightSpacing::Always)
                .scroll_padding(1);

            let mut list_state = ListState::default().with_selected(selected_list_idx);
            frame.render_stateful_widget(list, chunks[1], &mut list_state);

            // --- Footer: countdown, status, help ---
            let footer_chunks = Layout::vertical([
                Constraint::Length(1), // countdown or status
                Constraint::Length(1), // blank
                Constraint::Length(1), // help
            ])
            .split(chunks[2]);

            // Countdown or status message
            let footer_line = if let Some(msg) = status_msg {
                Line::from(Span::styled(
                    msg.as_str().to_string(),
                    Style::new().fg(TuiColor::Red),
                ))
                .alignment(Alignment::Center)
            } else if remaining_seconds > 0 {
                let msg = format!("Booting in {} seconds...", remaining_seconds);
                Line::from(Span::styled(msg, Style::new().fg(TuiColor::Yellow)))
                    .alignment(Alignment::Center)
            } else {
                Line::raw("")
            };
            frame.render_widget(Paragraph::new(footer_line), footer_chunks[0]);

            // Help text
            let help = Paragraph::new(
                Line::from(HELP_TEXT)
                    .style(Style::new().fg(TuiColor::Cyan))
                    .alignment(Alignment::Center),
            );
            frame.render_widget(help, footer_chunks[2]);
        });
    };

    // Initial render
    render(&mut terminal, menu, remaining_seconds, &status_msg);

    loop {
        // Check for timeout (first tick fires after 1 real second)
        if remaining_seconds > 0 && last_second_check.is_expired() {
            remaining_seconds -= 1;
            last_second_check = Timeout::from_ms(1000);
            status_msg = None;

            render(&mut terminal, menu, remaining_seconds, &status_msg);

            if remaining_seconds == 0 {
                return Some(menu.selected);
            }
        }

        // Check for keypress
        if let Some(key) = read_key() {
            // Any key resets the timeout
            remaining_seconds = menu.timeout_seconds;
            status_msg = None;

            match key {
                KeyPress::Up | KeyPress::Char('k') => {
                    menu.select_previous();
                    render(&mut terminal, menu, remaining_seconds, &status_msg);
                }
                KeyPress::Down | KeyPress::Char('j') => {
                    menu.select_next();
                    render(&mut terminal, menu, remaining_seconds, &status_msg);
                }
                KeyPress::Enter => {
                    if let Some(entry) = menu.entries.get(menu.selected) {
                        log::info!(
                            "Selected entry: name='{}', path='{}'",
                            entry.name,
                            entry.path
                        );
                        status_msg = Some(format!("Booting {}...", entry.name));
                    } else {
                        log::error!("No entry at selected index {}", menu.selected);
                        status_msg = Some("Error: No entry selected".into());
                    }
                    render(&mut terminal, menu, remaining_seconds, &status_msg);
                    return Some(menu.selected);
                }
                KeyPress::Escape => {
                    status_msg = Some("File browser not yet implemented".into());
                    render(&mut terminal, menu, remaining_seconds, &status_msg);
                }
                KeyPress::Char('s') | KeyPress::Char('S') => {
                    // Open Secure Boot settings menu
                    let _ = terminal.clear();
                    crate::secure_boot_menu::show_secure_boot_menu();
                    // Redraw boot menu after returning
                    let _ = terminal.clear();
                    render(&mut terminal, menu, remaining_seconds, &status_msg);
                }
                KeyPress::Char('f') | KeyPress::Char('F') => {
                    // Open Firmware Settings menu
                    let _ = terminal.clear();
                    crate::cfr_menu::show_cfr_menu();
                    let _ = terminal.clear();
                    render(&mut terminal, menu, remaining_seconds, &status_msg);
                }
                KeyPress::Char('r') | KeyPress::Char('R') => {
                    status_msg = Some("Resetting system...".into());
                    render(&mut terminal, menu, remaining_seconds, &status_msg);
                    delay_ms(500);
                    perform_system_reset();
                }
                KeyPress::Char('c') | KeyPress::Char('C') => {
                    // Edit kernel command line
                    if let Some(entry) = menu.entries.get_mut(menu.selected) {
                        if entry.has_cmdline() {
                            match edit_cmdline(entry, &mut terminal) {
                                EditResult::Boot => {
                                    status_msg = Some(format!("Booting {}...", entry.name));
                                    let _ = terminal.clear();
                                    render(&mut terminal, menu, remaining_seconds, &status_msg);
                                    return Some(menu.selected);
                                }
                                EditResult::Confirmed => {
                                    status_msg = Some("Command line updated".into());
                                }
                                EditResult::Cancelled => {
                                    status_msg = Some("Edit cancelled".into());
                                }
                            }
                        } else {
                            status_msg =
                                Some("This entry has no editable command line".into());
                        }
                    }
                    delay_ms(500);
                    let _ = terminal.clear();
                    render(&mut terminal, menu, remaining_seconds, &status_msg);
                }
                KeyPress::Char(c) if c.is_ascii_digit() => {
                    let num = (c as u8 - b'0') as usize;
                    if num > 0 && num <= menu.entry_count() {
                        menu.selected = num - 1;
                        render(&mut terminal, menu, remaining_seconds, &status_msg);
                    }
                }
                _ => {}
            }
        }

        // Small delay to avoid busy-waiting
        delay_ms(10);
    }
}

use crate::menu_common::{self, KeyPress};

fn read_key() -> Option<KeyPress> {
    menu_common::read_key()
}

/// Result of command line editing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EditResult {
    /// Edit cancelled (Escape) - don't modify cmdline
    Cancelled,
    /// Edit confirmed (Enter) - update cmdline and return to menu
    Confirmed,
    /// Boot now (Ctrl+X) - update cmdline and boot immediately
    Boot,
}

/// Edit the command line of a boot entry using ratatui
///
/// Displays a full-screen editor for the kernel command line.
///
/// # Arguments
///
/// * `entry` - The boot entry to edit
/// * `terminal` - The ratatui terminal for rendering
///
/// # Returns
///
/// `EditResult::Cancelled` if the user pressed Escape (cmdline unchanged)
/// `EditResult::Confirmed` if the user pressed Enter (cmdline updated, return to menu)
/// `EditResult::Boot` if the user pressed Ctrl+X (cmdline updated, boot immediately)
fn edit_cmdline(
    entry: &mut BootEntry,
    terminal: &mut ratatui::Terminal<crate::tui::DualBackend>,
) -> EditResult {
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;
    use ratatui::layout::{Alignment, Constraint, Layout};
    use ratatui::style::{Color as TuiColor, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Borders, Paragraph};

    // Check if entry has cmdline and extract initial value
    let initial_cmdline = match entry.get_cmdline() {
        Some(c) => c.clone(),
        None => return EditResult::Cancelled,
    };

    let entry_name: alloc::string::String = entry.name.to_string();
    let mut buffer: String<512> = initial_cmdline;
    let mut cursor_pos = buffer.len();

    let help1 = "Enter: Confirm | Esc: Cancel | Ctrl+X: Boot | Left/Right: Move cursor";
    let help2 = "Ctrl+A: Start | Ctrl+E: End | Ctrl+K: Delete to end | Ctrl+U: Delete to start";

    let _ = terminal.clear();

    let render = |terminal: &mut ratatui::Terminal<crate::tui::DualBackend>,
                  buffer: &str,
                  cursor_pos: usize| {
        let _ = terminal.draw(|frame| {
            let area = frame.area();
            let width = area.width.saturating_sub(4) as usize;

            // Calculate visible window for long command lines
            let buf_len = buffer.len();
            let (vis_start, vis_end, disp_cursor) = if buf_len <= width {
                (0, buf_len, cursor_pos)
            } else if cursor_pos < width / 2 {
                (0, width, cursor_pos)
            } else if cursor_pos > buf_len.saturating_sub(width / 2) {
                let start = buf_len.saturating_sub(width);
                (start, buf_len, cursor_pos - start)
            } else {
                let start = cursor_pos - width / 2;
                (start, (start + width).min(buf_len), width / 2)
            };
            let visible = &buffer[vis_start..vis_end];

            // Build the edit line with cursor highlighting
            let left_indicator = if vis_start > 0 { "<" } else { " " };
            let right_indicator = if vis_end < buf_len { ">" } else { " " };

            let before = &visible[..disp_cursor];
            let cursor_ch = if disp_cursor < visible.len() {
                &visible[disp_cursor..disp_cursor + 1]
            } else {
                " "
            };
            let after = if disp_cursor < visible.len() {
                &visible[disp_cursor + 1..]
            } else {
                ""
            };

            // Pad to fill the edit area width
            let content_len = before.len() + 1 + after.len();
            let padding = width.saturating_sub(content_len);
            let pad_str: alloc::string::String =
                core::iter::repeat(' ').take(padding).collect();

            let edit_line = Line::from(vec![
                Span::raw(left_indicator),
                Span::styled(
                    before.to_string(),
                    Style::new().bg(TuiColor::Blue),
                ),
                Span::styled(
                    cursor_ch.to_string(),
                    Style::new()
                        .fg(TuiColor::Black)
                        .bg(TuiColor::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}{}", after, pad_str),
                    Style::new().bg(TuiColor::Blue),
                ),
                Span::raw(right_indicator),
            ]);

            let length_line = Line::from(Span::styled(
                format!("Length: {}/512", buf_len),
                Style::new().fg(TuiColor::Yellow),
            ));

            // Layout: header(3), entry(2), label(1), edit(1), gap(1), length(1), gap(1), help(2), fill
            let chunks = Layout::vertical([
                Constraint::Length(3),  // header
                Constraint::Length(2),  // entry name
                Constraint::Length(1),  // "Command line:" label
                Constraint::Length(1),  // edit line
                Constraint::Length(1),  // gap
                Constraint::Length(1),  // length indicator
                Constraint::Length(1),  // gap
                Constraint::Length(2),  // help text
                Constraint::Min(0),    // fill
            ])
            .split(area);

            // Header
            let header =
                Paragraph::new(Line::from("Edit Kernel Command Line").alignment(Alignment::Center))
                    .style(
                        Style::new()
                            .fg(TuiColor::Yellow)
                            .add_modifier(Modifier::BOLD),
                    )
                    .block(
                        Block::new()
                            .borders(Borders::TOP | Borders::BOTTOM)
                            .border_style(Style::new().fg(TuiColor::Yellow)),
                    );
            frame.render_widget(header, chunks[0]);

            // Entry name
            let entry_line = Line::from(vec![
                Span::styled("Entry: ", Style::new().fg(TuiColor::Cyan)),
                Span::raw(entry_name.as_str()),
            ]);
            frame.render_widget(Paragraph::new(entry_line), chunks[1]);

            // Label
            frame.render_widget(Paragraph::new("Command line:"), chunks[2]);

            // Edit line
            frame.render_widget(Paragraph::new(edit_line), chunks[3]);

            // Length
            frame.render_widget(Paragraph::new(length_line), chunks[5]);

            // Help
            let help = Paragraph::new(vec![
                Line::from(Span::styled(help1, Style::new().fg(TuiColor::Cyan))),
                Line::from(Span::styled(help2, Style::new().fg(TuiColor::Cyan))),
            ]);
            frame.render_widget(help, chunks[7]);
        });
    };

    render(terminal, &buffer, cursor_pos);

    loop {
        if let Some(key) = read_key() {
            match key {
                KeyPress::Enter => {
                    if let Some(cmdline) = entry.get_cmdline_mut() {
                        cmdline.clear();
                        let _ = cmdline.push_str(&buffer);
                    }
                    return EditResult::Confirmed;
                }
                KeyPress::Escape => return EditResult::Cancelled,
                KeyPress::Char(c) => {
                    match c {
                        '\x18' => {
                            // Ctrl+X - boot immediately
                            if let Some(cmdline) = entry.get_cmdline_mut() {
                                cmdline.clear();
                                let _ = cmdline.push_str(&buffer);
                            }
                            return EditResult::Boot;
                        }
                        '\x08' | '\x7f' => {
                            // Backspace
                            if cursor_pos > 0 {
                                let mut new_buffer: String<512> = String::new();
                                for (i, ch) in buffer.chars().enumerate() {
                                    if i != cursor_pos - 1 {
                                        let _ = new_buffer.push(ch);
                                    }
                                }
                                buffer = new_buffer;
                                cursor_pos -= 1;
                            }
                        }
                        '\x01' => cursor_pos = 0,       // Ctrl+A
                        '\x05' => cursor_pos = buffer.len(), // Ctrl+E
                        '\x0b' => {
                            // Ctrl+K - delete to end
                            if cursor_pos < buffer.len() {
                                let mut new_buffer: String<512> = String::new();
                                for (i, ch) in buffer.chars().enumerate() {
                                    if i < cursor_pos {
                                        let _ = new_buffer.push(ch);
                                    }
                                }
                                buffer = new_buffer;
                            }
                        }
                        '\x15' => {
                            // Ctrl+U - delete to start
                            if cursor_pos > 0 {
                                let mut new_buffer: String<512> = String::new();
                                for (i, ch) in buffer.chars().enumerate() {
                                    if i >= cursor_pos {
                                        let _ = new_buffer.push(ch);
                                    }
                                }
                                buffer = new_buffer;
                                cursor_pos = 0;
                            }
                        }
                        _ if c.is_ascii_graphic() || c == ' ' => {
                            if buffer.len() < 511 {
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
                            }
                        }
                        _ => continue,
                    }
                    render(terminal, &buffer, cursor_pos);
                }
                KeyPress::Left if cursor_pos > 0 => {
                    cursor_pos -= 1;
                    render(terminal, &buffer, cursor_pos);
                }
                KeyPress::Right if cursor_pos < buffer.len() => {
                    cursor_pos += 1;
                    render(terminal, &buffer, cursor_pos);
                }
                _ => {}
            }
        }
        delay_ms(10);
    }
}

/// Perform a system reset
///
/// This attempts to reset the system using various methods:
/// 1. Keyboard controller reset (port 0x64, command 0xFE)
/// 2. Triple fault (if keyboard controller fails)
fn perform_system_reset() -> ! {
    use crate::arch::x86_64::io;

    log::info!("System reset requested");

    // Method 1: Keyboard controller reset
    unsafe {
        // Wait for keyboard controller to be ready
        for _ in 0..1000 {
            let status = io::inb(0x64);
            if status & 0x02 == 0 {
                break;
            }
        }
        // Send reset command
        io::outb(0x64, 0xFE);
    }

    // Wait a bit for reset to take effect
    delay_ms(100);

    // Method 2: Triple fault (if keyboard reset failed)
    unsafe {
        // Load a null IDT and trigger an interrupt
        let null_idt: [u8; 6] = [0; 6];
        core::arch::asm!(
            "lidt [{}]",
            "int3",
            in(reg) null_idt.as_ptr(),
            options(noreturn)
        );
    }
}

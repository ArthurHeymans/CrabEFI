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
use crate::drivers::block::{AhciDisk, BlockDevice, NvmeDisk, SdhciDisk, UsbDisk};
use crate::drivers::keyboard;
use crate::drivers::serial as serial_driver;
use crate::framebuffer_console::{
    Color, DEFAULT_BG, DEFAULT_FG, FramebufferConsole, HIGHLIGHT_BG, HIGHLIGHT_FG, TITLE_COLOR,
};
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
const HELP_TEXT: &str = "Arrows: Select | Enter: Boot | S: Secure Boot | R: Reset";

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

/// Discover boot entries from NVMe devices
fn discover_nvme_entries(menu: &mut BootMenu) {
    use crate::drivers::nvme;
    use crate::fs::fat::FatFilesystem;

    if let Some(controller) = nvme::get_controller(0)
        && let Some(ns) = controller.default_namespace()
    {
        let nsid = ns.nsid;
        let pci_addr = controller.pci_address();

        // Store device globally for reading
        if !nvme::store_global_device(0, nsid) {
            return;
        }

        // Create disk for GPT reading
        let mut disk = NvmeDisk::new(controller, nsid);

        // Read GPT and find partitions
        if let Ok(header) = gpt::read_gpt_header(&mut disk)
            && let Ok(partitions) = gpt::read_partitions(&mut disk, &header)
        {
            for (i, partition) in partitions.iter().enumerate() {
                let partition_num = (i + 1) as u32;

                // Check if this is an ESP or potential boot partition
                if partition.is_esp || is_potential_esp(partition) {
                    // Try to mount FAT filesystem on this partition
                    if let Some(controller) = nvme::get_controller(0) {
                        let mut disk = NvmeDisk::new(controller, nsid);
                        if let Ok(mut fat) = FatFilesystem::new(&mut disk, partition.first_lba) {
                            let device_type = DeviceType::Nvme {
                                controller_id: 0,
                                nsid,
                            };

                            // Check for UEFI bootloader
                            if fat.file_size("EFI\\BOOT\\BOOTX64.EFI").is_ok() {
                                let mut name: String<64> = String::new();
                                let _ = write!(name, "Boot Entry (NVMe ns{})", nsid);

                                let entry = BootEntry::new(
                                    &name,
                                    "EFI\\BOOT\\BOOTX64.EFI",
                                    device_type,
                                    partition_num,
                                    partition.clone(),
                                    pci_addr.device,
                                    pci_addr.function,
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
                                pci_addr.device,
                                pci_addr.function,
                                menu,
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Discover boot entries from AHCI devices
fn discover_ahci_entries(menu: &mut BootMenu) {
    use crate::drivers::ahci;
    use crate::fs::fat::FatFilesystem;

    if let Some(controller) = ahci::get_controller(0) {
        let pci_addr = controller.pci_address();
        let num_ports = controller.num_active_ports();

        for port_index in 0..num_ports {
            // Store device globally for reading
            if !ahci::store_global_device(0, port_index) {
                continue;
            }

            if let Some(controller) = ahci::get_controller(0) {
                let mut disk = AhciDisk::new(controller, port_index);

                // Try GPT first
                if let Ok(header) = gpt::read_gpt_header(&mut disk)
                    && let Ok(partitions) = gpt::read_partitions(&mut disk, &header)
                {
                    for (i, partition) in partitions.iter().enumerate() {
                        let partition_num = (i + 1) as u32;

                        // Check if this is an ESP or potential boot partition
                        if partition.is_esp || is_potential_esp(partition) {
                            // Try to mount FAT filesystem on this partition
                            if let Some(controller) = ahci::get_controller(0) {
                                let mut disk = AhciDisk::new(controller, port_index);
                                if let Ok(mut fat) =
                                    FatFilesystem::new(&mut disk, partition.first_lba)
                                {
                                    let device_type = DeviceType::Ahci {
                                        controller_id: 0,
                                        port: port_index,
                                    };

                                    // Check for UEFI bootloader
                                    if fat.file_size("EFI\\BOOT\\BOOTX64.EFI").is_ok() {
                                        let mut name: String<64> = String::new();
                                        let _ =
                                            write!(name, "Boot Entry (SATA port {})", port_index);

                                        let entry = BootEntry::new(
                                            &name,
                                            "EFI\\BOOT\\BOOTX64.EFI",
                                            device_type,
                                            partition_num,
                                            partition.clone(),
                                            pci_addr.device,
                                            pci_addr.function,
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
                                        pci_addr.device,
                                        pci_addr.function,
                                        menu,
                                    );
                                }
                            }
                        }
                    }
                } else {
                    // GPT failed - try El Torito (ISO9660) as fallback
                    if let Some(controller) = ahci::get_controller(0) {
                        let mut disk = AhciDisk::new(controller, port_index);
                        if let Ok(efi_image) = iso9660::find_efi_boot_image(&mut disk) {
                            // Create a synthetic partition for the El Torito boot image
                            let block_size = disk.info().block_size;
                            let partition = gpt::Partition {
                                type_guid: [0u8; 16], // Not a real GUID
                                partition_guid: [0u8; 16],
                                first_lba: efi_image.start_sector,
                                last_lba: efi_image.start_sector + efi_image.sector_count as u64
                                    - 1,
                                attributes: 0,
                                is_esp: true, // Treat it as ESP
                                block_size,
                            };

                            // Check if the boot image contains BOOTX64.EFI
                            if let Some(controller) = ahci::get_controller(0) {
                                let mut disk = AhciDisk::new(controller, port_index);
                                if check_bootloader_exists(&mut disk, efi_image.start_sector) {
                                    let mut name: String<64> = String::new();
                                    let _ = write!(name, "ISO Boot (SATA port {})", port_index);

                                    let entry = BootEntry::new(
                                        &name,
                                        "EFI\\BOOT\\BOOTX64.EFI",
                                        DeviceType::Ahci {
                                            controller_id: 0,
                                            port: port_index,
                                        },
                                        0, // No partition number for El Torito
                                        partition,
                                        pci_addr.device,
                                        pci_addr.function,
                                    );

                                    if !menu.add_entry(entry) {
                                        return; // Menu full
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Discover boot entries from USB devices (all controller types)
fn discover_usb_entries(menu: &mut BootMenu) {
    use crate::drivers::usb::{self, UsbMassStorage, mass_storage};
    use crate::fs::fat::FatFilesystem;

    // Check if we have any mass storage on any controller
    if let Some((controller_id, device_addr)) = usb::find_mass_storage() {
        log::info!(
            "Found USB mass storage on controller {}, device {}",
            controller_id,
            device_addr
        );

        // Get the controller pointer for storing globally
        let controller_ptr = match usb::get_controller_ptr(controller_id) {
            Some(ptr) => ptr,
            None => {
                log::error!("Failed to get controller {} pointer", controller_id);
                return;
            }
        };

        // Use with_controller to create the mass storage device
        let device_created = usb::with_controller(controller_id, |controller| {
            match UsbMassStorage::new(controller, device_addr) {
                Ok(usb_device) => {
                    // Store device globally WITH controller pointer so global_read_sector can use it directly
                    // This avoids lock contention since we store the pointer, not just the ID
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

        // Now read partitions using the stored device
        usb::with_controller(controller_id, |controller| {
            // Get controller type early (before any mutable borrows)
            let controller_type = controller.controller_type();

            if let Some(usb_device) = mass_storage::get_global_device() {
                let mut disk = UsbDisk::new(usb_device, controller);

                // Read GPT and find partitions
                if let Ok(header) = gpt::read_gpt_header(&mut disk)
                    && let Ok(partitions) = gpt::read_partitions(&mut disk, &header)
                {
                    for (i, partition) in partitions.iter().enumerate() {
                        let partition_num = (i + 1) as u32;

                        // Check if this is an ESP or potential boot partition
                        if partition.is_esp || is_potential_esp(partition) {
                            // Try to mount FAT filesystem on this partition
                            if let Some(usb_device2) = mass_storage::get_global_device() {
                                let mut disk2 = UsbDisk::new(usb_device2, controller);
                                if let Ok(mut fat) =
                                    FatFilesystem::new(&mut disk2, partition.first_lba)
                                {
                                    let device_type = DeviceType::Usb {
                                        controller_id,
                                        device_addr,
                                    };

                                    // Check for UEFI bootloader
                                    if fat.file_size("EFI\\BOOT\\BOOTX64.EFI").is_ok() {
                                        let mut name: String<64> = String::new();
                                        let _ =
                                            write!(name, "Boot Entry ({} USB)", controller_type);

                                        let entry = BootEntry::new(
                                            &name,
                                            "EFI\\BOOT\\BOOTX64.EFI",
                                            device_type,
                                            partition_num,
                                            partition.clone(),
                                            0, // PCI device - TODO: get from controller
                                            0, // PCI function - TODO: get from controller
                                        );

                                        menu.add_entry(entry);
                                    }

                                    // Scan for additional entries (BLS, GRUB, payloads)
                                    scan_partition_for_entries(
                                        &mut fat,
                                        device_type,
                                        partition_num,
                                        partition,
                                        0, // PCI device - TODO: get from controller
                                        0, // PCI function
                                        menu,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        });
    }
}

/// Discover boot entries from SDHCI devices (SD cards)
fn discover_sdhci_entries(menu: &mut BootMenu) {
    use crate::drivers::sdhci;
    use crate::fs::fat::FatFilesystem;

    for controller_id in 0..sdhci::controller_count() {
        if let Some(controller) = sdhci::get_controller(controller_id) {
            if !controller.is_ready() {
                continue;
            }

            let pci_addr = controller.pci_address();

            // Store device globally for reading
            if !sdhci::store_global_device(controller_id) {
                continue;
            }

            // Create disk for GPT reading
            if let Some(controller) = sdhci::get_controller(controller_id) {
                let mut disk = SdhciDisk::new(controller);

                // Read GPT and find partitions
                if let Ok(header) = gpt::read_gpt_header(&mut disk)
                    && let Ok(partitions) = gpt::read_partitions(&mut disk, &header)
                {
                    for (i, partition) in partitions.iter().enumerate() {
                        let partition_num = (i + 1) as u32;

                        // Check if this is an ESP or potential boot partition
                        if partition.is_esp || is_potential_esp(partition) {
                            // Try to mount FAT filesystem on this partition
                            if let Some(controller) = sdhci::get_controller(controller_id) {
                                let mut disk = SdhciDisk::new(controller);
                                if let Ok(mut fat) =
                                    FatFilesystem::new(&mut disk, partition.first_lba)
                                {
                                    let device_type = DeviceType::Sdhci { controller_id };

                                    // Check for UEFI bootloader
                                    if fat.file_size("EFI\\BOOT\\BOOTX64.EFI").is_ok() {
                                        let mut name: String<64> = String::new();
                                        let _ = write!(name, "Boot Entry (SD card)");

                                        let entry = BootEntry::new(
                                            &name,
                                            "EFI\\BOOT\\BOOTX64.EFI",
                                            device_type,
                                            partition_num,
                                            partition.clone(),
                                            pci_addr.device,
                                            pci_addr.function,
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
                                        pci_addr.device,
                                        pci_addr.function,
                                        menu,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
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
/// - Strips leading slash
/// - Converts forward slashes to backslashes
fn linux_path_to_fat(path: &str) -> String<128> {
    let mut fat_path: String<128> = String::new();

    // Strip leading slash
    let path = path.trim_start_matches('/');

    // Convert forward slashes to backslashes
    for c in path.chars() {
        if c == '/' {
            let _ = fat_path.push('\\');
        } else {
            let _ = fat_path.push(c);
        }
    }

    fat_path
}

/// Check if a bootloader exists on the given partition
fn check_bootloader_exists<D: BlockDevice>(disk: &mut D, partition_start: u64) -> bool {
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
    // 1. Scan for BLS entries
    // BLS entries should have kernels on the same partition (ESP or XBOOTLDR)
    if let Ok(bls_discovery) = crate::bls::discover_entries(fat) {
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

    // 2. Scan for GRUB config entries
    // NOTE: GRUB entries from grub.cfg often reference kernels on the root partition,
    // not the ESP where grub.cfg lives. We only add entries if the kernel file
    // actually exists on this partition (for direct boot to work).
    if let Ok(grub_config) = crate::grub::parse_config(fat) {
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
    let payloads = crate::payload::discover_payloads(fat);
    for payload_entry in payloads.iter() {
        let entry = BootEntry::new_with_kind(
            &payload_entry.name,
            &payload_entry.path,
            device_type,
            partition_num,
            partition.clone(),
            pci_device,
            pci_function,
            BootEntryKind::Payload {
                path: payload_entry.path.clone(),
                format: payload_entry.format,
            },
            BootCategory::Payload,
        );

        if !menu.add_entry(entry) {
            return; // Menu full
        }
    }
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
    if menu.entry_count() == 0 {
        log::error!("No boot entries to display");
        return None;
    }

    // Get framebuffer for rendering
    let fb_info = coreboot::get_framebuffer();

    // Create framebuffer console if available
    let mut fb_console = fb_info.as_ref().map(FramebufferConsole::new);

    // Clear screen
    clear_screen(&mut fb_console);

    // Initial display
    draw_menu(menu, &mut fb_console);

    // Handle input with timeout
    let mut remaining_seconds = menu.timeout_seconds;
    let mut last_second_check = Timeout::from_ms(0); // Immediately update

    loop {
        // Check for timeout
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
        if let Some(key) = read_key() {
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
                KeyPress::Enter => {
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
                KeyPress::Char('s') | KeyPress::Char('S') => {
                    // Open Secure Boot settings menu
                    crate::secure_boot_menu::show_secure_boot_menu();
                    // Redraw boot menu after returning
                    clear_screen(&mut fb_console);
                    draw_menu(menu, &mut fb_console);
                }
                KeyPress::Char('r') | KeyPress::Char('R') => {
                    // Reset the system
                    draw_status("Resetting system...", &mut fb_console);
                    delay_ms(500);
                    perform_system_reset();
                }
                KeyPress::Char(c) if c.is_ascii_digit() => {
                    // Direct selection by number
                    let num = (c as u8 - b'0') as usize;
                    if num > 0 && num <= menu.entry_count() {
                        menu.selected = num - 1;
                        draw_menu(menu, &mut fb_console);
                    }
                }
                _ => {}
            }
        }

        // Small delay to avoid busy-waiting
        delay_ms(10);
    }
}

/// Key press types for menu navigation
#[derive(Debug, Clone, Copy)]
enum KeyPress {
    Up,
    Down,
    Enter,
    Escape,
    Char(char),
}

/// Read a key from keyboard or serial
fn read_key() -> Option<KeyPress> {
    // Try PS/2 keyboard first
    if let Some((scan_code, unicode_char)) = keyboard::try_read_key() {
        return match scan_code {
            0x01 => Some(KeyPress::Up),                         // SCAN_UP
            0x02 => Some(KeyPress::Down),                       // SCAN_DOWN
            0x17 => Some(KeyPress::Escape),                     // SCAN_ESC
            0 if unicode_char == 0x0D => Some(KeyPress::Enter), // Carriage return
            0 if unicode_char > 0 => Some(KeyPress::Char(unicode_char as u8 as char)),
            _ => None,
        };
    }

    // Try serial input
    if let Some(byte) = serial_driver::try_read() {
        return match byte {
            0x1B => {
                // Escape - check for escape sequence
                delay_ms(10); // Wait for potential sequence
                if let Some(b'[') = serial_driver::try_read() {
                    match serial_driver::try_read() {
                        Some(b'A') => Some(KeyPress::Up),
                        Some(b'B') => Some(KeyPress::Down),
                        _ => Some(KeyPress::Escape),
                    }
                } else {
                    Some(KeyPress::Escape)
                }
            }
            b'\r' | b'\n' => Some(KeyPress::Enter),
            c => Some(KeyPress::Char(c as char)),
        };
    }

    None
}

/// Clear both serial and framebuffer screens
fn clear_screen(fb_console: &mut Option<FramebufferConsole>) {
    // Clear serial with ANSI escape
    serial_driver::write_str("\x1b[2J\x1b[H");

    // Clear framebuffer
    if let Some(console) = fb_console {
        console.clear();
    }
}

/// Draw the menu on both outputs
fn draw_menu(menu: &BootMenu, fb_console: &mut Option<FramebufferConsole>) {
    let cols = fb_console.as_ref().map(|c| c.cols()).unwrap_or(80) as usize;

    // Draw header
    draw_header(fb_console, cols);

    // Draw entries
    let start_row = 4;
    for (i, entry) in menu.entries.iter().enumerate() {
        let is_selected = i == menu.selected;
        draw_entry(i, entry, is_selected, start_row, fb_console, cols);
    }

    // Draw help text
    let help_row = start_row + menu.entry_count() + 2;
    draw_help(help_row, fb_console, cols);
}

/// Draw the menu header
fn draw_header(fb_console: &mut Option<FramebufferConsole>, cols: usize) {
    // Build horizontal line
    let mut line = [0u8; 128];
    let line_len = cols.min(line.len());
    line[..line_len].fill(b'=');
    let line_str = core::str::from_utf8(&line[..line_len]).unwrap_or("");

    // Serial output
    serial_driver::write_str("\x1b[H"); // Home cursor
    serial_driver::write_str("\x1b[1;33m"); // Yellow, bold
    serial_driver::write_str(line_str);
    serial_driver::write_str("\r\n");

    // Center title
    let title_pad = (cols.saturating_sub(MENU_TITLE.len())) / 2;
    for _ in 0..title_pad {
        serial_driver::write_str(" ");
    }
    serial_driver::write_str(MENU_TITLE);
    serial_driver::write_str("\r\n");

    serial_driver::write_str(line_str);
    serial_driver::write_str("\r\n\x1b[0m"); // Reset attributes

    // Framebuffer output
    if let Some(console) = fb_console {
        console.set_position(0, 0);
        console.set_fg_color(TITLE_COLOR);
        let _ = console.write_str(line_str);
        console.set_position(0, 1);
        console.write_centered(1, MENU_TITLE);
        console.set_position(0, 2);
        let _ = console.write_str(line_str);
        console.reset_colors();
    }
}

/// Draw a single boot entry
fn draw_entry(
    index: usize,
    entry: &BootEntry,
    is_selected: bool,
    start_row: usize,
    fb_console: &mut Option<FramebufferConsole>,
    _cols: usize,
) {
    let row = start_row + index;
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

/// Draw the help text
fn draw_help(row: usize, fb_console: &mut Option<FramebufferConsole>, cols: usize) {
    // Serial output
    let ansi_row = row + 1;
    let _ = write!(SerialWriter, "\x1b[{};1H", ansi_row);
    serial_driver::write_str("\x1b[36m"); // Cyan

    // Center help text
    let help_pad = (cols.saturating_sub(HELP_TEXT.len())) / 2;
    for _ in 0..help_pad {
        serial_driver::write_str(" ");
    }
    serial_driver::write_str(HELP_TEXT);
    serial_driver::write_str("\x1b[0m\r\n");

    // Framebuffer output
    if let Some(console) = fb_console {
        console.set_fg_color(Color::new(0, 192, 192)); // Cyan
        console.write_centered(row as u32, HELP_TEXT);
        console.reset_colors();
    }
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

/// Draw a status message
fn draw_status(message: &str, fb_console: &mut Option<FramebufferConsole>) {
    // Serial output
    serial_driver::write_str("\x1b[22;1H"); // Row 22
    serial_driver::write_str("\x1b[31m"); // Red
    serial_driver::write_str(message);
    serial_driver::write_str("\x1b[K"); // Clear rest of line
    serial_driver::write_str("\x1b[0m");

    // Framebuffer output
    if let Some(console) = fb_console {
        let row = console.rows().saturating_sub(1);
        console.set_fg_color(Color::new(255, 0, 0)); // Red
        console.write_centered(row, message);
        console.reset_colors();
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

/// Helper for serial formatted output
pub struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial_driver::write_str(s);
        Ok(())
    }
}

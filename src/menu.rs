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
const HELP_TEXT: &str = "Arrows: Select | Enter: Boot | C: Cmdline | S: Secure Boot | R: Reset";

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

/// Discover boot entries from NVMe devices
fn discover_nvme_entries(menu: &mut BootMenu) {
    use crate::drivers::nvme;
    use crate::fs::fat::FatFilesystem;

    if let Some(controller_ptr) = nvme::get_controller(0) {
        // Safety: pointer valid for firmware lifetime; no overlapping &mut created
        let controller = unsafe { &mut *controller_ptr };
        if let Some(ns) = controller.default_namespace() {
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
                        if let Some(controller_ptr) = nvme::get_controller(0) {
                            // Safety: pointer valid for firmware lifetime; no overlapping &mut created
                            let controller = unsafe { &mut *controller_ptr };
                            let mut disk = NvmeDisk::new(controller, nsid);
                            if let Ok(mut fat) = FatFilesystem::new(&mut disk, partition.first_lba)
                            {
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
}

/// Discover boot entries from AHCI devices
fn discover_ahci_entries(menu: &mut BootMenu) {
    use crate::drivers::ahci;
    use crate::fs::fat::FatFilesystem;

    if let Some(controller_ptr) = ahci::get_controller(0) {
        // Safety: pointer valid for firmware lifetime; no overlapping &mut created
        let controller = unsafe { &mut *controller_ptr };
        let pci_addr = controller.pci_address();
        let num_ports = controller.num_active_ports();

        for port_index in 0..num_ports {
            // Store device globally for reading
            if !ahci::store_global_device(0, port_index) {
                continue;
            }

            if let Some(controller_ptr) = ahci::get_controller(0) {
                // Safety: pointer valid for firmware lifetime; no overlapping &mut created
                let controller = unsafe { &mut *controller_ptr };
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
                            if let Some(controller_ptr) = ahci::get_controller(0) {
                                // Safety: pointer valid for firmware lifetime; no overlapping &mut created
                                let controller = unsafe { &mut *controller_ptr };
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
                    if let Some(controller_ptr) = ahci::get_controller(0) {
                        // Safety: pointer valid for firmware lifetime; no overlapping &mut created
                        let controller = unsafe { &mut *controller_ptr };
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
                            if let Some(controller_ptr) = ahci::get_controller(0) {
                                // Safety: pointer valid for firmware lifetime; no overlapping &mut created
                                let controller = unsafe { &mut *controller_ptr };
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
                    // Skip devices with no media (e.g., card reader without card)
                    if usb_device.num_blocks == 0 {
                        log::info!("USB Mass Storage: no media present, skipping");
                        return false;
                    }

                    // Store device globally WITH controller pointer so global_read_sectors can use it directly
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
                KeyPress::Char('c') | KeyPress::Char('C') => {
                    // Edit kernel command line
                    if let Some(entry) = menu.entries.get_mut(menu.selected) {
                        if entry.has_cmdline() {
                            match edit_cmdline(entry, &mut fb_console) {
                                EditResult::Boot => {
                                    // Boot immediately with the edited command line
                                    let mut msg: String<64> = String::new();
                                    let _ = msg.push_str("Booting ");
                                    let _ = msg.push_str(&entry.name);
                                    let _ = msg.push_str("...");
                                    clear_screen(&mut fb_console);
                                    draw_status(&msg, &mut fb_console);
                                    return Some(menu.selected);
                                }
                                EditResult::Confirmed => {
                                    draw_status("Command line updated", &mut fb_console);
                                }
                                EditResult::Cancelled => {
                                    draw_status("Edit cancelled", &mut fb_console);
                                }
                            }
                        } else {
                            draw_status("This entry has no editable command line", &mut fb_console);
                        }
                    }
                    // Redraw menu after editing (unless we're booting)
                    delay_ms(500);
                    clear_screen(&mut fb_console);
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
    Left,
    Right,
    Enter,
    Escape,
    Char(char),
}

/// Read a key from keyboard (PS/2, USB, or serial)
fn read_key() -> Option<KeyPress> {
    // Try PS/2 keyboard first
    if let Some((scan_code, unicode_char)) = keyboard::try_read_key() {
        return match scan_code {
            0x01 => Some(KeyPress::Up),                         // SCAN_UP
            0x02 => Some(KeyPress::Down),                       // SCAN_DOWN
            0x03 => Some(KeyPress::Right),                      // SCAN_RIGHT
            0x04 => Some(KeyPress::Left),                       // SCAN_LEFT
            0x17 => Some(KeyPress::Escape),                     // SCAN_ESC
            0 if unicode_char == 0x0D => Some(KeyPress::Enter), // Carriage return
            0 if unicode_char > 0 => Some(KeyPress::Char(unicode_char as u8 as char)),
            _ => None,
        };
    }

    // Try USB keyboard
    if let Some((scan_code, unicode_char)) = crate::drivers::usb::keyboard_get_key() {
        return match scan_code {
            0x01 => Some(KeyPress::Up),
            0x02 => Some(KeyPress::Down),
            0x03 => Some(KeyPress::Right),
            0x04 => Some(KeyPress::Left),
            0x17 => Some(KeyPress::Escape),
            0 if unicode_char == 0x0D => Some(KeyPress::Enter),
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
                        Some(b'C') => Some(KeyPress::Right),
                        Some(b'D') => Some(KeyPress::Left),
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

    // Draw entries with category separators
    let start_row = 4;
    let mut current_row = start_row;
    let mut current_category: Option<BootCategory> = None;

    for (i, entry) in menu.entries.iter().enumerate() {
        // Check if we need a category separator
        if current_category != Some(entry.category) {
            // Add blank line before separator (except for first category)
            if current_category.is_some() {
                current_row += 1;
            }
            draw_category_separator(entry.category, current_row, fb_console, cols);
            current_row += 1;
            current_category = Some(entry.category);
        }

        let is_selected = i == menu.selected;
        draw_entry(i, entry, is_selected, current_row, fb_console, cols);
        current_row += 1;
    }

    // Draw help text
    let help_row = current_row + 2;
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

/// Edit the command line of a boot entry
///
/// Displays a full-screen editor for the kernel command line.
///
/// # Arguments
///
/// * `entry` - The boot entry to edit
/// * `fb_console` - Optional framebuffer console for display
///
/// # Returns
///
/// `EditResult::Cancelled` if the user pressed Escape (cmdline unchanged)
/// `EditResult::Confirmed` if the user pressed Enter (cmdline updated, return to menu)
/// `EditResult::Boot` if the user pressed Ctrl+X (cmdline updated, boot immediately)
fn edit_cmdline(entry: &mut BootEntry, fb_console: &mut Option<FramebufferConsole>) -> EditResult {
    // Check if entry has cmdline and extract initial value
    let initial_cmdline = match entry.get_cmdline() {
        Some(c) => c.clone(),
        None => {
            draw_status("This entry has no command line to edit", fb_console);
            delay_ms(1500);
            return EditResult::Cancelled;
        }
    };

    // Copy entry name for display (to avoid borrow issues)
    let entry_name: String<64> = entry.name.clone();

    // Create a working buffer for editing
    let mut buffer: String<512> = initial_cmdline;
    let mut cursor_pos = buffer.len();

    // Calculate scroll offset for long command lines
    let cols = fb_console.as_ref().map(|c| c.cols()).unwrap_or(80) as usize;
    let edit_width = cols.saturating_sub(4); // Leave margin for decoration

    // Draw static parts once
    draw_cmdline_editor_static(&entry_name, fb_console, cols);

    // Track if display needs updating
    let mut needs_redraw = true;

    loop {
        // Only redraw if something changed
        if needs_redraw {
            draw_cmdline_editor_line(&buffer, cursor_pos, edit_width, fb_console);
            needs_redraw = false;
        }

        // Wait for input
        if let Some(key) = read_key() {
            match key {
                KeyPress::Enter => {
                    // Confirm - update the cmdline
                    if let Some(cmdline) = entry.get_cmdline_mut() {
                        cmdline.clear();
                        let _ = cmdline.push_str(&buffer);
                    }
                    return EditResult::Confirmed;
                }
                KeyPress::Escape => {
                    // Cancel - don't modify
                    return EditResult::Cancelled;
                }
                KeyPress::Char(c) => {
                    // Handle special characters
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
                                // Remove character before cursor
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
                        }
                        '\x01' => {
                            // Ctrl+A - move to beginning
                            if cursor_pos != 0 {
                                cursor_pos = 0;
                                needs_redraw = true;
                            }
                        }
                        '\x05' => {
                            // Ctrl+E - move to end
                            if cursor_pos != buffer.len() {
                                cursor_pos = buffer.len();
                                needs_redraw = true;
                            }
                        }
                        '\x0b' => {
                            // Ctrl+K - delete to end of line
                            if cursor_pos < buffer.len() {
                                let mut new_buffer: String<512> = String::new();
                                for (i, ch) in buffer.chars().enumerate() {
                                    if i < cursor_pos {
                                        let _ = new_buffer.push(ch);
                                    }
                                }
                                buffer = new_buffer;
                                needs_redraw = true;
                            }
                        }
                        '\x15' => {
                            // Ctrl+U - delete to beginning of line
                            if cursor_pos > 0 {
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
                        }
                        _ if c.is_ascii_graphic() || c == ' ' => {
                            // Regular printable character - insert at cursor (ASCII only)
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
                                needs_redraw = true;
                            }
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
                // Ignore Up/Down in editor
                KeyPress::Up | KeyPress::Down => {}
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

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

mod cmdline;
mod discovery;
mod text;

pub use discovery::discover_boot_entries;
pub(crate) use discovery::discover_entries;
pub use text::show_menu;
pub(crate) use text::show_menu_for_mode;

use crate::drivers::pci::PciAddress;
use crate::drivers::storage::{StorageDevice, StorageId};
use crate::fs::{boot::Kind as FilesystemKind, gpt};
use core::fmt::Write;
use heapless::String;

/// Default timeout in seconds for auto-boot
const DEFAULT_TIMEOUT_SECONDS: u32 = 5;

/// Architecture-specific EFI boot path
#[cfg(target_arch = "x86_64")]
pub const EFI_BOOT_PATH: &str = "EFI\\BOOT\\BOOTX64.EFI";
#[cfg(target_arch = "aarch64")]
pub const EFI_BOOT_PATH: &str = "EFI\\BOOT\\BOOTAA64.EFI";
#[cfg(target_arch = "riscv64")]
pub const EFI_BOOT_PATH: &str = "EFI\\BOOT\\BOOTRISCV64.EFI";

pub use crabefi_ui::{BootCategory, BootEntryKind, Initrds, MAX_INITRDS, PayloadFormat};

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
    pub(crate) filesystem: FilesystemKind,
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
            filesystem: FilesystemKind::Fat,
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

    fn add_entry(&mut self, entry: BootEntry) -> bool {
        if self.menu.add_entry(entry) {
            true
        } else {
            log::error!(
                "Boot menu: out of heap at {} entries",
                self.menu.entry_count()
            );
            false
        }
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

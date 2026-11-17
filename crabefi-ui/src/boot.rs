//! The boot menu model shared by firmware discovery and the setup UI.
//!
//! The UI needs only what it shows. A host wraps [`BootEntry`] in its own
//! entry type (devices, partitions) and exposes it through [`MenuEntry`].
use alloc::string::String as OwnedString;
use core::ops::{Deref, DerefMut};
use heapless::{String, Vec};

/// Maximum number of boot entries in one menu.
pub const MAX_BOOT_ENTRIES: usize = 16;
/// Maximum initrds of a direct Linux entry.
pub const MAX_INITRDS: usize = 4;
/// The initrds of a direct Linux entry, in order.
pub type Initrds = Vec<String<128>, MAX_INITRDS>;

/// Payload format type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFormat {
    /// Standard ELF executable
    Elf,
    /// Flat binary loaded to a fixed address
    FlatBinary {
        /// Address to load the binary
        load_addr: u64,
    },
}

/// Boot entry kind - how this entry should be booted
#[derive(Debug, Clone, Default)]
pub enum BootEntryKind {
    /// UEFI executable (EFI\BOOT\BOOTxx.EFI)
    #[default]
    Uefi,
    /// BLS Type #1 - direct Linux boot
    BlsLinux {
        /// Path to Linux kernel
        linux_path: String<128>,
        /// The initrds, in order
        initrd_paths: Initrds,
        /// Kernel command line
        cmdline: String<512>,
    },
    /// BLS Type #2 - Unified Kernel Image (still EFI)
    BlsUki,
    /// GRUB menu entry - direct Linux boot
    GrubLinux {
        /// Path to Linux kernel
        linux_path: String<128>,
        /// The initrds, in order
        initrd_paths: Initrds,
        /// Kernel command line
        cmdline: String<512>,
    },
    /// Coreboot payload (ELF or flat binary)
    Payload {
        /// Path to payload file
        path: String<128>,
        /// Payload format
        format: PayloadFormat,
    },
}

/// Category for menu grouping
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BootCategory {
    /// UEFI boot entries
    #[default]
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

/// What a boot menu shows about one entry.
#[derive(Debug, Clone, Default)]
pub struct BootEntry {
    /// Display name for the menu
    pub name: String<64>,
    /// Path to the EFI application (for UEFI entries)
    pub path: String<128>,
    /// Partition number (1-based)
    pub partition_num: u32,
    /// Boot entry kind (how to boot this entry)
    pub kind: BootEntryKind,
    /// Boot category (for menu grouping)
    pub category: BootCategory,
}

impl BootEntry {
    /// An entry with the given name and path; strings are truncated to fit.
    pub fn new(
        name: &str,
        path: &str,
        partition_num: u32,
        kind: BootEntryKind,
        category: BootCategory,
    ) -> Self {
        let mut entry = Self {
            partition_num,
            kind,
            category,
            ..Self::default()
        };
        push_truncated(&mut entry.name, name);
        push_truncated(&mut entry.path, path);
        entry
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
        self.is_linux_boot()
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

fn push_truncated<const N: usize>(out: &mut String<N>, text: &str) {
    for ch in text.chars() {
        if out.push(ch).is_err() {
            break;
        }
    }
}

/// A host's boot entry: the shown [`BootEntry`] plus where it lives.
pub trait MenuEntry: Deref<Target = BootEntry> + DerefMut {
    /// Label of the disk holding the entry, such as "NVMe 0".
    fn disk_name(&self) -> OwnedString;
    /// The disk as the details pane names it, telling controllers and
    /// namespaces apart where the short label does not.
    fn disk_detail(&self) -> OwnedString {
        self.disk_name()
    }
    /// Whether two entries are on the same disk.
    fn same_disk(&self, other: &Self) -> bool;
}

/// An entry on a disk known only by index and label (tests, simulations).
#[derive(Debug, Clone)]
pub struct DiskEntry {
    pub entry: BootEntry,
    pub disk: usize,
    pub disk_name: OwnedString,
}
impl Deref for DiskEntry {
    type Target = BootEntry;
    fn deref(&self) -> &BootEntry {
        &self.entry
    }
}
impl DerefMut for DiskEntry {
    fn deref_mut(&mut self) -> &mut BootEntry {
        &mut self.entry
    }
}
impl MenuEntry for DiskEntry {
    fn disk_name(&self) -> OwnedString {
        self.disk_name.clone()
    }
    fn same_disk(&self, other: &Self) -> bool {
        self.disk == other.disk
    }
}

/// Boot menu state
#[derive(Debug, Clone)]
pub struct BootMenu<E> {
    /// Discovered boot entries
    pub entries: Vec<E, MAX_BOOT_ENTRIES>,
    /// Currently selected entry index
    pub selected: usize,
    /// Timeout in seconds (0 = no timeout)
    pub timeout_seconds: u32,
    /// One-shot command-line edit for the next boot attempt of one entry.
    /// The entry itself keeps its discovered command line; the edit is
    /// applied only to the clone handed to the boot path, and each menu
    /// showing starts by clearing any leftover edit.
    edited_cmdline: Option<(usize, String<512>)>,
}

impl<E> Default for BootMenu<E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<E> BootMenu<E> {
    /// An empty menu without a timeout.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            selected: 0,
            timeout_seconds: 0,
            edited_cmdline: None,
        }
    }

    /// Add a boot entry
    pub fn add_entry(&mut self, entry: E) -> bool {
        self.entries.push(entry).is_ok()
    }

    /// Get the number of entries
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get a reference to an entry as discovered. To boot a selection, use
    /// [`entry_for_boot`](Self::entry_for_boot) instead: one-shot
    /// command-line edits are not applied to the entries returned here.
    pub fn get_entry(&self, index: usize) -> Option<&E> {
        self.entries.get(index)
    }

    /// Get the selected entry as discovered (see [`get_entry`](Self::get_entry))
    pub fn selected_entry(&self) -> Option<&E> {
        self.entries.get(self.selected)
    }

    /// Record a one-shot command-line edit for `index` (see `edited_cmdline`).
    pub fn set_edited_cmdline(&mut self, index: usize, cmdline: String<512>) {
        self.edited_cmdline = Some((index, cmdline));
    }

    /// The pending one-shot edit for `index`, if the user edited it.
    pub fn edited_cmdline(&self, index: usize) -> Option<&str> {
        self.edited_cmdline
            .as_ref()
            .filter(|(edited, _)| *edited == index)
            .map(|(_, cmdline)| cmdline.as_str())
    }

    /// Drop any pending one-shot edit; called when a menu showing begins so
    /// an edit can never outlive the boot attempt it was made for.
    pub fn clear_edited_cmdline(&mut self) {
        self.edited_cmdline = None;
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

impl<E: MenuEntry> BootMenu<E> {
    /// Command line an editor should start from: the pending edit if any,
    /// otherwise the entry's discovered command line.
    pub fn effective_cmdline(&self, index: usize) -> Option<&str> {
        self.edited_cmdline(index).or_else(|| {
            self.entries
                .get(index)
                .and_then(|entry| entry.get_cmdline())
                .map(|cmdline| cmdline.as_str())
        })
    }

    /// The entry to actually boot: a clone with any one-shot command-line
    /// edit applied. The menu's own entry is left as discovered, so a
    /// failed boot followed by a re-shown menu cannot silently reuse it.
    pub fn entry_for_boot(&self, index: usize) -> Option<E>
    where
        E: Clone,
    {
        let mut entry = self.entries.get(index)?.clone();
        if let Some(edited) = self.edited_cmdline(index)
            && let Some(cmdline) = entry.get_cmdline_mut()
        {
            cmdline.clear();
            let _ = cmdline.push_str(edited);
        }
        Some(entry)
    }
}

#[cfg(test)]
mod one_shot_cmdline_tests {
    use super::*;

    fn linux_menu() -> BootMenu<DiskEntry> {
        let mut menu = BootMenu::new();
        assert!(menu.add_entry(DiskEntry {
            entry: BootEntry::new(
                "Linux",
                "",
                1,
                BootEntryKind::BlsLinux {
                    linux_path: String::new(),
                    initrd_paths: Initrds::new(),
                    cmdline: "quiet".try_into().unwrap(),
                },
                BootCategory::Bls,
            ),
            disk: 0,
            disk_name: "NVMe 0".into(),
        }));
        menu
    }

    fn discovered(menu: &BootMenu<DiskEntry>) -> Option<&str> {
        menu.get_entry(0)?
            .get_cmdline()
            .map(|cmdline| cmdline.as_str())
    }

    #[test]
    fn edited_cmdline_applies_only_to_the_boot_clone() {
        let mut menu = linux_menu();
        menu.set_edited_cmdline(0, "quiet debug".try_into().unwrap());
        assert_eq!(discovered(&menu), Some("quiet"));
        assert_eq!(menu.effective_cmdline(0), Some("quiet debug"));
        let boot_entry = menu.entry_for_boot(0).expect("entry 0 exists");
        assert_eq!(
            boot_entry.get_cmdline().map(|cmdline| cmdline.as_str()),
            Some("quiet debug")
        );
        // The boot attempt consumed the clone, not the edit's target: after
        // it, and after the next showing clears the edit, only the
        // discovered command line remains.
        assert_eq!(discovered(&menu), Some("quiet"));
        menu.clear_edited_cmdline();
        assert_eq!(menu.edited_cmdline(0), None);
        assert_eq!(menu.effective_cmdline(0), Some("quiet"));
    }
}

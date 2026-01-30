//! AMD Chipset PCI ID Database and Detection
//!
//! This module contains the PCI device IDs for AMD chipsets and their
//! corresponding SPI controller types.

use super::{AMD_VID, ATI_VID};

/// Chipset type for AMD platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AmdChipset {
    /// SB600/SB700/SB800/SB900 (uses SMBus-based flash access)
    Sb600,
    /// Merlin Falcon (FCH 790b rev 0x4a, uses SMBus)
    MerlinFalcon,
    /// Stoney Ridge (FCH 790b rev 0x4b, uses SMBus)
    StoneyRidge,
    /// Renoir/Cezanne (FCH 790b rev 0x51, uses SPI100)
    RenoirCezanne,
    /// Pinnacle Ridge (FCH 790b rev 0x59, uses SPI100)
    PinnacleRidge,
    /// Raven Ridge/Matisse/Starship (FCH 790b rev 0x61, uses SPI100)
    RavenRidgeMatisseStarship,
    /// Mendocino/Van Gogh/Rembrandt/Raphael/Genoa (FCH 790b rev 0x71, uses SPI100)
    MendoncinoRembrandt,
}

impl AmdChipset {
    /// Returns true if this chipset uses the SPI100 controller
    pub fn uses_spi100(self) -> bool {
        matches!(
            self,
            Self::RenoirCezanne
                | Self::PinnacleRidge
                | Self::RavenRidgeMatisseStarship
                | Self::MendoncinoRembrandt
        )
    }
}

impl core::fmt::Display for AmdChipset {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sb600 => write!(f, "SB600/SB700/SB800/SB900"),
            Self::MerlinFalcon => write!(f, "Merlin Falcon"),
            Self::StoneyRidge => write!(f, "Stoney Ridge"),
            Self::RenoirCezanne => write!(f, "Renoir/Cezanne"),
            Self::PinnacleRidge => write!(f, "Pinnacle Ridge"),
            Self::RavenRidgeMatisseStarship => write!(f, "Raven Ridge/Matisse/Starship"),
            Self::MendoncinoRembrandt => write!(f, "Mendocino/Van Gogh/Rembrandt/Raphael/Genoa"),
        }
    }
}

/// Revision ID matching mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionMatch {
    /// Match any revision
    Any,
    /// Match specific revision ID
    Exact(u8),
}

/// AMD chipset enable entry
#[derive(Debug, Clone, Copy)]
pub struct AmdChipsetEnable {
    /// PCI vendor ID
    pub vendor_id: u16,
    /// PCI device ID
    pub device_id: u16,
    /// Revision ID matching
    pub revision: RevisionMatch,
    /// Device/chipset name
    pub device_name: &'static str,
    /// Chipset type
    pub chipset: AmdChipset,
}

impl AmdChipsetEnable {
    /// Check if this entry matches the given PCI device
    pub fn matches(&self, vendor_id: u16, device_id: u16, revision_id: u8) -> bool {
        if self.vendor_id != vendor_id || self.device_id != device_id {
            return false;
        }

        match self.revision {
            RevisionMatch::Any => true,
            RevisionMatch::Exact(rev) => rev == revision_id,
        }
    }
}

/// AMD chipset enable database
///
/// This table contains all supported AMD chipsets, organized by PCI device ID
/// and revision ID.
pub static AMD_CHIPSETS: &[AmdChipsetEnable] = &[
    // ATI/AMD SB600 (device 0x438d)
    AmdChipsetEnable {
        vendor_id: ATI_VID,
        device_id: 0x438d,
        revision: RevisionMatch::Any,
        device_name: "SB600",
        chipset: AmdChipset::Sb600,
    },
    // ATI/AMD SB7x0/SB8x0/SB9x0 (device 0x439d)
    AmdChipsetEnable {
        vendor_id: ATI_VID,
        device_id: 0x439d,
        revision: RevisionMatch::Any,
        device_name: "SB7x0/SB8x0/SB9x0",
        chipset: AmdChipset::Sb600,
    },
    // AMD FCH 790b - Merlin Falcon (rev 0x4a)
    AmdChipsetEnable {
        vendor_id: AMD_VID,
        device_id: 0x790b,
        revision: RevisionMatch::Exact(0x4a),
        device_name: "Merlin Falcon",
        chipset: AmdChipset::MerlinFalcon,
    },
    // AMD FCH 790b - Stoney Ridge (rev 0x4b)
    AmdChipsetEnable {
        vendor_id: AMD_VID,
        device_id: 0x790b,
        revision: RevisionMatch::Exact(0x4b),
        device_name: "Stoney Ridge",
        chipset: AmdChipset::StoneyRidge,
    },
    // AMD FCH 790b - Renoir/Cezanne (rev 0x51) - SPI100
    AmdChipsetEnable {
        vendor_id: AMD_VID,
        device_id: 0x790b,
        revision: RevisionMatch::Exact(0x51),
        device_name: "Renoir/Cezanne",
        chipset: AmdChipset::RenoirCezanne,
    },
    // AMD FCH 790b - Pinnacle Ridge (rev 0x59) - SPI100
    AmdChipsetEnable {
        vendor_id: AMD_VID,
        device_id: 0x790b,
        revision: RevisionMatch::Exact(0x59),
        device_name: "Pinnacle Ridge",
        chipset: AmdChipset::PinnacleRidge,
    },
    // AMD FCH 790b - Raven Ridge/Matisse/Starship (rev 0x61) - SPI100
    AmdChipsetEnable {
        vendor_id: AMD_VID,
        device_id: 0x790b,
        revision: RevisionMatch::Exact(0x61),
        device_name: "Raven Ridge/Matisse/Starship",
        chipset: AmdChipset::RavenRidgeMatisseStarship,
    },
    // AMD FCH 790b - Mendocino/Van Gogh/Rembrandt/Raphael/Genoa (rev 0x71) - SPI100
    AmdChipsetEnable {
        vendor_id: AMD_VID,
        device_id: 0x790b,
        revision: RevisionMatch::Exact(0x71),
        device_name: "Mendocino/Rembrandt/Raphael/Genoa",
        chipset: AmdChipset::MendoncinoRembrandt,
    },
];

/// Find a matching AMD chipset entry
///
/// Searches the AMD chipset database for a device matching the given
/// vendor ID, device ID, and revision ID.
pub fn find_chipset(
    vendor_id: u16,
    device_id: u16,
    revision_id: u8,
) -> Option<&'static AmdChipsetEnable> {
    AMD_CHIPSETS
        .iter()
        .find(|entry| entry.matches(vendor_id, device_id, revision_id))
}

//! Intel Chipset PCI ID Table
//!
//! This module contains the PCI device IDs for Intel chipsets and their
//! corresponding SPI controller types, ported from flashprog's chipset_enable.c.

use super::INTEL_VID;

/// Intel chipset generation/type
///
/// This enum defines the SPI controller variants and their register layouts.
/// The ordering is significant: chipsets are grouped by compatible SPI engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum IchChipset {
    /// Unknown chipset
    Unknown = 0,
    /// ICH7
    Ich7,

    // ======== ICH9 compatible from here on ========
    /// ICH8 (first ICH9-compatible SPI engine)
    Ich8,
    /// ICH9
    Ich9,
    /// ICH10
    Ich10,
    /// 5 Series (Ibex Peak)
    Series5IbexPeak,
    /// 6 Series (Cougar Point)
    Series6CougarPoint,
    /// 7 Series (Panther Point)
    Series7PantherPoint,
    /// Bay Trail / Avoton / Rangeley (Silvermont architecture)
    BayTrail,

    // ======== New component density from here on ========
    /// 8 Series (Lynx Point)
    Series8LynxPoint,
    /// 8 Series LP (Lynx Point LP)
    Series8LynxPointLp,
    /// 9 Series (Wildcat Point)
    Series9WildcatPoint,
    /// 9 Series LP (Wildcat Point LP)
    Series9WildcatPointLp,

    // ======== PCH100 compatible from here on ========
    /// 100 Series (Sunrise Point)
    Series100SunrisePoint,
    /// C620 Series (Lewisburg)
    C620Lewisburg,
    /// 300 Series (Cannon Point)
    Series300CannonPoint,
    /// 400/500 Series (Tiger Point)
    Series500TigerPoint,
    /// Apollo Lake
    ApolloLake,
    /// Gemini Lake
    GeminiLake,
    /// Elkhart Lake
    ElkhartLake,

    // ======== New access permissions from here on ========
    /// C740 Series (Emmitsburg)
    C740Emmitsburg,
    /// Meteor Lake
    MeteorLake,
    /// Lunar Lake
    LunarLake,
    /// Arrow Lake
    ArrowLake,
}

impl IchChipset {
    /// Marker for ICH9-compatible SPI engine
    pub const SPI_ENGINE_ICH9: Self = Self::Ich8;

    /// Marker for PCH100-compatible SPI engine
    pub const SPI_ENGINE_PCH100: Self = Self::Series100SunrisePoint;

    /// Marker for new access permission registers (BM_RAP/WAP)
    pub const HAS_NEW_ACCESS_PERM: Self = Self::C740Emmitsburg;

    /// Returns true if this chipset uses ICH9-compatible SPI engine
    pub fn is_ich9_compatible(self) -> bool {
        self >= Self::SPI_ENGINE_ICH9
    }

    /// Returns true if this chipset uses PCH100-compatible SPI engine
    pub fn is_pch100_compatible(self) -> bool {
        self >= Self::SPI_ENGINE_PCH100
    }

    /// Returns true if this chipset has new access permission registers
    pub fn has_new_access_perm(self) -> bool {
        self >= Self::HAS_NEW_ACCESS_PERM
    }

    /// Returns true if this chipset supports hardware sequencing (hwseq)
    ///
    /// Hardware sequencing was introduced with ICH8. ICH7 only supports
    /// software sequencing.
    pub fn supports_hwseq(self) -> bool {
        self >= Self::SPI_ENGINE_ICH9
    }

    /// Returns true if this chipset defaults to hwseq when in auto mode
    ///
    /// PCH100+ series defaults to hwseq because swseq is often locked
    /// and hwseq provides better compatibility.
    pub fn defaults_to_hwseq(self) -> bool {
        self >= Self::SPI_ENGINE_PCH100
    }
}

impl core::fmt::Display for IchChipset {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unknown => write!(f, "Unknown"),
            Self::Ich7 => write!(f, "ICH7"),
            Self::Ich8 => write!(f, "ICH8"),
            Self::Ich9 => write!(f, "ICH9"),
            Self::Ich10 => write!(f, "ICH10"),
            Self::Series5IbexPeak => write!(f, "5 Series (Ibex Peak)"),
            Self::Series6CougarPoint => write!(f, "6 Series (Cougar Point)"),
            Self::Series7PantherPoint => write!(f, "7 Series (Panther Point)"),
            Self::BayTrail => write!(f, "Bay Trail"),
            Self::Series8LynxPoint => write!(f, "8 Series (Lynx Point)"),
            Self::Series8LynxPointLp => write!(f, "8 Series LP (Lynx Point LP)"),
            Self::Series9WildcatPoint => write!(f, "9 Series (Wildcat Point)"),
            Self::Series9WildcatPointLp => write!(f, "9 Series LP (Wildcat Point LP)"),
            Self::Series100SunrisePoint => write!(f, "100 Series (Sunrise Point)"),
            Self::C620Lewisburg => write!(f, "C620 (Lewisburg)"),
            Self::Series300CannonPoint => write!(f, "300 Series (Cannon Point)"),
            Self::Series500TigerPoint => write!(f, "500 Series (Tiger Point)"),
            Self::ApolloLake => write!(f, "Apollo Lake"),
            Self::GeminiLake => write!(f, "Gemini Lake"),
            Self::ElkhartLake => write!(f, "Elkhart Lake"),
            Self::C740Emmitsburg => write!(f, "C740 (Emmitsburg)"),
            Self::MeteorLake => write!(f, "Meteor Lake"),
            Self::LunarLake => write!(f, "Lunar Lake"),
            Self::ArrowLake => write!(f, "Arrow Lake"),
        }
    }
}

/// A chipset enable entry in the PCI ID table
#[derive(Debug, Clone)]
pub struct ChipsetEnable {
    /// PCI vendor ID
    pub vendor_id: u16,
    /// PCI device ID
    pub device_id: u16,
    /// Device/chipset name
    pub device_name: &'static str,
    /// Chipset type (determines which register layout to use)
    pub chipset: IchChipset,
}

impl ChipsetEnable {
    /// Create a new chipset enable entry
    const fn new(
        vendor_id: u16,
        device_id: u16,
        device_name: &'static str,
        chipset: IchChipset,
    ) -> Self {
        Self {
            vendor_id,
            device_id,
            device_name,
            chipset,
        }
    }
}

/// Intel chipset PCI ID table
///
/// Keep this list sorted by device ID for easier maintenance.
/// Based on flashprog's chipset_enables[] array.
pub static INTEL_CHIPSETS: &[ChipsetEnable] = &[
    // Bay Trail
    ChipsetEnable::new(INTEL_VID, 0x0f1c, "Bay Trail", IchChipset::BayTrail),
    // Braswell
    ChipsetEnable::new(INTEL_VID, 0x229c, "Braswell", IchChipset::BayTrail),
    // ICH7
    ChipsetEnable::new(INTEL_VID, 0x27b0, "ICH7DH", IchChipset::Ich7),
    ChipsetEnable::new(INTEL_VID, 0x27b8, "ICH7/ICH7R", IchChipset::Ich7),
    ChipsetEnable::new(INTEL_VID, 0x27b9, "ICH7M", IchChipset::Ich7),
    ChipsetEnable::new(INTEL_VID, 0x27bc, "NM10", IchChipset::Ich7),
    ChipsetEnable::new(INTEL_VID, 0x27bd, "ICH7MDH", IchChipset::Ich7),
    // ICH8
    ChipsetEnable::new(INTEL_VID, 0x2810, "ICH8/ICH8R", IchChipset::Ich8),
    ChipsetEnable::new(INTEL_VID, 0x2811, "ICH8M-E", IchChipset::Ich8),
    ChipsetEnable::new(INTEL_VID, 0x2812, "ICH8DH", IchChipset::Ich8),
    ChipsetEnable::new(INTEL_VID, 0x2814, "ICH8DO", IchChipset::Ich8),
    ChipsetEnable::new(INTEL_VID, 0x2815, "ICH8M", IchChipset::Ich8),
    // ICH9
    ChipsetEnable::new(INTEL_VID, 0x2912, "ICH9DH", IchChipset::Ich9),
    ChipsetEnable::new(INTEL_VID, 0x2914, "ICH9DO", IchChipset::Ich9),
    ChipsetEnable::new(INTEL_VID, 0x2916, "ICH9R", IchChipset::Ich9),
    ChipsetEnable::new(INTEL_VID, 0x2917, "ICH9M-E", IchChipset::Ich9),
    ChipsetEnable::new(INTEL_VID, 0x2918, "ICH9", IchChipset::Ich9),
    ChipsetEnable::new(INTEL_VID, 0x2919, "ICH9M", IchChipset::Ich9),
    // Gemini Lake
    ChipsetEnable::new(INTEL_VID, 0x31e8, "Gemini Lake", IchChipset::GeminiLake),
    // ICH10
    ChipsetEnable::new(INTEL_VID, 0x3a14, "ICH10DO", IchChipset::Ich10),
    ChipsetEnable::new(INTEL_VID, 0x3a16, "ICH10R", IchChipset::Ich10),
    ChipsetEnable::new(INTEL_VID, 0x3a18, "ICH10", IchChipset::Ich10),
    ChipsetEnable::new(INTEL_VID, 0x3a1a, "ICH10D", IchChipset::Ich10),
    // 5 Series (Ibex Peak)
    ChipsetEnable::new(INTEL_VID, 0x3b02, "P55", IchChipset::Series5IbexPeak),
    ChipsetEnable::new(INTEL_VID, 0x3b03, "PM55", IchChipset::Series5IbexPeak),
    ChipsetEnable::new(INTEL_VID, 0x3b06, "H55", IchChipset::Series5IbexPeak),
    ChipsetEnable::new(INTEL_VID, 0x3b07, "QM57", IchChipset::Series5IbexPeak),
    ChipsetEnable::new(INTEL_VID, 0x3b09, "HM55", IchChipset::Series5IbexPeak),
    ChipsetEnable::new(INTEL_VID, 0x3b0f, "QS57", IchChipset::Series5IbexPeak),
    // 500 Series (Tiger Point)
    ChipsetEnable::new(
        INTEL_VID,
        0x4380,
        "Z590/H570/W580/Q570",
        IchChipset::Series500TigerPoint,
    ),
    ChipsetEnable::new(
        INTEL_VID,
        0x4381,
        "H510/B560",
        IchChipset::Series500TigerPoint,
    ),
    ChipsetEnable::new(INTEL_VID, 0x4387, "HM570", IchChipset::Series500TigerPoint),
    ChipsetEnable::new(
        INTEL_VID,
        0x4388,
        "QM580/WM590",
        IchChipset::Series500TigerPoint,
    ),
    // Elkhart Lake
    ChipsetEnable::new(INTEL_VID, 0x4b23, "Elkhart Lake", IchChipset::ElkhartLake),
    // Apollo Lake
    ChipsetEnable::new(INTEL_VID, 0x5ae8, "Apollo Lake", IchChipset::ApolloLake),
    // Meteor Lake
    ChipsetEnable::new(INTEL_VID, 0x7e23, "Meteor Lake", IchChipset::MeteorLake),
    // 6 Series (Cougar Point)
    ChipsetEnable::new(INTEL_VID, 0x1c44, "Z68", IchChipset::Series6CougarPoint),
    ChipsetEnable::new(INTEL_VID, 0x1c46, "P67", IchChipset::Series6CougarPoint),
    ChipsetEnable::new(INTEL_VID, 0x1c49, "HM65", IchChipset::Series6CougarPoint),
    ChipsetEnable::new(INTEL_VID, 0x1c4a, "H67", IchChipset::Series6CougarPoint),
    ChipsetEnable::new(INTEL_VID, 0x1c4e, "Q67", IchChipset::Series6CougarPoint),
    ChipsetEnable::new(INTEL_VID, 0x1c4f, "QM67", IchChipset::Series6CougarPoint),
    ChipsetEnable::new(INTEL_VID, 0x1c5c, "H61", IchChipset::Series6CougarPoint),
    // 7 Series (Panther Point)
    ChipsetEnable::new(INTEL_VID, 0x1e44, "Z77", IchChipset::Series7PantherPoint),
    ChipsetEnable::new(INTEL_VID, 0x1e47, "Q77", IchChipset::Series7PantherPoint),
    ChipsetEnable::new(INTEL_VID, 0x1e49, "B75", IchChipset::Series7PantherPoint),
    ChipsetEnable::new(INTEL_VID, 0x1e4a, "H77", IchChipset::Series7PantherPoint),
    ChipsetEnable::new(INTEL_VID, 0x1e55, "QM77", IchChipset::Series7PantherPoint),
    ChipsetEnable::new(INTEL_VID, 0x1e57, "HM77", IchChipset::Series7PantherPoint),
    ChipsetEnable::new(INTEL_VID, 0x1e59, "HM76", IchChipset::Series7PantherPoint),
    // 8 Series (Lynx Point)
    ChipsetEnable::new(INTEL_VID, 0x8c44, "Z87", IchChipset::Series8LynxPoint),
    ChipsetEnable::new(INTEL_VID, 0x8c4a, "H87", IchChipset::Series8LynxPoint),
    ChipsetEnable::new(INTEL_VID, 0x8c4b, "HM87", IchChipset::Series8LynxPoint),
    ChipsetEnable::new(INTEL_VID, 0x8c4f, "QM87", IchChipset::Series8LynxPoint),
    ChipsetEnable::new(INTEL_VID, 0x8c50, "B85", IchChipset::Series8LynxPoint),
    ChipsetEnable::new(INTEL_VID, 0x8c54, "C224", IchChipset::Series8LynxPoint),
    ChipsetEnable::new(INTEL_VID, 0x8c5c, "H81", IchChipset::Series8LynxPoint),
    // 9 Series
    ChipsetEnable::new(INTEL_VID, 0x8cc4, "Z97", IchChipset::Series9WildcatPoint),
    ChipsetEnable::new(INTEL_VID, 0x8cc6, "H97", IchChipset::Series9WildcatPoint),
    // 8 Series LP (Lynx Point LP)
    ChipsetEnable::new(
        INTEL_VID,
        0x9c43,
        "Lynx Point LP Premium",
        IchChipset::Series8LynxPointLp,
    ),
    ChipsetEnable::new(
        INTEL_VID,
        0x9c45,
        "Lynx Point LP Mainstream",
        IchChipset::Series8LynxPointLp,
    ),
    // 9 Series LP
    ChipsetEnable::new(
        INTEL_VID,
        0x9cc3,
        "Broadwell U Premium",
        IchChipset::Series9WildcatPointLp,
    ),
    ChipsetEnable::new(
        INTEL_VID,
        0x9cc5,
        "Broadwell U Base",
        IchChipset::Series9WildcatPointLp,
    ),
    // 100 Series (Sunrise Point)
    ChipsetEnable::new(
        INTEL_VID,
        0x9d48,
        "Skylake U Premium",
        IchChipset::Series100SunrisePoint,
    ),
    ChipsetEnable::new(
        INTEL_VID,
        0x9d4e,
        "Kaby Lake U Premium",
        IchChipset::Series100SunrisePoint,
    ),
    ChipsetEnable::new(INTEL_VID, 0xa143, "H110", IchChipset::Series100SunrisePoint),
    ChipsetEnable::new(INTEL_VID, 0xa144, "H170", IchChipset::Series100SunrisePoint),
    ChipsetEnable::new(INTEL_VID, 0xa145, "Z170", IchChipset::Series100SunrisePoint),
    ChipsetEnable::new(INTEL_VID, 0xa146, "Q170", IchChipset::Series100SunrisePoint),
    ChipsetEnable::new(INTEL_VID, 0xa148, "B150", IchChipset::Series100SunrisePoint),
    ChipsetEnable::new(INTEL_VID, 0xa149, "C236", IchChipset::Series100SunrisePoint),
    ChipsetEnable::new(
        INTEL_VID,
        0xa150,
        "CM236",
        IchChipset::Series100SunrisePoint,
    ),
    // C620 Series (Lewisburg)
    ChipsetEnable::new(INTEL_VID, 0xa1a4, "C620 Series", IchChipset::C620Lewisburg),
    ChipsetEnable::new(INTEL_VID, 0xa1c1, "C621 Series", IchChipset::C620Lewisburg),
    ChipsetEnable::new(INTEL_VID, 0xa1c2, "C622 Series", IchChipset::C620Lewisburg),
    ChipsetEnable::new(INTEL_VID, 0xa1c3, "C624 Series", IchChipset::C620Lewisburg),
    ChipsetEnable::new(INTEL_VID, 0xa1c6, "C627 Series", IchChipset::C620Lewisburg),
    ChipsetEnable::new(INTEL_VID, 0xa1c7, "C628 Series", IchChipset::C620Lewisburg),
    // 300 Series (Cannon Point)
    ChipsetEnable::new(INTEL_VID, 0xa303, "H310", IchChipset::Series300CannonPoint),
    ChipsetEnable::new(INTEL_VID, 0xa304, "H370", IchChipset::Series300CannonPoint),
    ChipsetEnable::new(INTEL_VID, 0xa305, "Z390", IchChipset::Series300CannonPoint),
    ChipsetEnable::new(INTEL_VID, 0xa306, "Q370", IchChipset::Series300CannonPoint),
    ChipsetEnable::new(INTEL_VID, 0xa308, "B360", IchChipset::Series300CannonPoint),
    ChipsetEnable::new(INTEL_VID, 0xa30d, "HM370", IchChipset::Series300CannonPoint),
    ChipsetEnable::new(
        INTEL_VID,
        0xa324,
        "Cannon Point LP",
        IchChipset::Series300CannonPoint,
    ),
    // 400 Series (Comet Lake)
    ChipsetEnable::new(INTEL_VID, 0xa3c8, "B460", IchChipset::Series300CannonPoint),
    ChipsetEnable::new(INTEL_VID, 0xa3da, "H410", IchChipset::Series300CannonPoint),
    // Lunar Lake
    ChipsetEnable::new(INTEL_VID, 0xa823, "Lunar Lake", IchChipset::LunarLake),
    // Arrow Lake
    ChipsetEnable::new(INTEL_VID, 0xae23, "Arrow Lake", IchChipset::ArrowLake),
];

/// Find a chipset enable entry by PCI vendor/device ID
pub fn find_chipset(vendor_id: u16, device_id: u16) -> Option<&'static ChipsetEnable> {
    for enable in INTEL_CHIPSETS {
        if enable.vendor_id == vendor_id && enable.device_id == device_id {
            return Some(enable);
        }
    }
    None
}

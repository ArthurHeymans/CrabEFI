//! Fixed-width initialization, platform, and bridge records.

use crate::format::{EFI_PAGE_SIZE, MAX_SECTIONS, architecture};

pub const HANDOFF_VERSION: u32 = 3;
pub const MAX_EXTERNAL_RANGES: usize = 8;
pub const MAX_VARIABLES: usize = 64;
pub const MAX_VARIABLE_NAME_LEN: usize = 64;
pub const MAX_VARIABLE_DATA_SIZE: usize = 16 * 1024;
pub const MAX_CONFIGURATION_TABLES: usize = 24;

pub mod phase {
    pub const UNINITIALIZED: u8 = 0;
    pub const BOOT_ACTIVE: u8 = 1;
    pub const SEALED_PHYSICAL: u8 = 2;
    pub const VIRTUAL: u8 = 3;
}

pub mod time_mechanism {
    pub const UNSUPPORTED: u32 = 0;
    pub const X86_CMOS: u32 = 1;
    pub const PL031: u32 = 2;
    pub const GOLDFISH_RTC: u32 = 3;
}

pub mod reset_mechanism {
    pub const X86_LEGACY: u32 = 1;
    pub const PSCI_SMC: u32 = 2;
    pub const PSCI_HVC: u32 = 3;
    pub const SBI_SRST: u32 = 4;
}

pub mod configuration_policy {
    pub const PLATFORM_PHYSICAL: u32 = 1;
    pub const IMAGE_RUNTIME: u32 = 2;
    pub const EXTERNAL_PHYSICAL: u32 = 3;
}

pub mod bridge_operation {
    pub const PERSIST_WRITE: u32 = 1;
    pub const PERSIST_DELETE: u32 = 2;
}

/// Private lifecycle operations accepted by the existing finish-import export.
pub mod finish_import_operation {
    /// Initialize retained staging and publish its stable capsule pointer.
    pub const PREPARE_RETAINED_STAGING: u32 = 1;
    /// Replay and durably consume retained deferred writes while keeping imports open.
    pub const REPLAY_DEFERRED: u32 = 2;
    /// Derive final policy and reject all subsequent boot imports.
    pub const COMPLETE_IMPORT: u32 = 3;
}

/// UEFI memory descriptor shared by the boot allocator and runtime-image ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryDescriptor {
    pub memory_type: u32,
    pub padding: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

impl MemoryDescriptor {
    pub const fn new(
        memory_type: u32,
        physical_start: u64,
        number_of_pages: u64,
        attribute: u64,
    ) -> Self {
        Self {
            memory_type,
            padding: 0,
            physical_start,
            virtual_start: 0,
            number_of_pages,
            attribute,
        }
    }

    pub fn end(&self) -> u64 {
        self.number_of_pages
            .checked_mul(u64::from(EFI_PAGE_SIZE))
            .and_then(|size| self.physical_start.checked_add(size))
            .unwrap_or(u64::MAX)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoadedSection {
    pub physical_base: u64,
    pub image_offset: u32,
    pub byte_len: u32,
    pub flags: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuntimeExternalRange {
    /// Retained MMIO base required by an image-local architecture mechanism.
    pub physical_base: u64,
    pub byte_len: u64,
    pub attributes: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuntimeTimeConfig {
    pub mechanism: u32,
    pub reserved: u32,
    pub io_or_mmio_base: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuntimeResetConfig {
    pub mechanism: u32,
    pub reserved: u32,
    pub io_or_mmio_base: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeHandoff {
    pub abi_version: u32,
    pub struct_size: u32,
    pub architecture: u16,
    pub section_count: u16,
    pub range_count: u16,
    pub reserved0: u16,
    pub image_base: u64,
    pub image_size: u32,
    pub reserved1: u32,
    pub boot_bridge: u64,
    pub deferred_buffer_base: u64,
    pub deferred_buffer_size: u64,
    pub time: RuntimeTimeConfig,
    pub reset: RuntimeResetConfig,
    pub sections: [LoadedSection; MAX_SECTIONS],
    pub ranges: [RuntimeExternalRange; MAX_EXTERNAL_RANGES],
}

impl RuntimeHandoff {
    pub const fn empty() -> Self {
        Self {
            abi_version: HANDOFF_VERSION,
            struct_size: core::mem::size_of::<Self>() as u32,
            architecture: 0,
            section_count: 0,
            range_count: 0,
            reserved0: 0,
            image_base: 0,
            image_size: 0,
            reserved1: 0,
            boot_bridge: 0,
            deferred_buffer_base: 0,
            deferred_buffer_size: 0,
            time: RuntimeTimeConfig {
                mechanism: time_mechanism::UNSUPPORTED,
                reserved: 0,
                io_or_mmio_base: 0,
            },
            reset: RuntimeResetConfig {
                mechanism: reset_mechanism::X86_LEGACY,
                reserved: 0,
                io_or_mmio_base: 0,
            },
            sections: [LoadedSection {
                physical_base: 0,
                image_offset: 0,
                byte_len: 0,
                flags: 0,
                reserved: 0,
            }; MAX_SECTIONS],
            ranges: [RuntimeExternalRange {
                physical_base: 0,
                byte_len: 0,
                attributes: 0,
            }; MAX_EXTERNAL_RANGES],
        }
    }

    pub fn validate(&self) -> Result<(), HandoffError> {
        if self.abi_version != HANDOFF_VERSION
            || usize::try_from(self.struct_size).ok() != Some(core::mem::size_of::<Self>())
        {
            return Err(HandoffError::Version);
        }
        let section_count = usize::from(self.section_count);
        let range_count = usize::from(self.range_count);
        if section_count == 0
            || section_count > MAX_SECTIONS
            || range_count > MAX_EXTERNAL_RANGES
            || self.image_base == 0
            || self.image_size == 0
        {
            return Err(HandoffError::Count);
        }
        self.image_base
            .checked_add(u64::from(self.image_size))
            .ok_or(HandoffError::Overflow)?;
        self.sections[..section_count]
            .iter()
            .try_fold(0u64, |watermark, section| {
                if section.physical_base == 0
                    || !section
                        .physical_base
                        .is_multiple_of(u64::from(EFI_PAGE_SIZE))
                    || section.byte_len == 0
                {
                    return Err(HandoffError::Section);
                }
                let start = u64::from(section.image_offset);
                let end = start
                    .checked_add(u64::from(section.byte_len))
                    .ok_or(HandoffError::Overflow)?;
                let expected_physical = self
                    .image_base
                    .checked_add(start)
                    .ok_or(HandoffError::Overflow)?;
                section
                    .physical_base
                    .checked_add(u64::from(section.byte_len))
                    .ok_or(HandoffError::Overflow)?;
                if start < watermark
                    || end > u64::from(self.image_size)
                    || section.physical_base != expected_physical
                {
                    return Err(HandoffError::Section);
                }
                Ok(end)
            })?;

        if self.deferred_buffer_base == 0
            || self.deferred_buffer_size == 0
            || !self
                .deferred_buffer_base
                .is_multiple_of(u64::from(EFI_PAGE_SIZE))
            || !self
                .deferred_buffer_size
                .is_multiple_of(u64::from(EFI_PAGE_SIZE))
            || self
                .deferred_buffer_base
                .checked_add(self.deferred_buffer_size)
                .is_none()
            || self.sections[..section_count].iter().any(|section| {
                ranges_overlap(
                    section.physical_base,
                    u64::from(section.byte_len),
                    self.deferred_buffer_base,
                    self.deferred_buffer_size,
                )
            })
        {
            return Err(HandoffError::Range);
        }

        self.ranges[..range_count]
            .iter()
            .enumerate()
            .try_for_each(|(index, range)| {
                if range.physical_base == 0
                    || range.byte_len == 0
                    || !range.physical_base.is_multiple_of(u64::from(EFI_PAGE_SIZE))
                    || !range.byte_len.is_multiple_of(u64::from(EFI_PAGE_SIZE))
                    || range.physical_base.checked_add(range.byte_len).is_none()
                {
                    return Err(HandoffError::Range);
                }
                if ranges_overlap(
                    range.physical_base,
                    range.byte_len,
                    self.deferred_buffer_base,
                    self.deferred_buffer_size,
                ) || self.ranges[..index].iter().any(|previous| {
                    ranges_overlap(
                        previous.physical_base,
                        previous.byte_len,
                        range.physical_base,
                        range.byte_len,
                    )
                }) || self.sections[..section_count].iter().any(|section| {
                    ranges_overlap(
                        section.physical_base,
                        u64::from(section.byte_len),
                        range.physical_base,
                        range.byte_len,
                    )
                }) {
                    return Err(HandoffError::Range);
                }
                Ok(())
            })?;

        let mmio_width = match (self.architecture, self.time.mechanism) {
            (_, time_mechanism::UNSUPPORTED) | (architecture::X86_64, time_mechanism::X86_CMOS) => {
                None
            }
            (architecture::AARCH64, time_mechanism::PL031) => Some(4),
            (architecture::RISCV64, time_mechanism::GOLDFISH_RTC) => Some(8),
            _ => return Err(HandoffError::Mechanism),
        };
        match (self.architecture, self.reset.mechanism) {
            (architecture::X86_64, reset_mechanism::X86_LEGACY)
            | (architecture::AARCH64, reset_mechanism::PSCI_SMC | reset_mechanism::PSCI_HVC)
            | (architecture::RISCV64, reset_mechanism::SBI_SRST) => {}
            _ => return Err(HandoffError::Mechanism),
        }
        if let Some(width) = mmio_width {
            let end = self
                .time
                .io_or_mmio_base
                .checked_add(width)
                .ok_or(HandoffError::Overflow)?;
            if self.time.io_or_mmio_base == 0
                || !self.time.io_or_mmio_base.is_multiple_of(4)
                || !self.ranges[..range_count].iter().any(|range| {
                    range.physical_base <= self.time.io_or_mmio_base
                        && range
                            .physical_base
                            .checked_add(range.byte_len)
                            .is_some_and(|range_end| end <= range_end)
                })
            {
                return Err(HandoffError::Range);
            }
        }
        Ok(())
    }
}

fn ranges_overlap(a_base: u64, a_len: u64, b_base: u64, b_len: u64) -> bool {
    let Some(a_end) = a_base.checked_add(a_len) else {
        return true;
    };
    let Some(b_end) = b_base.checked_add(b_len) else {
        return true;
    };
    a_base < b_end && b_base < a_end
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffError {
    Version,
    Count,
    Section,
    Range,
    Overflow,
    Mechanism,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RelocationImport {
    pub patch_offset: u32,
    pub target_offset: u32,
    pub patch_section: u8,
    pub target_section: u8,
    pub kind: u16,
    pub reserved: [u8; 12],
}

/// Pointer-free serialized EFI timestamp used by boot variable import.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VariableTimestamp {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub pad1: u8,
    pub nanosecond: u32,
    pub timezone: i16,
    pub daylight: u8,
    pub pad2: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VariableImport {
    pub name_address: u64,
    pub name_len: u32,
    pub attributes: u32,
    pub guid: [u8; 16],
    pub data_address: u64,
    pub data_len: u32,
    pub timestamp_valid: u32,
    pub timestamp: VariableTimestamp,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BridgeRequest {
    pub operation: u32,
    pub attributes: u32,
    pub guid: [u8; 16],
    pub name_address: u64,
    pub name_len: u32,
    pub data_len: u32,
    pub data_address: u64,
    pub timestamp_valid: u32,
    pub reserved: u32,
    pub timestamp: VariableTimestamp,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfigurationRegistration {
    pub guid: [u8; 16],
    pub table_address: u64,
    pub policy: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConsoleRegistration {
    pub kind: u32,
    pub reserved: u32,
    pub handle: u64,
    pub protocol: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EsrtRegistration {
    pub firmware_guid: [u8; 16],
    pub firmware_version: u32,
    pub lowest_supported_version: u32,
    pub capsule_flags: u32,
    pub last_attempt_version: u32,
    pub last_attempt_status: u32,
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<MemoryDescriptor>() == 40);
const _: () = assert!(core::mem::size_of::<LoadedSection>() == 24);
const _: () = assert!(core::mem::size_of::<RuntimeExternalRange>() == 24);
const _: () = assert!(core::mem::size_of::<RuntimeTimeConfig>() == 16);
const _: () = assert!(core::mem::size_of::<RuntimeResetConfig>() == 16);
const _: () = assert!(core::mem::size_of::<RuntimeHandoff>() == 472);
const _: () = assert!(core::mem::size_of::<RelocationImport>() == 24);
const _: () = assert!(core::mem::size_of::<VariableTimestamp>() == 16);
const _: () = assert!(core::mem::size_of::<VariableImport>() == 64);
const _: () = assert!(core::mem::size_of::<BridgeRequest>() == 72);
const _: () = assert!(core::mem::size_of::<ConfigurationRegistration>() == 32);
const _: () = assert!(core::mem::size_of::<ConsoleRegistration>() == 24);
const _: () = assert!(core::mem::size_of::<EsrtRegistration>() == 40);

//! Normalized runtime image file format and checked parser.

use core::fmt;

pub const MAGIC: [u8; 8] = *b"CRABRTI\0";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 64;
pub const SECTION_SIZE: usize = 32;
pub const RELOCATION_SIZE: usize = 24;
pub const EXPORTS_SIZE: usize = 64;
pub const EXPORTS_VERSION: u16 = 1;
pub const MAX_SECTIONS: usize = 8;
/// The normalized image permits a bounded relocation manifest. Current
/// supported images use fewer than 32 slots; 128 leaves audited growth room
/// without placing a multi-kilobyte zero manifest in RuntimeServicesData.
pub const MAX_RELOCATIONS: usize = 128;
pub const EFI_PAGE_SIZE: u32 = 4096;

pub mod architecture {
    pub const X86_64: u16 = 1;
    pub const AARCH64: u16 = 2;
    pub const RISCV64: u16 = 3;
}

pub mod section_flags {
    pub const READ: u32 = 1 << 0;
    pub const WRITE: u32 = 1 << 1;
    pub const EXECUTE: u32 = 1 << 2;
    pub const ZERO_FILL: u32 = 1 << 3;
    pub const RELOCATION_SLOTS: u32 = 1 << 4;
    pub const KNOWN: u32 = READ | WRITE | EXECUTE | ZERO_FILL | RELOCATION_SLOTS;
}

pub mod feature_bits {
    pub const VARIABLES: u64 = 1 << 0;
    pub const VIRTUAL_MAP: u64 = 1 << 1;
    pub const RESET: u64 = 1 << 2;
    pub const TIME: u64 = 1 << 3;
    pub const REQUIRED: u64 = VARIABLES | VIRTUAL_MAP | RESET | TIME;
    pub const KNOWN: u64 = REQUIRED;
}

/// Stable wire values for normalized-image relocation records.
pub mod relocation_kind {
    pub const ABSOLUTE64: u16 = 1;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiError {
    Truncated,
    BadMagic,
    BadVersion,
    BadArchitecture,
    BadHeaderSize,
    BadAlignment,
    UnknownFeatures,
    TooManySections,
    TooManyRelocations,
    RangeOverflow,
    FileRange,
    ImageRange,
    SectionOverlap,
    UnknownSectionFlags,
    WritableExecutableSection,
    BadRelocation,
    BadExports,
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeImageHeader {
    pub architecture: u16,
    pub image_size: u32,
    pub section_offset: u32,
    pub section_count: u16,
    pub relocation_offset: u32,
    pub relocation_count: u32,
    pub exports_offset: u32,
    pub exports_size: u16,
    pub required_alignment: u32,
    pub feature_bits: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeSection {
    pub file_offset: u32,
    pub image_offset: u32,
    pub file_size: u32,
    pub memory_size: u32,
    pub alignment: u32,
    pub flags: u32,
}

impl RuntimeSection {
    pub const fn image_end(self) -> Option<u32> {
        self.image_offset.checked_add(self.memory_size)
    }

    pub const fn file_end(self) -> Option<u32> {
        self.file_offset.checked_add(self.file_size)
    }

    pub const fn executable(self) -> bool {
        self.flags & section_flags::EXECUTE != 0
    }

    pub const fn writable(self) -> bool {
        self.flags & section_flags::WRITE != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeRelocation {
    pub patch_offset: u32,
    pub target_offset: u32,
    pub patch_section: u8,
    pub target_section: u8,
    pub kind: RelocationKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelocationKind {
    Absolute64,
}

impl TryFrom<u16> for RelocationKind {
    type Error = AbiError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            relocation_kind::ABSOLUTE64 => Ok(Self::Absolute64),
            _ => Err(AbiError::BadRelocation),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeExportsV1 {
    pub init: u32,
    pub import_relocation: u32,
    pub import_variable: u32,
    pub finish_import: u32,
    pub activate: u32,
    pub register_configuration: u32,
    pub set_console: u32,
    pub install_esrt: u32,
    pub prepare_ebs: u32,
    pub seal: u32,
    pub runtime_services: u32,
    pub system_table: u32,
}

#[derive(Clone, Copy)]
pub struct ValidatedImage<'a> {
    bytes: &'a [u8],
    header: RuntimeImageHeader,
}

impl<'a> ValidatedImage<'a> {
    pub fn parse(bytes: &'a [u8], architecture: u16) -> Result<Self, AbiError> {
        if bytes.len() < HEADER_SIZE {
            return Err(AbiError::Truncated);
        }
        if bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(AbiError::BadMagic);
        }
        if read_u16(bytes, 8)? != FORMAT_VERSION {
            return Err(AbiError::BadVersion);
        }
        let found_arch = read_u16(bytes, 10)?;
        if found_arch != architecture {
            return Err(AbiError::BadArchitecture);
        }
        if usize::from(read_u16(bytes, 12)?) != HEADER_SIZE {
            return Err(AbiError::BadHeaderSize);
        }
        let header = RuntimeImageHeader {
            architecture: found_arch,
            image_size: read_u32(bytes, 16)?,
            section_offset: read_u32(bytes, 20)?,
            section_count: read_u16(bytes, 24)?,
            relocation_offset: read_u32(bytes, 28)?,
            relocation_count: read_u32(bytes, 32)?,
            exports_offset: read_u32(bytes, 36)?,
            exports_size: read_u16(bytes, 40)?,
            required_alignment: read_u32(bytes, 44)?,
            feature_bits: read_u64(bytes, 48)?,
        };

        if header.image_size == 0 {
            return Err(AbiError::ImageRange);
        }
        if header.required_alignment != EFI_PAGE_SIZE {
            return Err(AbiError::BadAlignment);
        }
        if header.feature_bits != feature_bits::REQUIRED {
            return Err(AbiError::UnknownFeatures);
        }
        if usize::from(header.section_count) > MAX_SECTIONS || header.section_count == 0 {
            return Err(AbiError::TooManySections);
        }
        if usize::try_from(header.relocation_count)
            .ok()
            .is_none_or(|count| count > MAX_RELOCATIONS)
        {
            return Err(AbiError::TooManyRelocations);
        }
        table_range(
            bytes,
            header.section_offset,
            u32::from(header.section_count),
            SECTION_SIZE,
        )?;
        table_range(
            bytes,
            header.relocation_offset,
            header.relocation_count,
            RELOCATION_SIZE,
        )?;
        if usize::from(header.exports_size) != EXPORTS_SIZE {
            return Err(AbiError::BadExports);
        }
        checked_range(bytes, header.exports_offset, u32::from(header.exports_size))?;

        let image = Self { bytes, header };
        image.validate_sections()?;
        image.validate_relocations()?;
        image.exports()?;
        Ok(image)
    }

    pub const fn header(&self) -> RuntimeImageHeader {
        self.header
    }

    pub fn section(&self, index: usize) -> Result<RuntimeSection, AbiError> {
        if index >= usize::from(self.header.section_count) {
            return Err(AbiError::ImageRange);
        }
        let offset = usize::try_from(self.header.section_offset)
            .ok()
            .and_then(|start| {
                index
                    .checked_mul(SECTION_SIZE)
                    .and_then(|n| start.checked_add(n))
            })
            .ok_or(AbiError::RangeOverflow)?;
        Ok(RuntimeSection {
            file_offset: read_u32(self.bytes, offset)?,
            image_offset: read_u32(self.bytes, offset + 4)?,
            file_size: read_u32(self.bytes, offset + 8)?,
            memory_size: read_u32(self.bytes, offset + 12)?,
            alignment: read_u32(self.bytes, offset + 16)?,
            flags: read_u32(self.bytes, offset + 20)?,
        })
    }

    pub fn relocation(&self, index: usize) -> Result<RuntimeRelocation, AbiError> {
        if index >= usize::try_from(self.header.relocation_count).unwrap_or(usize::MAX) {
            return Err(AbiError::BadRelocation);
        }
        let offset = usize::try_from(self.header.relocation_offset)
            .ok()
            .and_then(|start| {
                index
                    .checked_mul(RELOCATION_SIZE)
                    .and_then(|n| start.checked_add(n))
            })
            .ok_or(AbiError::RangeOverflow)?;
        if read_u64(self.bytes, offset + 8)? != 0 {
            return Err(AbiError::BadRelocation);
        }
        Ok(RuntimeRelocation {
            patch_offset: read_u32(self.bytes, offset)?,
            target_offset: read_u32(self.bytes, offset + 4)?,
            patch_section: *self.bytes.get(offset + 16).ok_or(AbiError::Truncated)?,
            target_section: *self.bytes.get(offset + 17).ok_or(AbiError::Truncated)?,
            kind: RelocationKind::try_from(read_u16(self.bytes, offset + 18)?)?,
        })
    }

    pub fn exports(&self) -> Result<RuntimeExportsV1, AbiError> {
        let offset =
            usize::try_from(self.header.exports_offset).map_err(|_| AbiError::BadExports)?;
        if read_u16(self.bytes, offset)? != EXPORTS_VERSION
            || usize::from(read_u16(self.bytes, offset + 2)?) != EXPORTS_SIZE
        {
            return Err(AbiError::BadExports);
        }
        let exports = RuntimeExportsV1 {
            init: read_u32(self.bytes, offset + 8)?,
            import_relocation: read_u32(self.bytes, offset + 12)?,
            import_variable: read_u32(self.bytes, offset + 16)?,
            finish_import: read_u32(self.bytes, offset + 20)?,
            activate: read_u32(self.bytes, offset + 24)?,
            register_configuration: read_u32(self.bytes, offset + 28)?,
            set_console: read_u32(self.bytes, offset + 32)?,
            install_esrt: read_u32(self.bytes, offset + 36)?,
            prepare_ebs: read_u32(self.bytes, offset + 40)?,
            seal: read_u32(self.bytes, offset + 44)?,
            runtime_services: read_u32(self.bytes, offset + 48)?,
            system_table: read_u32(self.bytes, offset + 52)?,
        };
        let image_size = self.header.image_size;
        let valid = [
            exports.init,
            exports.import_relocation,
            exports.import_variable,
            exports.finish_import,
            exports.activate,
            exports.register_configuration,
            exports.set_console,
            exports.install_esrt,
            exports.prepare_ebs,
            exports.seal,
            exports.runtime_services,
            exports.system_table,
        ]
        .into_iter()
        .all(|value| value < image_size);
        if !valid {
            return Err(AbiError::BadExports);
        }
        Ok(exports)
    }

    pub fn section_bytes(&self, section: RuntimeSection) -> Result<&'a [u8], AbiError> {
        checked_range(self.bytes, section.file_offset, section.file_size)
    }

    fn validate_sections(&self) -> Result<(), AbiError> {
        (0..usize::from(self.header.section_count)).try_fold(0u32, |watermark, index| {
            let section = self.section(index)?;
            if section.memory_size == 0
                || section.file_size > section.memory_size
                || (section.file_size < section.memory_size
                    && section.flags & section_flags::ZERO_FILL == 0)
                || (section.file_size == section.memory_size
                    && section.flags & section_flags::ZERO_FILL != 0)
                || section.alignment < EFI_PAGE_SIZE
                || !section.alignment.is_power_of_two()
                || !section.image_offset.is_multiple_of(section.alignment)
            {
                return Err(AbiError::BadAlignment);
            }
            if section.flags & !section_flags::KNOWN != 0 {
                return Err(AbiError::UnknownSectionFlags);
            }
            if section.executable() && section.writable() {
                return Err(AbiError::WritableExecutableSection);
            }
            if section.file_size != 0 {
                checked_range(self.bytes, section.file_offset, section.file_size)?;
            }
            let end = section.image_end().ok_or(AbiError::RangeOverflow)?;
            if end > self.header.image_size {
                return Err(AbiError::ImageRange);
            }
            if section.image_offset < watermark {
                return Err(AbiError::SectionOverlap);
            }
            Ok(end)
        })?;
        Ok(())
    }

    fn validate_relocations(&self) -> Result<(), AbiError> {
        (0..usize::try_from(self.header.relocation_count).map_err(|_| AbiError::BadRelocation)?)
            .try_for_each(|index| {
                let relocation = self.relocation(index)?;
                let patch_index = usize::from(relocation.patch_section);
                let target_index = usize::from(relocation.target_section);
                let patch = self
                    .section(patch_index)
                    .map_err(|_| AbiError::BadRelocation)?;
                let target = self
                    .section(target_index)
                    .map_err(|_| AbiError::BadRelocation)?;
                if patch.flags & section_flags::RELOCATION_SLOTS == 0
                    || relocation.patch_offset < patch.image_offset
                    || relocation
                        .patch_offset
                        .checked_add(8)
                        .is_none_or(|end| patch.image_end().is_none_or(|patch_end| end > patch_end))
                    || !relocation.patch_offset.is_multiple_of(8)
                    || relocation.target_offset < target.image_offset
                    || relocation.target_offset >= target.image_end().unwrap_or(0)
                {
                    return Err(AbiError::BadRelocation);
                }
                Ok(())
            })
    }
}

fn checked_range(bytes: &[u8], offset: u32, size: u32) -> Result<&[u8], AbiError> {
    let start = usize::try_from(offset).map_err(|_| AbiError::RangeOverflow)?;
    let len = usize::try_from(size).map_err(|_| AbiError::RangeOverflow)?;
    let end = start.checked_add(len).ok_or(AbiError::RangeOverflow)?;
    bytes.get(start..end).ok_or(AbiError::FileRange)
}

fn table_range(bytes: &[u8], offset: u32, count: u32, width: usize) -> Result<(), AbiError> {
    let size = usize::try_from(count)
        .ok()
        .and_then(|n| n.checked_mul(width))
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(AbiError::RangeOverflow)?;
    checked_range(bytes, offset, size).map(drop)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AbiError> {
    let raw: [u8; 2] = bytes
        .get(offset..offset.checked_add(2).ok_or(AbiError::RangeOverflow)?)
        .ok_or(AbiError::Truncated)?
        .try_into()
        .map_err(|_| AbiError::Truncated)?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AbiError> {
    let raw: [u8; 4] = bytes
        .get(offset..offset.checked_add(4).ok_or(AbiError::RangeOverflow)?)
        .ok_or(AbiError::Truncated)?
        .try_into()
        .map_err(|_| AbiError::Truncated)?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, AbiError> {
    let raw: [u8; 8] = bytes
        .get(offset..offset.checked_add(8).ok_or(AbiError::RangeOverflow)?)
        .ok_or(AbiError::Truncated)?
        .try_into()
        .map_err(|_| AbiError::Truncated)?;
    Ok(u64::from_le_bytes(raw))
}

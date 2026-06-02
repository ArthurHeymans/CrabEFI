//! CFR (Coreboot Form Representation) Parser
//!
//! This module parses coreboot's CFR data structure which exposes firmware
//! configuration options to payloads. CFR allows displaying and modifying
//! boot-time configurable options like "Hyper-Threading Enable", "SATA Mode", etc.
//!
//! # CFR Structure
//!
//! CFR records form a tree structure where:
//! - Root record (LB_TAG_CFR_ROOT) contains forms
//! - Forms (CFR_TAG_OPTION_FORM) contain options and can nest
//! - Options (BOOL, NUMBER, ENUM, VARCHAR) have names, help text, and defaults
//! - Each option has an `opt_name` for storage and `ui_name` for display
//! - Dependencies between options control visibility/grayout
//!
//! # Reference
//!
//! - coreboot/src/commonlib/include/commonlib/cfr.h
//! - coreboot/Documentation/drivers/cfr.md

use alloc::string::String;
use alloc::vec::Vec;
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

/// CFR version (must match coreboot)
pub const CFR_VERSION: u32 = 0x0000_0000;

/// Coreboot table tag for CFR root
pub const CB_TAG_CFR_ROOT: u32 = 0x0047;

// CFR record tags
pub const CFR_TAG_OPTION_FORM: u32 = 1;
pub const CFR_TAG_ENUM_VALUE: u32 = 2;
pub const CFR_TAG_OPTION_ENUM: u32 = 3;
pub const CFR_TAG_OPTION_NUMBER: u32 = 4;
pub const CFR_TAG_OPTION_BOOL: u32 = 5;
pub const CFR_TAG_OPTION_VARCHAR: u32 = 6;
pub const CFR_TAG_VARCHAR_OPT_NAME: u32 = 7;
pub const CFR_TAG_VARCHAR_UI_NAME: u32 = 8;
pub const CFR_TAG_VARCHAR_UI_HELPTEXT: u32 = 9;
pub const CFR_TAG_VARCHAR_DEF_VALUE: u32 = 10;
pub const CFR_TAG_OPTION_COMMENT: u32 = 11;
pub const CFR_TAG_DEP_VALUES: u32 = 12;

// CFR option flags
pub const CFR_OPTFLAG_READONLY: u32 = 1 << 0;
pub const CFR_OPTFLAG_INACTIVE: u32 = 1 << 1;
pub const CFR_OPTFLAG_SUPPRESS: u32 = 1 << 2;
pub const CFR_OPTFLAG_VOLATILE: u32 = 1 << 3;
pub const CFR_OPTFLAG_RUNTIME: u32 = 1 << 4;

// Numeric display flags
pub const CFR_NUM_OPT_DISPFLAG_HEX: u32 = 1 << 0;

/// CFR root record header (matches lb_cfr in coreboot_tables.h)
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct CbCfrRoot {
    pub tag: u32,
    pub size: u32,
    pub version: u32,
    pub checksum: u32,
}

/// Generic CFR record header
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct CfrHeader {
    pub tag: u32,
    pub size: u32,
}

/// CFR option form header
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct CfrOptionFormHeader {
    pub tag: u32,
    pub size: u32,
    pub object_id: u64,
    pub dependency_id: u64,
    pub flags: u32,
}

/// CFR numeric option header (BOOL, NUMBER, ENUM)
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct CfrNumericOptionHeader {
    pub tag: u32,
    pub size: u32,
    pub object_id: u64,
    pub dependency_id: u64,
    pub flags: u32,
    pub default_value: u32,
    pub min: u32,
    pub max: u32,
    pub step: u32,
    pub display_flags: u32,
}

/// CFR varchar option header
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct CfrVarcharOptionHeader {
    pub tag: u32,
    pub size: u32,
    pub object_id: u64,
    pub dependency_id: u64,
    pub flags: u32,
}

/// CFR option comment header
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct CfrCommentHeader {
    pub tag: u32,
    pub size: u32,
    pub object_id: u64,
    pub dependency_id: u64,
    pub flags: u32,
}

/// CFR enum value header
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct CfrEnumValueHeader {
    pub tag: u32,
    pub size: u32,
    pub value: u32,
}

/// CFR variable-length binary header (for strings and dep values)
#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Debug, Clone, Copy)]
pub struct CfrVarbinaryHeader {
    pub tag: u32,
    pub size: u32,
    pub data_length: u32,
}

/// Enum choice (value and display name)
#[derive(Debug, Clone)]
pub struct CfrEnumChoice {
    pub value: u32,
    pub ui_name: String,
}

/// CFR option type with type-specific data
#[derive(Debug, Clone)]
pub enum CfrOptionType {
    /// Boolean option (true/false)
    Bool { default: bool },

    /// Numeric option with range
    Number {
        default: u32,
        min: u32,
        max: u32,
        step: u32,
        hex_display: bool,
    },

    /// Enum option with discrete choices
    Enum {
        default: u32,
        choices: Vec<CfrEnumChoice>,
    },

    /// Variable-length string option
    Varchar { default: String },

    /// Comment (informational, not editable)
    Comment,
}

/// A single CFR option
#[derive(Debug, Clone)]
pub struct CfrOption {
    /// Unique object ID
    pub object_id: u64,
    /// Dependency on another option's object_id (0 = none)
    pub dependency_id: u64,
    /// Variable name (for storage)
    pub opt_name: String,
    /// Display name
    pub ui_name: String,
    /// Help text
    pub ui_helptext: String,
    /// Option flags
    pub flags: u32,
    /// Option type and type-specific data
    pub option_type: CfrOptionType,
    /// Dependency values: option is visible when the dependency's current value
    /// matches one of these. Empty means visible when dependency value != 0.
    pub dep_values: Vec<u32>,
}

impl CfrOption {
    /// Check if this option is editable (ignoring dependency state)
    pub fn is_editable(&self) -> bool {
        (self.flags & CFR_OPTFLAG_READONLY) == 0
            && (self.flags & CFR_OPTFLAG_INACTIVE) == 0
            && (self.flags & CFR_OPTFLAG_VOLATILE) == 0
            && !matches!(self.option_type, CfrOptionType::Comment)
    }

    /// Check if this option is visible (ignoring dependency state)
    pub fn is_visible(&self) -> bool {
        (self.flags & CFR_OPTFLAG_SUPPRESS) == 0
    }
}

/// A CFR form (category/group of options)
///
/// Nested subforms are flattened during parsing: the subform's ui_name is
/// inserted as a Comment option, then its options are inlined into the parent.
#[derive(Debug, Clone)]
pub struct CfrForm {
    /// Unique object ID
    pub object_id: u64,
    /// Dependency on another option's object_id (0 = none)
    pub dependency_id: u64,
    /// Display name
    pub ui_name: String,
    /// Form flags
    pub flags: u32,
    /// Options in this form (including flattened subform options)
    pub options: Vec<CfrOption>,
    /// Dependency values for this form
    pub dep_values: Vec<u32>,
}

impl CfrForm {
    /// Check if this form is visible (ignoring dependency state)
    pub fn is_visible(&self) -> bool {
        (self.flags & CFR_OPTFLAG_SUPPRESS) == 0
    }
}

/// Parsed CFR information
#[derive(Debug, Clone)]
pub struct CfrInfo {
    /// CFR version
    pub version: u32,
    /// Top-level forms
    pub forms: Vec<CfrForm>,
}

impl CfrInfo {
    pub fn new() -> Self {
        Self {
            version: CFR_VERSION,
            forms: Vec::new(),
        }
    }

    /// Get total number of options across all forms
    pub fn total_options(&self) -> usize {
        self.forms.iter().map(|f| f.options.len()).sum()
    }

    /// Find an option by object_id across all forms and read its current numeric value.
    /// Returns None if the option is not found or is not a numeric type.
    pub fn find_numeric_value(&self, object_id: u64) -> Option<u32> {
        if object_id == 0 {
            return None;
        }
        for form in &self.forms {
            for option in &form.options {
                if option.object_id == object_id {
                    let value = read_option_value(option);
                    return match value {
                        CfrValue::Bool(b) => Some(if b { 1 } else { 0 }),
                        CfrValue::Number(n) => Some(n),
                        _ => None,
                    };
                }
            }
        }
        None
    }

    /// Evaluate whether an option/form with the given dependency is visible.
    ///
    /// Returns true if:
    /// - dependency_id is 0 (no dependency)
    /// - The dependency option's current value matches one of dep_values
    /// - dep_values is empty and the dependency value != 0
    pub fn is_dependency_met(&self, dependency_id: u64, dep_values: &[u32]) -> bool {
        if dependency_id == 0 {
            return true;
        }
        match self.find_numeric_value(dependency_id) {
            Some(current) => {
                if dep_values.is_empty() {
                    current != 0
                } else {
                    dep_values.contains(&current)
                }
            }
            None => true, // If we can't find the dependency, show the option
        }
    }
}

impl Default for CfrInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// CRC32 computation (matching coreboot's CRC32 used in lb_cfr.checksum)
// ============================================================================

/// Compute CRC32 matching coreboot's crc_byte implementation.
/// This is the standard CRC-32 (ISO 3309, ITU-T V.42, Ethernet, PKZIP, etc.)
fn compute_crc32(data: &[u8]) -> u32 {
    // Use the same CRC32 as the rest of CrabEFI
    crate::efi::boot_services::compute_crc32(data)
}

// ============================================================================
// Parsing
// ============================================================================

/// Parse CFR data from coreboot tables
///
/// # Arguments
///
/// * `data` - Raw bytes starting from the CFR root record
///
/// # Returns
///
/// Parsed CFR info, or None if parsing fails
pub fn parse_cfr(data: &[u8]) -> Option<CfrInfo> {
    if data.len() < core::mem::size_of::<CbCfrRoot>() {
        log::warn!("CFR data too small for header");
        return None;
    }

    let Ok((root, _)) = CbCfrRoot::read_from_prefix(data) else {
        log::warn!("Failed to parse CFR root header");
        return None;
    };

    let tag = root.tag;
    let size = root.size;
    let version = root.version;
    let checksum = root.checksum;

    if tag != CB_TAG_CFR_ROOT {
        log::warn!("Invalid CFR root tag: {:#x}", tag);
        return None;
    }

    if version != CFR_VERSION {
        log::warn!(
            "Unsupported CFR version: {:#x} (expected {:#x})",
            version,
            CFR_VERSION
        );
        return None;
    }

    log::info!("Parsing CFR data: {} bytes", size);

    // Validate CRC32 checksum over the data after the root header
    let header_size = core::mem::size_of::<CbCfrRoot>();
    let total_size = (size as usize).min(data.len());
    if total_size > header_size {
        let payload = &data[header_size..total_size];
        let computed = compute_crc32(payload);
        if computed != checksum {
            log::warn!(
                "CFR CRC32 mismatch: computed {:#x}, expected {:#x} (continuing anyway)",
                computed,
                checksum
            );
        }
    }

    let mut info = CfrInfo::new();

    // Parse children (forms) after the root header
    if total_size > header_size {
        let children_data = &data[header_size..total_size];
        parse_top_level_children(children_data, &mut info.forms);
    }

    log::info!(
        "CFR parsed: {} forms, {} total options",
        info.forms.len(),
        info.total_options()
    );

    Some(info)
}

/// Parse top-level child records into forms
fn parse_top_level_children(data: &[u8], forms: &mut Vec<CfrForm>) {
    let mut offset = 0;

    while offset + 8 <= data.len() {
        let record_data = &data[offset..];

        let Ok((header, _)) = CfrHeader::read_from_prefix(record_data) else {
            break;
        };

        let tag = header.tag;
        let size = header.size as usize;

        if size < 8 || offset + size > data.len() {
            log::debug!("Invalid CFR record size {} at offset {}", size, offset);
            break;
        }

        let record_bytes = &data[offset..offset + size];

        if tag == CFR_TAG_OPTION_FORM {
            if let Some(form) = parse_form(record_bytes) {
                forms.push(form);
            }
        } else {
            log::trace!("Skipping non-form CFR record tag={}", tag);
        }

        offset += size;
    }
}

/// Parse a CFR option form
fn parse_form(data: &[u8]) -> Option<CfrForm> {
    if data.len() < core::mem::size_of::<CfrOptionFormHeader>() {
        return None;
    }

    let Ok((header, _)) = CfrOptionFormHeader::read_from_prefix(data) else {
        return None;
    };

    let object_id = header.object_id;
    let dependency_id = header.dependency_id;
    let flags = header.flags;

    let mut form = CfrForm {
        object_id,
        dependency_id,
        ui_name: String::new(),
        flags,
        options: Vec::new(),
        dep_values: Vec::new(),
    };

    let header_size = core::mem::size_of::<CfrOptionFormHeader>();
    let size = header.size as usize;

    if size > header_size && size <= data.len() {
        let children_data = &data[header_size..size];
        parse_form_children(children_data, &mut form);
    }

    Some(form)
}

/// Parse children of a form
fn parse_form_children(data: &[u8], form: &mut CfrForm) {
    let mut offset = 0;

    while offset + 8 <= data.len() {
        let record_data = &data[offset..];

        let Ok((header, _)) = CfrHeader::read_from_prefix(record_data) else {
            break;
        };

        let tag = header.tag;
        let size = header.size as usize;

        if size < 8 || offset + size > data.len() {
            break;
        }

        let record_bytes = &data[offset..offset + size];

        match tag {
            CFR_TAG_VARCHAR_UI_NAME => {
                if let Some(name) = parse_varbinary_string(record_bytes) {
                    form.ui_name = name;
                }
            }
            CFR_TAG_OPTION_FORM => {
                // Nested form: flatten into parent.
                // Insert the subform's ui_name as a section header comment,
                // then inline all its options.
                if let Some(subform) = parse_form(record_bytes) {
                    // Add a comment with the subform name as section header
                    let section_comment = CfrOption {
                        object_id: subform.object_id,
                        dependency_id: subform.dependency_id,
                        opt_name: String::new(),
                        ui_name: subform.ui_name,
                        ui_helptext: String::new(),
                        flags: subform.flags,
                        option_type: CfrOptionType::Comment,
                        dep_values: subform.dep_values,
                    };
                    form.options.push(section_comment);

                    // Inline all options from the nested form
                    form.options.extend(subform.options);
                }
            }
            CFR_TAG_OPTION_BOOL | CFR_TAG_OPTION_NUMBER | CFR_TAG_OPTION_ENUM => {
                if let Some(option) = parse_numeric_option(record_bytes, tag) {
                    form.options.push(option);
                }
            }
            CFR_TAG_OPTION_VARCHAR => {
                if let Some(option) = parse_varchar_option(record_bytes) {
                    form.options.push(option);
                }
            }
            CFR_TAG_OPTION_COMMENT => {
                if let Some(option) = parse_comment_option(record_bytes) {
                    form.options.push(option);
                }
            }
            CFR_TAG_DEP_VALUES => {
                parse_dep_values_into(record_bytes, &mut form.dep_values);
            }
            _ => {
                log::trace!("Unknown form child tag: {}", tag);
            }
        }

        offset += size;
    }
}

/// Parse a numeric option (BOOL, NUMBER, ENUM)
fn parse_numeric_option(data: &[u8], tag: u32) -> Option<CfrOption> {
    if data.len() < core::mem::size_of::<CfrNumericOptionHeader>() {
        return None;
    }

    let Ok((header, _)) = CfrNumericOptionHeader::read_from_prefix(data) else {
        return None;
    };

    let object_id = header.object_id;
    let dependency_id = header.dependency_id;
    let flags = header.flags;
    let default_value = header.default_value;
    let min = header.min;
    let max = header.max;
    let step = header.step;
    let display_flags = header.display_flags;
    let size = header.size as usize;

    let option_type = match tag {
        CFR_TAG_OPTION_BOOL => CfrOptionType::Bool {
            default: default_value != 0,
        },
        CFR_TAG_OPTION_NUMBER => CfrOptionType::Number {
            default: default_value,
            min,
            max,
            step: if step > 0 { step } else { 1 },
            hex_display: (display_flags & CFR_NUM_OPT_DISPFLAG_HEX) != 0,
        },
        CFR_TAG_OPTION_ENUM => CfrOptionType::Enum {
            default: default_value,
            choices: Vec::new(),
        },
        _ => return None,
    };

    let mut option = CfrOption {
        object_id,
        dependency_id,
        opt_name: String::new(),
        ui_name: String::new(),
        ui_helptext: String::new(),
        flags,
        option_type,
        dep_values: Vec::new(),
    };

    let header_size = core::mem::size_of::<CfrNumericOptionHeader>();
    if size > header_size && size <= data.len() {
        let children_data = &data[header_size..size];
        parse_option_children(children_data, &mut option);
    }

    Some(option)
}

/// Parse a varchar option
fn parse_varchar_option(data: &[u8]) -> Option<CfrOption> {
    if data.len() < core::mem::size_of::<CfrVarcharOptionHeader>() {
        return None;
    }

    let Ok((header, _)) = CfrVarcharOptionHeader::read_from_prefix(data) else {
        return None;
    };

    let object_id = header.object_id;
    let dependency_id = header.dependency_id;
    let flags = header.flags;
    let size = header.size as usize;

    let mut option = CfrOption {
        object_id,
        dependency_id,
        opt_name: String::new(),
        ui_name: String::new(),
        ui_helptext: String::new(),
        flags,
        option_type: CfrOptionType::Varchar {
            default: String::new(),
        },
        dep_values: Vec::new(),
    };

    let header_size = core::mem::size_of::<CfrVarcharOptionHeader>();
    if size > header_size && size <= data.len() {
        let children_data = &data[header_size..size];
        parse_option_children(children_data, &mut option);
    }

    Some(option)
}

/// Parse a comment option (informational)
fn parse_comment_option(data: &[u8]) -> Option<CfrOption> {
    if data.len() < core::mem::size_of::<CfrCommentHeader>() {
        return None;
    }

    let Ok((header, _)) = CfrCommentHeader::read_from_prefix(data) else {
        return None;
    };

    let object_id = header.object_id;
    let dependency_id = header.dependency_id;
    let flags = header.flags;
    let size = header.size as usize;

    let mut option = CfrOption {
        object_id,
        dependency_id,
        opt_name: String::new(),
        ui_name: String::new(),
        ui_helptext: String::new(),
        flags,
        option_type: CfrOptionType::Comment,
        dep_values: Vec::new(),
    };

    let header_size = core::mem::size_of::<CfrCommentHeader>();
    if size > header_size && size <= data.len() {
        let children_data = &data[header_size..size];
        parse_option_children(children_data, &mut option);
    }

    Some(option)
}

/// Parse children of an option
fn parse_option_children(data: &[u8], option: &mut CfrOption) {
    let mut offset = 0;

    while offset + 8 <= data.len() {
        let record_data = &data[offset..];

        let Ok((header, _)) = CfrHeader::read_from_prefix(record_data) else {
            break;
        };

        let tag = header.tag;
        let size = header.size as usize;

        if size < 8 || offset + size > data.len() {
            break;
        }

        let record_bytes = &data[offset..offset + size];

        match tag {
            CFR_TAG_VARCHAR_OPT_NAME => {
                if let Some(name) = parse_varbinary_string(record_bytes) {
                    option.opt_name = name;
                }
            }
            CFR_TAG_VARCHAR_UI_NAME => {
                if let Some(name) = parse_varbinary_string(record_bytes) {
                    option.ui_name = name;
                }
            }
            CFR_TAG_VARCHAR_UI_HELPTEXT => {
                if let Some(help) = parse_varbinary_string(record_bytes) {
                    option.ui_helptext = help;
                }
            }
            CFR_TAG_VARCHAR_DEF_VALUE => {
                if let CfrOptionType::Varchar { ref mut default } = option.option_type
                    && let Some(def) = parse_varbinary_string(record_bytes)
                {
                    *default = def;
                }
            }
            CFR_TAG_ENUM_VALUE => {
                if let CfrOptionType::Enum {
                    ref mut choices, ..
                } = option.option_type
                    && let Some(choice) = parse_enum_value(record_bytes)
                {
                    choices.push(choice);
                }
            }
            CFR_TAG_DEP_VALUES => {
                parse_dep_values_into(record_bytes, &mut option.dep_values);
            }
            _ => {
                log::trace!("Unknown option child tag: {}", tag);
            }
        }

        offset += size;
    }
}

/// Parse a varbinary record as a UTF-8 string
fn parse_varbinary_string(data: &[u8]) -> Option<String> {
    if data.len() < core::mem::size_of::<CfrVarbinaryHeader>() {
        return None;
    }

    let Ok((header, _)) = CfrVarbinaryHeader::read_from_prefix(data) else {
        return None;
    };

    let data_length = header.data_length as usize;
    let header_size = core::mem::size_of::<CfrVarbinaryHeader>();

    if header_size + data_length > data.len() {
        return None;
    }

    let string_data = &data[header_size..header_size + data_length];

    let nul_pos = string_data
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(string_data.len());
    let result = String::from_utf8_lossy(&string_data[..nul_pos]).into_owned();

    Some(result)
}

/// Parse dependency values from a CFR_TAG_DEP_VALUES varbinary record
fn parse_dep_values_into(data: &[u8], dep_values: &mut Vec<u32>) {
    if data.len() < core::mem::size_of::<CfrVarbinaryHeader>() {
        return;
    }

    let Ok((header, _)) = CfrVarbinaryHeader::read_from_prefix(data) else {
        return;
    };

    let data_length = header.data_length as usize;
    let header_size = core::mem::size_of::<CfrVarbinaryHeader>();

    if header_size + data_length > data.len() {
        return;
    }

    let payload = &data[header_size..header_size + data_length];
    // Dependency values are stored as an array of u32 (little-endian)
    let num_values = data_length / 4;
    for i in 0..num_values {
        let offset = i * 4;
        if offset + 4 <= payload.len() {
            let value = u32::from_le_bytes([
                payload[offset],
                payload[offset + 1],
                payload[offset + 2],
                payload[offset + 3],
            ]);
            dep_values.push(value);
        }
    }
}

/// Parse an enum value record
fn parse_enum_value(data: &[u8]) -> Option<CfrEnumChoice> {
    if data.len() < core::mem::size_of::<CfrEnumValueHeader>() {
        return None;
    }

    let Ok((header, _)) = CfrEnumValueHeader::read_from_prefix(data) else {
        return None;
    };

    let value = header.value;
    let size = header.size as usize;

    let mut choice = CfrEnumChoice {
        value,
        ui_name: String::new(),
    };

    let header_size = core::mem::size_of::<CfrEnumValueHeader>();
    if size > header_size && size <= data.len() {
        let children_data = &data[header_size..size];
        let mut offset = 0;

        while offset + 8 <= children_data.len() {
            let record_data = &children_data[offset..];

            let Ok((child_header, _)) = CfrHeader::read_from_prefix(record_data) else {
                break;
            };

            let child_tag = child_header.tag;
            let child_size = child_header.size as usize;

            if child_size < 8 || offset + child_size > children_data.len() {
                break;
            }

            if child_tag == CFR_TAG_VARCHAR_UI_NAME
                && let Some(name) =
                    parse_varbinary_string(&children_data[offset..offset + child_size])
            {
                choice.ui_name = name;
            }

            offset += child_size;
        }
    }

    Some(choice)
}

// ============================================================================
// CFR Variable Storage
// ============================================================================

/// GUID for coreboot CFR options: EficorebootNvDataGuid
///
/// {ceae4c1d-335b-4685-a4a0-fc4a94eea085}
///
/// This is the GUID used by coreboot's `get_uint_option()` / `set_uint_option()`
/// in `src/drivers/efi/option.c`. It must match exactly for coreboot to find
/// the variables we write.
pub const COREBOOT_CFR_GUID: r_efi::efi::Guid = r_efi::efi::Guid::from_fields(
    0xceae4c1d,
    0x335b,
    0x4685,
    0xa4,
    0xa0,
    &[0xfc, 0x4a, 0x94, 0xee, 0xa0, 0x85],
);

/// Value types for CFR options
#[derive(Debug, Clone, PartialEq)]
pub enum CfrValue {
    Bool(bool),
    Number(u32),
    Varchar(String),
}

impl CfrValue {
    /// Get default value from an option type
    pub fn from_option_type(opt_type: &CfrOptionType) -> Self {
        match opt_type {
            CfrOptionType::Bool { default } => CfrValue::Bool(*default),
            CfrOptionType::Number { default, .. } | CfrOptionType::Enum { default, .. } => {
                CfrValue::Number(*default)
            }
            CfrOptionType::Varchar { default } => CfrValue::Varchar(default.clone()),
            CfrOptionType::Comment => CfrValue::Bool(false),
        }
    }
}

/// Convert ASCII string to UCS-2 (UTF-16LE) for UEFI variable names
fn ascii_to_ucs2(s: &str) -> Vec<u16> {
    let mut result = Vec::with_capacity(s.len() + 1);
    for c in s.chars() {
        result.push(c as u16);
    }
    result.push(0); // NULL terminator
    result
}

/// Read a CFR option value from storage
///
/// Returns the stored value or falls back to the CFR default.
pub fn read_option_value(option: &CfrOption) -> CfrValue {
    use crate::state;

    let name = ascii_to_ucs2(&option.opt_name);

    let mut found_value = None;
    state::with_efi_mut(|efi_state| {
        for var in efi_state.variables.iter() {
            if !var.in_use {
                continue;
            }
            if var.vendor_guid != COREBOOT_CFR_GUID {
                continue;
            }
            let var_name_len = var
                .name
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(var.name.len());
            let name_len = name.len().saturating_sub(1); // Exclude NULL terminator
            if var_name_len != name_len {
                continue;
            }
            if var.name[..var_name_len] != name[..name_len] {
                continue;
            }

            // Found the variable - deserialize based on option type
            // All numeric types (Bool, Number, Enum) are stored as 4-byte LE u32
            // for compatibility with coreboot's get_uint_option()
            found_value = Some(match &option.option_type {
                CfrOptionType::Bool { .. } => {
                    let val = if var.data_size >= 4 {
                        u32::from_le_bytes([var.data[0], var.data[1], var.data[2], var.data[3]])
                    } else if var.data_size >= 1 {
                        var.data[0] as u32
                    } else {
                        0
                    };
                    CfrValue::Bool(val != 0)
                }
                CfrOptionType::Number { .. } | CfrOptionType::Enum { .. } => {
                    let val = if var.data_size >= 4 {
                        u32::from_le_bytes([var.data[0], var.data[1], var.data[2], var.data[3]])
                    } else if var.data_size >= 1 {
                        var.data[0] as u32
                    } else {
                        0
                    };
                    CfrValue::Number(val)
                }
                CfrOptionType::Varchar { .. } => {
                    let raw = &var.data[..var.data_size];
                    let nul_pos = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
                    CfrValue::Varchar(String::from_utf8_lossy(&raw[..nul_pos]).into_owned())
                }
                CfrOptionType::Comment => CfrValue::Bool(false),
            });
            break;
        }
    });

    found_value.unwrap_or_else(|| CfrValue::from_option_type(&option.option_type))
}

/// Write a CFR option value to storage
///
/// All numeric types (Bool, Number, Enum) are stored as 4-byte LE u32
/// for compatibility with coreboot's get_uint_option() which returns unsigned int.
pub fn write_option_value(option: &CfrOption, value: &CfrValue) -> Result<(), &'static str> {
    use crate::efi::varstore;
    use r_efi::efi;

    let name = ascii_to_ucs2(&option.opt_name);

    // Serialize value - all numeric types as 4-byte LE u32
    let data: Vec<u8> = match value {
        CfrValue::Bool(b) => {
            let val: u32 = if *b { 1 } else { 0 };
            val.to_le_bytes().to_vec()
        }
        CfrValue::Number(n) => n.to_le_bytes().to_vec(),
        CfrValue::Varchar(s) => {
            let mut v: Vec<u8> = s.as_bytes().to_vec();
            v.push(0); // NULL terminator
            v
        }
    };

    // Always use NV|BS|RT (0x07) to match coreboot's convention.
    // Coreboot's set_uint_option() in option.c always writes with these exact
    // attributes, and while get_uint_option() doesn't check attributes when
    // reading, consistency avoids potential issues with other consumers.
    let attrs = efi::VARIABLE_NON_VOLATILE
        | efi::VARIABLE_BOOTSERVICE_ACCESS
        | efi::VARIABLE_RUNTIME_ACCESS;

    varstore::persist_variable(&COREBOOT_CFR_GUID, &name, attrs, &data)
        .map_err(|_| "Failed to persist CFR variable")
}

/// Delete a CFR option from storage (revert to default)
pub fn delete_option_value(option: &CfrOption) -> Result<(), &'static str> {
    use crate::efi::varstore;

    let name = ascii_to_ucs2(&option.opt_name);

    varstore::delete_variable(&COREBOOT_CFR_GUID, &name)
        .map_err(|_| "Failed to delete CFR variable")
}

//! Minimal UEFI HII database and string protocols.
//!
//! The UEFI shell registers its compiled string packages at startup and reads
//! them back through these protocols.  CrabEFI keeps the original package-list
//! bytes and decodes strings on demand; it does not implement forms or fonts.

use alloc::vec::Vec;
use core::{ffi::c_void, ptr};
use r_efi::{
    efi::{Char8, Char16, Guid, Handle, Status},
    hii,
    protocols::{hii_database, hii_string},
};
use zerocopy::little_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

use crate::cell::{Local, StaticMut};

const MAX_PACKAGE_LIST_SIZE: usize = 16 * 1024 * 1024;
const MAX_PACKAGE_STORAGE: usize = 64 * 1024 * 1024;
const MAX_PACKAGE_LISTS: usize = 64;
const MAX_DYNAMIC_STRINGS: usize = 4096;
const MAX_DYNAMIC_STRING_STORAGE: usize = 8 * 1024 * 1024;

struct PackageList {
    handle: usize,
    driver_handle: usize,
    bytes: Vec<u8>,
    strings: Vec<DynamicString>,
}

struct DynamicString {
    id: hii::StringId,
    language: Vec<u8>,
    value: Vec<Char16>,
}

struct Database {
    next_handle: usize,
    packages: Vec<PackageList>,
}

impl Database {
    const fn new() -> Self {
        Self {
            next_handle: 1,
            packages: Vec::new(),
        }
    }
}

static DATABASE: Local<Database> = Local::new(Database::new());

static HII_DATABASE_PROTOCOL: StaticMut<hii_database::Protocol> =
    StaticMut::new(hii_database::Protocol {
        new_package_list,
        remove_package_list,
        update_package_list,
        list_package_lists,
        export_package_lists,
        register_package_notify,
        unregister_package_notify,
        find_keyboard_layouts,
        get_keyboard_layout,
        set_keyboard_layout,
        get_package_list_handle,
    });

static HII_STRING_PROTOCOL: StaticMut<hii_string::Protocol> =
    StaticMut::new(hii_string::Protocol {
        new_string,
        get_string,
        set_string,
        get_languages,
        get_secondary_languages,
    });

pub fn database_protocol() -> *mut c_void {
    HII_DATABASE_PROTOCOL.get().cast()
}

pub fn string_protocol() -> *mut c_void {
    HII_STRING_PROTOCOL.get().cast()
}

fn hii_handle(value: usize) -> hii::Handle {
    value as hii::Handle
}

fn handle_value(handle: hii::Handle) -> usize {
    handle as usize
}

/// `EFI_HII_PACKAGE_LIST_HEADER`
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
struct PackageListPrefix {
    package_list_guid: [u8; 16],
    package_length: U32,
}

/// `EFI_HII_PACKAGE_HEADER`: a 24-bit length followed by the package type.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
struct PackageHeader {
    length: [u8; 3],
    package_type: u8,
}

impl PackageHeader {
    fn length(self) -> usize {
        u32::from_le_bytes([self.length[0], self.length[1], self.length[2], 0]) as usize
    }
}

/// `EFI_HII_STRING_PACKAGE_HDR` up to the NUL-terminated language name.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
struct StringPackagePrefix {
    header: PackageHeader,
    header_size: U32,
    string_info_offset: U32,
    language_window: [U16; 16],
    language_name: U16,
}

const _: () = {
    assert!(core::mem::size_of::<PackageListPrefix>() == 20);
    assert!(core::mem::size_of::<PackageHeader>() == 4);
    assert!(core::mem::size_of::<StringPackagePrefix>() == 46);
};

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let (value, _) = U16::read_from_prefix(bytes.get(offset..)?).ok()?;
    Some(value.get())
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let (value, _) = U32::read_from_prefix(bytes.get(offset..)?).ok()?;
    Some(value.get())
}

fn package_list_prefix(bytes: &[u8]) -> Option<PackageListPrefix> {
    PackageListPrefix::read_from_prefix(bytes)
        .ok()
        .map(|(prefix, _)| prefix)
}

fn package_header(bytes: &[u8], offset: usize) -> Option<PackageHeader> {
    PackageHeader::read_from_prefix(bytes.get(offset..)?)
        .ok()
        .map(|(header, _)| header)
}

fn string_package_prefix(bytes: &[u8]) -> Option<StringPackagePrefix> {
    StringPackagePrefix::read_from_prefix(bytes)
        .ok()
        .map(|(prefix, _)| prefix)
}

fn package_list_bytes(header: *const hii::PackageListHeader) -> Result<Vec<u8>, Status> {
    if header.is_null() {
        return Err(Status::INVALID_PARAMETER);
    }

    // SAFETY: the HII protocol requires a non-null argument to reference a
    // complete package-list header. The wire header may be unaligned.
    let prefix = unsafe { ptr::read_unaligned(header.cast::<PackageListPrefix>()) };
    let length = prefix.package_length.get() as usize;
    if !(core::mem::size_of::<PackageListPrefix>()..=MAX_PACKAGE_LIST_SIZE).contains(&length) {
        return Err(Status::INVALID_PARAMETER);
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Status::OUT_OF_RESOURCES)?;
    bytes.extend_from_slice(unsafe { core::slice::from_raw_parts(header.cast::<u8>(), length) });
    if !valid_package_list(&bytes) {
        return Err(Status::INVALID_PARAMETER);
    }
    Ok(bytes)
}

fn valid_package_list(bytes: &[u8]) -> bool {
    if package_list_prefix(bytes).map(|prefix| prefix.package_length.get() as usize)
        != Some(bytes.len())
    {
        return false;
    }

    let mut offset = core::mem::size_of::<PackageListPrefix>();
    while offset + 4 <= bytes.len() {
        let Some(header) = package_header(bytes, offset) else {
            return false;
        };
        let length = header.length();
        let Some(end) = offset.checked_add(length) else {
            return false;
        };
        if length < 4 || end > bytes.len() {
            return false;
        }
        if header.package_type == hii::PACKAGE_END {
            return length == 4 && end == bytes.len();
        }
        offset = end;
    }
    false
}

fn language_of_package(package: &[u8]) -> Option<&[u8]> {
    string_package_prefix(package)?;
    let language_offset = core::mem::size_of::<StringPackagePrefix>();
    let end = package
        .get(language_offset..)?
        .iter()
        .position(|&c| c == 0)?;
    package.get(language_offset..language_offset + end)
}

fn language_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(&left, &right)| left.eq_ignore_ascii_case(&right))
}

fn primary_language(language_list: &[u8]) -> &[u8] {
    language_list
        .split(|&character| character == b';')
        .next()
        .unwrap_or_default()
}

fn language_matches(package: &[u8], language: &[u8]) -> bool {
    language_of_package(package)
        .is_some_and(|actual| language_eq(primary_language(actual), language))
}

#[derive(Clone, Copy)]
enum Encoding {
    /// ASCII subset of SCSU, which is all EDK2's English shell packages use.
    Scsu,
    Ucs2,
}

/// One `EFI_HII_SIBT_*` string information block.
enum Block {
    End,
    /// `count` consecutive strings starting at `offset`.
    Strings {
        encoding: Encoding,
        offset: usize,
        count: u16,
    },
    /// The next string ID repeats another string.
    Duplicate(hii::StringId),
    /// Reserve this many string IDs without defining strings.
    SkipIds(u16),
    /// Font and extension blocks, which carry no string IDs.
    Other,
}

/// Offset just past the NUL-terminated string starting at `start`.
fn string_end(package: &[u8], start: usize, encoding: Encoding) -> Option<usize> {
    match encoding {
        Encoding::Scsu => package
            .get(start..)?
            .iter()
            .position(|&byte| byte == 0)
            .map(|length| start + length + 1),
        Encoding::Ucs2 => package
            .get(start..)?
            .as_chunks::<2>()
            .0
            .iter()
            .position(|unit| *unit == [0, 0])
            .map(|index| start + index * 2 + 2),
    }
}

/// Borrow text while the database is locked. Getters, including size queries,
/// must work without allocating from the firmware's small boot heap.
enum StringValue<'a> {
    Dynamic(&'a [Char16]),
    Scsu(&'a [u8]),
    Ucs2(&'a [U16]),
}

impl StringValue<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Dynamic(value) => value.len(),
            Self::Scsu(value) => value.len(),
            Self::Ucs2(value) => value.len(),
        }
    }

    fn units(&self) -> impl Iterator<Item = Char16> + '_ {
        (0..self.len()).map(|index| match self {
            Self::Dynamic(value) => value[index],
            Self::Scsu(value) => Char16::from(value[index]),
            Self::Ucs2(value) => value[index].get(),
        })
    }
}

fn decode_string(package: &[u8], start: usize, encoding: Encoding) -> Option<StringValue<'_>> {
    let end = string_end(package, start, encoding)?;
    match encoding {
        Encoding::Scsu => {
            let bytes = &package[start..end - 1];
            bytes
                .iter()
                .all(|&byte| byte < 0x80)
                .then_some(StringValue::Scsu(bytes))
        }
        Encoding::Ucs2 => {
            let units = <[U16]>::ref_from_bytes(&package[start..end - 2]).ok()?;
            Some(StringValue::Ucs2(units))
        }
    }
}

/// Parse the block header at `*offset` and advance past the whole block.
fn next_block(package: &[u8], offset: &mut usize) -> Option<Block> {
    let start = *offset;
    let kind = *package.get(start)?;
    let mut at = start + 1;
    let block = match kind {
        0x00 => return Some(Block::End),
        // SIBT_STRING_SCSU[_FONT] and SIBT_STRING_UCS2[_FONT]
        0x10 | 0x11 | 0x14 | 0x15 => {
            let encoding = if kind < 0x14 {
                Encoding::Scsu
            } else {
                Encoding::Ucs2
            };
            if kind & 1 != 0 {
                at += 1; // Font identifier.
            }
            let first = at;
            at = string_end(package, first, encoding)?;
            Block::Strings {
                encoding,
                offset: first,
                count: 1,
            }
        }
        // SIBT_STRINGS_SCSU[_FONT] and SIBT_STRINGS_UCS2[_FONT]
        0x12 | 0x13 | 0x16 | 0x17 => {
            let encoding = if kind < 0x16 {
                Encoding::Scsu
            } else {
                Encoding::Ucs2
            };
            if kind & 1 != 0 {
                at += 1; // Font identifier.
            }
            let count = read_u16(package, at)?;
            at += 2;
            let first = at;
            for _ in 0..count {
                at = string_end(package, at, encoding)?;
            }
            Block::Strings {
                encoding,
                offset: first,
                count,
            }
        }
        0x20 => {
            let source = read_u16(package, at)?;
            at += 2;
            Block::Duplicate(source)
        }
        0x21 => {
            let count = read_u16(package, at)?;
            at += 2;
            Block::SkipIds(count)
        }
        0x22 => {
            let count = *package.get(at)?;
            at += 1;
            Block::SkipIds(count.into())
        }
        // Extension blocks store their total length after the block type
        // (EXT1: u8, EXT2: u16, EXT4: u32); EFI_HII_SIBT_FONT (0x40) shares
        // the EXT2 layout. They are skipped by length rather than failing the
        // whole package.
        0x30 | 0x31 | 0x32 | 0x40 => {
            let (length, minimum) = match kind {
                0x30 => (package.get(start + 2).map(|&length| length as usize)?, 3),
                0x32 => (read_u32(package, start + 2)? as usize, 6),
                _ => (read_u16(package, start + 2)? as usize, 4),
            };
            if length < minimum {
                return None;
            }
            at = start.checked_add(length)?;
            Block::Other
        }
        _ => return None,
    };
    *offset = at;
    Some(block)
}

fn find_string_value(package: &[u8], wanted: hii::StringId) -> Option<StringValue<'_>> {
    let (offset, encoding) = find_string_location(package, wanted, 0)?;
    decode_string(package, offset, encoding)
}

#[cfg(test)]
fn find_string_in_package(package: &[u8], wanted: hii::StringId) -> Option<Vec<Char16>> {
    find_string_value(package, wanted).map(|value| value.units().collect())
}

// Identity is structural: an unsupported encoding must not prevent a caller
// from replacing an existing string with a dynamic Unicode value.
fn find_string_location(
    package: &[u8],
    wanted: hii::StringId,
    duplicate_depth: u8,
) -> Option<(usize, Encoding)> {
    if duplicate_depth > 8 {
        return None;
    }

    let mut offset = string_package_prefix(package)?.string_info_offset.get() as usize;
    let mut id: hii::StringId = 1;
    loop {
        match next_block(package, &mut offset)? {
            Block::End => return None,
            Block::Strings {
                encoding,
                offset: first,
                count,
            } => {
                if let Some(index) = wanted.checked_sub(id).filter(|&index| index < count) {
                    let mut at = first;
                    for _ in 0..index {
                        at = string_end(package, at, encoding)?;
                    }
                    return Some((at, encoding));
                }
                id = id.checked_add(count)?;
            }
            Block::Duplicate(source) => {
                if id == wanted {
                    return find_string_location(package, source, duplicate_depth + 1);
                }
                id = id.checked_add(1)?;
            }
            Block::SkipIds(count) => id = id.checked_add(count)?,
            Block::Other => {}
        }
    }
}

fn max_string_id_in_package(package: &[u8]) -> Option<hii::StringId> {
    let mut offset = string_package_prefix(package)?.string_info_offset.get() as usize;
    let mut id: hii::StringId = 1;
    let mut max = 0;
    loop {
        let count = match next_block(package, &mut offset)? {
            Block::End => return Some(max),
            Block::Strings { count, .. } | Block::SkipIds(count) => count,
            Block::Duplicate(_) => 1,
            Block::Other => 0,
        };
        if count != 0 {
            max = id.checked_add(count - 1)?;
            id = max.checked_add(1)?;
        }
    }
}

fn string_packages(bytes: &[u8]) -> impl Iterator<Item = &[u8]> + Clone {
    let total = package_list_prefix(bytes).map_or(0, |prefix| prefix.package_length.get() as usize);
    let end = total.min(bytes.len());
    let mut offset = core::mem::size_of::<PackageListPrefix>();
    core::iter::from_fn(move || {
        while offset + core::mem::size_of::<PackageHeader>() <= end {
            let header = package_header(bytes, offset)?;
            let length = header.length();
            let package_end = offset.checked_add(length)?;
            if length < core::mem::size_of::<PackageHeader>() || package_end > end {
                offset = end;
                return None;
            }
            let start = offset;
            offset = package_end;
            if header.package_type == hii::PACKAGE_STRINGS {
                return bytes.get(start..package_end);
            }
        }
        None
    })
}

extern "efiapi" fn new_package_list(
    _this: *const hii_database::Protocol,
    package_list: *const hii::PackageListHeader,
    driver_handle: Handle,
    handle: *mut hii::Handle,
) -> Status {
    if handle.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let bytes = match package_list_bytes(package_list) {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };

    let mut database = DATABASE.borrow_mut();
    if database.packages.len() >= MAX_PACKAGE_LISTS
        || database
            .packages
            .iter()
            .map(|package| package.bytes.len())
            .sum::<usize>()
            .checked_add(bytes.len())
            .is_none_or(|total| total > MAX_PACKAGE_STORAGE)
        || database.packages.try_reserve(1).is_err()
    {
        return Status::OUT_OF_RESOURCES;
    }
    let value = database.next_handle;
    database.next_handle += 1;
    database.packages.push(PackageList {
        handle: value,
        driver_handle: driver_handle as usize,
        bytes,
        strings: Vec::new(),
    });
    unsafe { *handle = hii_handle(value) };
    Status::SUCCESS
}

extern "efiapi" fn remove_package_list(
    _this: *const hii_database::Protocol,
    handle: hii::Handle,
) -> Status {
    let mut database = DATABASE.borrow_mut();
    let Some(index) = database
        .packages
        .iter()
        .position(|package| package.handle == handle_value(handle))
    else {
        return Status::NOT_FOUND;
    };
    database.packages.remove(index);
    Status::SUCCESS
}

extern "efiapi" fn update_package_list(
    _this: *const hii_database::Protocol,
    _handle: hii::Handle,
    _package_list: *const hii::PackageListHeader,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn list_package_lists(
    _this: *const hii_database::Protocol,
    _package_type: u8,
    _package_guid: *const Guid,
    _handle_buffer_length: *mut usize,
    _handle_buffer: *mut hii::Handle,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn export_package_lists(
    _this: *const hii_database::Protocol,
    _handle: hii::Handle,
    _buffer_size: *mut usize,
    _buffer: *mut hii::PackageListHeader,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn register_package_notify(
    _this: *const hii_database::Protocol,
    _package_type: u8,
    _package_guid: *const Guid,
    _notify: hii_database::Notify,
    _notify_type: hii_database::NotifyType,
    _notify_handle: *mut Handle,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn unregister_package_notify(
    _this: *const hii_database::Protocol,
    _notification_handle: Handle,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn find_keyboard_layouts(
    _this: *const hii_database::Protocol,
    keyboard_layout_length: *mut u16,
    _keyboard_layout: *mut Guid,
) -> Status {
    if keyboard_layout_length.is_null() {
        return Status::INVALID_PARAMETER;
    }
    unsafe { *keyboard_layout_length = 0 };
    Status::NOT_FOUND
}

extern "efiapi" fn get_keyboard_layout(
    _this: *const hii_database::Protocol,
    _key_guid: *const Guid,
    _keyboard_layout_length: *mut u16,
    _keyboard_layout: *mut hii_database::KeyboardLayout,
) -> Status {
    Status::NOT_FOUND
}

extern "efiapi" fn set_keyboard_layout(
    _this: *const hii_database::Protocol,
    _key_guid: *mut Guid,
) -> Status {
    Status::NOT_FOUND
}

extern "efiapi" fn get_package_list_handle(
    _this: *const hii_database::Protocol,
    handle: hii::Handle,
    driver_handle: *mut Handle,
) -> Status {
    if driver_handle.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let database = DATABASE.borrow();
    let Some(package) = database
        .packages
        .iter()
        .find(|package| package.handle == handle_value(handle))
    else {
        return Status::NOT_FOUND;
    };
    unsafe { *driver_handle = package.driver_handle as Handle };
    Status::SUCCESS
}

// Protocol callers provide terminated, readable input strings. Borrow them
// only for this call; enforce limits before making any owned allocation.
unsafe fn language_bytes<'a>(language: *const Char8) -> Option<&'a [u8]> {
    if language.is_null() {
        return None;
    }
    for i in 0..256 {
        if unsafe { *language.add(i) } == 0 {
            return Some(unsafe { core::slice::from_raw_parts(language, i) });
        }
    }
    None
}

unsafe fn utf16_bytes<'a>(string: *const Char16) -> Option<&'a [Char16]> {
    if string.is_null() {
        return None;
    }
    for i in 0..(1 << 20) {
        if unsafe { *string.add(i) } == 0 {
            return Some(unsafe { core::slice::from_raw_parts(string, i) });
        }
    }
    None
}

fn try_copy<T: Copy>(input: &[T]) -> Result<Vec<T>, Status> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| Status::OUT_OF_RESOURCES)?;
    output.extend_from_slice(input);
    Ok(output)
}

fn owned_string(
    id: hii::StringId,
    language: &[u8],
    value: &[Char16],
) -> Result<DynamicString, Status> {
    Ok(DynamicString {
        id,
        language: try_copy(language)?,
        value: try_copy(value)?,
    })
}

fn dynamic_string_storage(package: &PackageList) -> usize {
    package
        .strings
        .iter()
        .map(|string| string.language.len() + string.value.len() * core::mem::size_of::<Char16>())
        .sum()
}

fn max_string_id(package: &PackageList) -> hii::StringId {
    let dynamic = package
        .strings
        .iter()
        .map(|string| string.id)
        .max()
        .unwrap_or(0);
    let compiled = string_packages(&package.bytes)
        .filter_map(max_string_id_in_package)
        .max()
        .unwrap_or(0);
    dynamic.max(compiled)
}

fn string_id_exists(package: &PackageList, id: hii::StringId) -> bool {
    package.strings.iter().any(|entry| entry.id == id)
        || string_packages(&package.bytes)
            .any(|strings| find_string_location(strings, id, 0).is_some())
}

fn has_language(package: &PackageList, language: &[u8]) -> bool {
    package
        .strings
        .iter()
        .any(|entry| language_eq(&entry.language, language))
        || string_packages(&package.bytes)
            .filter_map(language_of_package)
            .any(|languages| language_eq(primary_language(languages), language))
}

extern "efiapi" fn new_string(
    _this: *const hii_string::Protocol,
    package_list: hii::Handle,
    string_id: *mut hii::StringId,
    language: *const Char8,
    _language_name: *const Char16,
    string: *mut Char16,
    string_font_info: *const hii_string::Info,
) -> Status {
    // Fonts are not implemented, so no supplied font exists in this database.
    if string_id.is_null() || !string_font_info.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let Some(language) = (unsafe { language_bytes(language) }) else {
        return Status::INVALID_PARAMETER;
    };
    let Some(value) = (unsafe { utf16_bytes(string) }) else {
        return Status::INVALID_PARAMETER;
    };
    let mut database = DATABASE.borrow_mut();
    let Some(package) = database
        .packages
        .iter_mut()
        .find(|package| package.handle == handle_value(package_list))
    else {
        return Status::NOT_FOUND;
    };
    // StringId is an OUT parameter: the incoming value is undefined and must
    // never be reused as a hint, otherwise an uninitialized caller value can
    // collide with a compiled-in string.
    let Some(id) = max_string_id(package).checked_add(1) else {
        return Status::OUT_OF_RESOURCES;
    };
    let added = language.len() + core::mem::size_of_val(value);
    if package.strings.len() >= MAX_DYNAMIC_STRINGS
        || dynamic_string_storage(package)
            .checked_add(added)
            .is_none_or(|total| total > MAX_DYNAMIC_STRING_STORAGE)
    {
        return Status::OUT_OF_RESOURCES;
    }
    let string = match owned_string(id, language, value) {
        Ok(string) => string,
        Err(status) => return status,
    };
    if package.strings.try_reserve(1).is_err() {
        return Status::OUT_OF_RESOURCES;
    }
    package.strings.push(string);
    unsafe { *string_id = id };
    Status::SUCCESS
}

extern "efiapi" fn get_string(
    _this: *const hii_string::Protocol,
    language: *const Char8,
    package_list: hii::Handle,
    string_id: hii::StringId,
    string: *mut Char16,
    string_size: *mut usize,
    string_font_info: *mut *mut hii_string::Info,
) -> Status {
    if string_id == 0 || string_size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let Some(language_value) = (unsafe { language_bytes(language) }) else {
        return Status::INVALID_PARAMETER;
    };
    if string.is_null() && unsafe { *string_size } != 0 {
        return Status::INVALID_PARAMETER;
    }
    let database = DATABASE.borrow();
    let Some(package) = database
        .packages
        .iter()
        .find(|package| package.handle == handle_value(package_list))
    else {
        return Status::NOT_FOUND;
    };

    let value = package
        .strings
        .iter()
        .rev()
        .find(|entry| entry.id == string_id && language_eq(&entry.language, language_value))
        .map(|entry| StringValue::Dynamic(&entry.value))
        .or_else(|| {
            string_packages(&package.bytes)
                .find(|strings| language_matches(strings, language_value))
                .and_then(|strings| find_string_value(strings, string_id))
        });
    let Some(value) = value else {
        return if string_packages(&package.bytes)
            .filter(|strings| language_matches(strings, language_value))
            .any(|strings| find_string_location(strings, string_id, 0).is_some())
        {
            // The requested translation exists, but its encoding is not
            // implemented. Do not misreport an absent language or string ID.
            Status::UNSUPPORTED
        } else if string_id_exists(package, string_id) {
            Status::INVALID_LANGUAGE
        } else {
            Status::NOT_FOUND
        };
    };

    let required = (value.len() + 1) * core::mem::size_of::<Char16>();
    let supplied = unsafe { *string_size };
    unsafe { *string_size = required };
    if string.is_null() {
        return if supplied == 0 {
            Status::BUFFER_TOO_SMALL
        } else {
            Status::INVALID_PARAMETER
        };
    }
    if supplied < required {
        return Status::BUFFER_TOO_SMALL;
    }
    unsafe {
        for (index, unit) in value.units().enumerate() {
            *string.add(index) = unit;
        }
        *string.add(value.len()) = 0;
        if !string_font_info.is_null() {
            *string_font_info = ptr::null_mut();
        }
    }
    Status::SUCCESS
}

extern "efiapi" fn set_string(
    _this: *const hii_string::Protocol,
    package_list: hii::Handle,
    string_id: hii::StringId,
    language: *const Char8,
    string: *mut Char16,
    string_font_info: *const hii_string::Info,
) -> Status {
    if string_id == 0 || !string_font_info.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let Some(language) = (unsafe { language_bytes(language) }) else {
        return Status::INVALID_PARAMETER;
    };
    let Some(value) = (unsafe { utf16_bytes(string) }) else {
        return Status::INVALID_PARAMETER;
    };
    let mut database = DATABASE.borrow_mut();
    let Some(package) = database
        .packages
        .iter_mut()
        .find(|package| package.handle == handle_value(package_list))
    else {
        return Status::NOT_FOUND;
    };
    // SetString replaces an existing global ID, including a missing translation
    // reserved in a supported language. Only NewString allocates new IDs.
    if !string_id_exists(package, string_id) || !has_language(package, language) {
        return Status::NOT_FOUND;
    }
    if let Some(index) = package
        .strings
        .iter()
        .position(|entry| entry.id == string_id && language_eq(&entry.language, language))
    {
        let old = package.strings[index].value.len() * core::mem::size_of::<Char16>();
        let new = core::mem::size_of_val(value);
        if dynamic_string_storage(package)
            .checked_sub(old)
            .and_then(|total| total.checked_add(new))
            .is_none_or(|total| total > MAX_DYNAMIC_STRING_STORAGE)
        {
            return Status::OUT_OF_RESOURCES;
        }
        let value = match try_copy(value) {
            Ok(value) => value,
            Err(status) => return status,
        };
        package.strings[index].value = value;
    } else {
        let added = language.len() + core::mem::size_of_val(value);
        if package.strings.len() >= MAX_DYNAMIC_STRINGS
            || dynamic_string_storage(package)
                .checked_add(added)
                .is_none_or(|total| total > MAX_DYNAMIC_STRING_STORAGE)
        {
            return Status::OUT_OF_RESOURCES;
        }
        let string = match owned_string(string_id, language, value) {
            Ok(string) => string,
            Err(status) => return status,
        };
        if package.strings.try_reserve(1).is_err() {
            return Status::OUT_OF_RESOURCES;
        }
        package.strings.push(string);
    }
    Status::SUCCESS
}

fn package_languages(package: &PackageList) -> impl Iterator<Item = &[u8]> + Clone {
    string_packages(&package.bytes)
        .filter_map(language_of_package)
        .flat_map(|languages| languages.split(|&character| character == b';'))
        .chain(
            package
                .strings
                .iter()
                .map(|string| string.language.as_slice()),
        )
        .filter(|language| !language.is_empty())
}

fn supported_languages(package: &PackageList) -> impl Iterator<Item = &[u8]> + Clone {
    package_languages(package)
        .enumerate()
        .filter_map(move |(index, language)| {
            (!package_languages(package)
                .take(index)
                .any(|old| language_eq(old, language)))
            .then_some(language)
        })
}

// Size and write the borrowed language list in two passes, without allocating.
unsafe fn write_languages<'a>(
    value: impl Iterator<Item = &'a [u8]> + Clone,
    output: *mut Char8,
    size: *mut usize,
) -> Status {
    let required = value
        .clone()
        .map(|language| language.len() + 1)
        .sum::<usize>()
        .max(1);
    let supplied = unsafe { *size };
    unsafe { *size = required };
    if output.is_null() {
        return if supplied == 0 {
            Status::BUFFER_TOO_SMALL
        } else {
            Status::INVALID_PARAMETER
        };
    }
    if supplied < required {
        return Status::BUFFER_TOO_SMALL;
    }
    let mut offset = 0;
    for language in value {
        unsafe {
            if offset != 0 {
                *output.add(offset - 1) = b';';
            }
            ptr::copy_nonoverlapping(language.as_ptr(), output.add(offset), language.len());
        }
        offset += language.len() + 1;
    }
    unsafe { *output.add(required - 1) = 0 };
    Status::SUCCESS
}

extern "efiapi" fn get_languages(
    _this: *const hii_string::Protocol,
    package_list: hii::Handle,
    languages: *mut Char8,
    languages_size: *mut usize,
) -> Status {
    if languages_size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let database = DATABASE.borrow();
    let Some(package) = database
        .packages
        .iter()
        .find(|package| package.handle == handle_value(package_list))
    else {
        return Status::NOT_FOUND;
    };
    unsafe { write_languages(supported_languages(package), languages, languages_size) }
}

extern "efiapi" fn get_secondary_languages(
    _this: *const hii_string::Protocol,
    package_list: hii::Handle,
    requested_primary: *const Char8,
    secondary_languages: *mut Char8,
    secondary_languages_size: *mut usize,
) -> Status {
    if requested_primary.is_null() || secondary_languages_size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let Some(primary) = (unsafe { language_bytes(requested_primary) }) else {
        return Status::INVALID_PARAMETER;
    };
    let database = DATABASE.borrow();
    let Some(package) = database
        .packages
        .iter()
        .find(|package| package.handle == handle_value(package_list))
    else {
        return Status::NOT_FOUND;
    };

    let Some(language_list) = string_packages(&package.bytes)
        .filter_map(language_of_package)
        .find(|languages| language_eq(primary_language(languages), primary))
    else {
        return Status::INVALID_LANGUAGE;
    };
    let value = language_list
        .split(|&character| character == b';')
        .skip(1)
        .filter(|language| !language.is_empty());
    unsafe { write_languages(value, secondary_languages, secondary_languages_size) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Build an `en-US` string package whose string information blocks are `blocks`.
    fn string_package(blocks: &[u8]) -> Vec<u8> {
        let mut package = vec![0; 46];
        package[3] = hii::PACKAGE_STRINGS;
        package[4..8].copy_from_slice(&52u32.to_le_bytes());
        package[8..12].copy_from_slice(&52u32.to_le_bytes());
        package[44..46].copy_from_slice(&1u16.to_le_bytes());
        package.extend_from_slice(b"en-US\0");
        package.extend_from_slice(blocks);
        let length = package.len().to_le_bytes();
        package[..3].copy_from_slice(&length[..3]);
        package
    }

    fn ascii(text: &str) -> Vec<Char16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn decodes_shell_style_ucs2_blocks() {
        let package = string_package(&[
            0x14, b'O', 0, b'K', 0, 0, 0, // id 1
            0x22, 1, // skip id 2
            0x14, b'X', 0, 0, 0, // id 3
            0x00,
        ]);

        assert_eq!(find_string_in_package(&package, 1), Some(ascii("OK")));
        assert_eq!(find_string_in_package(&package, 2), None);
        assert_eq!(find_string_in_package(&package, 3), Some(ascii("X")));
        assert_eq!(max_string_id_in_package(&package), Some(3));
    }

    #[test]
    fn indexes_multi_string_scsu_blocks_duplicates_and_skips_fonts() {
        let package = string_package(&[
            0x12, 2, 0, b'a', 0, b'b', b'c', 0, // ids 1-2 (SCSU)
            0x40, 0, 6, 0, 0xaa, 0xbb, // font block: no string ids
            0x20, 2, 0, // id 3 repeats id 2
            0x00,
        ]);

        assert_eq!(find_string_in_package(&package, 1), Some(ascii("a")));
        assert_eq!(find_string_in_package(&package, 2), Some(ascii("bc")));
        assert_eq!(find_string_in_package(&package, 3), Some(ascii("bc")));
        assert_eq!(find_string_in_package(&package, 4), None);
        assert_eq!(max_string_id_in_package(&package), Some(3));
    }

    #[test]
    fn string_protocol_output_and_identity_contracts() {
        let mut bytes = vec![0u8; 20];
        bytes.extend_from_slice(&string_package(&[0x10, b'A', 0, 0x10, 0x80, 0, 0]));
        let mut french = string_package(&[0x22, 1, 0x10, b'B', 0, 0]);
        french[46..52].copy_from_slice(b"fr-FR\0");
        bytes.extend_from_slice(&french);
        bytes.extend_from_slice(&[4, 0, 0, hii::PACKAGE_END]);
        let length = bytes.len() as u32;
        bytes[16..20].copy_from_slice(&length.to_le_bytes());
        let mut handle = ptr::null_mut();
        assert_eq!(
            new_package_list(
                ptr::null(),
                bytes.as_ptr().cast(),
                ptr::null_mut(),
                &mut handle
            ),
            Status::SUCCESS
        );
        let mut output = [0u16; 4];
        let mut size = core::mem::size_of_val(&output);
        let mut font = 0x1234usize as *mut hii_string::Info;
        assert_eq!(
            get_string(
                ptr::null(),
                c"en-US".as_ptr().cast(),
                handle,
                1,
                output.as_mut_ptr(),
                &mut size,
                &mut font
            ),
            Status::SUCCESS
        );
        assert_eq!(output[..2], [b'A' as u16, 0]);
        assert!(font.is_null());
        assert_eq!(size, 4);
        for (language, expected) in [
            (c"en-US", Status::UNSUPPORTED),
            (c"de-DE", Status::INVALID_LANGUAGE),
        ] {
            assert_eq!(
                get_string(
                    ptr::null(),
                    language.as_ptr().cast(),
                    handle,
                    2,
                    output.as_mut_ptr(),
                    &mut size,
                    &mut font,
                ),
                expected
            );
        }
        let mut replacement = [b'X' as u16, 0];
        for (id, language, expected) in [
            (42, c"en-US", Status::NOT_FOUND),
            (1, c"de-DE", Status::NOT_FOUND),
            (1, c"fr-FR", Status::SUCCESS),
            (1, c"en-US", Status::SUCCESS),
            (2, c"en-US", Status::SUCCESS), // Override undecodable SCSU text.
        ] {
            assert_eq!(
                set_string(
                    ptr::null(),
                    handle,
                    id,
                    language.as_ptr().cast(),
                    replacement.as_mut_ptr(),
                    ptr::null()
                ),
                expected
            );
        }
        size = core::mem::size_of_val(&output);
        assert_eq!(
            get_string(
                ptr::null(),
                c"fr-FR".as_ptr().cast(),
                handle,
                1,
                output.as_mut_ptr(),
                &mut size,
                &mut font
            ),
            Status::SUCCESS
        );
        assert_eq!(output[..2], replacement);
        assert_eq!(
            get_string(
                ptr::null(),
                c"de-DE".as_ptr().cast(),
                handle,
                1,
                output.as_mut_ptr(),
                &mut size,
                &mut font
            ),
            Status::INVALID_LANGUAGE
        );
        assert_eq!(
            get_string(
                ptr::null(),
                c"en-US".as_ptr().cast(),
                handle,
                42,
                output.as_mut_ptr(),
                &mut size,
                &mut font
            ),
            Status::NOT_FOUND
        );
        let mut id = u16::MAX;
        assert_eq!(
            new_string(
                ptr::null(),
                handle,
                &mut id,
                c"en-US".as_ptr().cast(),
                ptr::null(),
                replacement.as_mut_ptr(),
                ptr::null()
            ),
            Status::SUCCESS
        );
        assert_eq!(id, 3);
        assert_eq!(
            set_string(
                ptr::null(),
                handle,
                1,
                c"en-US".as_ptr().cast(),
                replacement.as_mut_ptr(),
                0x1234usize as *const hii_string::Info
            ),
            Status::INVALID_PARAMETER
        );
        assert_eq!(remove_package_list(ptr::null(), handle), Status::SUCCESS);
    }

    #[test]
    fn rejects_truncated_blocks() {
        let package = string_package(&[0x14, b'O', 0, b'K']);
        assert_eq!(find_string_in_package(&package, 1), None);
    }
}

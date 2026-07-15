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

pub struct State {
    next_handle: usize,
    packages: Vec<PackageList>,
}

impl State {
    pub const fn new() -> Self {
        Self {
            next_handle: 1,
            packages: Vec::new(),
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::new()
    }
}

fn database() -> &'static mut State {
    // SAFETY: UEFI boot services are single-threaded and HII callbacks do not
    // re-enter HII state while this reference is live.
    unsafe { &mut (*crate::state::efi_mut_ptr()).hii }
}

static HII_DATABASE_PROTOCOL: hii_database::Protocol = hii_database::Protocol {
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
};

static HII_STRING_PROTOCOL: hii_string::Protocol = hii_string::Protocol {
    new_string,
    get_string,
    set_string,
    get_languages,
    get_secondary_languages,
};

pub fn database_protocol() -> *mut c_void {
    &HII_DATABASE_PROTOCOL as *const _ as *mut c_void
}

pub fn string_protocol() -> *mut c_void {
    &HII_STRING_PROTOCOL as *const _ as *mut c_void
}

fn hii_handle(value: usize) -> hii::Handle {
    value as hii::Handle
}

fn handle_value(handle: hii::Handle) -> usize {
    handle as usize
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn package_length(bytes: &[u8], offset: usize) -> Option<usize> {
    let header = bytes.get(offset..offset + 3)?;
    Some(header[0] as usize | ((header[1] as usize) << 8) | ((header[2] as usize) << 16))
}

fn package_type(bytes: &[u8], offset: usize) -> Option<u8> {
    bytes.get(offset + 3).copied()
}

fn package_list_bytes(header: *const hii::PackageListHeader) -> Result<Vec<u8>, Status> {
    if header.is_null() {
        return Err(Status::INVALID_PARAMETER);
    }

    let length = unsafe { ptr::read_unaligned(ptr::addr_of!((*header).package_length)) } as usize;
    if !(core::mem::size_of::<hii::PackageListHeader>()..=MAX_PACKAGE_LIST_SIZE).contains(&length) {
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
    if read_u32(bytes, 16).map(|length| length as usize) != Some(bytes.len()) {
        return false;
    }

    let mut offset = core::mem::size_of::<hii::PackageListHeader>();
    while offset + 4 <= bytes.len() {
        let Some(length) = package_length(bytes, offset) else {
            return false;
        };
        let Some(end) = offset.checked_add(length) else {
            return false;
        };
        if length < 4 || end > bytes.len() {
            return false;
        }
        if package_type(bytes, offset) == Some(hii::PACKAGE_END) {
            return length == 4 && end == bytes.len();
        }
        offset = end;
    }
    false
}

fn language_of_package(package: &[u8]) -> Option<&[u8]> {
    // Package header + HdrSize + StringInfoOffset + LanguageWindow + LanguageName.
    const LANGUAGE_OFFSET: usize = 4 + 4 + 4 + 32 + 2;
    let end = package
        .get(LANGUAGE_OFFSET..)?
        .iter()
        .position(|&c| c == 0)?;
    package.get(LANGUAGE_OFFSET..LANGUAGE_OFFSET + end)
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

fn language_matches(package: &[u8], language: *const Char8) -> bool {
    let Some(requested) = language_bytes(language) else {
        return false;
    };
    language_of_package(package)
        .is_some_and(|actual| language_eq(primary_language(actual), &requested))
}

fn ucs2_string(bytes: &[u8], offset: &mut usize) -> Option<Vec<Char16>> {
    let mut value = Vec::new();
    loop {
        let character = read_u16(bytes, *offset)?;
        *offset += 2;
        if character == 0 {
            return Some(value);
        }
        value.push(character);
    }
}

fn scsu_string(bytes: &[u8], offset: &mut usize) -> Option<Vec<Char16>> {
    // EDK2's English shell packages only need the ASCII subset of SCSU.
    let mut value = Vec::new();
    loop {
        let character = *bytes.get(*offset)?;
        *offset += 1;
        if character == 0 {
            return Some(value);
        }
        if character >= 0x80 {
            return None;
        }
        value.push(character as Char16);
    }
}

fn find_string_in_package(package: &[u8], wanted: hii::StringId) -> Option<Vec<Char16>> {
    find_string_in_package_inner(package, wanted, 0)
}

fn find_string_in_package_inner(
    package: &[u8],
    wanted: hii::StringId,
    duplicate_depth: u8,
) -> Option<Vec<Char16>> {
    if duplicate_depth > 8 {
        return None;
    }

    let mut offset = read_u32(package, 8)? as usize;
    if offset >= package.len() {
        return None;
    }
    let mut id: hii::StringId = 1;

    loop {
        let block_type = *package.get(offset)?;
        offset += 1;
        match block_type {
            0x00 => return None,
            0x10 => {
                let value = scsu_string(package, &mut offset)?;
                if id == wanted {
                    return Some(value);
                }
                id = id.checked_add(1)?;
            }
            0x11 => {
                offset += 1; // Font identifier.
                let value = scsu_string(package, &mut offset)?;
                if id == wanted {
                    return Some(value);
                }
                id = id.checked_add(1)?;
            }
            0x12 | 0x13 => {
                if block_type == 0x13 {
                    offset += 1; // Font identifier.
                }
                let count = read_u16(package, offset)?;
                offset += 2;
                for _ in 0..count {
                    let value = scsu_string(package, &mut offset)?;
                    if id == wanted {
                        return Some(value);
                    }
                    id = id.checked_add(1)?;
                }
            }
            0x14 => {
                let value = ucs2_string(package, &mut offset)?;
                if id == wanted {
                    return Some(value);
                }
                id = id.checked_add(1)?;
            }
            0x15 => {
                offset += 1; // Font identifier.
                let value = ucs2_string(package, &mut offset)?;
                if id == wanted {
                    return Some(value);
                }
                id = id.checked_add(1)?;
            }
            0x16 | 0x17 => {
                if block_type == 0x17 {
                    offset += 1; // Font identifier.
                }
                let count = read_u16(package, offset)?;
                offset += 2;
                for _ in 0..count {
                    let value = ucs2_string(package, &mut offset)?;
                    if id == wanted {
                        return Some(value);
                    }
                    id = id.checked_add(1)?;
                }
            }
            0x20 => {
                let source = read_u16(package, offset)?;
                offset += 2;
                if id == wanted {
                    return find_string_in_package_inner(package, source, duplicate_depth + 1);
                }
                id = id.checked_add(1)?;
            }
            0x21 => {
                id = id.checked_add(read_u16(package, offset)?)?;
                offset += 2;
            }
            0x22 => {
                id = id.checked_add(*package.get(offset)? as u16)?;
                offset += 1;
            }
            0x30 => {
                let length = *package.get(offset + 1)? as usize;
                if length < 3 {
                    return None;
                }
                offset = offset.checked_add(length - 1)?;
            }
            0x31 => {
                let length = read_u16(package, offset + 1)? as usize;
                if length < 4 {
                    return None;
                }
                offset = offset.checked_add(length - 1)?;
            }
            0x32 => {
                let length = read_u32(package, offset + 1)? as usize;
                if length < 6 {
                    return None;
                }
                offset = offset.checked_add(length - 1)?;
            }
            _ => return None,
        }
    }
}

fn string_packages(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    let total = read_u32(bytes, 16).unwrap_or(0) as usize;
    let end = total.min(bytes.len());
    let mut offset = core::mem::size_of::<hii::PackageListHeader>();
    core::iter::from_fn(move || {
        while offset + 4 <= end {
            let length = package_length(bytes, offset)?;
            if length < 4 || offset + length > end {
                offset = end;
                return None;
            }
            let start = offset;
            offset += length;
            if package_type(bytes, start) == Some(hii::PACKAGE_STRINGS) {
                return bytes.get(start..start + length);
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

    let database = database();
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
    let database = database();
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
    let database = database();
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

fn language_bytes(language: *const Char8) -> Option<Vec<u8>> {
    if language.is_null() {
        return None;
    }
    let mut value = Vec::new();
    for i in 0..256 {
        let character = unsafe { *language.add(i) };
        if character == 0 {
            return Some(value);
        }
        value.push(character);
    }
    None
}

fn utf16_bytes(string: *const Char16) -> Option<Vec<Char16>> {
    if string.is_null() {
        return None;
    }
    let mut value = Vec::new();
    for i in 0..(1 << 20) {
        let character = unsafe { *string.add(i) };
        if character == 0 {
            return Some(value);
        }
        value.push(character);
    }
    None
}

fn max_string_id_in_package(package: &[u8]) -> Option<hii::StringId> {
    let mut offset = read_u32(package, 8)? as usize;
    let mut id: hii::StringId = 1;
    let mut max = 0;

    loop {
        let block_type = *package.get(offset)?;
        offset += 1;
        let count = match block_type {
            0x00 => return Some(max),
            0x10 => {
                scsu_string(package, &mut offset)?;
                1
            }
            0x11 => {
                offset += 1;
                scsu_string(package, &mut offset)?;
                1
            }
            0x12 | 0x13 => {
                if block_type == 0x13 {
                    offset += 1;
                }
                let count = read_u16(package, offset)?;
                offset += 2;
                for _ in 0..count {
                    scsu_string(package, &mut offset)?;
                }
                count
            }
            0x14 => {
                ucs2_string(package, &mut offset)?;
                1
            }
            0x15 => {
                offset += 1;
                ucs2_string(package, &mut offset)?;
                1
            }
            0x16 | 0x17 => {
                if block_type == 0x17 {
                    offset += 1;
                }
                let count = read_u16(package, offset)?;
                offset += 2;
                for _ in 0..count {
                    ucs2_string(package, &mut offset)?;
                }
                count
            }
            0x20 => {
                offset += 2;
                1
            }
            0x21 => {
                let count = read_u16(package, offset)?;
                offset += 2;
                count
            }
            0x22 => {
                let count = *package.get(offset)? as u16;
                offset += 1;
                count
            }
            0x30 => {
                let length = *package.get(offset + 1)? as usize;
                if length < 3 {
                    return None;
                }
                offset = offset.checked_add(length - 1)?;
                0
            }
            0x31 => {
                let length = read_u16(package, offset + 1)? as usize;
                if length < 4 {
                    return None;
                }
                offset = offset.checked_add(length - 1)?;
                0
            }
            0x32 => {
                let length = read_u32(package, offset + 1)? as usize;
                if length < 6 {
                    return None;
                }
                offset = offset.checked_add(length - 1)?;
                0
            }
            _ => return None,
        };
        if count != 0 {
            max = id.checked_add(count - 1)?;
            id = max.checked_add(1)?;
        }
    }
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

extern "efiapi" fn new_string(
    _this: *const hii_string::Protocol,
    package_list: hii::Handle,
    string_id: *mut hii::StringId,
    language: *const Char8,
    _language_name: *const Char16,
    string: *mut Char16,
    _string_font_info: *const hii_string::Info,
) -> Status {
    if string_id.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let Some(language) = language_bytes(language) else {
        return Status::INVALID_PARAMETER;
    };
    let Some(value) = utf16_bytes(string) else {
        return Status::INVALID_PARAMETER;
    };
    let database = database();
    let Some(package) = database
        .packages
        .iter_mut()
        .find(|package| package.handle == handle_value(package_list))
    else {
        return Status::NOT_FOUND;
    };
    let mut id = unsafe { *string_id };
    if id == 0 {
        let Some(next) = max_string_id(package).checked_add(1) else {
            return Status::OUT_OF_RESOURCES;
        };
        id = next;
        unsafe { *string_id = id };
    }
    let added = language.len() + value.len() * core::mem::size_of::<Char16>();
    if package.strings.len() >= MAX_DYNAMIC_STRINGS
        || dynamic_string_storage(package)
            .checked_add(added)
            .is_none_or(|total| total > MAX_DYNAMIC_STRING_STORAGE)
        || package.strings.try_reserve(1).is_err()
    {
        return Status::OUT_OF_RESOURCES;
    }
    package.strings.push(DynamicString {
        id,
        language,
        value,
    });
    Status::SUCCESS
}

extern "efiapi" fn get_string(
    _this: *const hii_string::Protocol,
    language: *const Char8,
    package_list: hii::Handle,
    string_id: hii::StringId,
    string: *mut Char16,
    string_size: *mut usize,
    _string_font_info: *mut *mut hii_string::Info,
) -> Status {
    if language.is_null() || string_id == 0 || string_size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let database = database();
    let Some(package) = database
        .packages
        .iter()
        .find(|package| package.handle == handle_value(package_list))
    else {
        return Status::NOT_FOUND;
    };

    let language_value = language_bytes(language).unwrap_or_default();
    let value = package
        .strings
        .iter()
        .rev()
        .find(|entry| entry.id == string_id && language_eq(&entry.language, &language_value))
        .map(|entry| entry.value.clone())
        .or_else(|| {
            string_packages(&package.bytes)
                .find(|strings| language_matches(strings, language))
                .and_then(|strings| find_string_in_package(strings, string_id))
        });
    let Some(value) = value else {
        return Status::NOT_FOUND;
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
        ptr::copy_nonoverlapping(value.as_ptr(), string, value.len());
        *string.add(value.len()) = 0;
    }
    Status::SUCCESS
}

extern "efiapi" fn set_string(
    _this: *const hii_string::Protocol,
    package_list: hii::Handle,
    string_id: hii::StringId,
    language: *const Char8,
    string: *mut Char16,
    _string_font_info: *const hii_string::Info,
) -> Status {
    if string_id == 0 {
        return Status::INVALID_PARAMETER;
    }
    let Some(language) = language_bytes(language) else {
        return Status::INVALID_PARAMETER;
    };
    let Some(value) = utf16_bytes(string) else {
        return Status::INVALID_PARAMETER;
    };
    let database = database();
    let Some(package) = database
        .packages
        .iter_mut()
        .find(|package| package.handle == handle_value(package_list))
    else {
        return Status::NOT_FOUND;
    };
    if let Some(index) = package
        .strings
        .iter()
        .position(|entry| entry.id == string_id && language_eq(&entry.language, &language))
    {
        let old = package.strings[index].value.len() * core::mem::size_of::<Char16>();
        let new = value.len() * core::mem::size_of::<Char16>();
        if dynamic_string_storage(package)
            .checked_sub(old)
            .and_then(|total| total.checked_add(new))
            .is_none_or(|total| total > MAX_DYNAMIC_STRING_STORAGE)
        {
            return Status::OUT_OF_RESOURCES;
        }
        package.strings[index].value = value;
    } else {
        let added = language.len() + value.len() * core::mem::size_of::<Char16>();
        if package.strings.len() >= MAX_DYNAMIC_STRINGS
            || dynamic_string_storage(package)
                .checked_add(added)
                .is_none_or(|total| total > MAX_DYNAMIC_STRING_STORAGE)
            || package.strings.try_reserve(1).is_err()
        {
            return Status::OUT_OF_RESOURCES;
        }
        package.strings.push(DynamicString {
            id: string_id,
            language,
            value,
        });
    }
    Status::SUCCESS
}

fn supported_languages(package: &PackageList) -> Vec<u8> {
    let mut values: Vec<Vec<u8>> = Vec::new();
    for strings in string_packages(&package.bytes) {
        let Some(languages) = language_of_package(strings) else {
            continue;
        };
        for language in languages
            .split(|&character| character == b';')
            .filter(|language| !language.is_empty())
        {
            if !values
                .iter()
                .any(|existing| language_eq(existing, language))
            {
                values.push(language.to_vec());
            }
        }
    }
    for string in &package.strings {
        if !values
            .iter()
            .any(|existing| language_eq(existing, &string.language))
        {
            values.push(string.language.clone());
        }
    }

    let mut languages = Vec::new();
    for language in values {
        if !languages.is_empty() {
            languages.push(b';');
        }
        languages.extend_from_slice(&language);
    }
    languages.push(0);
    languages
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
    let database = database();
    let Some(package) = database
        .packages
        .iter()
        .find(|package| package.handle == handle_value(package_list))
    else {
        return Status::NOT_FOUND;
    };
    let value = supported_languages(package);
    let supplied = unsafe { *languages_size };
    unsafe { *languages_size = value.len() };
    if languages.is_null() {
        return if supplied == 0 {
            Status::BUFFER_TOO_SMALL
        } else {
            Status::INVALID_PARAMETER
        };
    }
    if supplied < value.len() {
        return Status::BUFFER_TOO_SMALL;
    }
    unsafe { ptr::copy_nonoverlapping(value.as_ptr(), languages, value.len()) };
    Status::SUCCESS
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
    let Some(primary) = language_bytes(requested_primary) else {
        return Status::INVALID_PARAMETER;
    };
    let database = database();
    let Some(package) = database
        .packages
        .iter()
        .find(|package| package.handle == handle_value(package_list))
    else {
        return Status::NOT_FOUND;
    };

    let Some(language_list) = string_packages(&package.bytes)
        .filter_map(language_of_package)
        .find(|languages| language_eq(primary_language(languages), &primary))
    else {
        return Status::INVALID_LANGUAGE;
    };
    let mut value = language_list
        .split(|&character| character == b';')
        .skip(1)
        .filter(|language| !language.is_empty())
        .fold(Vec::new(), |mut output, language| {
            if !output.is_empty() {
                output.push(b';');
            }
            output.extend_from_slice(language);
            output
        });
    value.push(0);

    let supplied = unsafe { *secondary_languages_size };
    unsafe { *secondary_languages_size = value.len() };
    if secondary_languages.is_null() {
        return if supplied == 0 {
            Status::BUFFER_TOO_SMALL
        } else {
            Status::INVALID_PARAMETER
        };
    }
    if supplied < value.len() {
        return Status::BUFFER_TOO_SMALL;
    }
    unsafe { ptr::copy_nonoverlapping(value.as_ptr(), secondary_languages, value.len()) };
    Status::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_shell_style_ucs2_blocks() {
        let mut package = vec![0; 60];
        package[3] = hii::PACKAGE_STRINGS;
        package[4..8].copy_from_slice(&58u32.to_le_bytes());
        package[8..12].copy_from_slice(&60u32.to_le_bytes());
        package[44..46].copy_from_slice(&1u16.to_le_bytes());
        package[46..52].copy_from_slice(b"en-US\0");
        package.extend_from_slice(&[0x14, b'O', 0, b'K', 0, 0, 0]);
        package.extend_from_slice(&[0x22, 1]);
        package.extend_from_slice(&[0x14, b'X', 0, 0, 0, 0]);
        let length = package.len();
        package[0] = length as u8;
        package[1] = (length >> 8) as u8;
        package[2] = (length >> 16) as u8;

        assert_eq!(
            find_string_in_package(&package, 1),
            Some(vec![b'O' as u16, b'K' as u16])
        );
        assert_eq!(find_string_in_package(&package, 2), None);
        assert_eq!(find_string_in_package(&package, 3), Some(vec![b'X' as u16]));
    }
}

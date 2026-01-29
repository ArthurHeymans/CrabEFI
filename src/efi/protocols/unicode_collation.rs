//! EFI Unicode Collation Protocol
//!
//! This module implements the Unicode Collation Protocol which provides
//! string comparison and FAT filename handling services.

use core::ffi::c_void;
use r_efi::efi::{Boolean, Char16, Char8, Guid};

/// Unicode Collation Protocol GUID (version 2)
pub const UNICODE_COLLATION_PROTOCOL2_GUID: Guid = Guid::from_fields(
    0xa4c751fc,
    0x23ae,
    0x4c3e,
    0x92,
    0xe9,
    &[0x49, 0x64, 0xcf, 0x63, 0xf3, 0x49],
);

/// Unicode Collation Protocol (legacy version 1)
pub const UNICODE_COLLATION_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x1d85cd7f,
    0xf43d,
    0x11d2,
    0x9a,
    0x0c,
    &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
);

/// Unicode Collation Protocol structure
#[repr(C)]
pub struct UnicodeCollationProtocol {
    pub stri_coll: extern "efiapi" fn(
        this: *mut UnicodeCollationProtocol,
        s1: *mut Char16,
        s2: *mut Char16,
    ) -> isize,
    pub metai_match: extern "efiapi" fn(
        this: *mut UnicodeCollationProtocol,
        string: *mut Char16,
        pattern: *mut Char16,
    ) -> Boolean,
    pub str_lwr: extern "efiapi" fn(this: *mut UnicodeCollationProtocol, string: *mut Char16),
    pub str_upr: extern "efiapi" fn(this: *mut UnicodeCollationProtocol, string: *mut Char16),
    pub fat_to_str: extern "efiapi" fn(
        this: *mut UnicodeCollationProtocol,
        fat_size: usize,
        fat: *mut Char8,
        string: *mut Char16,
    ),
    pub str_to_fat: extern "efiapi" fn(
        this: *mut UnicodeCollationProtocol,
        string: *mut Char16,
        fat_size: usize,
        fat: *mut Char8,
    ) -> Boolean,
    pub supported_languages: *const Char8,
}

// Static storage for supported languages string
// Note: Unicode Collation v1 uses ISO 639-2 three-letter codes (e.g., "eng")
// Unicode Collation v2 uses RFC 4646 codes (e.g., "en")
// We use "eng" which works for v1, and many v2 implementations accept it too
static SUPPORTED_LANGUAGES: [u8; 4] = *b"eng\0";

/// Static protocol instance
static mut UNICODE_COLLATION: UnicodeCollationProtocol = UnicodeCollationProtocol {
    stri_coll,
    metai_match,
    str_lwr,
    str_upr,
    fat_to_str,
    str_to_fat,
    supported_languages: SUPPORTED_LANGUAGES.as_ptr() as *const Char8,
};

/// Get the Unicode Collation Protocol
pub fn get_protocol() -> *mut UnicodeCollationProtocol {
    &raw mut UNICODE_COLLATION
}

/// Get the protocol as a void pointer
pub fn get_protocol_void() -> *mut c_void {
    get_protocol() as *mut c_void
}

// Convert a UTF-16 character to uppercase (ASCII only for now)
fn char_to_upper(c: u16) -> u16 {
    if c >= b'a' as u16 && c <= b'z' as u16 {
        c - 32
    } else {
        c
    }
}

// Convert a UTF-16 character to lowercase (ASCII only for now)
fn char_to_lower(c: u16) -> u16 {
    if c >= b'A' as u16 && c <= b'Z' as u16 {
        c + 32
    } else {
        c
    }
}

/// Case-insensitive string comparison
extern "efiapi" fn stri_coll(
    _this: *mut UnicodeCollationProtocol,
    s1: *mut Char16,
    s2: *mut Char16,
) -> isize {
    log::debug!("UnicodeCollation.StriColl()");
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    let mut p1 = s1;
    let mut p2 = s2;

    unsafe {
        loop {
            let c1 = char_to_upper(*p1);
            let c2 = char_to_upper(*p2);

            if c1 != c2 {
                return (c1 as isize) - (c2 as isize);
            }

            if c1 == 0 {
                return 0;
            }

            p1 = p1.add(1);
            p2 = p2.add(1);
        }
    }
}

/// Pattern matching with wildcards
extern "efiapi" fn metai_match(
    _this: *mut UnicodeCollationProtocol,
    string: *mut Char16,
    pattern: *mut Char16,
) -> Boolean {
    log::debug!("UnicodeCollation.MetaiMatch()");
    if string.is_null() || pattern.is_null() {
        return Boolean::FALSE;
    }

    // Simple implementation - just do exact match for now
    // A full implementation would handle *, ?, and [] wildcards
    let mut ps = string;
    let mut pp = pattern;

    unsafe {
        loop {
            let cs = char_to_lower(*ps);
            let cp = char_to_lower(*pp);

            match cp {
                0 => {
                    return if cs == 0 {
                        Boolean::TRUE
                    } else {
                        Boolean::FALSE
                    };
                }
                0x2A => {
                    // '*' - match zero or more characters
                    pp = pp.add(1);
                    if *pp == 0 {
                        return Boolean::TRUE;
                    }
                    // Try matching rest of pattern at each position
                    while *ps != 0 {
                        if metai_match(_this, ps, pp) == Boolean::TRUE {
                            return Boolean::TRUE;
                        }
                        ps = ps.add(1);
                    }
                    return metai_match(_this, ps, pp);
                }
                0x3F => {
                    // '?' - match exactly one character
                    if cs == 0 {
                        return Boolean::FALSE;
                    }
                }
                _ => {
                    if cs != cp {
                        return Boolean::FALSE;
                    }
                }
            }

            if cs == 0 {
                break;
            }

            ps = ps.add(1);
            pp = pp.add(1);
        }
    }

    Boolean::TRUE
}

/// Convert string to lowercase
extern "efiapi" fn str_lwr(_this: *mut UnicodeCollationProtocol, string: *mut Char16) {
    if string.is_null() {
        return;
    }

    let mut p = string;
    unsafe {
        while *p != 0 {
            *p = char_to_lower(*p);
            p = p.add(1);
        }
    }
}

/// Convert string to uppercase
extern "efiapi" fn str_upr(_this: *mut UnicodeCollationProtocol, string: *mut Char16) {
    if string.is_null() {
        return;
    }

    let mut p = string;
    unsafe {
        while *p != 0 {
            *p = char_to_upper(*p);
            p = p.add(1);
        }
    }
}

/// Convert FAT 8.3 filename to Unicode
extern "efiapi" fn fat_to_str(
    _this: *mut UnicodeCollationProtocol,
    fat_size: usize,
    fat: *mut Char8,
    string: *mut Char16,
) {
    log::debug!("UnicodeCollation.FatToStr(size={})", fat_size);
    if fat.is_null() || string.is_null() {
        return;
    }

    unsafe {
        for i in 0..fat_size {
            let c = *fat.add(i) as u8;
            if c == 0 {
                *string.add(i) = 0;
                break;
            }
            // Simple ASCII conversion
            *string.add(i) = c as u16;
        }
        *string.add(fat_size) = 0;
    }
}

/// Convert Unicode string to FAT 8.3 filename
extern "efiapi" fn str_to_fat(
    _this: *mut UnicodeCollationProtocol,
    string: *mut Char16,
    fat_size: usize,
    fat: *mut Char8,
) -> Boolean {
    log::debug!("UnicodeCollation.StrToFat(size={})", fat_size);
    if string.is_null() || fat.is_null() {
        return Boolean::FALSE;
    }

    let mut has_illegal = Boolean::FALSE;
    let illegal = b"+,<=>:;\"/\\|?*[]\x7f";

    unsafe {
        let mut i = 0;
        let mut ps = string;

        while i < fat_size && *ps != 0 {
            let c = *ps as u32;
            ps = ps.add(1);

            // Skip spaces and periods
            if c == b' ' as u32 || c == b'.' as u32 {
                continue;
            }

            // Convert to uppercase
            let c = if c >= b'a' as u32 && c <= b'z' as u32 {
                c - 32
            } else {
                c
            };

            // Check for illegal characters or non-ASCII
            if c >= 128 || c < 0x20 || illegal.contains(&(c as u8)) {
                *fat.add(i) = b'_' as Char8;
                has_illegal = Boolean::TRUE;
            } else {
                *fat.add(i) = c as Char8;
            }

            i += 1;
        }

        // Null terminate
        if i < fat_size {
            *fat.add(i) = 0;
        }
    }

    has_illegal
}

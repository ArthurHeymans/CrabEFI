//! UEFI Boot Variable Support
//!
//! Implements the UEFI boot manager variable protocol:
//! - `Boot####` — individual boot option entries (EFI_LOAD_OPTION format)
//! - `BootOrder` — ordered list of Boot#### option numbers to try
//! - `BootNext` — one-shot next-boot override (deleted before use)
//! - `BootCurrent` — volatile variable set during boot attempt
//! - `Timeout` — seconds to wait before auto-booting
//!
//! All variables use the EFI Global Variable GUID
//! (`8BE4DF61-93CA-11D2-AA0D-00E098032B8C`) and follow the UEFI
//! Specification sections 3.1 (Boot Manager) and 3.1.2 (Load Options).
//!
//! # Binary format of Boot#### (EFI_LOAD_OPTION)
//!
//! ```text
//! Offset 0:  u32    Attributes        (LOAD_OPTION_ACTIVE = 0x01, etc.)
//! Offset 4:  u16    FilePathListLength (bytes)
//! Offset 6:  [u16]  Description        (null-terminated UCS-2)
//! Then:      [u8]   FilePathList       (EFI_DEVICE_PATH, FilePathListLength bytes)
//! Then:      [u8]   OptionalData       (remaining bytes)
//! ```

use crate::efi::auth::{EFI_GLOBAL_VARIABLE_GUID, attributes};
use crate::efi::utils::ucs2_eq;
use crate::state::{self, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN};
use core::fmt::Write;
use heapless::Vec as HeaplessVec;

// ============================================================================
// Constants
// ============================================================================

/// EFI_LOAD_OPTION attribute: option is active and should be tried
pub const LOAD_OPTION_ACTIVE: u32 = 0x00000001;

/// EFI_LOAD_OPTION attribute: force reconnect of all drivers before boot
#[allow(dead_code)]
pub const LOAD_OPTION_FORCE_RECONNECT: u32 = 0x00000002;

/// EFI_LOAD_OPTION attribute: option is hidden from the user
#[allow(dead_code)]
pub const LOAD_OPTION_HIDDEN: u32 = 0x00000008;

/// EFI_LOAD_OPTION attribute mask for option category
pub const LOAD_OPTION_CATEGORY: u32 = 0x00001F00;

/// Category: this is a normal boot option
pub const LOAD_OPTION_CATEGORY_BOOT: u32 = 0x00000000;

/// Category: this is an application (not a boot option)
#[allow(dead_code)]
pub const LOAD_OPTION_CATEGORY_APP: u32 = 0x00000100;

/// NV+BS+RT attributes for persistent boot variables
const NV_BS_RT: u32 =
    attributes::NON_VOLATILE | attributes::BOOTSERVICE_ACCESS | attributes::RUNTIME_ACCESS;

/// BS+RT attributes for volatile boot variables (BootCurrent)
const BS_RT: u32 = attributes::BOOTSERVICE_ACCESS | attributes::RUNTIME_ACCESS;

/// Maximum number of boot options we can track
const MAX_BOOT_OPTIONS: usize = 16;

/// Maximum description length (in UCS-2 characters, including null)
const MAX_DESCRIPTION_CHARS: usize = 64;

/// Maximum file path list length we can handle
const MAX_FILE_PATH_SIZE: usize = 512;

/// Maximum optional data size
const MAX_OPTIONAL_DATA_SIZE: usize = 256;

// ============================================================================
// UCS-2 variable name constants
// ============================================================================

/// "BootOrder" in UCS-2
const BOOT_ORDER_NAME: [u16; 10] = [
    b'B' as u16,
    b'o' as u16,
    b'o' as u16,
    b't' as u16,
    b'O' as u16,
    b'r' as u16,
    b'd' as u16,
    b'e' as u16,
    b'r' as u16,
    0,
];

/// "BootNext" in UCS-2
const BOOT_NEXT_NAME: [u16; 9] = [
    b'B' as u16,
    b'o' as u16,
    b'o' as u16,
    b't' as u16,
    b'N' as u16,
    b'e' as u16,
    b'x' as u16,
    b't' as u16,
    0,
];

/// "BootCurrent" in UCS-2
const BOOT_CURRENT_NAME: [u16; 12] = [
    b'B' as u16,
    b'o' as u16,
    b'o' as u16,
    b't' as u16,
    b'C' as u16,
    b'u' as u16,
    b'r' as u16,
    b'r' as u16,
    b'e' as u16,
    b'n' as u16,
    b't' as u16,
    0,
];

/// "Timeout" in UCS-2
const TIMEOUT_NAME: [u16; 8] = [
    b'T' as u16,
    b'i' as u16,
    b'm' as u16,
    b'e' as u16,
    b'o' as u16,
    b'u' as u16,
    b't' as u16,
    0,
];

// ============================================================================
// EFI_LOAD_OPTION (Boot#### variable data)
// ============================================================================

/// Parsed Boot#### load option
#[derive(Debug, Clone)]
pub struct LoadOption {
    /// Option number (the #### part)
    pub option_number: u16,
    /// LOAD_OPTION_ACTIVE, etc.
    pub attributes: u32,
    /// Human-readable description (ASCII, truncated from UCS-2)
    pub description: heapless::String<MAX_DESCRIPTION_CHARS>,
    /// Raw file path list (EFI_DEVICE_PATH_PROTOCOL nodes)
    pub file_path: HeaplessVec<u8, MAX_FILE_PATH_SIZE>,
    /// Optional data passed to the image as LoadOptions
    pub optional_data: HeaplessVec<u8, MAX_OPTIONAL_DATA_SIZE>,
}

impl LoadOption {
    /// Check if this option is active (should be tried during boot)
    pub fn is_active(&self) -> bool {
        (self.attributes & LOAD_OPTION_ACTIVE) != 0
    }

    /// Check if this is a normal boot option (not an application)
    pub fn is_boot_category(&self) -> bool {
        (self.attributes & LOAD_OPTION_CATEGORY) == LOAD_OPTION_CATEGORY_BOOT
    }

    /// Check if this option should be attempted during the BootOrder loop
    pub fn should_boot(&self) -> bool {
        self.is_active() && self.is_boot_category()
    }
}

/// Parse a raw Boot#### variable value into a LoadOption
///
/// The binary layout is:
/// ```text
/// u32    Attributes
/// u16    FilePathListLength
/// [u16]  Description (null-terminated UCS-2)
/// [u8]   FilePathList (FilePathListLength bytes)
/// [u8]   OptionalData (remaining bytes)
/// ```
pub fn parse_load_option(option_number: u16, data: &[u8]) -> Option<LoadOption> {
    // Minimum size: 4 (attrs) + 2 (fplen) + 2 (null-term description) = 8
    if data.len() < 8 {
        log::debug!(
            "Boot{:04X}: too short ({} bytes, need >= 8)",
            option_number,
            data.len()
        );
        return None;
    }

    let mut offset = 0;

    // Attributes (u32 LE)
    let attrs = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    offset += 4;

    // FilePathListLength (u16 LE)
    let fp_len = u16::from_le_bytes([data[4], data[5]]) as usize;
    offset += 2;

    // Description: null-terminated UCS-2 string
    let mut desc = heapless::String::<MAX_DESCRIPTION_CHARS>::new();

    loop {
        if offset + 1 >= data.len() {
            log::debug!(
                "Boot{:04X}: description runs past end of data",
                option_number
            );
            return None;
        }
        let ch = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;
        if ch == 0 {
            break; // Null terminator
        }
        // Convert UCS-2 to ASCII (best-effort: non-ASCII becomes '?')
        let ascii = if ch < 128 { ch as u8 as char } else { '?' };
        let _ = desc.push(ascii);
    }

    // FilePathList
    if offset + fp_len > data.len() {
        log::debug!(
            "Boot{:04X}: file path list extends past end (offset={}, fp_len={}, total={})",
            option_number,
            offset,
            fp_len,
            data.len()
        );
        return None;
    }

    let mut file_path = HeaplessVec::<u8, MAX_FILE_PATH_SIZE>::new();
    if fp_len <= MAX_FILE_PATH_SIZE {
        file_path
            .extend_from_slice(&data[offset..offset + fp_len])
            .ok();
    } else {
        log::warn!(
            "Boot{:04X}: file path list too large ({} bytes, max {})",
            option_number,
            fp_len,
            MAX_FILE_PATH_SIZE
        );
    }
    offset += fp_len;

    // OptionalData: everything remaining
    let mut optional_data = HeaplessVec::<u8, MAX_OPTIONAL_DATA_SIZE>::new();
    if offset < data.len() {
        let opt_len = data.len() - offset;
        if opt_len <= MAX_OPTIONAL_DATA_SIZE {
            optional_data.extend_from_slice(&data[offset..]).ok();
        }
    }

    log::debug!(
        "Boot{:04X}: attrs={:#x}, desc='{}', fp_len={}, opt_len={}",
        option_number,
        attrs,
        desc,
        file_path.len(),
        optional_data.len()
    );

    Some(LoadOption {
        option_number,
        attributes: attrs,
        description: desc,
        file_path,
        optional_data,
    })
}

// ============================================================================
// Variable helpers (internal firmware API)
// ============================================================================

/// Build a "Boot####" UCS-2 name for a given option number.
///
/// Returns a fixed-size buffer suitable for variable lookup.
fn boot_option_name(option_number: u16) -> [u16; MAX_VARIABLE_NAME_LEN] {
    let mut name = [0u16; MAX_VARIABLE_NAME_LEN];
    // "Boot" prefix
    name[0] = b'B' as u16;
    name[1] = b'o' as u16;
    name[2] = b'o' as u16;
    name[3] = b't' as u16;

    // 4-digit hex number
    let hex_chars = *b"0123456789ABCDEF";
    name[4] = hex_chars[((option_number >> 12) & 0xF) as usize] as u16;
    name[5] = hex_chars[((option_number >> 8) & 0xF) as usize] as u16;
    name[6] = hex_chars[((option_number >> 4) & 0xF) as usize] as u16;
    name[7] = hex_chars[(option_number & 0xF) as usize] as u16;
    // name[8] = 0 already (null terminator)

    name
}

/// Read a variable from the in-memory variable store.
///
/// Returns `Some((attributes, data_slice))` if found, `None` otherwise.
fn read_variable(name: &[u16]) -> Option<(u32, HeaplessVec<u8, MAX_VARIABLE_DATA_SIZE>)> {
    let efi = state::efi();
    for var in efi.variables.iter() {
        if var.in_use && var.vendor_guid == EFI_GLOBAL_VARIABLE_GUID && ucs2_eq(&var.name, name) {
            let mut data = HeaplessVec::new();
            data.extend_from_slice(&var.data[..var.data_size]).ok();
            return Some((var.attributes, data));
        }
    }
    None
}

/// Write (or create) a variable in the in-memory variable store.
///
/// If `data` is empty and `attrs` is 0, the variable is deleted.
fn write_variable(name: &[u16], attrs: u32, data: &[u8]) -> bool {
    state::with_efi_mut(|efi| {
        let guid = EFI_GLOBAL_VARIABLE_GUID;

        // If deleting (size=0, attrs=0), find and remove
        if data.is_empty() && attrs == 0 {
            for var in efi.variables.iter_mut() {
                if var.in_use && var.vendor_guid == guid && ucs2_eq(&var.name, name) {
                    var.clear();
                    return true;
                }
            }
            return true; // Not found is OK for delete
        }

        if data.len() > MAX_VARIABLE_DATA_SIZE {
            log::error!("write_variable: data too large ({} bytes)", data.len());
            return false;
        }

        // Try to find existing variable to update
        for var in efi.variables.iter_mut() {
            if var.in_use && var.vendor_guid == guid && ucs2_eq(&var.name, name) {
                var.attributes = attrs;
                return var.set_data(data).is_ok();
            }
        }

        // Create new variable in first empty slot
        for var in efi.variables.iter_mut() {
            if !var.in_use {
                var.in_use = true;
                var.vendor_guid = guid;
                var.attributes = attrs;
                // Copy name
                let name_len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
                let copy_len = name_len.min(MAX_VARIABLE_NAME_LEN - 1);
                var.name[..copy_len].copy_from_slice(&name[..copy_len]);
                var.name[copy_len] = 0;
                // Zero remaining name bytes
                for c in &mut var.name[copy_len + 1..] {
                    *c = 0;
                }
                return var.set_data(data).is_ok();
            }
        }

        log::error!("write_variable: no free variable slots");
        false
    })
}

/// Delete a variable from the in-memory store.
fn delete_variable(name: &[u16]) -> bool {
    write_variable(name, 0, &[])
}

// ============================================================================
// BootNext
// ============================================================================

/// Read and cache the BootNext variable.
///
/// Returns `Some(option_number)` if BootNext is set and valid (exactly 2 bytes).
/// Returns `None` if BootNext is not set or invalid.
///
/// This should be called early in the boot process, before platform hooks
/// can modify it (matching edk2 behavior).
pub fn read_boot_next() -> Option<u16> {
    let (_, data) = read_variable(&BOOT_NEXT_NAME)?;

    if data.len() != 2 {
        log::warn!("BootNext: invalid size {} (expected 2)", data.len());
        return None;
    }

    let value = u16::from_le_bytes([data[0], data[1]]);
    log::info!("BootNext: Boot{:04X}", value);
    Some(value)
}

/// Delete the BootNext variable.
///
/// Per UEFI spec, BootNext must be deleted before attempting to boot
/// the referenced option, to prevent infinite boot loops.
pub fn delete_boot_next() {
    if delete_variable(&BOOT_NEXT_NAME) {
        log::info!("BootNext: deleted");
    }
}

// ============================================================================
// BootOrder
// ============================================================================

/// Read the BootOrder variable.
///
/// Returns an ordered list of Boot#### option numbers.
/// Returns an empty list if BootOrder is not set.
pub fn read_boot_order() -> HeaplessVec<u16, MAX_BOOT_OPTIONS> {
    let mut order = HeaplessVec::new();

    let Some((_, data)) = read_variable(&BOOT_ORDER_NAME) else {
        log::debug!("BootOrder: not set");
        return order;
    };

    if data.len() % 2 != 0 {
        log::warn!("BootOrder: odd data size {}", data.len());
        return order;
    }

    for chunk in data.as_chunks::<2>().0 {
        let num = u16::from_le_bytes(*chunk);
        if order.push(num).is_err() {
            log::warn!(
                "BootOrder: truncated at {} entries (max {})",
                order.len(),
                MAX_BOOT_OPTIONS
            );
            break;
        }
    }

    if !order.is_empty() {
        log::info!("BootOrder: {} entries", order.len());
        for (i, &num) in order.iter().enumerate() {
            log::debug!("  [{}] Boot{:04X}", i, num);
        }
    }

    order
}

// ============================================================================
// Boot#### (Load Option)
// ============================================================================

/// Read and parse a Boot#### variable.
///
/// Returns `None` if the variable doesn't exist or can't be parsed.
pub fn read_boot_option(option_number: u16) -> Option<LoadOption> {
    let name = boot_option_name(option_number);
    let (_, data) = read_variable(&name)?;
    parse_load_option(option_number, &data)
}

/// Read all Boot#### entries referenced by BootOrder.
///
/// Skips entries that don't exist or can't be parsed (matching edk2 behavior
/// which also silently drops invalid entries).
pub fn read_boot_options() -> HeaplessVec<LoadOption, MAX_BOOT_OPTIONS> {
    let order = read_boot_order();
    let mut options = HeaplessVec::new();

    for &num in order.iter() {
        match read_boot_option(num) {
            Some(opt) => {
                if options.push(opt).is_err() {
                    log::warn!("Boot options list full at {} entries", options.len());
                    break;
                }
            }
            None => {
                log::debug!("Boot{:04X}: not found or invalid, skipping", num);
            }
        }
    }

    options
}

// ============================================================================
// BootCurrent
// ============================================================================

/// Set the BootCurrent variable (volatile, BS+RT).
///
/// Called just before starting a boot option's image.
pub fn set_boot_current(option_number: u16) {
    let data = option_number.to_le_bytes();
    if write_variable(&BOOT_CURRENT_NAME, BS_RT, &data) {
        log::info!("BootCurrent: set to Boot{:04X}", option_number);
    } else {
        log::error!("BootCurrent: failed to set");
    }
}

/// Clear the BootCurrent variable.
///
/// Called after a boot option's image returns.
pub fn clear_boot_current() {
    delete_variable(&BOOT_CURRENT_NAME);
    log::debug!("BootCurrent: cleared");
}

// ============================================================================
// Timeout
// ============================================================================

/// Read the Timeout variable.
///
/// Returns the timeout in seconds:
/// - `Some(0)` — no wait, boot immediately
/// - `Some(0xFFFF)` — wait forever
/// - `Some(n)` — wait n seconds
/// - `None` — variable not set (caller should use a default)
pub fn read_timeout() -> Option<u16> {
    let (_, data) = read_variable(&TIMEOUT_NAME)?;

    if data.len() != 2 {
        log::warn!("Timeout: invalid size {} (expected 2)", data.len());
        return None;
    }

    let value = u16::from_le_bytes([data[0], data[1]]);
    log::info!("Timeout: {} seconds", value);
    Some(value)
}

/// Write the Timeout variable (NV+BS+RT).
///
/// Sets the boot menu timeout in seconds.
pub fn set_timeout(seconds: u16) {
    let data = seconds.to_le_bytes();
    if write_variable(&TIMEOUT_NAME, NV_BS_RT, &data) {
        log::debug!("Timeout: set to {} seconds", seconds);
    }
}

// ============================================================================
// Device Path Extraction
// ============================================================================

/// Extract a file path string from the FilePathList in a LoadOption.
///
/// Walks the EFI_DEVICE_PATH_PROTOCOL nodes looking for a Media/FilePath
/// node (type=4, subtype=4) and extracts the UCS-2 path string from it.
///
/// Returns `None` if no file path node is found.
pub fn extract_file_path(load_option: &LoadOption) -> Option<heapless::String<128>> {
    let data = &load_option.file_path;
    let mut offset = 0;

    while offset + 4 <= data.len() {
        let node_type = data[offset];
        let node_subtype = data[offset + 1];
        let node_length = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;

        if node_length < 4 || offset + node_length > data.len() {
            break;
        }

        // End of Device Path node (type=0x7F, subtype=0xFF)
        if node_type == 0x7F && node_subtype == 0xFF {
            break;
        }

        // Media/FilePath node (type=4, subtype=4)
        if node_type == 4 && node_subtype == 4 && node_length > 4 {
            let path_data = &data[offset + 4..offset + node_length];
            let mut path = heapless::String::<128>::new();

            // UCS-2 to ASCII conversion
            for chunk in path_data.as_chunks::<2>().0 {
                let ch = u16::from_le_bytes(*chunk);
                if ch == 0 {
                    break;
                }
                let ascii = if ch < 128 { ch as u8 as char } else { '?' };
                if path.push(ascii).is_err() {
                    log::warn!("extract_file_path: path exceeds 128 chars, truncated");
                    break;
                }
            }

            if !path.is_empty() {
                return Some(path);
            }
        }

        offset += node_length;
    }

    None
}

// ============================================================================
// Boot Manager Integration
// ============================================================================

/// Result of attempting to boot a single option
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootAttemptResult {
    /// Boot was successful (image ran and returned SUCCESS)
    Success,
    /// Boot failed (image not found, verification failed, etc.)
    Failed,
    /// Option was skipped (inactive, wrong category, etc.)
    Skipped,
}

/// Summary of the boot variable state, gathered early in boot.
///
/// This is cached before platform hooks run (matching edk2's approach).
pub struct BootVarState {
    /// Cached BootNext value (read and cached early)
    pub boot_next: Option<u16>,
    /// BootOrder entries
    pub boot_order: HeaplessVec<u16, MAX_BOOT_OPTIONS>,
    /// Timeout in seconds (None = use default)
    pub timeout: Option<u16>,
}

/// Read all boot manager variables at once.
///
/// Call this early in the boot process, before platform hooks or driver
/// binding, to cache the boot variable state.
pub fn read_boot_var_state() -> BootVarState {
    let boot_next = read_boot_next();
    let boot_order = read_boot_order();
    let timeout = read_timeout();

    log::info!("Boot variable state:");
    log::info!(
        "  BootNext: {}",
        match boot_next {
            Some(n) => {
                let mut s = heapless::String::<16>::new();
                let _ = write!(s, "Boot{:04X}", n);
                s
            }
            None => {
                let mut s = heapless::String::<16>::new();
                let _ = s.push_str("(not set)");
                s
            }
        }
    );
    log::info!("  BootOrder: {} entries", boot_order.len());
    log::info!(
        "  Timeout: {}",
        match timeout {
            Some(0xFFFF) => {
                let mut s = heapless::String::<16>::new();
                let _ = s.push_str("forever");
                s
            }
            Some(n) => {
                let mut s = heapless::String::<16>::new();
                let _ = write!(s, "{}s", n);
                s
            }
            None => {
                let mut s = heapless::String::<16>::new();
                let _ = s.push_str("(default)");
                s
            }
        }
    );

    BootVarState {
        boot_next,
        boot_order,
        timeout,
    }
}

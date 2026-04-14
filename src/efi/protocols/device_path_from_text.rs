//! EFI Device Path From Text Protocol
//!
//! Implements `EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL` which converts text strings
//! to device path nodes and full device paths. Used by GRUB2 and systemd-boot
//! to parse device path strings from configuration.
//!
//! Reference: UEFI Specification 2.10, Section 10.6.5
//! Reference: EDK2 `MdePkg/Library/UefiDevicePathLib/DevicePathFromText.c`

use core::ffi::c_void;
use core::ptr;

use r_efi::efi::{Char16, Guid};
use r_efi::protocols::device_path;
use r_efi::protocols::device_path_from_text;

use crate::efi::allocator;
use crate::efi::utils::allocate_protocol_with_log;

// Re-use shared helpers from device_path.rs
use super::device_path::{
    MIN_NODE_LENGTH, SUBTYPE_END_INSTANCE, alloc_pool, device_path_size, write_end_node,
};

pub const DEVICE_PATH_FROM_TEXT_GUID: Guid = device_path_from_text::PROTOCOL_GUID;

// Device path node types
const TYPE_HARDWARE: u8 = 0x01;
const TYPE_ACPI: u8 = 0x02;
const TYPE_MESSAGING: u8 = 0x03;
const TYPE_MEDIA: u8 = 0x04;

// Subtypes
const HW_SUBTYPE_PCI: u8 = 0x01;
const ACPI_SUBTYPE_ACPI: u8 = 0x01;
const MSG_SUBTYPE_USB: u8 = 0x05;
const MSG_SUBTYPE_SATA: u8 = 0x12;
const MSG_SUBTYPE_NVME: u8 = 0x17;
const MEDIA_SUBTYPE_HARDDRIVE: u8 = 0x01;
const MEDIA_SUBTYPE_FILEPATH: u8 = 0x04;
const MEDIA_SUBTYPE_VENDOR: u8 = 0x03;

// PNP IDs
const EISA_PNP_ID_PCI_ROOT: u32 = 0x0a0341d0;
const EISA_PNP_ID_PCIE_ROOT: u32 = 0x0a0841d0;

/// Signature types for HD() nodes
const SIGNATURE_TYPE_GUID: u8 = 0x02;

/// Partition format GPT
const PARTITION_FORMAT_GPT: u8 = 0x02;

// ============================================================================
// UCS-2 to ASCII conversion helpers
// ============================================================================

/// Maximum text length we support for device path strings.
const MAX_TEXT_LEN: usize = 512;

/// Convert a UCS-2 string to an ASCII buffer. Returns the length (not including
/// null terminator), or 0 if the input is null/empty.
fn ucs2_to_ascii(text: *const Char16, out: &mut [u8; MAX_TEXT_LEN]) -> usize {
    if text.is_null() {
        return 0;
    }
    let mut len = 0;
    unsafe {
        loop {
            let ch = ptr::read_unaligned(text.add(len) as *const u16);
            if ch == 0 || len >= MAX_TEXT_LEN - 1 {
                break;
            }
            out[len] = if ch < 0x80 { ch as u8 } else { b'?' };
            len += 1;
        }
    }
    out[len] = 0;
    len
}

// ============================================================================
// Simple number parsing
// ============================================================================

/// Parse a hex or decimal number from ASCII text.
///
/// Supports `0x` prefix for hex, otherwise decimal.
/// Returns (value, chars_consumed).
fn parse_number(s: &[u8]) -> (u64, usize) {
    if s.is_empty() {
        return (0, 0);
    }
    // Skip leading whitespace
    let mut i = 0;
    while i < s.len() && s[i] == b' ' {
        i += 1;
    }
    if i >= s.len() {
        return (0, 0);
    }

    if s.len() - i >= 2 && s[i] == b'0' && (s[i + 1] == b'x' || s[i + 1] == b'X') {
        // Hex
        i += 2;
        let start = i;
        let mut val: u64 = 0;
        while i < s.len() {
            let d = match s[i] {
                b'0'..=b'9' => (s[i] - b'0') as u64,
                b'a'..=b'f' => (s[i] - b'a' + 10) as u64,
                b'A'..=b'F' => (s[i] - b'A' + 10) as u64,
                _ => break,
            };
            val = val.wrapping_mul(16).wrapping_add(d);
            i += 1;
        }
        if i == start { (0, 0) } else { (val, i) }
    } else {
        // Decimal
        let start = i;
        let mut val: u64 = 0;
        while i < s.len() && s[i] >= b'0' && s[i] <= b'9' {
            val = val.wrapping_mul(10).wrapping_add((s[i] - b'0') as u64);
            i += 1;
        }
        if i == start { (0, 0) } else { (val, i) }
    }
}

/// Skip past an expected character (typically `,`), advancing past whitespace too.
fn skip_separator(s: &[u8], pos: usize) -> usize {
    let mut i = pos;
    while i < s.len() && (s[i] == b',' || s[i] == b' ') {
        i += 1;
    }
    i
}

// ============================================================================
// GUID parsing
// ============================================================================

/// Parse a hex byte from 2 ASCII chars.
fn parse_hex_byte(s: &[u8], off: usize) -> u8 {
    let hi = match s.get(off) {
        Some(&c) => match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        },
        None => 0,
    };
    let lo = match s.get(off + 1) {
        Some(&c) => match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        },
        None => 0,
    };
    (hi << 4) | lo
}

/// Parse a GUID from text like `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`.
///
/// Returns the GUID bytes in mixed-endian format (matching UEFI layout).
fn parse_guid(s: &[u8]) -> Option<[u8; 16]> {
    // Minimum: 8-4-4-4-12 = 32 hex + 4 dashes = 36 chars
    if s.len() < 36 {
        return None;
    }
    let mut guid = [0u8; 16];

    // Data1: 8 hex chars, little-endian u32
    let d1 = (parse_hex_byte(s, 0) as u32) << 24
        | (parse_hex_byte(s, 2) as u32) << 16
        | (parse_hex_byte(s, 4) as u32) << 8
        | parse_hex_byte(s, 6) as u32;
    guid[0..4].copy_from_slice(&d1.to_le_bytes());

    // Data2: 4 hex chars at offset 9, little-endian u16
    let d2 = (parse_hex_byte(s, 9) as u16) << 8 | parse_hex_byte(s, 11) as u16;
    guid[4..6].copy_from_slice(&d2.to_le_bytes());

    // Data3: 4 hex chars at offset 14, little-endian u16
    let d3 = (parse_hex_byte(s, 14) as u16) << 8 | parse_hex_byte(s, 16) as u16;
    guid[6..8].copy_from_slice(&d3.to_le_bytes());

    // Data4: 2 hex chars at offset 19, 2 at offset 21
    guid[8] = parse_hex_byte(s, 19);
    guid[9] = parse_hex_byte(s, 21);

    // Data4[2..8]: 12 hex chars at offset 24
    for i in 0..6 {
        guid[10 + i] = parse_hex_byte(s, 24 + i * 2);
    }

    Some(guid)
}

// ============================================================================
// Allocate a device path node
// ============================================================================

/// Allocate a zeroed device node with given type, subtype, and length.
fn alloc_node(ntype: u8, nsub: u8, len: u16) -> *mut u8 {
    if len < MIN_NODE_LENGTH {
        return ptr::null_mut();
    }
    let buf = alloc_pool(len as usize);
    if buf.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        ptr::write_bytes(buf, 0, len as usize);
        *buf = ntype;
        *buf.add(1) = nsub;
        let lb = len.to_le_bytes();
        *buf.add(2) = lb[0];
        *buf.add(3) = lb[1];
    }
    buf
}

/// Write a little-endian u16 at offset.
#[inline]
unsafe fn write_u16(buf: *mut u8, off: usize, val: u16) {
    let bytes = val.to_le_bytes();
    unsafe {
        *buf.add(off) = bytes[0];
        *buf.add(off + 1) = bytes[1];
    }
}

/// Write a little-endian u32 at offset.
#[inline]
unsafe fn write_u32(buf: *mut u8, off: usize, val: u32) {
    let bytes = val.to_le_bytes();
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buf.add(off), 4) };
}

/// Write a little-endian u64 at offset.
#[inline]
unsafe fn write_u64(buf: *mut u8, off: usize, val: u64) {
    let bytes = val.to_le_bytes();
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buf.add(off), 8) };
}

// ============================================================================
// Node parsers (keyword + arguments -> allocated node)
// ============================================================================

/// Case-insensitive ASCII prefix match.
fn ascii_prefix_eq(text: &[u8], prefix: &[u8]) -> bool {
    if text.len() < prefix.len() {
        return false;
    }
    for i in 0..prefix.len() {
        if text[i].to_ascii_lowercase() != prefix[i].to_ascii_lowercase() {
            return false;
        }
    }
    true
}

/// Extract the arguments inside parentheses: `Keyword(args)` -> `args` portion.
///
/// Returns the byte slice of the args and the keyword length.
fn extract_args<'a>(text: &'a [u8]) -> Option<(&'a [u8], usize)> {
    let paren_open = text.iter().position(|&c| c == b'(')?;
    // Find matching close paren (handle nesting, though unlikely)
    let mut depth = 0;
    let mut close = None;
    for i in paren_open..text.len() {
        match text[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;
    Some((&text[paren_open + 1..close], paren_open))
}

/// Parse `PciRoot(UID)` or `PcieRoot(UID)` -> ACPI node
fn parse_pci_root(args: &[u8], hid: u32) -> *mut device_path::Protocol {
    let (uid, _) = parse_number(args);
    let node = alloc_node(TYPE_ACPI, ACPI_SUBTYPE_ACPI, 12);
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        write_u32(node, 4, hid);
        write_u32(node, 8, uid as u32);
    }
    node as *mut device_path::Protocol
}

/// Parse `Pci(Dev,Func)` -> PCI hardware node
fn parse_pci(args: &[u8]) -> *mut device_path::Protocol {
    let (dev, consumed) = parse_number(args);
    let rest = skip_separator(args, consumed);
    let (func, _) = parse_number(&args[rest..]);
    let node = alloc_node(TYPE_HARDWARE, HW_SUBTYPE_PCI, 6);
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        *node.add(4) = func as u8;
        *node.add(5) = dev as u8;
    }
    node as *mut device_path::Protocol
}

/// Parse `USB(Port,Interface)` -> USB messaging node
fn parse_usb(args: &[u8]) -> *mut device_path::Protocol {
    let (port, consumed) = parse_number(args);
    let rest = skip_separator(args, consumed);
    let (iface, _) = parse_number(&args[rest..]);
    let node = alloc_node(TYPE_MESSAGING, MSG_SUBTYPE_USB, 6);
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        *node.add(4) = port as u8;
        *node.add(5) = iface as u8;
    }
    node as *mut device_path::Protocol
}

/// Parse `Sata(Port,PortMul,Lun)` -> SATA messaging node
fn parse_sata(args: &[u8]) -> *mut device_path::Protocol {
    let (port, c1) = parse_number(args);
    let r1 = skip_separator(args, c1);
    let (pmul, c2) = parse_number(&args[r1..]);
    let r2 = skip_separator(args, r1 + c2);
    let (lun, _) = parse_number(&args[r2..]);
    let node = alloc_node(TYPE_MESSAGING, MSG_SUBTYPE_SATA, 10);
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        write_u16(node, 4, port as u16);
        write_u16(node, 6, pmul as u16);
        write_u16(node, 8, lun as u16);
    }
    node as *mut device_path::Protocol
}

/// Parse `NVMe(NSID,EUI)` -> NVMe messaging node
fn parse_nvme(args: &[u8]) -> *mut device_path::Protocol {
    let (nsid, consumed) = parse_number(args);
    let node = alloc_node(TYPE_MESSAGING, MSG_SUBTYPE_NVME, 16);
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        write_u32(node, 4, nsid as u32);
        // EUI64 after the comma: XX-XX-XX-XX-XX-XX-XX-XX
        let rest = skip_separator(args, consumed);
        let eui_data = &args[rest..];
        let mut off = 0;
        for i in 0..8 {
            if off + 1 < eui_data.len() {
                *node.add(8 + i) = parse_hex_byte(eui_data, off);
                off += 2;
                // Skip dash separator
                if off < eui_data.len() && eui_data[off] == b'-' {
                    off += 1;
                }
            }
        }
    }
    node as *mut device_path::Protocol
}

/// Parse `HD(PartNo,GPT,GUID[,Start,Size])` -> Hard Drive media node
fn parse_hd(args: &[u8]) -> *mut device_path::Protocol {
    // HD(1,GPT,GUID,0x800,0x100000) or HD(1,GPT,GUID)
    let (part_num, c1) = parse_number(args);
    let r1 = skip_separator(args, c1);

    // Check partition type: GPT, MBR, or numeric
    let remaining = &args[r1..];
    let is_gpt = ascii_prefix_eq(remaining, b"GPT");

    // Skip past the type keyword
    let r2 = if is_gpt {
        skip_separator(args, r1 + 3)
    } else {
        // Skip past the type field (could be MBR or number)
        let (_, c) = parse_number(remaining);
        skip_separator(args, r1 + c.max(3))
    };

    // Node: header(4) + part_num(4) + start(8) + size(8) + sig(16) + format(1) + sig_type(1) = 42
    let node = alloc_node(TYPE_MEDIA, MEDIA_SUBTYPE_HARDDRIVE, 42);
    if node.is_null() {
        return ptr::null_mut();
    }

    unsafe {
        write_u32(node, 4, part_num as u32);

        if is_gpt {
            // Parse GUID
            let guid_data = &args[r2..];
            if let Some(guid_bytes) = parse_guid(guid_data) {
                ptr::copy_nonoverlapping(guid_bytes.as_ptr(), node.add(24), 16);
            }
            *node.add(40) = PARTITION_FORMAT_GPT;
            *node.add(41) = SIGNATURE_TYPE_GUID;

            // Optional start and size after GUID (36 chars)
            let after_guid = skip_separator(args, r2 + 36);
            if after_guid < args.len() {
                let (start, c3) = parse_number(&args[after_guid..]);
                write_u64(node, 8, start);
                let r3 = skip_separator(args, after_guid + c3);
                let (size, _) = parse_number(&args[r3..]);
                write_u64(node, 16, size);
            }
        }
    }

    node as *mut device_path::Protocol
}

/// Parse `VenMedia(GUID)` -> Vendor media node
fn parse_vendor_media(args: &[u8]) -> *mut device_path::Protocol {
    let node = alloc_node(TYPE_MEDIA, MEDIA_SUBTYPE_VENDOR, 20);
    if node.is_null() {
        return ptr::null_mut();
    }
    if let Some(guid_bytes) = parse_guid(args) {
        unsafe {
            ptr::copy_nonoverlapping(guid_bytes.as_ptr(), node.add(4), 16);
        }
    }
    node as *mut device_path::Protocol
}

/// Parse an ACPI node: `Acpi(HID,UID)` -> ACPI node
fn parse_acpi(args: &[u8]) -> *mut device_path::Protocol {
    let (hid, consumed) = parse_number(args);
    let rest = skip_separator(args, consumed);
    let (uid, _) = parse_number(&args[rest..]);
    let node = alloc_node(TYPE_ACPI, ACPI_SUBTYPE_ACPI, 12);
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        write_u32(node, 4, hid as u32);
        write_u32(node, 8, uid as u32);
    }
    node as *mut device_path::Protocol
}

/// Create a file path device node from a text string.
///
/// The file path node contains the UCS-2 encoded path.
fn create_file_path_node(text: &[u8]) -> *mut device_path::Protocol {
    // Calculate UCS-2 size: each char -> 2 bytes + null terminator
    let path_ucs2_size = (text.len() + 1) * 2;
    let total_len = 4 + path_ucs2_size;
    if total_len > u16::MAX as usize {
        return ptr::null_mut();
    }
    let node = alloc_node(TYPE_MEDIA, MEDIA_SUBTYPE_FILEPATH, total_len as u16);
    if node.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        let str_ptr = node.add(4) as *mut u16;
        for (i, &c) in text.iter().enumerate() {
            let ch = if c == b'/' { b'\\' } else { c };
            ptr::write_unaligned(str_ptr.add(i), ch as u16);
        }
        ptr::write_unaligned(str_ptr.add(text.len()), 0u16);
    }
    node as *mut device_path::Protocol
}

/// Keyword dispatch table: match keyword prefix, call parser on args.
///
/// Returns a newly allocated device node, or null if not matched.
fn parse_known_node(text: &[u8]) -> *mut device_path::Protocol {
    let (args, kw_len) = match extract_args(text) {
        Some(v) => v,
        None => return ptr::null_mut(), // No parens -> treat as file path
    };

    let keyword = &text[..kw_len];

    // Try each known keyword (case-insensitive)
    if ascii_prefix_eq(keyword, b"PciRoot") && kw_len == 7 {
        return parse_pci_root(args, EISA_PNP_ID_PCI_ROOT);
    }
    if ascii_prefix_eq(keyword, b"PcieRoot") && kw_len == 8 {
        return parse_pci_root(args, EISA_PNP_ID_PCIE_ROOT);
    }
    if ascii_prefix_eq(keyword, b"Pci") && kw_len == 3 {
        return parse_pci(args);
    }
    if ascii_prefix_eq(keyword, b"USB") && kw_len == 3 {
        return parse_usb(args);
    }
    if ascii_prefix_eq(keyword, b"Sata") && kw_len == 4 {
        return parse_sata(args);
    }
    if ascii_prefix_eq(keyword, b"NVMe") && kw_len == 4 {
        return parse_nvme(args);
    }
    if ascii_prefix_eq(keyword, b"HD") && kw_len == 2 {
        return parse_hd(args);
    }
    if ascii_prefix_eq(keyword, b"VenMedia") && kw_len == 8 {
        return parse_vendor_media(args);
    }
    if ascii_prefix_eq(keyword, b"Acpi") && kw_len == 4 {
        return parse_acpi(args);
    }

    // Unknown keyword: return null to fall through to file path
    ptr::null_mut()
}

// ============================================================================
// Protocol function implementations
// ============================================================================

/// `ConvertTextToDeviceNode` — parse text into a single allocated device node.
///
/// If the text does not match any known keyword, it is treated as a file path.
extern "efiapi" fn convert_text_to_device_node(
    text_device_node: *const Char16,
) -> *mut device_path::Protocol {
    if text_device_node.is_null() {
        return ptr::null_mut();
    }

    let mut ascii = [0u8; MAX_TEXT_LEN];
    let len = ucs2_to_ascii(text_device_node, &mut ascii);
    if len == 0 {
        return ptr::null_mut();
    }

    let text = &ascii[..len];

    // Try known node keywords first
    let node = parse_known_node(text);
    if !node.is_null() {
        return node;
    }

    // Fallback: treat as file path
    create_file_path_node(text)
}

/// `ConvertTextToDevicePath` — parse text into a full device path.
///
/// Text nodes are separated by `/`. Instance separators are `,`.
extern "efiapi" fn convert_text_to_device_path(
    text_device_path: *const Char16,
) -> *mut device_path::Protocol {
    if text_device_path.is_null() {
        return ptr::null_mut();
    }

    let mut ascii = [0u8; MAX_TEXT_LEN];
    let len = ucs2_to_ascii(text_device_path, &mut ascii);
    if len == 0 {
        return ptr::null_mut();
    }

    // Start with an end-only device path
    let end_size = MIN_NODE_LENGTH as usize;
    let end_buf = alloc_pool(end_size);
    if end_buf.is_null() {
        return ptr::null_mut();
    }
    unsafe { write_end_node(end_buf) };
    let mut result = end_buf as *mut device_path::Protocol;

    // Split by '/' and ',' (respecting parentheses)
    let text = &ascii[..len];
    let mut pos = 0;

    // Skip leading '/'
    while pos < text.len() && text[pos] == b'/' {
        pos += 1;
    }

    while pos < text.len() {
        // Find the end of this node (next unparenthesized '/' or ',')
        let mut end = pos;
        let mut depth: i32 = 0;
        while end < text.len() {
            match text[end] {
                b'(' => depth += 1,
                b')' => depth -= 1,
                b'/' | b',' if depth == 0 => break,
                _ => {}
            }
            end += 1;
        }

        if end > pos {
            let node_text = &text[pos..end];

            // Parse the node
            let node = {
                let n = parse_known_node(node_text);
                if n.is_null() {
                    create_file_path_node(node_text)
                } else {
                    n
                }
            };

            if !node.is_null() {
                // Append to result using the device_path_utilities append logic
                let new_result = append_node_to_path(result, node);
                let _ = allocator::free_pool(result as *mut u8);
                let _ = allocator::free_pool(node as *mut u8);
                result = new_result;

                if result.is_null() {
                    return ptr::null_mut();
                }
            }
        }

        // Handle separator
        if end < text.len() {
            if text[end] == b',' {
                // Instance separator: append an end-instance node
                let new_result = append_instance_end(result);
                let _ = allocator::free_pool(result as *mut u8);
                result = new_result;
                if result.is_null() {
                    return ptr::null_mut();
                }
            }
            pos = end + 1;
            // Skip additional '/' after separator
            while pos < text.len() && text[pos] == b'/' {
                pos += 1;
            }
        } else {
            break;
        }
    }

    result
}

/// Append a single node to a device path, returning a new path.
///
/// This is a simplified version of AppendDeviceNode from the utilities protocol.
fn append_node_to_path(
    path: *mut device_path::Protocol,
    node: *mut device_path::Protocol,
) -> *mut device_path::Protocol {
    if path.is_null() || node.is_null() {
        return ptr::null_mut();
    }
    let path_size = unsafe { device_path_size(path as *const _) };
    if path_size == 0 {
        return ptr::null_mut();
    }
    let node_len = unsafe {
        let p = node as *const u8;
        u16::from_le_bytes([*p.add(2), *p.add(3)]) as usize
    };
    let end_size = MIN_NODE_LENGTH as usize;
    // path without end + node + end
    let new_size = (path_size - end_size) + node_len + end_size;
    let buf = alloc_pool(new_size);
    if buf.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        ptr::copy_nonoverlapping(path as *const u8, buf, path_size - end_size);
        ptr::copy_nonoverlapping(node as *const u8, buf.add(path_size - end_size), node_len);
        write_end_node(buf.add(path_size - end_size + node_len));
    }
    buf as *mut device_path::Protocol
}

/// Replace the end-entire of a path with an end-instance, then add a new end-entire.
fn append_instance_end(path: *mut device_path::Protocol) -> *mut device_path::Protocol {
    if path.is_null() {
        return ptr::null_mut();
    }
    let path_size = unsafe { device_path_size(path as *const _) };
    if path_size == 0 {
        return ptr::null_mut();
    }
    let end_size = MIN_NODE_LENGTH as usize;
    // Keep everything including the end node (change it to instance-end), add new end-entire
    let new_size = path_size + end_size;
    let buf = alloc_pool(new_size);
    if buf.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        ptr::copy_nonoverlapping(path as *const u8, buf, path_size);
        // Change last end node's subtype from end-entire to end-instance
        let end_off = path_size - end_size;
        *buf.add(end_off + 1) = SUBTYPE_END_INSTANCE;
        // Append new end-entire
        write_end_node(buf.add(path_size));
    }
    buf as *mut device_path::Protocol
}

// ============================================================================
// Protocol creation
// ============================================================================

/// Create a Device Path From Text protocol instance.
///
/// Returns a pointer suitable for `install_protocol`, or null on allocation failure.
pub fn create_protocol() -> *mut c_void {
    let proto =
        allocate_protocol_with_log::<device_path_from_text::Protocol>("DevicePathFromText", |p| {
            p.convert_text_to_device_node = convert_text_to_device_node;
            p.convert_text_to_device_path = convert_text_to_device_path;
        });
    proto as *mut c_void
}

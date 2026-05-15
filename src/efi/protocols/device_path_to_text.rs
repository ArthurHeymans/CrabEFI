//! EFI Device Path To Text Protocol
//!
//! Implements `EFI_DEVICE_PATH_TO_TEXT_PROTOCOL` which converts device path
//! nodes and full device paths to human-readable UCS-2 strings. Used by GRUB2
//! and systemd-boot for logging and display.
//!
//! Reference: UEFI Specification 2.10, Section 10.6.4
//! Reference: EDK2 `MdePkg/Library/UefiDevicePathLib/DevicePathToText.c`

use core::ffi::c_void;
use core::fmt::Write;
use core::ptr;

use r_efi::efi::{Boolean, Char16, Guid};
use r_efi::protocols::device_path;
use r_efi::protocols::device_path_to_text;

use crate::efi::allocator::{self, MemoryType};
use crate::efi::utils::allocate_protocol_with_log;

// Re-use shared helpers from device_path.rs
use super::device_path::{MAX_DEVICE_PATH_SIZE, SUBTYPE_END_INSTANCE, device_path_size};

pub const DEVICE_PATH_TO_TEXT_GUID: Guid = device_path_to_text::PROTOCOL_GUID;

// Device path node types
const TYPE_HARDWARE: u8 = 0x01;
const TYPE_ACPI: u8 = 0x02;
const TYPE_MESSAGING: u8 = 0x03;
const TYPE_MEDIA: u8 = 0x04;
const TYPE_END: u8 = 0x7F;

// Hardware subtypes
const HW_SUBTYPE_PCI: u8 = 0x01;

// ACPI subtypes
const ACPI_SUBTYPE_ACPI: u8 = 0x01;

// Messaging subtypes
const MSG_SUBTYPE_USB: u8 = 0x05;
const MSG_SUBTYPE_SATA: u8 = 0x12;
const MSG_SUBTYPE_NVME: u8 = 0x17;

// Media subtypes
const MEDIA_SUBTYPE_HARDDRIVE: u8 = 0x01;
const MEDIA_SUBTYPE_CDROM: u8 = 0x02;
const MEDIA_SUBTYPE_VENDOR: u8 = 0x03;
const MEDIA_SUBTYPE_FILEPATH: u8 = 0x04;

// PNP ID for PCI root bridge (EISA encoded PNP0A03)
const EISA_PNP_ID_PCI_ROOT: u32 = 0x0a0341d0;
// PNP ID for PCIe root bridge (EISA encoded PNP0A08)
const EISA_PNP_ID_PCIE_ROOT: u32 = 0x0a0841d0;

/// Signature type constants for HD() nodes
const SIGNATURE_TYPE_MBR: u8 = 0x01;
const SIGNATURE_TYPE_GUID: u8 = 0x02;

// ============================================================================
// Inline node accessors (all work on packed, possibly-unaligned data)
// ============================================================================

#[inline]
unsafe fn node_type(node: *const u8) -> u8 {
    unsafe { *node }
}

#[inline]
unsafe fn node_subtype(node: *const u8) -> u8 {
    unsafe { *node.add(1) }
}

#[inline]
unsafe fn node_len(node: *const u8) -> u16 {
    unsafe { u16::from_le_bytes([*node.add(2), *node.add(3)]) }
}

/// Read a u8 at offset from node start.
#[inline]
unsafe fn read_u8(node: *const u8, off: usize) -> u8 {
    unsafe { *node.add(off) }
}

/// Read a little-endian u16 at offset from node start.
#[inline]
unsafe fn read_u16(node: *const u8, off: usize) -> u16 {
    unsafe { u16::from_le_bytes([*node.add(off), *node.add(off + 1)]) }
}

/// Read a little-endian u32 at offset from node start.
#[inline]
unsafe fn read_u32(node: *const u8, off: usize) -> u32 {
    let mut buf = [0u8; 4];
    unsafe { ptr::copy_nonoverlapping(node.add(off), buf.as_mut_ptr(), 4) };
    u32::from_le_bytes(buf)
}

/// Read a little-endian u64 at offset from node start.
#[inline]
unsafe fn read_u64(node: *const u8, off: usize) -> u64 {
    let mut buf = [0u8; 8];
    unsafe { ptr::copy_nonoverlapping(node.add(off), buf.as_mut_ptr(), 8) };
    u64::from_le_bytes(buf)
}

// ============================================================================
// ASCII string builder (we build ASCII first, then convert to UCS-2)
// ============================================================================

/// Fixed-size ASCII buffer for building device path text.
///
/// 512 bytes is generous — device paths rarely exceed ~200 chars.
struct AsciiBuffer {
    buf: [u8; 512],
    len: usize,
}

impl AsciiBuffer {
    fn new() -> Self {
        Self {
            buf: [0; 512],
            len: 0,
        }
    }

    fn push_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let avail = self.buf.len() - self.len;
        let n = bytes.len().min(avail);
        self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
    }

    fn as_str(&self) -> &str {
        // Safety: we only ever push valid ASCII/UTF-8
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

impl Write for AsciiBuffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

/// Allocate a UCS-2 string from an ASCII string.
///
/// Returns a `*mut Char16` allocated via `AllocatePool`. Caller frees.
fn ascii_to_ucs2_alloc(s: &str) -> *mut Char16 {
    let char_count = s.len() + 1; // +1 for null terminator
    let byte_count = char_count * 2;
    let buf = match allocator::allocate_pool(MemoryType::BootServicesData, byte_count) {
        Ok(p) => p as *mut u16,
        Err(_) => return ptr::null_mut(),
    };
    unsafe {
        for (i, c) in s.bytes().enumerate() {
            *buf.add(i) = c as u16;
        }
        *buf.add(s.len()) = 0; // null terminator
    }
    buf as *mut Char16
}

// ============================================================================
// Per-node-type formatters
// ============================================================================

/// Format a PCI device path node: `Pci(Dev,Func)`
///
/// Layout: header(4) + function(1) + device(1) = 6 bytes
unsafe fn fmt_pci(node: *const u8, buf: &mut AsciiBuffer) {
    let function = unsafe { read_u8(node, 4) };
    let device = unsafe { read_u8(node, 5) };
    let _ = write!(buf, "Pci(0x{:X},0x{:X})", device, function);
}

/// Format an ACPI device path node.
///
/// If HID matches PNP0A03 => `PciRoot(UID)`, PNP0A08 => `PcieRoot(UID)`,
/// else generic `Acpi(HID,UID)`.
///
/// Layout: header(4) + HID(4) + UID(4) = 12 bytes
unsafe fn fmt_acpi(node: *const u8, buf: &mut AsciiBuffer) {
    let hid = unsafe { read_u32(node, 4) };
    let uid = unsafe { read_u32(node, 8) };
    match hid {
        EISA_PNP_ID_PCI_ROOT => {
            let _ = write!(buf, "PciRoot(0x{:X})", uid);
        }
        EISA_PNP_ID_PCIE_ROOT => {
            let _ = write!(buf, "PcieRoot(0x{:X})", uid);
        }
        _ => {
            let _ = write!(buf, "Acpi(0x{:X},0x{:X})", hid, uid);
        }
    }
}

/// Format a USB device path node: `USB(Port,Interface)`
///
/// Layout: header(4) + parent_port(1) + interface(1) = 6 bytes
unsafe fn fmt_usb(node: *const u8, buf: &mut AsciiBuffer) {
    let port = unsafe { read_u8(node, 4) };
    let interface = unsafe { read_u8(node, 5) };
    let _ = write!(buf, "USB(0x{:X},0x{:X})", port, interface);
}

/// Format a SATA device path node: `Sata(Port,PortMul,Lun)`
///
/// Layout: header(4) + hba_port(2) + port_multiplier(2) + lun(2) = 10 bytes
unsafe fn fmt_sata(node: *const u8, buf: &mut AsciiBuffer) {
    let port = unsafe { read_u16(node, 4) };
    let pmul = unsafe { read_u16(node, 6) };
    let lun = unsafe { read_u16(node, 8) };
    let _ = write!(buf, "Sata(0x{:X},0x{:X},0x{:X})", port, pmul, lun);
}

/// Format an NVMe device path node: `NVMe(0xNSID,EUI64)`
///
/// Layout: header(4) + nsid(4) + eui64(8) = 16 bytes
unsafe fn fmt_nvme(node: *const u8, buf: &mut AsciiBuffer) {
    let nsid = unsafe { read_u32(node, 4) };
    let _ = write!(buf, "NVMe(0x{:X},", nsid);
    for i in (0..8).rev() {
        if i < 7 {
            buf.push_str("-");
        }
        let _ = write!(buf, "{:02X}", unsafe { read_u8(node, 8 + i) });
    }
    buf.push_str(")");
}

/// Format a Hard Drive device path node.
///
/// Display-only: `HD(PartNo,Type,Sig)`
/// Full: `HD(PartNo,Type,Sig,Start,Size)`
///
/// Layout: header(4) + partition_number(4) + partition_start(8) + partition_size(8) +
///         signature(16) + partition_format(1) + signature_type(1) = 42 bytes
unsafe fn fmt_hard_drive(node: *const u8, display_only: bool, buf: &mut AsciiBuffer) {
    let part_num = unsafe { read_u32(node, 4) };
    let part_start = unsafe { read_u64(node, 8) };
    let part_size = unsafe { read_u64(node, 16) };
    let sig_type = unsafe { read_u8(node, 41) };

    let _ = write!(buf, "HD({},", part_num);

    match sig_type {
        SIGNATURE_TYPE_GUID => {
            buf.push_str("GPT,");
            // Signature is a GUID at offset 24 (16 bytes)
            // Format as standard GUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            // GUID is stored in mixed-endian format
            let data1 = unsafe { read_u32(node, 24) };
            let data2 = unsafe { read_u16(node, 28) };
            let data3 = unsafe { read_u16(node, 30) };
            let _ = write!(
                buf,
                "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                data1,
                data2,
                data3,
                unsafe { read_u8(node, 32) },
                unsafe { read_u8(node, 33) },
                unsafe { read_u8(node, 34) },
                unsafe { read_u8(node, 35) },
                unsafe { read_u8(node, 36) },
                unsafe { read_u8(node, 37) },
                unsafe { read_u8(node, 38) },
                unsafe { read_u8(node, 39) },
            );
        }
        SIGNATURE_TYPE_MBR => {
            let mbr_sig = unsafe { read_u32(node, 24) };
            let _ = write!(buf, "MBR,0x{:08X}", mbr_sig);
        }
        _ => {
            buf.push_str("0");
        }
    }

    if !display_only {
        let _ = write!(buf, ",0x{:X},0x{:X}", part_start, part_size);
    }
    buf.push_str(")");
}

/// Format a CD-ROM device path node: `CDROM(Entry,Start,Size)`
///
/// Layout: header(4) + boot_entry(4) + partition_start(8) + partition_size(8) = 24 bytes
unsafe fn fmt_cdrom(node: *const u8, display_only: bool, buf: &mut AsciiBuffer) {
    let entry = unsafe { read_u32(node, 4) };
    if display_only {
        let _ = write!(buf, "CDROM(0x{:X})", entry);
    } else {
        let start = unsafe { read_u64(node, 8) };
        let size = unsafe { read_u64(node, 16) };
        let _ = write!(buf, "CDROM(0x{:X},0x{:X},0x{:X})", entry, start, size);
    }
}

/// Format a Vendor Media device path node: `VenMedia(GUID)`
///
/// Layout: header(4) + GUID(16) [+ optional data] = 20+ bytes
unsafe fn fmt_vendor_media(node: *const u8, buf: &mut AsciiBuffer) {
    let data1 = unsafe { read_u32(node, 4) };
    let data2 = unsafe { read_u16(node, 8) };
    let data3 = unsafe { read_u16(node, 10) };
    let _ = write!(
        buf,
        "VenMedia({:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X})",
        data1,
        data2,
        data3,
        unsafe { read_u8(node, 12) },
        unsafe { read_u8(node, 13) },
        unsafe { read_u8(node, 14) },
        unsafe { read_u8(node, 15) },
        unsafe { read_u8(node, 16) },
        unsafe { read_u8(node, 17) },
        unsafe { read_u8(node, 18) },
        unsafe { read_u8(node, 19) },
    );
}

/// Format a File Path device path node.
///
/// The node contains a null-terminated UCS-2 string starting at offset 4.
/// Output is the raw path text (no wrapping keyword).
unsafe fn fmt_file_path(node: *const u8, len: u16, buf: &mut AsciiBuffer) {
    let str_ptr = unsafe { node.add(4) as *const u16 };
    let max_chars = ((len as usize) - 4) / 2;
    for i in 0..max_chars {
        let ch = unsafe { ptr::read_unaligned(str_ptr.add(i)) };
        if ch == 0 {
            break;
        }
        // Printable ASCII range — pass through. Non-ASCII becomes '?'.
        if (0x20..0x7F).contains(&ch) {
            let byte = [ch as u8];
            // Safety: single ASCII byte is valid UTF-8
            buf.push_str(unsafe { core::str::from_utf8_unchecked(&byte) });
        } else {
            buf.push_str("?");
        }
    }
}

/// Format an unknown/generic node.
///
/// Uses the EDK2 convention: known-type fallback or fully generic hex dump.
unsafe fn fmt_unknown(node: *const u8, len: u16, buf: &mut AsciiBuffer) {
    let ntype = unsafe { node_type(node) };
    let nsub = unsafe { node_subtype(node) };

    let type_name = match ntype {
        TYPE_HARDWARE => "HardwarePath",
        TYPE_ACPI => "AcpiPath",
        TYPE_MESSAGING => "Msg",
        TYPE_MEDIA => "MediaPath",
        _ => "",
    };

    if !type_name.is_empty() {
        let _ = write!(buf, "{}(0x{:X}", type_name, nsub);
    } else {
        let _ = write!(buf, "Path({},0x{:X}", ntype, nsub);
    }

    // Dump payload bytes (after the 4-byte header) as hex
    let payload_len = (len as usize).saturating_sub(4);
    if payload_len > 0 {
        buf.push_str(",");
        for i in 0..payload_len {
            let _ = write!(buf, "{:02X}", unsafe { read_u8(node, 4 + i) });
        }
    }
    buf.push_str(")");
}

/// Return the minimum byte length for a node type we decode specially.
fn known_node_min_len(ntype: u8, nsub: u8) -> usize {
    match (ntype, nsub) {
        (TYPE_HARDWARE, HW_SUBTYPE_PCI) | (TYPE_MESSAGING, MSG_SUBTYPE_USB) => 6,
        (TYPE_ACPI, ACPI_SUBTYPE_ACPI) => 12,
        (TYPE_MESSAGING, MSG_SUBTYPE_SATA) => 10,
        (TYPE_MESSAGING, MSG_SUBTYPE_NVME) => 16,
        (TYPE_MEDIA, MEDIA_SUBTYPE_HARDDRIVE) => 42,
        (TYPE_MEDIA, MEDIA_SUBTYPE_CDROM) => 24,
        (TYPE_MEDIA, MEDIA_SUBTYPE_VENDOR) => 20,
        _ => 4,
    }
}

/// Format a single device path node into the ASCII buffer.
unsafe fn format_node(node: *const u8, display_only: bool, buf: &mut AsciiBuffer) {
    let ntype = unsafe { node_type(node) };
    let nsub = unsafe { node_subtype(node) };
    let nlen = unsafe { node_len(node) };

    if nlen as usize > MAX_DEVICE_PATH_SIZE || (nlen as usize) < known_node_min_len(ntype, nsub) {
        unsafe { fmt_unknown(node, nlen, buf) };
        return;
    }

    match (ntype, nsub) {
        (TYPE_HARDWARE, HW_SUBTYPE_PCI) => unsafe { fmt_pci(node, buf) },
        (TYPE_ACPI, ACPI_SUBTYPE_ACPI) => unsafe { fmt_acpi(node, buf) },
        (TYPE_MESSAGING, MSG_SUBTYPE_USB) => unsafe { fmt_usb(node, buf) },
        (TYPE_MESSAGING, MSG_SUBTYPE_SATA) => unsafe { fmt_sata(node, buf) },
        (TYPE_MESSAGING, MSG_SUBTYPE_NVME) => unsafe { fmt_nvme(node, buf) },
        (TYPE_MEDIA, MEDIA_SUBTYPE_HARDDRIVE) => unsafe { fmt_hard_drive(node, display_only, buf) },
        (TYPE_MEDIA, MEDIA_SUBTYPE_CDROM) => unsafe { fmt_cdrom(node, display_only, buf) },
        (TYPE_MEDIA, MEDIA_SUBTYPE_VENDOR) => unsafe { fmt_vendor_media(node, buf) },
        (TYPE_MEDIA, MEDIA_SUBTYPE_FILEPATH) => unsafe { fmt_file_path(node, nlen, buf) },
        _ => unsafe { fmt_unknown(node, nlen, buf) },
    }
}

// ============================================================================
// Protocol function implementations
// ============================================================================

/// `ConvertDeviceNodeToText` — format a single node as a UCS-2 string.
extern "efiapi" fn convert_device_node_to_text(
    device_node: *mut device_path::Protocol,
    display_only: Boolean,
    _allow_shortcuts: Boolean,
) -> *mut Char16 {
    if device_node.is_null() {
        return ptr::null_mut();
    }
    let mut buf = AsciiBuffer::new();
    let is_display_only = display_only != Boolean::FALSE;
    unsafe {
        let nlen = node_len(device_node as *const u8) as usize;
        if !(4..=MAX_DEVICE_PATH_SIZE).contains(&nlen) {
            return ptr::null_mut();
        }
        format_node(device_node as *const u8, is_display_only, &mut buf);
    }
    ascii_to_ucs2_alloc(buf.as_str())
}

/// `ConvertDevicePathToText` — format a full device path as a UCS-2 string.
///
/// Nodes are separated by `/`. Multi-instance separators produce `,`.
extern "efiapi" fn convert_device_path_to_text(
    device_path: *mut device_path::Protocol,
    display_only: Boolean,
    _allow_shortcuts: Boolean,
) -> *mut Char16 {
    if device_path.is_null() {
        return ptr::null_mut();
    }

    let is_display_only = display_only != Boolean::FALSE;
    let mut buf = AsciiBuffer::new();
    let mut first = true;

    unsafe {
        let path_size = device_path_size(device_path);
        if path_size == 0 {
            return ptr::null_mut();
        }

        let mut node = device_path as *const u8;
        let mut consumed = 0usize;
        while consumed < path_size {
            let ntype = node_type(node);
            let nlen = node_len(node) as usize;
            if nlen < 4 || consumed + nlen > path_size {
                return ptr::null_mut();
            }

            if ntype == TYPE_END {
                let nsub = node_subtype(node);
                if nsub == SUBTYPE_END_INSTANCE {
                    // Multi-instance separator
                    buf.push_str(",");
                    first = true;
                    consumed += nlen;
                    node = node.add(nlen);
                    continue;
                }
                // End-entire: done
                break;
            }

            if !first {
                buf.push_str("/");
            }
            first = false;

            format_node(node, is_display_only, &mut buf);
            consumed += nlen;
            node = node.add(nlen);
        }
    }

    ascii_to_ucs2_alloc(buf.as_str())
}

// ============================================================================
// Protocol creation
// ============================================================================

/// Create a Device Path To Text protocol instance.
///
/// Returns a pointer suitable for `install_protocol`, or null on allocation failure.
pub fn create_protocol() -> *mut c_void {
    let proto =
        allocate_protocol_with_log::<device_path_to_text::Protocol>("DevicePathToText", |p| {
            p.convert_device_node_to_text = convert_device_node_to_text;
            p.convert_device_path_to_text = convert_device_path_to_text;
        });
    proto as *mut c_void
}

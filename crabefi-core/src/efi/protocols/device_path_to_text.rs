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
use crate::efi::utils::allocate_protocol_value_with_log;

use super::device_path_view::{DevicePath, Node};

pub const DEVICE_PATH_TO_TEXT_GUID: Guid = device_path_to_text::PROTOCOL_GUID;

// Device path node types
const TYPE_HARDWARE: u8 = 0x01;
const TYPE_ACPI: u8 = 0x02;
const TYPE_MESSAGING: u8 = 0x03;
const TYPE_MEDIA: u8 = 0x04;

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
// EISA PNP IDs are encoded as (numeric_id << 16) | "PNP".
const EISA_PNP_VENDOR: u32 = 0x41d0;

/// Signature type constants for HD() nodes
const SIGNATURE_TYPE_MBR: u8 = 0x01;
const SIGNATURE_TYPE_GUID: u8 = 0x02;

// ============================================================================
// ASCII string builder (we build ASCII first, then convert to UCS-2)
// ============================================================================

/// Fixed-size ASCII buffer for building device path text.
///
/// 512 bytes is generous — device paths rarely exceed ~200 chars. Only ASCII
/// is ever pushed, so truncation cannot split a character.
pub(crate) struct AsciiBuffer {
    buf: [u8; 512],
    len: usize,
}

impl Default for AsciiBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl AsciiBuffer {
    fn new() -> Self {
        Self {
            buf: [0; 512],
            len: 0,
        }
    }

    fn push_str(&mut self, s: &str) {
        for byte in s.bytes() {
            self.push_ascii(byte);
        }
    }

    /// Push one byte, replacing anything but printable ASCII with `?`.
    fn push_ascii(&mut self, byte: u8) {
        if self.len < self.buf.len() {
            self.buf[self.len] = if (0x20..0x7f).contains(&byte) {
                byte
            } else {
                b'?'
            };
            self.len += 1;
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        // Every pushed byte is printable ASCII.
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or_default()
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
    for (i, c) in s.bytes().chain([0]).enumerate() {
        // SAFETY: AllocatePool returned `char_count` exclusively owned u16
        // slots, aligned for any EFI type; each is written, never read.
        unsafe { buf.add(i).write(u16::from(c)) };
    }
    buf as *mut Char16
}

// ============================================================================
// Per-node-type formatters
//
// Each reads every field it needs before writing anything. A node too short
// for its type yields `None` and is rendered generically instead.
// ============================================================================

/// `Pci(Dev,Func)`. Layout: header(4) + function(1) + device(1).
fn fmt_pci(node: Node, buf: &mut AsciiBuffer) -> Option<()> {
    let function = node.u8_at(4)?;
    let device = node.u8_at(5)?;
    let _ = write!(buf, "Pci(0x{:X},0x{:X})", device, function);
    Some(())
}

/// If HID matches PNP0A03 => `PciRoot(UID)`, PNP0A08 => `PcieRoot(UID)`,
/// else generic `Acpi(HID,UID)`. Layout: header(4) + HID(4) + UID(4).
fn fmt_acpi(node: Node, buf: &mut AsciiBuffer) -> Option<()> {
    let hid = node.u32_at(4)?;
    let uid = node.u32_at(8)?;
    let _ = match hid {
        EISA_PNP_ID_PCI_ROOT => write!(buf, "PciRoot(0x{:X})", uid),
        EISA_PNP_ID_PCIE_ROOT => write!(buf, "PcieRoot(0x{:X})", uid),
        _ if (hid & 0xffff) == EISA_PNP_VENDOR => {
            write!(buf, "Acpi(PNP{:04X},0x{:X})", hid >> 16, uid)
        }
        _ => write!(buf, "Acpi(0x{:08X},0x{:X})", hid, uid),
    };
    Some(())
}

/// `USB(Port,Interface)`. Layout: header(4) + parent_port(1) + interface(1).
fn fmt_usb(node: Node, buf: &mut AsciiBuffer) -> Option<()> {
    let port = node.u8_at(4)?;
    let interface = node.u8_at(5)?;
    let _ = write!(buf, "USB(0x{:X},0x{:X})", port, interface);
    Some(())
}

/// `Sata(Port,PortMul,Lun)`. Layout: header(4) + port(2) + multiplier(2) + lun(2).
fn fmt_sata(node: Node, buf: &mut AsciiBuffer) -> Option<()> {
    let port = node.u16_at(4)?;
    let pmul = node.u16_at(6)?;
    let lun = node.u16_at(8)?;
    let _ = write!(buf, "Sata(0x{:X},0x{:X},0x{:X})", port, pmul, lun);
    Some(())
}

/// `NVMe(0xNSID,EUI64)`. Layout: header(4) + nsid(4) + eui64(8).
fn fmt_nvme(node: Node, buf: &mut AsciiBuffer) -> Option<()> {
    let nsid = node.u32_at(4)?;
    let eui: [u8; 8] = node.field(8)?;
    let _ = write!(buf, "NVMe(0x{:X},", nsid);
    for (i, byte) in eui.iter().rev().enumerate() {
        if i > 0 {
            buf.push_str("-");
        }
        let _ = write!(buf, "{:02X}", byte);
    }
    buf.push_str(")");
    Some(())
}

/// Write a mixed-endian EFI GUID stored at `offset`.
fn write_guid(buf: &mut AsciiBuffer, guid: [u8; 16]) {
    let data1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let data2 = u16::from_le_bytes([guid[4], guid[5]]);
    let data3 = u16::from_le_bytes([guid[6], guid[7]]);
    let _ = write!(
        buf,
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        data1,
        data2,
        data3,
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15],
    );
}

/// Display-only: `HD(PartNo,Type,Sig)`; full: `HD(PartNo,Type,Sig,Start,Size)`.
///
/// Layout: header(4) + partition_number(4) + partition_start(8) + partition_size(8) +
///         signature(16) + partition_format(1) + signature_type(1) = 42 bytes
fn fmt_hard_drive(node: Node, display_only: bool, buf: &mut AsciiBuffer) -> Option<()> {
    let part_num = node.u32_at(4)?;
    let part_start = node.u64_at(8)?;
    let part_size = node.u64_at(16)?;
    let signature: [u8; 16] = node.field(24)?;
    let sig_type = node.u8_at(41)?;

    let _ = write!(buf, "HD({},", part_num);
    match sig_type {
        SIGNATURE_TYPE_GUID => {
            buf.push_str("GPT,");
            write_guid(buf, signature);
        }
        SIGNATURE_TYPE_MBR => {
            let mbr_sig =
                u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]);
            let _ = write!(buf, "MBR,0x{:08X}", mbr_sig);
        }
        _ => buf.push_str("0"),
    }
    if !display_only {
        let _ = write!(buf, ",0x{:X},0x{:X}", part_start, part_size);
    }
    buf.push_str(")");
    Some(())
}

/// `CDROM(Entry,Start,Size)`. Layout: header(4) + entry(4) + start(8) + size(8).
fn fmt_cdrom(node: Node, display_only: bool, buf: &mut AsciiBuffer) -> Option<()> {
    let entry = node.u32_at(4)?;
    let start = node.u64_at(8)?;
    let size = node.u64_at(16)?;
    let _ = if display_only {
        write!(buf, "CDROM(0x{:X})", entry)
    } else {
        write!(buf, "CDROM(0x{:X},0x{:X},0x{:X})", entry, start, size)
    };
    Some(())
}

/// `VenMedia(GUID)`. Layout: header(4) + GUID(16) [+ optional data].
fn fmt_vendor_media(node: Node, buf: &mut AsciiBuffer) -> Option<()> {
    let guid: [u8; 16] = node.field(4)?;
    buf.push_str("VenMedia(");
    write_guid(buf, guid);
    buf.push_str(")");
    Some(())
}

/// A File Path node: a NUL-terminated UCS-2 string after the header, written
/// without a wrapping keyword. Non-ASCII characters become `?`.
fn fmt_file_path(node: Node, buf: &mut AsciiBuffer) {
    for unit in node.payload().as_chunks::<2>().0 {
        let ch = u16::from_le_bytes([unit[0], unit[1]]);
        if ch == 0 {
            break;
        }
        buf.push_ascii(u8::try_from(ch).unwrap_or(b'?'));
    }
}

/// Format an unknown/generic node.
///
/// Uses the EDK2 convention: known-type fallback or fully generic hex dump.
fn fmt_unknown(node: Node, buf: &mut AsciiBuffer) {
    let type_name = match node.kind() {
        TYPE_HARDWARE => "HardwarePath",
        TYPE_ACPI => "AcpiPath",
        TYPE_MESSAGING => "Msg",
        TYPE_MEDIA => "MediaPath",
        _ => "",
    };
    let _ = if type_name.is_empty() {
        write!(buf, "Path({},0x{:X}", node.kind(), node.subtype())
    } else {
        write!(buf, "{}(0x{:X}", type_name, node.subtype())
    };
    if !node.payload().is_empty() {
        buf.push_str(",");
        for byte in node.payload() {
            let _ = write!(buf, "{:02X}", byte);
        }
    }
    buf.push_str(")");
}

/// Format a single device path node.
pub(crate) fn format_node(node: Node, display_only: bool, buf: &mut AsciiBuffer) {
    let formatted = match (node.kind(), node.subtype()) {
        (TYPE_HARDWARE, HW_SUBTYPE_PCI) => fmt_pci(node, buf),
        (TYPE_ACPI, ACPI_SUBTYPE_ACPI) => fmt_acpi(node, buf),
        (TYPE_MESSAGING, MSG_SUBTYPE_USB) => fmt_usb(node, buf),
        (TYPE_MESSAGING, MSG_SUBTYPE_SATA) => fmt_sata(node, buf),
        (TYPE_MESSAGING, MSG_SUBTYPE_NVME) => fmt_nvme(node, buf),
        (TYPE_MEDIA, MEDIA_SUBTYPE_HARDDRIVE) => fmt_hard_drive(node, display_only, buf),
        (TYPE_MEDIA, MEDIA_SUBTYPE_CDROM) => fmt_cdrom(node, display_only, buf),
        (TYPE_MEDIA, MEDIA_SUBTYPE_VENDOR) => fmt_vendor_media(node, buf),
        (TYPE_MEDIA, MEDIA_SUBTYPE_FILEPATH) => {
            fmt_file_path(node, buf);
            Some(())
        }
        _ => None,
    };
    if formatted.is_none() {
        fmt_unknown(node, buf);
    }
}

/// Text for a whole device path. Nodes are separated by `/`; instances by `,`.
pub(crate) fn format_path(path: DevicePath, display_only: bool) -> AsciiBuffer {
    let mut buf = AsciiBuffer::new();
    let mut first = true;
    for node in path.nodes() {
        if node.is_end_instance() {
            buf.push_str(",");
            first = true;
            continue;
        }
        if !first {
            buf.push_str("/");
        }
        first = false;
        format_node(node, display_only, &mut buf);
    }
    buf
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
    // SAFETY: the caller passes null or a readable node of its claimed length.
    let Some(node) = (unsafe { Node::from_raw(device_node) }) else {
        return ptr::null_mut();
    };
    let mut buf = AsciiBuffer::new();
    format_node(node, display_only != Boolean::FALSE, &mut buf);
    ascii_to_ucs2_alloc(buf.as_str())
}

/// `ConvertDevicePathToText` — format a full device path as a UCS-2 string.
extern "efiapi" fn convert_device_path_to_text(
    device_path: *mut device_path::Protocol,
    display_only: Boolean,
    _allow_shortcuts: Boolean,
) -> *mut Char16 {
    // SAFETY: the caller passes null or a readable device path.
    let Some(path) = (unsafe { DevicePath::from_raw(device_path) }) else {
        return ptr::null_mut();
    };
    ascii_to_ucs2_alloc(format_path(path, display_only != Boolean::FALSE).as_str())
}

// ============================================================================
// Protocol creation
// ============================================================================

/// Create a Device Path To Text protocol instance.
///
/// Returns a pointer suitable for `install_protocol`, or null on allocation failure.
pub fn create_protocol() -> *mut c_void {
    let proto = allocate_protocol_value_with_log(
        "DevicePathToText",
        device_path_to_text::Protocol {
            convert_device_node_to_text,
            convert_device_path_to_text,
        },
    );
    proto as *mut c_void
}

#[cfg(test)]
mod tests {
    use super::super::device_path_view::terminated;
    use super::*;

    fn node(kind: u8, subtype: u8, payload: &[u8]) -> alloc::vec::Vec<u8> {
        let len = (payload.len() + 4) as u16;
        let mut node = alloc::vec![kind, subtype];
        node.extend_from_slice(&len.to_le_bytes());
        node.extend_from_slice(payload);
        node
    }

    fn text(parts: &[&[u8]], display_only: bool) -> alloc::string::String {
        let path = terminated(parts).unwrap();
        let path = DevicePath::parse(&path).unwrap();
        format_path(path, display_only).as_str().into()
    }

    #[test]
    fn known_nodes_render_like_edk2() {
        let root = node(
            TYPE_ACPI,
            ACPI_SUBTYPE_ACPI,
            &[0xd0, 0x41, 0x03, 0x0a, 0, 0, 0, 0],
        );
        let pci = node(TYPE_HARDWARE, HW_SUBTYPE_PCI, &[1, 0x1f]);
        let mut hd = alloc::vec![0u8; 38];
        hd[0] = 1; // partition 1
        hd[4] = 0x22; // start
        hd[12] = 0x10; // size
        hd[20..36].copy_from_slice(&[
            0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0, 0xa0, 0xc9, 0x3e, 0xc9,
            0x3b,
        ]);
        hd[36] = 2;
        hd[37] = SIGNATURE_TYPE_GUID;
        let hd = node(TYPE_MEDIA, MEDIA_SUBTYPE_HARDDRIVE, &hd);
        let file = node(
            TYPE_MEDIA,
            MEDIA_SUBTYPE_FILEPATH,
            &[b'\\', 0, b'A', 0, 0xe9, 0, 0, 0],
        );
        assert_eq!(
            text(&[&root, &pci, &hd, &file], false),
            "PciRoot(0x0)/Pci(0x1F,0x1)/HD(1,GPT,C12A7328-F81F-11D2-BA4B-00A0C93EC93B,0x22,0x10)/\\A?"
        );
        assert_eq!(
            text(&[&hd], true),
            "HD(1,GPT,C12A7328-F81F-11D2-BA4B-00A0C93EC93B)"
        );
    }

    #[test]
    fn short_nodes_and_instances_render_generically() {
        // A Hard Drive node one byte short of its fixed layout.
        let short = node(TYPE_MEDIA, MEDIA_SUBTYPE_HARDDRIVE, &[0xab; 37]);
        let rendered = text(&[&short], false);
        assert!(rendered.starts_with("MediaPath(0x1,ABAB"), "{rendered}");
        let usb = node(TYPE_MESSAGING, MSG_SUBTYPE_USB, &[3, 0]);
        let separator = [0x7f, 0x01, 4, 0];
        assert_eq!(
            text(&[&usb, &separator, &usb], false),
            "USB(0x3,0x0),USB(0x3,0x0)"
        );
        assert_eq!(text(&[&node(0x42, 7, &[])], false), "Path(66,0x7)");
    }
}

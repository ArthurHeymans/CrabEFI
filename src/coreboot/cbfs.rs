//! Minimal CBFS payload discovery/chainloading for CrabEFI-as-coreboot-payload.
//!
//! This intentionally lives behind the `coreboot-payload` feature so library
//! users do not get flash payload boot entries.

use crate::drivers::spi::SpiController;
use heapless::{String, Vec};
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

const CBFS_FILE_MAGIC: &[u8; 8] = b"LARCHIVE";
const CBFS_ALIGNMENT: u32 = 64;
const MAX_CBFS_FILES: usize = 32;
const MAX_NAME: usize = 128;
const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

const CBFS_TYPE_SELF: u32 = 0x20;
const CBFS_TYPE_SIMPLE_ELF: u32 = 0x7f;

#[repr(C, packed)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned, Clone, Copy)]
struct CbfsFileHeader {
    magic: [u8; 8],
    len: u32,
    type_: u32,
    attributes_offset: u32,
    offset: u32,
}

#[derive(Debug, Clone)]
pub struct CbfsPayloadEntry {
    pub name: String<MAX_NAME>,
    pub flash_offset: u32,
    pub size: u32,
    pub file_type: u32,
}

fn be32(v: u32) -> u32 {
    u32::from_be(v)
}

fn align_up(v: u32, align: u32) -> Option<u32> {
    Some(v.checked_add(align - 1)? & !(align - 1))
}

fn should_offer_payload(name: &str, file_type: u32) -> bool {
    // Do not offer ourselves; offer common alternate payload names and generic
    // CBFS payload records. coreboot/grub/seabios builds normally use names
    // such as `seabios`, `img/grub2`, or `fallback/payload`.
    file_type == CBFS_TYPE_SELF
        || file_type == CBFS_TYPE_SIMPLE_ELF
        || name.contains("seabios")
        || name.contains("grub")
        || name.contains("payload")
}

pub fn discover_payloads() -> Vec<CbfsPayloadEntry, MAX_CBFS_FILES> {
    let mut out = Vec::new();

    if discover_payloads_mmap(&mut out) {
        return out;
    }

    crate::state::with_drivers_mut(|drivers| {
        let Some(storage) = drivers.platform.storage.as_mut() else {
            log::debug!("CBFS: no SPI storage backend available");
            return;
        };

        let fmap = match super::fmap::read_fmap(storage.controller_mut()) {
            Some(fmap) => fmap,
            None => return,
        };
        let Some(coreboot_area) = super::fmap::find_region(&fmap, "COREBOOT") else {
            log::debug!("CBFS: FMAP has no COREBOOT area");
            return;
        };

        let base = coreboot_area.offset;
        let end = match coreboot_area.offset.checked_add(coreboot_area.size) {
            Some(v) => v,
            None => return,
        };
        let mut off = base;
        let mut header_buf = [0u8; core::mem::size_of::<CbfsFileHeader>()];

        while off
            .checked_add(header_buf.len() as u32)
            .is_some_and(|v| v <= end)
        {
            if storage.controller_mut().read(off, &mut header_buf).is_err() {
                break;
            }

            let Ok((hdr, _)) = CbfsFileHeader::read_from_prefix(&header_buf) else {
                break;
            };
            if &hdr.magic != CBFS_FILE_MAGIC {
                off = match off.checked_add(CBFS_ALIGNMENT) {
                    Some(v) => v,
                    None => break,
                };
                continue;
            }

            let len = be32(hdr.len);
            let file_type = be32(hdr.type_);
            let data_offset = be32(hdr.offset);
            if data_offset < header_buf.len() as u32 || len == 0 || len as usize > MAX_PAYLOAD_SIZE
            {
                off = match off.checked_add(CBFS_ALIGNMENT) {
                    Some(v) => v,
                    None => break,
                };
                continue;
            }

            let name_len = data_offset.saturating_sub(header_buf.len() as u32) as usize;
            let mut name_buf = [0u8; MAX_NAME];
            let read_len = name_len.min(MAX_NAME);
            if read_len != 0
                && storage
                    .controller_mut()
                    .read(off + header_buf.len() as u32, &mut name_buf[..read_len])
                    .is_err()
            {
                break;
            }
            let nul = name_buf.iter().position(|&b| b == 0).unwrap_or(read_len);
            let name_str = core::str::from_utf8(&name_buf[..nul]).unwrap_or("");

            if should_offer_payload(name_str, file_type) && name_str != "fallback/payload" {
                let mut name = String::new();
                let _ = name.push_str(name_str);
                let _ = out.push(CbfsPayloadEntry {
                    name,
                    flash_offset: off,
                    size: len,
                    file_type,
                });
            }

            let next = match off
                .checked_add(data_offset)
                .and_then(|v| v.checked_add(len))
                .and_then(|v| align_up(v, CBFS_ALIGNMENT))
            {
                Some(v) if v > off => v,
                _ => break,
            };
            off = next;
        }
    });

    out
}

#[cfg(target_arch = "x86_64")]
fn discover_payloads_mmap(out: &mut Vec<CbfsPayloadEntry, MAX_CBFS_FILES>) -> bool {
    let Some(boot_media) = super::get_boot_media() else {
        return false;
    };
    let Some(mmap_base) = 0x1_0000_0000u64.checked_sub(boot_media.boot_media_size) else {
        return false;
    };
    let Some(cbfs_addr) = mmap_base.checked_add(boot_media.cbfs_offset) else {
        return false;
    };
    if boot_media.cbfs_size == 0 || boot_media.cbfs_size > usize::MAX as u64 {
        return false;
    }

    // SAFETY: coreboot reports the boot-media memory-mapped window and keeps it
    // readable while payloads run on x86.
    let cbfs = unsafe {
        core::slice::from_raw_parts(cbfs_addr as *const u8, boot_media.cbfs_size as usize)
    };
    discover_payloads_in_slice(cbfs, boot_media.cbfs_offset as u32, out);
    true
}

#[cfg(not(target_arch = "x86_64"))]
fn discover_payloads_mmap(_out: &mut Vec<CbfsPayloadEntry, MAX_CBFS_FILES>) -> bool {
    false
}

fn discover_payloads_in_slice(
    cbfs: &[u8],
    base_flash_offset: u32,
    out: &mut Vec<CbfsPayloadEntry, MAX_CBFS_FILES>,
) {
    let mut off = 0usize;
    let header_len = core::mem::size_of::<CbfsFileHeader>();
    while off.checked_add(header_len).is_some_and(|v| v <= cbfs.len()) {
        let Ok((hdr, _)) = CbfsFileHeader::read_from_prefix(&cbfs[off..off + header_len]) else {
            break;
        };
        if &hdr.magic != CBFS_FILE_MAGIC {
            off = match off.checked_add(CBFS_ALIGNMENT as usize) {
                Some(v) => v,
                None => break,
            };
            continue;
        }

        let len = be32(hdr.len) as usize;
        let file_type = be32(hdr.type_);
        let data_offset = be32(hdr.offset) as usize;
        if data_offset < header_len || len == 0 || len > MAX_PAYLOAD_SIZE {
            off = match off.checked_add(CBFS_ALIGNMENT as usize) {
                Some(v) => v,
                None => break,
            };
            continue;
        }

        let name_start = off + header_len;
        let name_end = off.saturating_add(data_offset).min(cbfs.len());
        if name_start > name_end {
            break;
        }
        let name_bytes = &cbfs[name_start..name_end];
        let nul = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        let name_str = core::str::from_utf8(&name_bytes[..nul]).unwrap_or("");
        if should_offer_payload(name_str, file_type) && name_str != "fallback/payload" {
            let mut name = String::new();
            let _ = name.push_str(name_str);
            let flash_offset = base_flash_offset.saturating_add(off as u32);
            let _ = out.push(CbfsPayloadEntry {
                name,
                flash_offset,
                size: len as u32,
                file_type,
            });
        }

        let next = match off
            .checked_add(data_offset)
            .and_then(|v| v.checked_add(len))
            .and_then(|v| align_up(v as u32, CBFS_ALIGNMENT).map(|v| v as usize))
        {
            Some(v) if v > off => v,
            _ => break,
        };
        off = next;
    }
}

pub unsafe fn chainload_payload(
    entry: &CbfsPayloadEntry,
) -> Result<!, crate::payload::PayloadError> {
    log::info!(
        "CBFS chainload requested for '{}' at {:#x} (type {:#x}, {} bytes)",
        entry.name,
        entry.flash_offset,
        entry.file_type,
        entry.size
    );
    log::warn!("CBFS chainloading loader is not implemented yet");
    Err(crate::payload::PayloadError::InvalidFormat)
}

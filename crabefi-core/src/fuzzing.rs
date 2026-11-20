//! Entry points for the cargo-fuzz targets in `fuzz/`.
//!
//! Each function feeds attacker-controlled bytes to a parser the way the
//! firmware does: a PE image from removable media, a disk's partition table,
//! a FAT or ISO 9660 filesystem, or a boot configuration file. The parsers
//! must reject malformed input with an error, never panic. Built only with
//! the `fuzzing` feature; never part of firmware.

use alloc::vec;
use alloc::vec::Vec;

use crate::drivers::block::{BlockDevice, BlockDeviceInfo, BlockError};
use crate::fs::boot::BootFilesystem;

/// Largest image the PE target materializes. Larger layouts are still parsed.
const MAX_FUZZ_IMAGE: u32 = 16 << 20;

/// A read-only disk image held in memory.
struct Disk {
    data: Vec<u8>,
    block_size: u32,
}

impl Disk {
    /// Pick the block size from the first byte, the disk from the rest.
    fn new(data: &[u8], block_sizes: &[u32]) -> Option<Self> {
        let (&selector, rest) = data.split_first()?;
        let block_size = block_sizes[usize::from(selector) % block_sizes.len()];
        let mut data = rest.to_vec();
        // Whole blocks only, at least one.
        let blocks = data.len().div_ceil(block_size as usize).max(1);
        data.resize(blocks * block_size as usize, 0);
        Some(Self { data, block_size })
    }
}

impl BlockDevice for Disk {
    fn info(&self) -> BlockDeviceInfo {
        BlockDeviceInfo {
            num_blocks: (self.data.len() / self.block_size as usize) as u64,
            block_size: self.block_size,
            media_id: 0,
            removable: true,
            read_only: true,
        }
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.validate_read(lba, count, buffer)?;
        let start = lba as usize * self.block_size as usize;
        let len = count as usize * self.block_size as usize;
        buffer[..len].copy_from_slice(&self.data[start..start + len]);
        Ok(())
    }
}

/// Parse a PE/COFF file, then lay it out and relocate it in host memory.
pub fn pe(data: &[u8]) {
    if let Ok(headers) = crate::pe::parse_headers(data) {
        for section in headers.sections() {
            core::hint::black_box(section);
        }
        for index in 0..16 {
            core::hint::black_box(headers.data_directory(index));
        }
        core::hint::black_box(headers.preferred_image_base());
    }
    let Ok(layout) = crate::pe::image_layout(data) else {
        return;
    };
    if layout.image_size() > MAX_FUZZ_IMAGE {
        return;
    }
    let mut image = vec![0u8; layout.image_size() as usize];
    // Load away from the preferred base so relocations run.
    let base = layout.load_address(0x4000_0000);
    let _ = layout.build(&mut image, base);
}

/// Read a GPT or MBR partition table and look for an ESP.
pub fn partitions(data: &[u8]) {
    let Some(mut disk) = Disk::new(data, &[512, 4096]) else {
        return;
    };
    let _ = crate::fs::gpt::read_partitions_auto(&mut disk);
    let _ = crate::fs::gpt::find_esp(&mut disk);
}

/// Mount a FAT filesystem and walk the paths boot discovery uses.
pub fn fat(data: &[u8]) {
    let Some(mut disk) = Disk::new(data, &[512, 4096]) else {
        return;
    };
    let Ok(mut fs) = crate::fs::fat::FatFilesystem::new(&mut disk, 0) else {
        return;
    };
    let mut buffer = [0u8; 4096];
    for directory in ["", "EFI", "EFI/BOOT", "loader/entries"] {
        let Ok(files) = fs.list_files(directory, "") else {
            continue;
        };
        let _ = fs.list_subdirectories(directory);
        for file in files.iter().take(8) {
            let path = alloc::format!("{directory}/{file}");
            let _ = fs.file_size(&path);
            let _ = fs.read_file_at(&path, 0, &mut buffer);
            let _ = fs.read_file_at(&path, 4096, &mut buffer);
        }
    }
    let _ = fs.read_file_all("EFI/BOOT/BOOTX64.EFI", &mut buffer);
}

/// Find the El Torito EFI boot image on an ISO 9660 disc.
pub fn iso9660(data: &[u8]) {
    let Some(mut disk) = Disk::new(data, &[2048, 512]) else {
        return;
    };
    if crate::fs::iso9660::is_iso9660(&mut disk) {
        let _ = crate::fs::iso9660::find_efi_boot_image(&mut disk);
    }
}

/// Parse BLS entries, loader.conf and grub.cfg text.
pub fn boot_config(data: &[u8]) {
    let Ok(text) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(entry) = crate::bls::BlsEntry::parse(text) {
        core::hint::black_box(entry.display_title());
    }
    core::hint::black_box(crate::bls::LoaderConf::parse(text));
    let _ = crate::grub::parse_grub_content(text);
}

/// Render, split and rebuild a caller-supplied device path.
pub fn device_path(data: &[u8]) {
    use crate::efi::protocols::device_path_to_text::{format_node, format_path};
    use crate::efi::protocols::device_path_utilities::{append, append_instance, next_instance};
    use crate::efi::protocols::device_path_view::{DevicePath, Node};

    if let Some(node) = Node::parse(data) {
        let mut text = crate::efi::protocols::device_path_to_text::AsciiBuffer::default();
        format_node(node, false, &mut text);
    }
    let Some(path) = DevicePath::parse(data) else {
        return;
    };
    for display_only in [false, true] {
        core::hint::black_box(format_path(path, display_only).as_str());
    }
    // Every path construction accepts parses again in full.
    fn parses(bytes: &[u8]) -> Option<DevicePath<'_>> {
        DevicePath::parse(bytes).filter(|path| path.as_bytes().len() == bytes.len())
    }
    if let Some(doubled) = append(Some(path), Some(path)) {
        let doubled = parses(&doubled).expect("appended path");
        if !path.is_multi_instance() {
            assert_eq!(doubled.strip_prefix(path), Some(path.body().len()));
        }
    }
    let Some(joined) = append_instance(path, path) else {
        return;
    };
    let joined = parses(&joined).expect("joined path");
    let mut rest = Some(joined);
    while let Some(current) = rest {
        let (instance, next) = next_instance(current).expect("an instance is smaller");
        assert!(parses(&instance).is_some());
        rest = next.map(|offset| DevicePath::parse(&current.as_bytes()[offset..]).unwrap());
    }
}

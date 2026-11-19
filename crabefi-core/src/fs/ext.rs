//! Read-only ext2/3/4 adapter. The parser never sees the rest of the disk.

use alloc::boxed::Box;
use ext4_view::{Ext4, Ext4Read};
use heapless::String;

use super::boot::{BootFilesystem, Names, ReadError, check_path};
use super::gpt::Partition;
use crate::drivers::block::{BlockDevice, BlockDeviceInfo, BlockError, BlockRange};
use crate::drivers::storage::{self, StorageId};

pub(super) struct ExtFilesystem(Ext4);

const SUPERBLOCK_OFFSET: u64 = 1024;
const MAX_BLOCK_GROUPS: u64 = 8192;
const MAX_DISCOVERY_READS: usize = 16_384;
const MAX_DIRENTS: usize = 1024;

fn same_fixed_media(expected: BlockDeviceInfo, live: BlockDeviceInfo) -> bool {
    !expected.removable
        && !live.removable
        && expected.media_id == live.media_id
        && expected.block_size == live.block_size
        && expected.num_blocks == live.num_blocks
}

// ext4-view allocates its cache and group descriptors from these fields before
// it visits any files. Refuse oversized layouts and journal replay up front.
// This isn't a hard allocator limit for the rest of the parser.
fn supported_superblock(bytes: &[u8; 1024], partition_bytes: u64) -> bool {
    const NEEDS_RECOVERY: u32 = 0x0004;
    let read_u32 =
        |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    if bytes[0x38..0x3a] != [0x53, 0xef] || read_u32(0x60) & NEEDS_RECOVERY != 0 {
        return false;
    }
    let block_shift = read_u32(0x18);
    if block_shift > 2 {
        return false;
    }
    let block_size = 1024u64 << block_shift;
    let blocks = u64::from(read_u32(0x04)) | (u64::from(read_u32(0x150)) << 32);
    let first = u64::from(read_u32(0x14));
    let per_group = u64::from(read_u32(0x20));
    blocks > first
        && per_group != 0
        && blocks <= partition_bytes / block_size
        && (blocks - first).div_ceil(per_group) <= MAX_BLOCK_GROUPS
}

// Ext4Read owns its input, so keep a device identity and reborrow the device
// per read instead of storing a borrowed controller in the parser.
struct PartitionReader {
    storage: StorageId,
    range: BlockRange,
    media: BlockDeviceInfo,
    reads_left: Option<usize>,
}

impl PartitionReader {
    fn read_from(
        &mut self,
        disk: &mut dyn BlockDevice,
        offset: u64,
        out: &mut [u8],
    ) -> Result<(), BlockError> {
        if !same_fixed_media(self.media, disk.info()) {
            return Err(BlockError::MediaChanged);
        }
        if let Some(left) = self.reads_left.as_mut() {
            *left = left.checked_sub(1).ok_or(BlockError::DeviceError)?;
        }
        self.range.read(disk, offset, out)
    }
}

impl Ext4Read for PartitionReader {
    fn read(
        &mut self,
        offset: u64,
        out: &mut [u8],
    ) -> Result<(), Box<dyn core::error::Error + Send + Sync>> {
        storage::with_disk(self.storage, |disk| self.read_from(disk, offset, out))
            .and_then(core::convert::identity)
            .map_err(|err| Box::new(err) as _)
    }
}

impl ExtFilesystem {
    pub(super) fn mount(
        storage: StorageId,
        partition: &Partition,
        media: BlockDeviceInfo,
        discovery: bool,
    ) -> Option<Self> {
        let reader = storage::with_disk(storage, |disk| {
            if !same_fixed_media(media, disk.info()) {
                return None;
            }
            let range =
                BlockRange::new(disk, partition.first_lba, partition.size_sectors()).ok()?;
            let mut superblock = [0; 1024];
            range.read(disk, SUPERBLOCK_OFFSET, &mut superblock).ok()?;
            supported_superblock(&superblock, range.byte_len(disk).ok()?).then_some(
                PartitionReader {
                    storage,
                    range,
                    media,
                    reads_left: discovery.then_some(MAX_DISCOVERY_READS),
                },
            )
        })
        .ok()??;
        match Ext4::load(Box::new(reader)) {
            Ok(volume) => Some(Self(volume)),
            Err(err) => {
                log::debug!(
                    "Cannot mount ext filesystem at LBA {}: {err}",
                    partition.first_lba
                );
                None
            }
        }
    }

    fn list<const N: usize>(
        &self,
        directory: &str,
        matches: impl Fn(&str, ext4_view::FileType) -> bool,
    ) -> Result<Names<N>, ReadError> {
        let path = ext_path(directory)?;
        let mut names = Names::new();
        let entries = self.0.read_dir(path.as_str()).map_err(ReadError::Ext)?;
        for entry in entries.take(MAX_DIRENTS) {
            let entry = entry.map_err(ReadError::Ext)?;
            let Ok(name) = entry.file_name().as_str() else {
                continue;
            };
            if name != "."
                && name != ".."
                && matches(name, entry.file_type().map_err(ReadError::Ext)?)
            {
                // ext limits a name to 255 bytes.
                if let Ok(name) = String::try_from(name)
                    && names.push(name).is_err()
                {
                    break;
                }
            }
        }
        Ok(names)
    }
}

fn ext_path(path: &str) -> Result<String<512>, ReadError> {
    check_path(path)?;
    let mut absolute = String::new();
    absolute.push('/').map_err(|_| ReadError::InvalidPath)?;
    absolute
        .push_str(path.trim_start_matches('/'))
        .map_err(|_| ReadError::InvalidPath)?;
    Ok(absolute)
}

impl BootFilesystem for ExtFilesystem {
    fn file_size(&mut self, path: &str) -> Result<u64, ReadError> {
        let path = ext_path(path)?;
        let metadata = self.0.metadata(path.as_str()).map_err(ReadError::Ext)?;
        if !metadata.file_type().is_regular_file() {
            return Err(ReadError::NotAFile);
        }
        Ok(metadata.len())
    }

    fn read_file_at(
        &mut self,
        path: &str,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, ReadError> {
        let path = ext_path(path)?;
        let mut file = self.0.open(path.as_str()).map_err(ReadError::Ext)?;
        if offset >= file.metadata().len() || out.is_empty() {
            return Ok(0);
        }
        file.seek_to(offset).map_err(ReadError::Ext)?;
        let mut read = 0;
        while read < out.len() {
            let n = file.read_bytes(&mut out[read..]).map_err(ReadError::Ext)?;
            if n == 0 {
                break;
            }
            read += n;
        }
        Ok(read)
    }

    fn list_files(&mut self, directory: &str, suffix: &str) -> Result<Names<32>, ReadError> {
        self.list(directory, |name, kind| {
            name.ends_with(suffix) && (kind.is_regular_file() || kind.is_symlink())
        })
    }

    fn list_subdirectories(&mut self, directory: &str) -> Result<Names<16>, ReadError> {
        self.list(directory, |_, kind| kind.is_dir())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ReadOnlyDisk {
        media: BlockDeviceInfo,
        reads: usize,
    }

    impl BlockDevice for ReadOnlyDisk {
        fn info(&self) -> BlockDeviceInfo {
            self.media
        }

        fn read_blocks(&mut self, lba: u64, count: u32, out: &mut [u8]) -> Result<(), BlockError> {
            self.validate_read(lba, count, out)?;
            self.reads += 1;
            // Fill each block with its absolute LBA so the test can verify translation.
            for (i, block) in out
                .chunks_exact_mut(self.media.block_size as usize)
                .enumerate()
            {
                block.fill((lba + i as u64) as u8);
            }
            Ok(())
        }
    }

    #[test]
    fn byte_reads_use_partition_bounds_and_reject_changed_media() {
        for block_size in [512, 4096] {
            let mut disk = ReadOnlyDisk {
                media: BlockDeviceInfo {
                    num_blocks: 16,
                    block_size,
                    media_id: 1,
                    removable: false,
                    read_only: true,
                },
                reads: 0,
            };
            let mut reader = PartitionReader {
                storage: StorageId::Platform { index: 0 },
                range: BlockRange::new(&disk, 5, 2).unwrap(),
                media: disk.info(),
                reads_left: Some(3),
            };
            let mut bytes = [0; 3];
            reader
                .read_from(&mut disk, u64::from(block_size) - 1, &mut bytes)
                .unwrap();
            assert_eq!(bytes, [5, 6, 6]);
            let reads = disk.reads;
            assert_eq!(
                reader.read_from(&mut disk, 2 * u64::from(block_size) - 1, &mut bytes),
                Err(BlockError::OutOfRange),
            );
            disk.media.removable = true;
            assert_eq!(
                reader.read_from(&mut disk, 0, &mut bytes),
                Err(BlockError::MediaChanged)
            );
            disk.media.removable = false;
            disk.media.media_id += 1;
            assert_eq!(
                reader.read_from(&mut disk, 0, &mut bytes),
                Err(BlockError::MediaChanged)
            );
            assert_eq!(disk.reads, reads);
            disk.media.media_id -= 1;
            reader.read_from(&mut disk, 0, &mut bytes).unwrap();
            assert_eq!(
                reader.read_from(&mut disk, 0, &mut bytes),
                Err(BlockError::DeviceError)
            );
        }
    }

    #[test]
    fn preflight_checks_layout_before_mounting() {
        let mut sb = [0; 1024];
        sb[0x38..0x3a].copy_from_slice(&[0x53, 0xef]);
        sb[4..8].copy_from_slice(&128u32.to_le_bytes());
        sb[0x20..0x24].copy_from_slice(&32u32.to_le_bytes());
        let partition = 128 * 1024;
        assert!(supported_superblock(&sb, partition));
        assert!(!supported_superblock(&sb, partition - 1));
        sb[0x60] = 4; // Needs journal recovery.
        assert!(!supported_superblock(&sb, partition));
        sb[0x60] = 0;
        sb[0x18] = 3; // 8 KiB filesystem blocks.
        assert!(!supported_superblock(&sb, partition * 8));
        sb[0x18] = 0;
        sb[4..8].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert!(!supported_superblock(&sb, 1_000_000 * 1024));
    }
}

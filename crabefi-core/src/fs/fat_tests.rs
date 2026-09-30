//! FAT32 mutation tests on a sparse in-memory disk.

#[path = "fat_efi_tests.rs"]
mod efi;
#[path = "fat_metadata_tests.rs"]
mod metadata;
#[path = "fat_mutation_tests.rs"]
mod mutation;
#[path = "fat_recovery_tests.rs"]
mod recovery;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::*;
use crate::drivers::block::{BlockDeviceInfo, BlockError};

/// Clusters in the test volume: just above the FAT32 detection threshold.
const DATA_CLUSTERS: u32 = 65_600;
/// First LBA of the partition, so partition-relative arithmetic is exercised.
const PARTITION_START: u64 = 8;

/// Sparse disk: blocks that were never written read as zero.
#[derive(Clone)]
struct RamDisk {
    block_size: usize,
    blocks: BTreeMap<u64, Vec<u8>>,
}

impl RamDisk {
    fn block(&self, lba: u64) -> Vec<u8> {
        self.blocks
            .get(&lba)
            .cloned()
            .unwrap_or_else(|| alloc::vec![0; self.block_size])
    }

    fn poke(&mut self, byte_offset: u64, bytes: &[u8]) {
        for (index, &byte) in bytes.iter().enumerate() {
            let position = byte_offset + index as u64;
            let lba = position / self.block_size as u64;
            let mut block = self.block(lba);
            block[position as usize % self.block_size] = byte;
            self.blocks.insert(lba, block);
        }
    }

    fn peek(&self, byte_offset: u64, len: usize) -> Vec<u8> {
        (0..len as u64)
            .map(|index| {
                let position = byte_offset + index;
                self.block(position / self.block_size as u64)[position as usize % self.block_size]
            })
            .collect()
    }
}

impl BlockDevice for RamDisk {
    fn info(&self) -> BlockDeviceInfo {
        BlockDeviceInfo {
            num_blocks: 1 << 32,
            block_size: self.block_size as u32,
            media_id: 0,
            removable: false,
            read_only: false,
        }
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.validate_io(lba, count, buffer)?;
        for index in 0..count as usize {
            let block = self.block(lba + index as u64);
            buffer[index * self.block_size..][..self.block_size].copy_from_slice(&block);
        }
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, count: u32, buffer: &[u8]) -> Result<(), BlockError> {
        self.validate_io(lba, count, buffer)?;
        for index in 0..count as usize {
            let block = buffer[index * self.block_size..][..self.block_size].to_vec();
            self.blocks.insert(lba + index as u64, block);
        }
        Ok(())
    }
}

/// Volume layout knobs for [`format`].
#[derive(Clone, Copy)]
struct Layout {
    block_size: usize,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
}

const LAYOUTS: [Layout; 4] = [
    Layout {
        block_size: 512,
        sectors_per_cluster: 1,
        reserved_sectors: 32,
    },
    // Data area starts half-way into a 1 KiB block and clusters span blocks.
    Layout {
        block_size: 1024,
        sectors_per_cluster: 4,
        reserved_sectors: 33,
    },
    Layout {
        block_size: 2048,
        sectors_per_cluster: 2,
        reserved_sectors: 32,
    },
    Layout {
        block_size: 4096,
        sectors_per_cluster: 1,
        reserved_sectors: 35,
    },
];

/// Build an empty FAT32 volume with two FAT copies.
fn format(layout: Layout) -> RamDisk {
    let mut disk = RamDisk {
        block_size: layout.block_size,
        blocks: BTreeMap::new(),
    };
    let sectors_per_fat = (DATA_CLUSTERS + 2).div_ceil(128);
    let total_sectors = layout.reserved_sectors as u32
        + 2 * sectors_per_fat
        + DATA_CLUSTERS * layout.sectors_per_cluster as u32;
    let base = PARTITION_START * layout.block_size as u64;

    let mut boot = [0u8; 64];
    boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    boot[11..13].copy_from_slice(&512u16.to_le_bytes());
    boot[13] = layout.sectors_per_cluster;
    boot[14..16].copy_from_slice(&layout.reserved_sectors.to_le_bytes());
    boot[16] = 2;
    boot[32..36].copy_from_slice(&total_sectors.to_le_bytes());
    boot[36..40].copy_from_slice(&sectors_per_fat.to_le_bytes());
    boot[44..48].copy_from_slice(&2u32.to_le_bytes());
    disk.poke(base, &boot);

    let reserved_entries = [0x0fff_fff8u32, 0x0fff_ffff, 0x0fff_ffff];
    for copy in 0..2 {
        let fat = base + (layout.reserved_sectors as u32 + copy * sectors_per_fat) as u64 * 512;
        disk.poke(fat, &reserved_entries.map(u32::to_le_bytes).concat());
    }
    disk
}

fn fat_value(disk: &RamDisk, layout: Layout, copy: u32, cluster: u32) -> u32 {
    let sectors_per_fat = (DATA_CLUSTERS + 2).div_ceil(128);
    let offset = PARTITION_START * layout.block_size as u64
        + (layout.reserved_sectors as u32 + copy * sectors_per_fat) as u64 * 512
        + cluster as u64 * 4;
    u32::from_le_bytes(disk.peek(offset, 4).try_into().unwrap()) & 0x0fff_ffff
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index * 7 + 3) as u8).collect()
}

fn read_all(fat: &mut FatFilesystem, path: &str) -> Vec<u8> {
    let entry = fat.find_file(path).unwrap();
    let mut data = alloc::vec![0; entry.file_size() as usize];
    assert_eq!(fat.read_file(&entry, 0, &mut data).unwrap(), data.len());
    data
}

fn names(fat: &mut FatFilesystem, directory: &str) -> Vec<alloc::string::String> {
    let cluster = fat.resolve_dir_cluster(directory).unwrap();
    (0..)
        .map_while(|position| {
            fat.get_directory_entry_at_position(cluster, position)
                .unwrap()
        })
        .map(|(_, name)| name.as_str().into())
        .collect()
}

#[test]
fn file_roundtrip_spans_clusters_and_mirrors_fat() {
    for layout in LAYOUTS {
        let mut disk = format(layout);
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        let data = pattern(5000);

        let created = fat.create("EFI.BIN", false).unwrap();
        assert_eq!((created.first_cluster(), created.file_size()), (0, 0));
        // Two writes, the second one overlapping the first and extending it.
        fat.write_path("EFI.BIN", 0, &data[..3000]).unwrap();
        let (size, first) = fat.write_path("EFI.BIN", 2000, &data[2000..]).unwrap();
        assert_eq!(size, 5000);
        assert!(first >= 3);
        assert_eq!(read_all(&mut fat, "EFI.BIN"), data);

        let mut cluster = first;
        loop {
            let copy0 = fat_value(&disk, layout, 0, cluster);
            assert_eq!(copy0, fat_value(&disk, layout, 1, cluster));
            if copy0 >= 0x0fff_fff8 {
                break;
            }
            cluster = copy0;
        }
    }
}

#[test]
fn long_names_keep_case_and_get_unique_short_names() {
    let layout = LAYOUTS[0];
    let mut disk = format(layout);
    let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();

    for name in [
        "Long File Name.txt",
        "Long File Name 2.txt",
        "Mixed.Txt",
        "BOOT.EFI",
    ] {
        fat.create(name, false).unwrap();
    }
    assert!(matches!(
        fat.create("long file name.TXT", false),
        Err(FatError::AlreadyExists)
    ));

    let listed = names(&mut fat, "");
    assert_eq!(
        listed,
        [
            "Long File Name.txt",
            "Long File Name 2.txt",
            "Mixed.Txt",
            "BOOT.EFI"
        ]
    );
    // The two long names cannot share a short name.
    let short = |fat: &mut FatFilesystem, name: &str| fat.find_file(name).unwrap().short_name();
    assert_eq!(short(&mut fat, "Long File Name.txt"), "LONGFI~1.TXT");
    assert_eq!(short(&mut fat, "Long File Name 2.txt"), "LONGFI~2.TXT");
    assert_eq!(short(&mut fat, "mixed.txt"), "MIXED.TXT");
}

#[test]
fn rejects_unrepresentable_names() {
    let mut disk = format(LAYOUTS[0]);
    let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
    for name in ["a*b", "trailing.", "q?", &"x".repeat(256)] {
        assert!(
            matches!(fat.create(name, false), Err(FatError::InvalidName)),
            "{name:?}"
        );
    }
    // Long names are limited to one UTF-16 unit per character.
    assert!(matches!(
        fat.create("smile-\u{1f600}.txt", false),
        Err(FatError::InvalidName)
    ));
    fat.create("caf\u{e9}.txt", false).unwrap();
    assert_eq!(names(&mut fat, ""), ["caf\u{e9}.txt"]);
}

#[test]
fn directories_nest_and_deletion_frees_clusters() {
    let layout = LAYOUTS[1];
    let mut disk = format(layout);
    let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
    let root = fat.root_cluster();

    let outer = fat.create("outer", true).unwrap();
    let inner = fat.create("outer/inner", true).unwrap();
    fat.create("outer/inner/file.txt", false).unwrap();
    let (_, file_cluster) = fat
        .write_path("outer/inner/file.txt", 0, &pattern(100))
        .unwrap();

    // `..` of a top-level directory is cluster 0, otherwise the parent.
    let dotdot = |fat: &mut FatFilesystem, cluster: u32| {
        fat.find_in_directory(cluster, "..")
            .unwrap()
            .first_cluster()
    };
    assert_eq!(dotdot(&mut fat, outer.first_cluster()), 0);
    assert_eq!(
        dotdot(&mut fat, inner.first_cluster()),
        outer.first_cluster()
    );
    assert_eq!(
        fat.resolve_dir_cluster("outer").unwrap(),
        outer.first_cluster()
    );
    assert_ne!(outer.first_cluster(), root);

    assert!(matches!(
        fat.delete_path("outer/inner"),
        Err(FatError::DirectoryNotEmpty)
    ));
    fat.delete_path("outer/inner/file.txt").unwrap();
    fat.delete_path("outer/inner").unwrap();
    assert!(matches!(
        fat.find_file("outer/inner"),
        Err(FatError::NotFound)
    ));
    assert_eq!(fat_value(&disk, layout, 0, file_cluster), 0);
    assert_eq!(fat_value(&disk, layout, 0, inner.first_cluster()), 0);
    assert_eq!(fat_value(&disk, layout, 1, inner.first_cluster()), 0);
}

#[test]
fn directory_grows_across_clusters() {
    let layout = LAYOUTS[0];
    let mut disk = format(layout);
    let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();

    // 512-byte clusters hold 16 records; each lower-case name needs two.
    let created: Vec<_> = (0..40)
        .map(|index| alloc::format!("file{index:03}"))
        .collect();
    for name in &created {
        fat.create(name, false).unwrap();
    }
    assert_eq!(names(&mut fat, ""), created);
    for name in &created {
        fat.find_file(name).unwrap();
    }

    // A deleted run is reused instead of growing the directory further.
    fat.delete_path("file010").unwrap();
    fat.create("file999", false).unwrap();
    assert_eq!(names(&mut fat, "").len(), 40);
}

#[test]
fn truncate_zeroes_tail_so_growing_writes_read_zeros() {
    for layout in LAYOUTS {
        let mut disk = format(layout);
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        fat.create("data", false).unwrap();
        fat.write_path("data", 0, &[0xaa; 1500]).unwrap();

        fat.truncate_path("data", 100).unwrap();
        assert_eq!(read_all(&mut fat, "data"), [0xaa; 100]);
        fat.write_path("data", 1200, &[0xbb]).unwrap();
        let data = read_all(&mut fat, "data");
        assert_eq!(data.len(), 1201);
        assert_eq!(data[..100], [0xaa; 100]);
        assert!(data[100..1200].iter().all(|&byte| byte == 0));
        assert_eq!(data[1200], 0xbb);

        let first = fat.find_file("data").unwrap().first_cluster();
        fat.truncate_path("data", 0).unwrap();
        assert_eq!(fat.find_file("data").unwrap().first_cluster(), 0);
        assert_eq!(fat_value(&disk, layout, 0, first), 0);
    }
}

#[test]
fn full_volume_rolls_back_partial_growth() {
    let layout = LAYOUTS[0];
    let mut disk = format(layout);
    let last = DATA_CLUSTERS + 1;
    // Mark every cluster after the first data cluster as used, except `last`.
    let fat0 = PARTITION_START * 512 + layout.reserved_sectors as u64 * 512;
    let used = (4..last)
        .flat_map(|_| 0x0fff_ffffu32.to_le_bytes())
        .collect::<Vec<_>>();
    disk.poke(fat0 + 4 * 4, &used);
    let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();

    fat.create("big", false).unwrap();
    // Cluster 3 and `last` are free: a 2-cluster write fits, a 3-cluster one
    // must fail and give both clusters back.
    assert!(matches!(
        fat.write_path("big", 0, &[1; 3 * 512]),
        Err(FatError::NoSpace)
    ));
    assert_eq!(fat.find_file("big").unwrap().first_cluster(), 0);
    fat.write_path("big", 0, &[1; 2 * 512]).unwrap();
    assert_eq!(read_all(&mut fat, "big"), [1; 1024]);
}

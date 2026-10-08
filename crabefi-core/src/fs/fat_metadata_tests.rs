use super::*;
use crate::drivers::block::BlockRange;
use zerocopy::FromZeros;
use zerocopy::little_endian::U32;

struct CountingDisk {
    disk: RamDisk,
    reads: usize,
}
impl BlockDevice for CountingDisk {
    fn info(&self) -> BlockDeviceInfo {
        self.disk.info()
    }
    fn read_blocks(&mut self, lba: u64, count: u32, output: &mut [u8]) -> Result<(), BlockError> {
        self.reads += count as usize;
        self.disk.read_blocks(lba, count, output)
    }
    fn write_blocks(&mut self, lba: u64, count: u32, input: &[u8]) -> Result<(), BlockError> {
        self.disk.write_blocks(lba, count, input)
    }
}

#[test]
fn repeated_appends_preserve_allocator_and_tail_across_device_borrows() {
    let reads = |count: u32| {
        let mut disk = CountingDisk {
            disk: format(LAYOUTS[0]),
            reads: 0,
        };
        let blocks = disk.info().num_blocks - PARTITION_START;
        let (geometry, mut state, mut file) = {
            let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
            let file = fat.create_with_attributes("A.BIN", 0).unwrap();
            (fat.geometry(), fat.volume_state(), file)
        };
        disk.reads = 0;
        for index in 0..count {
            let mut fat = FatFilesystem::from_geometry_in_partition(
                &mut disk,
                PARTITION_START,
                blocks,
                geometry,
                state,
            )
            .unwrap();
            fat.write_file(&mut file, index * 512, &[0xaa; 512])
                .unwrap();
            state = fat.volume_state();
        }
        disk.reads
    };
    let small = reads(128);
    let large = reads(1024);
    // Eight times the appends should remain linear, not repeatedly scan the
    // growing FAT prefix and the entire existing chain.
    assert!(large <= small * 9, "small={small}, large={large}");
}

#[test]
fn active_fat_one_is_used_for_allocation_instead_of_stale_fat_zero() {
    let layout = LAYOUTS[0];
    let mut disk = format(layout);
    let spf = (DATA_CLUSTERS + 2).div_ceil(128);
    let base = PARTITION_START * 512;
    // Cluster 3 is live only in the authoritative FAT; the other copy is stale.
    disk.poke(base + 40, &0x0081u16.to_le_bytes());
    disk.poke(
        base + (layout.reserved_sectors as u64 + spf as u64) * 512 + 3 * 4,
        &0x0fff_ffffu32.to_le_bytes(),
    );
    let root = base + (layout.reserved_sectors as u64 + 2 * spf as u64) * 512;
    disk.poke(
        root,
        DirectoryEntry::new(*b"B       BIN", 0, 3, 100).as_bytes(),
    );
    disk.poke(root + 512, &[0xbb; 512]);
    {
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        fat.create("A.BIN", false).unwrap();
        fat.write_path("A.BIN", 0, &[0xaa; 100]).unwrap();
        assert_eq!(fat.find_file("A.BIN").unwrap().first_cluster(), 4);
        assert_eq!(read_all(&mut fat, "B.BIN"), [0xbb; 100]);
        fat.flush().unwrap();
    }
    assert_eq!(disk.peek(root + 512, 100), [0xbb; 100]);
    assert_eq!(fat_value(&disk, layout, 0, 4), 0);
    assert_eq!(fat_value(&disk, layout, 1, 4), 0x0fff_ffff);
}

#[test]
fn bpb_layout_cannot_escape_the_independent_partition_extent() {
    let original = format(LAYOUTS[0]);
    let base = PARTITION_START * 512;
    let sectors = u32::from_le_bytes(original.peek(base + 32, 4).try_into().unwrap()) as u64;
    for (offset, bytes) in [
        (32, u32::MAX.to_le_bytes().to_vec()),
        (36, 1u32.to_le_bytes().to_vec()),
        (40, 0x0082u16.to_le_bytes().to_vec()),
        (44, u32::MAX.to_le_bytes().to_vec()),
        (13, alloc::vec![0]),
        (17, 16u16.to_le_bytes().to_vec()),
    ] {
        let mut disk = original.clone();
        disk.poke(base + offset, &bytes);
        assert!(matches!(
            FatFilesystem::new_partition(&mut disk, PARTITION_START, sectors),
            Err(FatError::InvalidBpb)
        ));
    }
    let mut disk = original;
    assert!(matches!(
        FatFilesystem::new_partition(&mut disk, PARTITION_START, sectors - 1),
        Err(FatError::InvalidBpb)
    ));
}

#[test]
fn bounded_byte_io_preserves_neighbouring_blocks() {
    for layout in LAYOUTS {
        let mut disk = format(layout);
        let bytes = layout.block_size as u64;
        let base = PARTITION_START * bytes;
        disk.poke(base - bytes, &alloc::vec![0xcc; layout.block_size]);
        disk.poke(base + 2 * bytes, &alloc::vec![0xdd; layout.block_size]);
        let range = BlockRange::new(&disk, PARTITION_START, 2).unwrap();
        range.write(&mut disk, bytes - 1, &[0xaa, 0xbb]).unwrap();
        let mut output = [0; 2];
        range.read(&mut disk, bytes - 1, &mut output).unwrap();
        assert_eq!(output, [0xaa, 0xbb]);
        let before = disk.blocks.clone();
        assert!(range.write(&mut disk, 2 * bytes - 1, &[0; 2]).is_err());
        assert!(range.read(&mut disk, 2 * bytes - 1, &mut output).is_err());
        assert!(range.write(&mut disk, u64::MAX, &[0]).is_err());
        assert_eq!(disk.blocks, before);
    }
}

#[test]
fn advisory_hints_are_invalidated_and_unclean_mounts_require_repair() {
    let layout = LAYOUTS[0];
    let mut disk = format(layout);
    let base = PARTITION_START * 512;
    disk.poke(base + 48, &1u16.to_le_bytes());
    let mut info = Fat32FsInfo::new_zeroed();
    info.lead_signature = U32::new(0x4161_5252);
    info.structure_signature = U32::new(0x6141_7272);
    info.trail_signature = U32::new(0xaa55_0000);
    info.free_count = U32::new(7); // Deliberately incorrect advisory count.
    info.next_free = U32::new(3);
    info.reserved_tail[0] = 42;
    disk.poke(base + 512, info.as_bytes());
    let (geometry, state) = {
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        assert!(!fat.is_read_only());
        fat.create("A.BIN", false).unwrap();
        assert_eq!(fat.free_space().unwrap(), (DATA_CLUSTERS as u64 - 1) * 512);
        (fat.geometry(), fat.volume_state())
    };
    let info = Fat32FsInfo::read_from_bytes(&disk.peek(base + 512, 512)).unwrap();
    assert_eq!(info.free_count.get(), u32::MAX);
    assert_eq!(info.next_free.get(), u32::MAX);
    assert_eq!(info.reserved_tail[0], 42);
    assert_eq!(fat_value(&disk, layout, 0, 1) & 0x0800_0000, 0);
    {
        let mut unclean = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        assert!(unclean.is_read_only());
        unclean.find_file("A.BIN").unwrap();
        assert!(matches!(
            unclean.create("B.BIN", false),
            Err(FatError::ReadOnly)
        ));
    }
    // Reborrowing the same live mount must retain its dirty/allocator state,
    // rather than mistaking our own in-progress writes for an unsafe remount.
    let blocks = disk.info().num_blocks - PARTITION_START;
    FatFilesystem::from_geometry_in_partition(&mut disk, PARTITION_START, blocks, geometry, state)
        .unwrap()
        .flush()
        .unwrap();
    assert_eq!(fat_value(&disk, layout, 0, 1) & 0x0800_0000, 0x0800_0000);
    assert_eq!(fat_value(&disk, layout, 1, 1) & 0x0800_0000, 0x0800_0000);
    assert!(
        !FatFilesystem::new(&mut disk, PARTITION_START)
            .unwrap()
            .is_read_only()
    );
}

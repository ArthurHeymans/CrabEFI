use super::*;

fn data_offset(layout: Layout, cluster: u32) -> u64 {
    let spf = (DATA_CLUSTERS + 2).div_ceil(128);
    PARTITION_START * layout.block_size as u64
        + (layout.reserved_sectors as u64
            + 2 * spf as u64
            + (cluster - 2) as u64 * layout.sectors_per_cluster as u64)
            * 512
}

#[test]
fn imported_file_slack_is_not_exposed_when_growing() {
    let layout = LAYOUTS[0];
    let mut disk = format(layout);
    let first = {
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        fat.create("A.BIN", false).unwrap();
        let first = fat.write_path("A.BIN", 0, &[0xaa; 100]).unwrap().1;
        fat.flush().unwrap();
        first
    };
    // FAT does not require the unused bytes after EOF to be zero.
    disk.poke(data_offset(layout, first) + 100, &[0xcc; 412]);
    let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
    fat.write_path("A.BIN", 500, &[0xbb]).unwrap();
    assert!(
        read_all(&mut fat, "A.BIN")[100..500]
            .iter()
            .all(|b| *b == 0)
    );
}

#[test]
fn truncation_invalidates_a_preexisting_read_hint() {
    let mut disk = format(LAYOUTS[0]);
    let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
    fat.create("A.BIN", false).unwrap();
    fat.write_path("A.BIN", 0, &[0xaa; 1500]).unwrap();
    let entry = fat.find_file("A.BIN").unwrap();
    let mut hint = FileClusterHint::new(entry.first_cluster());
    fat.read_file_with_hint(&entry, 512, &mut [0; 1], &mut hint)
        .unwrap();
    fat.truncate_path("A.BIN", 100).unwrap();
    fat.create("B.BIN", false).unwrap();
    fat.write_path("B.BIN", 0, &[0xbb; 512]).unwrap();
    fat.write_path("A.BIN", 512, &[0xcc]).unwrap();
    let entry = fat.find_file("A.BIN").unwrap();
    let mut out = [0];
    fat.read_file_with_hint(&entry, 512, &mut out, &mut hint)
        .unwrap();
    assert_eq!(out, [0xcc]);
}

#[test]
fn a_valid_255_unit_name_can_span_directory_clusters() {
    let mut disk = format(LAYOUTS[0]);
    let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
    let name = "x".repeat(255);
    fat.create(&name, false).unwrap();
    fat.find_file(&name).unwrap();
    assert_eq!(
        names(&mut fat, "/").as_slice(),
        core::slice::from_ref(&name)
    );
    fat.delete_path(&name).unwrap();
    assert!(names(&mut fat, "/").is_empty());
}

#[test]
fn extending_an_existing_directory_does_not_leave_an_earlier_end_marker() {
    let layout = LAYOUTS[0];
    let mut disk = format(layout);
    {
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        for i in 0..15 {
            fat.create(&alloc::format!("F{i:07}"), false).unwrap();
        }
        fat.flush().unwrap();
    }
    // A valid noncontiguous directory chain with spare capacity after EOF.
    let spf = (DATA_CLUSTERS + 2).div_ceil(128);
    for copy in 0..2 {
        let base =
            PARTITION_START * 512 + (layout.reserved_sectors as u32 + copy * spf) as u64 * 512;
        disk.poke(base + 2 * 4, &4u32.to_le_bytes());
        disk.poke(base + 4 * 4, &0x0fff_ffffu32.to_le_bytes());
    }
    let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
    fat.create("newfile", false).unwrap();
    fat.find_file("newfile").unwrap();
}

#[test]
fn deletion_rejects_a_bad_cluster_marker_instead_of_writing_outside_the_volume() {
    let layout = LAYOUTS[0];
    let mut disk = format(layout);
    let first = {
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        fat.create("A.BIN", false).unwrap();
        let first = fat.write_path("A.BIN", 0, &[0xaa; 100]).unwrap().1;
        fat.flush().unwrap();
        first
    };
    let spf = (DATA_CLUSTERS + 2).div_ceil(128);
    for copy in 0..2 {
        let base =
            PARTITION_START * 512 + (layout.reserved_sectors as u32 + copy * spf) as u64 * 512;
        disk.poke(base + first as u64 * 4, &0x0fff_fff7u32.to_le_bytes());
    }
    {
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        assert!(matches!(
            fat.delete_path("A.BIN"),
            Err(FatError::InvalidCluster)
        ));
        assert_eq!(fat.find_file("A.BIN").unwrap().first_cluster(), first);
    }
    let volume_end =
        PARTITION_START + layout.reserved_sectors as u64 + 2 * spf as u64 + DATA_CLUSTERS as u64;
    assert!(
        disk.blocks.keys().all(|lba| *lba < volume_end),
        "out-of-volume writes: {:?}",
        disk.blocks
            .keys()
            .filter(|lba| **lba >= volume_end)
            .collect::<Vec<_>>()
    );
}

struct FailDataWrite {
    disk: RamDisk,
    fail: bool,
}
impl BlockDevice for FailDataWrite {
    fn info(&self) -> BlockDeviceInfo {
        self.disk.info()
    }
    fn read_blocks(&mut self, lba: u64, count: u32, out: &mut [u8]) -> Result<(), BlockError> {
        self.disk.read_blocks(lba, count, out)
    }
    fn write_blocks(&mut self, lba: u64, count: u32, input: &[u8]) -> Result<(), BlockError> {
        if self.fail && input[0] == 0x77 {
            self.fail = false;
            return Err(BlockError::DeviceError);
        }
        self.disk.write_blocks(lba, count, input)
    }
}

#[test]
fn failed_first_data_write_does_not_leak_an_unreachable_chain() {
    let layout = LAYOUTS[0];
    let mut disk = FailDataWrite {
        disk: format(layout),
        fail: true,
    };
    {
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        fat.create("A.BIN", false).unwrap();
        assert!(matches!(
            fat.write_path("A.BIN", 0, &[0x77; 512]),
            Err(FatError::WriteError)
        ));
        assert_eq!(fat.find_file("A.BIN").unwrap().first_cluster(), 0);
    }
    assert_eq!(fat_value(&disk.disk, layout, 0, 3), 0);
}

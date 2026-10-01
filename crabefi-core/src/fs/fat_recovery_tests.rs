//! Failure injection at every write/flush boundary, including torn transfers.
use super::*;

struct FaultDisk {
    disk: RamDisk,
    read_only: bool,
    writes: usize,
    flushes: usize,
    fail_write: Option<usize>,
    fail_flush: Option<usize>,
    torn: bool,
    persistent: bool,
    durable: Vec<RamDisk>,
}
impl FaultDisk {
    fn new(disk: RamDisk) -> Self {
        Self {
            disk,
            read_only: false,
            writes: 0,
            flushes: 0,
            fail_write: None,
            fail_flush: None,
            torn: false,
            persistent: false,
            durable: Vec::new(),
        }
    }
}
impl BlockDevice for FaultDisk {
    fn info(&self) -> BlockDeviceInfo {
        BlockDeviceInfo {
            read_only: self.read_only,
            ..self.disk.info()
        }
    }
    fn read_blocks(&mut self, lba: u64, count: u32, output: &mut [u8]) -> Result<(), BlockError> {
        self.disk.read_blocks(lba, count, output)
    }
    fn write_blocks(&mut self, lba: u64, count: u32, input: &[u8]) -> Result<(), BlockError> {
        self.writes += 1;
        if self.read_only {
            return Err(BlockError::WriteProtected);
        }
        if self
            .fail_write
            .is_some_and(|nth| self.writes == nth || self.persistent && self.writes >= nth)
        {
            if self.torn {
                self.disk
                    .poke(lba * self.disk.block_size as u64, &input[..input.len() / 2]);
            }
            return Err(BlockError::DeviceError);
        }
        self.disk.write_blocks(lba, count, input)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        self.flushes += 1;
        if self
            .fail_flush
            .is_some_and(|nth| self.flushes == nth || self.persistent && self.flushes >= nth)
        {
            return Err(BlockError::DeviceError);
        }
        self.durable.push(self.disk.clone());
        Ok(())
    }
}

const ORIGINAL: &str = "existing long name.bin";
#[derive(Clone, Copy, Debug)]
enum Operation {
    Grow,
    Truncate,
    Delete,
    Create,
}
fn operation(fat: &mut FatFilesystem, operation: Operation) -> Result<(), FatError> {
    match operation {
        Operation::Grow => fat.write_path(ORIGINAL, 1600, &[0xbb; 5000]).map(|_| ()),
        Operation::Truncate => fat.truncate_path(ORIGINAL, 100),
        Operation::Delete => fat.delete_path(ORIGINAL),
        Operation::Create => fat.create(&"x".repeat(255), true).map(|_| ()),
    }
}

#[test]
fn metadata_recovery_at_every_io_boundary() {
    let mut initial = format(LAYOUTS[0]);
    let original;
    let free;
    {
        let mut fat = FatFilesystem::new(&mut initial, PARTITION_START).unwrap();
        fat.create(ORIGINAL, false).unwrap();
        fat.write_path(ORIGINAL, 0, &[0xaa; 1000]).unwrap();
        fat.create("B.BIN", false).unwrap();
        fat.write_path("B.BIN", 0, &[0xcc; 100]).unwrap();
        fat.flush().unwrap();
        original = fat.find_file(ORIGINAL).unwrap();
        free = fat.free_space().unwrap();
    }
    for op in [
        Operation::Grow,
        Operation::Truncate,
        Operation::Delete,
        Operation::Create,
    ] {
        let mut baseline = FaultDisk::new(initial.clone());
        operation(
            &mut FatFilesystem::new(&mut baseline, PARTITION_START).unwrap(),
            op,
        )
        .unwrap();
        // Failed calls may perform recovery I/O. Only inject once, then verify
        // that a recoverable error restores pointers and staged allocation.
        for (write, count) in [(true, baseline.writes), (false, baseline.flushes)] {
            for nth in 1..=count {
                for torn in [false, true] {
                    let mut disk = FaultDisk::new(initial.clone());
                    if write {
                        disk.fail_write = Some(nth);
                    } else {
                        disk.fail_flush = Some(nth);
                    }
                    disk.torn = torn;
                    let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
                    let result = operation(&mut fat, op);
                    assert!(
                        result.is_err(),
                        "{op:?}, write={write}, nth={nth}, torn={torn}"
                    );
                    if fat.volume_state().failed() {
                        assert!(fat.is_read_only());
                        assert!(
                            fat.get_directory_entry_at_position(fat.root_cluster(), 0)
                                .is_err()
                        );
                        assert!(fat.open_file(ORIGINAL).is_err());
                        assert!(fat.flush().is_err());
                    } else {
                        let restored = fat.find_file(ORIGINAL).unwrap();
                        assert_eq!(
                            restored.first_cluster(),
                            original.first_cluster(),
                            "{op:?}, {nth}"
                        );
                        assert_eq!(restored.file_size(), original.file_size(), "{op:?}, {nth}");
                        assert_eq!(
                            fat.free_space().unwrap(),
                            free,
                            "{op:?}, write={write}, nth={nth}, torn={torn}"
                        );
                        assert_eq!(read_all(&mut fat, "B.BIN"), [0xcc; 100]);
                        if matches!(op, Operation::Create) {
                            assert!(matches!(
                                fat.find_file(&"x".repeat(255)),
                                Err(FatError::NotFound)
                            ));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn flush_failure_only_poisons_pending_mutations() {
    let mut initial = format(LAYOUTS[0]);
    {
        let mut fat = FatFilesystem::new(&mut initial, PARTITION_START).unwrap();
        fat.create(ORIGINAL, false).unwrap();
        fat.write_path(ORIGINAL, 0, &[0xaa; 1000]).unwrap();
        fat.flush().unwrap();
    }
    let mut baseline = FaultDisk::new(initial.clone());
    {
        let mut fat = FatFilesystem::new(&mut baseline, PARTITION_START).unwrap();
        let mut file = fat.open_file(ORIGINAL).unwrap();
        fat.set_attributes(&mut file, 0x20).unwrap();
    }
    for (read_only, pending) in [(false, false), (true, false), (false, true)] {
        let mut disk = FaultDisk::new(initial.clone());
        disk.read_only = read_only;
        // Mutation setup also flushes; fail the explicit flush after it.
        disk.fail_flush = Some(if pending { baseline.flushes + 1 } else { 1 });
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        if pending {
            let mut file = fat.open_file(ORIGINAL).unwrap();
            fat.set_attributes(&mut file, 0x20).unwrap();
        }
        if read_only {
            fat.flush().unwrap();
        } else {
            assert!(matches!(fat.flush(), Err(FatError::WriteError)));
        }
        assert_eq!(fat.volume_state().failed(), pending);
        if !pending {
            assert_eq!(read_all(&mut fat, ORIGINAL), [0xaa; 1000]);
            fat.flush().unwrap();
        }
    }
}

#[test]
fn pending_writes_are_flushed_after_media_becomes_read_only() {
    let mut disk = FaultDisk::new(format(LAYOUTS[0]));
    let (geometry, state) = {
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        fat.create("A.BIN", false).unwrap();
        fat.write_path("A.BIN", 0, &[0xaa]).unwrap();
        (fat.geometry(), fat.volume_state())
    };
    let flushes = disk.flushes;
    disk.read_only = true;
    let blocks = disk.info().num_blocks - PARTITION_START;
    {
        let mut fat = FatFilesystem::from_geometry_in_partition(
            &mut disk,
            PARTITION_START,
            blocks,
            geometry,
            state,
        )
        .unwrap();
        // Sync accepted writes even though clean-bit finalization now fails.
        assert!(fat.flush().is_err());
        assert!(fat.volume_state().failed());
    }
    assert!(disk.flushes > flushes);
    // Read-only remount must come from the dirty bit, not device protection.
    disk.read_only = false;
    let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
    assert!(fat.is_read_only());
    assert_eq!(read_all(&mut fat, "A.BIN"), [0xaa]);
}

/// Let the linking write reach media, then fail either its rollback write or
/// the durability barrier preceding allocation cleanup. Later I/O works: this
/// catches cleanup that continues after poisoning rather than relying on a
/// permanently broken device to protect reachable clusters.
struct FailedLinkDisk {
    disk: RamDisk,
    phase: u8,
    fail_recovery_flush: bool,
    writes_after_failure: usize,
    flushes_after_failure: usize,
}
impl BlockDevice for FailedLinkDisk {
    fn info(&self) -> BlockDeviceInfo {
        self.disk.info()
    }
    fn read_blocks(&mut self, lba: u64, count: u32, out: &mut [u8]) -> Result<(), BlockError> {
        self.disk.read_blocks(lba, count, out)
    }
    fn write_blocks(&mut self, lba: u64, count: u32, input: &[u8]) -> Result<(), BlockError> {
        if self.phase == 3 {
            self.writes_after_failure += 1;
        }
        if lba == PARTITION_START + 32 {
            let root = u32::from_le_bytes(input[8..12].try_into().unwrap()) & 0x0fff_ffff;
            if self.phase == 0 && root == 3 {
                self.disk.write_blocks(lba, count, input)?;
                self.phase = 1;
                return Err(BlockError::DeviceError);
            }
            if self.phase == 1 {
                self.phase = if self.fail_recovery_flush { 2 } else { 3 };
                if !self.fail_recovery_flush {
                    return Err(BlockError::DeviceError);
                }
            }
        }
        self.disk.write_blocks(lba, count, input)
    }
    fn flush(&mut self) -> Result<(), BlockError> {
        if self.phase == 3 {
            self.flushes_after_failure += 1;
        }
        if self.phase == 2 {
            self.phase = 3;
            return Err(BlockError::DeviceError);
        }
        Ok(())
    }
}

#[test]
fn uncertain_directory_link_never_frees_its_target_or_continues_writing() {
    let mut initial = format(LAYOUTS[0]);
    {
        let mut fat = FatFilesystem::new(&mut initial, PARTITION_START).unwrap();
        for i in 0..16 {
            fat.create(&alloc::format!("F{i:07}"), false).unwrap();
        }
        fat.flush().unwrap();
    }
    for fail_recovery_flush in [false, true] {
        let mut disk = FailedLinkDisk {
            disk: initial.clone(),
            phase: 0,
            fail_recovery_flush,
            writes_after_failure: 0,
            flushes_after_failure: 0,
        };
        {
            let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
            assert!(fat.create("NEW", false).is_err());
            assert!(fat.volume_state().failed());
            assert!(fat.create("LATER", false).is_err());
            assert!(fat.flush().is_err());
        }
        assert_eq!(disk.phase, 3);
        assert_eq!(disk.writes_after_failure, 0);
        assert_eq!(disk.flushes_after_failure, 1);
        assert_ne!(fat_value(&disk.disk, LAYOUTS[0], 0, 3), 0);
        if !fail_recovery_flush {
            assert_eq!(fat_value(&disk.disk, LAYOUTS[0], 0, 2), 3);
        }
    }
}

#[test]
fn failed_recovery_poisoning_survives_a_fresh_mount() {
    let mut initial = format(LAYOUTS[0]);
    {
        let mut fat = FatFilesystem::new(&mut initial, PARTITION_START).unwrap();
        fat.create(ORIGINAL, false).unwrap();
        fat.write_path(ORIGINAL, 0, &[0xaa; 1000]).unwrap();
        fat.flush().unwrap();
    }
    let mut baseline = FaultDisk::new(initial.clone());
    operation(
        &mut FatFilesystem::new(&mut baseline, PARTITION_START).unwrap(),
        Operation::Grow,
    )
    .unwrap();
    for (write, nth) in [(true, baseline.writes), (false, baseline.flushes)] {
        let mut disk = FaultDisk::new(initial.clone());
        disk.persistent = true;
        disk.torn = true;
        if write {
            disk.fail_write = Some(nth);
        } else {
            disk.fail_flush = Some(nth);
        }
        {
            let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
            assert!(operation(&mut fat, Operation::Grow).is_err());
            assert!(fat.volume_state().failed());
            assert!(fat.open_file(ORIGINAL).is_err());
            assert!(fat.flush().is_err());
        }
        disk.fail_write = None;
        disk.fail_flush = None;
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        assert!(fat.is_read_only());
        assert!(matches!(
            fat.create("NEW.BIN", false),
            Err(FatError::ReadOnly)
        ));
    }
}

#[test]
fn growth_is_initialized_before_its_size_is_published() {
    let mut disk = FaultDisk::new(format(LAYOUTS[0]));
    {
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        fat.create("A.BIN", false).unwrap();
        fat.write_path("A.BIN", 0, &[0xaa; 1000]).unwrap();
        fat.flush().unwrap();
    }
    disk.durable.clear();
    {
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        fat.write_path("A.BIN", 1600, &[0xbb; 5000]).unwrap();
    }
    for mut snapshot in disk.durable {
        let mut fat = FatFilesystem::new(&mut snapshot, PARTITION_START).unwrap();
        let data = read_all(&mut fat, "A.BIN");
        assert_eq!(&data[..1000], &[0xaa; 1000]);
        if data.len() > 1000 {
            assert_eq!(data.len(), 6600);
            assert!(data[1000..1600].iter().all(|byte| *byte == 0));
            assert_eq!(&data[1600..], &[0xbb; 5000]);
        }
    }
}

#[test]
fn failed_overwrite_reports_only_completed_transfers() {
    let mut disk = FaultDisk::new(format(LAYOUTS[1]));
    {
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        fat.create("A.BIN", false).unwrap();
        fat.write_path("A.BIN", 0, &[0xaa; 8192]).unwrap();
        fat.flush().unwrap();
    }
    // Reuse a dirty mount state so the two payload transfers are the next
    // writes (the file already has the archive attribute).
    let (mut file, state) = {
        let mut fat = FatFilesystem::new(&mut disk, PARTITION_START).unwrap();
        let mut file = fat.open_file("A.BIN").unwrap();
        fat.write_file(&mut file, 0, &[0xaa; 1]).unwrap();
        (file, fat.volume_state())
    };
    disk.writes = 0;
    disk.fail_write = Some(2);
    let geometry = FatFilesystem::new(&mut disk, PARTITION_START)
        .unwrap()
        .geometry();
    let blocks = disk.info().num_blocks - PARTITION_START;
    let mut fat = FatFilesystem::from_geometry_in_partition(
        &mut disk,
        PARTITION_START,
        blocks,
        geometry,
        state,
    )
    .unwrap();
    let error = fat.write_file(&mut file, 0, &[0xbb; 8192]).unwrap_err();
    // LAYOUTS[1] starts midway through a 1 KiB block: the partial head
    // succeeds, then the aligned middle transfer fails.
    assert_eq!(error.written, 512);
    let data = read_all(&mut fat, "A.BIN");
    assert_eq!(&data[..512], &[0xbb; 512]);
    assert_eq!(&data[512..], &[0xaa; 7680]);
}

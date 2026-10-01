use super::*;
use crate::drivers::block::BlockDeviceInfo;
use alloc::vec;
use alloc::vec::Vec;

struct RamDisk {
    info: BlockDeviceInfo,
    data: Vec<u8>,
    writes: usize,
    fail_write: Option<usize>,
}

impl RamDisk {
    fn new(block_size: u32) -> Self {
        Self {
            info: BlockDeviceInfo {
                num_blocks: 4,
                block_size,
                media_id: 0,
                removable: false,
                read_only: false,
            },
            data: vec![0x7b; block_size as usize * 4],
            writes: 0,
            fail_write: None,
        }
    }
}

impl BlockDevice for RamDisk {
    fn info(&self) -> BlockDeviceInfo {
        self.info
    }

    fn read_blocks(&mut self, lba: u64, count: u32, output: &mut [u8]) -> Result<(), BlockError> {
        self.validate_read(lba, count, output)?;
        let start = lba as usize * self.info.block_size as usize;
        let len = count as usize * self.info.block_size as usize;
        output[..len].copy_from_slice(&self.data[start..start + len]);
        Ok(())
    }

    fn write_blocks(&mut self, lba: u64, count: u32, input: &[u8]) -> Result<(), BlockError> {
        self.validate_io(lba, count, input)?;
        if self.info.read_only {
            return Err(BlockError::WriteProtected);
        }
        let start = lba as usize * self.info.block_size as usize;
        let len = count as usize * self.info.block_size as usize;
        self.writes += 1;
        if self.fail_write == Some(self.writes) {
            // A failed call can alter bytes without completing the transfer.
            self.data[start] = input[0];
            return Err(BlockError::DeviceError);
        }
        self.data[start..start + len].copy_from_slice(&input[..len]);
        Ok(())
    }
}

#[test]
fn partial_and_bulk_writes_preserve_neighboring_bytes() {
    for block_size in [512, 4096] {
        let mut disk = RamDisk::new(block_size);
        let range = BlockRange::new(&disk, 1, 2).unwrap();
        let input = vec![0xa1; block_size as usize + 7];
        assert_eq!(
            range.write_with_progress(&mut disk, 3, &input).unwrap(),
            input.len()
        );
        let mut output = vec![0; input.len()];
        range.read(&mut disk, 3, &mut output).unwrap();
        assert_eq!(output, input);
        let start = block_size as usize + 3;
        assert!(disk.data[..start].iter().all(|byte| *byte == 0x7b));
        assert!(
            disk.data[start + input.len()..]
                .iter()
                .all(|byte| *byte == 0x7b)
        );
    }
}

#[test]
fn range_and_live_geometry_are_checked_before_io() {
    let mut disk = RamDisk::new(512);
    assert!(matches!(
        BlockRange::new(&disk, u64::MAX, 2),
        Err(BlockError::OutOfRange)
    ));
    let range = BlockRange::new(&disk, 1, 2).unwrap();
    assert!(matches!(
        range.write(&mut disk, 1023, &[1, 2]),
        Err(BlockError::OutOfRange)
    ));
    disk.info.num_blocks = 2;
    assert!(matches!(
        range.write(&mut disk, 0, &[1]),
        Err(BlockError::OutOfRange)
    ));
    assert_eq!(disk.writes, 0);
    assert!(disk.data.iter().all(|byte| *byte == 0x7b));
}

#[test]
fn protection_does_not_prevent_reads() {
    let mut disk = RamDisk::new(512);
    let range = BlockRange::new(&disk, 1, 2).unwrap();
    disk.info.read_only = true;
    let mut output = [0; 3];
    range.read(&mut disk, 0, &mut output).unwrap();
    assert_eq!(output, [0x7b; 3]);
    assert!(matches!(
        range.write(&mut disk, 0, &[1]),
        Err(BlockError::WriteProtected)
    ));
    assert_eq!(disk.writes, 0);
}

#[test]
fn progress_excludes_the_torn_failed_call() {
    let mut disk = RamDisk::new(512);
    let range = BlockRange::new(&disk, 1, 2).unwrap();
    disk.fail_write = Some(2);
    let error = range
        .write_with_progress(&mut disk, 2, &vec![0xa1; 1022])
        .unwrap_err();
    assert!(matches!(error.error, BlockError::DeviceError));
    assert_eq!(error.completed, 510);
    assert_eq!(disk.data[1024], 0xa1);
    assert_eq!(disk.data[1025], 0x7b);
}

use super::*;
use crate::drivers::block::BlockDeviceInfo;

/// Sparse fixture: a 4 TB disk must not require a 4 TB test allocation.
struct Disk {
    info: BlockDeviceInfo,
    prefix: Vec<u8>,
}

impl BlockDevice for Disk {
    fn info(&self) -> BlockDeviceInfo {
        self.info
    }

    fn read_blocks(&mut self, lba: u64, count: u32, buffer: &mut [u8]) -> Result<(), BlockError> {
        self.validate_read(lba, count, buffer)?;
        let start = lba as usize * self.info.block_size as usize;
        let size = count as usize * self.info.block_size as usize;
        buffer[..size].fill(0);
        if start < self.prefix.len() {
            let copied = size.min(self.prefix.len() - start);
            buffer[..copied].copy_from_slice(&self.prefix[start..start + copied]);
        }
        Ok(())
    }
}

fn disk(block_size: u32, hybrid: bool) -> Disk {
    let unit = if hybrid { 512 } else { block_size as usize };
    let mut prefix = alloc::vec![0; 4 * block_size as usize];
    let header = &mut prefix[unit..unit + 92];
    header[..8].copy_from_slice(b"EFI PART");
    header[8..12].copy_from_slice(&0x10000u32.to_le_bytes());
    header[12..16].copy_from_slice(&92u32.to_le_bytes());
    header[24..32].copy_from_slice(&1u64.to_le_bytes());
    header[72..80].copy_from_slice(&2u64.to_le_bytes());
    header[80..84].copy_from_slice(&4u32.to_le_bytes());
    header[84..88].copy_from_slice(&128u32.to_le_bytes());
    let entry = &mut prefix[2 * unit..2 * unit + 128];
    entry[..16].copy_from_slice(&ESP_TYPE_GUID);
    entry[16..32].fill(0x42);
    entry[32..40].copy_from_slice(&2048u64.to_le_bytes());
    entry[40..48].copy_from_slice(&4095u64.to_le_bytes());
    Disk {
        info: BlockDeviceInfo {
            num_blocks: 4_000_000_000_000 / block_size as u64,
            block_size,
            media_id: 0,
            removable: true,
            read_only: false,
        },
        prefix,
    }
}

#[test]
fn native_gpt_preserves_logical_lbas_and_measurement() {
    for block_size in [512, 1024, 2048, 4096] {
        let mut disk = disk(block_size, false);
        let header = read_gpt_header(&mut disk).unwrap();
        let partitions = read_partitions(&mut disk, &header).unwrap();
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].first_lba, 2048);
        assert_eq!(partitions[0].last_lba, 4095);
        assert_eq!(partitions[0].size_bytes(), 2048 * block_size as u64);
        let event = build_gpt_measurement_event(&mut disk, &header).unwrap();
        assert_eq!(event.len(), 92 + 8 + 128);
        assert_eq!(&event[92..100], &1u64.to_le_bytes());
        assert_eq!(&event[100..116], &ESP_TYPE_GUID);
        assert_eq!(&event[132..140], &2048u64.to_le_bytes());
    }
}

#[test]
fn hybrid_iso_fallback_translates_only_partition_lbas() {
    let mut disk = disk(2048, true);
    let header = read_gpt_header(&mut disk).unwrap();
    let partitions = read_partitions(&mut disk, &header).unwrap();
    assert_eq!(partitions[0].first_lba, 512);
    assert_eq!(partitions[0].last_lba, 1023);
    let event = build_gpt_measurement_event(&mut disk, &header).unwrap();
    assert_eq!(&event[132..140], &2048u64.to_le_bytes());
}

#[test]
fn native_header_takes_precedence_over_embedded_signature() {
    let mut disk = disk(4096, false);
    disk.prefix[512..520].copy_from_slice(b"EFI PART");
    assert_eq!(find_esp(&mut disk).unwrap().first_lba, 2048);
}

#[test]
fn missing_header_and_unsupported_block_sizes_are_rejected() {
    let mut disk = disk(4096, false);
    disk.prefix.fill(0);
    assert!(read_gpt_header(&mut disk).is_err());
    for block_size in [0, 256, 513, 8192] {
        disk.info.block_size = block_size;
        assert!(read_gpt_header(&mut disk).is_err());
    }
}

fn set_partition_range(disk: &mut Disk, hybrid: bool, first: u64, last: u64) {
    let unit = if hybrid {
        512
    } else {
        disk.info.block_size as usize
    };
    disk.prefix[2 * unit + 32..2 * unit + 40].copy_from_slice(&first.to_le_bytes());
    disk.prefix[2 * unit + 40..2 * unit + 48].copy_from_slice(&last.to_le_bytes());
}

#[test]
fn hybrid_partitions_must_cover_whole_native_blocks() {
    for (first, last) in [(33, 63), (32, 62), (33, 62)] {
        let mut disk = disk(2048, true);
        set_partition_range(&mut disk, true, first, last);
        let header = read_gpt_header(&mut disk).unwrap();
        assert!(matches!(
            read_partitions(&mut disk, &header),
            Err(GptError::InvalidHeader)
        ));
        assert!(matches!(
            build_gpt_measurement_event(&mut disk, &header),
            Err(GptError::InvalidHeader)
        ));
    }
    let mut disk = disk(2048, true);
    set_partition_range(&mut disk, true, 32, 63);
    let header = read_gpt_header(&mut disk).unwrap();
    let partitions = read_partitions(&mut disk, &header).unwrap();
    assert_eq!((partitions[0].first_lba, partitions[0].last_lba), (8, 15));
}

#[test]
fn invalid_partition_ranges_are_rejected_for_discovery_and_measurement() {
    for (block_size, hybrid) in [(512, false), (4096, false), (2048, true)] {
        let mut disk = disk(block_size, hybrid);
        let header = read_gpt_header(&mut disk).unwrap();
        let unit = if hybrid { 512 } else { block_size as u64 };
        let end = disk.info.num_blocks * block_size as u64 / unit;
        for (first, last) in [
            (4096, 2048),                               // Reversed range.
            (2048, u64::MAX),                           // Inclusive end overflows.
            (u64::MAX / unit + 1, u64::MAX / unit + 2), // Byte offset overflows.
            (2048, end + block_size as u64 / unit - 1), // One block beyond media.
        ] {
            set_partition_range(&mut disk, hybrid, first, last);
            assert!(matches!(
                read_partitions(&mut disk, &header),
                Err(GptError::InvalidHeader)
            ));
            assert!(matches!(
                build_gpt_measurement_event(&mut disk, &header),
                Err(GptError::InvalidHeader)
            ));
        }
        // The inclusive last block of the disk is valid.
        set_partition_range(&mut disk, hybrid, 2048, end - 1);
        let partitions = read_partitions(&mut disk, &header).unwrap();
        assert_eq!(partitions[0].last_lba, disk.info.num_blocks - 1);
        assert!(build_gpt_measurement_event(&mut disk, &header).is_ok());
    }
}

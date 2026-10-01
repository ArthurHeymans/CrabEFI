//! Fixed-root FAT12/16 lookup shares record decoding with FAT32 mutation.

use super::*;

struct CountReads<'a> {
    disk: RamDisk,
    reads: &'a core::cell::Cell<usize>,
}
impl BlockDevice for CountReads<'_> {
    fn info(&self) -> BlockDeviceInfo {
        self.disk.info()
    }
    fn read_blocks(&mut self, lba: u64, count: u32, output: &mut [u8]) -> Result<(), BlockError> {
        self.reads.set(self.reads.get() + 1);
        self.disk.read_blocks(lba, count, output)
    }
}

#[test]
fn fixed_root_long_names_and_record_locations_on_all_block_sizes() {
    let name = alloc::format!("{}.txt", "é".repeat(251));
    let units: Vec<_> = name.encode_utf16().collect();
    let short = *b"LONGNA~1TXT";
    let checksum = LfnEntry::short_name_checksum(&short);
    let count = units.len().div_ceil(13);

    for (fat_type, sectors, fat_sectors) in [
        (FatType::Fat12, 4000u16, 12u16),
        (FatType::Fat16, 65_520, 256),
    ] {
        for block_size in [512, 1024, 2048, 4096] {
            let mut disk = RamDisk {
                block_size,
                blocks: BTreeMap::new(),
            };
            let base = PARTITION_START * block_size as u64;
            let root = (1 + 2 * fat_sectors as u64) * 512;
            let data = root + 1024;
            let mut boot = [0; 64];
            boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
            boot[11..13].copy_from_slice(&512u16.to_le_bytes());
            boot[13] = 1;
            boot[14..16].copy_from_slice(&1u16.to_le_bytes());
            boot[16] = 2;
            boot[17..19].copy_from_slice(&32u16.to_le_bytes());
            boot[19..21].copy_from_slice(&sectors.to_le_bytes());
            boot[21] = 0xf8;
            boot[22..24].copy_from_slice(&fat_sectors.to_le_bytes());
            disk.poke(base, &boot);
            disk.poke(base + 510, &[0x55, 0xaa]);
            let reserved: &[u8] = if fat_type == FatType::Fat12 {
                &[0xf8, 0xff, 0xff, 0xff, 0x0f]
            } else {
                &[0xf8, 0xff, 0xff, 0xff, 0xff, 0xff]
            };
            for copy in 0..2 {
                let fat_base = base + (1 + copy * fat_sectors as u64) * 512;
                disk.poke(fat_base, reserved);
                // Nonzero entries on either side of a chunk boundary, including
                // the packed FAT12 entry spanning bytes 4095 and 4096.
                let (offset, entries): (u64, &[u8]) = if fat_type == FatType::Fat12 {
                    (4095, &[0x34, 0x12, 0x00])
                } else {
                    (4094, &[0x34, 0x12, 0x78, 0x56])
                };
                disk.poke(fat_base + offset, entries);
            }
            for index in 0..count {
                let sequence = count - index;
                let first = (sequence - 1) * 13;
                let chunk = core::array::from_fn(|slot| match (first + slot).cmp(&units.len()) {
                    core::cmp::Ordering::Less => units[first + slot],
                    core::cmp::Ordering::Equal => 0,
                    core::cmp::Ordering::Greater => 0xffff,
                });
                let lfn = LfnEntry::new(sequence as u8, index == 0, checksum, &chunk);
                disk.poke(base + root + index as u64 * 32, lfn.as_bytes());
            }
            let entry = DirectoryEntry::new(short, ATTR_READ_ONLY, 2, 3);
            disk.poke(base + root + count as u64 * 32, entry.as_bytes());
            disk.poke(base + data, &[1, 2, 3]);

            let blocks = sectors as u64 * 512 / block_size as u64;
            let reads = core::cell::Cell::new(0);
            let mut disk = CountReads {
                disk,
                reads: &reads,
            };
            let mut fat = FatFilesystem::new_partition(&mut disk, PARTITION_START, blocks).unwrap();
            assert_eq!(fat.fat_type(), fat_type);
            assert!(fat.is_read_only());
            let record = fat.find_record_in_directory(0, &name).unwrap();
            assert_eq!(record.first_offset, root);
            assert_eq!(record.short_offset, root + count as u64 * 32);
            assert_eq!(fat.find_file("LONGNA~1.TXT").unwrap().first_cluster(), 2);
            assert_eq!(
                fat.get_directory_entry_at_position(0, 0)
                    .unwrap()
                    .unwrap()
                    .1,
                name.as_str()
            );
            let mut output = [0; 3];
            assert_eq!(fat.read_file(&record.entry, 0, &mut output).unwrap(), 3);
            assert_eq!(output, [1, 2, 3]);
            let before = reads.get();
            let expected_free = (sectors as u64 - data / 512 - 3) * 512;
            assert_eq!(fat.free_space().unwrap(), expected_free);
            assert!(
                reads.get() - before < 300,
                "free-space scan must read chunks, not individual entries"
            );
            let cached = reads.get();
            assert_eq!(fat.free_space().unwrap(), expected_free);
            assert_eq!(reads.get(), cached);
            assert!(matches!(fat.create("new", false), Err(FatError::ReadOnly)));
        }
    }
}

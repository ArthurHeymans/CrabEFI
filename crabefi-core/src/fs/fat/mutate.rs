//! FAT32 file and directory mutation.
//!
//! Everything here works on byte offsets relative to the partition start and
//! goes through [`FatFilesystem::partition_read`] / [`FatFilesystem::partition_write`],
//! so it does not depend on the device block size matching the FAT sector size.
//! FAT12/16 volumes stay read-only ([`FatError::ReadOnly`]).
//!
//! Invariant relied upon by growing writes: bytes past a file's size but inside
//! its last cluster are zero. New clusters are zeroed when allocated and
//! [`FatFilesystem::truncate_path`] zeroes the tail of the last kept cluster.

use core::fmt::Write;
use core::ops::ControlFlow;

use zerocopy::little_endian::U32;
use zerocopy::{FromBytes, FromZeros, IntoBytes};

use super::{
    ATTR_DIRECTORY, DirectoryEntry, FatError, FatFilesystem, FatType, LfnEntry, MAX_BLOCK_SIZE,
    MAX_LFN_LENGTH,
};

/// Size of one directory record.
const SLOT: usize = core::mem::size_of::<DirectoryEntry>();
/// FAT32 end-of-chain marker written by this driver.
const END_OF_CHAIN: u32 = 0x0fff_ffff;
/// First FAT32 value that marks the end of a chain.
const END_OF_CHAIN_MIN: u32 = 0x0fff_fff8;
/// Deleted-entry marker for the first byte of a directory record.
const DELETED: u8 = 0xe5;

/// Location of a directory record found by [`FatFilesystem::find_record_in_directory`].
struct Record {
    entry: DirectoryEntry,
    /// Partition byte offset of the short (8.3) record.
    short_offset: u64,
    /// Partition byte offset of the first record of the run (first LFN record,
    /// or the short record when the entry has no long name).
    first_offset: u64,
}

impl FatFilesystem<'_> {
    fn require_fat32(&self) -> Result<(), FatError> {
        if self.fat_type == FatType::Fat32 {
            Ok(())
        } else {
            Err(FatError::ReadOnly)
        }
    }

    fn cluster_size(&self) -> usize {
        self.sectors_per_cluster as usize * self.bytes_per_sector as usize
    }

    /// Read `output.len()` bytes at a partition byte offset.
    fn partition_read(&mut self, byte_offset: u64, output: &mut [u8]) -> Result<(), FatError> {
        let block_size = self.device_block_size as usize;
        let mut block = [0u8; MAX_BLOCK_SIZE];
        let mut done = 0;
        while done < output.len() {
            let position = byte_offset + done as u64;
            let lba = self.partition_start + position / block_size as u64;
            let within = position as usize % block_size;
            self.device
                .read_block(lba, &mut block[..block_size])
                .map_err(|_| FatError::ReadError)?;
            let count = (block_size - within).min(output.len() - done);
            output[done..done + count].copy_from_slice(&block[within..within + count]);
            done += count;
        }
        Ok(())
    }

    /// Write `input` at a partition byte offset.
    ///
    /// Whole blocks are written with a single multi-block call; partial head
    /// and tail blocks are read-modify-written.
    fn partition_write(&mut self, byte_offset: u64, input: &[u8]) -> Result<(), FatError> {
        self.require_fat32()?;
        let block_size = self.device_block_size as usize;
        let mut block = [0u8; MAX_BLOCK_SIZE];
        let mut done = 0;
        while done < input.len() {
            let position = byte_offset + done as u64;
            let lba = self.partition_start + position / block_size as u64;
            let within = position as usize % block_size;
            let remaining = input.len() - done;
            if within == 0 && remaining >= block_size {
                let blocks = remaining / block_size;
                let len = blocks * block_size;
                self.device
                    .write_blocks(lba, blocks as u32, &input[done..done + len])
                    .map_err(|_| FatError::WriteError)?;
                done += len;
                continue;
            }
            self.device
                .read_block(lba, &mut block[..block_size])
                .map_err(|_| FatError::ReadError)?;
            let count = (block_size - within).min(remaining);
            block[within..within + count].copy_from_slice(&input[done..done + count]);
            self.device
                .write_block(lba, &block[..block_size])
                .map_err(|_| FatError::WriteError)?;
            done += count;
        }
        // The FAT block cache is not written through.
        self.fat_block_cached = u64::MAX;
        Ok(())
    }

    fn cluster_byte_offset(&self, cluster: u32) -> Result<u64, FatError> {
        if cluster < 2 || cluster - 2 >= self.data_clusters {
            return Err(FatError::InvalidCluster);
        }
        Ok(self.data_start as u64 * self.bytes_per_sector as u64
            + (cluster - 2) as u64 * self.cluster_size() as u64)
    }

    /// Partition byte offset of a cluster's entry in FAT copy `copy`.
    fn fat32_entry_offset(&self, copy: u32, cluster: u32) -> u64 {
        (self.fat_start + copy * self.sectors_per_fat) as u64 * self.bytes_per_sector as u64
            + cluster as u64 * 4
    }

    fn fat32_value(&mut self, cluster: u32) -> Result<u32, FatError> {
        let mut value = U32::ZERO;
        self.partition_read(self.fat32_entry_offset(0, cluster), value.as_mut_bytes())?;
        Ok(value.get() & 0x0fff_ffff)
    }

    /// Set a FAT32 entry in every FAT copy, preserving the reserved top bits.
    ///
    /// On a failed write the copies already updated are restored.
    fn set_fat32_value(&mut self, cluster: u32, value: u32) -> Result<(), FatError> {
        self.require_fat32()?;
        let mut old = heapless::Vec::<(u64, u32), 2>::new();
        for copy in 0..self.num_fats as u32 {
            let offset = self.fat32_entry_offset(copy, cluster);
            let mut value = U32::ZERO;
            self.partition_read(offset, value.as_mut_bytes())?;
            let _ = old.push((offset, value.get()));
        }

        for (index, &(offset, previous)) in old.iter().enumerate() {
            let new = U32::new((previous & 0xf000_0000) | (value & 0x0fff_ffff));
            if let Err(error) = self.partition_write(offset, new.as_bytes()) {
                for &(offset, previous) in &old[..index] {
                    let _ = self.partition_write(offset, U32::new(previous).as_bytes());
                }
                return Err(error);
            }
        }
        if value == 0 {
            self.alloc_hint = self.alloc_hint.min(cluster);
        }
        Ok(())
    }

    /// Zero a whole cluster using a block-sized scratch buffer.
    ///
    /// Deliberately avoids a max-cluster-sized (64 KiB) stack buffer: this
    /// firmware runs on a small fixed stack and these helpers nest.
    fn zero_cluster(&mut self, cluster: u32) -> Result<(), FatError> {
        let cluster_size = self.cluster_size();
        let base = self.cluster_byte_offset(cluster)?;
        let zero = [0u8; MAX_BLOCK_SIZE];
        (0..cluster_size)
            .step_by(MAX_BLOCK_SIZE)
            .try_for_each(|done| {
                let count = MAX_BLOCK_SIZE.min(cluster_size - done);
                self.partition_write(base + done as u64, &zero[..count])
            })
    }

    /// Allocate a zeroed cluster and mark it end-of-chain.
    fn allocate_cluster(&mut self) -> Result<u32, FatError> {
        self.require_fat32()?;
        let entries_per_chunk = MAX_BLOCK_SIZE / 4;
        let cluster_limit = self.data_clusters + 2;
        let mut chunk = [0u8; MAX_BLOCK_SIZE];

        let start = self.alloc_hint - self.alloc_hint % entries_per_chunk as u32;

        for first in (start..cluster_limit).step_by(entries_per_chunk) {
            let entries = (cluster_limit - first).min(entries_per_chunk as u32) as usize;
            self.partition_read(self.fat32_entry_offset(0, first), &mut chunk[..entries * 4])?;
            let table =
                <[U32]>::ref_from_bytes(&chunk[..entries * 4]).map_err(|_| FatError::ReadError)?;
            let free = table
                .iter()
                .enumerate()
                .map(|(index, value)| (first + index as u32, value.get() & 0x0fff_ffff))
                .find(|&(cluster, value)| cluster >= self.alloc_hint.max(2) && value == 0);
            if let Some((cluster, _)) = free {
                self.zero_cluster(cluster)?;
                self.set_fat32_value(cluster, END_OF_CHAIN)?;
                self.alloc_hint = cluster + 1;
                return Ok(cluster);
            }
        }
        Err(FatError::NoSpace)
    }

    /// Free a cluster chain. The walk is bounded so a cyclic (corrupt) chain
    /// cannot hang the firmware.
    fn free_chain(&mut self, first: u32) -> Result<(), FatError> {
        let mut cluster = first;
        for _ in 0..=self.data_clusters {
            if cluster < 2 {
                return Ok(());
            }
            let next = self.fat32_value(cluster)?;
            self.set_fat32_value(cluster, 0)?;
            if !(2..END_OF_CHAIN_MIN).contains(&next) {
                return Ok(());
            }
            cluster = next;
        }
        Err(FatError::InvalidCluster)
    }

    /// Allocate a cluster and link it after `last`.
    fn append_cluster(&mut self, last: u32) -> Result<u32, FatError> {
        let new = self.allocate_cluster()?;
        if let Err(error) = self.set_fat32_value(last, new) {
            let _ = self.set_fat32_value(new, 0);
            return Err(error);
        }
        Ok(new)
    }

    /// Follow a chain to its last cluster, returning it with the chain length.
    fn chain_end(&mut self, first: u32) -> Result<(u32, u32), FatError> {
        let mut cluster = first;
        for length in 1..=self.data_clusters {
            match self.next_cluster(cluster)? {
                Some(next) => cluster = next,
                None => return Ok((cluster, length)),
            }
        }
        Err(FatError::InvalidCluster)
    }

    /// Visit every 32-byte record of a directory in order, with its partition
    /// byte offset.
    ///
    /// `Continue` carries the directory's last cluster.
    fn for_each_slot<T>(
        &mut self,
        directory: u32,
        mut visit: impl FnMut(u64, &DirectoryEntry) -> ControlFlow<T>,
    ) -> Result<ControlFlow<T, u32>, FatError> {
        let cluster_size = self.cluster_size();
        let chunk_size = MAX_BLOCK_SIZE.min(cluster_size);
        let mut data = [0u8; MAX_BLOCK_SIZE];
        let mut cluster = directory;
        for _ in 0..self.data_clusters {
            let base = self.cluster_byte_offset(cluster)?;
            for chunk_start in (0..cluster_size).step_by(chunk_size) {
                self.partition_read(base + chunk_start as u64, &mut data[..chunk_size])?;
                let records = <[DirectoryEntry]>::ref_from_bytes(&data[..chunk_size])
                    .map_err(|_| FatError::ReadError)?;
                for (index, record) in records.iter().enumerate() {
                    let position = base + (chunk_start + index * SLOT) as u64;
                    if let ControlFlow::Break(value) = visit(position, record) {
                        return Ok(ControlFlow::Break(value));
                    }
                }
            }
            match self.next_cluster(cluster)? {
                Some(next) => cluster = next,
                None => return Ok(ControlFlow::Continue(cluster)),
            }
        }
        Err(FatError::InvalidCluster)
    }

    fn find_record_in_directory(&mut self, directory: u32, name: &str) -> Result<Record, FatError> {
        let mut lfn = super::LfnBuffer::new();
        let mut lfn_start = 0;
        let found = self.for_each_slot(directory, |position, entry| {
            if entry.is_end() {
                return ControlFlow::Break(None);
            }
            if entry.is_free() {
                lfn.reset();
                return ControlFlow::Continue(());
            }
            if entry.is_lfn() {
                if !lfn.active {
                    lfn_start = position;
                }
                if let Ok(part) = LfnEntry::read_from_bytes(entry.as_bytes()) {
                    lfn.process_lfn(&part);
                }
                return ControlFlow::Continue(());
            }
            let matched = !entry.is_volume_id() && (lfn.matches(name) || entry.matches_name(name));
            let first_offset = if lfn.active { lfn_start } else { position };
            lfn.reset();
            if matched {
                ControlFlow::Break(Some(Record {
                    entry: *entry,
                    short_offset: position,
                    first_offset,
                }))
            } else {
                ControlFlow::Continue(())
            }
        })?;
        match found {
            ControlFlow::Break(Some(record)) => Ok(record),
            _ => Err(FatError::NotFound),
        }
    }

    /// Split a path into its parent directory cluster and final component.
    fn split_parent<'p>(&mut self, path: &'p str) -> Result<(u32, &'p str), FatError> {
        let path = path.trim_matches(['/', '\\']);
        let (parent, name) = path.rsplit_once(['/', '\\']).unwrap_or(("", path));
        validate_name(name)?;
        Ok((self.resolve_dir_cluster(parent)?, name))
    }

    fn find_record(&mut self, path: &str) -> Result<Record, FatError> {
        let (parent, name) = self.split_parent(path)?;
        self.find_record_in_directory(parent, name)
    }

    fn short_name_exists(&mut self, directory: u32, short: &[u8; 11]) -> Result<bool, FatError> {
        let found = self.for_each_slot(directory, |_, entry| {
            if entry.is_end() {
                ControlFlow::Break(false)
            } else if !entry.is_free() && !entry.is_lfn() && entry.short_name_bytes() == *short {
                ControlFlow::Break(true)
            } else {
                ControlFlow::Continue(())
            }
        })?;
        Ok(matches!(found, ControlFlow::Break(true)))
    }

    /// Pick an unused 8.3 name for `name`.
    ///
    /// Returns it with whether a long-name record is needed to preserve the
    /// exact spelling (any name that is not already an upper-case 8.3 name).
    fn make_short_name(
        &mut self,
        directory: u32,
        name: &str,
    ) -> Result<([u8; 11], bool), FatError> {
        let (stem, extension) = match name.rsplit_once('.') {
            Some((stem, extension)) if !stem.is_empty() => (stem, extension),
            _ => (name, ""),
        };
        let fits = stem.len() <= 8
            && extension.len() <= 3
            && stem
                .bytes()
                .chain(extension.bytes())
                .all(is_short_name_char);
        if fits {
            let short = short_name_bytes(stem.bytes(), extension.bytes());
            if !self.short_name_exists(directory, &short)? {
                return Ok((short, name.bytes().any(|byte| byte.is_ascii_lowercase())));
            }
        }

        // Numeric tail: "LONGNA~1.TXT". Non-ASCII and punctuation characters
        // are dropped from the base; the long-name record keeps the spelling.
        let mut base: heapless::Vec<u8, 8> = stem
            .bytes()
            .filter(u8::is_ascii_alphanumeric)
            .take(8)
            .collect();
        if base.is_empty() {
            let _ = base.push(b'_');
        }
        let extension: heapless::Vec<u8, 3> = extension
            .bytes()
            .map(|byte| if is_short_name_char(byte) { byte } else { b'_' })
            .take(3)
            .collect();
        for number in 1u16..=9999 {
            let mut tail = heapless::String::<5>::new();
            let _ = write!(tail, "~{number}");
            let keep = base.len().min(8 - tail.len());
            let short = short_name_bytes(
                base[..keep].iter().copied().chain(tail.bytes()),
                extension.iter().copied(),
            );
            if !self.short_name_exists(directory, &short)? {
                return Ok((short, true));
            }
        }
        Err(FatError::NoSpace)
    }

    /// Find `count` consecutive free records, growing the directory if needed.
    ///
    /// Returns the partition byte offset of the first record. Records of a run
    /// are written at contiguous byte offsets, so a freshly allocated cluster
    /// is used when no existing run is long enough.
    fn find_free_slots(&mut self, directory: u32, count: usize) -> Result<u64, FatError> {
        let cluster_size = self.cluster_size();
        if count == 0 || count * SLOT > cluster_size {
            return Err(FatError::NoSpace);
        }
        let (mut run_start, mut run_end, mut run_len) = (0u64, 0u64, 0usize);
        let scan = self.for_each_slot(directory, |position, entry| {
            if !entry.is_free() {
                run_len = 0;
                return ControlFlow::Continue(());
            }
            // Records only join a run when adjacent on disk, so a run can
            // continue across clusters that happen to be neighbours.
            if run_len == 0 || position != run_end {
                run_start = position;
                run_len = 0;
            }
            run_len += 1;
            run_end = position + SLOT as u64;
            if run_len == count {
                ControlFlow::Break(run_start)
            } else {
                ControlFlow::Continue(())
            }
        })?;
        match scan {
            ControlFlow::Break(start) => Ok(start),
            ControlFlow::Continue(last) => {
                // Readers stop at the first 0x00 record, so end markers in the
                // old tail must become deleted entries before the directory is
                // extended; otherwise the new cluster would never be reached.
                self.retire_end_markers(last)?;
                let new = self.append_cluster(last)?;
                self.cluster_byte_offset(new)
            }
        }
    }

    /// Turn every 0x00 (end-of-directory) record of one cluster into a deleted record.
    fn retire_end_markers(&mut self, cluster: u32) -> Result<(), FatError> {
        let cluster_size = self.cluster_size();
        let chunk_size = MAX_BLOCK_SIZE.min(cluster_size);
        let base = self.cluster_byte_offset(cluster)?;
        let mut data = [0u8; MAX_BLOCK_SIZE];
        for chunk_start in (0..cluster_size).step_by(chunk_size) {
            self.partition_read(base + chunk_start as u64, &mut data[..chunk_size])?;
            let records = <[DirectoryEntry]>::ref_from_bytes(&data[..chunk_size])
                .map_err(|_| FatError::ReadError)?;
            for (index, record) in records.iter().enumerate() {
                if record.is_end() {
                    let position = base + (chunk_start + index * SLOT) as u64;
                    self.partition_write(position, &[DELETED])?;
                }
            }
        }
        Ok(())
    }

    /// Add a directory record (with a long-name run when needed) for `name`.
    fn insert_entry(
        &mut self,
        directory: u32,
        name: &str,
        attributes: u8,
        first_cluster: u32,
    ) -> Result<(), FatError> {
        if self.find_record_in_directory(directory, name).is_ok() {
            return Err(FatError::AlreadyExists);
        }
        let (short, needs_lfn) = self.make_short_name(directory, name)?;
        let utf16: heapless::Vec<u16, MAX_LFN_LENGTH> = name.encode_utf16().collect();
        let lfn_count = if needs_lfn {
            utf16.len().div_ceil(13)
        } else {
            0
        };
        let start = self.find_free_slots(directory, lfn_count + 1)?;

        let checksum = lfn_checksum(&short);
        for index in 0..lfn_count {
            // Long-name records are stored last-first.
            let sequence = lfn_count - index;
            let first = (sequence - 1) * 13;
            let units: [u16; 13] =
                core::array::from_fn(|slot| match (first + slot).cmp(&utf16.len()) {
                    core::cmp::Ordering::Less => utf16[first + slot],
                    core::cmp::Ordering::Equal => 0,
                    core::cmp::Ordering::Greater => 0xffff,
                });
            let record = LfnEntry::new(sequence as u8, index == 0, checksum, &units);
            self.partition_write(start + (index * SLOT) as u64, record.as_bytes())?;
        }

        let record = DirectoryEntry::new(short, attributes, first_cluster, 0);
        self.partition_write(start + (lfn_count * SLOT) as u64, record.as_bytes())
    }

    /// Create an empty file or directory at `path` and return its record.
    pub fn create(&mut self, path: &str, directory: bool) -> Result<DirectoryEntry, FatError> {
        self.require_fat32()?;
        let (parent, name) = self.split_parent(path)?;
        // Files get their first cluster on the first write.
        let cluster = if directory {
            self.allocate_cluster()?
        } else {
            0
        };
        let result = self
            .init_directory(cluster, parent, directory)
            .and_then(|()| {
                let attributes = if directory { ATTR_DIRECTORY } else { 0 };
                self.insert_entry(parent, name, attributes, cluster)
            })
            .and_then(|()| self.find_record_in_directory(parent, name));
        match result {
            Ok(record) => Ok(record.entry),
            Err(error) => {
                let _ = self.free_chain(cluster);
                Err(error)
            }
        }
    }

    /// Write the `.` and `..` records of a new (already zeroed) directory cluster.
    fn init_directory(
        &mut self,
        cluster: u32,
        parent: u32,
        directory: bool,
    ) -> Result<(), FatError> {
        if !directory {
            return Ok(());
        }
        // Per the FAT specification `..` holds cluster 0 when the parent is the
        // root directory.
        let parent = if parent == self.root_cluster {
            0
        } else {
            parent
        };
        let records = [
            DirectoryEntry::new(*b".          ", ATTR_DIRECTORY, cluster, 0),
            DirectoryEntry::new(*b"..         ", ATTR_DIRECTORY, parent, 0),
        ];
        let offset = self.cluster_byte_offset(cluster)?;
        self.partition_write(offset, records.as_bytes())
    }

    /// Rewrite the first cluster and size of the short record at `offset`.
    fn update_record(
        &mut self,
        offset: u64,
        first_cluster: u32,
        size: u32,
    ) -> Result<(), FatError> {
        let mut record = DirectoryEntry::new_zeroed();
        self.partition_read(offset, record.as_mut_bytes())?;
        record.set_first_cluster(first_cluster);
        record.file_size = size;
        self.partition_write(offset, record.as_bytes())
    }

    /// Make sure a chain starting at `first` (0 for none) holds `required`
    /// clusters, returning its first cluster.
    ///
    /// On failure the chain is restored to its previous length.
    fn ensure_clusters(&mut self, first: u32, required: u32) -> Result<u32, FatError> {
        let created = first < 2;
        let (first, old_last, existing) = if created {
            let first = self.allocate_cluster()?;
            (first, first, 1)
        } else {
            let (last, length) = self.chain_end(first)?;
            (first, last, length)
        };
        let mut last = old_last;
        for _ in existing..required {
            match self.append_cluster(last) {
                Ok(next) => last = next,
                Err(error) => {
                    // Best-effort undo; the allocation failure is what matters.
                    let _ = if created {
                        self.free_chain(first)
                    } else {
                        self.cut_chain_after(old_last)
                    };
                    return Err(error);
                }
            }
        }
        Ok(first)
    }

    /// Make `last` the end of its chain and free everything after it.
    fn cut_chain_after(&mut self, last: u32) -> Result<(), FatError> {
        let tail = self.next_cluster(last)?;
        self.set_fat32_value(last, END_OF_CHAIN)?;
        tail.map_or(Ok(()), |tail| self.free_chain(tail))
    }

    /// Write `input` at `offset` into the file at `path`, extending it as needed.
    ///
    /// # Returns
    /// The file's new size and first cluster.
    pub fn write_path(
        &mut self,
        path: &str,
        offset: u32,
        input: &[u8],
    ) -> Result<(u32, u32), FatError> {
        self.require_fat32()?;
        let Record {
            entry,
            short_offset,
            ..
        } = self.find_record(path)?;
        if entry.is_directory() {
            return Err(FatError::NotAFile);
        }
        if input.is_empty() {
            return Ok((entry.file_size(), entry.first_cluster()));
        }
        let end = u32::try_from(input.len())
            .ok()
            .and_then(|len| offset.checked_add(len))
            .ok_or(FatError::NoSpace)?;
        let cluster_size = self.cluster_size() as u32;
        let first = self.ensure_clusters(entry.first_cluster(), end.div_ceil(cluster_size))?;

        let mut cluster = first;
        for _ in 0..offset / cluster_size {
            cluster = self
                .next_cluster(cluster)?
                .ok_or(FatError::InvalidCluster)?;
        }
        let mut within = (offset % cluster_size) as u64;
        let mut remaining = input;
        while !remaining.is_empty() {
            let count = ((cluster_size as u64 - within) as usize).min(remaining.len());
            let (now, later) = remaining.split_at(count);
            self.partition_write(self.cluster_byte_offset(cluster)? + within, now)?;
            remaining = later;
            within = 0;
            if !remaining.is_empty() {
                cluster = self
                    .next_cluster(cluster)?
                    .ok_or(FatError::InvalidCluster)?;
            }
        }

        let size = entry.file_size().max(end);
        self.update_record(short_offset, first, size)?;
        Ok((size, first))
    }

    /// Shrink the file at `path` to `size` bytes. Growing is not supported here.
    pub fn truncate_path(&mut self, path: &str, size: u32) -> Result<(), FatError> {
        self.require_fat32()?;
        let Record {
            entry,
            short_offset,
            ..
        } = self.find_record(path)?;
        if entry.is_directory() {
            return Err(FatError::NotAFile);
        }
        if size >= entry.file_size() {
            return Ok(());
        }
        let first = entry.first_cluster();
        if size == 0 {
            self.update_record(short_offset, 0, 0)?;
            return self.free_chain(first);
        }

        let cluster_size = self.cluster_size() as u32;
        let mut last = first;
        for _ in 1..size.div_ceil(cluster_size) {
            last = self.next_cluster(last)?.ok_or(FatError::InvalidCluster)?;
        }
        // Keep the "zero past EOF" invariant for later growing writes.
        let used = (size % cluster_size) as usize;
        if used != 0 {
            let zeros = [0u8; MAX_BLOCK_SIZE];
            let tail = cluster_size as usize - used;
            let base = self.cluster_byte_offset(last)? + used as u64;
            (0..tail).step_by(MAX_BLOCK_SIZE).try_for_each(|done| {
                let count = MAX_BLOCK_SIZE.min(tail - done);
                self.partition_write(base + done as u64, &zeros[..count])
            })?;
        }
        self.update_record(short_offset, first, size)?;
        self.cut_chain_after(last)
    }

    /// Delete the file or empty directory at `path`.
    pub fn delete_path(&mut self, path: &str) -> Result<(), FatError> {
        self.require_fat32()?;
        let (parent, name) = self.split_parent(path)?;
        let Record {
            entry,
            short_offset,
            first_offset,
        } = self.find_record_in_directory(parent, name)?;
        if entry.is_directory() {
            let has_children = self.for_each_dir_entry(entry.first_cluster(), |child, _| {
                match child.short_name().as_str() {
                    "." | ".." => ControlFlow::Continue(()),
                    _ => ControlFlow::Break(()),
                }
            })?;
            if has_children.is_break() {
                return Err(FatError::DirectoryNotEmpty);
            }
        }

        // Collect the record run first; the directory is walked through its
        // cluster chain because its clusters need not be adjacent on disk.
        let mut run = heapless::Vec::<u64, { MAX_LFN_LENGTH.div_ceil(13) + 1 }>::new();
        let mut inside = false;
        let _ = self.for_each_slot(parent, |position, _| {
            inside |= position == first_offset;
            if inside && run.push(position).is_err() {
                return ControlFlow::Break(());
            }
            if position == short_offset {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })?;
        if run.last() != Some(&short_offset) {
            return Err(FatError::InvalidCluster);
        }
        run.iter()
            .try_for_each(|&position| self.partition_write(position, &[DELETED]))?;
        self.free_chain(entry.first_cluster())
    }

    /// Commit written data to stable media.
    pub fn flush(&mut self) -> Result<(), FatError> {
        self.device.flush().map_err(|_| FatError::WriteError)
    }
}

/// Reject names the FAT long-name format cannot represent.
///
/// Only BMP characters are accepted: the name lookup and directory listing
/// code compares and converts long names one UTF-16 unit per character.
fn validate_name(name: &str) -> Result<(), FatError> {
    let invalid = name.is_empty()
        || name.chars().count() > MAX_LFN_LENGTH
        || name.chars().any(|c| c.len_utf16() != 1)
        || matches!(name, "." | "..")
        || name.ends_with(['.', ' '])
        || name.chars().any(|c| {
            c.is_control() || matches!(c, '"' | '*' | '/' | ':' | '<' | '>' | '?' | '\\' | '|')
        });
    if invalid {
        Err(FatError::InvalidName)
    } else {
        Ok(())
    }
}

fn is_short_name_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"$%'-_@~`!(){}^#&".contains(&byte)
}

/// Pack an 8.3 name from stem and extension bytes (upper-cased, space padded).
fn short_name_bytes(
    stem: impl Iterator<Item = u8>,
    extension: impl Iterator<Item = u8>,
) -> [u8; 11] {
    let mut short = [b' '; 11];
    for (slot, byte) in short[..8].iter_mut().zip(stem) {
        *slot = byte.to_ascii_uppercase();
    }
    for (slot, byte) in short[8..].iter_mut().zip(extension) {
        *slot = byte.to_ascii_uppercase();
    }
    short
}

fn lfn_checksum(short: &[u8; 11]) -> u8 {
    short
        .iter()
        .fold(0u8, |sum, byte| sum.rotate_right(1).wrapping_add(*byte))
}

//! FAT32 file and directory mutation.
//!
//! Everything here works on byte offsets relative to the partition start and
//! goes through [`FatFilesystem::partition_read`] / [`FatFilesystem::partition_write`],
//! so it does not depend on the device block size matching the FAT sector size.
//! FAT12/16 volumes stay read-only ([`FatError::ReadOnly`]).
//!
//! Growth is staged in an unlinked chain, persisted, then linked and published.
//! Recovery restores directory/FAT pointers before freeing staged allocation.
//! This is not a journal: crashes or sector corruption can require filesystem
//! repair. Failed recovery poisons the mount; fresh unclean mounts stay read-only.
//! Gaps are explicitly zeroed; imported files need not have zeroed EOF slack.

use core::fmt::Write;
use core::ops::ControlFlow;

use zerocopy::little_endian::U32;
use zerocopy::{FromBytes, FromZeros, IntoBytes};

use super::{
    ATTR_DIRECTORY, ATTR_READ_ONLY, DirectoryEntry, FatError, FatFilesystem, FatType, LfnEntry,
    MAX_BLOCK_SIZE, MAX_LFN_LENGTH,
};

/// Size of one directory record.
const SLOT: usize = core::mem::size_of::<DirectoryEntry>();
/// FAT32 end-of-chain marker written by this driver.
const END_OF_CHAIN: u32 = 0x0fff_ffff;
/// Deleted-entry marker for the first byte of a directory record.
const DELETED: u8 = 0xe5;

/// Identity of a live directory record, independent of filename spelling.
/// Slots can be reused after deletion; the handle owner must track deletion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatFileId(u64);

/// Open file metadata shared by EFI handles; cursors belong to the handles.
/// Copies are operation snapshots: owners must propagate metadata updates to
/// all aliases and invalidate them on deletion.
#[derive(Clone, Copy)]
pub struct FatFile {
    entry: DirectoryEntry,
    location: Option<RecordLocation>,
    tail: Option<ChainTail>,
}

impl FatFile {
    pub fn entry(&self) -> DirectoryEntry {
        self.entry
    }
    pub fn id(&self) -> Option<FatFileId> {
        self.location
            .map(|location| FatFileId(location.short_offset))
    }
}

#[derive(Clone, Copy)]
struct RecordLocation {
    parent: u32,
    short_offset: u64,
    first_offset: u64,
}

#[derive(Clone, Copy)]
struct ChainTail {
    last: u32,
    length: u32,
    generation: u64,
}

/// Only completed transfers inside the committed file size count as written
/// after recovery. The failing transfer may itself have partially changed data.
#[derive(Debug)]
pub struct FatWriteError {
    pub error: FatError,
    pub written: usize,
}

/// An isolated extension, not linked into the old file until data is durable.
struct Growth {
    first: u32,
    old_last: Option<u32>,
    existing: u32,
    added: u32,
    last: u32,
    length: u32,
}

/// A logically consecutive directory run may span fragmented clusters.
const MAX_SLOTS: usize = MAX_LFN_LENGTH.div_ceil(13) + 1;
struct FreeSlots {
    offsets: heapless::Vec<u64, MAX_SLOTS>,
    // End markers consumed by this run are restored if insertion fails.
    end_offsets: heapless::Vec<u64, MAX_SLOTS>,
    next: Option<u64>,
    old_last: Option<u32>,
}

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

    /// Fresh mounts must not clear evidence of interrupted/failed mutation.
    pub(super) fn check_mount_status(&mut self) -> Result<(), FatError> {
        if self.fat_type == FatType::Fat32 {
            let mut status = U32::ZERO;
            self.partition_read(
                self.fat32_entry_offset(self.active_fat as u32, 1)?,
                status.as_mut_bytes(),
            )?;
            self.state.needs_repair = status.get() & 0x0c00_0000 != 0x0c00_0000;
        }
        Ok(())
    }

    fn require_writable(&self) -> Result<(), FatError> {
        self.require_fat32()?;
        if self.state.failed {
            return Err(FatError::InvalidCluster);
        }
        if self.is_read_only() {
            return Err(FatError::ReadOnly);
        }
        Ok(())
    }

    fn check_volume_range(&self, offset: u64, len: usize) -> Result<(), FatError> {
        if offset
            .checked_add(len as u64)
            .is_none_or(|end| end > self.volume_size())
        {
            return Err(FatError::InvalidCluster);
        }
        Ok(())
    }

    fn partition_read(&mut self, offset: u64, output: &mut [u8]) -> Result<(), FatError> {
        self.check_volume_range(offset, output.len())?;
        self.range
            .read(self.device, offset, output)
            .map_err(|_| FatError::ReadError)
    }

    fn partition_write(&mut self, offset: u64, input: &[u8]) -> Result<(), FatError> {
        self.partition_write_progress(offset, input)
            .map(|_| ())
            .map_err(|error| error.error)
    }

    fn partition_write_progress(
        &mut self,
        offset: u64,
        input: &[u8],
    ) -> Result<usize, FatWriteError> {
        self.require_fat32()
            .and_then(|()| self.check_volume_range(offset, input.len()))
            .map_err(|error| FatWriteError { error, written: 0 })?;
        // Invalidate before I/O: even an unsuccessful write may change media.
        self.fat_block_cached = u64::MAX;
        self.state.generation = self.state.generation.wrapping_add(1);
        self.range
            .write_with_progress(self.device, offset, input)
            .map_err(|error| FatWriteError {
                error: match error.error {
                    crate::drivers::block::BlockError::WriteProtected => FatError::ReadOnly,
                    _ => FatError::WriteError,
                },
                written: error.completed,
            })
    }

    /// Persist dirty status and invalidate advisory free-space hints *before*
    /// changing allocation. Flush marks clean only after all writes are durable.
    fn begin_mutation(&mut self) -> Result<(), FatError> {
        self.require_writable()?;
        if self.state.dirty {
            return Ok(());
        }
        let result = (|| {
            if !self.state.fs_info_invalidated {
                if let Some(sector) = self.fs_info_sector {
                    let offset = sector as u64 * self.bytes_per_sector as u64;
                    let mut info = super::Fat32FsInfo::new_zeroed();
                    self.partition_read(offset, info.as_mut_bytes())?;
                    if info.valid() {
                        info.free_count = U32::new(u32::MAX);
                        info.next_free = U32::new(u32::MAX);
                        self.partition_write(offset, info.as_bytes())?;
                    }
                }
                self.state.fs_info_invalidated = true;
            }
            let mut status = U32::ZERO;
            self.partition_read(
                self.fat32_entry_offset(self.active_fat as u32, 1)?,
                status.as_mut_bytes(),
            )?;
            self.set_fat32_value(1, status.get() & !0x0800_0000)?;
            self.device.flush().map_err(|_| FatError::WriteError)
        })();
        if result.is_err() {
            self.state.failed = true;
        } else {
            self.state.dirty = true;
        }
        result
    }

    fn cluster_byte_offset(&self, cluster: u32) -> Result<u64, FatError> {
        if cluster < 2 || cluster - 2 >= self.data_clusters {
            return Err(FatError::InvalidCluster);
        }
        Ok(self.data_start as u64 * self.bytes_per_sector as u64
            + (cluster - 2) as u64 * self.cluster_size() as u64)
    }

    /// Partition byte offset of a cluster's entry in FAT copy `copy`.
    fn fat32_entry_offset(&self, copy: u32, cluster: u32) -> Result<u64, FatError> {
        if copy >= self.num_fats as u32
            || cluster >= self.data_clusters + 2
            || cluster as u64 * 4 + 4 > self.sectors_per_fat as u64 * self.bytes_per_sector as u64
        {
            return Err(FatError::InvalidCluster);
        }
        Ok(
            (self.fat_start as u64 + copy as u64 * self.sectors_per_fat as u64)
                * self.bytes_per_sector as u64
                + cluster as u64 * 4,
        )
    }

    /// Update the authoritative FAT(s), preserving reserved bits. Recovery
    /// includes the failed copy: its transfer may have partially succeeded.
    fn set_fat32_value(&mut self, cluster: u32, value: u32) -> Result<(), FatError> {
        self.require_fat32()?;
        let mut old = heapless::Vec::<(u64, u32), 2>::new();
        let copies = if self.mirrored {
            0..self.num_fats as u32
        } else {
            self.active_fat as u32..self.active_fat as u32 + 1
        };
        for copy in copies {
            let offset = self.fat32_entry_offset(copy, cluster)?;
            let mut value = U32::ZERO;
            self.partition_read(offset, value.as_mut_bytes())?;
            let _ = old.push((offset, value.get()));
        }

        for (index, &(offset, previous)) in old.iter().enumerate() {
            let new = U32::new((previous & 0xf000_0000) | (value & 0x0fff_ffff));
            if let Err(error) = self.partition_write(offset, new.as_bytes()) {
                for &(offset, previous) in &old[..=index] {
                    if self
                        .partition_write(offset, U32::new(previous).as_bytes())
                        .is_err()
                    {
                        self.state.failed = true;
                    }
                }
                return Err(error);
            }
        }
        if cluster >= 2 {
            self.state.free_clusters = None;
            if value == 0 {
                self.state.alloc_hint = self.state.alloc_hint.min(cluster);
            }
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

        let hint = self.state.alloc_hint.clamp(2, cluster_limit);
        // A hint is not proof that earlier clusters are occupied; wrap once.
        let start = hint - hint % entries_per_chunk as u32;
        for (first, low, high) in (start..cluster_limit)
            .step_by(entries_per_chunk)
            .map(|first| (first, hint, cluster_limit))
            .chain(
                (0..hint)
                    .step_by(entries_per_chunk)
                    .map(|first| (first, 2, hint)),
            )
        {
            let entries = (cluster_limit - first).min(entries_per_chunk as u32) as usize;
            self.partition_read(
                self.fat32_entry_offset(self.active_fat as u32, first)?,
                &mut chunk[..entries * 4],
            )?;
            let table =
                <[U32]>::ref_from_bytes(&chunk[..entries * 4]).map_err(|_| FatError::ReadError)?;
            let free = table
                .iter()
                .enumerate()
                .map(|(index, value)| (first + index as u32, value.get() & 0x0fff_ffff))
                .find(|&(cluster, value)| cluster >= low && cluster < high && value == 0);
            if let Some((cluster, _)) = free {
                self.zero_cluster(cluster)?;
                self.set_fat32_value(cluster, END_OF_CHAIN)?;
                self.state.alloc_hint = cluster + 1;
                return Ok(cluster);
            }
        }
        Err(FatError::NoSpace)
    }

    /// Free a cluster chain. The walk is bounded so a cyclic (corrupt) chain
    /// cannot hang the firmware.
    fn free_chain(&mut self, first: u32) -> Result<(), FatError> {
        if first == 0 {
            return Ok(());
        }
        // Validate the entire chain, including cycles, before freeing anything.
        self.chain_end(first)?;
        let mut cluster = first;
        loop {
            let next = self.next_cluster(cluster)?;
            self.set_fat32_value(cluster, 0)?;
            match next {
                Some(next) => cluster = next,
                None => return Ok(()),
            }
        }
    }

    /// Allocate a cluster and link it after `last`.
    fn append_cluster(&mut self, last: u32) -> Result<u32, FatError> {
        let new = self.allocate_cluster()?;
        if let Err(error) = self.set_fat32_value(last, new) {
            if self.set_fat32_value(new, 0).is_err() {
                self.state.failed = true;
            }
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
    pub(super) fn for_each_slot<T>(
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
                if let Ok(part) = LfnEntry::read_from_bytes(entry.as_bytes()) {
                    if part.is_last() {
                        lfn_start = position;
                    }
                    lfn.process_lfn(&part);
                }
                return ControlFlow::Continue(());
            }
            let has_lfn = lfn.belongs_to(entry);
            let matched = !entry.is_volume_id()
                && ((has_lfn && lfn.matches(name)) || entry.matches_name(name));
            let first_offset = if has_lfn { lfn_start } else { position };
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
        let candidate = |number| {
            let mut tail = heapless::String::<5>::new();
            let _ = write!(tail, "~{number}");
            let keep = base.len().min(8 - tail.len());
            short_name_bytes(
                base[..keep].iter().copied().chain(tail.bytes()),
                extension.iter().copied(),
            )
        };
        // One directory scan, not one scan for every colliding numeric tail.
        let mut used = [0u8; 1250];
        let _ = self.for_each_slot(directory, |_, entry| {
            if entry.is_end() {
                return ControlFlow::Break(());
            }
            if !entry.is_free() && !entry.is_lfn() {
                let short = entry.short_name_bytes();
                if let Some(tilde) = short[..8].iter().rposition(|&byte| byte == b'~') {
                    let end = short[..8]
                        .iter()
                        .position(|&byte| byte == b' ')
                        .unwrap_or(8);
                    if tilde < end
                        && let Ok(digits) = core::str::from_utf8(&short[tilde + 1..end])
                        && let Ok(number) = digits.parse::<u16>()
                        && (1..=9999).contains(&number)
                        && candidate(number) == short
                    {
                        used[number as usize / 8] |= 1 << (number % 8);
                    }
                }
            }
            ControlFlow::Continue(())
        })?;
        (1u16..=9999)
            .find(|&number| used[number as usize / 8] & (1 << (number % 8)) == 0)
            .map(|number| (candidate(number), true))
            .ok_or(FatError::NoSpace)
    }

    /// Reserve a run in *logical* directory order, including the first EOF
    /// slot. Bytes beyond EOF are free even if they contain stale records.
    fn find_free_slots(&mut self, directory: u32, count: usize) -> Result<FreeSlots, FatError> {
        if count == 0 || count > MAX_SLOTS {
            return Err(FatError::NoSpace);
        }
        let mut slots = FreeSlots {
            offsets: heapless::Vec::new(),
            end_offsets: heapless::Vec::new(),
            next: None,
            old_last: None,
        };
        let mut ended = false;
        let scan = self.for_each_slot(directory, |position, entry| {
            if slots.offsets.len() == count {
                slots.next = Some(position);
                return ControlFlow::Break(());
            }
            ended |= entry.is_end();
            if !ended && !entry.is_free() {
                slots.offsets.clear();
                slots.end_offsets.clear();
            } else {
                let _ = slots.offsets.push(position);
                if entry.is_end() {
                    let _ = slots.end_offsets.push(position);
                }
                if slots.offsets.len() == count && !ended {
                    return ControlFlow::Break(());
                }
            }
            ControlFlow::Continue(())
        })?;
        if let ControlFlow::Continue(mut last) = scan
            && slots.offsets.len() < count
        {
            slots.old_last = Some(last);
            let result = (|| {
                while slots.offsets.len() < count {
                    last = self.append_cluster(last)?;
                    let base = self.cluster_byte_offset(last)?;
                    for within in (0..self.cluster_size()).step_by(SLOT) {
                        let position = base + within as u64;
                        if slots.offsets.len() == count {
                            slots.next = Some(position);
                            break;
                        }
                        let _ = slots.offsets.push(position);
                        let _ = slots.end_offsets.push(position);
                    }
                }
                Ok(())
            })();
            if let Err(error) = result {
                if self.cut_chain_after(slots.old_last.unwrap()).is_err() {
                    self.state.failed = true;
                }
                return Err(error);
            }
        }
        Ok(slots)
    }

    fn undo_slots(&mut self, slots: &FreeSlots) -> Result<(), FatError> {
        for &offset in &slots.offsets {
            self.partition_write(
                offset,
                &[if slots.end_offsets.contains(&offset) {
                    0
                } else {
                    DELETED
                }],
            )?;
        }
        self.device.flush().map_err(|_| FatError::WriteError)?;
        if let Some(last) = slots.old_last {
            self.cut_chain_after(last)?;
        }
        self.device.flush().map_err(|_| FatError::WriteError)
    }

    /// Add a directory record (with a long-name run when needed) for `name`.
    fn insert_entry(
        &mut self,
        directory: u32,
        name: &str,
        attributes: u8,
        first_cluster: u32,
    ) -> Result<Record, FatError> {
        match self.find_record_in_directory(directory, name) {
            Ok(_) => return Err(FatError::AlreadyExists),
            Err(FatError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let (short, needs_lfn) = self.make_short_name(directory, name)?;
        let utf16: heapless::Vec<u16, MAX_LFN_LENGTH> = name.encode_utf16().collect();
        let lfn_count = if needs_lfn {
            utf16.len().div_ceil(13)
        } else {
            0
        };
        let slots = self.find_free_slots(directory, lfn_count + 1)?;
        let record = DirectoryEntry::new(short, attributes, first_cluster, 0);
        let result = (|| {
            // Establish the new EOF before consuming the old one. Publishing the
            // short record last keeps incomplete LFN runs from naming a file.
            if !slots.end_offsets.is_empty()
                && let Some(next) = slots.next
            {
                self.partition_write(next, &[0])?;
            }
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
                self.partition_write(slots.offsets[index], record.as_bytes())?;
            }
            self.device.flush().map_err(|_| FatError::WriteError)?;
            self.partition_write(slots.offsets[lfn_count], record.as_bytes())?;
            self.device.flush().map_err(|_| FatError::WriteError)
        })();
        if let Err(error) = result {
            if self.undo_slots(&slots).is_err() {
                self.state.failed = true;
            }
            return Err(error);
        }
        Ok(Record {
            entry: record,
            short_offset: slots.offsets[lfn_count],
            first_offset: slots.offsets[0],
        })
    }

    /// Open once by path; subsequent operations use record identity, not lookup.
    pub fn open_file(&mut self, path: &str) -> Result<FatFile, FatError> {
        if self.state.failed {
            return Err(FatError::InvalidCluster);
        }
        if path.trim_matches(['/', '\\']).is_empty() {
            return Ok(FatFile {
                entry: DirectoryEntry::new(*b"           ", ATTR_DIRECTORY, self.root_cluster, 0),
                location: None,
                tail: None,
            });
        }
        if self.fat_type != FatType::Fat32 {
            return Ok(FatFile {
                entry: self.find_file(path)?,
                location: None,
                tail: None,
            });
        }
        let (parent, name) = self.split_parent(path)?;
        let record = self.find_record_in_directory(parent, name)?;
        Ok(FatFile {
            entry: record.entry,
            location: Some(RecordLocation {
                parent,
                short_offset: record.short_offset,
                first_offset: record.first_offset,
            }),
            tail: None,
        })
    }

    pub fn create(&mut self, path: &str, directory: bool) -> Result<DirectoryEntry, FatError> {
        self.create_with_attributes(path, if directory { ATTR_DIRECTORY } else { 0 })
            .map(|file| file.entry)
    }

    /// Preserve the FAT attributes requested by the caller.
    pub fn create_with_attributes(
        &mut self,
        path: &str,
        attributes: u8,
    ) -> Result<FatFile, FatError> {
        if attributes & !0x37 != 0 {
            return Err(FatError::InvalidName);
        }
        self.require_writable()?;
        let directory = attributes & ATTR_DIRECTORY != 0;
        let (parent, name) = self.split_parent(path)?;
        match self.find_record_in_directory(parent, name) {
            Ok(_) => return Err(FatError::AlreadyExists),
            Err(FatError::NotFound) => {}
            Err(error) => return Err(error),
        }
        self.begin_mutation()?;
        // Files get their first cluster on the first write.
        let cluster = if directory {
            self.allocate_cluster()?
        } else {
            0
        };
        let result = self
            .init_directory(cluster, parent, directory)
            .and_then(|()| self.insert_entry(parent, name, attributes, cluster));
        match result {
            Ok(record) => Ok(FatFile {
                entry: record.entry,
                location: Some(RecordLocation {
                    parent,
                    short_offset: record.short_offset,
                    first_offset: record.first_offset,
                }),
                tail: None,
            }),
            Err(error) => {
                // Never free allocation if failed recovery may have left a
                // live directory entry pointing at it.
                if !self.state.failed && self.free_chain(cluster).is_err() {
                    self.state.failed = true;
                }
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

    fn writable_location(&self, file: &FatFile) -> Result<RecordLocation, FatError> {
        self.require_writable()?;
        if !file.entry.is_directory() && file.entry.attributes() & ATTR_READ_ONLY != 0 {
            return Err(FatError::ReadOnly);
        }
        file.location.ok_or(FatError::ReadOnly)
    }

    /// Allocate an isolated extension. A retained tail makes repeated appends
    /// linear rather than walking the whole file on each write.
    fn ensure_clusters(&mut self, file: &FatFile, required: u32) -> Result<Growth, FatError> {
        let first = file.entry.first_cluster();
        let (old_last, existing) = if first == 0 {
            (None, 0)
        } else if let Some(tail) = file
            .tail
            .filter(|tail| tail.generation == self.state.generation)
        {
            (Some(tail.last), tail.length)
        } else {
            let (last, length) = self.chain_end(first)?;
            (Some(last), length)
        };
        let mut growth = Growth {
            first,
            old_last,
            existing,
            added: 0,
            last: old_last.unwrap_or(0),
            length: existing,
        };
        for _ in existing..required {
            let allocation = if growth.added == 0 {
                self.allocate_cluster()
            } else {
                self.append_cluster(growth.last)
            };
            match allocation {
                Ok(cluster) => {
                    if growth.added == 0 {
                        growth.added = cluster;
                    }
                    growth.last = cluster;
                    growth.length += 1;
                }
                Err(error) => {
                    if growth.added != 0 && self.free_chain(growth.added).is_err() {
                        self.state.failed = true;
                    }
                    return Err(error);
                }
            }
        }
        if first == 0 {
            growth.first = growth.added;
        }
        Ok(growth)
    }

    fn cut_chain_after(&mut self, last: u32) -> Result<(), FatError> {
        let tail = self.next_cluster(last)?;
        if let Some(tail) = tail {
            self.chain_end(tail)?;
        }
        self.set_fat32_value(last, END_OF_CHAIN)?;
        // Persist detachment before making any clusters reusable.
        self.device.flush().map_err(|_| FatError::WriteError)?;
        tail.map_or(Ok(()), |tail| self.free_chain(tail))
    }

    fn growth_cluster(&mut self, growth: &Growth, index: u32) -> Result<u32, FatError> {
        if index >= growth.length {
            return Err(FatError::InvalidCluster);
        }
        if index + 1 == growth.existing {
            return growth.old_last.ok_or(FatError::InvalidCluster);
        }
        let (mut cluster, skip) = if index >= growth.existing {
            (growth.added, index - growth.existing)
        } else {
            (growth.first, index)
        };
        for _ in 0..skip {
            cluster = self
                .next_cluster(cluster)?
                .ok_or(FatError::InvalidCluster)?;
        }
        Ok(cluster)
    }

    /// Write payload or zero a gap through the logical old+staged chain.
    fn write_growth(
        &mut self,
        growth: &Growth,
        offset: u32,
        len: usize,
        input: Option<&[u8]>,
        done: &mut usize,
    ) -> Result<(), FatError> {
        if len == 0 {
            return Ok(());
        }
        let cluster_size = self.cluster_size();
        let mut index = offset / cluster_size as u32;
        let mut cluster = self.growth_cluster(growth, index)?;
        let mut within = offset as usize % cluster_size;
        let zeros = [0u8; MAX_BLOCK_SIZE];
        while *done < len {
            let count = (cluster_size - within).min(len - *done).min(MAX_BLOCK_SIZE);
            let bytes = input.map_or(&zeros[..count], |data| &data[*done..*done + count]);
            match self
                .partition_write_progress(self.cluster_byte_offset(cluster)? + within as u64, bytes)
            {
                Ok(_) => *done += count,
                Err(error) => {
                    *done += error.written;
                    return Err(error.error);
                }
            }
            within += count;
            if within == cluster_size && *done < len {
                index += 1;
                cluster = if index == growth.existing {
                    growth.added
                } else {
                    self.next_cluster(cluster)?
                        .ok_or(FatError::InvalidCluster)?
                };
                within = 0;
            }
        }
        Ok(())
    }

    fn restore_record(&mut self, file: &FatFile, location: RecordLocation) -> Result<(), FatError> {
        self.partition_write(location.short_offset, file.entry.as_bytes())?;
        self.device.flush().map_err(|_| FatError::WriteError)
    }

    fn undo_growth(
        &mut self,
        file: &FatFile,
        location: RecordLocation,
        growth: &Growth,
        record_attempted: bool,
        link_attempted: bool,
    ) -> Result<(), FatError> {
        if record_attempted {
            self.restore_record(file, location)?;
        }
        if link_attempted {
            self.set_fat32_value(
                growth.old_last.ok_or(FatError::InvalidCluster)?,
                END_OF_CHAIN,
            )?;
            self.device.flush().map_err(|_| FatError::WriteError)?;
        }
        if growth.added != 0 {
            // If FAT recovery already failed, references are uncertain. Do not
            // free possibly referenced clusters just to avoid an orphan.
            if self.state.failed {
                return Err(FatError::InvalidCluster);
            }
            self.free_chain(growth.added)?;
            self.device.flush().map_err(|_| FatError::WriteError)?;
        }
        Ok(())
    }

    /// Write an open file, reporting the committed prefix on failure. Existing
    /// payload overwrites are not transactional; allocation and pointers are.
    pub fn write_file(
        &mut self,
        file: &mut FatFile,
        offset: u32,
        input: &[u8],
    ) -> Result<usize, FatWriteError> {
        let mut done = 0;
        let old_size = file.entry.file_size();
        let result = (|| {
            let location = self.writable_location(file)?;
            if file.entry.is_directory() {
                return Err(FatError::NotAFile);
            }
            if input.is_empty() {
                return Ok(());
            }
            let end = u32::try_from(input.len())
                .ok()
                .and_then(|len| offset.checked_add(len))
                .ok_or(FatError::NoSpace)?;
            // Validate/cache before begin_mutation changes the generation.
            if file.entry.first_cluster() != 0
                && file
                    .tail
                    .is_none_or(|tail| tail.generation != self.state.generation)
            {
                let (last, length) = self.chain_end(file.entry.first_cluster())?;
                file.tail = Some(ChainTail {
                    last,
                    length,
                    generation: self.state.generation,
                });
            }
            self.begin_mutation()?;
            if let Some(tail) = &mut file.tail {
                tail.generation = self.state.generation;
            }
            let growth = self.ensure_clusters(file, end.div_ceil(self.cluster_size() as u32))?;
            let mut record_attempted = false;
            let mut link_attempted = false;
            let mut entry = file.entry;
            entry.set_first_cluster(growth.first);
            entry.file_size = old_size.max(end);
            entry.attr |= 0x20; // A modified file is archived.
            let changed = entry.as_bytes() != file.entry.as_bytes();
            let write = (|| {
                if offset > old_size {
                    self.write_growth(
                        &growth,
                        old_size,
                        (offset - old_size) as usize,
                        None,
                        &mut 0,
                    )?;
                }
                self.write_growth(&growth, offset, input.len(), Some(input), &mut done)?;
                if growth.added != 0 || end > old_size {
                    self.device.flush().map_err(|_| FatError::WriteError)?;
                }
                if growth.added != 0
                    && let Some(last) = growth.old_last
                {
                    link_attempted = true;
                    self.set_fat32_value(last, growth.added)?;
                    self.device.flush().map_err(|_| FatError::WriteError)?;
                }
                if changed {
                    record_attempted = true;
                    self.partition_write(location.short_offset, entry.as_bytes())?;
                    self.device.flush().map_err(|_| FatError::WriteError)?;
                }
                Ok(())
            })();
            if let Err(error) = write {
                if self
                    .undo_growth(file, location, &growth, record_attempted, link_attempted)
                    .is_err()
                {
                    self.state.failed = true;
                }
                file.tail = None;
                return Err(error);
            }
            file.entry = entry;
            file.tail = Some(ChainTail {
                last: growth.last,
                length: growth.length,
                generation: self.state.generation,
            });
            Ok(())
        })();
        result.map(|()| input.len()).map_err(|error| FatWriteError {
            error,
            written: done.min(old_size.saturating_sub(offset) as usize),
        })
    }

    pub fn write_path(
        &mut self,
        path: &str,
        offset: u32,
        input: &[u8],
    ) -> Result<(u32, u32), FatError> {
        let mut file = self.open_file(path)?;
        self.write_file(&mut file, offset, input)
            .map_err(|error| error.error)?;
        Ok((file.entry.file_size(), file.entry.first_cluster()))
    }

    /// Publish a metadata change durably before releasing old allocation.
    fn publish_record(
        &mut self,
        file: &mut FatFile,
        entry: DirectoryEntry,
        location: RecordLocation,
    ) -> Result<(), FatError> {
        let result = self
            .partition_write(location.short_offset, entry.as_bytes())
            .and_then(|()| self.device.flush().map_err(|_| FatError::WriteError));
        if let Err(error) = result {
            if self.restore_record(file, location).is_err() {
                self.state.failed = true;
            }
            return Err(error);
        }
        file.entry = entry;
        file.tail = None;
        Ok(())
    }

    pub fn truncate_file(&mut self, file: &mut FatFile, size: u32) -> Result<(), FatError> {
        let location = self.writable_location(file)?;
        if file.entry.is_directory() {
            return Err(FatError::NotAFile);
        }
        if size >= file.entry.file_size() {
            return Ok(());
        }
        let first = file.entry.first_cluster();
        self.chain_end(first)?;
        let mut last = first;
        for _ in 1..size.div_ceil(self.cluster_size() as u32) {
            last = self.next_cluster(last)?.ok_or(FatError::InvalidCluster)?;
        }
        self.begin_mutation()?;
        let mut entry = file.entry;
        entry.file_size = size;
        if size == 0 {
            entry.set_first_cluster(0);
        }
        self.publish_record(file, entry, location)?;
        // No need to overwrite EOF slack here: growing writes zero their gap.
        let result = if size == 0 {
            self.free_chain(first)
        } else {
            self.cut_chain_after(last)
        }
        .and_then(|()| self.device.flush().map_err(|_| FatError::WriteError));
        if result.is_err() {
            self.state.failed = true;
        }
        result
    }

    pub fn truncate_path(&mut self, path: &str, size: u32) -> Result<(), FatError> {
        let mut file = self.open_file(path)?;
        self.truncate_file(&mut file, size)
    }

    pub fn delete_file(&mut self, file: &FatFile) -> Result<(), FatError> {
        let location = self.writable_location(file)?;
        let entry = file.entry;
        if entry.first_cluster() != 0 {
            self.chain_end(entry.first_cluster())?;
        }
        if entry.is_directory() {
            let children = self.for_each_slot(entry.first_cluster(), |_, child| {
                if child.is_end() {
                    return ControlFlow::Break(false);
                }
                if child.is_free()
                    || child.is_lfn()
                    || child.is_volume_id()
                    || matches!(child.short_name().as_str(), "." | "..")
                {
                    ControlFlow::Continue(())
                } else {
                    ControlFlow::Break(true)
                }
            })?;
            if matches!(children, ControlFlow::Break(true)) {
                return Err(FatError::DirectoryNotEmpty);
            }
        }
        let mut run = heapless::Vec::<u64, MAX_SLOTS>::new();
        let mut inside = false;
        let _ = self.for_each_slot(location.parent, |position, _| {
            inside |= position == location.first_offset;
            if inside && run.push(position).is_err() {
                return ControlFlow::Break(());
            }
            if position == location.short_offset {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })?;
        if run.last() != Some(&location.short_offset) {
            return Err(FatError::InvalidCluster);
        }
        self.begin_mutation()?;
        // Remove the short entry and persist it before freeing any clusters.
        if let Err(error) = self
            .partition_write(location.short_offset, &[DELETED])
            .and_then(|()| self.device.flush().map_err(|_| FatError::WriteError))
        {
            if self.restore_record(file, location).is_err() {
                self.state.failed = true;
            }
            return Err(error);
        }
        let result = run[..run.len() - 1]
            .iter()
            .try_for_each(|&offset| self.partition_write(offset, &[DELETED]))
            .and_then(|()| self.free_chain(entry.first_cluster()))
            .and_then(|()| self.device.flush().map_err(|_| FatError::WriteError));
        if result.is_err() {
            self.state.failed = true;
        }
        result
    }

    pub fn delete_path(&mut self, path: &str) -> Result<(), FatError> {
        let file = self.open_file(path)?;
        self.delete_file(&file)
    }

    /// Attribute-only changes may clear read-only protection, but cannot
    /// convert a directory into a regular file (or vice versa).
    pub fn set_attributes(&mut self, file: &mut FatFile, attributes: u8) -> Result<(), FatError> {
        if attributes & !0x37 != 0 || (attributes ^ file.entry.attr) & ATTR_DIRECTORY != 0 {
            return Err(FatError::InvalidName);
        }
        let location = file.location.ok_or(FatError::ReadOnly)?;
        self.begin_mutation()?;
        let mut entry = file.entry;
        entry.attr = attributes;
        self.publish_record(file, entry, location)
    }

    /// Count free clusters from the authoritative FAT, never from FSInfo hints.
    pub fn free_space(&mut self) -> Result<u64, FatError> {
        if self.state.failed {
            return Err(FatError::InvalidCluster);
        }
        if let Some(count) = self.state.free_clusters {
            return Ok(count as u64 * self.cluster_size() as u64);
        }
        let mut free = 0;
        let base = (self.fat_start as u64 + self.active_fat as u64 * self.sectors_per_fat as u64)
            * self.bytes_per_sector as u64;
        if self.fat_type == FatType::Fat32 {
            let mut chunk = [0u8; MAX_BLOCK_SIZE];
            for first in (2..self.data_clusters + 2).step_by(MAX_BLOCK_SIZE / 4) {
                let entries =
                    (self.data_clusters + 2 - first).min((MAX_BLOCK_SIZE / 4) as u32) as usize;
                self.partition_read(base + first as u64 * 4, &mut chunk[..entries * 4])?;
                free += <[U32]>::ref_from_bytes(&chunk[..entries * 4])
                    .map_err(|_| FatError::ReadError)?
                    .iter()
                    .filter(|value| value.get() & 0x0fff_ffff == 0)
                    .count() as u32;
            }
        } else {
            for cluster in 2..self.data_clusters + 2 {
                let offset = if self.fat_type == FatType::Fat12 {
                    cluster as u64 * 3 / 2
                } else {
                    cluster as u64 * 2
                };
                let mut bytes = [0u8; 2];
                self.partition_read(base + offset, &mut bytes)?;
                let entry = u16::from_le_bytes(bytes);
                let entry = if self.fat_type == FatType::Fat12 {
                    if cluster & 1 == 0 {
                        entry & 0xfff
                    } else {
                        entry >> 4
                    }
                } else {
                    entry
                };
                free += u32::from(entry == 0);
            }
        }
        self.state.free_clusters = Some(free);
        Ok(free as u64 * self.cluster_size() as u64)
    }

    /// Commit data and metadata, then persist the FAT clean-shutdown bit. A
    /// failed mount is never marked clean just because a later flush succeeds.
    pub fn flush(&mut self) -> Result<(), FatError> {
        let result = (|| {
            self.device.flush().map_err(|_| FatError::WriteError)?;
            if self.state.failed {
                return Err(FatError::InvalidCluster);
            }
            if self.state.dirty {
                let mut status = U32::ZERO;
                self.partition_read(
                    self.fat32_entry_offset(self.active_fat as u32, 1)?,
                    status.as_mut_bytes(),
                )?;
                self.set_fat32_value(1, status.get() | 0x0800_0000)?;
                self.device.flush().map_err(|_| FatError::WriteError)?;
                self.state.dirty = false;
            }
            Ok(())
        })();
        if result.is_err() {
            self.state.failed = true;
        }
        result
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

pub(super) fn lfn_checksum(short: &[u8; 11]) -> u8 {
    short
        .iter()
        .fold(0u8, |sum, byte| sum.rotate_right(1).wrapping_add(*byte))
}

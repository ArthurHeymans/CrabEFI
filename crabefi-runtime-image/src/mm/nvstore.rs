//! EDK2 authenticated variable store in flash, written from SMM without a heap.
//!
//! Records use the same format and protocol as crabefi-core's boot-time writer
//! (`efi/varstore/edk2.rs`, `persistence.rs`): appended with state 0xFF, then
//! VAR_HEADER_VALID_ONLY, then VAR_ADDED; predecessors are retired afterwards.
//!
//! The region is split into a primary half at offset 0 (the store other
//! readers such as coreboot see) and a spare half. Compaction survives power
//! loss: live records go to the spare first (header last), then the primary is
//! erased header-first and rebuilt from the spare (header last), then the spare
//! is erased. Opening the store finishes an interrupted compaction. A region
//! that is neither a store nor blank is reported as corrupt, never reformatted:
//! the caller must fail closed.

use core::ptr::addr_of_mut;

use crabefi_efi_types::varstore::{
    self, AUTH_VAR_HEADER_SIZE, EFI_AUTH_VARIABLE_GUID, EFI_SYSTEM_NV_DATA_FV_GUID,
    FV_HEADER_LENGTH, FV_REVISION, FV_SIGNATURE, HEADER_ALIGNMENT, VAR_ADDED, VAR_DELETED,
    VAR_HEADER_VALID_ONLY, VARIABLE_DATA, VARIABLE_DATA_OFFSET, VARIABLE_STORE_FORMATTED,
    VARIABLE_STORE_HEALTHY, VS_HEADER_LENGTH, checked_align_up,
};
use crabefi_runtime_abi::{MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN, VariableTimestamp};

use super::flash::{ERASE_BLOCK, Flash};

const HEADERS: usize = FV_HEADER_LENGTH + VS_HEADER_LENGTH;
/// Largest region this writer compacts (the SMMSTORE region on QEMU and Jaguar).
pub const MAX_STORE_SIZE: usize = 256 * 1024;
const NAME_BYTES_MAX: usize = (MAX_VARIABLE_NAME_LEN + 1) * 2;
const RECORD_MAX: usize = AUTH_VAR_HEADER_SIZE + NAME_BYTES_MAX + MAX_VARIABLE_DATA_SIZE + 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Device,
    Full,
    Invalid,
    /// Neither a valid store nor blank flash.
    Corrupt,
}

/// One record header as found in the store.
#[derive(Clone, Copy)]
pub struct Record {
    pub offset: u32,
    pub state: u8,
    pub attributes: u32,
    pub timestamp: VariableTimestamp,
    pub guid: [u8; 16],
    pub name_offset: u32,
    pub name_size: u32,
    pub data_offset: u32,
    pub data_size: u32,
    pub next: u32,
}

/// Called with each live record, its name (with terminator) and its data.
type LiveRecordVisitor<'a> = dyn FnMut(&Record, &[u16], &[u8]) -> Result<(), Error> + 'a;

/// Region-relative reader over flash or over a RAM copy of the region.
type Reader<'a> = &'a mut dyn FnMut(u32, &mut [u8]) -> bool;

pub struct NvStore {
    flash: Flash,
    /// Flash offset and size of the store region.
    region: u64,
    size: u32,
    /// Size of each half; the primary store spans [0, half), the spare [half, size).
    half: u32,
    /// End of the variable data area (region-relative).
    data_end: u32,
    /// First free byte (region-relative).
    write_offset: u32,
    /// A rebuild failed after it started erasing: no copy on flash is known
    /// to be complete, so writes are refused until the store is opened again.
    poisoned: bool,
}

// The boot firmware checks the store size against this before loading MM.
const _: () = assert!(
    2 * (HEADERS + RECORD_MAX).div_ceil(ERASE_BLOCK as usize) * ERASE_BLOCK as usize
        == crabefi_runtime_abi::mm::MIN_STORE_SIZE as usize
);

static mut RECORD: [u8; RECORD_MAX] = [0; RECORD_MAX];

fn timestamp_bytes(t: &VariableTimestamp) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..2].copy_from_slice(&t.year.to_le_bytes());
    b[2] = t.month;
    b[3] = t.day;
    b[4] = t.hour;
    b[5] = t.minute;
    b[6] = t.second;
    b[8..12].copy_from_slice(&t.nanosecond.to_le_bytes());
    b[12..14].copy_from_slice(&t.timezone.to_le_bytes());
    b[14] = t.daylight;
    b
}

fn timestamp_from(h: &[u8]) -> VariableTimestamp {
    VariableTimestamp {
        year: u16::from_le_bytes([h[0x10], h[0x11]]),
        month: h[0x12],
        day: h[0x13],
        hour: h[0x14],
        minute: h[0x15],
        second: h[0x16],
        pad1: h[0x17],
        nanosecond: u32::from_le_bytes([h[0x18], h[0x19], h[0x1a], h[0x1b]]),
        timezone: i16::from_le_bytes([h[0x1c], h[0x1d]]),
        daylight: h[0x1e],
        pad2: h[0x1f],
    }
}

fn u32_at(h: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]])
}

/// FV header + variable store header for a region of `size` bytes.
fn fv_headers(size: u32) -> [u8; HEADERS] {
    let mut b = [0u8; HEADERS];
    b[0x10..0x20].copy_from_slice(&EFI_SYSTEM_NV_DATA_FV_GUID);
    b[0x20..0x28].copy_from_slice(&(size as u64).to_le_bytes());
    b[0x28..0x2c].copy_from_slice(&FV_SIGNATURE.to_le_bytes());
    b[0x2c..0x30].copy_from_slice(&0x0004_feffu32.to_le_bytes());
    b[0x30..0x32].copy_from_slice(&(FV_HEADER_LENGTH as u16).to_le_bytes());
    b[0x37] = FV_REVISION;
    b[0x38..0x3c].copy_from_slice(&1u32.to_le_bytes());
    b[0x3c..0x40].copy_from_slice(&size.to_le_bytes());
    let mut sum = 0u16;
    for i in (0..FV_HEADER_LENGTH).step_by(2) {
        sum = sum.wrapping_add(u16::from_le_bytes([b[i], b[i + 1]]));
    }
    b[0x32..0x34].copy_from_slice(&0u16.wrapping_sub(sum).to_le_bytes());
    let vs = FV_HEADER_LENGTH;
    b[vs..vs + 16].copy_from_slice(&EFI_AUTH_VARIABLE_GUID);
    b[vs + 0x10..vs + 0x14].copy_from_slice(&(size - HEADERS as u32).to_le_bytes());
    b[vs + 0x14] = VARIABLE_STORE_FORMATTED;
    b[vs + 0x15] = VARIABLE_STORE_HEALTHY;
    b
}

/// Walk the records; returns the offset where it stopped: the append point
/// (blank flash, or a record still being appended, whose state is 0xFF), or
/// the record `f` stopped at.
///
/// A read failure, or a programmed record that does not parse, is an error
/// rather than the end of the store: treating it as the end would serve, or
/// compact into, a store that silently lacks the records after it.
fn walk(read: Reader<'_>, data_end: u32, f: &mut dyn FnMut(&Record) -> bool) -> Result<u32, Error> {
    let header_size = AUTH_VAR_HEADER_SIZE as u32;
    let mut offset = VARIABLE_DATA_OFFSET;
    let mut h = [0u8; AUTH_VAR_HEADER_SIZE];
    while offset + header_size <= data_end {
        if !read(offset, &mut h) {
            return Err(Error::Device);
        }
        // A record's state is only programmed after the whole record, so
        // 0xFF there means an append that never committed (possibly torn
        // inside its header, magic included): the end of the store.
        let magic = u16::from_le_bytes([h[0], h[1]]);
        if magic == 0xffff || h[2] == 0xff {
            return Ok(offset);
        }
        if magic != VARIABLE_DATA {
            return Err(Error::Corrupt);
        }
        let (attributes, name_size, data_size) =
            (u32_at(&h, 4), u32_at(&h, 0x24), u32_at(&h, 0x28));
        let next = offset.checked_add(header_size).and_then(|name_offset| {
            let data_offset = name_offset.checked_add(name_size)?;
            let end = data_offset.checked_add(data_size)?;
            let next = checked_align_up(end - offset, HEADER_ALIGNMENT)
                .and_then(|n| offset.checked_add(n))?;
            (end <= data_end).then_some((name_offset, data_offset, next))
        });
        let Some((name_offset, data_offset, next)) = next else {
            return Err(Error::Corrupt);
        };
        let mut guid = [0u8; 16];
        guid.copy_from_slice(&h[0x2c..0x3c]);
        let record = Record {
            offset,
            state: h[2],
            attributes,
            timestamp: timestamp_from(&h),
            guid,
            name_offset,
            name_size,
            data_offset,
            data_size,
            next,
        };
        if !f(&record) {
            return Ok(offset);
        }
        offset = next;
    }
    Ok(offset)
}

/// A read failure is an error, not a mismatch: callers deciding what to
/// retire or keep must not act on a name they could not read.
fn name_is(read: Reader<'_>, record: &Record, name: &[u16]) -> Result<bool, Error> {
    if record.name_size as usize != name.len() * 2 || name.len() > MAX_VARIABLE_NAME_LEN + 1 {
        return Ok(false);
    }
    let mut bytes = [0u8; NAME_BYTES_MAX];
    let Some(bytes) = bytes.get_mut(..name.len() * 2) else {
        return Ok(false);
    };
    if !read(record.name_offset, bytes) {
        return Err(Error::Device);
    }
    Ok(bytes
        .as_chunks::<2>()
        .0
        .iter()
        .zip(name)
        .all(|(b, &unit)| u16::from_le_bytes(*b) == unit))
}

impl NvStore {
    pub const fn empty() -> Self {
        Self {
            flash: Flash::empty(),
            region: 0,
            size: 0,
            half: 0,
            data_end: 0,
            write_offset: 0,
            poisoned: false,
        }
    }

    fn read(&self, offset: u32, buf: &mut [u8]) -> bool {
        self.flash.read(self.region + offset as u64, buf)
    }

    fn read_at(&self, base: u32, offset: u32, buf: &mut [u8]) -> bool {
        self.flash
            .read(self.region + base as u64 + offset as u64, buf)
    }

    /// End of the data area if a valid authenticated store of `size` bytes
    /// starts at `base`. A read failure is an error: opening must not pick an
    /// erase path from headers it could not read.
    fn store_at(&self, base: u32, size: u32) -> Result<Option<u32>, Error> {
        let mut headers = [0u8; HEADERS];
        if !self.read_at(base, 0, &mut headers) {
            return Err(Error::Device);
        }
        Ok(varstore::validate(&headers, size)
            .filter(|valid| valid.auth_format)
            .map(|valid| VARIABLE_DATA_OFFSET + valid.data_size))
    }

    fn blank(&self, base: u32, len: u32) -> Result<bool, Error> {
        let mut chunk = [0u8; 256];
        let mut offset = 0;
        while offset < len {
            let n = ((len - offset) as usize).min(chunk.len());
            if !self.read_at(base, offset, &mut chunk[..n]) {
                return Err(Error::Device);
            }
            if chunk[..n].iter().any(|&b| b != 0xff) {
                return Ok(false);
            }
            offset += n as u32;
        }
        Ok(true)
    }

    /// First free byte after the records of the store at `base`.
    fn scan_end(&self, base: u32, data_end: u32) -> Result<u32, Error> {
        walk(&mut |o, b| self.read_at(base, o, b), data_end, &mut |_| {
            true
        })
    }

    fn erase_half(&self, base: u32) -> bool {
        // Ascending block order erases the header block first, so an
        // interrupted erase never leaves a valid header over missing records.
        self.flash
            .erase(self.region + base as u64, self.half as u64)
    }

    /// Open the store: finish an interrupted compaction, migrate a full-region
    /// store from the boot-time writer, or format blank flash.
    pub fn open(&mut self, flash: Flash, region: u64, size: u32) -> Result<(), Error> {
        let half = size / 2;
        if size as usize > MAX_STORE_SIZE
            || !(half as u64).is_multiple_of(ERASE_BLOCK)
            || half == 0
            || (half as usize) < HEADERS + RECORD_MAX
        {
            return Err(Error::Invalid);
        }
        self.flash = flash;
        self.region = region;
        self.size = size;
        self.half = half;
        if let Some(end) = self.store_at(0, half)? {
            self.data_end = end;
            if self.store_at(half, half)?.is_some() {
                // compact() writes the spare header only once the spare holds
                // every live record, and erasing the spare starts with that
                // header. So while it validates, the spare is a complete
                // copy, whatever the primary holds: the old log, a finished
                // copy, or an erase that tore past its header block.
                self.copy_spare_to_primary()?;
            } else if !self.blank(half, half)? && !self.erase_half(half) {
                return Err(Error::Device);
            }
        } else if let Some(end) = self.store_at(0, size)? {
            self.data_end = end;
            let records_end = self.scan_end(0, end);
            if self.store_at(half, half)?.is_some()
                && !matches!(records_end, Ok(records_end) if records_end > half)
            {
                // A committed spare from a migration that stopped while
                // erasing the primary (whose header survived the torn erase).
                // A legacy store whose records do reach into the spare half
                // holds no spare there: migrate() refuses it below.
                self.copy_spare_to_primary()?;
            } else {
                self.write_offset = records_end?;
                self.migrate()?;
            }
        } else if self.store_at(half, half)?.is_some() {
            self.copy_spare_to_primary()?;
        } else if self.blank(0, size)? {
            self.format()?;
        } else {
            return Err(Error::Corrupt);
        }
        self.write_offset = self.scan_end(0, self.data_end)?;
        Ok(())
    }

    fn format(&mut self) -> Result<(), Error> {
        if !self.flash.erase(self.region, self.size as u64)
            || !self.flash.program(self.region, &fv_headers(self.half))
        {
            return Err(Error::Device);
        }
        self.data_end = self.half;
        Ok(())
    }

    /// Move a full-region store (boot-time writer) into the primary half.
    ///
    /// When its records reach into the spare half there is no second place
    /// to build the new copy in, and any rebuild would erase the only one.
    /// Opening then fails, so the boot stops; the store has to be compacted
    /// by a build without payload MM, or backed up and restored, first.
    fn migrate(&mut self) -> Result<(), Error> {
        if self.write_offset > self.half {
            return Err(Error::Full);
        }
        self.compact()
    }

    /// Rebuild the primary from a complete spare, then clear the spare.
    fn copy_spare_to_primary(&mut self) -> Result<(), Error> {
        let half = self.half;
        let spare_end = self.store_at(half, half)?.ok_or(Error::Corrupt)?;
        let end = self.scan_end(half, spare_end)?;
        // Until the primary is rebuilt only the spare holds the store.
        self.poisoned = true;
        if !self.erase_half(0) {
            return Err(Error::Device);
        }
        let mut chunk = [0u8; 256];
        let mut offset = VARIABLE_DATA_OFFSET;
        while offset < end {
            let n = ((end - offset) as usize).min(chunk.len());
            if !self.read_at(half, offset, &mut chunk[..n])
                || !self.flash.program(self.region + offset as u64, &chunk[..n])
            {
                return Err(Error::Device);
            }
            offset += n as u32;
        }
        // Zero the spare's headers before erasing it: an erase torn inside
        // the header block could otherwise leave a valid header over damaged
        // records, which open() would take as the complete copy.
        if !self.flash.program(self.region, &fv_headers(half))
            || !self
                .flash
                .program(self.region + half as u64, &[0u8; HEADERS])
            || !self.erase_half(half)
        {
            return Err(Error::Device);
        }
        self.data_end = half;
        self.poisoned = false;
        Ok(())
    }

    /// Call `f` with every live record (VAR_ADDED, last one per name wins),
    /// its name (with terminator) and data, in store order.
    pub fn for_each_live(
        &self,
        name_buf: &mut [u16],
        data_buf: &mut [u8],
        f: &mut LiveRecordVisitor<'_>,
    ) -> Result<(), Error> {
        let mut result = Ok(());
        let mut reader = |o: u32, b: &mut [u8]| self.read(o, b);
        walk(&mut reader, self.data_end, &mut |record| {
            if record.state != VAR_ADDED {
                return true;
            }
            let units = record.name_size as usize / 2;
            let data_len = record.data_size as usize;
            if record.name_size % 2 != 0
                || units == 0
                || units > name_buf.len()
                || data_len > data_buf.len()
            {
                result = Err(Error::Invalid);
                return false;
            }
            let mut bytes = [0u8; NAME_BYTES_MAX];
            let (Some(bytes), Some(data)) =
                (bytes.get_mut(..units * 2), data_buf.get_mut(..data_len))
            else {
                result = Err(Error::Invalid);
                return false;
            };
            if !self.read(record.name_offset, bytes)
                || (data_len != 0 && !self.read(record.data_offset, data))
            {
                result = Err(Error::Device);
                return false;
            }
            for (unit, b) in name_buf.iter_mut().zip(bytes.as_chunks::<2>().0) {
                *unit = u16::from_le_bytes(*b);
            }
            let Some(name) = name_buf.get(..units) else {
                result = Err(Error::Invalid);
                return false;
            };
            match self.superseded(record, name) {
                Ok(true) => return true,
                Ok(false) => {}
                Err(error) => {
                    result = Err(error);
                    return false;
                }
            }
            result = f(record, name, data);
            result.is_ok()
        })?;
        result
    }

    /// A later live record has the same GUID and name.
    fn superseded(&self, record: &Record, name: &[u16]) -> Result<bool, Error> {
        let mut found = Ok(false);
        let mut reader = |o: u32, b: &mut [u8]| self.read(o, b);
        walk(&mut reader, self.data_end, &mut |other| {
            if other.offset > record.offset && other.state == VAR_ADDED && other.guid == record.guid
            {
                let mut reader = |o: u32, b: &mut [u8]| self.read(o, b);
                found = name_is(&mut reader, other, name);
            }
            found == Ok(false)
        })?;
        found
    }

    /// Append a record and retire its predecessors. `name` includes the terminator.
    pub fn write(
        &mut self,
        guid: &[u8; 16],
        name: &[u16],
        attributes: u32,
        data: &[u8],
        timestamp: Option<VariableTimestamp>,
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Device);
        }
        let name_bytes = name.len() * 2;
        if name.last() != Some(&0)
            || name.len() < 2
            || name_bytes > NAME_BYTES_MAX
            || data.len() > MAX_VARIABLE_DATA_SIZE
        {
            return Err(Error::Invalid);
        }
        let raw = AUTH_VAR_HEADER_SIZE + name_bytes + data.len();
        let len = checked_align_up(raw as u32, HEADER_ALIGNMENT).ok_or(Error::Invalid)?;
        // SAFETY: single-threaded SMM; RECORD is only used here.
        let record = unsafe { &mut *addr_of_mut!(RECORD) }
            .get_mut(..len as usize)
            .ok_or(Error::Invalid)?;
        record.fill(0xff);
        let (header, body) = record
            .split_first_chunk_mut::<AUTH_VAR_HEADER_SIZE>()
            .ok_or(Error::Invalid)?;
        header[0..2].copy_from_slice(&VARIABLE_DATA.to_le_bytes());
        header[3] = 0;
        header[4..8].copy_from_slice(&attributes.to_le_bytes());
        header[8..0x10].fill(0);
        header[0x10..0x20].copy_from_slice(&timestamp_bytes(&timestamp.unwrap_or_default()));
        header[0x20..0x24].fill(0);
        header[0x24..0x28].copy_from_slice(&(name_bytes as u32).to_le_bytes());
        header[0x28..0x2c].copy_from_slice(&(data.len() as u32).to_le_bytes());
        header[0x2c..0x3c].copy_from_slice(guid);
        let (name_area, data_area) = body
            .split_at_mut_checked(name_bytes)
            .ok_or(Error::Invalid)?;
        for (bytes, unit) in name_area.as_chunks_mut::<2>().0.iter_mut().zip(name) {
            *bytes = unit.to_le_bytes();
        }
        data_area
            .get_mut(..data.len())
            .ok_or(Error::Invalid)?
            .copy_from_slice(data);
        let record: &[u8] = record;

        if !self.slot_free(len) {
            self.compact()?;
            if !self.slot_free(len) {
                return Err(Error::Full);
            }
        }
        let at = self.write_offset;
        let flash_at = self.region + at as u64;
        let state = flash_at + 2;
        if !self.flash.program(flash_at, record)
            || !self.flash.program_bits(state, VAR_HEADER_VALID_ONLY)
            || !self.flash.program_bits(state, VAR_ADDED)
        {
            return Err(Error::Device);
        }
        self.write_offset = at + len;
        // The new record is the commit point; a stale predecessor is reclaimed
        // by a later compaction if retiring it fails.
        let _ = self.retire(guid, name, Some(at));
        Ok(())
    }

    /// Mark every live record of `guid`/`name` deleted, except the one at `keep`.
    pub fn retire(
        &mut self,
        guid: &[u8; 16],
        name: &[u16],
        keep: Option<u32>,
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Device);
        }
        let mut failed = false;
        let mut unreadable = false;
        let mut reader = |o: u32, b: &mut [u8]| self.read(o, b);
        let mut matches = [0u32; 16];
        let mut count = 0;
        walk(&mut reader, self.data_end, &mut |record| {
            if Some(record.offset) != keep && record.state == VAR_ADDED && record.guid == *guid {
                let mut reader = |o: u32, b: &mut [u8]| self.read(o, b);
                let Ok(matched) = name_is(&mut reader, record, name) else {
                    unreadable = true;
                    return false;
                };
                if matched {
                    if count < matches.len() {
                        matches[count] = record.offset;
                        count += 1;
                    } else {
                        failed = true;
                    }
                }
            }
            true
        })?;
        // Retire nothing unless every candidate's name was read: a partial
        // deletion would report failure yet take effect.
        if unreadable {
            return Err(Error::Device);
        }
        for &offset in matches.iter().take(count) {
            let state = self.region + offset as u64 + 2;
            if !self.flash.program_bits(state, VAR_DELETED) {
                failed = true;
            }
        }
        if failed { Err(Error::Device) } else { Ok(()) }
    }

    fn slot_free(&self, len: u32) -> bool {
        let Some(end) = self.write_offset.checked_add(len) else {
            return false;
        };
        if end > self.data_end {
            return false;
        }
        let mut chunk = [0u8; 64];
        let mut offset = self.write_offset;
        while offset < end {
            let n = ((end - offset) as usize).min(chunk.len());
            if !self.read(offset, &mut chunk[..n]) || chunk[..n].iter().any(|&b| b != 0xff) {
                return false;
            }
            offset += n as u32;
        }
        true
    }

    /// Rebuild the primary with only its live records through the spare half.
    fn compact(&mut self) -> Result<(), Error> {
        let half = self.half;
        if !self.erase_half(half) {
            return Err(Error::Device);
        }
        let mut offset = VARIABLE_DATA_OFFSET;
        let mut result = Ok(());
        let mut reader = |o: u32, b: &mut [u8]| self.read(o, b);
        walk(&mut reader, self.data_end, &mut |record| {
            if record.state != VAR_ADDED {
                return true;
            }
            let units = record.name_size as usize / 2;
            let mut name = [0u16; MAX_VARIABLE_NAME_LEN + 1];
            let mut bytes = [0u8; NAME_BYTES_MAX];
            let (Some(name), Some(bytes)) = (name.get_mut(..units), bytes.get_mut(..units * 2))
            else {
                result = Err(Error::Device);
                return false;
            };
            if units == 0 || !self.read(record.name_offset, bytes) {
                result = Err(Error::Device);
                return false;
            }
            for (unit, b) in name.iter_mut().zip(bytes.as_chunks::<2>().0) {
                *unit = u16::from_le_bytes(*b);
            }
            match self.superseded(record, name) {
                Ok(true) => return true,
                Ok(false) => {}
                Err(error) => {
                    result = Err(error);
                    return false;
                }
            }
            let len = record.next - record.offset;
            if offset + len > half {
                result = Err(Error::Full);
                return false;
            }
            let mut chunk = [0u8; 256];
            let mut done = 0;
            while done < len {
                let n = ((len - done) as usize).min(chunk.len());
                if !self.read(record.offset + done, &mut chunk[..n])
                    || !self
                        .flash
                        .program(self.region + (half + offset + done) as u64, &chunk[..n])
                {
                    result = Err(Error::Device);
                    return false;
                }
                done += n as u32;
            }
            offset += len;
            true
        })?;
        result?;
        // The spare becomes the authoritative copy once its header is written.
        if !self
            .flash
            .program(self.region + half as u64, &fv_headers(half))
        {
            return Err(Error::Device);
        }
        self.copy_spare_to_primary()?;
        self.write_offset = offset;
        Ok(())
    }
}

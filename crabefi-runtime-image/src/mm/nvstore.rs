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
}

static mut RECORD: [u8; RECORD_MAX] = [0; RECORD_MAX];
static mut COMPACT: [u8; MAX_STORE_SIZE] = [0; MAX_STORE_SIZE];

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

/// Walk records like crabefi-core's `walk_variables_inner`; stops at the append
/// point or at the first record it cannot parse. Returns where it stopped.
fn walk(read: Reader<'_>, data_end: u32, f: &mut dyn FnMut(&Record) -> bool) -> u32 {
    let header_size = AUTH_VAR_HEADER_SIZE as u32;
    let mut offset = VARIABLE_DATA_OFFSET;
    let mut h = [0u8; AUTH_VAR_HEADER_SIZE];
    while offset + header_size <= data_end {
        if !read(offset, &mut h) {
            return offset;
        }
        if u16::from_le_bytes([h[0], h[1]]) != VARIABLE_DATA || h[2] == 0xff {
            return offset;
        }
        let (attributes, name_size, data_size) =
            (u32_at(&h, 4), u32_at(&h, 0x24), u32_at(&h, 0x28));
        if attributes == u32::MAX || name_size == u32::MAX || data_size == u32::MAX {
            return offset;
        }
        let Some(name_offset) = offset.checked_add(header_size) else {
            return offset;
        };
        let Some(data_offset) = name_offset.checked_add(name_size) else {
            return offset;
        };
        let Some(end) = data_offset.checked_add(data_size) else {
            return offset;
        };
        let Some(next) =
            checked_align_up(end - offset, HEADER_ALIGNMENT).and_then(|n| offset.checked_add(n))
        else {
            return offset;
        };
        if end > data_end {
            return offset;
        }
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
            return offset;
        }
        offset = next;
    }
    offset
}

/// The record's name equals `name` (UTF-16 including the terminator).
fn name_is(read: Reader<'_>, record: &Record, name: &[u16]) -> bool {
    if record.name_size as usize != name.len() * 2 || name.len() > MAX_VARIABLE_NAME_LEN + 1 {
        return false;
    }
    let mut bytes = [0u8; NAME_BYTES_MAX];
    let bytes = &mut bytes[..name.len() * 2];
    read(record.name_offset, bytes)
        && bytes
            .chunks_exact(2)
            .zip(name)
            .all(|(b, &unit)| u16::from_le_bytes([b[0], b[1]]) == unit)
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
        }
    }

    fn read(&self, offset: u32, buf: &mut [u8]) -> bool {
        self.flash.read(self.region + offset as u64, buf)
    }

    fn read_at(&self, base: u32, offset: u32, buf: &mut [u8]) -> bool {
        self.flash
            .read(self.region + base as u64 + offset as u64, buf)
    }

    /// End of the data area if a valid authenticated store of `size` bytes starts at `base`.
    fn store_at(&self, base: u32, size: u32) -> Option<u32> {
        let mut headers = [0u8; HEADERS];
        if !self.read_at(base, 0, &mut headers) {
            return None;
        }
        varstore::validate(&headers, size)
            .filter(|valid| valid.auth_format)
            .map(|valid| VARIABLE_DATA_OFFSET + valid.data_size)
    }

    fn blank(&self, base: u32, len: u32) -> bool {
        let mut chunk = [0u8; 256];
        let mut offset = 0;
        while offset < len {
            let n = ((len - offset) as usize).min(chunk.len());
            if !self.read_at(base, offset, &mut chunk[..n]) || chunk[..n].iter().any(|&b| b != 0xff)
            {
                return false;
            }
            offset += n as u32;
        }
        true
    }

    /// First free byte after the records of the store at `base`.
    fn scan_end(&self, base: u32, data_end: u32) -> u32 {
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
            || (half as u64) % ERASE_BLOCK != 0
            || half == 0
            || (half as usize) < HEADERS + RECORD_MAX
        {
            return Err(Error::Invalid);
        }
        self.flash = flash;
        self.region = region;
        self.size = size;
        self.half = half;
        if let Some(end) = self.store_at(0, half) {
            self.data_end = end;
            if !self.blank(half, half) && !self.erase_half(half) {
                return Err(Error::Device);
            }
        } else if let Some(end) = self.store_at(0, size) {
            self.data_end = end;
            self.write_offset = self.scan_end(0, end);
            self.migrate()?;
        } else if self.store_at(half, half).is_some() {
            self.copy_spare_to_primary()?;
        } else if self.blank(0, size) {
            self.format()?;
        } else {
            return Err(Error::Corrupt);
        }
        self.write_offset = self.scan_end(0, self.data_end);
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
    fn migrate(&mut self) -> Result<(), Error> {
        if self.write_offset > self.half {
            // Records reach into the spare half, so it cannot hold the copy.
            return self.compact_in_place();
        }
        self.compact()
    }

    /// Rebuild the primary from a complete spare, then clear the spare.
    fn copy_spare_to_primary(&mut self) -> Result<(), Error> {
        let half = self.half;
        let spare_end = self.store_at(half, half).ok_or(Error::Corrupt)?;
        let end = self.scan_end(half, spare_end);
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
        if !self.flash.program(self.region, &fv_headers(half)) || !self.erase_half(half) {
            return Err(Error::Device);
        }
        self.data_end = half;
        Ok(())
    }

    /// Call `f` with every live record (VAR_ADDED, last one per name wins),
    /// its name (with terminator) and data, in store order.
    pub fn for_each_live(
        &self,
        name_buf: &mut [u16],
        data_buf: &mut [u8],
        f: &mut dyn FnMut(&Record, &[u16], &[u8]) -> Result<(), Error>,
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
            if units * 2 > bytes.len()
                || !self.read(record.name_offset, &mut bytes[..units * 2])
                || (data_len != 0 && !self.read(record.data_offset, &mut data_buf[..data_len]))
            {
                result = Err(Error::Device);
                return false;
            }
            for (unit, b) in name_buf.iter_mut().zip(bytes[..units * 2].chunks_exact(2)) {
                *unit = u16::from_le_bytes([b[0], b[1]]);
            }
            let name = &name_buf[..units];
            if self.superseded(record, name) {
                return true;
            }
            result = f(record, name, &data_buf[..data_len]);
            result.is_ok()
        });
        result
    }

    /// A later live record has the same GUID and name.
    fn superseded(&self, record: &Record, name: &[u16]) -> bool {
        let mut found = false;
        let mut reader = |o: u32, b: &mut [u8]| self.read(o, b);
        walk(&mut reader, self.data_end, &mut |other| {
            if other.offset > record.offset && other.state == VAR_ADDED && other.guid == record.guid
            {
                let mut reader = |o: u32, b: &mut [u8]| self.read(o, b);
                found = name_is(&mut reader, other, name);
            }
            !found
        });
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
        let record = unsafe { &mut (&mut *addr_of_mut!(RECORD))[..len as usize] };
        record.fill(0xff);
        record[0..2].copy_from_slice(&VARIABLE_DATA.to_le_bytes());
        record[3] = 0;
        record[4..8].copy_from_slice(&attributes.to_le_bytes());
        record[8..0x10].fill(0);
        record[0x10..0x20].copy_from_slice(&timestamp_bytes(&timestamp.unwrap_or_default()));
        record[0x20..0x24].fill(0);
        record[0x24..0x28].copy_from_slice(&(name_bytes as u32).to_le_bytes());
        record[0x28..0x2c].copy_from_slice(&(data.len() as u32).to_le_bytes());
        record[0x2c..0x3c].copy_from_slice(guid);
        for (i, unit) in name.iter().enumerate() {
            let o = AUTH_VAR_HEADER_SIZE + i * 2;
            record[o..o + 2].copy_from_slice(&unit.to_le_bytes());
        }
        let data_at = AUTH_VAR_HEADER_SIZE + name_bytes;
        record[data_at..data_at + data.len()].copy_from_slice(data);

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
        let mut failed = false;
        let mut reader = |o: u32, b: &mut [u8]| self.read(o, b);
        let mut matches = [0u32; 16];
        let mut count = 0;
        walk(&mut reader, self.data_end, &mut |record| {
            if Some(record.offset) != keep && record.state == VAR_ADDED && record.guid == *guid {
                let mut reader = |o: u32, b: &mut [u8]| self.read(o, b);
                if name_is(&mut reader, record, name) {
                    if count < matches.len() {
                        matches[count] = record.offset;
                        count += 1;
                    } else {
                        failed = true;
                    }
                }
            }
            true
        });
        for &offset in &matches[..count] {
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
            if units == 0
                || units > name.len()
                || !self.read(record.name_offset, &mut bytes[..units * 2])
            {
                result = Err(Error::Device);
                return false;
            }
            for (unit, b) in name[..units].iter_mut().zip(bytes.chunks_exact(2)) {
                *unit = u16::from_le_bytes([b[0], b[1]]);
            }
            if self.superseded(record, &name[..units]) {
                return true;
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
        });
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

    /// Rewrite a full-region store's live records into a fresh primary (one-time
    /// migration only; not power-fail safe, like the boot-time writer).
    fn compact_in_place(&mut self) -> Result<(), Error> {
        // SAFETY: single-threaded SMM; COMPACT is only used here.
        let copy = unsafe { &mut (&mut *addr_of_mut!(COMPACT))[..self.size as usize] };
        if !self.read(0, copy) {
            return Err(Error::Device);
        }
        self.format()?;
        let mut offset = VARIABLE_DATA_OFFSET;
        let mut failed = false;
        let copy_ro: &[u8] = copy;
        let mut reader = |o: u32, b: &mut [u8]| match copy_ro.get(o as usize..o as usize + b.len())
        {
            Some(src) => {
                b.copy_from_slice(src);
                true
            }
            None => false,
        };
        let data_end = self.data_end;
        walk(&mut reader, data_end, &mut |record| {
            if record.state != VAR_ADDED {
                return true;
            }
            // Keep only the last live record per name.
            let units = record.name_size as usize / 2;
            let mut name = [0u16; MAX_VARIABLE_NAME_LEN + 1];
            if units == 0 || units > name.len() {
                return true;
            }
            for (i, unit) in name[..units].iter_mut().enumerate() {
                let o = record.name_offset as usize + i * 2;
                *unit = u16::from_le_bytes([copy_ro[o], copy_ro[o + 1]]);
            }
            let mut later = false;
            let mut reader2 =
                |o: u32, b: &mut [u8]| match copy_ro.get(o as usize..o as usize + b.len()) {
                    Some(src) => {
                        b.copy_from_slice(src);
                        true
                    }
                    None => false,
                };
            walk(&mut reader2, data_end, &mut |other| {
                if other.offset > record.offset
                    && other.state == VAR_ADDED
                    && other.guid == record.guid
                {
                    let mut reader3 = |o: u32, b: &mut [u8]| match copy_ro
                        .get(o as usize..o as usize + b.len())
                    {
                        Some(src) => {
                            b.copy_from_slice(src);
                            true
                        }
                        None => false,
                    };
                    later = name_is(&mut reader3, other, &name[..units]);
                }
                !later
            });
            if later {
                return true;
            }
            let bytes = &copy_ro[record.offset as usize..record.next as usize];
            if offset as usize + bytes.len() > self.half as usize {
                failed = true;
                return false;
            }
            if !self.flash.program(self.region + offset as u64, bytes) {
                failed = true;
                return false;
            }
            offset = offset.saturating_add(bytes.len() as u32);
            true
        });
        self.write_offset = offset;
        if failed { Err(Error::Device) } else { Ok(()) }
    }
}

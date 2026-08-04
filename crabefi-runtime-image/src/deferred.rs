//! Deferred-v1 journal access using the image-local bounded scratch allocator.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::{crc32, efi, scratch};

pub const MAX_NAME_LEN: usize = 64;
pub const MAX_DATA_SIZE: usize = 32 * 1024;
pub const MAX_ENTRY_SIZE: usize = 16 * 1024;

const RECORD_MAGIC: u16 = 0xaa55;
const STATE_VALID: u8 = 0x7f;
const STATE_DELETED: u8 = 0x00;
const DEFERRED_MAGIC: u32 = 0x4642_5643;
const DEFERRED_VERSION: u8 = 1;
const HEADER_SIZE: usize = 32;
const CAPSULE_DESCRIPTOR_SIZE: usize = 16;
const RESERVATION_CAPSULE_OFFSET: usize = 4096;
const JOURNAL_OFFSET: usize = 8192;
const CAPSULE_HEADER_SIZE: usize = 28;
const RESERVATION_MARKER: [u8; 4] = *b"CRDJ";
const WINDOWS_UX_CAPSULE_GUID: [u8; 16] = [
    0x62, 0x81, 0x8c, 0x3b, 0x8c, 0x18, 0xa4, 0x46, 0xae, 0xc9, 0xbe, 0x43, 0xf1, 0xd6, 0x56, 0x97,
];
const CAPSULE_FLAGS_PERSIST_ACROSS_RESET: u32 = 0x0001_0000;

pub mod entry_flags {
    pub const IS_AUTHENTICATED: u8 = 0x01;
    pub const IS_DELETION: u8 = 0x04;
    pub const ACKNOWLEDGED: u8 = 0x80;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EntryHeader {
    flags: u8,
    reserved: [u8; 3],
    record_len: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DeferredHeader {
    magic: u32,
    version: u8,
    flags: u8,
    entry_count: u16,
    total_size: u32,
    header_crc: u32,
    data_crc: u32,
    reserved: [u8; 12],
}

impl DeferredHeader {
    const fn empty() -> Self {
        Self {
            magic: DEFERRED_MAGIC,
            version: DEFERRED_VERSION,
            flags: 0,
            entry_count: 0,
            total_size: 0,
            header_crc: 0,
            data_crc: 0,
            reserved: [0; 12],
        }
    }

    fn header_crc(self) -> u32 {
        let mut bytes = [0u8; 12];
        bytes[..4].copy_from_slice(&self.magic.to_le_bytes());
        bytes[4] = self.version;
        bytes[5] = self.flags;
        bytes[6..8].copy_from_slice(&self.entry_count.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.total_size.to_le_bytes());
        crc32::calculate(&bytes)
    }

    fn valid(self) -> bool {
        self.magic == DEFERRED_MAGIC
            && self.version == DEFERRED_VERSION
            && self.header_crc == self.header_crc()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedGuid {
    pub bytes: [u8; 16],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanosecond: u32,
    pub timezone: i16,
    pub daylight: u8,
}

impl SerializedTime {
    pub const fn zero() -> Self {
        Self {
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0,
            nanosecond: 0,
            timezone: 0,
            daylight: 0,
        }
    }

    pub fn from_abi(value: crabefi_runtime_abi::VariableTimestamp) -> Self {
        Self {
            year: value.year,
            month: value.month,
            day: value.day,
            hour: value.hour,
            minute: value.minute,
            second: value.second,
            nanosecond: value.nanosecond,
            timezone: value.timezone,
            daylight: value.daylight,
        }
    }

    pub fn to_abi(self) -> crabefi_runtime_abi::VariableTimestamp {
        crabefi_runtime_abi::VariableTimestamp {
            year: self.year,
            month: self.month,
            day: self.day,
            hour: self.hour,
            minute: self.minute,
            second: self.second,
            pad1: 0,
            nanosecond: self.nanosecond,
            timezone: self.timezone,
            daylight: self.daylight,
            pad2: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableRecord {
    pub magic: u16,
    pub state: u8,
    pub attributes: u32,
    pub guid: SerializedGuid,
    pub name: Vec<u16>,
    pub data: Vec<u8>,
    pub monotonic_count: u64,
    pub timestamp: SerializedTime,
    pub crc: u32,
}

impl VariableRecord {
    pub fn active(&self) -> bool {
        self.magic == RECORD_MAGIC && self.state == STATE_VALID
    }

    pub fn deleted(&self) -> bool {
        self.magic == RECORD_MAGIC && self.state == STATE_DELETED
    }
}

#[derive(Serialize)]
struct VariableRecordRef<'a> {
    magic: u16,
    state: u8,
    attributes: u32,
    guid: SerializedGuid,
    name: &'a [u16],
    data: &'a [u8],
    monotonic_count: u64,
    timestamp: SerializedTime,
    crc: u32,
}

#[repr(C)]
pub struct DeferredTransaction {
    bytes: [u8; MAX_ENTRY_SIZE],
}

impl DeferredTransaction {
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAX_ENTRY_SIZE],
        }
    }
}

fn initialize_journal(base: *mut u8, size: usize) -> Result<(), efi::Status> {
    if base.is_null() || size < HEADER_SIZE {
        return Err(efi::Status::DEVICE_ERROR);
    }
    // SAFETY: the handoff validated this retained writable range and the caller
    // holds the sole operation lease.
    unsafe { core::ptr::write_bytes(base, 0, size) };
    let mut header = DeferredHeader::empty();
    header.header_crc = header.header_crc();
    // SAFETY: the page-aligned retained range can hold the fixed header.
    unsafe { base.cast::<DeferredHeader>().write_unaligned(header) };
    Ok(())
}

/// Prepare the retained reservation capsule and deferred journal.
///
/// The reservation capsule makes coreboot reserve this range before optional
/// DRAM clearing. Its descriptor pointer is published persistently during the
/// preceding boot, while the actual capsule descriptor is filled only by a
/// successful post-EBS `UpdateCapsule()` call.
pub fn prepare_retained(base: *mut u8, size: usize) -> Result<u64, efi::Status> {
    if base.is_null() || size < JOURNAL_OFFSET + HEADER_SIZE || size > u32::MAX as usize {
        return Err(efi::Status::OUT_OF_RESOURCES);
    }
    write_reservation_capsule(base, size);
    clear_staged_capsule(base);
    let (journal, journal_size) = journal_range(base, size)?;
    // SAFETY: journal_range proved the fixed header lies in retained memory.
    let header = unsafe { journal.cast::<DeferredHeader>().read_unaligned() };
    if header.magic == DEFERRED_MAGIC {
        if !valid_journal(journal, journal_size, header) {
            return Err(efi::Status::DEVICE_ERROR);
        }
    } else {
        initialize_journal(journal, journal_size)?;
    }
    Ok(base as u64)
}

fn write_reservation_capsule(base: *mut u8, size: usize) {
    let capsule_size = (size - RESERVATION_CAPSULE_OFFSET) as u32;
    // SAFETY: prepare_retained checked all fixed offsets against size.
    unsafe {
        write_descriptor(
            base,
            0,
            u64::from(capsule_size),
            base.add(RESERVATION_CAPSULE_OFFSET) as u64,
        );
        let capsule = base.add(RESERVATION_CAPSULE_OFFSET);
        core::ptr::copy_nonoverlapping(WINDOWS_UX_CAPSULE_GUID.as_ptr(), capsule, 16);
        capsule
            .add(16)
            .cast::<u32>()
            .write_unaligned(CAPSULE_HEADER_SIZE as u32);
        capsule
            .add(20)
            .cast::<u32>()
            .write_unaligned(CAPSULE_FLAGS_PERSIST_ACROSS_RESET);
        capsule.add(24).cast::<u32>().write_unaligned(capsule_size);
        core::ptr::copy_nonoverlapping(
            RESERVATION_MARKER.as_ptr(),
            capsule.add(CAPSULE_HEADER_SIZE),
            RESERVATION_MARKER.len(),
        );
    }
}

fn clear_staged_capsule(base: *mut u8) {
    // SAFETY: callers validated the three fixed descriptor slots.
    unsafe {
        write_descriptor(base, 1, 0, 0);
        write_descriptor(base, 2, 0, 0);
    }
}

/// Stage one caller-provided capsule SG list behind the reservation capsule.
pub fn stage_capsule(
    base: *mut u8,
    size: usize,
    capsule_size: u32,
    scatter_gather_list: u64,
) -> Result<(), efi::Status> {
    if base.is_null()
        || size < JOURNAL_OFFSET + HEADER_SIZE
        || capsule_size < CAPSULE_HEADER_SIZE as u32
        || scatter_gather_list == 0
        || !scatter_gather_list.is_multiple_of(8)
    {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let descriptor = scatter_gather_list as *const u64;
    // SAFETY: UpdateCapsule defines scatter_gather_list as a readable physical
    // EFI_CAPSULE_BLOCK_DESCRIPTOR list and this immediate call reads its first
    // fixed-width descriptor only.
    let (length, address) = unsafe {
        (
            descriptor.read_unaligned(),
            descriptor.add(1).read_unaligned(),
        )
    };
    if length == 0 || address == 0 || length > u64::from(capsule_size) {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    // SAFETY: the retained range has all fixed descriptor slots.
    unsafe {
        write_descriptor(base, 1, length, address);
        if length == u64::from(capsule_size) {
            write_descriptor(base, 2, 0, 0);
        } else {
            write_descriptor(
                base,
                2,
                0,
                scatter_gather_list + CAPSULE_DESCRIPTOR_SIZE as u64,
            );
        }
    }
    Ok(())
}

unsafe fn write_descriptor(base: *mut u8, index: usize, length: u64, address: u64) {
    let descriptor = unsafe { base.add(index * CAPSULE_DESCRIPTOR_SIZE).cast::<u64>() };
    // SAFETY: callers prove index is within the three reserved descriptor slots.
    unsafe {
        descriptor.write_unaligned(length);
        descriptor.add(1).write_unaligned(address);
    }
}

fn journal_range(base: *mut u8, size: usize) -> Result<(*mut u8, usize), efi::Status> {
    if base.is_null() || size < JOURNAL_OFFSET + HEADER_SIZE {
        return Err(efi::Status::DEVICE_ERROR);
    }
    // SAFETY: the checked offset lies in the retained range.
    Ok((unsafe { base.add(JOURNAL_OFFSET) }, size - JOURNAL_OFFSET))
}

pub struct DeferredWrite<'a> {
    pub guid: [u8; 16],
    pub name: &'a [u16],
    pub attributes: u32,
    pub data: &'a [u8],
    pub timestamp: SerializedTime,
    pub authenticated: bool,
    pub deletion: bool,
}

pub fn queue_write(
    base: *mut u8,
    size: usize,
    transaction: &mut DeferredTransaction,
    write: DeferredWrite<'_>,
) -> Result<(), efi::Status> {
    let DeferredWrite {
        guid,
        name,
        attributes,
        data,
        timestamp,
        authenticated,
        deletion,
    } = write;
    let (base, size) = journal_range(base, size)?;
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    if data.len() > MAX_DATA_SIZE {
        return Err(efi::Status::OUT_OF_RESOURCES);
    }
    let state = if deletion && !authenticated {
        STATE_DELETED
    } else {
        STATE_VALID
    };
    let mut terminated_name = [0u16; MAX_NAME_LEN + 1];
    terminated_name[..name.len()].copy_from_slice(name);
    let serialized_name = &terminated_name[..=name.len()];
    let mut record = VariableRecordRef {
        magic: RECORD_MAGIC,
        state,
        attributes,
        guid: SerializedGuid { bytes: guid },
        name: serialized_name,
        data,
        monotonic_count: 0,
        timestamp,
        crc: 0,
    };
    let crc_len = postcard::to_slice(&record, &mut transaction.bytes)
        .map_err(|_| efi::Status::OUT_OF_RESOURCES)?
        .len();
    record.crc = crc32::calculate(&transaction.bytes[..crc_len]);
    let record_len = postcard::to_slice(&record, &mut transaction.bytes)
        .map_err(|_| efi::Status::OUT_OF_RESOURCES)?
        .len();
    if record_len > MAX_ENTRY_SIZE {
        return Err(efi::Status::OUT_OF_RESOURCES);
    }

    // SAFETY: fixed header lies inside the validated retained journal.
    let mut header = unsafe { base.cast::<DeferredHeader>().read_unaligned() };
    if !valid_journal(base, size, header) {
        return Err(efi::Status::DEVICE_ERROR);
    }
    let entry_size = core::mem::size_of::<EntryHeader>()
        .checked_add(record_len)
        .ok_or(efi::Status::OUT_OF_RESOURCES)?;
    let mut offset = HEADER_SIZE
        .checked_add(header.total_size as usize)
        .ok_or(efi::Status::OUT_OF_RESOURCES)?;
    if (offset.checked_add(entry_size).is_none_or(|end| end > size)
        || header.entry_count == u16::MAX)
        && all_acknowledged(base, header)
    {
        initialize_journal(base, size)?;
        header = unsafe { base.cast::<DeferredHeader>().read_unaligned() };
        offset = HEADER_SIZE;
    }
    if offset.checked_add(entry_size).is_none_or(|end| end > size) || header.entry_count == u16::MAX
    {
        return Err(efi::Status::OUT_OF_RESOURCES);
    }
    let mut flags = 0;
    if authenticated {
        flags |= entry_flags::IS_AUTHENTICATED;
    }
    if deletion {
        flags |= entry_flags::IS_DELETION;
    }
    let entry = EntryHeader {
        flags,
        reserved: [0; 3],
        record_len: record_len as u32,
    };
    // SAFETY: checked arithmetic proved both writes lie within the buffer.
    unsafe {
        base.add(offset)
            .cast::<EntryHeader>()
            .write_unaligned(entry);
        core::ptr::copy_nonoverlapping(
            transaction.bytes.as_ptr(),
            base.add(offset + core::mem::size_of::<EntryHeader>()),
            record_len,
        );
    }
    header.entry_count += 1;
    header.total_size += entry_size as u32;
    header.header_crc = header.header_crc();
    header.data_crc = journal_crc(base, header).ok_or(efi::Status::DEVICE_ERROR)?;
    // SAFETY: fixed header lies inside the retained buffer.
    unsafe { base.cast::<DeferredHeader>().write_unaligned(header) };
    Ok(())
}

pub fn replay(
    base: *mut u8,
    size: usize,
    transaction: &mut DeferredTransaction,
    mut apply: impl FnMut(&VariableRecord, bool, bool) -> Result<(), efi::Status>,
) -> Result<usize, efi::Status> {
    let (base, size) = journal_range(base, size)?;
    // SAFETY: fixed header lies inside the retained journal.
    let header = unsafe { base.cast::<DeferredHeader>().read_unaligned() };
    if !valid_journal(base, size, header) {
        return Err(efi::Status::DEVICE_ERROR);
    }

    let mut offset = HEADER_SIZE;
    let end = HEADER_SIZE + header.total_size as usize;
    let mut processed = 0usize;
    for _ in 0..header.entry_count {
        let entry_offset = offset;
        // valid_journal proved every entry boundary.
        let entry = unsafe { base.add(offset).cast::<EntryHeader>().read_unaligned() };
        offset += core::mem::size_of::<EntryHeader>();
        let length = entry.record_len as usize;
        if entry.flags & entry_flags::ACKNOWLEDGED != 0 {
            offset += length;
            continue;
        }
        if !scratch::preflight(length.saturating_mul(3)) {
            return Err(efi::Status::OUT_OF_RESOURCES);
        }
        // SAFETY: valid_journal proved the complete serialized record lies in range.
        let bytes = unsafe { core::slice::from_raw_parts(base.add(offset), length) };
        let record =
            postcard::from_bytes::<VariableRecord>(bytes).map_err(|_| efi::Status::DEVICE_ERROR)?;
        let crc = record_crc(&record, transaction)?;
        if crc != record.crc || !(record.active() || record.deleted()) {
            return Err(efi::Status::DEVICE_ERROR);
        }
        apply(
            &record,
            entry.flags & entry_flags::IS_AUTHENTICATED != 0,
            entry.flags & entry_flags::IS_DELETION != 0,
        )?;
        // The callback completed durable persistence. The acknowledgement bit
        // is excluded from the journal CRC, so this one-byte retained write is
        // an atomic consume point and cannot invalidate later records.
        unsafe {
            base.add(entry_offset)
                .write_volatile(entry.flags | entry_flags::ACKNOWLEDGED)
        };
        processed += 1;
        offset += length;
    }
    debug_assert_eq!(offset, end);
    Ok(processed)
}

fn valid_journal(base: *const u8, size: usize, header: DeferredHeader) -> bool {
    header.valid()
        && HEADER_SIZE
            .checked_add(header.total_size as usize)
            .is_some_and(|end| end <= size)
        && validate_entry_layout(base, header)
        && journal_crc(base, header) == Some(header.data_crc)
}

fn validate_entry_layout(base: *const u8, header: DeferredHeader) -> bool {
    let mut offset = HEADER_SIZE;
    let end = HEADER_SIZE + header.total_size as usize;
    for _ in 0..header.entry_count {
        if offset
            .checked_add(core::mem::size_of::<EntryHeader>())
            .is_none_or(|next| next > end)
        {
            return false;
        }
        // SAFETY: the fixed header boundary was checked against total_size.
        let entry = unsafe { base.add(offset).cast::<EntryHeader>().read_unaligned() };
        let length = entry.record_len as usize;
        if length == 0 || length > MAX_ENTRY_SIZE {
            return false;
        }
        let Some(next) = offset
            .checked_add(core::mem::size_of::<EntryHeader>())
            .and_then(|offset| offset.checked_add(length))
        else {
            return false;
        };
        if next > end {
            return false;
        }
        offset = next;
    }
    offset == end
}

fn journal_crc(base: *const u8, header: DeferredHeader) -> Option<u32> {
    if !validate_entry_layout(base, header) {
        return None;
    }
    let total = header.total_size as usize;
    let mut next_header = 0usize;
    Some(crc32::calculate_with(total, |index| {
        // SAFETY: validate_entry_layout proved all total_size bytes readable.
        let byte = unsafe { base.add(HEADER_SIZE + index).read() };
        if index == next_header {
            // SAFETY: this is a validated EntryHeader start.
            let entry = unsafe {
                base.add(HEADER_SIZE + index)
                    .cast::<EntryHeader>()
                    .read_unaligned()
            };
            next_header = index + core::mem::size_of::<EntryHeader>() + entry.record_len as usize;
            byte & !entry_flags::ACKNOWLEDGED
        } else {
            byte
        }
    }))
}

fn all_acknowledged(base: *const u8, header: DeferredHeader) -> bool {
    if !validate_entry_layout(base, header) {
        return false;
    }
    let mut offset = HEADER_SIZE;
    for _ in 0..header.entry_count {
        // SAFETY: layout validation established this entry boundary.
        let entry = unsafe { base.add(offset).cast::<EntryHeader>().read_unaligned() };
        if entry.flags & entry_flags::ACKNOWLEDGED == 0 {
            return false;
        }
        offset += core::mem::size_of::<EntryHeader>() + entry.record_len as usize;
    }
    true
}

fn record_crc(
    record: &VariableRecord,
    transaction: &mut DeferredTransaction,
) -> Result<u32, efi::Status> {
    let reference = VariableRecordRef {
        magic: record.magic,
        state: record.state,
        attributes: record.attributes,
        guid: record.guid,
        name: &record.name,
        data: &record.data,
        monotonic_count: record.monotonic_count,
        timestamp: record.timestamp,
        crc: 0,
    };
    let length = postcard::to_slice(&reference, &mut transaction.bytes)
        .map_err(|_| efi::Status::INVALID_PARAMETER)?
        .len();
    Ok(crc32::calculate(&transaction.bytes[..length]))
}

const _: () = assert!(core::mem::size_of::<DeferredHeader>() == HEADER_SIZE);
const _: () = assert!(core::mem::size_of::<EntryHeader>() == 8);

#[cfg(test)]
mod tests {
    use super::*;

    fn queued_fixture() -> (Vec<u8>, usize) {
        crate::scratch::activate();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut transaction = DeferredTransaction::new();
        prepare_retained(buffer.as_mut_ptr(), buffer.len()).unwrap();
        queue_write(
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut transaction,
            DeferredWrite {
                guid: [
                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                    0xee, 0xff, 0x10,
                ],
                name: &[b'T' as u16, b'e' as u16, b's' as u16, b't' as u16],
                attributes: 7,
                data: &[1, 2, 3, 4],
                timestamp: SerializedTime::zero(),
                authenticated: false,
                deletion: false,
            },
        )
        .unwrap();
        // SAFETY: prepare_retained initialized the fixed journal header.
        let header = unsafe {
            buffer
                .as_ptr()
                .add(JOURNAL_OFFSET)
                .cast::<DeferredHeader>()
                .read_unaligned()
        };
        (
            buffer,
            JOURNAL_OFFSET + HEADER_SIZE + header.total_size as usize,
        )
    }

    #[test]
    fn deferred_v1_round_trip_and_crc_rejection() {
        let _guard = crate::scratch::test_lock();
        let (mut buffer, used) = queued_fixture();
        assert_eq!(
            &buffer[JOURNAL_OFFSET..used],
            include_bytes!("../tests/fixtures/deferred-v1.bin")
        );
        let mut transaction = DeferredTransaction::new();
        let mut seen = false;
        let processed = replay(
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut transaction,
            |record, authenticated, deletion| {
                seen = true;
                assert!(!authenticated && !deletion);
                assert_eq!(
                    record.name,
                    [b'T' as u16, b'e' as u16, b's' as u16, b't' as u16, 0]
                );
                assert_eq!(record.data, [1, 2, 3, 4]);
                Ok(())
            },
        )
        .unwrap();
        assert!(seen);
        assert_eq!(processed, 1);

        let (mut corrupt, used) = queued_fixture();
        corrupt[used - 1] ^= 0x80;
        let mut called = false;
        assert_eq!(
            replay(
                corrupt.as_mut_ptr(),
                corrupt.len(),
                &mut transaction,
                |_, _, _| {
                    called = true;
                    Ok(())
                },
            ),
            Err(efi::Status::DEVICE_ERROR)
        );
        assert!(!called);

        let (mut retained, _) = queued_fixture();
        assert_eq!(
            replay(
                retained.as_mut_ptr(),
                retained.len(),
                &mut transaction,
                |_, _, _| Err(efi::Status::WRITE_PROTECTED),
            ),
            Err(efi::Status::WRITE_PROTECTED)
        );
        let mut retries = 0;
        assert_eq!(
            replay(
                retained.as_mut_ptr(),
                retained.len(),
                &mut transaction,
                |_, _, _| {
                    retries += 1;
                    Ok(())
                },
            ),
            Ok(1)
        );
        assert_eq!(retries, 1);
        assert_eq!(
            replay(
                retained.as_mut_ptr(),
                retained.len(),
                &mut transaction,
                |_, _, _| {
                    retries += 1;
                    Ok(())
                },
            ),
            Ok(0)
        );
        assert_eq!(retries, 1);
        crate::scratch::reset();
    }
}

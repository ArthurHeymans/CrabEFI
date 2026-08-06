//! Deferred-v2 journal access using a fixed zerocopy wire header.

use crabefi_efi_types::crc32;
use crabefi_runtime_abi::{
    VariableTimestamp,
    capsule::{
        CAPSULE_HEADER_SIZE, RETAINED_RESERVATION_CAPSULE_GUID, RETAINED_RESERVATION_MARKER,
        RETAINED_RESERVATION_WRAPPER_GUID,
    },
};
use zerocopy::byteorder::little_endian::{I16, U16, U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::efi;

pub const MAX_NAME_LEN: usize = 64;
pub const MAX_DATA_SIZE: usize = 32 * 1024;
pub const MAX_ENTRY_SIZE: usize = 16 * 1024;

const RECORD_MAGIC: u16 = 0xaa55;
const STATE_VALID: u8 = 0x7f;
const STATE_DELETED: u8 = 0x00;
const DEFERRED_MAGIC: u32 = 0x4642_5643;
const DEFERRED_VERSION: u8 = 2;
const HEADER_SIZE: usize = 32;
const CAPSULE_DESCRIPTOR_SIZE: usize = 16;
const RESERVATION_CAPSULE_OFFSET: usize = 4096;
const JOURNAL_OFFSET: usize = 8192;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerializedGuid {
    pub bytes: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
struct VariableTimestampWire {
    year: U16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    pad1: u8,
    nanosecond: U32,
    timezone: I16,
    daylight: u8,
    pad2: u8,
}

impl From<VariableTimestamp> for VariableTimestampWire {
    fn from(timestamp: VariableTimestamp) -> Self {
        Self {
            year: U16::new(timestamp.year),
            month: timestamp.month,
            day: timestamp.day,
            hour: timestamp.hour,
            minute: timestamp.minute,
            second: timestamp.second,
            pad1: timestamp.pad1,
            nanosecond: U32::new(timestamp.nanosecond),
            timezone: I16::new(timestamp.timezone),
            daylight: timestamp.daylight,
            pad2: timestamp.pad2,
        }
    }
}

impl From<VariableTimestampWire> for VariableTimestamp {
    fn from(timestamp: VariableTimestampWire) -> Self {
        Self {
            year: timestamp.year.get(),
            month: timestamp.month,
            day: timestamp.day,
            hour: timestamp.hour,
            minute: timestamp.minute,
            second: timestamp.second,
            pad1: timestamp.pad1,
            nanosecond: timestamp.nanosecond.get(),
            timezone: timestamp.timezone.get(),
            daylight: timestamp.daylight,
            pad2: timestamp.pad2,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
struct VariableRecordHeader {
    magic: U16,
    state: u8,
    reserved1: u8,
    attributes: U32,
    guid: [u8; 16],
    name_len: U16,
    reserved2: U16,
    data_len: U32,
    monotonic_count: U64,
    timestamp: VariableTimestampWire,
    crc: U32,
}

#[derive(Debug)]
pub struct VariableRecord<'a> {
    pub magic: u16,
    pub state: u8,
    pub attributes: u32,
    pub guid: SerializedGuid,
    pub name: [u16; MAX_NAME_LEN + 1],
    pub data: &'a [u8],
    pub timestamp: VariableTimestamp,
    pub crc: u32,
}

impl VariableRecord<'_> {
    pub fn active(&self) -> bool {
        self.magic == RECORD_MAGIC && self.state == STATE_VALID
    }

    pub fn deleted(&self) -> bool {
        self.magic == RECORD_MAGIC && self.state == STATE_DELETED
    }
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
    if header.magic != DEFERRED_MAGIC || header.version != DEFERRED_VERSION {
        // Journal wire formats are not replay-compatible. Discard entries from
        // older firmware explicitly rather than permanently rejecting retained
        // memory that still carries our magic with a different version.
        initialize_journal(journal, journal_size)?;
    } else if !valid_journal(journal, journal_size, header) {
        return Err(efi::Status::DEVICE_ERROR);
    }
    Ok(base as u64)
}

fn write_reservation_capsule(base: *mut u8, size: usize) {
    let capsule_size = (size - RESERVATION_CAPSULE_OFFSET) as u32;
    let private_capsule_size = capsule_size - CAPSULE_HEADER_SIZE as u32;
    // SAFETY: prepare_retained checked all fixed offsets against size. The
    // recognized outer wrapper lets coreboot reserve and coalesce the range;
    // the nested private GUID and marker remain the reservation identity.
    unsafe {
        write_descriptor(
            base,
            0,
            u64::from(capsule_size),
            base.add(RESERVATION_CAPSULE_OFFSET) as u64,
        );
        let wrapper = base.add(RESERVATION_CAPSULE_OFFSET);
        core::ptr::copy_nonoverlapping(
            RETAINED_RESERVATION_WRAPPER_GUID.as_ptr(),
            wrapper,
            RETAINED_RESERVATION_WRAPPER_GUID.len(),
        );
        wrapper
            .add(16)
            .cast::<u32>()
            .write_unaligned(CAPSULE_HEADER_SIZE as u32);
        wrapper
            .add(20)
            .cast::<u32>()
            .write_unaligned(CAPSULE_FLAGS_PERSIST_ACROSS_RESET);
        wrapper.add(24).cast::<u32>().write_unaligned(capsule_size);

        let private = wrapper.add(CAPSULE_HEADER_SIZE);
        core::ptr::copy_nonoverlapping(
            RETAINED_RESERVATION_CAPSULE_GUID.as_ptr(),
            private,
            RETAINED_RESERVATION_CAPSULE_GUID.len(),
        );
        private
            .add(16)
            .cast::<u32>()
            .write_unaligned(CAPSULE_HEADER_SIZE as u32);
        private
            .add(20)
            .cast::<u32>()
            .write_unaligned(CAPSULE_FLAGS_PERSIST_ACROSS_RESET);
        private
            .add(24)
            .cast::<u32>()
            .write_unaligned(private_capsule_size);
        core::ptr::copy_nonoverlapping(
            RETAINED_RESERVATION_MARKER.as_ptr(),
            private.add(CAPSULE_HEADER_SIZE),
            RETAINED_RESERVATION_MARKER.len(),
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
    pub timestamp: VariableTimestamp,
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
    let name_len = name.len() + 1;
    let name_bytes_len = name_len
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(efi::Status::OUT_OF_RESOURCES)?;
    let record_len = core::mem::size_of::<VariableRecordHeader>()
        .checked_add(name_bytes_len)
        .and_then(|length| length.checked_add(data.len()))
        .filter(|length| *length <= MAX_ENTRY_SIZE)
        .ok_or(efi::Status::OUT_OF_RESOURCES)?;
    let mut record = VariableRecordHeader {
        magic: U16::new(RECORD_MAGIC),
        state,
        reserved1: 0,
        attributes: U32::new(attributes),
        guid,
        name_len: U16::new(name_len as u16),
        reserved2: U16::new(0),
        data_len: U32::new(data.len() as u32),
        monotonic_count: U64::new(0),
        timestamp: timestamp.into(),
        crc: U32::new(0),
    };
    let header_len = core::mem::size_of::<VariableRecordHeader>();
    transaction
        .bytes
        .get_mut(..header_len)
        .ok_or(efi::Status::OUT_OF_RESOURCES)?
        .iter_mut()
        .zip(record.as_bytes())
        .for_each(|(destination, source)| *destination = *source);
    let mut offset = header_len;
    for unit in name.iter().copied().chain(core::iter::once(0)) {
        let end = offset.checked_add(2).ok_or(efi::Status::OUT_OF_RESOURCES)?;
        transaction
            .bytes
            .get_mut(offset..end)
            .ok_or(efi::Status::OUT_OF_RESOURCES)?
            .iter_mut()
            .zip(unit.to_le_bytes())
            .for_each(|(destination, source)| *destination = source);
        offset = end;
    }
    transaction
        .bytes
        .get_mut(offset..record_len)
        .ok_or(efi::Status::OUT_OF_RESOURCES)?
        .iter_mut()
        .zip(data)
        .for_each(|(destination, source)| *destination = *source);
    let serialized = transaction
        .bytes
        .get(..record_len)
        .ok_or(efi::Status::OUT_OF_RESOURCES)?;
    record.crc = U32::new(record_crc(serialized));
    transaction
        .bytes
        .get_mut(..header_len)
        .ok_or(efi::Status::OUT_OF_RESOURCES)?
        .iter_mut()
        .zip(record.as_bytes())
        .for_each(|(destination, source)| *destination = *source);

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
    _transaction: &mut DeferredTransaction,
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
        // SAFETY: valid_journal proved the complete serialized record lies in range.
        let bytes = unsafe { core::slice::from_raw_parts(base.add(offset), length) };
        let record = decode_record(bytes)?;
        let crc = record_crc(bytes);
        if crc != record.crc || !(record.active() || record.deleted()) {
            return Err(efi::Status::DEVICE_ERROR);
        }
        apply(
            &record,
            entry.flags & entry_flags::IS_AUTHENTICATED != 0,
            entry.flags & entry_flags::IS_DELETION != 0,
        )?;
        // The callback completed durable persistence. Journal CRC calculation
        // normalizes the acknowledgement bit to zero, so this one-byte logical
        // consume marker does not invalidate later records. Retention across a
        // reset is provided by the platform's deferred-buffer contract.
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

fn decode_record(bytes: &[u8]) -> Result<VariableRecord<'_>, efi::Status> {
    let (header, payload) =
        VariableRecordHeader::read_from_prefix(bytes).map_err(|_| efi::Status::DEVICE_ERROR)?;
    if header.reserved1 != 0 || header.reserved2.get() != 0 {
        return Err(efi::Status::DEVICE_ERROR);
    }
    let name_len = header.name_len.get() as usize;
    if name_len == 0 || name_len > MAX_NAME_LEN + 1 {
        return Err(efi::Status::DEVICE_ERROR);
    }
    let name_bytes_len = name_len
        .checked_mul(core::mem::size_of::<u16>())
        .ok_or(efi::Status::DEVICE_ERROR)?;
    let data_len = header.data_len.get() as usize;
    if name_bytes_len
        .checked_add(data_len)
        .is_none_or(|length| length != payload.len())
    {
        return Err(efi::Status::DEVICE_ERROR);
    }
    let mut name = [0u16; MAX_NAME_LEN + 1];
    let (name_bytes, remainder) = payload[..name_bytes_len].as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for (unit, bytes) in name[..name_len].iter_mut().zip(name_bytes) {
        *unit = u16::from_le_bytes([bytes[0], bytes[1]]);
    }
    if name[name_len - 1] != 0 || name[..name_len - 1].contains(&0) {
        return Err(efi::Status::DEVICE_ERROR);
    }
    Ok(VariableRecord {
        magic: header.magic.get(),
        state: header.state,
        attributes: header.attributes.get(),
        guid: SerializedGuid { bytes: header.guid },
        name,
        data: &payload[name_bytes_len..],
        timestamp: header.timestamp.into(),
        crc: header.crc.get(),
    })
}

fn record_crc(bytes: &[u8]) -> u32 {
    const CRC_OFFSET: usize = core::mem::offset_of!(VariableRecordHeader, crc);
    const CRC_END: usize = CRC_OFFSET + core::mem::size_of::<U32>();
    crc32::calculate_with(bytes.len(), |index| {
        if (CRC_OFFSET..CRC_END).contains(&index) {
            0
        } else {
            bytes[index]
        }
    })
}

const _: () = assert!(core::mem::size_of::<DeferredHeader>() == HEADER_SIZE);
const _: () = assert!(core::mem::size_of::<EntryHeader>() == 8);
const _: () = assert!(core::mem::size_of::<VariableTimestampWire>() == 16);
const _: () = assert!(core::mem::size_of::<VariableRecordHeader>() == 60);

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
                timestamp: VariableTimestamp::default(),
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
    fn prepare_retained_discards_journals_from_other_versions() {
        let _guard = crate::scratch::test_lock();
        let mut buffer = vec![0u8; 64 * 1024];
        let journal = unsafe { buffer.as_mut_ptr().add(JOURNAL_OFFSET) };
        let mut old_header = DeferredHeader::empty();
        old_header.version = DEFERRED_VERSION - 1;
        old_header.entry_count = 1;
        old_header.total_size = 8;
        old_header.header_crc = old_header.header_crc();
        // SAFETY: the buffer has room for the fixed journal header.
        unsafe { journal.cast::<DeferredHeader>().write_unaligned(old_header) };

        prepare_retained(buffer.as_mut_ptr(), buffer.len()).unwrap();

        // SAFETY: prepare_retained initialized the fixed journal header.
        let header = unsafe { journal.cast::<DeferredHeader>().read_unaligned() };
        assert!(header.valid());
        assert_eq!(header.entry_count, 0);
        assert_eq!(header.total_size, 0);
        assert_eq!(header.data_crc, crc32::calculate(&[]));
        crate::scratch::reset();
    }

    #[test]
    fn retained_reservation_wraps_private_guid_and_marker() {
        let _guard = crate::scratch::test_lock();
        let mut buffer = vec![0u8; 64 * 1024];
        prepare_retained(buffer.as_mut_ptr(), buffer.len()).unwrap();
        let wrapper = &buffer[RESERVATION_CAPSULE_OFFSET..];
        assert_eq!(&wrapper[..16], RETAINED_RESERVATION_WRAPPER_GUID.as_slice());
        assert_eq!(
            u32::from_le_bytes(wrapper[24..28].try_into().unwrap()) as usize,
            wrapper.len()
        );
        let private = &wrapper[CAPSULE_HEADER_SIZE..];
        assert_eq!(&private[..16], RETAINED_RESERVATION_CAPSULE_GUID.as_slice());
        assert_eq!(
            u32::from_le_bytes(private[24..28].try_into().unwrap()) as usize,
            private.len()
        );
        assert_eq!(
            &private[CAPSULE_HEADER_SIZE..CAPSULE_HEADER_SIZE + 4],
            RETAINED_RESERVATION_MARKER.as_slice()
        );
        const WINDOWS_UX_GUID: [u8; 16] = [
            0x62, 0x81, 0x8c, 0x3b, 0x8c, 0x18, 0xa4, 0x46, 0xae, 0xc9, 0xbe, 0x43, 0xf1, 0xd6,
            0x56, 0x97,
        ];
        assert_ne!(&private[..16], WINDOWS_UX_GUID.as_slice());
        crate::scratch::reset();
    }

    #[test]
    fn deferred_v2_round_trip_and_crc_rejection() {
        let _guard = crate::scratch::test_lock();
        let (mut buffer, used) = queued_fixture();
        assert_eq!(
            &buffer[JOURNAL_OFFSET..used],
            include_bytes!("../tests/fixtures/deferred-v2.bin")
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
                    &record.name[..5],
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

//! Retained deferred region: reservation capsule, staged capsule descriptors
//! and the deferred variable journal.
//!
//! The journal is a crash-consistency mechanism, not an authenticity boundary:
//! its CRC32 guards against torn writes and unrelated memory damage, but any
//! attacker who can rewrite the journal can already issue runtime service
//! calls directly. Writes are queued only after the in-image policy checks
//! (including signature verification for authenticated variables) have
//! accepted them.

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

#[cfg(feature = "secure-boot")]
use crate::auth::MAX_AUTHENTICATED_ENVELOPE_SIZE;
use crate::efi;

pub const MAX_NAME_LEN: usize = 64;
/// Records carry the complete authenticated input envelope so a full-width
/// envelope always fits a single journal entry.
#[cfg(feature = "secure-boot")]
pub const MAX_DATA_SIZE: usize = MAX_AUTHENTICATED_ENVELOPE_SIZE;
#[cfg(not(feature = "secure-boot"))]
pub const MAX_DATA_SIZE: usize = crabefi_runtime_abi::MAX_VARIABLE_DATA_SIZE;
pub const MAX_ENTRY_SIZE: usize =
    core::mem::size_of::<VariableRecordHeader>() + (MAX_NAME_LEN + 1) * 2 + MAX_DATA_SIZE;

// Capacity note: the retained deferred buffer reserved by the payload linker
// scripts is 128 KiB, of which [`JOURNAL_OFFSET`] is reserved for the private
// reservation capsule. That leaves room for two full-width entries plus the
// journal header; smaller entries pack more densely. If `MAX_DATA_SIZE` or
// `MAX_ENTRY_SIZE` grows, grow the linker reservation to match.

const RECORD_MAGIC: u16 = 0xaa55;
const STATE_VALID: u8 = 0x7f;
const STATE_DELETED: u8 = 0x00;
const DEFERRED_MAGIC: u32 = 0x4642_5643;
const DEFERRED_VERSION: u8 = 3;
const HEADER_SIZE: usize = core::mem::size_of::<DeferredHeader>();
const ENTRY_HEADER_SIZE: usize = core::mem::size_of::<EntryHeader>();
const RESERVATION_CAPSULE_OFFSET: usize = 4096;
const JOURNAL_OFFSET: usize = 8192;
const CAPSULE_FLAGS_PERSIST_ACROSS_RESET: u32 = 0x0001_0000;

mod entry_flags {
    pub const IS_AUTHENTICATED: u8 = 0x01;
    pub const IS_DELETION: u8 = 0x04;
    pub const ACKNOWLEDGED: u8 = 0x80;
}

/// `EFI_CAPSULE_BLOCK_DESCRIPTOR`: a data block, or a continuation pointer
/// when `length` is zero.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
pub struct CapsuleBlockDescriptor {
    pub length: U64,
    pub address: U64,
}

impl CapsuleBlockDescriptor {
    const fn new(length: u64, address: u64) -> Self {
        Self {
            length: U64::new(length),
            address: U64::new(address),
        }
    }
}

/// `EFI_CAPSULE_HEADER`.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
struct CapsuleHeader {
    guid: [u8; 16],
    header_size: U32,
    flags: U32,
    image_size: U32,
}

impl CapsuleHeader {
    fn persistent(guid: [u8; 16], image_size: u32) -> Self {
        Self {
            guid,
            header_size: U32::new(CAPSULE_HEADER_SIZE as u32),
            flags: U32::new(CAPSULE_FLAGS_PERSIST_ACROSS_RESET),
            image_size: U32::new(image_size),
        }
    }
}

/// Block descriptors at the start of the region: the reservation capsule,
/// then the staged capsule's first block and its terminator or continuation.
#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
struct Descriptors {
    reservation: CapsuleBlockDescriptor,
    staged: CapsuleBlockDescriptor,
    staged_next: CapsuleBlockDescriptor,
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
struct EntryHeader {
    flags: u8,
    reserved: [u8; 3],
    record_len: U32,
}

impl EntryHeader {
    fn acknowledged(&self) -> bool {
        self.flags & entry_flags::ACKNOWLEDGED != 0
    }
}

#[repr(C)]
#[derive(Clone, Copy, FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
struct DeferredHeader {
    magic: U32,
    version: u8,
    flags: u8,
    entry_count: U16,
    total_size: U32,
    header_crc: U32,
    data_crc: U32,
    features: [u8; 8],
    reserved: [u8; 4],
}

impl DeferredHeader {
    fn empty() -> Self {
        let mut header = Self {
            magic: U32::new(DEFERRED_MAGIC),
            version: DEFERRED_VERSION,
            flags: 0,
            entry_count: U16::new(0),
            total_size: U32::new(0),
            header_crc: U32::new(0),
            data_crc: U32::new(crc32::calculate(&[])),
            features: crate::RUNTIME_IMAGE_FEATURE_BITS.to_le_bytes(),
            reserved: [0; 4],
        };
        header.header_crc = U32::new(header.header_crc());
        header
    }

    /// CRC over magic, version, flags, entry count, total size and features.
    fn header_crc(&self) -> u32 {
        const COUNTED: usize = core::mem::offset_of!(DeferredHeader, header_crc);
        let mut bytes = [0u8; COUNTED + 8];
        let (counted, features) = bytes.split_at_mut(COUNTED);
        counted.copy_from_slice(&self.as_bytes()[..COUNTED]);
        features.copy_from_slice(&self.features);
        crc32::calculate(&bytes)
    }

    fn same_format(&self) -> bool {
        self.magic.get() == DEFERRED_MAGIC && self.version == DEFERRED_VERSION
    }

    fn valid(&self) -> bool {
        self.same_format()
            && u64::from_le_bytes(self.features) == crate::RUNTIME_IMAGE_FEATURE_BITS
            && self.header_crc.get() == self.header_crc()
    }

    fn total_size(&self) -> usize {
        self.total_size.get() as usize
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

/// Scratch space for serializing one journal record.
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

pub struct DeferredWrite<'a> {
    pub guid: [u8; 16],
    pub name: &'a [u16],
    pub attributes: u32,
    pub data: &'a [u8],
    pub timestamp: VariableTimestamp,
    pub authenticated: bool,
    pub deletion: bool,
}

/// The retained buffer shared with the next boot.
///
/// Layout: capsule block [`Descriptors`] at offset 0, the reservation capsule
/// at [`RESERVATION_CAPSULE_OFFSET`] and the journal at [`JOURNAL_OFFSET`].
pub struct DeferredRegion<'a> {
    bytes: &'a mut [u8],
}

impl<'a> DeferredRegion<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }

    fn has_journal(&self) -> bool {
        self.bytes.len() >= JOURNAL_OFFSET + HEADER_SIZE
    }

    fn journal(&self) -> Result<&[u8], efi::Status> {
        self.bytes
            .get(JOURNAL_OFFSET..)
            .filter(|journal| journal.len() >= HEADER_SIZE)
            .ok_or(efi::Status::DEVICE_ERROR)
    }

    fn journal_mut(&mut self) -> Result<&mut [u8], efi::Status> {
        self.bytes
            .get_mut(JOURNAL_OFFSET..)
            .filter(|journal| journal.len() >= HEADER_SIZE)
            .ok_or(efi::Status::DEVICE_ERROR)
    }

    fn descriptors(&mut self) -> Result<&mut Descriptors, efi::Status> {
        Descriptors::mut_from_prefix(self.bytes)
            .map(|(descriptors, _)| descriptors)
            .map_err(|_| efi::Status::DEVICE_ERROR)
    }

    /// Prepare the reservation capsule and deferred journal.
    ///
    /// The reservation capsule makes coreboot reserve this range before
    /// optional DRAM clearing. Its descriptor address is published
    /// persistently during the preceding boot, while the staged capsule
    /// descriptors are filled only by a successful post-EBS `UpdateCapsule()`.
    ///
    /// # Returns
    /// The address of the descriptor list.
    pub fn prepare_retained(&mut self) -> Result<u64, efi::Status> {
        if !self.has_journal() || u32::try_from(self.bytes.len()).is_err() {
            return Err(efi::Status::OUT_OF_RESOURCES);
        }
        let journal = self.journal_mut()?;
        let header = read_header(journal)?;
        reject_profile_mismatch(&header)?;
        if !header.same_format() {
            // Journal wire formats are not replay-compatible. Discard entries
            // from other formats rather than permanently rejecting retained
            // memory that still carries our magic with a different version.
            initialize_journal(journal)?;
        } else if !valid_journal(journal, &header) {
            return Err(efi::Status::DEVICE_ERROR);
        }
        self.write_reservation_capsule()?;
        let descriptors = self.descriptors()?;
        descriptors.staged = CapsuleBlockDescriptor::new(0, 0);
        descriptors.staged_next = CapsuleBlockDescriptor::new(0, 0);
        Ok(self.bytes.as_ptr() as u64)
    }

    fn write_reservation_capsule(&mut self) -> Result<(), efi::Status> {
        let base = self.bytes.as_ptr() as u64;
        let capsule_size = self
            .bytes
            .len()
            .checked_sub(RESERVATION_CAPSULE_OFFSET)
            .and_then(|size| u32::try_from(size).ok())
            .ok_or(efi::Status::OUT_OF_RESOURCES)?;
        // The recognized outer wrapper lets coreboot reserve and coalesce the
        // range; the nested private GUID and marker remain its identity.
        self.descriptors()?.reservation = CapsuleBlockDescriptor::new(
            capsule_size.into(),
            base + RESERVATION_CAPSULE_OFFSET as u64,
        );
        let capsule = self
            .bytes
            .get_mut(RESERVATION_CAPSULE_OFFSET..)
            .ok_or(efi::Status::OUT_OF_RESOURCES)?;
        let (wrapper, capsule) =
            CapsuleHeader::mut_from_prefix(capsule).map_err(|_| efi::Status::OUT_OF_RESOURCES)?;
        *wrapper = CapsuleHeader::persistent(RETAINED_RESERVATION_WRAPPER_GUID, capsule_size);
        let (private, capsule) =
            CapsuleHeader::mut_from_prefix(capsule).map_err(|_| efi::Status::OUT_OF_RESOURCES)?;
        *private = CapsuleHeader::persistent(
            RETAINED_RESERVATION_CAPSULE_GUID,
            capsule_size - CAPSULE_HEADER_SIZE as u32,
        );
        let (marker, _) =
            <[u8; 4]>::mut_from_prefix(capsule).map_err(|_| efi::Status::OUT_OF_RESOURCES)?;
        *marker = RETAINED_RESERVATION_MARKER;
        Ok(())
    }

    /// Stage one caller-provided capsule behind the reservation capsule.
    ///
    /// # Arguments
    /// * `capsule_size` - Total size of the capsule the list describes
    /// * `scatter_gather_list` - Address of the caller's block descriptor list
    /// * `first_block` - The first descriptor of that list
    pub fn stage_capsule(
        &mut self,
        capsule_size: u32,
        scatter_gather_list: u64,
        first_block: CapsuleBlockDescriptor,
    ) -> Result<(), efi::Status> {
        if !self.has_journal() || capsule_size < CAPSULE_HEADER_SIZE as u32 {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        reject_profile_mismatch(&read_header(self.journal()?)?)?;
        let (length, address) = (first_block.length.get(), first_block.address.get());
        if length == 0
            || address == 0
            || length > u64::from(capsule_size)
            // The described physical block must not wrap; coreboot consumes
            // this descriptor pair verbatim on the next boot.
            || address.checked_add(length).is_none()
        {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        let next_descriptor = scatter_gather_list
            .checked_add(core::mem::size_of::<CapsuleBlockDescriptor>() as u64)
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        let descriptors = self.descriptors()?;
        descriptors.staged = first_block;
        descriptors.staged_next = if length == u64::from(capsule_size) {
            CapsuleBlockDescriptor::new(0, 0)
        } else {
            CapsuleBlockDescriptor::new(0, next_descriptor)
        };
        Ok(())
    }

    /// Check compatibility before the caller stages any live variable transaction.
    pub fn validate_profile(&self) -> Result<(), efi::Status> {
        let header = read_header(self.journal()?)?;
        reject_profile_mismatch(&header)?;
        if header.valid() {
            Ok(())
        } else {
            Err(efi::Status::DEVICE_ERROR)
        }
    }

    /// Append one record to the journal, recycling it when every entry has
    /// been acknowledged and the record does not fit.
    pub fn queue_write(
        &mut self,
        transaction: &mut DeferredTransaction,
        write: DeferredWrite<'_>,
    ) -> Result<(), efi::Status> {
        let journal = self.journal_mut()?;
        let mut header = read_header(journal)?;
        reject_profile_mismatch(&header)?;
        if !valid_journal(journal, &header) {
            return Err(efi::Status::DEVICE_ERROR);
        }
        let record = serialize_record(transaction, &write)?;
        let entry_size = ENTRY_HEADER_SIZE + record.len();
        let capacity = journal.len();
        let fits = |header: &DeferredHeader| {
            header.entry_count.get() != u16::MAX
                && (HEADER_SIZE + header.total_size())
                    .checked_add(entry_size)
                    .is_some_and(|end| end <= capacity)
        };
        if !fits(&header) && all_acknowledged(journal, &header) {
            header = initialize_journal(journal)?;
        }
        if !fits(&header) {
            return Err(efi::Status::OUT_OF_RESOURCES);
        }
        let mut flags = 0;
        if write.authenticated {
            flags |= entry_flags::IS_AUTHENTICATED;
        }
        if write.deletion {
            flags |= entry_flags::IS_DELETION;
        }
        let entry = EntryHeader {
            flags,
            reserved: [0; 3],
            record_len: U32::new(record.len() as u32),
        };
        let offset = HEADER_SIZE + header.total_size();
        let destination = journal
            .get_mut(offset..offset + entry_size)
            .ok_or(efi::Status::OUT_OF_RESOURCES)?;
        let (entry_bytes, record_bytes) = destination.split_at_mut(ENTRY_HEADER_SIZE);
        copy(entry_bytes, entry.as_bytes())?;
        copy(record_bytes, record)?;
        header.entry_count = U16::new(header.entry_count.get() + 1);
        header.total_size = U32::new(header.total_size.get() + entry_size as u32);
        header.header_crc = U32::new(header.header_crc());
        let data_crc = journal_body(journal, &header)
            .and_then(|body| body_crc(body, header.entry_count.get()))
            .ok_or(efi::Status::DEVICE_ERROR)?;
        header.data_crc = U32::new(data_crc);
        header
            .write_to_prefix(journal)
            .map_err(|_| efi::Status::DEVICE_ERROR)
    }

    /// Hand every unacknowledged record to `apply` in order, acknowledging
    /// each one once `apply` has durably persisted it.
    ///
    /// # Returns
    /// The number of records applied.
    pub fn replay(
        &mut self,
        mut apply: impl FnMut(&VariableRecord, bool, bool) -> Result<(), efi::Status>,
    ) -> Result<usize, efi::Status> {
        let journal = self.journal_mut()?;
        let header = read_header(journal)?;
        reject_profile_mismatch(&header)?;
        if !valid_journal(journal, &header) {
            return Err(efi::Status::DEVICE_ERROR);
        }
        let mut offset = 0;
        let mut processed = 0usize;
        for _ in 0..header.entry_count.get() {
            let body = journal_body(journal, &header).ok_or(efi::Status::DEVICE_ERROR)?;
            let entry = entry_at(body, offset).ok_or(efi::Status::DEVICE_ERROR)?;
            let next = entry.end;
            let acknowledged = entry.header.flags | entry_flags::ACKNOWLEDGED;
            if !entry.header.acknowledged() {
                let record = decode_record(entry.record)?;
                if record_crc(entry.record) != record.crc || !(record.active() || record.deleted())
                {
                    return Err(efi::Status::DEVICE_ERROR);
                }
                apply(
                    &record,
                    entry.header.flags & entry_flags::IS_AUTHENTICATED != 0,
                    entry.header.flags & entry_flags::IS_DELETION != 0,
                )?;
                // The callback completed durable persistence. Journal CRC
                // calculation masks the acknowledgement bit, so this one-byte
                // consume marker does not invalidate later records. Retention
                // across a reset is provided by the platform's deferred-buffer
                // contract.
                *journal
                    .get_mut(HEADER_SIZE + offset)
                    .ok_or(efi::Status::DEVICE_ERROR)? = acknowledged;
                processed += 1;
            }
            offset = next;
        }
        Ok(processed)
    }
}

/// Copy `source` into `destination`, which must have the same length.
fn copy(destination: &mut [u8], source: &[u8]) -> Result<(), efi::Status> {
    if destination.len() != source.len() {
        return Err(efi::Status::DEVICE_ERROR);
    }
    destination.copy_from_slice(source);
    Ok(())
}

fn read_header(journal: &[u8]) -> Result<DeferredHeader, efi::Status> {
    DeferredHeader::read_from_prefix(journal)
        .map(|(header, _)| header)
        .map_err(|_| efi::Status::DEVICE_ERROR)
}

/// Zero the journal and write an empty header.
fn initialize_journal(journal: &mut [u8]) -> Result<DeferredHeader, efi::Status> {
    journal.fill(0);
    let header = DeferredHeader::empty();
    header
        .write_to_prefix(journal)
        .map_err(|_| efi::Status::DEVICE_ERROR)?;
    Ok(header)
}

// CRC is local integrity, not authentication. Refuse a different profile before
// parsing its differently bounded entries or modifying any retained bytes.
fn reject_profile_mismatch(header: &DeferredHeader) -> Result<(), efi::Status> {
    if header.same_format()
        && u64::from_le_bytes(header.features) != crate::RUNTIME_IMAGE_FEATURE_BITS
    {
        Err(efi::Status::UNSUPPORTED)
    } else {
        Ok(())
    }
}

/// The `total_size` entry bytes following the journal header.
fn journal_body<'j>(journal: &'j [u8], header: &DeferredHeader) -> Option<&'j [u8]> {
    journal.get(HEADER_SIZE..HEADER_SIZE.checked_add(header.total_size())?)
}

fn valid_journal(journal: &[u8], header: &DeferredHeader) -> bool {
    header.valid()
        && journal_body(journal, header)
            .and_then(|body| body_crc(body, header.entry_count.get()))
            .is_some_and(|crc| crc == header.data_crc.get())
}

/// One journal entry within the journal body.
struct Entry<'a> {
    header: EntryHeader,
    record: &'a [u8],
    /// Body offset just past this entry.
    end: usize,
}

fn entry_at(body: &[u8], offset: usize) -> Option<Entry<'_>> {
    let (header, rest) = EntryHeader::read_from_prefix(body.get(offset..)?).ok()?;
    let length = header.record_len.get() as usize;
    if length == 0 || length > MAX_ENTRY_SIZE {
        return None;
    }
    Some(Entry {
        header,
        record: rest.get(..length)?,
        end: offset + ENTRY_HEADER_SIZE + length,
    })
}

/// Walk `count` entries of `body`, yielding `None` at the first malformed one.
fn entries(body: &[u8], count: u16) -> impl Iterator<Item = Option<Entry<'_>>> {
    let mut offset = Some(0);
    (0..count).map_while(move |_| {
        let entry = entry_at(body, offset?);
        offset = entry.as_ref().map(|entry| entry.end);
        Some(entry)
    })
}

/// Whether `count` well-formed entries exactly fill `body`.
fn layout_valid(body: &[u8], count: u16) -> bool {
    entries(body, count)
        .try_fold(0, |_, entry| entry.map(|entry| entry.end))
        .is_some_and(|end| end == body.len())
}

/// CRC of a well-formed body with every acknowledgement bit masked.
fn body_crc(body: &[u8], count: u16) -> Option<u32> {
    if !layout_valid(body, count) {
        return None;
    }
    let mut next_entry = 0;
    Some(crc32::calculate_with(body.len(), |index| {
        let byte = body.get(index).copied().unwrap_or(0);
        if index != next_entry {
            return byte;
        }
        next_entry = entry_at(body, index).map_or(body.len(), |entry| entry.end);
        byte & !entry_flags::ACKNOWLEDGED
    }))
}

fn all_acknowledged(journal: &[u8], header: &DeferredHeader) -> bool {
    journal_body(journal, header).is_some_and(|body| {
        let count = header.entry_count.get();
        layout_valid(body, count)
            && entries(body, count)
                .all(|entry| entry.is_some_and(|entry| entry.header.acknowledged()))
    })
}

/// Serialize `write` into the transaction scratch space.
fn serialize_record<'t>(
    transaction: &'t mut DeferredTransaction,
    write: &DeferredWrite<'_>,
) -> Result<&'t [u8], efi::Status> {
    if write.name.is_empty() || write.name.len() > MAX_NAME_LEN {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    if write.data.len() > MAX_DATA_SIZE {
        return Err(efi::Status::OUT_OF_RESOURCES);
    }
    let name_len = write.name.len() + 1;
    let name_bytes_len = name_len * core::mem::size_of::<u16>();
    let record_len =
        core::mem::size_of::<VariableRecordHeader>() + name_bytes_len + write.data.len();
    let record = transaction
        .bytes
        .get_mut(..record_len)
        .ok_or(efi::Status::OUT_OF_RESOURCES)?;
    let (header, payload) = VariableRecordHeader::mut_from_prefix(&mut *record)
        .map_err(|_| efi::Status::OUT_OF_RESOURCES)?;
    *header = VariableRecordHeader {
        magic: U16::new(RECORD_MAGIC),
        state: if write.deletion && !write.authenticated {
            STATE_DELETED
        } else {
            STATE_VALID
        },
        reserved1: 0,
        attributes: U32::new(write.attributes),
        guid: write.guid,
        name_len: U16::new(name_len as u16),
        reserved2: U16::new(0),
        data_len: U32::new(write.data.len() as u32),
        monotonic_count: U64::new(0),
        timestamp: write.timestamp.into(),
        crc: U32::new(0),
    };
    let (name_bytes, data) = payload
        .split_at_mut_checked(name_bytes_len)
        .ok_or(efi::Status::OUT_OF_RESOURCES)?;
    let (name_units, _) = name_bytes.as_chunks_mut::<2>();
    for (destination, unit) in name_units
        .iter_mut()
        .zip(write.name.iter().copied().chain(core::iter::once(0)))
    {
        *destination = unit.to_le_bytes();
    }
    copy(data, write.data)?;
    let crc = record_crc(record);
    let (header, _) = VariableRecordHeader::mut_from_prefix(&mut *record)
        .map_err(|_| efi::Status::OUT_OF_RESOURCES)?;
    header.crc = U32::new(crc);
    Ok(record)
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
    let name_bytes_len = name_len * core::mem::size_of::<u16>();
    let data_len = header.data_len.get() as usize;
    if name_bytes_len
        .checked_add(data_len)
        .is_none_or(|length| length != payload.len())
    {
        return Err(efi::Status::DEVICE_ERROR);
    }
    let (name_bytes, data) = payload
        .split_at_checked(name_bytes_len)
        .ok_or(efi::Status::DEVICE_ERROR)?;
    let mut name = [0u16; MAX_NAME_LEN + 1];
    for (unit, bytes) in name.iter_mut().zip(name_bytes.as_chunks::<2>().0) {
        *unit = u16::from_le_bytes(*bytes);
    }
    let (terminator, units) = name
        .get(..name_len)
        .and_then(<[u16]>::split_last)
        .ok_or(efi::Status::DEVICE_ERROR)?;
    if *terminator != 0 || units.contains(&0) {
        return Err(efi::Status::DEVICE_ERROR);
    }
    Ok(VariableRecord {
        magic: header.magic.get(),
        state: header.state,
        attributes: header.attributes.get(),
        guid: SerializedGuid { bytes: header.guid },
        name,
        data,
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
            bytes.get(index).copied().unwrap_or(0)
        }
    })
}

const _: () = assert!(HEADER_SIZE == 32);
const _: () = assert!(ENTRY_HEADER_SIZE == 8);
const _: () = assert!(core::mem::size_of::<CapsuleHeader>() == CAPSULE_HEADER_SIZE);
const _: () = assert!(core::mem::size_of::<VariableTimestampWire>() == 16);
const _: () = assert!(core::mem::size_of::<VariableRecordHeader>() == 60);

#[cfg(test)]
mod tests {
    use super::*;

    fn test_write(name: &[u16]) -> DeferredWrite<'_> {
        DeferredWrite {
            guid: [0x42; 16],
            name,
            attributes: 7,
            data: &[9],
            timestamp: VariableTimestamp::default(),
            authenticated: false,
            deletion: false,
        }
    }

    fn journal_header(buffer: &[u8]) -> DeferredHeader {
        read_header(&buffer[JOURNAL_OFFSET..]).unwrap()
    }

    fn queued_fixture() -> (Vec<u8>, usize) {
        let mut buffer = vec![0u8; 64 * 1024];
        let mut transaction = DeferredTransaction::new();
        let mut region = DeferredRegion::new(&mut buffer);
        region.prepare_retained().unwrap();
        region
            .queue_write(
                &mut transaction,
                DeferredWrite {
                    guid: [
                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                        0xdd, 0xee, 0xff, 0x10,
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
        let used = JOURNAL_OFFSET + HEADER_SIZE + journal_header(&buffer).total_size();
        (buffer, used)
    }

    #[test]
    fn prepare_retained_discards_journals_from_other_versions() {
        let mut buffer = vec![0u8; 64 * 1024];
        let mut old_header = DeferredHeader::empty();
        old_header.version = DEFERRED_VERSION - 1;
        old_header.entry_count = U16::new(1);
        old_header.total_size = U32::new(8);
        old_header.header_crc = U32::new(old_header.header_crc());
        old_header
            .write_to_prefix(&mut buffer[JOURNAL_OFFSET..])
            .unwrap();

        DeferredRegion::new(&mut buffer).prepare_retained().unwrap();

        let header = journal_header(&buffer);
        assert!(header.valid());
        assert_eq!(header.entry_count.get(), 0);
        assert_eq!(header.total_size.get(), 0);
        assert_eq!(header.data_crc.get(), crc32::calculate(&[]));
    }

    #[test]
    fn retained_profile_mismatch_preserves_bytes_and_never_replays() {
        let (mut buffer, _) = queued_fixture();
        let mut header = journal_header(&buffer);
        header.features = (crate::RUNTIME_IMAGE_FEATURE_BITS
            ^ crabefi_runtime_abi::feature_bits::SECURE_BOOT)
            .to_le_bytes();
        header.header_crc = U32::new(header.header_crc());
        header
            .write_to_prefix(&mut buffer[JOURNAL_OFFSET..])
            .unwrap();
        let before = buffer.clone();
        let mut transaction = DeferredTransaction::new();
        let mut region = DeferredRegion::new(&mut buffer);
        assert_eq!(region.prepare_retained(), Err(efi::Status::UNSUPPORTED));
        assert_eq!(
            region.replay(|_, _, _| panic!("mismatched journal replayed")),
            Err(efi::Status::UNSUPPORTED)
        );
        assert_eq!(region.validate_profile(), Err(efi::Status::UNSUPPORTED));
        assert_eq!(
            region.queue_write(&mut transaction, test_write(&[b'X' as u16])),
            Err(efi::Status::UNSUPPORTED)
        );
        assert!(transaction.bytes.iter().all(|byte| *byte == 0));
        assert_eq!(buffer, before);
    }

    #[test]
    fn retained_reservation_wraps_private_guid_and_marker() {
        let mut buffer = vec![0u8; 64 * 1024];
        DeferredRegion::new(&mut buffer).prepare_retained().unwrap();
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
    }

    #[test]
    fn stage_capsule_rejects_wrapping_scatter_gather_blocks() {
        let mut buffer = vec![0u8; 64 * 1024];
        assert_eq!(
            DeferredRegion::new(&mut buffer).stage_capsule(
                u32::MAX,
                0x1000,
                CapsuleBlockDescriptor::new(u32::MAX.into(), u64::MAX),
            ),
            Err(efi::Status::INVALID_PARAMETER)
        );
    }

    #[test]
    fn full_journal_recycles_only_when_every_entry_is_acknowledged() {
        // Room for exactly two entries with a one-unit name and one data byte.
        const ENTRY_SIZE: usize =
            ENTRY_HEADER_SIZE + core::mem::size_of::<VariableRecordHeader>() + 2 * 2 + 1;
        let mut buffer = vec![0u8; JOURNAL_OFFSET + HEADER_SIZE + 2 * ENTRY_SIZE];
        let mut transaction = DeferredTransaction::new();
        let mut region = DeferredRegion::new(&mut buffer);
        region.prepare_retained().unwrap();
        let name = [b'N' as u16];
        region
            .queue_write(&mut transaction, test_write(&name))
            .unwrap();
        region
            .queue_write(&mut transaction, test_write(&name))
            .unwrap();
        assert_eq!(
            region.queue_write(&mut transaction, test_write(&name)),
            Err(efi::Status::OUT_OF_RESOURCES)
        );
        assert_eq!(region.replay(|_, _, _| Ok(())), Ok(2));
        region
            .queue_write(&mut transaction, test_write(&name))
            .unwrap();
        assert_eq!(journal_header(&buffer).entry_count.get(), 1);
    }

    #[test]
    fn deferred_v3_round_trip_and_crc_rejection() {
        let (mut buffer, used) = queued_fixture();
        assert_eq!(
            &buffer[JOURNAL_OFFSET..used],
            if cfg!(feature = "secure-boot") {
                include_bytes!("../tests/fixtures/deferred-v3-full.bin")
            } else {
                include_bytes!("../tests/fixtures/deferred-v3-basic.bin")
            }
        );
        let mut seen = false;
        let processed = DeferredRegion::new(&mut buffer)
            .replay(|record, authenticated, deletion| {
                seen = true;
                assert!(!authenticated && !deletion);
                assert_eq!(
                    &record.name[..5],
                    [b'T' as u16, b'e' as u16, b's' as u16, b't' as u16, 0]
                );
                assert_eq!(record.data, [1, 2, 3, 4]);
                Ok(())
            })
            .unwrap();
        assert!(seen);
        assert_eq!(processed, 1);

        let (mut corrupt, used) = queued_fixture();
        corrupt[used - 1] ^= 0x80;
        let mut called = false;
        assert_eq!(
            DeferredRegion::new(&mut corrupt).replay(|_, _, _| {
                called = true;
                Ok(())
            }),
            Err(efi::Status::DEVICE_ERROR)
        );
        assert!(!called);

        let (mut retained, _) = queued_fixture();
        let mut region = DeferredRegion::new(&mut retained);
        // Simulate the next boot's preparation, preserving same-profile records.
        region.prepare_retained().unwrap();
        assert_eq!(
            region.replay(|_, _, _| Err(efi::Status::WRITE_PROTECTED)),
            Err(efi::Status::WRITE_PROTECTED)
        );
        let mut retries = 0;
        assert_eq!(
            region.replay(|_, _, _| {
                retries += 1;
                Ok(())
            }),
            Ok(1)
        );
        assert_eq!(retries, 1);
        assert_eq!(
            region.replay(|_, _, _| {
                retries += 1;
                Ok(())
            }),
            Ok(0)
        );
        assert_eq!(retries, 1);
    }
}

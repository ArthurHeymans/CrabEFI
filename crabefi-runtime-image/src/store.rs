//! Bounded packed EFI variable store and transaction buffer.

use crabefi_efi_types::authentication::{
    EfiSignatureList, SignatureListIterator, validate_signature_database,
};
use crabefi_efi_types::secure_boot::{
    EFI_GLOBAL_VARIABLE_GUID, SECURE_BOOT_ENABLE_NAME, SecureBootVariable, identify_key_database,
    is_status_variable,
};
use crabefi_runtime_abi::{
    MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN, MAX_VARIABLES, VariableTimestamp,
};

use crate::efi::{Status, VariableAttributes};

/// Total image-local variable payload capacity.
///
/// Variable payloads are packed rather than reserving `MAX_VARIABLE_DATA_SIZE`
/// for every slot. This keeps the runtime allocation bounded while retaining
/// the UEFI per-variable maximum.
pub const VARIABLE_ARENA_SIZE: usize = 128 * 1024;

const ZERO_TIMESTAMP: VariableTimestamp = VariableTimestamp {
    year: 0,
    month: 0,
    day: 0,
    hour: 0,
    minute: 0,
    second: 0,
    pad1: 0,
    nanosecond: 0,
    timezone: 0,
    daylight: 0,
    pad2: 0,
};

#[repr(C)]
pub struct VariableSlot {
    pub guid: [u8; 16],
    pub attributes: VariableAttributes,
    pub name_len: u16,
    pub data_len: u16,
    pub data_offset: u32,
    pub in_use: u8,
    /// Bit flags; see [`VariableSlot::FLAG_TOMBSTONE`]. Zero while in use.
    pub reserved: [u8; 3],
    pub name: [u16; MAX_VARIABLE_NAME_LEN],
    /// Timestamp of the last accepted authenticated write or deletion.
    pub timestamp: VariableTimestamp,
}

impl VariableSlot {
    /// Set on slots left behind by an authenticated deletion. A tombstone is
    /// invisible to variable lookups but keeps the variable's last
    /// authentication timestamp alive so it can neither be re-created raw nor
    /// rolled back past the deletion.
    pub const FLAG_TOMBSTONE: u8 = 1;

    pub const fn empty() -> Self {
        Self {
            guid: [0; 16],
            attributes: VariableAttributes::empty(),
            name_len: 0,
            data_len: 0,
            data_offset: 0,
            in_use: 0,
            reserved: [0; 3],
            name: [0; MAX_VARIABLE_NAME_LEN],
            timestamp: ZERO_TIMESTAMP,
        }
    }

    pub fn matches(&self, guid: &[u8; 16], name: &[u16]) -> bool {
        self.in_use != 0
            && self.guid == *guid
            && usize::from(self.name_len) == name.len()
            && self.name.get(..name.len()) == Some(name)
    }

    const fn is_tombstone(&self) -> bool {
        self.reserved[0] & Self::FLAG_TOMBSTONE != 0
    }

    fn tombstone_matches(&self, guid: &[u8; 16], name: &[u16]) -> bool {
        self.is_tombstone()
            && self.guid == *guid
            && usize::from(self.name_len) == name.len()
            && self.name.get(..name.len()) == Some(name)
    }
}

#[repr(C)]
pub struct VariableStore {
    slots: [VariableSlot; MAX_VARIABLES],
    arena: [u8; VARIABLE_ARENA_SIZE],
    auth_timestamps: [VariableTimestamp; 4],
    // Store the zero-initialized polarity so the large store stays in BSS.
    user_mode: bool,
    secure_boot: bool,
}

/// Exclusive staging storage for one SetVariable request.
#[repr(C)]
pub struct VariableTransaction {
    bytes: [u8; MAX_VARIABLE_DATA_SIZE],
}

impl VariableTransaction {
    pub const fn new() -> Self {
        Self {
            bytes: [0; MAX_VARIABLE_DATA_SIZE],
        }
    }

    fn stage(&mut self, old: &[u8], input: &[u8]) -> Result<&[u8], Status> {
        let total = old
            .len()
            .checked_add(input.len())
            .ok_or(Status::OUT_OF_RESOURCES)?;
        let destination = self
            .bytes
            .get_mut(..total)
            .ok_or(Status::OUT_OF_RESOURCES)?;
        let (prefix, suffix) = destination.split_at_mut(old.len());
        prefix.copy_from_slice(old);
        suffix.copy_from_slice(input);
        Ok(destination)
    }

    /// Stage `old` followed by the signatures of `input` it does not hold yet.
    ///
    /// UEFI forbids appending an `EFI_SIGNATURE_DATA` a signature database
    /// already contains. It also makes an append safe to repeat, which
    /// deferred replay relies on. A list left without new signatures is
    /// dropped.
    fn stage_new_signatures(&mut self, old: &[u8], input: &[u8]) -> Result<&[u8], Status> {
        if !input.is_empty() && !validate_signature_database(input) {
            return Err(Status::INVALID_PARAMETER);
        }
        let mut len = self.push(0, old)?;
        for (list, bytes) in SignatureListIterator::new(input) {
            let header = bytes
                .get(..signatures_offset(list))
                .ok_or(Status::INVALID_PARAMETER)?;
            let start = len;
            for signature in signatures(list, bytes) {
                if contains_signature(old, &list.signature_type, signature) {
                    continue;
                }
                if len == start {
                    len = self.push(len, header)?;
                }
                len = self.push(len, signature)?;
            }
            if len != start {
                // signature_list_size follows the 16-byte signature type.
                let list_size = u32::try_from(len - start).map_err(|_| Status::DEVICE_ERROR)?;
                self.push(start + 16, &list_size.to_le_bytes())?;
            }
        }
        self.bytes.get(..len).ok_or(Status::DEVICE_ERROR)
    }

    /// Copy `bytes` to offset `at`, returning the offset after them.
    fn push(&mut self, at: usize, bytes: &[u8]) -> Result<usize, Status> {
        let end = at
            .checked_add(bytes.len())
            .ok_or(Status::OUT_OF_RESOURCES)?;
        self.bytes
            .get_mut(at..end)
            .ok_or(Status::OUT_OF_RESOURCES)?
            .copy_from_slice(bytes);
        Ok(end)
    }

    pub fn data(&self, len: usize) -> Option<&[u8]> {
        self.bytes.get(..len)
    }
}

/// Whether `database` holds `signature` (owner and data) under `signature_type`.
fn contains_signature(database: &[u8], signature_type: &[u8; 16], signature: &[u8]) -> bool {
    SignatureListIterator::new(database).any(|(list, bytes)| {
        list.signature_type == *signature_type
            && signatures(list, bytes).any(|existing| existing == signature)
    })
}

/// Offset of the first `EFI_SIGNATURE_DATA` in a signature list.
fn signatures_offset(list: &EfiSignatureList) -> usize {
    EfiSignatureList::HEADER_SIZE.saturating_add(list.signature_header_size as usize)
}

/// The `EFI_SIGNATURE_DATA` entries of the list `bytes`, owner included.
fn signatures<'a>(list: &EfiSignatureList, bytes: &'a [u8]) -> impl Iterator<Item = &'a [u8]> {
    let size = list.signature_size as usize;
    let mut rest = bytes.get(signatures_offset(list)..).unwrap_or_default();
    core::iter::from_fn(move || {
        let (signature, tail) = rest.split_at_checked(size).filter(|_| size != 0)?;
        rest = tail;
        Some(signature)
    })
}

pub struct PreparedWrite {
    pub slot: usize,
    pub data_len: usize,
    pub name_len: usize,
    pub attributes: VariableAttributes,
    pub guid: [u8; 16],
    pub delete: bool,
    /// Authentication timestamp to record with the committed slot. Zero for
    /// unauthenticated writes; callers stamp it before `commit`.
    pub timestamp: VariableTimestamp,
}

impl VariableStore {
    pub const fn new() -> Self {
        Self {
            slots: [const { VariableSlot::empty() }; MAX_VARIABLES],
            arena: [0; VARIABLE_ARENA_SIZE],
            auth_timestamps: [ZERO_TIMESTAMP; 4],
            user_mode: false,
            secure_boot: false,
        }
    }

    pub fn import(
        &mut self,
        transaction: &mut VariableTransaction,
        guid: [u8; 16],
        name: &[u16],
        attributes: VariableAttributes,
        data: &[u8],
        timestamp: Option<VariableTimestamp>,
    ) -> Result<(), Status> {
        if is_status_variable(&guid, name) {
            return Ok(());
        }
        let secure_variable = identify_key_database(&guid, name);
        if data.is_empty()
            && let Some(timestamp) = timestamp
            && attributes.contains(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
        {
            // The boot side persists authenticated deletions as zero-length
            // records carrying the verified deletion timestamp. Keep it as a
            // tombstone so the floor survives the reboot.
            self.record_tombstone(guid, name, attributes, timestamp)?;
            if let Some(variable) = secure_variable {
                self.auth_timestamps[variable.index()] = timestamp;
            }
            return Ok(());
        }
        let mut prepared = self.prepare(guid, name, attributes, data.len())?;
        prepared.timestamp = timestamp.unwrap_or_default();
        self.stage(transaction, &mut prepared, data, false)?;
        self.commit(transaction, prepared, name)?;
        if let (Some(variable), Some(timestamp)) = (secure_variable, timestamp) {
            self.auth_timestamps[variable.index()] = timestamp;
        }
        self.refresh_policy();
        Ok(())
    }

    /// Last authentication timestamp recorded for a variable, including the
    /// tombstone left behind by an authenticated deletion.
    ///
    /// Returns `None` when the variable has no authenticated history. This is
    /// the anti-rollback floor enforced on later authenticated updates.
    pub fn auth_history_timestamp(
        &self,
        guid: &[u8; 16],
        name: &[u16],
    ) -> Option<VariableTimestamp> {
        self.slots.iter().find_map(|slot| {
            let authenticated_history = (slot.matches(guid, name)
                && slot
                    .attributes
                    .contains(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS))
                || slot.tombstone_matches(guid, name);
            authenticated_history.then_some(slot.timestamp)
        })
    }

    /// Record a deletion tombstone for an authenticated variable.
    fn record_tombstone(
        &mut self,
        guid: [u8; 16],
        name: &[u16],
        attributes: VariableAttributes,
        timestamp: VariableTimestamp,
    ) -> Result<(), Status> {
        if name.is_empty() || name.len() > MAX_VARIABLE_NAME_LEN {
            return Err(Status::INVALID_PARAMETER);
        }
        let index = self
            .slots
            .iter()
            .position(|slot| slot.matches(&guid, name))
            .or_else(|| {
                self.slots
                    .iter()
                    .position(|slot| slot.tombstone_matches(&guid, name))
            })
            .or_else(|| {
                self.slots
                    .iter()
                    .position(|slot| slot.in_use == 0 && !slot.is_tombstone())
            })
            .ok_or(Status::OUT_OF_RESOURCES)?;
        let slot = &mut self.slots[index];
        slot.in_use = 0;
        slot.data_len = 0;
        slot.data_offset = 0;
        slot.guid = guid;
        slot.attributes = attributes.difference(VariableAttributes::APPEND_WRITE);
        slot.name_len = name.len() as u16;
        let (slot_name, remainder) = slot.name.split_at_mut(name.len());
        slot_name.copy_from_slice(name);
        remainder.fill(0);
        slot.timestamp = timestamp;
        slot.reserved[0] |= VariableSlot::FLAG_TOMBSTONE;
        self.refresh_policy();
        Ok(())
    }

    pub fn setup_mode(&self) -> bool {
        !self.user_mode
    }

    pub fn secure_boot_enabled(&self) -> bool {
        self.secure_boot
    }

    pub fn auth_timestamp(&self, variable: SecureBootVariable) -> VariableTimestamp {
        self.auth_timestamps[variable.index()]
    }

    pub fn commit_auth_timestamp(
        &mut self,
        variable: SecureBootVariable,
        timestamp: VariableTimestamp,
    ) {
        self.auth_timestamps[variable.index()] = timestamp;
    }

    pub fn key_database_data(&self, variable: SecureBootVariable) -> Option<&[u8]> {
        self.find(variable.guid(), variable.name(), false)
            .and_then(|slot| self.data(slot))
    }

    pub fn refresh_policy(&mut self) {
        self.user_mode = cfg!(feature = "secure-boot")
            && self
                .key_database_data(SecureBootVariable::PK)
                .is_some_and(|data| !data.is_empty());
        let preference = self
            .find(&EFI_GLOBAL_VARIABLE_GUID, SECURE_BOOT_ENABLE_NAME, false)
            .and_then(|slot| self.data(slot))
            .is_some_and(|data| data.first() == Some(&1));
        self.secure_boot = self.user_mode && preference;
    }

    pub fn find(&self, guid: &[u8; 16], name: &[u16], runtime_only: bool) -> Option<&VariableSlot> {
        self.slots.iter().find(|slot| {
            slot.matches(guid, name)
                && (!runtime_only || slot.attributes.contains(VariableAttributes::RUNTIME_ACCESS))
        })
    }

    pub fn data(&self, slot: &VariableSlot) -> Option<&[u8]> {
        let offset = usize::try_from(slot.data_offset).ok()?;
        let end = offset.checked_add(usize::from(slot.data_len))?;
        self.arena.get(offset..end)
    }

    pub fn visible_slots(&self, runtime_only: bool) -> impl Iterator<Item = &VariableSlot> {
        self.slots.iter().filter(move |slot| {
            slot.in_use != 0
                && (!runtime_only || slot.attributes.contains(VariableAttributes::RUNTIME_ACCESS))
        })
    }

    pub fn prepare(
        &self,
        guid: [u8; 16],
        name: &[u16],
        attributes: VariableAttributes,
        data_len: usize,
    ) -> Result<PreparedWrite, Status> {
        if name.is_empty()
            || name.len() > MAX_VARIABLE_NAME_LEN
            || data_len > MAX_VARIABLE_DATA_SIZE
        {
            return Err(Status::INVALID_PARAMETER);
        }
        let existing = self.slots.iter().position(|slot| slot.matches(&guid, name));
        let append = attributes.contains(VariableAttributes::APPEND_WRITE);
        let delete = data_len == 0 && !append;
        let attributes = attributes.difference(VariableAttributes::APPEND_WRITE);
        let slot = match (existing, delete) {
            (Some(index), _) => {
                if !delete
                    && !append
                    && self.slots[index].attributes != attributes
                    && identify_key_database(&guid, name).is_none()
                {
                    return Err(Status::INVALID_PARAMETER);
                }
                index
            }
            (None, true) => return Err(Status::NOT_FOUND),
            // Prefer reclaiming this variable's own tombstone so re-creation
            // after an authenticated deletion does not leak slots.
            (None, false) => self
                .slots
                .iter()
                .position(|slot| slot.tombstone_matches(&guid, name))
                .or_else(|| {
                    self.slots
                        .iter()
                        .position(|slot| slot.in_use == 0 && !slot.is_tombstone())
                })
                .ok_or(Status::OUT_OF_RESOURCES)?,
        };
        Ok(PreparedWrite {
            slot,
            data_len,
            name_len: name.len(),
            attributes: existing.map_or(attributes, |index| {
                if append || delete {
                    self.slots[index].attributes
                } else {
                    attributes
                }
            }),
            guid,
            delete,
            timestamp: VariableTimestamp::default(),
        })
    }

    pub fn stage<'a>(
        &self,
        transaction: &'a mut VariableTransaction,
        prepared: &mut PreparedWrite,
        input: &[u8],
        append: bool,
    ) -> Result<&'a [u8], Status> {
        let slot = self.slots.get(prepared.slot).ok_or(Status::DEVICE_ERROR)?;
        let old = if append && slot.in_use != 0 {
            self.data(slot).ok_or(Status::DEVICE_ERROR)?
        } else {
            &[]
        };
        let signature_database = append
            && slot
                .name
                .get(..usize::from(slot.name_len))
                .is_some_and(|name| identify_key_database(&slot.guid, name).is_some());
        let staged = if signature_database && !old.is_empty() {
            transaction.stage_new_signatures(old, input)?
        } else {
            transaction.stage(old, input)?
        };
        if staged.len() > self.available_after_replacing(prepared.slot) {
            return Err(Status::OUT_OF_RESOURCES);
        }
        prepared.data_len = staged.len();
        Ok(staged)
    }

    pub fn commit(
        &mut self,
        transaction: &VariableTransaction,
        prepared: PreparedWrite,
        name: &[u16],
    ) -> Result<(), Status> {
        if prepared.delete {
            let slot = self
                .slots
                .get_mut(prepared.slot)
                .ok_or(Status::DEVICE_ERROR)?;
            slot.in_use = 0;
            slot.data_len = 0;
            slot.data_offset = 0;
            if prepared.timestamp != VariableTimestamp::default() {
                // Authenticated deletions leave a timestamped tombstone so the
                // variable cannot be re-created raw or rolled back.
                slot.attributes = prepared.attributes;
                slot.timestamp = prepared.timestamp;
                slot.reserved[0] |= VariableSlot::FLAG_TOMBSTONE;
            } else {
                slot.timestamp = VariableTimestamp::default();
            }
            self.refresh_policy();
            return Ok(());
        }

        // Slot order differs from payload order after replacing a variable.
        // Compact in increasing source-offset order so every move is leftward
        // and cannot overwrite another live payload before it is read. The
        // bounded scan needs only one flag per slot, not a second arena.
        let mut moved = [false; MAX_VARIABLES];
        let mut used = 0usize;
        loop {
            let next = self
                .slots
                .iter()
                .zip(&moved)
                .enumerate()
                .filter(|(index, (slot, done))| {
                    *index != prepared.slot && slot.in_use != 0 && !**done
                })
                .min_by_key(|(_, (slot, _))| slot.data_offset)
                .map(|(index, _)| index);
            let Some(index) = next else { break };
            let slot = self.slots.get_mut(index).ok_or(Status::DEVICE_ERROR)?;
            *moved.get_mut(index).ok_or(Status::DEVICE_ERROR)? = true;
            let old = slot.data_offset as usize;
            let len = usize::from(slot.data_len);
            let old_end = old.checked_add(len).ok_or(Status::DEVICE_ERROR)?;
            let new_end = used.checked_add(len).ok_or(Status::DEVICE_ERROR)?;
            if old_end > self.arena.len() || new_end > self.arena.len() {
                return Err(Status::DEVICE_ERROR);
            }
            if old != used {
                let arena = self.arena.as_mut_ptr();
                // SAFETY: both source and destination ranges were checked
                // against the arena above. `ptr::copy` permits overlap.
                unsafe { core::ptr::copy(arena.add(old), arena.add(used), len) };
                slot.data_offset = used as u32;
            }
            used = new_end;
        }

        let data_end = used
            .checked_add(prepared.data_len)
            .ok_or(Status::OUT_OF_RESOURCES)?;
        let source = transaction
            .bytes
            .get(..prepared.data_len)
            .ok_or(Status::DEVICE_ERROR)?;
        let destination = self
            .arena
            .get_mut(used..data_end)
            .ok_or(Status::OUT_OF_RESOURCES)?;
        destination.copy_from_slice(source);

        let slot = self
            .slots
            .get_mut(prepared.slot)
            .ok_or(Status::DEVICE_ERROR)?;
        if prepared.name_len != name.len() || prepared.name_len > slot.name.len() {
            return Err(Status::DEVICE_ERROR);
        }
        slot.in_use = 0;
        slot.guid = prepared.guid;
        slot.attributes = prepared.attributes;
        slot.name_len = prepared.name_len as u16;
        slot.data_len = prepared.data_len as u16;
        slot.data_offset = used as u32;
        let (slot_name, remainder) = slot.name.split_at_mut(prepared.name_len);
        slot_name.copy_from_slice(name);
        remainder.fill(0);
        slot.reserved[0] &= !VariableSlot::FLAG_TOMBSTONE;
        slot.timestamp = prepared.timestamp;
        slot.in_use = 1;
        self.refresh_policy();
        Ok(())
    }

    pub const fn maximum_storage() -> u64 {
        VARIABLE_ARENA_SIZE as u64
    }

    pub fn remaining_storage(&self) -> u64 {
        VARIABLE_ARENA_SIZE.saturating_sub(
            self.slots
                .iter()
                .filter(|slot| slot.in_use != 0)
                .map(|slot| usize::from(slot.data_len))
                .sum(),
        ) as u64
    }

    fn available_after_replacing(&self, slot: usize) -> usize {
        VARIABLE_ARENA_SIZE.saturating_sub(
            self.slots
                .iter()
                .enumerate()
                .filter(|(index, variable)| *index != slot && variable.in_use != 0)
                .map(|(_, variable)| usize::from(variable.data_len))
                .sum(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compaction_preserves_payloads_after_replacement_reorders_slots() {
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        let guid = [0x77; 16];
        let names = [[b'A' as u16], [b'B' as u16], [b'C' as u16]];
        let attributes =
            VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS;
        let mut expected = [std::vec![0xa1; 17], std::vec![1], std::vec![0xc3; 31]];
        for (name, data) in names.iter().zip(&expected) {
            store
                .import(&mut transaction, guid, name, attributes, data, None)
                .unwrap();
        }
        // Updating A moves its data past B and C without changing its slot.
        // Updating C must not move A over B's still-unread source bytes.
        for (round, (index, len)) in [(0, 1), (2, 48), (1, 3), (0, 62), (1, 5), (2, 11)]
            .into_iter()
            .enumerate()
        {
            expected[index] = std::vec![0xb0 + round as u8; len];
            store
                .import(
                    &mut transaction,
                    guid,
                    &names[index],
                    attributes,
                    &expected[index],
                    None,
                )
                .unwrap();
            for (name, expected) in names.iter().zip(&expected) {
                let slot = store.find(&guid, name, false).unwrap();
                assert_eq!(
                    store.data(slot),
                    Some(expected.as_slice()),
                    "name={name:?}, round={round}"
                );
            }
        }
    }

    #[test]
    fn compaction_matches_reference_across_deletions_and_slot_reuse() {
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        let guid = [0x77; 16];
        let attributes =
            VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS;
        let mut expected: [std::vec::Vec<u8>; 8] = core::array::from_fn(|_| std::vec::Vec::new());
        let mut random = 0x12345678u32;
        for step in 0..256 {
            random = random.wrapping_mul(1664525).wrapping_add(1013904223);
            let index = (random >> 24) as usize % expected.len();
            let len = if step % 5 == 0 {
                0
            } else {
                1 + ((random >> 8) as usize % 97)
            };
            if len == 0 && expected[index].is_empty() {
                continue;
            }
            expected[index] = std::vec![step as u8; len];
            store
                .import(
                    &mut transaction,
                    guid,
                    &[b'A' as u16 + index as u16],
                    attributes,
                    &expected[index],
                    None,
                )
                .unwrap();
            for (index, expected) in expected.iter().enumerate() {
                let actual = store.find(&guid, &[b'A' as u16 + index as u16], false);
                if expected.is_empty() {
                    assert!(actual.is_none());
                } else {
                    assert_eq!(
                        store.data(actual.unwrap()),
                        Some(expected.as_slice()),
                        "index={index}, step={step}"
                    );
                }
            }
        }
    }
}

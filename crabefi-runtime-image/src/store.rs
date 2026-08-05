//! Bounded packed EFI variable store and transaction buffer.

use crabefi_efi_types::secure_boot::{
    EFI_GLOBAL_VARIABLE_GUID, SECURE_BOOT_ENABLE_NAME, SecureBootVariable, identify_key_database,
    is_status_variable,
};
use crabefi_runtime_abi::{
    MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN, MAX_VARIABLES, VariableTimestamp,
};

use crate::efi;

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
    pub attributes: u32,
    pub name_len: u16,
    pub data_len: u16,
    pub data_offset: u32,
    pub in_use: u8,
    pub reserved: [u8; 3],
    pub name: [u16; MAX_VARIABLE_NAME_LEN],
}

impl VariableSlot {
    pub const fn empty() -> Self {
        Self {
            guid: [0; 16],
            attributes: 0,
            name_len: 0,
            data_len: 0,
            data_offset: 0,
            in_use: 0,
            reserved: [0; 3],
            name: [0; MAX_VARIABLE_NAME_LEN],
        }
    }

    pub fn matches(&self, guid: &[u8; 16], name: &[u16]) -> bool {
        self.in_use != 0
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
    setup_mode: bool,
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

    fn stage(&mut self, old: &[u8], input: &[u8]) -> Result<&[u8], efi::Status> {
        let total = old
            .len()
            .checked_add(input.len())
            .ok_or(efi::OUT_OF_RESOURCES)?;
        let destination = self.bytes.get_mut(..total).ok_or(efi::OUT_OF_RESOURCES)?;
        let (prefix, suffix) = destination.split_at_mut(old.len());
        prefix.copy_from_slice(old);
        suffix.copy_from_slice(input);
        Ok(destination)
    }

    pub fn data(&self, len: usize) -> Option<&[u8]> {
        self.bytes.get(..len)
    }
}

pub struct PreparedWrite {
    pub slot: usize,
    pub data_len: usize,
    pub name_len: usize,
    pub attributes: u32,
    pub guid: [u8; 16],
    pub delete: bool,
}

impl VariableStore {
    pub const fn new() -> Self {
        Self {
            slots: [const { VariableSlot::empty() }; MAX_VARIABLES],
            arena: [0; VARIABLE_ARENA_SIZE],
            auth_timestamps: [ZERO_TIMESTAMP; 4],
            setup_mode: true,
            secure_boot: false,
        }
    }

    pub fn import(
        &mut self,
        transaction: &mut VariableTransaction,
        guid: [u8; 16],
        name: &[u16],
        attributes: u32,
        data: &[u8],
        timestamp: Option<VariableTimestamp>,
    ) -> Result<(), efi::Status> {
        if is_status_variable(&guid, name) {
            return Ok(());
        }
        let secure_variable = identify_key_database(&guid, name);
        if data.is_empty()
            && let (Some(variable), Some(timestamp)) = (secure_variable, timestamp)
        {
            self.auth_timestamps[variable.index()] = timestamp;
            self.refresh_policy();
            return Ok(());
        }
        let mut prepared = self.prepare(guid, name, attributes, data.len())?;
        self.stage(transaction, &mut prepared, data, false)?;
        self.commit(transaction, prepared, name);
        if let (Some(variable), Some(timestamp)) = (secure_variable, timestamp) {
            self.auth_timestamps[variable.index()] = timestamp;
        }
        self.refresh_policy();
        Ok(())
    }

    pub fn setup_mode(&self) -> bool {
        self.setup_mode
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
        self.setup_mode = self
            .key_database_data(SecureBootVariable::PK)
            .is_none_or(|data| data.is_empty());
        let preference = self
            .find(&EFI_GLOBAL_VARIABLE_GUID, SECURE_BOOT_ENABLE_NAME, false)
            .and_then(|slot| self.data(slot))
            .is_some_and(|data| data.first() == Some(&1));
        self.secure_boot = !self.setup_mode && preference;
    }

    pub fn find(&self, guid: &[u8; 16], name: &[u16], runtime_only: bool) -> Option<&VariableSlot> {
        self.slots.iter().find(|slot| {
            slot.matches(guid, name)
                && (!runtime_only || slot.attributes & efi::VARIABLE_RUNTIME_ACCESS != 0)
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
                && (!runtime_only || slot.attributes & efi::VARIABLE_RUNTIME_ACCESS != 0)
        })
    }

    pub fn prepare(
        &self,
        guid: [u8; 16],
        name: &[u16],
        attributes: u32,
        data_len: usize,
    ) -> Result<PreparedWrite, efi::Status> {
        if name.is_empty()
            || name.len() > MAX_VARIABLE_NAME_LEN
            || data_len > MAX_VARIABLE_DATA_SIZE
        {
            return Err(efi::INVALID_PARAMETER);
        }
        let existing = self.slots.iter().position(|slot| slot.matches(&guid, name));
        let append = attributes & efi::VARIABLE_APPEND_WRITE != 0;
        let delete = data_len == 0 && !append;
        let attributes = attributes & !efi::VARIABLE_APPEND_WRITE;
        let slot = match (existing, delete) {
            (Some(index), _) => {
                if !delete
                    && !append
                    && self.slots[index].attributes != attributes
                    && identify_key_database(&guid, name).is_none()
                {
                    return Err(efi::INVALID_PARAMETER);
                }
                index
            }
            (None, true) => return Err(efi::NOT_FOUND),
            (None, false) => self
                .slots
                .iter()
                .position(|slot| slot.in_use == 0)
                .ok_or(efi::OUT_OF_RESOURCES)?,
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
        })
    }

    pub fn stage<'a>(
        &self,
        transaction: &'a mut VariableTransaction,
        prepared: &mut PreparedWrite,
        input: &[u8],
        append: bool,
    ) -> Result<&'a [u8], efi::Status> {
        let old = if append && self.slots[prepared.slot].in_use != 0 {
            self.data(&self.slots[prepared.slot])
                .ok_or(efi::DEVICE_ERROR)?
        } else {
            &[]
        };
        let staged = transaction.stage(old, input)?;
        if staged.len() > self.available_after_replacing(prepared.slot) {
            return Err(efi::OUT_OF_RESOURCES);
        }
        prepared.data_len = staged.len();
        Ok(staged)
    }

    pub fn commit(
        &mut self,
        transaction: &VariableTransaction,
        prepared: PreparedWrite,
        name: &[u16],
    ) {
        if prepared.delete {
            self.slots[prepared.slot].in_use = 0;
            self.slots[prepared.slot].data_len = 0;
            self.slots[prepared.slot].data_offset = 0;
            self.refresh_policy();
            return;
        }

        let mut used = 0usize;
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if index == prepared.slot || slot.in_use == 0 {
                continue;
            }
            let old = slot.data_offset as usize;
            let len = usize::from(slot.data_len);
            if old != used {
                self.arena.copy_within(old..old + len, used);
                slot.data_offset = used as u32;
            }
            used += len;
        }

        let slot = &mut self.slots[prepared.slot];
        slot.in_use = 0;
        slot.guid = prepared.guid;
        slot.attributes = prepared.attributes;
        slot.name_len = prepared.name_len as u16;
        slot.data_len = prepared.data_len as u16;
        slot.data_offset = used as u32;
        slot.name[..prepared.name_len].copy_from_slice(name);
        slot.name[prepared.name_len..].fill(0);
        self.arena[used..used + prepared.data_len]
            .copy_from_slice(&transaction.bytes[..prepared.data_len]);
        slot.in_use = 1;
        self.refresh_policy();
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

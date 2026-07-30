//! SetVirtualAddressMap-safe runtime state
//!
//! Runtime services must not retain ordinary Rust pointers across the
//! physical-to-virtual transition. This module stores variable metadata inline
//! and payloads as offsets from one explicitly converted root.

#![no_std]
#![feature(auto_traits, negative_impls)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use r_efi::efi::Guid;

/// Maximum number of variables in the runtime cache.
pub const MAX_VARIABLES: usize = 64;
/// Maximum variable name length, including the null terminator.
pub const MAX_VARIABLE_NAME_LEN: usize = 64;
/// Maximum payload size for one variable.
pub const MAX_VARIABLE_DATA_SIZE: usize = 16 * 1024;
/// Total payload storage available to runtime variables.
pub const BLOB_ARENA_SIZE: usize = 256 * 1024;

/// Compare a stored, null-terminated UCS-2 name with another canonical name.
///
/// Unlike `crabefi_core::efi::utils::ucs2_eq`, both slices here must include
/// their null terminator. Runtime names are stored in that canonical form.
fn ucs2_eq(stored: &[u16], name: &[u16]) -> bool {
    let stored_len = stored
        .iter()
        .position(|&unit| unit == 0)
        .map_or(stored.len(), |index| index + 1);
    stored_len == name.len() && stored[..stored_len] == *name
}

fn is_canonical_name(name: &[u16]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_VARIABLE_NAME_LEN
        && name.last() == Some(&0)
        && !name[..name.len() - 1].contains(&0)
}

/// Bytes remain meaningful after `SetVirtualAddressMap`.
///
/// This auto trait rejects pointer-bearing fields transitively. Integer fields
/// that intentionally contain addresses remain an explicit audit boundary.
///
/// # Safety
/// Implementors must contain no absolute address that requires conversion at
/// `SetVirtualAddressMap`. Manual positive impls require an explicit relocation
/// argument documented at the impl site.
pub unsafe auto trait VamSafe {}

impl<T: ?Sized> !VamSafe for *const T {}
impl<T: ?Sized> !VamSafe for *mut T {}
impl<T: ?Sized> !VamSafe for &T {}
impl<T: ?Sized> !VamSafe for &mut T {}

// This intentionally covers the ABIs used by CrabEFI and arities through eight
// arguments; it is a tripwire for current runtime state, not an exhaustive
// model of every Rust-supported ABI, variadic function, or possible arity.
macro_rules! impl_not_vam_safe_fn {
    ($(($($arg:ident),*)),* $(,)?) => {
        $(
            impl<R, $($arg,)*> !VamSafe for fn($($arg),*) -> R {}
            impl<R, $($arg,)*> !VamSafe for unsafe fn($($arg),*) -> R {}
            impl<R, $($arg,)*> !VamSafe for extern "C" fn($($arg),*) -> R {}
            impl<R, $($arg,)*> !VamSafe for unsafe extern "C" fn($($arg),*) -> R {}
            impl<R, $($arg,)*> !VamSafe for extern "efiapi" fn($($arg),*) -> R {}
            impl<R, $($arg,)*> !VamSafe for unsafe extern "efiapi" fn($($arg),*) -> R {}
        )*
    };
}

impl_not_vam_safe_fn!(
    (),
    (A0),
    (A0, A1),
    (A0, A1, A2),
    (A0, A1, A2, A3),
    (A0, A1, A2, A3, A4),
    (A0, A1, A2, A3, A4, A5),
    (A0, A1, A2, A3, A4, A5, A6),
    (A0, A1, A2, A3, A4, A5, A6, A7),
);

/// Errors returned by the fixed runtime variable store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeStateError {
    /// A name is malformed, or a name or payload exceeds the fixed UEFI limit.
    InvalidSize,
    /// No metadata slot or blob-arena space remains.
    OutOfResources,
}

/// An arena-relative payload slice.
#[repr(C)]
#[derive(Clone, Copy)]
struct RtSlice {
    off: u32,
    len: u32,
}

impl RtSlice {
    const fn empty() -> Self {
        Self { off: 0, len: 0 }
    }
}

/// Fixed metadata for one runtime variable.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuntimeVariable {
    name: [u16; MAX_VARIABLE_NAME_LEN],
    vendor_guid: Guid,
    attributes: u32,
    data: RtSlice,
    in_use: bool,
}

impl RuntimeVariable {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_VARIABLE_NAME_LEN],
            vendor_guid: Guid::from_fields(0, 0, 0, 0, 0, &[0; 6]),
            attributes: 0,
            data: RtSlice::empty(),
            in_use: false,
        }
    }

    /// Null-terminated UCS-2 variable name.
    pub fn name(&self) -> &[u16] {
        let len = self
            .name
            .iter()
            .position(|&unit| unit == 0)
            .map_or(self.name.len(), |index| index + 1);
        &self.name[..len]
    }

    /// Variable vendor GUID.
    pub fn vendor_guid(&self) -> Guid {
        self.vendor_guid
    }

    /// UEFI variable attributes.
    pub fn attributes(&self) -> u32 {
        self.attributes
    }

    /// Payload length in bytes.
    pub fn data_size(&self) -> usize {
        self.data.len as usize
    }
}

/// Pointer-free runtime state reached through one converted root.
#[repr(C)]
pub struct RuntimeState {
    variables: [RuntimeVariable; MAX_VARIABLES],
    blobs_used: u32,
    /// Whether the platform is in Secure Boot setup mode.
    pub setup_mode: bool,
    /// Whether Secure Boot policy is enabled.
    pub secure_boot_enabled: bool,
    blobs: [u8; BLOB_ARENA_SIZE],
}

impl RuntimeState {
    const fn new() -> Self {
        Self {
            variables: [const { RuntimeVariable::empty() }; MAX_VARIABLES],
            blobs_used: 0,
            setup_mode: true,
            secure_boot_enabled: false,
            blobs: [0; BLOB_ARENA_SIZE],
        }
    }

    fn data(&self, variable: &RuntimeVariable) -> Option<&[u8]> {
        let start = variable.data.off as usize;
        let end = start.checked_add(variable.data.len as usize)?;
        self.blobs.get(start..end)
    }

    /// Iterate over valid active variables and their payloads.
    pub fn iter(&self) -> impl Iterator<Item = (&RuntimeVariable, &[u8])> {
        self.variables
            .iter()
            .filter(|variable| variable.in_use)
            .filter_map(move |variable| self.data(variable).map(|data| (variable, data)))
    }

    /// Find a variable by vendor GUID and canonical null-terminated name.
    pub fn get(&self, guid: &Guid, name: &[u16]) -> Option<(&RuntimeVariable, &[u8])> {
        self.iter()
            .find(|(variable, _)| variable.vendor_guid == *guid && ucs2_eq(&variable.name, name))
    }

    fn allocate_blob(&mut self, data: &[u8]) -> Option<RtSlice> {
        let start = self.blobs_used as usize;
        let end = start.checked_add(data.len())?;
        if end > self.blobs.len() {
            return None;
        }
        self.blobs[start..end].copy_from_slice(data);
        self.blobs_used = end as u32;
        Some(RtSlice {
            off: start as u32,
            len: data.len() as u32,
        })
    }

    fn compact(&mut self) -> usize {
        let old_used = self.blobs_used as usize;
        let mut dropped = 0usize;
        for variable in &mut self.variables {
            if !variable.in_use {
                continue;
            }
            let start = variable.data.off as usize;
            let valid = start
                .checked_add(variable.data.len as usize)
                .is_some_and(|end| end <= old_used);
            if !valid {
                *variable = RuntimeVariable::empty();
                dropped += 1;
            }
        }

        // Metadata slot order can differ from arena order after replacements.
        // Move payloads in increasing source-offset order so an earlier move
        // cannot overwrite a later source that has not been copied yet.
        let mut indices = [0u8; MAX_VARIABLES];
        let mut count = 0usize;
        for (index, variable) in self.variables.iter().enumerate() {
            if variable.in_use {
                indices[count] = index as u8;
                count += 1;
            }
        }
        indices[..count].sort_unstable_by_key(|index| {
            let variable = &self.variables[*index as usize];
            (variable.data.off, *index)
        });

        let mut next = 0usize;
        for index in indices[..count].iter().map(|index| *index as usize) {
            let variable = &mut self.variables[index];
            let old_start = variable.data.off as usize;
            let old_end = old_start + variable.data.len as usize;
            if old_start != next {
                self.blobs.copy_within(old_start..old_end, next);
            }
            variable.data.off = next as u32;
            next += variable.data.len as usize;
        }
        self.blobs[next..old_used].fill(0);
        self.blobs_used = next as u32;
        dropped
    }

    /// Replace or insert a variable without allocation.
    pub fn set_variable(
        &mut self,
        guid: Guid,
        name: &[u16],
        attributes: u32,
        data: &[u8],
    ) -> Result<usize, RuntimeStateError> {
        if !is_canonical_name(name) || data.len() > MAX_VARIABLE_DATA_SIZE {
            return Err(RuntimeStateError::InvalidSize);
        }

        let existing = self
            .variables
            .iter()
            .position(|var| var.in_use && var.vendor_guid == guid && ucs2_eq(&var.name, name));
        let index = match existing {
            Some(index) => index,
            None => self
                .variables
                .iter()
                .position(|var| !var.in_use)
                .ok_or(RuntimeStateError::OutOfResources)?,
        };

        // Check capacity before changing metadata, so a failed replacement
        // leaves the old value intact as required by UEFI SetVariable.
        let old_len = existing.map_or(0, |old| self.variables[old].data_size());
        let live_without_old = self.used_bytes().saturating_sub(old_len);
        if live_without_old
            .checked_add(data.len())
            .is_none_or(|required| required > self.blobs.len())
        {
            return Err(RuntimeStateError::OutOfResources);
        }

        // Avoid the 256 KiB compaction on the common path. If the unused tail
        // cannot hold the new payload, remove only the old metadata and compact
        // once; the capacity check above guarantees the retry will succeed.
        let (blob, dropped) = if let Some(blob) = self.allocate_blob(data) {
            (blob, 0)
        } else {
            if let Some(old) = existing {
                self.variables[old].in_use = false;
            }
            let dropped = self.compact();
            (
                self.allocate_blob(data)
                    .ok_or(RuntimeStateError::OutOfResources)?,
                dropped,
            )
        };

        let variable = &mut self.variables[index];
        variable.name.fill(0);
        variable.name[..name.len()].copy_from_slice(name);
        variable.vendor_guid = guid;
        variable.attributes = attributes;
        variable.data = blob;
        variable.in_use = true;
        Ok(dropped)
    }

    /// Delete a variable from the runtime cache.
    pub fn delete_variable(&mut self, guid: &Guid, name: &[u16]) -> bool {
        let Some(index) = self
            .variables
            .iter()
            .position(|var| var.in_use && var.vendor_guid == *guid && ucs2_eq(&var.name, name))
        else {
            return false;
        };
        self.variables[index] = RuntimeVariable::empty();
        true
    }

    /// Bytes currently occupied by active runtime variable payloads.
    pub fn used_bytes(&self) -> usize {
        self.iter().map(|(_, data)| data.len()).sum()
    }

    /// Reset the arena before boot state is frozen into it.
    pub fn reset(&mut self, setup_mode: bool, secure_boot_enabled: bool) {
        self.variables.fill(RuntimeVariable::empty());
        self.blobs.fill(0);
        self.blobs_used = 0;
        self.setup_mode = setup_mode;
        self.secure_boot_enabled = secure_boot_enabled;
    }
}

#[unsafe(link_section = ".runtime_state")]
static mut RUNTIME_STATE: RuntimeState = RuntimeState::new();

static RUNTIME_STATE_PTR: AtomicPtr<RuntimeState> = AtomicPtr::new(core::ptr::null_mut());
static RUNTIME_STATE_BORROWED: AtomicBool = AtomicBool::new(false);

struct BorrowGuard;

impl BorrowGuard {
    fn acquire() -> Self {
        assert!(
            RUNTIME_STATE_BORROWED
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok(),
            "re-entrant runtime state access"
        );
        Self
    }
}

impl Drop for BorrowGuard {
    fn drop(&mut self) {
        RUNTIME_STATE_BORROWED.store(false, Ordering::Release);
    }
}

/// Initialize the runtime root and its empty arena.
pub fn init() {
    let ptr = &raw mut RUNTIME_STATE;
    RUNTIME_STATE_PTR.store(ptr, Ordering::Release);
}

/// Access the current runtime root without letting a borrow escape.
pub fn with<R>(f: impl FnOnce(&RuntimeState) -> R) -> R {
    let _guard = BorrowGuard::acquire();
    let ptr = RUNTIME_STATE_PTR.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "runtime state is not initialized");
    // SAFETY: the root is initialized before use and the borrow guard prevents
    // aliasing through nested runtime-state access. The closure cannot retain
    // the reference after this call.
    unsafe { f(&*ptr) }
}

/// Mutate the current runtime root without letting a borrow escape.
pub fn with_mut<R>(f: impl FnOnce(&mut RuntimeState) -> R) -> R {
    let _guard = BorrowGuard::acquire();
    let ptr = RUNTIME_STATE_PTR.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "runtime state is not initialized");
    // SAFETY: the borrow guard serializes both shared and mutable access, and
    // the closure cannot retain the reference after this call.
    unsafe { f(&mut *ptr) }
}

/// Physical address of the runtime root.
pub fn physical_address() -> u64 {
    &raw const RUNTIME_STATE as u64
}

/// Address currently stored in the converted root pointer.
pub fn current_address() -> u64 {
    RUNTIME_STATE_PTR.load(Ordering::Acquire) as u64
}

/// Convert the single runtime root after `SetVirtualAddressMap`.
///
/// # Safety
/// The caller must supply the live, aligned virtual alias of the linker-defined
/// runtime state and call this exactly once from SVAM.
pub unsafe fn relocate(new_ptr: *mut RuntimeState) {
    assert!(!new_ptr.is_null(), "runtime state virtual pointer is null");
    assert_eq!(
        new_ptr as usize % core::mem::align_of::<RuntimeState>(),
        0,
        "runtime state virtual pointer is misaligned"
    );
    // SAFETY: null and alignment were checked above; the caller guarantees the
    // pointer names the live virtual alias of RuntimeState.
    let new_ptr = unsafe { core::ptr::NonNull::new_unchecked(new_ptr) }.as_ptr();
    RUNTIME_STATE_PTR.store(new_ptr, Ordering::Release);
}

const _: () = {
    const fn assert_vam_safe<T: VamSafe>() {}
    assert_vam_safe::<RuntimeState>();
};

#[cfg(test)]
mod tests {
    use super::*;

    fn guid(id: u32) -> Guid {
        Guid::from_fields(id, 0, 0, 0, 0, &[0; 6])
    }

    fn name(id: u16) -> [u16; 2] {
        [id, 0]
    }

    fn set(state: &mut RuntimeState, id: u32, name_id: u16, data: &[u8]) {
        assert_eq!(state.set_variable(guid(id), &name(name_id), 7, data), Ok(0));
    }

    fn stored_payload(state: &RuntimeState, id: u32, name_id: u16) -> &[u8] {
        match state.get(&guid(id), &name(name_id)) {
            Some((_, payload)) => payload,
            None => panic!("test variable was not found"),
        }
    }

    #[test]
    fn stores_and_resolves_payload_by_offset() {
        let mut state = RuntimeState::new();
        set(&mut state, 1, 1, b"Crab");
        assert_eq!(stored_payload(&state, 1, 1), b"Crab");
    }

    #[test]
    fn replacement_compacts_a_full_arena() {
        let mut state = RuntimeState::new();
        let payload = [0x5a; MAX_VARIABLE_DATA_SIZE];
        for id in 0..(BLOB_ARENA_SIZE / MAX_VARIABLE_DATA_SIZE) {
            set(&mut state, id as u32, id as u16 + 1, &payload);
        }
        assert_eq!(state.used_bytes(), BLOB_ARENA_SIZE);

        let replacement = [0xa5; MAX_VARIABLE_DATA_SIZE];
        set(&mut state, 3, 4, &replacement);
        assert_eq!(stored_payload(&state, 3, 4), &replacement);
        assert_eq!(state.used_bytes(), BLOB_ARENA_SIZE);
    }

    #[test]
    fn failed_replacement_preserves_previous_value() {
        let mut state = RuntimeState::new();
        set(&mut state, 0, 1, b"x");
        let payload = [0x5a; MAX_VARIABLE_DATA_SIZE];
        for id in 1..(BLOB_ARENA_SIZE / MAX_VARIABLE_DATA_SIZE) {
            set(&mut state, id as u32, id as u16 + 1, &payload);
        }
        let tail = [0x33; MAX_VARIABLE_DATA_SIZE - 1];
        set(&mut state, 63, 63, &tail);
        assert_eq!(state.used_bytes(), BLOB_ARENA_SIZE);

        assert_eq!(
            state.set_variable(guid(0), &name(1), 7, b"xx"),
            Err(RuntimeStateError::OutOfResources)
        );
        assert_eq!(stored_payload(&state, 0, 1), b"x");
    }

    #[test]
    fn compaction_preserves_payloads_when_slot_and_arena_order_differ() {
        let mut state = RuntimeState::new();
        set(&mut state, 1, 1, b"old");
        set(&mut state, 2, 2, b"second");
        set(&mut state, 1, 1, b"replacement");
        assert_eq!(state.compact(), 0);

        assert_eq!(stored_payload(&state, 1, 1), b"replacement");
        assert_eq!(stored_payload(&state, 2, 2), b"second");
    }

    #[test]
    fn compaction_reports_corrupt_entries() {
        let mut state = RuntimeState::new();
        set(&mut state, 1, 1, b"value");
        state.variables[0].data.off = BLOB_ARENA_SIZE as u32;
        assert_eq!(state.compact(), 1);
        assert!(state.get(&guid(1), &name(1)).is_none());
    }

    #[test]
    fn accepts_maximum_name_and_rejects_malformed_names() {
        let mut state = RuntimeState::new();
        assert_eq!(
            state.set_variable(guid(1), &[1], 7, b"value"),
            Err(RuntimeStateError::InvalidSize)
        );

        let mut maximum = [1; MAX_VARIABLE_NAME_LEN];
        maximum[MAX_VARIABLE_NAME_LEN - 1] = 0;
        assert_eq!(state.set_variable(guid(1), &maximum, 7, b"value"), Ok(0));

        let mut overlong = [1; MAX_VARIABLE_NAME_LEN + 1];
        overlong[MAX_VARIABLE_NAME_LEN] = 0;
        assert_eq!(
            state.set_variable(guid(2), &overlong, 7, b"value"),
            Err(RuntimeStateError::InvalidSize)
        );
    }

    #[test]
    fn deletion_releases_space_on_next_compaction() {
        let mut state = RuntimeState::new();
        set(&mut state, 1, 1, b"one");
        set(&mut state, 2, 2, b"two");
        assert!(state.delete_variable(&guid(1), &name(1)));
        set(&mut state, 2, 2, b"updated");
        assert_eq!(state.used_bytes(), 7);
    }
}

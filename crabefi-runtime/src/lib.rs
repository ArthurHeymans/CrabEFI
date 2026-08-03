//! SetVirtualAddressMap-safe runtime state
//!
//! Runtime services must not retain ordinary Rust pointers across the
//! physical-to-virtual transition. This module stores variable metadata inline
//! and payloads as offsets from one explicitly converted root.

#![no_std]
#![feature(auto_traits, negative_impls)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use r_efi::efi::Guid;

/// Maximum number of variables in the runtime cache.
pub const MAX_VARIABLES: usize = 64;
/// Maximum variable name length, including the null terminator.
pub const MAX_VARIABLE_NAME_LEN: usize = 64;
/// Maximum payload size for one variable.
pub const MAX_VARIABLE_DATA_SIZE: usize = 16 * 1024;
/// Total payload storage available to runtime variables.
///
/// The boot cache permits one maximum-sized payload in every metadata slot.
/// Keep the runtime arena at the same capacity so freezing cannot silently
/// discard a valid boot-time runtime variable.
pub const BLOB_ARENA_SIZE: usize = MAX_VARIABLES * MAX_VARIABLE_DATA_SIZE;

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

#[repr(C)]
#[derive(Clone, Copy)]
struct ReplayEntry {
    name: [u16; MAX_VARIABLE_NAME_LEN],
    vendor_guid: Guid,
    timestamp: [u8; 16],
    in_use: bool,
}

impl ReplayEntry {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_VARIABLE_NAME_LEN],
            vendor_guid: Guid::from_fields(0, 0, 0, 0, 0, &[0; 6]),
            timestamp: [0; 16],
            in_use: false,
        }
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
    /// EFI_TIME bytes for the last authenticated write, or zero for none.
    auth_timestamp: [u8; 16],
    in_use: bool,
}

impl RuntimeVariable {
    const fn empty() -> Self {
        Self {
            name: [0; MAX_VARIABLE_NAME_LEN],
            vendor_guid: Guid::from_fields(0, 0, 0, 0, 0, &[0; 6]),
            attributes: 0,
            data: RtSlice::empty(),
            auth_timestamp: [0; 16],
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

    /// Timestamp of the last authenticated write, if one is recorded.
    pub fn auth_timestamp(&self) -> Option<[u8; 16]> {
        (self.auth_timestamp != [0; 16]).then_some(self.auth_timestamp)
    }
}

/// Pointer-free Secure Boot mode and policy state.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecureBootStatus {
    setup_mode: bool,
    secure_boot_enabled: bool,
}

impl SecureBootStatus {
    /// Initial state before a platform key is enrolled.
    pub const SETUP: Self = Self {
        setup_mode: true,
        secure_boot_enabled: false,
    };

    /// Whether the platform is in Secure Boot setup mode.
    pub const fn setup_mode(self) -> bool {
        self.setup_mode
    }

    /// Whether Secure Boot policy is enabled.
    pub const fn secure_boot_enabled(self) -> bool {
        self.secure_boot_enabled
    }

    /// Enter User Mode after enrolling the platform key.
    pub fn enter_user_mode(&mut self) {
        self.setup_mode = false;
    }

    /// Enter Setup Mode and disable Secure Boot policy.
    pub fn enter_setup_mode(&mut self) {
        self.setup_mode = true;
        self.secure_boot_enabled = false;
    }

    /// Enable Secure Boot policy when the platform is in User Mode.
    ///
    /// Returns whether policy is enabled after the transition.
    pub fn enable(&mut self) -> bool {
        if !self.setup_mode {
            self.secure_boot_enabled = true;
        }
        self.secure_boot_enabled
    }

    /// Disable Secure Boot policy.
    pub fn disable(&mut self) {
        self.secure_boot_enabled = false;
    }
}

/// Evidence that an operation is executing before ExitBootServices.
///
/// The branded lifetime and invariant, non-Send marker prevent safe code from
/// retaining this capability beyond the dispatch closure that minted it.
pub struct BootCtx<'brand> {
    _marker: PhantomData<*mut &'brand ()>,
}

/// Evidence that an operation is executing after ExitBootServices.
///
/// This covers both physical runtime and virtual runtime.
pub struct RuntimeCtx<'brand> {
    _marker: PhantomData<*mut &'brand ()>,
}

/// Dynamically determined firmware phase at a phase-blind UEFI ABI boundary.
pub enum Phase<'brand> {
    /// Boot-services phase.
    Boot(BootCtx<'brand>),
    /// Post-ExitBootServices phase.
    Runtime(RuntimeCtx<'brand>),
}

/// Pointer-free runtime state reached through one converted root.
#[repr(C)]
pub struct RuntimeState {
    variables: [RuntimeVariable; MAX_VARIABLES],
    replay: [ReplayEntry; MAX_VARIABLES],
    blobs_used: u32,
    secure_boot: SecureBootStatus,
    exit_boot_services_called: AtomicBool,
    virtual_mode: AtomicBool,
    blobs: [u8; BLOB_ARENA_SIZE],
}

impl RuntimeState {
    const fn new() -> Self {
        Self {
            variables: [const { RuntimeVariable::empty() }; MAX_VARIABLES],
            replay: [const { ReplayEntry::empty() }; MAX_VARIABLES],
            blobs_used: 0,
            secure_boot: SecureBootStatus::SETUP,
            exit_boot_services_called: AtomicBool::new(false),
            virtual_mode: AtomicBool::new(false),
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

    /// Return replay metadata for an active or deleted authenticated variable.
    pub fn auth_timestamp(&self, guid: &Guid, name: &[u16]) -> Option<[u8; 16]> {
        self.variables
            .iter()
            .find(|variable| {
                variable.in_use && variable.vendor_guid == *guid && ucs2_eq(&variable.name, name)
            })
            .and_then(RuntimeVariable::auth_timestamp)
            .or_else(|| {
                self.replay
                    .iter()
                    .find(|entry| {
                        entry.in_use && entry.vendor_guid == *guid && ucs2_eq(&entry.name, name)
                    })
                    .map(|entry| entry.timestamp)
            })
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

    /// Check whether a replacement can commit without exhausting fixed state.
    pub fn can_set_variable(
        &self,
        guid: &Guid,
        name: &[u16],
        data_len: usize,
        authenticated: bool,
    ) -> Result<(), RuntimeStateError> {
        if !is_canonical_name(name) || data_len > MAX_VARIABLE_DATA_SIZE {
            return Err(RuntimeStateError::InvalidSize);
        }
        let existing = self.variables.iter().position(|variable| {
            variable.in_use && variable.vendor_guid == *guid && ucs2_eq(&variable.name, name)
        });
        if existing.is_none() && self.variables.iter().all(|variable| variable.in_use) {
            return Err(RuntimeStateError::OutOfResources);
        }
        if authenticated
            && self.replay.iter().all(|entry| {
                entry.in_use && !(entry.vendor_guid == *guid && ucs2_eq(&entry.name, name))
            })
        {
            return Err(RuntimeStateError::OutOfResources);
        }
        let old_len = existing.map_or(0, |index| self.variables[index].data_size());
        if self
            .used_bytes()
            .saturating_sub(old_len)
            .checked_add(data_len)
            .is_none_or(|required| required > self.blobs.len())
        {
            return Err(RuntimeStateError::OutOfResources);
        }
        Ok(())
    }

    /// Replace or insert a variable without allocation.
    pub fn set_variable(
        &mut self,
        guid: Guid,
        name: &[u16],
        attributes: u32,
        data: &[u8],
        auth_timestamp: Option<[u8; 16]>,
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
        let replay_index = if auth_timestamp.is_some() {
            Some(
                self.replay
                    .iter()
                    .position(|entry| {
                        entry.in_use && entry.vendor_guid == guid && ucs2_eq(&entry.name, name)
                    })
                    .or_else(|| self.replay.iter().position(|entry| !entry.in_use))
                    .ok_or(RuntimeStateError::OutOfResources)?,
            )
        } else {
            None
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
        variable.auth_timestamp = auth_timestamp.unwrap_or([0; 16]);
        variable.in_use = true;
        if let Some(replay_index) = replay_index {
            let replay = &mut self.replay[replay_index];
            replay.name = variable.name;
            replay.vendor_guid = guid;
            replay.timestamp = variable.auth_timestamp;
            replay.in_use = true;
        }
        Ok(dropped)
    }

    /// Record an authenticated replay floor without changing variable data.
    pub fn record_auth_timestamp(
        &mut self,
        guid: Guid,
        name: &[u16],
        timestamp: [u8; 16],
    ) -> Result<(), RuntimeStateError> {
        if !is_canonical_name(name) || timestamp == [0; 16] {
            return Err(RuntimeStateError::InvalidSize);
        }
        let index = self
            .replay
            .iter()
            .position(|entry| {
                entry.in_use && entry.vendor_guid == guid && ucs2_eq(&entry.name, name)
            })
            .or_else(|| self.replay.iter().position(|entry| !entry.in_use))
            .ok_or(RuntimeStateError::OutOfResources)?;
        let entry = &mut self.replay[index];
        entry.name.fill(0);
        entry.name[..name.len()].copy_from_slice(name);
        entry.vendor_guid = guid;
        entry.timestamp = timestamp;
        entry.in_use = true;
        Ok(())
    }

    /// Delete an authenticated variable while retaining its replay floor.
    pub fn delete_authenticated_variable(
        &mut self,
        guid: &Guid,
        name: &[u16],
        timestamp: [u8; 16],
    ) -> Result<bool, RuntimeStateError> {
        if !is_canonical_name(name) || timestamp == [0; 16] {
            return Err(RuntimeStateError::InvalidSize);
        }
        let Some(variable_index) = self.variables.iter().position(|variable| {
            variable.in_use && variable.vendor_guid == *guid && ucs2_eq(&variable.name, name)
        }) else {
            return Ok(false);
        };

        self.record_auth_timestamp(*guid, name, timestamp)?;
        self.variables[variable_index] = RuntimeVariable::empty();
        Ok(true)
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

    /// Return a copy of the pointer-free Secure Boot status.
    pub const fn secure_boot_status(&self) -> SecureBootStatus {
        self.secure_boot
    }

    /// Mutate Secure Boot status using post-ExitBootServices evidence.
    pub fn with_secure_boot_status_mut<R>(
        &mut self,
        _runtime: &RuntimeCtx<'_>,
        f: impl FnOnce(&mut SecureBootStatus) -> R,
    ) -> R {
        f(&mut self.secure_boot)
    }

    /// Reset the arena before boot state is frozen into it.
    pub fn reset(&mut self, _boot: &BootCtx<'_>, secure_boot: SecureBootStatus) {
        self.variables.fill(RuntimeVariable::empty());
        self.replay.fill(ReplayEntry::empty());
        self.blobs.fill(0);
        self.blobs_used = 0;
        self.secure_boot = secure_boot;
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
///
/// Phase-sensitive fields additionally require a capability token in their
/// own APIs. This general accessor remains available for variable handoff and
/// the pointer-free runtime variable store.
pub fn with_mut<R>(f: impl FnOnce(&mut RuntimeState) -> R) -> R {
    let _guard = BorrowGuard::acquire();
    let ptr = RUNTIME_STATE_PTR.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "runtime state is not initialized");
    // SAFETY: the borrow guard serializes both shared and mutable access, and
    // the closure cannot retain the reference after this call.
    unsafe { f(&mut *ptr) }
}

fn exit_boot_services_called() -> bool {
    let ptr = RUNTIME_STATE_PTR.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "runtime state is not initialized");
    // SAFETY: initialization installs the live runtime root. The atomic field
    // is pointer-free and remains reachable through the converted root.
    unsafe { (*ptr).exit_boot_services_called.load(Ordering::Acquire) }
}

/// Dispatch once at a phase-blind UEFI ABI boundary.
pub fn dispatch<R>(f: impl for<'brand> FnOnce(Phase<'brand>) -> R) -> R {
    if exit_boot_services_called() {
        f(Phase::Runtime(RuntimeCtx {
            _marker: PhantomData,
        }))
    } else {
        f(Phase::Boot(BootCtx {
            _marker: PhantomData,
        }))
    }
}

/// Run a boot-only operation, failing immediately if ExitBootServices passed.
///
/// Runtime-reachable modules must use [`dispatch`] instead. This helper exists
/// for boot managers and setup UI entry points whose public APIs are not phase
/// parameterized.
pub fn assert_boot<R>(f: impl for<'brand> FnOnce(&BootCtx<'brand>) -> R) -> R {
    assert!(
        !exit_boot_services_called(),
        "boot-only operation called after ExitBootServices"
    );
    f(&BootCtx {
        _marker: PhantomData,
    })
}

/// Whether ExitBootServices has completed.
///
/// Prefer [`dispatch`] for phase-sensitive code. This compatibility query is
/// retained for unrelated runtime backends while their call graphs migrate.
pub fn is_runtime() -> bool {
    exit_boot_services_called()
}

/// Commit the successful ExitBootServices transition.
///
/// This is the sole phase source of truth and must be called only after the
/// pointer-free boot snapshot and runtime allocator are ready.
pub fn commit_exit_boot_services() {
    let ptr = RUNTIME_STATE_PTR.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "runtime state is not initialized");
    // SAFETY: initialization installs the live runtime root and this transition
    // occurs before the OS can invoke runtime services concurrently.
    let phase = unsafe { &(*ptr).exit_boot_services_called };
    assert!(
        phase
            .compare_exchange(false, true, Ordering::Release, Ordering::Relaxed)
            .is_ok(),
        "ExitBootServices phase committed more than once"
    );
}

/// Whether SetVirtualAddressMap completed successfully.
pub fn is_virtual_mode() -> bool {
    let ptr = RUNTIME_STATE_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return false;
    }
    // SAFETY: initialization installs the live root and relocation updates this
    // pointer before virtual mode is committed.
    unsafe { (*ptr).virtual_mode.load(Ordering::Acquire) }
}

/// Commit virtual runtime mode after all physical FirmwareState access ends.
pub fn commit_virtual_mode() {
    let ptr = RUNTIME_STATE_PTR.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "runtime state is not initialized");
    // SAFETY: initialization installs the live root and SVAM has already
    // relocated the root before this one-way transition.
    let virtual_mode = unsafe { &(*ptr).virtual_mode };
    assert!(
        virtual_mode
            .compare_exchange(false, true, Ordering::Release, Ordering::Relaxed)
            .is_ok(),
        "virtual mode committed more than once"
    );
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
extern crate std;

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;

    fn new_state() -> Box<RuntimeState> {
        let mut state = Box::<RuntimeState>::new_uninit();
        // A zeroed RuntimeState is valid (all flags are false and empty
        // metadata has a null GUID). Build it in place so the 1 MiB runtime
        // arena does not consume the test thread's stack.
        unsafe {
            state.as_mut_ptr().write_bytes(0, 1);
            state.assume_init()
        }
    }

    fn guid(id: u32) -> Guid {
        Guid::from_fields(id, 0, 0, 0, 0, &[0; 6])
    }

    fn name(id: u16) -> [u16; 2] {
        [id, 0]
    }

    fn set(state: &mut RuntimeState, id: u32, name_id: u16, data: &[u8]) {
        assert_eq!(
            state.set_variable(guid(id), &name(name_id), 7, data, None),
            Ok(0)
        );
    }

    fn stored_payload(state: &RuntimeState, id: u32, name_id: u16) -> &[u8] {
        match state.get(&guid(id), &name(name_id)) {
            Some((_, payload)) => payload,
            None => panic!("test variable was not found"),
        }
    }

    #[test]
    fn secure_boot_status_enforces_mode_transitions() {
        let mut status = SecureBootStatus::SETUP;
        assert!(!status.enable());
        status.enter_user_mode();
        assert!(status.enable());
        status.enter_setup_mode();
        assert_eq!(status, SecureBootStatus::SETUP);
    }

    #[test]
    fn post_ebs_capability_mutates_the_authoritative_runtime_status() {
        init();
        let mut frozen = SecureBootStatus::SETUP;
        frozen.enter_user_mode();
        dispatch(|phase| match phase {
            Phase::Boot(boot) => with_mut(|state| state.reset(&boot, frozen)),
            Phase::Runtime(_) => panic!("runtime capability minted before ExitBootServices"),
        });
        commit_exit_boot_services();
        assert!(std::panic::catch_unwind(|| assert_boot(|_| ())).is_err());
        dispatch(|phase| match phase {
            Phase::Runtime(runtime) => with_mut(|state| {
                state.with_secure_boot_status_mut(&runtime, |status| {
                    assert!(status.enable());
                });
            }),
            Phase::Boot(_) => panic!("boot capability minted after ExitBootServices"),
        });

        assert!(with(|state| {
            state.secure_boot_status().secure_boot_enabled()
        }));
    }

    #[test]
    fn stores_and_resolves_payload_by_offset() {
        let mut state = new_state();
        set(&mut state, 1, 1, b"Crab");
        assert_eq!(stored_payload(&state, 1, 1), b"Crab");
    }

    #[test]
    fn replacement_compacts_a_full_arena() {
        let mut state = new_state();
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
    fn stores_all_maximum_sized_boot_cache_variables() {
        let mut state = new_state();
        let payload = [0x5a; MAX_VARIABLE_DATA_SIZE];

        for id in 0..MAX_VARIABLES {
            set(&mut state, id as u32, id as u16 + 1, &payload);
        }

        assert_eq!(state.used_bytes(), MAX_VARIABLES * MAX_VARIABLE_DATA_SIZE);
        for id in 0..MAX_VARIABLES {
            assert_eq!(stored_payload(&state, id as u32, id as u16 + 1), payload);
        }
    }

    #[test]
    fn full_variable_table_rejects_a_new_variable() {
        let mut state = new_state();
        let payload = [0x5a; MAX_VARIABLE_DATA_SIZE];
        for id in 0..MAX_VARIABLES {
            set(&mut state, id as u32, id as u16 + 1, &payload);
        }
        assert_eq!(state.used_bytes(), BLOB_ARENA_SIZE);

        assert_eq!(
            state.set_variable(guid(MAX_VARIABLES as u32), &name(65), 7, b"new", None),
            Err(RuntimeStateError::OutOfResources)
        );
        assert_eq!(stored_payload(&state, 0, 1), payload);
    }

    #[test]
    fn compaction_preserves_payloads_when_slot_and_arena_order_differ() {
        let mut state = new_state();
        set(&mut state, 1, 1, b"old");
        set(&mut state, 2, 2, b"second");
        set(&mut state, 1, 1, b"replacement");
        assert_eq!(state.compact(), 0);

        assert_eq!(stored_payload(&state, 1, 1), b"replacement");
        assert_eq!(stored_payload(&state, 2, 2), b"second");
    }

    #[test]
    fn compaction_reports_corrupt_entries() {
        let mut state = new_state();
        set(&mut state, 1, 1, b"value");
        state.variables[0].data.off = BLOB_ARENA_SIZE as u32;
        assert_eq!(state.compact(), 1);
        assert!(state.get(&guid(1), &name(1)).is_none());
    }

    #[test]
    fn accepts_maximum_name_and_rejects_malformed_names() {
        let mut state = new_state();
        assert_eq!(
            state.set_variable(guid(1), &[1], 7, b"value", None),
            Err(RuntimeStateError::InvalidSize)
        );

        let mut maximum = [1; MAX_VARIABLE_NAME_LEN];
        maximum[MAX_VARIABLE_NAME_LEN - 1] = 0;
        assert_eq!(
            state.set_variable(guid(1), &maximum, 7, b"value", None),
            Ok(0)
        );

        let mut overlong = [1; MAX_VARIABLE_NAME_LEN + 1];
        overlong[MAX_VARIABLE_NAME_LEN] = 0;
        assert_eq!(
            state.set_variable(guid(2), &overlong, 7, b"value", None),
            Err(RuntimeStateError::InvalidSize)
        );
    }

    #[test]
    fn deletion_releases_space_on_next_compaction() {
        let mut state = new_state();
        set(&mut state, 1, 1, b"one");
        set(&mut state, 2, 2, b"two");
        assert!(state.delete_variable(&guid(1), &name(1)));
        set(&mut state, 2, 2, b"updated");
        assert_eq!(state.used_bytes(), 7);
    }

    #[test]
    fn authenticated_deletion_keeps_replay_timestamp() {
        let mut state = new_state();
        let timestamp = [0x5a; 16];
        state
            .set_variable(guid(1), &name(1), 7, b"value", Some(timestamp))
            .unwrap();
        for value in 1..8u8 {
            let mut next_timestamp = timestamp;
            next_timestamp[0] = value;
            state
                .set_variable(guid(1), &name(1), 7, b"value", Some(next_timestamp))
                .unwrap();
        }
        let mut final_timestamp = timestamp;
        final_timestamp[0] = 9;
        assert!(
            state
                .delete_authenticated_variable(&guid(1), &name(1), final_timestamp)
                .unwrap()
        );
        assert!(state.get(&guid(1), &name(1)).is_none());
        assert_eq!(
            state.auth_timestamp(&guid(1), &name(1)),
            Some(final_timestamp)
        );
    }
}

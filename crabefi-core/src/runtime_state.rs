//! SetVirtualAddressMap-safe runtime state
//!
//! Runtime services must not retain ordinary Rust pointers across the
//! physical-to-virtual transition. This module stores variable metadata inline
//! and payloads as offsets from one explicitly converted root.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicPtr, Ordering};

use r_efi::efi::Guid;

use crate::state::{MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN, MAX_VARIABLES, VariableEntry};

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

/// Total payload storage available to runtime variables.
pub const BLOB_ARENA_SIZE: usize = 256 * 1024;

/// An offset from the start of [`RuntimeState`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtOffset<T> {
    off: u32,
    marker: PhantomData<T>,
}

impl<T> RtOffset<T> {
    const fn new(off: u32) -> Self {
        Self {
            off,
            marker: PhantomData,
        }
    }
}

/// An offset-addressed slice inside [`RuntimeState`].
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RtSlice<T> {
    offset: RtOffset<T>,
    len: u32,
}

impl<T> RtSlice<T> {
    const fn empty() -> Self {
        Self {
            offset: RtOffset::new(0),
            len: 0,
        }
    }
}

/// Fixed metadata for one runtime variable.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuntimeVariable {
    pub name: [u16; MAX_VARIABLE_NAME_LEN],
    pub vendor_guid: Guid,
    pub attributes: u32,
    data: RtSlice<u8>,
    pub in_use: bool,
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

    /// Payload length in bytes.
    pub fn data_size(&self) -> usize {
        self.data.len as usize
    }
}

/// Pointer-free runtime state reached through one converted root.
#[repr(C)]
pub struct RuntimeState {
    pub variables: [RuntimeVariable; MAX_VARIABLES],
    blobs_used: u32,
    pub setup_mode: bool,
    pub secure_boot_enabled: bool,
    pub monotonic_high: u32,
    blobs: [u8; BLOB_ARENA_SIZE],
}

impl RuntimeState {
    const fn new() -> Self {
        Self {
            variables: [const { RuntimeVariable::empty() }; MAX_VARIABLES],
            blobs_used: 0,
            setup_mode: true,
            secure_boot_enabled: false,
            monotonic_high: 0,
            blobs: [0; BLOB_ARENA_SIZE],
        }
    }

    fn blob_base_offset() -> usize {
        core::mem::offset_of!(RuntimeState, blobs)
    }

    fn arena_offset(relative: usize) -> RtOffset<u8> {
        RtOffset::new((Self::blob_base_offset() + relative) as u32)
    }

    /// Resolve a runtime variable's payload from the current root.
    pub fn data<'a>(&'a self, variable: &RuntimeVariable) -> &'a [u8] {
        let start = variable
            .data
            .offset
            .off
            .saturating_sub(Self::blob_base_offset() as u32) as usize;
        let len = variable.data.len as usize;
        &self.blobs[start..start + len]
    }

    fn allocate_blob(&mut self, data: &[u8]) -> Option<RtSlice<u8>> {
        let start = self.blobs_used as usize;
        let end = start.checked_add(data.len())?;
        if end > self.blobs.len() {
            return None;
        }
        self.blobs[start..end].copy_from_slice(data);
        self.blobs_used = end as u32;
        Some(RtSlice {
            offset: Self::arena_offset(start),
            len: data.len() as u32,
        })
    }

    fn compact(&mut self) {
        let mut next = 0usize;
        for index in 0..self.variables.len() {
            if !self.variables[index].in_use {
                continue;
            }
            let old_start = self.variables[index]
                .data
                .offset
                .off
                .saturating_sub(Self::blob_base_offset() as u32)
                as usize;
            let len = self.variables[index].data.len as usize;
            if old_start != next {
                self.blobs.copy_within(old_start..old_start + len, next);
            }
            self.variables[index].data.offset = Self::arena_offset(next);
            next += len;
        }
        self.blobs[next..self.blobs_used as usize].fill(0);
        self.blobs_used = next as u32;
    }

    /// Replace or insert a variable without allocation.
    pub fn set_variable(
        &mut self,
        guid: Guid,
        name: &[u16],
        attributes: u32,
        data: &[u8],
    ) -> Result<(), ()> {
        if name.len() > MAX_VARIABLE_NAME_LEN || data.len() > MAX_VARIABLE_DATA_SIZE {
            return Err(());
        }

        let existing = self.variables.iter().position(|var| {
            var.in_use && var.vendor_guid == guid && crate::efi::utils::ucs2_eq(&var.name, name)
        });
        let index = match existing {
            Some(index) => index,
            None => self
                .variables
                .iter()
                .position(|var| !var.in_use)
                .ok_or(())?,
        };

        // Remove the old payload before compaction so replacement does not need
        // space for both versions at once.
        self.variables[index].in_use = false;
        self.compact();
        let blob = self.allocate_blob(data).ok_or(())?;

        let variable = &mut self.variables[index];
        variable.name.fill(0);
        variable.name[..name.len()].copy_from_slice(name);
        variable.vendor_guid = guid;
        variable.attributes = attributes;
        variable.data = blob;
        variable.in_use = true;
        Ok(())
    }

    /// Delete a variable from the runtime cache.
    pub fn delete_variable(&mut self, guid: &Guid, name: &[u16]) -> bool {
        let Some(index) = self.variables.iter().position(|var| {
            var.in_use && var.vendor_guid == *guid && crate::efi::utils::ucs2_eq(&var.name, name)
        }) else {
            return false;
        };
        self.variables[index].in_use = false;
        self.variables[index].data = RtSlice::empty();
        true
    }

    /// Bytes currently occupied by active runtime variable payloads.
    pub fn used_bytes(&self) -> usize {
        self.variables
            .iter()
            .filter(|var| var.in_use)
            .map(RuntimeVariable::data_size)
            .sum()
    }

    fn freeze_from_boot(
        &mut self,
        variables: &[VariableEntry; MAX_VARIABLES],
        setup_mode: bool,
        secure_boot_enabled: bool,
    ) -> Result<(), ()> {
        self.variables.fill(RuntimeVariable::empty());
        self.blobs.fill(0);
        self.blobs_used = 0;
        self.setup_mode = setup_mode;
        self.secure_boot_enabled = secure_boot_enabled;

        for variable in variables.iter().filter(|variable| {
            variable.in_use
                && (variable.attributes & crate::efi::auth::attributes::RUNTIME_ACCESS) != 0
        }) {
            let name_len = variable
                .name
                .iter()
                .position(|&unit| unit == 0)
                .map_or(variable.name.len(), |index| index + 1);
            self.set_variable(
                variable.vendor_guid,
                &variable.name[..name_len],
                variable.attributes,
                &variable.data[..variable.data_size],
            )?;
        }
        Ok(())
    }
}

#[unsafe(link_section = ".runtime_state")]
static mut RUNTIME_STATE: RuntimeState = RuntimeState::new();

static RUNTIME_STATE_PTR: AtomicPtr<RuntimeState> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize the runtime root and its empty arena.
pub fn init() {
    let ptr = &raw mut RUNTIME_STATE;
    RUNTIME_STATE_PTR.store(ptr, Ordering::Release);
}

/// Freeze boot variables into pointer-free runtime storage.
pub fn freeze_from_boot_state() -> Result<(), ()> {
    let efi = crate::state::efi();
    with_mut(|runtime| {
        runtime.freeze_from_boot(&efi.variables, efi.setup_mode, efi.secure_boot_enabled)
    })
}

/// Access the current runtime root.
pub fn get() -> &'static RuntimeState {
    let ptr = RUNTIME_STATE_PTR.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "runtime state is not initialized");
    // SAFETY: initialized once before use and only mutated through `with_mut`
    // in the firmware's single-threaded runtime-service execution model.
    unsafe { &*ptr }
}

/// Mutate the current runtime root without letting a borrow escape.
pub fn with_mut<R>(f: impl FnOnce(&mut RuntimeState) -> R) -> R {
    let ptr = RUNTIME_STATE_PTR.load(Ordering::Acquire);
    assert!(!ptr.is_null(), "runtime state is not initialized");
    // SAFETY: EFI runtime services are serialized by the firmware execution
    // environment, and the closure's borrow cannot escape this call.
    unsafe { f(&mut *ptr) }
}

/// Physical address of the runtime root.
pub fn physical_address() -> u64 {
    &raw const RUNTIME_STATE as u64
}

/// Convert the single runtime root after `SetVirtualAddressMap`.
///
/// The caller must supply the virtual alias of the linker-defined runtime
/// state; this function is crate-private so only SVAM performs the update.
pub(crate) fn relocate(new_ptr: *mut RuntimeState) {
    RUNTIME_STATE_PTR.store(new_ptr, Ordering::Release);
}

const _: () = {
    const fn assert_vam_safe<T: VamSafe>() {}
    assert_vam_safe::<RuntimeState>();
};

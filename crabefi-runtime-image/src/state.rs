//! Sole mutable state cell and non-spinning runtime operation lease.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crabefi_runtime_abi::{
    LoadedSection, MAX_EXTERNAL_RANGES, MAX_RELOCATIONS, MAX_SECTIONS, RelocationImport,
    RuntimeExternalRange, RuntimeHandoff, RuntimeResetConfig, RuntimeTimeConfig, phase,
    relocation_kind,
};

use crate::{
    deferred::DeferredTransaction,
    efi, scratch,
    store::{VariableStore, VariableTransaction},
    tables::ImageTables,
};

#[derive(Clone, Copy)]
pub struct SectionRecord {
    pub physical_base: u64,
    pub virtual_base: u64,
    pub image_offset: u32,
    pub byte_len: u32,
    pub flags: u32,
}

impl SectionRecord {
    const fn empty() -> Self {
        Self {
            physical_base: 0,
            virtual_base: 0,
            image_offset: 0,
            byte_len: 0,
            flags: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct RangeRecord {
    pub physical_base: u64,
    pub virtual_base: u64,
    pub byte_len: u64,
    pub attributes: u64,
}

impl RangeRecord {
    const fn empty() -> Self {
        Self {
            physical_base: 0,
            virtual_base: 0,
            byte_len: 0,
            attributes: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct RelocationRecord {
    pub patch_offset: u32,
    pub target_offset: u32,
    pub patch_section: u8,
    pub target_section: u8,
    pub kind: u16,
}

impl RelocationRecord {
    const fn empty() -> Self {
        Self {
            patch_offset: 0,
            target_offset: 0,
            patch_section: 0,
            target_section: 0,
            kind: 0,
        }
    }
}

pub struct RuntimeState {
    pub tables: ImageTables,
    pub image_base: u64,
    pub image_size: u32,
    pub architecture: u16,
    pub section_count: usize,
    pub sections: [SectionRecord; MAX_SECTIONS],
    pub range_count: usize,
    pub ranges: [RangeRecord; MAX_EXTERNAL_RANGES],
    pub relocation_count: usize,
    pub relocations: [RelocationRecord; MAX_RELOCATIONS],
    pub time: RuntimeTimeConfig,
    pub reset: RuntimeResetConfig,
    pub boot_bridge: u64,
    pub deferred_buffer_physical: u64,
    pub deferred_buffer_virtual: u64,
    pub deferred_buffer_size: usize,
    pub initialized: bool,
    pub import_finished: bool,
}

impl RuntimeState {
    pub const fn new() -> Self {
        Self {
            tables: ImageTables::new(),
            image_base: 0,
            image_size: 0,
            architecture: 0,
            section_count: 0,
            sections: [SectionRecord::empty(); MAX_SECTIONS],
            range_count: 0,
            ranges: [RangeRecord::empty(); MAX_EXTERNAL_RANGES],
            relocation_count: 0,
            relocations: [RelocationRecord::empty(); MAX_RELOCATIONS],
            time: RuntimeTimeConfig {
                mechanism: 0,
                reserved: 0,
                io_or_mmio_base: 0,
            },
            reset: RuntimeResetConfig {
                mechanism: 0,
                reserved: 0,
                io_or_mmio_base: 0,
            },
            boot_bridge: 0,
            deferred_buffer_physical: 0,
            deferred_buffer_virtual: 0,
            deferred_buffer_size: 0,
            initialized: false,
            import_finished: false,
        }
    }

    pub fn initialize(&mut self, handoff: &RuntimeHandoff) -> Result<(), efi::Status> {
        if self.initialized {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        handoff
            .validate()
            .map_err(|_| efi::Status::INVALID_PARAMETER)?;
        self.image_base = handoff.image_base;
        self.image_size = handoff.image_size;
        self.architecture = handoff.architecture;
        self.section_count = usize::from(handoff.section_count);
        self.range_count = usize::from(handoff.range_count);
        self.time = handoff.time;
        self.reset = handoff.reset;
        self.boot_bridge = handoff.boot_bridge;
        self.deferred_buffer_physical = handoff.deferred_buffer_base;
        self.deferred_buffer_size = usize::try_from(handoff.deferred_buffer_size)
            .map_err(|_| efi::Status::INVALID_PARAMETER)?;
        for (destination, source) in self
            .sections
            .iter_mut()
            .take(self.section_count)
            .zip(handoff.sections.iter())
        {
            *destination = section_from_handoff(source);
        }
        for (destination, source) in self
            .ranges
            .iter_mut()
            .take(self.range_count)
            .zip(handoff.ranges.iter())
        {
            *destination = range_from_handoff(source);
        }
        // Publish ResetSystem's lock-free snapshot before BootActive can be
        // observed. The snapshot is outside RuntimeState so a re-entrant reset
        // never reads through an outstanding mutable state lease.
        RUNTIME_RESET_CONFIG.publish(handoff.reset);
        self.initialized = true;
        Ok(())
    }

    pub fn import_relocation(&mut self, relocation: &RelocationImport) -> Result<(), efi::Status> {
        if self.import_finished || self.relocation_count >= MAX_RELOCATIONS {
            return Err(efi::Status::OUT_OF_RESOURCES);
        }
        if usize::from(relocation.patch_section) >= self.section_count
            || usize::from(relocation.target_section) >= self.section_count
            || relocation.kind != relocation_kind::ABSOLUTE64
        {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        self.relocations[self.relocation_count] = RelocationRecord {
            patch_offset: relocation.patch_offset,
            target_offset: relocation.target_offset,
            patch_section: relocation.patch_section,
            target_section: relocation.target_section,
            kind: relocation.kind,
        };
        self.relocation_count += 1;
        Ok(())
    }

    pub fn runtime_only(&self) -> bool {
        RUNTIME_PHASE.load(Ordering::Acquire) >= phase::SEALED_PHYSICAL
    }

    pub fn deferred_buffer(&self) -> (*mut u8, usize) {
        let base = if RUNTIME_PHASE.load(Ordering::Acquire) == phase::VIRTUAL {
            self.deferred_buffer_virtual
        } else {
            self.deferred_buffer_physical
        };
        (base as *mut u8, self.deferred_buffer_size)
    }
}

fn section_from_handoff(section: &LoadedSection) -> SectionRecord {
    SectionRecord {
        physical_base: section.physical_base,
        virtual_base: 0,
        image_offset: section.image_offset,
        byte_len: section.byte_len,
        flags: section.flags,
    }
}

fn range_from_handoff(range: &RuntimeExternalRange) -> RangeRecord {
    RangeRecord {
        physical_base: range.physical_base,
        virtual_base: 0,
        byte_len: range.byte_len,
        attributes: range.attributes,
    }
}

#[repr(transparent)]
pub struct ResetConfigCell(UnsafeCell<RuntimeResetConfig>);

// SAFETY: the value is published exactly once while the image is
// Uninitialized, before BootActive is released, and is immutable afterward.
unsafe impl Sync for ResetConfigCell {}

impl ResetConfigCell {
    const fn new() -> Self {
        Self(UnsafeCell::new(RuntimeResetConfig {
            mechanism: 0,
            reserved: 0,
            io_or_mmio_base: 0,
        }))
    }

    fn publish(&self, config: RuntimeResetConfig) {
        // SAFETY: RuntimeState::initialize is single-shot and serialized by the
        // operation lock before BootActive publication.
        unsafe { self.0.get().write(config) };
    }

    fn read(&self) -> RuntimeResetConfig {
        // SAFETY: callers can observe this only after initialization publishes
        // the immutable value before BootActive.
        unsafe { self.0.get().read() }
    }

    fn address(&self) -> u64 {
        self.0.get() as u64
    }
}

#[repr(transparent)]
pub struct RuntimeCell(UnsafeCell<RuntimeState>);

// SAFETY: all state access is serialized by `RUNTIME_OPERATION_LOCK`; SVAM
// uses the dedicated physical transition path after acquiring that same lock.
unsafe impl Sync for RuntimeCell {}

impl RuntimeCell {
    pub const fn new() -> Self {
        Self(UnsafeCell::new(RuntimeState::new()))
    }

    fn get(&self) -> *mut RuntimeState {
        self.0.get()
    }
}

#[repr(C)]
pub struct RuntimeStore {
    store: VariableStore,
    transaction: VariableTransaction,
    deferred_transaction: DeferredTransaction,
}

impl RuntimeStore {
    const fn new() -> Self {
        Self {
            store: VariableStore::new(),
            transaction: VariableTransaction::new(),
            deferred_transaction: DeferredTransaction::new(),
        }
    }
}

#[repr(transparent)]
pub struct RuntimeStoreCell(UnsafeCell<RuntimeStore>);

// SAFETY: RuntimeStore is accessed only through the RuntimeState operation lease.
unsafe impl Sync for RuntimeStoreCell {}

impl RuntimeStoreCell {
    const fn new() -> Self {
        Self(UnsafeCell::new(RuntimeStore::new()))
    }

    fn get(&self) -> *mut RuntimeStore {
        self.0.get()
    }
}

#[unsafe(no_mangle)]
pub static RUNTIME_VARIABLE_STORE: RuntimeStoreCell = RuntimeStoreCell::new();
#[unsafe(no_mangle)]
pub static RUNTIME_RESET_CONFIG: ResetConfigCell = ResetConfigCell::new();
#[unsafe(no_mangle)]
pub static RUNTIME_STATE: RuntimeCell = RuntimeCell::new();
#[unsafe(no_mangle)]
pub static RUNTIME_OPERATION_LOCK: AtomicBool = AtomicBool::new(false);
#[unsafe(no_mangle)]
pub static RUNTIME_PHASE: AtomicU8 = AtomicU8::new(phase::UNINITIALIZED);

pub struct Lease {
    _not_send: PhantomData<*mut ()>,
}

impl Lease {
    pub fn state(&self) -> &RuntimeState {
        // SAFETY: this lease owns the operation lock until Drop and is !Send.
        unsafe { &*RUNTIME_STATE.get() }
    }

    pub fn state_mut(&mut self) -> &mut RuntimeState {
        // SAFETY: this lease is the unique holder and `&mut self` prevents
        // aliasing within the lease.
        unsafe { &mut *RUNTIME_STATE.get() }
    }

    pub fn variables(&self) -> &VariableStore {
        // SAFETY: this lease serializes every RuntimeStore access.
        unsafe { &(*RUNTIME_VARIABLE_STORE.get()).store }
    }

    pub fn variables_mut(&mut self) -> (&mut VariableStore, &mut VariableTransaction) {
        // SAFETY: the two fields are disjoint and this lease uniquely owns the
        // runtime operation lock for the duration of both mutable references.
        unsafe {
            let store = &mut *RUNTIME_VARIABLE_STORE.get();
            (&mut store.store, &mut store.transaction)
        }
    }

    pub fn variable_state_mut(
        &mut self,
    ) -> (
        &mut VariableStore,
        &mut VariableTransaction,
        &mut DeferredTransaction,
    ) {
        // SAFETY: all three fields are disjoint and the lease is unique.
        unsafe {
            let store = &mut *RUNTIME_VARIABLE_STORE.get();
            (
                &mut store.store,
                &mut store.transaction,
                &mut store.deferred_transaction,
            )
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        scratch::reset();
        RUNTIME_OPERATION_LOCK.store(false, Ordering::Release);
    }
}

pub fn try_lease() -> Result<Lease, efi::Status> {
    if RUNTIME_OPERATION_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(efi::Status::DEVICE_ERROR);
    }
    scratch::activate();
    Ok(Lease {
        _not_send: PhantomData,
    })
}

pub fn try_lease_phase(expected: u8) -> Result<Lease, efi::Status> {
    let lease = try_lease()?;
    if RUNTIME_PHASE.load(Ordering::Acquire) != expected {
        drop(lease);
        return Err(efi::Status::UNSUPPORTED);
    }
    Ok(lease)
}

pub fn set_phase(from: u8, to: u8) -> Result<(), efi::Status> {
    RUNTIME_PHASE
        .compare_exchange(from, to, Ordering::AcqRel, Ordering::Acquire)
        .map(|_| ())
        .map_err(|_| efi::Status::UNSUPPORTED)
}

pub fn phase_value() -> u8 {
    RUNTIME_PHASE.load(Ordering::Acquire)
}

/// Read the immutable reset configuration without taking the operation lease.
/// ResetSystem must remain available even if a failing caller holds that lease.
pub fn reset_config() -> RuntimeResetConfig {
    RUNTIME_RESET_CONFIG.read()
}

pub fn transition_tail_addresses() -> [u64; 3] {
    [
        core::ptr::addr_of!(RUNTIME_OPERATION_LOCK) as u64,
        core::ptr::addr_of!(RUNTIME_PHASE) as u64,
        RUNTIME_RESET_CONFIG.address(),
    ]
}

pub fn begin_virtual_transition() -> Result<*mut RuntimeState, efi::Status> {
    if RUNTIME_OPERATION_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        return Err(efi::Status::NOT_READY);
    }
    if RUNTIME_PHASE.load(Ordering::Acquire) != phase::SEALED_PHYSICAL {
        RUNTIME_OPERATION_LOCK.store(false, Ordering::Release);
        return Err(efi::Status::UNSUPPORTED);
    }
    Ok(RUNTIME_STATE.get())
}

pub fn abort_virtual_transition() {
    RUNTIME_OPERATION_LOCK.store(false, Ordering::Release);
}

/// Publish Virtual and release the operation lock before relocation slots that
/// address these atomics are changed. No image state may be accessed afterward.
pub fn publish_virtual_and_unlock() {
    RUNTIME_PHASE.store(phase::VIRTUAL, Ordering::Release);
    RUNTIME_OPERATION_LOCK.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_snapshot_is_independent_of_mutably_borrowed_runtime_state() {
        let snapshot = ResetConfigCell::new();
        let expected = RuntimeResetConfig {
            mechanism: 3,
            reserved: 0,
            io_or_mmio_base: 0xcf9,
        };
        snapshot.publish(expected);

        let mut runtime = RuntimeState::new();
        let runtime_lease = &mut runtime;
        runtime_lease.reset.io_or_mmio_base = 0x1234;
        assert_eq!(snapshot.read(), expected);
    }
}

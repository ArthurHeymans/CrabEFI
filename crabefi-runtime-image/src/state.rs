//! Sole mutable state cell and non-spinning runtime operation lease.

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

use crabefi_runtime_abi::{
    LoadedSection, MAX_EXTERNAL_RANGES, MAX_RELOCATIONS, MAX_SECTIONS, RelocationImport,
    ResetMechanism, RuntimeExternalRange, RuntimeHandoff, TimeMechanism, relocation_kind,
    section_flags,
};
use heapless::Vec;

use crate::{
    deferred::{DeferredRegion, DeferredTransaction},
    efi,
    store::{VariableStore, VariableTransaction},
    tables::ImageTables,
};

/// Lifecycle phase of the runtime image, published through [`RUNTIME_PHASE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    /// No handoff has been accepted.
    Uninitialized,
    /// The handoff is accepted and relocations are being imported.
    Loaded,
    /// Boot services are active and persisted variables are being imported.
    Importing,
    /// Boot services are active and the variable store is authoritative.
    BootActive,
    /// ExitBootServices sealed the image; it still runs at physical addresses.
    SealedPhysical,
    /// SetVirtualAddressMap committed the virtual mapping.
    Virtual,
}

impl Phase {
    /// Phases in which boot services are still active.
    pub const BOOT_SERVICES: &[Self] = &[Self::Importing, Self::BootActive];

    /// The phase currently published in [`RUNTIME_PHASE`].
    pub fn current() -> Self {
        match RUNTIME_PHASE.load(Ordering::Acquire) {
            1 => Self::Loaded,
            2 => Self::Importing,
            3 => Self::BootActive,
            4 => Self::SealedPhysical,
            5 => Self::Virtual,
            _ => Self::Uninitialized,
        }
    }

    fn publish(self) {
        RUNTIME_PHASE.store(self as u8, Ordering::Release);
    }

    /// Boot services are active.
    pub fn boot_services(self) -> bool {
        Self::BOOT_SERVICES.contains(&self)
    }

    /// ExitBootServices has completed.
    pub fn runtime(self) -> bool {
        matches!(self, Self::SealedPhysical | Self::Virtual)
    }
}

#[derive(Clone, Copy)]
pub struct SectionRecord {
    pub physical_base: u64,
    pub virtual_base: u64,
    pub image_offset: u32,
    pub byte_len: u32,
    pub flags: u32,
}

#[derive(Clone, Copy)]
pub struct RangeRecord {
    pub physical_base: u64,
    pub virtual_base: u64,
    pub byte_len: u64,
    pub attributes: u64,
}

#[derive(Clone, Copy)]
pub struct RelocationRecord {
    pub patch_offset: u32,
    pub target_offset: u32,
    pub patch_section: u8,
    pub target_section: u8,
    pub kind: u16,
}

/// Time source selected by the handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimeConfig {
    pub mechanism: TimeMechanism,
    /// I/O port or MMIO base; virtual after SetVirtualAddressMap.
    pub base: u64,
}

/// Reset conduit selected by the handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResetConfig {
    pub mechanism: ResetMechanism,
    pub base: u64,
}

/// Retained deferred buffer described by the handoff.
#[derive(Clone, Copy)]
pub struct RetainedBuffer {
    pub physical_base: u64,
    /// Zero until SetVirtualAddressMap commits.
    pub virtual_base: u64,
    pub size: usize,
}

pub struct RuntimeState {
    pub tables: ImageTables,
    pub sections: Vec<SectionRecord, MAX_SECTIONS>,
    pub ranges: Vec<RangeRecord, MAX_EXTERNAL_RANGES>,
    pub relocations: Vec<RelocationRecord, MAX_RELOCATIONS>,
    pub time: TimeConfig,
    pub boot_bridge: u64,
    pub retained: Option<RetainedBuffer>,
    pub capsule_delivery_enabled: bool,
}

impl RuntimeState {
    pub const fn new() -> Self {
        Self {
            tables: ImageTables::new(),
            sections: Vec::new(),
            ranges: Vec::new(),
            relocations: Vec::new(),
            time: TimeConfig {
                mechanism: TimeMechanism::Unsupported,
                base: 0,
            },
            boot_bridge: 0,
            retained: None,
            capsule_delivery_enabled: false,
        }
    }

    pub fn initialize(&mut self, handoff: &RuntimeHandoff) -> Result<(), efi::Status> {
        handoff
            .validate()
            .map_err(|_| efi::Status::INVALID_PARAMETER)?;
        let sections = handoff
            .sections()
            .map_err(|_| efi::Status::INVALID_PARAMETER)?;
        let ranges = handoff
            .ranges()
            .map_err(|_| efi::Status::INVALID_PARAMETER)?;
        self.sections = collect_bounded(
            sections
                .iter()
                .map(|section| Ok(section_from_handoff(section))),
        )?;
        self.ranges = collect_bounded(ranges.iter().map(|range| Ok(range_from_handoff(range))))?;
        self.time = TimeConfig {
            mechanism: TimeMechanism::try_from(handoff.time.mechanism)
                .map_err(|_| efi::Status::INVALID_PARAMETER)?,
            base: handoff.time.io_or_mmio_base,
        };
        let reset = ResetConfig {
            mechanism: ResetMechanism::try_from(handoff.reset.mechanism)
                .map_err(|_| efi::Status::INVALID_PARAMETER)?,
            base: handoff.reset.io_or_mmio_base,
        };
        self.boot_bridge = handoff.boot_bridge;
        self.retained = match (handoff.deferred_buffer_base, handoff.deferred_buffer_size) {
            (0, 0) => None,
            (physical_base, size) => Some(RetainedBuffer {
                physical_base,
                virtual_base: 0,
                size: usize::try_from(size).map_err(|_| efi::Status::INVALID_PARAMETER)?,
            }),
        };
        // Publish ResetSystem's lock-free snapshot before boot services can
        // call it. The snapshot is outside RuntimeState so a re-entrant reset
        // never reads through an outstanding mutable state lease.
        RUNTIME_RESET_CONFIG.publish(reset);
        Ok(())
    }

    pub fn import_relocation(&mut self, relocation: &RelocationImport) -> Result<(), efi::Status> {
        let patch = self
            .sections
            .get(usize::from(relocation.patch_section))
            .copied()
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        let target = self
            .sections
            .get(usize::from(relocation.target_section))
            .copied()
            .ok_or(efi::Status::INVALID_PARAMETER)?;
        // Mirror the normalized-image manifest checks (format.rs) so an
        // invalid record is rejected at import instead of only at
        // SetVirtualAddressMap time.
        if relocation.kind != relocation_kind::ABSOLUTE64
            || patch.flags & section_flags::RELOCATION_SLOTS == 0
            || !relocation.patch_offset.is_multiple_of(8)
            || !offset_within_section(&patch, relocation.patch_offset, 8)
            || !offset_within_section(&target, relocation.target_offset, 1)
        {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        self.relocations
            .push(RelocationRecord {
                patch_offset: relocation.patch_offset,
                target_offset: relocation.target_offset,
                patch_section: relocation.patch_section,
                target_section: relocation.target_section,
                kind: relocation.kind,
            })
            .map_err(|_| efi::Status::OUT_OF_RESOURCES)
    }

    /// The retained buffer at its address for the current phase.
    pub fn deferred_region(&mut self) -> Option<DeferredRegion<'_>> {
        let retained = self.retained?;
        let base = if Phase::current() == Phase::Virtual {
            retained.virtual_base
        } else {
            retained.physical_base
        };
        // SAFETY: the handoff validated a nonzero, page-aligned range the boot
        // allocator reserved as RuntimeServicesData for this image, and it is
        // mapped at `base` in the current phase. The region borrows the leased
        // state mutably, so it is the only live view of those bytes.
        let bytes = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, retained.size) };
        Some(DeferredRegion::new(bytes))
    }
}

/// Collect fallible `items`, failing instead of truncating beyond `N`.
pub fn collect_bounded<T, const N: usize>(
    items: impl Iterator<Item = Result<T, efi::Status>>,
) -> Result<Vec<T, N>, efi::Status> {
    let mut collected = Vec::new();
    for item in items {
        collected
            .push(item?)
            .map_err(|_| efi::Status::INVALID_PARAMETER)?;
    }
    Ok(collected)
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

/// Return whether `[offset, offset + width)` lies fully inside the section's
/// image-relative `[image_offset, image_offset + byte_len)` range.
pub(crate) fn offset_within_section(section: &SectionRecord, offset: u32, width: u32) -> bool {
    section
        .image_offset
        .checked_add(section.byte_len)
        .is_some_and(|section_end| {
            offset >= section.image_offset
                && offset
                    .checked_add(width)
                    .is_some_and(|end| end <= section_end)
        })
}

fn range_from_handoff(range: &RuntimeExternalRange) -> RangeRecord {
    RangeRecord {
        physical_base: range.physical_base,
        virtual_base: 0,
        byte_len: range.byte_len,
        attributes: range.attributes,
    }
}

/// Lock-free snapshot of the reset configuration for `ResetSystem`.
///
/// The pair is published exactly once while the image is uninitialized: the
/// base word first, then the mechanism word with `Release`. The `Acquire`
/// mechanism load in `read` makes the prior base store visible without taking
/// the operation lease, so a re-entrant reset never reads a torn
/// configuration. Every ABI reset mechanism value is nonzero, so a zero
/// mechanism word means the snapshot is unpublished.
#[repr(C)]
pub struct ResetConfigCell {
    mechanism: AtomicU64,
    base: AtomicU64,
}

impl ResetConfigCell {
    const fn new() -> Self {
        Self {
            mechanism: AtomicU64::new(0),
            base: AtomicU64::new(0),
        }
    }

    fn publish(&self, config: ResetConfig) {
        self.base.store(config.base, Ordering::Relaxed);
        self.mechanism
            .store(u32::from(config.mechanism).into(), Ordering::Release);
    }

    fn read(&self) -> Option<ResetConfig> {
        let mechanism = u32::try_from(self.mechanism.load(Ordering::Acquire)).ok()?;
        Some(ResetConfig {
            mechanism: ResetMechanism::try_from(mechanism).ok()?,
            base: self.base.load(Ordering::Relaxed),
        })
    }

    fn address(&self) -> u64 {
        core::ptr::addr_of!(self.mechanism) as u64
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

/// Variable store and its scratch buffers, kept outside `RuntimeState`.
#[repr(C)]
pub struct RuntimeStore {
    pub store: VariableStore,
    pub transaction: VariableTransaction,
    pub deferred_transaction: DeferredTransaction,
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
pub static RUNTIME_PHASE: AtomicU8 = AtomicU8::new(Phase::Uninitialized as u8);

/// Exclusive access to the image state for one operation.
pub struct Lease {
    _not_send: PhantomData<*mut ()>,
}

impl Lease {
    pub fn phase(&self) -> Phase {
        Phase::current()
    }

    /// Publish the next lifecycle phase while holding the operation lock.
    pub fn advance(&mut self, phase: Phase) {
        phase.publish();
    }

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

    /// Disjoint mutable views of the runtime state and the variable store.
    pub fn parts_mut(&mut self) -> (&mut RuntimeState, &mut RuntimeStore) {
        // SAFETY: the two statics are distinct and this lease uniquely owns
        // the runtime operation lock for the duration of both references.
        unsafe {
            (
                &mut *RUNTIME_STATE.get(),
                &mut *RUNTIME_VARIABLE_STORE.get(),
            )
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        RUNTIME_OPERATION_LOCK.store(false, Ordering::Release);
    }
}

fn acquire_lock() -> bool {
    RUNTIME_OPERATION_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_ok()
}

/// Lease the state in any phase; fails while another operation holds it.
pub fn lease() -> Result<Lease, efi::Status> {
    if !acquire_lock() {
        return Err(efi::Status::DEVICE_ERROR);
    }
    Ok(Lease {
        _not_send: PhantomData,
    })
}

/// Lease the state only while the image is in one of `phases`.
pub fn lease_in(phases: &[Phase]) -> Result<Lease, efi::Status> {
    let lease = lease()?;
    if phases.contains(&lease.phase()) {
        Ok(lease)
    } else {
        Err(efi::Status::UNSUPPORTED)
    }
}

/// Read the immutable reset configuration without taking the operation lease.
/// ResetSystem must remain available even if a failing caller holds that lease.
pub fn reset_config() -> Option<ResetConfig> {
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
    if !acquire_lock() {
        return Err(efi::Status::NOT_READY);
    }
    if Phase::current() != Phase::SealedPhysical {
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
    Phase::Virtual.publish();
    RUNTIME_OPERATION_LOCK.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_reset_snapshot_reads_back() {
        let snapshot = ResetConfigCell::new();
        let expected = ResetConfig {
            mechanism: ResetMechanism::PsciHvc,
            base: 0xcf9,
        };
        snapshot.publish(expected);
        assert_eq!(snapshot.read(), Some(expected));
    }

    #[test]
    fn unpublished_reset_snapshot_reads_as_unconfigured() {
        let snapshot = ResetConfigCell::new();
        snapshot.base.store(0xcf9, Ordering::Relaxed);
        assert_eq!(snapshot.read(), None);
    }

    #[test]
    fn import_relocation_validates_offsets_against_imported_sections() {
        let mut runtime = RuntimeState::new();
        runtime.sections = Vec::from_array([
            SectionRecord {
                physical_base: 0x10_0000,
                virtual_base: 0,
                image_offset: 0,
                byte_len: 0x1000,
                flags: section_flags::EXECUTE,
            },
            SectionRecord {
                physical_base: 0x10_1000,
                virtual_base: 0,
                image_offset: 0x1000,
                byte_len: 0x1000,
                flags: section_flags::RELOCATION_SLOTS | section_flags::WRITE,
            },
        ]);
        let valid = RelocationImport {
            patch_offset: 0x1008,
            target_offset: 0x0,
            patch_section: 1,
            target_section: 0,
            kind: relocation_kind::ABSOLUTE64,
            reserved: [0; 12],
        };
        assert!(runtime.import_relocation(&valid).is_ok());

        for invalid in [
            // Patch slot outside the relocation-slot section.
            RelocationImport {
                patch_offset: 0x8,
                ..valid
            },
            // Patch slot crosses the section end.
            RelocationImport {
                patch_offset: 0x1ff8 + 8,
                ..valid
            },
            // Unaligned patch slot.
            RelocationImport {
                patch_offset: 0x1004,
                ..valid
            },
            // Target offset equals the section end.
            RelocationImport {
                target_offset: 0x1000,
                ..valid
            },
            // Section index past the imported sections.
            RelocationImport {
                patch_section: 2,
                ..valid
            },
            RelocationImport {
                target_section: 2,
                ..valid
            },
            // Unknown relocation kind.
            RelocationImport {
                kind: relocation_kind::ABSOLUTE64 + 1,
                ..valid
            },
        ] {
            assert!(runtime.import_relocation(&invalid).is_err());
        }
        assert_eq!(runtime.relocations.len(), 1);
    }
}

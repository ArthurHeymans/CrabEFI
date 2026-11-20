//! Power loss at every flash operation of a variable write.
//!
//! A NOR-like medium in memory loses power at a chosen operation: before it,
//! halfway through, one byte short, or right after. The firmware then boots
//! again from whatever reached the medium. Every variable must read back as
//! either its old or its new value, unrelated variables must be untouched,
//! and the store must accept and keep the next write.

use super::*;
use crate::efi::varstore::storage::StorageError;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use std::sync::Mutex;

const SIZE: usize = 16 * 1024;
const ATTRIBUTES: u32 = 0x7; // NV | BS | RT
/// Plus TIME_BASED_AUTHENTICATED_WRITE_ACCESS.
const AUTHENTICATED: u32 = ATTRIBUTES | 0x20;

fn attributes(year: u16) -> u32 {
    if year == 0 { ATTRIBUTES } else { AUTHENTICATED }
}

#[derive(Clone, Copy, Debug)]
enum Cut {
    Before,
    Half,
    AllButOne,
    After,
}
const CUTS: [Cut; 4] = [Cut::Before, Cut::Half, Cut::AllButOne, Cut::After];

struct Media {
    bytes: Vec<u8>,
    operations: usize,
    erases: usize,
    cut: Option<(usize, Cut)>,
    powered: bool,
    /// A byte that fails every read covering it.
    unreadable: Option<usize>,
}

impl Media {
    /// Apply one program or erase, or the part of it that lands before the cut.
    fn mutate(&mut self, offset: u32, len: usize, change: impl Fn(usize, u8) -> u8) -> bool {
        if !self.powered {
            return false;
        }
        let index = self.operations;
        self.operations += 1;
        let done = match self.cut {
            Some((at, cut)) if at == index => {
                self.powered = false;
                match cut {
                    Cut::Before => 0,
                    Cut::Half => len / 2,
                    Cut::AllButOne => len.saturating_sub(1),
                    Cut::After => len,
                }
            }
            _ => len,
        };
        let start = offset as usize;
        for (i, byte) in self.bytes[start..start + done].iter_mut().enumerate() {
            *byte = change(i, *byte);
        }
        self.powered
    }
}

struct Disk(Arc<Mutex<Media>>);

impl StorageBackend for Disk {
    fn name(&self) -> &str {
        "power-loss test medium"
    }
    fn size(&self) -> u32 {
        SIZE as u32
    }
    fn program_granularity(&self) -> u32 {
        1
    }
    fn erase_granularity(&self) -> u32 {
        4096
    }
    fn is_write_protected(&self) -> bool {
        false
    }
    fn read(&mut self, offset: u32, buffer: &mut [u8]) -> Result<(), StorageError> {
        let media = self.0.lock().unwrap();
        if !media.powered {
            return Err(StorageError::IoError);
        }
        let start = offset as usize;
        if media
            .unreadable
            .is_some_and(|byte| (start..start + buffer.len()).contains(&byte))
        {
            return Err(StorageError::IoError);
        }
        buffer.copy_from_slice(&media.bytes[start..start + buffer.len()]);
        Ok(())
    }
    fn program(&mut self, offset: u32, data: &[u8]) -> Result<(), StorageError> {
        // NOR flash only clears bits.
        let ok = self
            .0
            .lock()
            .unwrap()
            .mutate(offset, data.len(), |i, old| old & data[i]);
        ok.then_some(()).ok_or(StorageError::IoError)
    }
    fn erase(&mut self, offset: u32, size: u32) -> Result<(), StorageError> {
        let mut media = self.0.lock().unwrap();
        media.erases += 1;
        let ok = media.mutate(offset, size as usize, |_, _| 0xff);
        ok.then_some(()).ok_or(StorageError::IoError)
    }
}

/// Boot from `bytes`, losing power at `cut` if given.
fn boot(bytes: Vec<u8>, cut: Option<(usize, Cut)>) -> Arc<Mutex<Media>> {
    try_boot(bytes, cut).unwrap()
}

fn try_boot(bytes: Vec<u8>, cut: Option<(usize, Cut)>) -> Result<Arc<Mutex<Media>>, VarStoreError> {
    let media = Arc::new(Mutex::new(Media {
        bytes,
        operations: 0,
        erases: 0,
        cut: None,
        powered: true,
        unreadable: None,
    }));
    let disk: &'static mut dyn StorageBackend = Box::leak(Box::new(Disk(media.clone())));
    detach_backend();
    VARSTORE.set(VarStoreState::new());
    validate_backend(disk).unwrap();
    *STORAGE.borrow_mut() = Some(Storage::Platform(disk));
    init_varstore()?;
    // Count only the operations of the write under test.
    let mut state = media.lock().unwrap();
    state.operations = 0;
    state.erases = 0;
    state.cut = cut;
    drop(state);
    Ok(media)
}

fn bytes(media: &Arc<Mutex<Media>>) -> Vec<u8> {
    media.lock().unwrap().bytes.clone()
}

fn name(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn guid(n: u8) -> r_efi::efi::Guid {
    r_efi::efi::Guid::from_fields(u32::from(n), 0, 0, 0, 0, &[0; 6])
}

/// A variable's visible state: GUID tag, data, and the year of its
/// authenticated timestamp (zero for none).
type Var = (u8, Vec<u8>, u16);

fn plain(n: u8, value: &[u8]) -> Var {
    (n, value.to_vec(), 0)
}

fn timestamp(year: u16) -> Option<VariableTimestamp> {
    (year != 0).then(|| VariableTimestamp {
        year,
        month: 1,
        day: 1,
        ..VariableTimestamp::default()
    })
}

fn write((n, value, year): &Var) -> Result<(), VarStoreError> {
    write_variable_to_storage_internal(
        &guid(*n),
        &name("Var"),
        attributes(*year),
        value,
        timestamp(*year),
    )
}

fn set(n: u8, value: &[u8]) -> Result<(), VarStoreError> {
    write(&plain(n, value))
}

fn delete(n: u8, year: u16) -> Result<(), VarStoreError> {
    write_variable_deletion_internal(&guid(n), &name("Var"), attributes(year), timestamp(year))
}

/// The visible state of every variable, as the next boot imports them.
fn visible() -> Vec<Var> {
    let vs = VARSTORE.get();
    let records = with_storage_mut(|storage| {
        let mut read = |offset: u32, buf: &mut [u8]| storage.read(offset, buf).is_ok();
        edk2::walk_variables(&mut read, vs.auth_format, vs.data_size)
    })
    .unwrap();
    let mut values: Vec<_> = live_records(&records)
        .into_iter()
        .map(|record| {
            // Everything but the data and timestamp is fixed by the tests.
            assert_eq!(record.guid, edk2::guid_to_bytes(&guid(record.guid[0])));
            assert!(edk2::name_matches(&record.name, &name("Var")));
            // Unauthenticated records carry an all-zero timestamp.
            let stamp = record.timestamp.unwrap_or_default();
            let year = stamp.year;
            assert_eq!(record.attributes, attributes(year));
            // The whole timestamp survives, and the replay-floor lookup that
            // authenticated writes use accepts the recovered store and agrees
            // with the live record.
            assert_eq!(stamp, timestamp(year).unwrap_or_default());
            assert_eq!(
                try_get_variable_timestamp(&guid(record.guid[0]), &name("Var"))
                    .map(Option::unwrap_or_default),
                Ok(stamp),
            );
            (record.guid[0], record.data.clone(), year)
        })
        .collect();
    values.sort();
    values
}

/// Run `operation` once per flash operation and cut point, losing power
/// there, and check the store after the next boot.
fn every_power_loss(
    history: &[Var],
    operation: impl Fn() -> Result<(), VarStoreError>,
    after: &[Var],
) -> usize {
    power_loss_scenario(history, operation, after, false)
}

/// Like [`every_power_loss`], and also lose power again at every operation
/// of retrying the same write after the first recovery.
fn every_double_power_loss(
    history: &[Var],
    operation: impl Fn() -> Result<(), VarStoreError>,
    after: &[Var],
) -> usize {
    power_loss_scenario(history, operation, after, true)
}

fn power_loss_scenario(
    history: &[Var],
    operation: impl Fn() -> Result<(), VarStoreError>,
    after: &[Var],
    retries: bool,
) -> usize {
    // The persistence layer keeps firmware-global state; every test touching
    // it holds the crate's firmware state lock.
    let _state = crate::efi::boot_services::IMAGE_EXECUTION_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut initial = vec![0xff; SIZE];
    let media = boot(initial.clone(), None);
    let mut before = Vec::new();
    for var in history {
        write(var).unwrap();
        before.retain(|(m, _, _)| *m != var.0);
        before.push(var.clone());
    }
    before.sort();
    initial = bytes(&media);
    assert_eq!(visible(), before);

    let media = boot(initial.clone(), None);
    operation().unwrap();
    let (operations, erases) = {
        let media = media.lock().unwrap();
        (media.operations, media.erases)
    };
    assert_eq!(visible(), after);
    assert!(operations > 0);

    for at in 0..operations {
        for cut in CUTS {
            let media = boot(initial.clone(), Some((at, cut)));
            let _ = operation();
            let rebooted = try_boot(bytes(&media), None).unwrap_or_else(|error| {
                panic!("power loss at operation {at} ({cut:?}) left no store: {error:?}")
            });
            let seen = visible();
            assert!(
                seen == before || seen == after,
                "power loss at operation {at} ({cut:?}) left {seen:?}"
            );
            let torn = bytes(&rebooted);

            // Retrying the operation after recovery may lose power again.
            let retry = boot(torn.clone(), None);
            let _ = operation();
            let retry_operations = retry.lock().unwrap().operations;
            for again in (0..retry_operations).filter(|_| retries) {
                for cut_again in CUTS {
                    let media = boot(torn.clone(), Some((again, cut_again)));
                    let _ = operation();
                    try_boot(bytes(&media), None).unwrap_or_else(|error| {
                        panic!("second power loss at {again} ({cut_again:?}) after {at} ({cut:?}) left no store: {error:?}")
                    });
                    let seen_again = visible();
                    assert!(
                        seen_again == seen || seen_again == after,
                        "second power loss at {again} ({cut_again:?}) after {at} ({cut:?}) left {seen_again:?}"
                    );
                }
            }

            let fresh = boot(torn, None);
            // The store stays usable and the next write survives a reboot.
            set(9, b"next").unwrap();
            boot(bytes(&fresh), None);
            let mut expected = seen.clone();
            expected.push(plain(9, b"next"));
            expected.sort();
            assert_eq!(visible(), expected, "after power loss at {at} ({cut:?})");
        }
    }
    detach_backend();
    VARSTORE.set(VarStoreState::new());
    erases
}

#[test]
fn updating_a_variable_is_atomic() {
    let erases = every_power_loss(
        &[plain(1, b"old"), plain(2, b"other")],
        || set(1, b"new value"),
        &[plain(1, b"new value"), plain(2, b"other")],
    );
    assert_eq!(erases, 0);
}

#[test]
fn creating_a_variable_is_atomic() {
    let _ = every_power_loss(
        &[plain(2, b"other")],
        || set(1, b"created"),
        &[plain(1, b"created"), plain(2, b"other")],
    );
}

#[test]
fn deleting_a_variable_is_atomic() {
    let _ = every_power_loss(
        &[plain(1, b"old"), plain(2, b"other")],
        || delete(1, 0),
        &[plain(2, b"other")],
    );
}

/// The timestamp is the replay floor of an authenticated variable: it must
/// never be lost or move backwards across a power loss.
#[test]
fn authenticated_update_keeps_a_replay_floor() {
    let _ = every_power_loss(
        &[(1, b"v1".to_vec(), 2024), plain(2, b"other")],
        || write(&(1, b"v2".to_vec(), 2025)),
        &[(1, b"v2".to_vec(), 2025), plain(2, b"other")],
    );
}

/// An authenticated deletion leaves an empty record carrying the floor.
#[test]
fn authenticated_deletion_keeps_a_replay_floor() {
    let _ = every_power_loss(
        &[(1, b"v1".to_vec(), 2024), plain(2, b"other")],
        || delete(1, 2025),
        &[(1, Vec::new(), 2025), plain(2, b"other")],
    );
}

/// Compaction erases the only copy, so a read failure while taking its
/// inventory must stop it instead of dropping every later record.
#[test]
fn compaction_refuses_an_incomplete_inventory() {
    let _state = crate::efi::boot_services::IMAGE_EXECUTION_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let media = boot(vec![0xff; SIZE], None);
    // Ten records leave too little room for another, so the next write
    // compacts.
    for n in 1..=10 {
        set(n, &[n; 1500]).unwrap();
    }
    let full = bytes(&media);
    let before = visible();

    let media = boot(full.clone(), None);
    // The last record's data cannot be read.
    media.lock().unwrap().unreadable = Some(SIZE * 7 / 8);
    assert_eq!(set(11, &[11; 1500]), Err(VarStoreError::StorageFailure));
    assert_eq!(
        media.lock().unwrap().erases,
        0,
        "compacted without an inventory"
    );
    boot(bytes(&media), None);
    assert_eq!(visible(), before);
    detach_backend();
    VARSTORE.set(VarStoreState::new());
}

/// Known gap: a write torn mid-record leaves bytes at the append point that
/// are not erased, so the retry compacts the store, and losing power during
/// that compaction loses every variable. A single torn write is safe.
#[test]
#[ignore = "a torn write makes the retry compact, which is not power-loss safe"]
fn retrying_after_a_torn_update_is_atomic() {
    let _ = every_double_power_loss(
        &[plain(1, b"old"), plain(2, b"other")],
        || set(1, b"new value"),
        &[plain(1, b"new value"), plain(2, b"other")],
    );
}

/// Known gap: compaction erases the only copy of the store before rewriting
/// it. Power loss during that erase leaves a region that is neither a store
/// nor blank, which init refuses; after it, every variable is gone. Fixing
/// this needs spare space, as the payload MM writer uses.
#[test]
#[ignore = "boot-time compaction is not power-loss safe; see the comment"]
fn compacting_a_full_store_is_atomic() {
    // Superseded copies fill the store, so the next large write must compact.
    let large = vec![0x5a; 1500];
    let mut history = vec![plain(2, b"other")];
    history.extend((0..10).map(|_| plain(1, &large)));
    let erases = every_power_loss(
        &history,
        || set(1, &[0xa5; 1500]),
        &[plain(1, &[0xa5; 1500]), plain(2, b"other")],
    );
    assert!(erases > 0, "the update did not compact");
}

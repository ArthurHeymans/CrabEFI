//! Bounds, protection and partial-I/O behavior of the boot-only region adapter.

use super::{Storage, validate_backend};
use crate::efi::varstore::{
    VarStoreError,
    storage::{StorageBackend, StorageError},
};
use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

struct Region {
    calls: Arc<AtomicUsize>,
    media_byte: Arc<AtomicU8>,
    protected: bool,
    fail_program: bool,
    size: u32,
    program_unit: u32,
}
impl Region {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            media_byte: Arc::new(AtomicU8::new(0xff)),
            protected: false,
            fail_program: false,
            size: 4096,
            program_unit: 1,
        }
    }
}
impl StorageBackend for Region {
    fn name(&self) -> &str {
        "bounded test region"
    }
    fn size(&self) -> u32 {
        self.size
    }
    fn program_granularity(&self) -> u32 {
        self.program_unit
    }
    fn erase_granularity(&self) -> u32 {
        4096
    }
    fn is_write_protected(&self) -> bool {
        self.protected
    }
    fn read(&mut self, _offset: u32, data: &mut [u8]) -> Result<(), StorageError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        data.fill(0xff);
        Ok(())
    }
    fn program(&mut self, _offset: u32, data: &[u8]) -> Result<(), StorageError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if let Some(byte) = data.first() {
            self.media_byte.store(*byte, Ordering::Relaxed);
        }
        if self.fail_program {
            Err(StorageError::IoError)
        } else {
            Ok(())
        }
    }
    fn erase(&mut self, _offset: u32, _size: u32) -> Result<(), StorageError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[test]
fn bounds_and_alignment_reject_without_touching_media() {
    let backend = Region::new();
    assert!(validate_backend(&backend).is_ok());
    let calls = backend.calls.clone();
    let mut storage = Storage::Platform(Box::leak(Box::new(backend)));
    assert_eq!(
        storage.read(u32::MAX, &mut [0; 2]),
        Err(StorageError::InvalidArgument)
    );
    assert_eq!(
        storage.program(4095, &[1, 2]),
        Err(StorageError::InvalidArgument)
    );
    assert_eq!(storage.erase(1, 4096), Err(StorageError::InvalidArgument));
    assert_eq!(storage.erase(0, 4095), Err(StorageError::InvalidArgument));
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(storage.program(4095, &[1]).is_ok());
    assert!(storage.erase(0, 4096).is_ok());
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(
        super::validate_range(4096, 1, usize::MAX, 1),
        Err(StorageError::InvalidArgument)
    );
}

#[test]
fn invalid_geometry_is_rejected_before_formatting() {
    for (size, program_unit) in [(4095, 1), (4096, 4), (64, 1)] {
        let mut backend = Region::new();
        backend.size = size;
        backend.program_unit = program_unit;
        assert_eq!(
            validate_backend(&backend),
            Err(VarStoreError::InvalidArgument)
        );
        assert_eq!(backend.calls.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn protection_is_not_cleared_and_partial_program_failure_is_preserved() {
    let mut backend = Region::new();
    backend.protected = true;
    let calls = backend.calls.clone();
    let mut storage = Storage::Platform(Box::leak(Box::new(backend)));
    assert_eq!(storage.program(0, &[1]), Err(StorageError::WriteProtected));
    assert_eq!(storage.erase(0, 4096), Err(StorageError::WriteProtected));
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    let mut backend = Region::new();
    backend.fail_program = true;
    let byte = backend.media_byte.clone();
    let mut storage = Storage::Platform(Box::leak(Box::new(backend)));
    assert_eq!(
        storage.program(0, &[0x55, 0x66]),
        Err(StorageError::IoError)
    );
    assert_eq!(byte.load(Ordering::Relaxed), 0x55); // Partial media effects are not atomic.
}

#[test]
fn detaching_removes_access_to_the_boot_owned_backend() {
    let backend = Region::new();
    let calls = backend.calls.clone();
    *super::STORAGE.borrow_mut() = Some(Storage::Platform(Box::leak(Box::new(backend))));
    super::detach_backend();
    assert!(super::with_storage_mut(|storage| storage.program(0, &[1])).is_none());
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

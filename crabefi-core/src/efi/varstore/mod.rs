//! Boot-only EDK2 variable persistence and runtime-image importer.
//!
//! Persistent records are imported directly into the authoritative runtime
//! image store. The boot image retains no variable copy or EBS snapshot.

pub mod edk2;
pub mod persistence;
pub mod storage;

pub(crate) use persistence::import_variable_into_runtime;
pub use persistence::{
    get_variable_timestamp, get_varstore_stats, init as init_persistence, is_storage_available,
    is_varstore_initialized, is_varstore_writable, with_storage_mut,
};
pub use storage::{SpiStorageBackend, StorageBackend, StorageError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarStoreError {
    NotInitialized,
    InvalidHeader,
    NotFound,
    NameTooLong,
    DataTooLarge,
    StoreFull,
    SpiError,
    InvalidArgument,
    CrcMismatch,
}

pub type Result<T> = core::result::Result<T, VarStoreError>;

//! Boot-only EDK2 variable persistence and runtime-image importer.
//!
//! Persistent records are imported directly into the authoritative runtime
//! image store. The boot image retains no variable copy or EBS snapshot.

pub mod edk2;
#[cfg(feature = "variable-store")]
pub mod persistence;
#[cfg(not(feature = "variable-store"))]
#[path = "volatile.rs"]
pub mod persistence;
pub mod storage;

pub(crate) fn import_variable_into_runtime(
    guid: &r_efi::efi::Guid,
    name: &[u16],
    attributes: u32,
    data: &[u8],
) {
    let status = crate::efi::runtime_image::client::variables::set(guid, name, attributes, data);
    if status != r_efi::efi::Status::SUCCESS {
        log::warn!("Runtime image rejected boot variable update: {:?}", status);
    }
}
#[cfg(feature = "spi-flash")]
pub use persistence::with_spi_storage_mut;
pub use persistence::{get_variable_timestamp, init as init_persistence, is_varstore_writable};
#[cfg(feature = "variable-store")]
pub use persistence::{get_varstore_stats, is_storage_available, is_varstore_initialized};
#[cfg(feature = "spi-flash")]
pub use storage::SpiStorageBackend;
pub use storage::{StorageBackend, StorageError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarStoreError {
    NotInitialized,
    InvalidHeader,
    NotFound,
    NameTooLong,
    DataTooLarge,
    StoreFull,
    StorageFailure,
    InvalidArgument,
    CrcMismatch,
}

pub type Result<T> = core::result::Result<T, VarStoreError>;

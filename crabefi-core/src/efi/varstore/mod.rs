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
    is_varstore_initialized,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SerializedTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanosecond: u32,
    pub timezone: i16,
    pub daylight: u8,
}

impl SerializedTime {
    pub fn is_zero(&self) -> bool {
        self.year == 0
            && self.month == 0
            && self.day == 0
            && self.hour == 0
            && self.minute == 0
            && self.second == 0
            && self.nanosecond == 0
    }

    pub fn is_after(&self, other: &Self) -> bool {
        if other.is_zero() {
            return !self.is_zero();
        }
        (
            self.year,
            self.month,
            self.day,
            self.hour,
            self.minute,
            self.second,
            self.nanosecond,
        ) > (
            other.year,
            other.month,
            other.day,
            other.hour,
            other.minute,
            other.second,
            other.nanosecond,
        )
    }
}

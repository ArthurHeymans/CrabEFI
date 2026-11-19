//! Filesystem operations needed by boot discovery and the native Linux loader.
//!
//! This is deliberately not the EFI File Protocol: writable FAT state and EFI
//! handle semantics stay in Simple File System. Paths use `/` and are relative
//! to the volume root (a leading slash is optional).

use crate::drivers::storage::{self, StorageId};
use crate::fs::fat::{FatError, FatFilesystem};
use crate::fs::gpt::Partition;
use alloc::vec::Vec;
use heapless::String;

#[derive(Debug)]
pub enum ReadError {
    InvalidPath,
    InvalidSize,
    NotAFile,
    OutOfMemory,
    Fat(FatError),
    #[cfg(all(feature = "ext4", target_arch = "x86_64"))]
    Ext(ext4_view::Ext4Error),
}

impl From<FatError> for ReadError {
    fn from(err: FatError) -> Self {
        Self::Fat(err)
    }
}

pub type Names = Vec<String<256>>;

pub trait BootFilesystem {
    fn file_size(&mut self, path: &str) -> Result<u64, ReadError>;

    /// Read up to `out.len()` bytes, stopping at EOF.
    fn read_file_at(&mut self, path: &str, offset: u64, out: &mut [u8])
    -> Result<usize, ReadError>;

    fn list_files(&mut self, directory: &str, suffix: &str) -> Result<Names, ReadError>;
    fn list_subdirectories(&mut self, directory: &str) -> Result<Names, ReadError>;

    /// Read the whole file into caller-owned storage; never silently truncate.
    fn read_file_all(&mut self, path: &str, out: &mut [u8]) -> Result<usize, ReadError> {
        let size = usize::try_from(self.file_size(path)?).map_err(|_| ReadError::InvalidSize)?;
        let out = out.get_mut(..size).ok_or(ReadError::InvalidSize)?;
        let read = self.read_file_at(path, 0, out)?;
        if read != size {
            return Err(ReadError::InvalidSize);
        }
        Ok(read)
    }
}

pub(crate) fn check_path(path: &str) -> Result<(), ReadError> {
    if path.contains('\0') || path.split(['/', '\\']).any(|part| part == "..") {
        return Err(ReadError::InvalidPath);
    }
    Ok(())
}

impl BootFilesystem for FatFilesystem<'_> {
    fn file_size(&mut self, path: &str) -> Result<u64, ReadError> {
        check_path(path)?;
        let entry = self.find_file(path)?;
        if entry.is_directory() {
            return Err(ReadError::NotAFile);
        }
        Ok(u64::from(entry.file_size()))
    }

    fn read_file_at(
        &mut self,
        path: &str,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, ReadError> {
        check_path(path)?;
        let entry = self.find_file(path)?;
        if entry.is_directory() {
            return Err(ReadError::NotAFile);
        }
        if offset >= u64::from(entry.file_size()) || out.is_empty() {
            return Ok(0);
        }
        let len = out.len().min(entry.file_size() as usize - offset as usize);
        Ok(self.read_file(&entry, offset as u32, &mut out[..len])?)
    }

    fn list_files(&mut self, directory: &str, suffix: &str) -> Result<Names, ReadError> {
        check_path(directory)?;
        Ok(self.list_directory_files(directory, suffix)?)
    }

    fn list_subdirectories(&mut self, directory: &str) -> Result<Names, ReadError> {
        check_path(directory)?;
        Ok(FatFilesystem::list_subdirectories(self, directory)?)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Kind {
    Fat,
    #[cfg(all(feature = "ext4", target_arch = "x86_64"))]
    Ext {
        media: crate::drivers::block::BlockDeviceInfo,
        discovery: bool,
    },
}

impl Kind {
    pub(crate) fn for_boot(self) -> Self {
        match self {
            Self::Fat => Self::Fat,
            #[cfg(all(feature = "ext4", target_arch = "x86_64"))]
            Self::Ext { media, .. } => Self::Ext {
                media,
                discovery: false,
            },
        }
    }
}

/// Temporarily mount one boot volume. FAT borrows the device for the closure;
/// ext4-view owns its reader and takes a device borrow for each read instead.
pub(crate) fn with_filesystem<R>(
    storage: StorageId,
    partition: &Partition,
    kind: Kind,
    f: impl FnOnce(&mut dyn BootFilesystem) -> R,
) -> Option<R> {
    match kind {
        Kind::Fat => storage::with_disk(storage, |disk| {
            let mut fs =
                FatFilesystem::new_partition(disk, partition.first_lba, partition.size_sectors())
                    .ok()?;
            Some(f(&mut fs))
        })
        .ok()?,
        #[cfg(all(feature = "ext4", target_arch = "x86_64"))]
        Kind::Ext { media, discovery } => {
            let mut fs = super::ext::ExtFilesystem::mount(storage, partition, media, discovery)?;
            Some(f(&mut fs))
        }
    }
}

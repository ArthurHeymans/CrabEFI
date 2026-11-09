//! Stable EFI protocol slots and shared ownership of live FAT records.
//! This pool performs no device I/O. Deleted records remain tombstoned until
//! their last handle closes, even when FAT reuses the on-disk directory slot.

use alloc::vec::Vec;
use core::ops::{Index, IndexMut};
use r_efi::efi::Status;
use r_efi::protocols::file as efi_file;

use super::path::path_str;
use super::{
    FILE_MODE_CREATE, MAX_PATH_LEN, file_close, file_delete, file_flush, file_flush_ex,
    file_get_info, file_get_position, file_open, file_open_ex, file_read, file_read_ex,
    file_set_info, file_set_position, file_write, file_write_ex,
};
use crate::fs::fat::{FatFile, FileClusterHint};

/// Only the pool constructs indices; callbacks cannot confuse a handle with
/// its shared metadata node or manufacture a slot that was never reserved.
#[derive(Clone, Copy)]
pub(super) struct HandleId(usize);

#[derive(Clone, Copy)]
struct OpenFile {
    file: Option<FatFile>,
    references: usize,
    deleted: bool,
}

impl OpenFile {
    const fn empty() -> Self {
        Self {
            file: None,
            references: 0,
            deleted: false,
        }
    }
}

struct FileHandle {
    in_use: bool,
    node: usize,
    /// Path spelling belongs to this handle, not to the shared record.
    path: [u8; MAX_PATH_LEN],
    path_len: usize,
    /// Independent seek position, cluster hint and access mode.
    position: u64,
    cluster_hint: FileClusterHint,
    /// Zero means a reserved slot whose protocol has not been published.
    open_mode: u64,
    protocol: efi_file::Protocol,
}

impl FileHandle {
    const fn empty() -> Self {
        Self {
            in_use: false,
            node: 0,
            path: [0; MAX_PATH_LEN],
            path_len: 0,
            position: 0,
            cluster_hint: FileClusterHint::new(0),
            open_mode: 0,
            protocol: efi_file::Protocol {
                revision: efi_file::REVISION,
                open: file_open,
                close: file_close,
                delete: file_delete,
                read: file_read,
                write: file_write,
                get_position: file_get_position,
                set_position: file_set_position,
                get_info: file_get_info,
                set_info: file_set_info,
                flush: file_flush,
                open_ex: file_open_ex,
                read_ex: file_read_ex,
                write_ex: file_write_ex,
                flush_ex: file_flush_ex,
            },
        }
    }
}

/// An operation snapshot. Mutations must be returned to the pool afterwards;
/// no reference into the pool is held across FAT/device I/O.
#[derive(Clone, Copy)]
pub(super) struct Snapshot {
    pub(super) file: FatFile,
    pub(super) position: u64,
    pub(super) mode: u64,
    pub(super) hint: FileClusterHint,
    pub(super) path: [u8; MAX_PATH_LEN],
    pub(super) path_len: usize,
}

const SLOTS_PER_SLAB: usize = 16;
// Bound requested handle/record payload and slab headers, not a fixed number
// of simultaneous opens. Allocator failure remains an honest EFI error.
const POOL_BUDGET: usize = 1024 * 1024;
const SLOT_COST: usize = core::mem::size_of::<FileHandle>()
    + core::mem::size_of::<OpenFile>()
    + core::mem::size_of::<Vec<FileHandle>>().div_ceil(SLOTS_PER_SLAB);

/// Inner buffers never resize or move after insertion. Growing the outer Vec
/// moves only Vec headers, never published EFI protocol objects. Closing/reset
/// reuses slots; it does not deallocate their published addresses.
struct StableHandles {
    slabs: Vec<Vec<FileHandle>>,
    len: usize,
}
impl StableHandles {
    const fn new() -> Self {
        Self {
            slabs: Vec::new(),
            len: 0,
        }
    }
    fn len(&self) -> usize {
        self.len
    }
    fn iter(&self) -> impl Iterator<Item = &FileHandle> {
        self.slabs.iter().flat_map(|slab| slab.iter())
    }
}
impl Index<usize> for StableHandles {
    type Output = FileHandle;
    fn index(&self, index: usize) -> &FileHandle {
        &self.slabs[index / SLOTS_PER_SLAB][index % SLOTS_PER_SLAB]
    }
}
impl IndexMut<usize> for StableHandles {
    fn index_mut(&mut self, index: usize) -> &mut FileHandle {
        &mut self.slabs[index / SLOTS_PER_SLAB][index % SLOTS_PER_SLAB]
    }
}

pub(super) struct FilePool {
    handles: StableHandles,
    nodes: Vec<OpenFile>,
    budget: usize,
}

impl FilePool {
    pub(super) const fn new() -> Self {
        Self {
            handles: StableHandles::new(),
            nodes: Vec::new(),
            budget: POOL_BUDGET,
        }
    }

    pub(super) fn index(&self, protocol: *mut efi_file::Protocol) -> Option<HandleId> {
        self.handles
            .iter()
            .position(|handle| {
                handle.in_use && handle.open_mode != 0 && core::ptr::eq(&handle.protocol, protocol)
            })
            .map(HandleId)
    }

    fn grow(&mut self) -> Result<(), Status> {
        let count = self
            .handles
            .len()
            .checked_add(SLOTS_PER_SLAB)
            .ok_or(Status::OUT_OF_RESOURCES)?;
        if count
            .checked_mul(SLOT_COST)
            .is_none_or(|bytes| bytes > self.budget)
        {
            return Err(Status::OUT_OF_RESOURCES);
        }
        let mut slab = Vec::new();
        slab.try_reserve_exact(SLOTS_PER_SLAB)
            .map_err(|_| Status::OUT_OF_RESOURCES)?;
        slab.resize_with(SLOTS_PER_SLAB, FileHandle::empty);
        self.handles
            .slabs
            .try_reserve_exact(1)
            .map_err(|_| Status::OUT_OF_RESOURCES)?;
        self.nodes
            .try_reserve_exact(SLOTS_PER_SLAB)
            .map_err(|_| Status::OUT_OF_RESOURCES)?;
        // No fallible work after this point: failure cannot publish a half
        // slab, consume a reservation or retag a live record/address.
        self.nodes.resize(count, OpenFile::empty());
        self.handles.slabs.push(slab);
        self.handles.len = count;
        Ok(())
    }

    pub(super) fn reserve(&mut self) -> Result<HandleId, Status> {
        let free = self.handles.iter().position(|handle| !handle.in_use);
        let index = match free {
            Some(index) => index,
            None => {
                let index = self.handles.len();
                self.grow()?;
                index
            }
        };
        self.handles[index].in_use = true;
        self.handles[index].open_mode = 0;
        Ok(HandleId(index))
    }

    pub(super) fn snapshot(
        &self,
        protocol: *mut efi_file::Protocol,
    ) -> Result<(HandleId, Snapshot), Status> {
        let index = self.index(protocol).ok_or(Status::INVALID_PARAMETER)?;
        let handle = &self.handles[index.0];
        let node = &self.nodes[handle.node];
        if node.deleted {
            return Err(Status::DEVICE_ERROR);
        }
        Ok((
            index,
            Snapshot {
                file: node.file.ok_or(Status::INVALID_PARAMETER)?,
                position: handle.position,
                mode: handle.open_mode,
                hint: handle.cluster_hint,
                path: handle.path,
                path_len: handle.path_len,
            },
        ))
    }

    pub(super) fn release(&mut self, index: HandleId) {
        let handle = &mut self.handles[index.0];
        if handle.open_mode != 0 {
            let node = &mut self.nodes[handle.node];
            node.references -= 1;
            if node.references == 0 {
                *node = OpenFile::empty();
            }
        }
        handle.in_use = false;
        handle.open_mode = 0;
        handle.path_len = 0;
        handle.position = 0;
        handle.cluster_hint = FileClusterHint::new(0);
    }

    pub(super) fn reset(&mut self) {
        for index in 0..self.handles.len() {
            if self.handles[index].in_use {
                self.release(HandleId(index));
            }
        }
    }

    pub(super) fn attach(
        &mut self,
        index: HandleId,
        file: FatFile,
        path: &str,
        mode: u64,
    ) -> Result<*mut efi_file::Protocol, Status> {
        if path.len() >= MAX_PATH_LEN {
            return Err(Status::INVALID_PARAMETER);
        }
        // FAT32 aliases share record identity, including long and short names.
        // FAT12/16 is read-only; normalized spelling suffices for its metadata.
        let node = self
            .handles
            .iter()
            .filter(|handle| handle.in_use && handle.open_mode != 0)
            .find(|handle| {
                let node = &self.nodes[handle.node];
                !node.deleted
                    && node.file.is_some_and(|old| match (old.id(), file.id()) {
                        (Some(a), Some(b)) => a == b,
                        (None, None) => {
                            path_str(&handle.path, handle.path_len).eq_ignore_ascii_case(path)
                        }
                        _ => false,
                    })
            })
            .map(|handle| handle.node);
        let node = match node {
            Some(node) => node,
            None => {
                let node = self
                    .nodes
                    .iter()
                    .position(|node| node.references == 0)
                    .ok_or(Status::OUT_OF_RESOURCES)?;
                self.nodes[node] = OpenFile {
                    file: Some(file),
                    references: 0,
                    deleted: false,
                };
                node
            }
        };
        self.nodes[node].references += 1;
        let handle = &mut self.handles[index.0];
        handle.node = node;
        handle.path[..path.len()].copy_from_slice(path.as_bytes());
        handle.path_len = path.len();
        handle.position = 0;
        handle.cluster_hint =
            FileClusterHint::new(self.nodes[node].file.unwrap().entry().first_cluster());
        handle.open_mode = mode & !FILE_MODE_CREATE;
        Ok(&raw mut handle.protocol)
    }

    pub(super) fn update_file(&mut self, index: HandleId, file: FatFile) {
        self.nodes[self.handles[index.0].node].file = Some(file);
    }

    pub(super) fn mark_deleted(&mut self, index: HandleId) {
        self.nodes[self.handles[index.0].node].deleted = true;
    }

    pub(super) fn advance(&mut self, index: HandleId, amount: u64) {
        self.handles[index.0].position += amount;
    }

    pub(super) fn finish_read(&mut self, index: HandleId, bytes: usize, hint: FileClusterHint) {
        self.advance(index, bytes as u64);
        self.handles[index.0].cluster_hint = hint;
    }

    pub(super) fn finish_write(&mut self, index: HandleId, file: FatFile, bytes: usize) {
        self.update_file(index, file);
        self.advance(index, bytes as u64);
    }

    pub(super) fn set_position(&mut self, index: HandleId, position: u64) {
        self.handles[index.0].position = position;
    }
}

#[cfg(test)]
#[path = "handles_tests.rs"]
mod tests;

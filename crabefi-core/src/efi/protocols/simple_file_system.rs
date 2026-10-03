//! EFI Simple File System Protocol over the shared FAT implementation.
//!
//! Open files share record identity and metadata. Handles own only access mode,
//! path spelling and cursor state. Device borrows are temporary; allocator and
//! mutation state live for the lifetime of the mount.

use core::ffi::c_void;
use r_efi::efi::{Char16, Guid, Status};
use r_efi::protocols::file as efi_file;
use r_efi::protocols::simple_file_system as efi_sfs;
use spin::Mutex;

use crate::cell::{LocalCell, StaticMut};
use crate::drivers::storage::{self, StorageId};
use crate::fs::fat::{FatError, FatFilesystem, FatGeometry, FatVolumeState};

mod handles;
mod info;
mod path;
use handles::{FilePool, HandleId, Snapshot};
use path::{build_full_path, path_str, strip_device_path_prefix, utf16_to_utf8};

/// A single mounted boot volume. Media IDs are checked when supported by the
/// device; removable devices also reread the BPB. Same-geometry replacements
/// cannot be detected when a driver does not advance its media ID.
#[derive(Clone, Copy)]
pub struct FilesystemState {
    /// Storage device holding the mounted filesystem.
    pub storage: StorageId,
    /// Independently known partition extent, in device blocks.
    pub partition_start: u64,
    pub partition_blocks: u64,
    /// Validated on-media layout, not proof of removable-media identity.
    pub geometry: FatGeometry,
    /// Live device properties captured at mount and rechecked on each borrow.
    pub device_block_size: u32,
    pub removable: bool,
    /// Root directory cluster (FAT32), or zero for FAT12/16 fixed roots.
    pub root_cluster: u32,
    /// Cached writability; every operation also checks the live FAT/device state.
    pub read_only: bool,
    media_id: u32,
    /// Updated after every temporary FAT borrow, including failed operations.
    volume: FatVolumeState,
}

static FILESYSTEM: LocalCell<Option<FilesystemState>> = LocalCell::new(None);
pub const SIMPLE_FILE_SYSTEM_GUID: Guid = efi_sfs::PROTOCOL_GUID;
pub const FILE_INFO_GUID: Guid = efi_file::INFO_ID;
pub const FILE_SYSTEM_INFO_GUID: Guid = efi_file::SYSTEM_INFO_ID;
pub const FILE_SYSTEM_VOLUME_LABEL_GUID: Guid = efi_file::SYSTEM_VOLUME_LABEL_ID;

// Both information formats expose the existing firmware-assigned volume name.
// Reading or renaming the on-media FAT label is not implemented.
const VOLUME_LABEL: &str = "EFI";

// A FAT name may contain 255 BMP characters (up to 765 UTF-8 bytes).
const MAX_PATH_LEN: usize = 1024;
const MAX_FILE_HANDLES: usize = 32;
pub const FILE_MODE_READ: u64 = efi_file::MODE_READ;
pub const FILE_MODE_WRITE: u64 = efi_file::MODE_WRITE;
pub const FILE_MODE_CREATE: u64 = efi_file::MODE_CREATE;
const FILE_MODE_READ_WRITE: u64 = FILE_MODE_READ | FILE_MODE_WRITE;
pub const FILE_DIRECTORY: u64 = efi_file::DIRECTORY;

// Protocol addresses are stable for the lifetime of the firmware. The file-pool
// lock is released before FAT/device I/O; storage owns its exclusive device borrow.
static FILES: Mutex<FilePool> = Mutex::new(FilePool::new());
static SFS_PROTOCOL: StaticMut<efi_sfs::Protocol> = StaticMut::new(efi_sfs::Protocol {
    revision: efi_sfs::REVISION,
    open_volume: sfs_open_volume,
});

/// Mount a volume when no independent partition extent is available.
pub fn init(storage: StorageId, partition_start: u64) -> *mut efi_sfs::Protocol {
    let blocks = storage::with_disk(storage, |disk| {
        disk.info().num_blocks.checked_sub(partition_start)
    });
    match blocks {
        Ok(Some(blocks)) => init_partition(storage, partition_start, blocks),
        _ => core::ptr::null_mut(),
    }
}

/// Mount a boot partition using its GPT/MBR bounds, not its untrusted BPB size.
pub fn init_partition(
    storage: StorageId,
    partition_start: u64,
    partition_blocks: u64,
) -> *mut efi_sfs::Protocol {
    let mounted = storage::with_disk(storage, |disk| {
        let info = disk.info();
        FatFilesystem::new_partition(disk, partition_start, partition_blocks).map(|fat| {
            FilesystemState {
                storage,
                partition_start,
                partition_blocks,
                geometry: fat.geometry(),
                device_block_size: info.block_size,
                removable: info.removable,
                root_cluster: fat.root_cluster(),
                read_only: fat.is_read_only(),
                media_id: info.media_id,
                volume: fat.volume_state(),
            }
        })
    });
    let state = match mounted {
        Ok(Ok(state)) => state,
        Ok(Err(error)) => {
            log::error!(
                "SimpleFileSystem: failed to mount FAT filesystem: {:?}",
                error
            );
            return core::ptr::null_mut();
        }
        Err(error) => {
            log::error!(
                "SimpleFileSystem: storage {:?} unavailable: {}",
                storage,
                error
            );
            return core::ptr::null_mut();
        }
    };
    FILES.lock().reset();
    FILESYSTEM.set(Some(state));
    SFS_PROTOCOL.get()
}

pub fn get_guid() -> &'static Guid {
    &SIMPLE_FILE_SYSTEM_GUID
}

fn snapshot(this: *mut efi_file::Protocol) -> Result<(HandleId, Snapshot), Status> {
    let state = FILESYSTEM.get().ok_or(Status::NOT_READY)?;
    let snapshot = FILES.lock().snapshot(this)?;
    if state.volume.failed() {
        return Err(Status::VOLUME_CORRUPTED);
    }
    Ok(snapshot)
}

extern "efiapi" fn sfs_open_volume(
    _this: *mut efi_sfs::Protocol,
    root: *mut *mut efi_file::Protocol,
) -> Status {
    if root.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let file = match with_fat(|fat| fat.open_file("").map_err(fat_status)) {
        Ok(file) => file,
        Err(status) => return status,
    };
    let mut files = FILES.lock();
    let index = match files.reserve() {
        Ok(index) => index,
        Err(status) => return status,
    };
    match files.attach(index, file, "", FILE_MODE_READ_WRITE) {
        Ok(protocol) => {
            unsafe {
                *root = protocol;
            }
            Status::SUCCESS
        }
        Err(status) => {
            files.release(index);
            status
        }
    }
}

extern "efiapi" fn file_open(
    this: *mut efi_file::Protocol,
    new_handle: *mut *mut efi_file::Protocol,
    file_name: *mut Char16,
    open_mode: u64,
    attributes: u64,
) -> Status {
    if new_handle.is_null() || file_name.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let create = open_mode & FILE_MODE_CREATE != 0;
    let writable = open_mode & FILE_MODE_WRITE != 0;
    if !matches!(
        open_mode & !FILE_MODE_CREATE,
        FILE_MODE_READ | FILE_MODE_READ_WRITE
    ) || (create
        && (!writable || attributes & (!efi_file::VALID_ATTR | efi_file::READ_ONLY) != 0))
    {
        return Status::INVALID_PARAMETER;
    }
    let (_, parent) = match snapshot(this) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let mut name = [0u8; MAX_PATH_LEN];
    let name_len = match unsafe { utf16_to_utf8(file_name, &mut name) } {
        Ok(len) => len,
        Err(status) => return status,
    };
    let mut path = [0u8; MAX_PATH_LEN];
    let base = &parent.path[..parent.path_len];
    let path_len = match build_full_path(
        base,
        parent.file.entry().is_directory(),
        strip_device_path_prefix(path_str(&name, name_len)),
        &mut path,
    ) {
        Ok(len) => len,
        Err(status) => return status,
    };
    let path = path_str(&path, path_len);
    if writable && FILESYSTEM.get().is_none_or(|state| state.read_only) {
        return Status::WRITE_PROTECTED;
    }
    // Reserve a handle before creating anything on disk.
    let index = match FILES.lock().reserve() {
        Ok(index) => index,
        Err(status) => return status,
    };
    let result = with_fat(|fat| {
        if writable && fat.is_read_only() {
            return Err(Status::WRITE_PROTECTED);
        }
        let file = match fat.open_file(path) {
            Ok(file) => {
                if writable
                    && !file.entry().is_directory()
                    && file.entry().attributes() & efi_file::READ_ONLY as u8 != 0
                {
                    return Err(Status::ACCESS_DENIED);
                }
                file
            }
            Err(FatError::NotFound) if create => fat
                .create_with_attributes(path, attributes as u8)
                .map_err(fat_status)?,
            Err(error) => return Err(fat_status(error)),
        };
        Ok(file)
    });
    let mut files = FILES.lock();
    let result = result.and_then(|file| files.attach(index, file, path, open_mode));
    match result {
        Ok(protocol) => {
            unsafe {
                *new_handle = protocol;
            }
            Status::SUCCESS
        }
        Err(status) => {
            files.release(index);
            status
        }
    }
}

extern "efiapi" fn file_close(this: *mut efi_file::Protocol) -> Status {
    let index = match FILES.lock().index(this) {
        Some(index) => index,
        None => return Status::INVALID_PARAMETER,
    };
    let result = with_fat(|fat| fat.flush().map_err(fat_status));
    // Even a failed flush must not leak a handle. A poisoned volume remains
    // dirty and rejects later access; Close must never disguise that failure.
    FILES.lock().release(index);
    result.map_or_else(|status| status, |()| Status::SUCCESS)
}

extern "efiapi" fn file_delete(this: *mut efi_file::Protocol) -> Status {
    let index = match FILES.lock().index(this) {
        Some(index) => index,
        None => return Status::INVALID_PARAMETER,
    };
    let result = snapshot(this).and_then(|(_, handle)| {
        if handle.mode & FILE_MODE_WRITE == 0 {
            return Err(Status::ACCESS_DENIED);
        }
        with_fat(|fat| fat.delete_file(&handle.file).map_err(fat_status))?;
        FILES.lock().mark_deleted(index);
        Ok(())
    });
    // Delete closes the handle even when deletion fails. Finalize pending
    // mutations as Close does; a successful unlink alone does not mark the
    // volume clean. Aliases are invalidated before a final flush can fail.
    let flushed = with_fat(|fat| fat.flush().map_err(fat_status));
    FILES.lock().release(index);
    if result.is_ok() && flushed.is_ok() {
        Status::SUCCESS
    } else {
        Status::WARN_DELETE_FAILURE
    }
}

extern "efiapi" fn file_read(
    this: *mut efi_file::Protocol,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    if buffer_size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let requested = unsafe { *buffer_size };
    let (index, handle) = match snapshot(this) {
        Ok(value) => value,
        Err(status) => return status,
    };
    if handle.file.entry().is_directory() {
        return read_directory(buffer_size, buffer, index, handle);
    }
    if requested > 0 && buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let size = handle.file.entry().file_size() as u64;
    if handle.position > size {
        unsafe {
            *buffer_size = 0;
        }
        return Status::DEVICE_ERROR;
    }
    if handle.position == size || requested == 0 {
        unsafe {
            *buffer_size = 0;
        }
        return Status::SUCCESS;
    }
    let count = requested.min((size - handle.position) as usize);
    let output = unsafe { core::slice::from_raw_parts_mut(buffer.cast::<u8>(), count) };
    let mut hint = handle.hint;
    match with_fat(|fat| {
        fat.read_file_with_hint(
            &handle.file.entry(),
            handle.position as u32,
            output,
            &mut hint,
        )
        .map_err(fat_status)
    }) {
        Ok(read) => {
            FILES.lock().finish_read(index, read, hint);
            unsafe {
                *buffer_size = read;
            }
            Status::SUCCESS
        }
        Err(status) => {
            unsafe {
                *buffer_size = 0;
            }
            status
        }
    }
}

extern "efiapi" fn file_write(
    this: *mut efi_file::Protocol,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    if buffer_size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let requested = unsafe { *buffer_size };
    if requested > 0 && buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }
    unsafe {
        *buffer_size = 0;
    }
    let (index, handle) = match snapshot(this) {
        Ok(value) => value,
        Err(status) => return status,
    };
    if handle.file.entry().is_directory() {
        return Status::UNSUPPORTED;
    }
    if handle.mode & FILE_MODE_WRITE == 0 {
        return Status::ACCESS_DENIED;
    }
    if FILESYSTEM.get().is_none_or(|state| state.read_only)
        || handle.file.entry().attributes() & efi_file::READ_ONLY as u8 != 0
    {
        return Status::WRITE_PROTECTED;
    }
    if requested == 0 {
        return Status::SUCCESS;
    }
    let Ok(offset) = u32::try_from(handle.position) else {
        return Status::UNSUPPORTED;
    };
    let data = unsafe { core::slice::from_raw_parts(buffer.cast::<u8>(), requested) };
    let mut file = handle.file;
    let mut written = 0;
    let result = with_fat(|fat| match fat.write_file(&mut file, offset, data) {
        Ok(count) => {
            written = count;
            Ok(())
        }
        Err(error) => {
            written = error.written;
            Err(fat_status(error.error))
        }
    });
    FILES.lock().finish_write(index, file, written);
    unsafe {
        *buffer_size = written;
    }
    result.map_or_else(|status| status, |()| Status::SUCCESS)
}

extern "efiapi" fn file_get_position(this: *mut efi_file::Protocol, position: *mut u64) -> Status {
    if position.is_null() {
        return Status::INVALID_PARAMETER;
    }
    match snapshot(this) {
        Ok((_, handle)) if !handle.file.entry().is_directory() => {
            unsafe {
                *position = handle.position;
            }
            Status::SUCCESS
        }
        Ok(_) => Status::UNSUPPORTED,
        Err(status) => status,
    }
}

extern "efiapi" fn file_set_position(this: *mut efi_file::Protocol, position: u64) -> Status {
    let (index, handle) = match snapshot(this) {
        Ok(value) => value,
        Err(status) => return status,
    };
    if handle.file.entry().is_directory() && position != 0 {
        return Status::UNSUPPORTED;
    }
    FILES.lock().set_position(
        index,
        if position == u64::MAX {
            handle.file.entry().file_size() as u64
        } else {
            position
        },
    );
    Status::SUCCESS
}

extern "efiapi" fn file_get_info(
    this: *mut efi_file::Protocol,
    info_type: *mut Guid,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    if info_type.is_null() || buffer_size.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let (_, handle) = match snapshot(this) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let guid = unsafe { *info_type };
    if guid == FILE_INFO_GUID {
        let name = path_str(&handle.path, handle.path_len)
            .rsplit('/')
            .next()
            .unwrap_or("");
        return fill_file_info(handle.file.entry(), name, buffer_size, buffer);
    }
    if guid == FILE_SYSTEM_VOLUME_LABEL_GUID {
        return unsafe { info::write_volume_label(buffer, buffer_size, VOLUME_LABEL) };
    }
    if guid != FILE_SYSTEM_INFO_GUID {
        return Status::UNSUPPORTED;
    }
    let label = VOLUME_LABEL;
    let required = info::system_info_size(label);
    if unsafe { *buffer_size } < required {
        unsafe {
            *buffer_size = required;
        }
        return Status::BUFFER_TOO_SMALL;
    }
    if buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let (volume_size, free_space) =
        match with_fat(|fat| Ok((fat.volume_size(), fat.free_space().map_err(fat_status)?))) {
            Ok(value) => value,
            Err(status) => return status,
        };
    let state = FILESYSTEM.get().unwrap();
    unsafe {
        info::write_system_info(
            buffer,
            buffer_size,
            state.read_only,
            volume_size,
            free_space,
            state.device_block_size,
            label,
        )
    }
}

extern "efiapi" fn file_set_info(
    this: *mut efi_file::Protocol,
    info_type: *mut Guid,
    buffer_size: usize,
    buffer: *mut c_void,
) -> Status {
    if info_type.is_null() || buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }
    if unsafe { *info_type } != FILE_INFO_GUID {
        return Status::UNSUPPORTED;
    }
    if buffer_size < core::mem::size_of::<efi_file::Info>() {
        return Status::BAD_BUFFER_SIZE;
    }
    let (index, handle) = match snapshot(this) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let entry = handle.file.entry();
    let name = path_str(&handle.path, handle.path_len)
        .rsplit('/')
        .next()
        .unwrap_or("");
    let input = unsafe { core::slice::from_raw_parts(buffer.cast::<u8>(), buffer_size) };
    let update = match info::read_file_info(input, name) {
        Ok(update) => update,
        Err(status) => return status,
    };
    if update.attributes & !efi_file::VALID_ATTR != 0 {
        return Status::INVALID_PARAMETER;
    }
    if (update.attributes ^ entry.attributes() as u64) & FILE_DIRECTORY != 0 {
        return Status::ACCESS_DENIED;
    }
    // Rename, timestamps and growing SetInfo are intentionally unsupported.
    let Ok(size) = u32::try_from(update.file_size) else {
        return Status::UNSUPPORTED;
    };
    if size > entry.file_size() {
        return Status::UNSUPPORTED;
    }
    if size != entry.file_size() && (entry.is_directory() || handle.mode & FILE_MODE_WRITE == 0) {
        return Status::ACCESS_DENIED;
    }
    let mut file = handle.file;
    let result = with_fat(|fat| {
        if size != entry.file_size() {
            fat.truncate_file(&mut file, size).map_err(fat_status)?;
        }
        if update.attributes != file.entry().attributes() as u64 {
            fat.set_attributes(&mut file, update.attributes as u8)
                .map_err(fat_status)?;
        }
        Ok(())
    });
    FILES.lock().update_file(index, file);
    // Truncation changes shared metadata, not another handle's independent seek.
    result.map_or_else(|status| status, |()| Status::SUCCESS)
}

extern "efiapi" fn file_flush(this: *mut efi_file::Protocol) -> Status {
    let (_, handle) = match snapshot(this) {
        Ok(value) => value,
        Err(status) => return status,
    };
    if handle.mode & FILE_MODE_WRITE == 0 {
        return Status::ACCESS_DENIED;
    }
    if FILESYSTEM.get().is_none_or(|state| state.read_only)
        || handle.file.entry().attributes() & efi_file::READ_ONLY as u8 != 0
    {
        return Status::WRITE_PROTECTED;
    }
    with_fat(|fat| fat.flush().map_err(fat_status))
        .map_or_else(|status| status, |()| Status::SUCCESS)
}

extern "efiapi" fn file_open_ex(
    _this: *mut efi_file::Protocol,
    _new_handle: *mut *mut efi_file::Protocol,
    _file_name: *mut Char16,
    _open_mode: u64,
    _attributes: u64,
    _token: *mut efi_file::IoToken,
) -> Status {
    Status::UNSUPPORTED
}
extern "efiapi" fn file_read_ex(
    _this: *mut efi_file::Protocol,
    _token: *mut efi_file::IoToken,
) -> Status {
    Status::UNSUPPORTED
}
extern "efiapi" fn file_write_ex(
    _this: *mut efi_file::Protocol,
    _token: *mut efi_file::IoToken,
) -> Status {
    Status::UNSUPPORTED
}
extern "efiapi" fn file_flush_ex(
    _this: *mut efi_file::Protocol,
    _token: *mut efi_file::IoToken,
) -> Status {
    Status::UNSUPPORTED
}

fn with_fat<R>(f: impl FnOnce(&mut FatFilesystem) -> Result<R, Status>) -> Result<R, Status> {
    let mut state = FILESYSTEM.get().ok_or(Status::NOT_READY)?;
    storage::with_disk(state.storage, |device| {
        let info = device.info();
        if info.media_id != state.media_id || info.block_size != state.device_block_size {
            return Err(Status::MEDIA_CHANGED);
        }
        if state.removable {
            let fat =
                FatFilesystem::new_partition(device, state.partition_start, state.partition_blocks)
                    .map_err(fat_status)?;
            if fat.geometry() != state.geometry {
                return Err(Status::MEDIA_CHANGED);
            }
        }
        let mut fat = FatFilesystem::from_geometry_in_partition(
            device,
            state.partition_start,
            state.partition_blocks,
            state.geometry,
            state.volume,
        )
        .map_err(fat_status)?;
        let result = f(&mut fat);
        state.volume = fat.volume_state();
        state.read_only = fat.is_read_only();
        FILESYSTEM.set(Some(state));
        result
    })
    .map_err(|error| match error {
        crate::drivers::block::BlockError::MediaChanged => Status::MEDIA_CHANGED,
        crate::drivers::block::BlockError::NoMedia => Status::NO_MEDIA,
        _ => Status::DEVICE_ERROR,
    })?
}

fn fat_status(error: FatError) -> Status {
    match error {
        FatError::NotFound => Status::NOT_FOUND,
        FatError::AlreadyExists | FatError::DirectoryNotEmpty => Status::ACCESS_DENIED,
        FatError::ReadOnly => Status::WRITE_PROTECTED,
        FatError::InvalidName | FatError::NotADirectory | FatError::NotAFile => {
            Status::INVALID_PARAMETER
        }
        FatError::NoSpace => Status::VOLUME_FULL,
        FatError::InvalidBpb | FatError::InvalidCluster | FatError::NotFat => {
            Status::VOLUME_CORRUPTED
        }
        _ => Status::DEVICE_ERROR,
    }
}

fn fill_file_info(
    entry: crate::fs::fat::DirectoryEntry,
    name: &str,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    unsafe {
        info::write_file_info(
            buffer,
            buffer_size,
            entry.file_size() as u64,
            entry.attributes() as u64,
            name,
        )
    }
}

fn read_directory(
    buffer_size: *mut usize,
    buffer: *mut c_void,
    index: HandleId,
    handle: Snapshot,
) -> Status {
    let result = with_fat(|fat| {
        fat.get_directory_entry_at_position(
            handle.file.entry().first_cluster(),
            handle.position as usize,
        )
        .map_err(fat_status)
    });
    match result {
        Ok(Some((entry, name))) => {
            let status = fill_file_info(entry, &name, buffer_size, buffer);
            if status == Status::SUCCESS {
                FILES.lock().advance(index, 1);
            }
            status
        }
        Ok(None) => {
            unsafe {
                *buffer_size = 0;
            }
            Status::SUCCESS
        }
        Err(status) => status,
    }
}

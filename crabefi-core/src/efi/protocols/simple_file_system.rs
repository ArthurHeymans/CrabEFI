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
use crate::fs::fat::{
    FatError, FatFile, FatFilesystem, FatGeometry, FatVolumeState, FileClusterHint,
};

/// A single mounted boot volume. Media IDs are checked when supported by the
/// device; removable devices also reread the BPB. Same-geometry replacements
/// cannot be detected when a driver does not advance its media ID.
#[derive(Clone, Copy)]
pub struct FilesystemState {
    pub storage: StorageId,
    pub partition_start: u64,
    pub partition_blocks: u64,
    pub geometry: FatGeometry,
    pub device_block_size: u32,
    pub removable: bool,
    pub root_cluster: u32,
    pub read_only: bool,
    media_id: u32,
    volume: FatVolumeState,
}

static FILESYSTEM: LocalCell<Option<FilesystemState>> = LocalCell::new(None);
pub const SIMPLE_FILE_SYSTEM_GUID: Guid = efi_sfs::PROTOCOL_GUID;
pub const FILE_INFO_GUID: Guid = efi_file::INFO_ID;
pub const FILE_SYSTEM_INFO_GUID: Guid = efi_file::SYSTEM_INFO_ID;

// A FAT name may contain 255 BMP characters (up to 765 UTF-8 bytes).
const MAX_PATH_LEN: usize = 1024;
const MAX_FILE_HANDLES: usize = 32;
pub const FILE_MODE_READ: u64 = efi_file::MODE_READ;
pub const FILE_MODE_WRITE: u64 = efi_file::MODE_WRITE;
pub const FILE_MODE_CREATE: u64 = efi_file::MODE_CREATE;
const FILE_MODE_READ_WRITE: u64 = FILE_MODE_READ | FILE_MODE_WRITE;
pub const FILE_DIRECTORY: u64 = efi_file::DIRECTORY;

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
    path: [u8; MAX_PATH_LEN],
    path_len: usize,
    position: u64,
    cluster_hint: FileClusterHint,
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

struct FilePool {
    handles: [FileHandle; MAX_FILE_HANDLES],
    nodes: [OpenFile; MAX_FILE_HANDLES],
}
impl FilePool {
    const fn new() -> Self {
        Self {
            handles: [const { FileHandle::empty() }; MAX_FILE_HANDLES],
            nodes: [OpenFile::empty(); MAX_FILE_HANDLES],
        }
    }

    fn index(&self, protocol: *mut efi_file::Protocol) -> Option<usize> {
        self.handles
            .iter()
            .position(|handle| handle.in_use && core::ptr::eq(&handle.protocol, protocol))
    }

    fn release(&mut self, index: usize) {
        let handle = &mut self.handles[index];
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

    fn attach(
        &mut self,
        index: usize,
        file: FatFile,
        path: &str,
        mode: u64,
    ) -> Result<*mut efi_file::Protocol, Status> {
        // FAT32 record offsets identify aliases (including short names). FAT12/16
        // is read-only; normalized spelling suffices for its shared metadata.
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
        let handle = &mut self.handles[index];
        handle.in_use = true;
        handle.node = node;
        handle.path[..path.len()].copy_from_slice(path.as_bytes());
        handle.path_len = path.len();
        handle.position = 0;
        handle.cluster_hint =
            FileClusterHint::new(self.nodes[node].file.unwrap().entry().first_cluster());
        handle.open_mode = mode & !FILE_MODE_CREATE;
        Ok(&raw mut handle.protocol)
    }
}

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
        error => {
            log::error!("SimpleFileSystem: mount failed: {:?}", error.err());
            return core::ptr::null_mut();
        }
    };
    {
        let mut files = FILES.lock();
        for index in 0..MAX_FILE_HANDLES {
            if files.handles[index].in_use {
                files.release(index);
            }
        }
    }
    FILESYSTEM.set(Some(state));
    SFS_PROTOCOL.get()
}

pub fn get_guid() -> &'static Guid {
    &SIMPLE_FILE_SYSTEM_GUID
}

#[derive(Clone, Copy)]
struct Snapshot {
    node: usize,
    file: FatFile,
    position: u64,
    mode: u64,
    hint: FileClusterHint,
    path: [u8; MAX_PATH_LEN],
    path_len: usize,
}

fn snapshot(this: *mut efi_file::Protocol) -> Result<(usize, Snapshot), Status> {
    let state = FILESYSTEM.get().ok_or(Status::NOT_READY)?;
    if state.volume.failed() {
        return Err(Status::VOLUME_CORRUPTED);
    }
    let files = FILES.lock();
    let index = files.index(this).ok_or(Status::INVALID_PARAMETER)?;
    let handle = &files.handles[index];
    let node = &files.nodes[handle.node];
    if node.deleted {
        return Err(Status::DEVICE_ERROR);
    }
    let file = node.file.ok_or(Status::INVALID_PARAMETER)?;
    Ok((
        index,
        Snapshot {
            node: handle.node,
            file,
            position: handle.position,
            mode: handle.open_mode,
            hint: handle.cluster_hint,
            path: handle.path,
            path_len: handle.path_len,
        },
    ))
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
    let Some(index) = files.handles.iter().position(|handle| !handle.in_use) else {
        return Status::OUT_OF_RESOURCES;
    };
    match files.attach(index, file, "", FILE_MODE_READ_WRITE) {
        Ok(protocol) => {
            unsafe {
                *root = protocol;
            }
            Status::SUCCESS
        }
        Err(status) => status,
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
    let name_len = match utf16_to_utf8(file_name, &mut name) {
        Ok(len) => len,
        Err(status) => return status,
    };
    let mut path = [0u8; MAX_PATH_LEN];
    let base = &parent.path[..parent.path_len];
    let base_len = if parent.file.entry().is_directory() {
        base.len()
    } else {
        base.iter().rposition(|&byte| byte == b'/').unwrap_or(0)
    };
    let path_len = match build_full_path(
        &base[..base_len],
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
    let index = {
        let mut files = FILES.lock();
        let Some(index) = files.handles.iter().position(|handle| !handle.in_use) else {
            return Status::OUT_OF_RESOURCES;
        };
        files.handles[index].in_use = true;
        files.handles[index].open_mode = 0;
        index
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
        FILES.lock().nodes[handle.node].deleted = true;
        Ok(())
    });
    FILES.lock().release(index);
    if result.is_ok() {
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
            let mut files = FILES.lock();
            files.handles[index].position += read as u64;
            files.handles[index].cluster_hint = hint;
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
    let mut files = FILES.lock();
    files.nodes[handle.node].file = Some(file);
    files.handles[index].position += written as u64;
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
    FILES.lock().handles[index].position = if position == u64::MAX {
        handle.file.entry().file_size() as u64
    } else {
        position
    };
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
    if guid != FILE_SYSTEM_INFO_GUID {
        return Status::UNSUPPORTED;
    }
    let label = "EFI";
    let label_offset = core::mem::offset_of!(efi_file::SystemInfo, volume_label);
    let required = label_offset + (label.len() + 1) * 2;
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
    let info = buffer.cast::<efi_file::SystemInfo>();
    unsafe {
        // The flexible label starts before SystemInfo's trailing padding.
        // Initialize padding too, without requiring caller-buffer alignment.
        buffer.cast::<u8>().write_bytes(0, required);
        core::ptr::addr_of_mut!((*info).size).write_unaligned(required as u64);
        core::ptr::addr_of_mut!((*info).read_only).write_unaligned(state.read_only.into());
        core::ptr::addr_of_mut!((*info).volume_size).write_unaligned(volume_size);
        core::ptr::addr_of_mut!((*info).free_space).write_unaligned(free_space);
        core::ptr::addr_of_mut!((*info).block_size).write_unaligned(state.device_block_size);
        let name = buffer.cast::<u8>().add(label_offset).cast::<u16>();
        for (index, unit) in label.encode_utf16().chain([0]).enumerate() {
            name.add(index).write_unaligned(unit);
        }
        *buffer_size = required;
    }
    Status::SUCCESS
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
    let (_, handle) = match snapshot(this) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let info = unsafe { buffer.cast::<efi_file::Info>().read_unaligned() };
    let entry = handle.file.entry();
    let name = path_str(&handle.path, handle.path_len)
        .rsplit('/')
        .next()
        .unwrap_or("");
    if !requested_name_matches(buffer, buffer_size, name) {
        return Status::UNSUPPORTED;
    }
    if info.attribute & !efi_file::VALID_ATTR != 0 {
        return Status::INVALID_PARAMETER;
    }
    if (info.attribute ^ entry.attributes() as u64) & FILE_DIRECTORY != 0 {
        return Status::ACCESS_DENIED;
    }
    // Rename, timestamps and growing SetInfo are intentionally unsupported.
    if !zero_time(info.create_time)
        || !zero_time(info.last_access_time)
        || !zero_time(info.modification_time)
    {
        return Status::UNSUPPORTED;
    }
    let Ok(size) = u32::try_from(info.file_size) else {
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
        if info.attribute != file.entry().attributes() as u64 {
            fat.set_attributes(&mut file, info.attribute as u8)
                .map_err(fat_status)?;
        }
        Ok(())
    });
    FILES.lock().nodes[handle.node].file = Some(file);
    // Truncation changes shared metadata, not another handle's independent seek.
    result.map_or_else(|status| status, |()| Status::SUCCESS)
}

fn zero_time(time: r_efi::efi::Time) -> bool {
    time.year == 0
        && time.month == 0
        && time.day == 0
        && time.hour == 0
        && time.minute == 0
        && time.second == 0
        && time.nanosecond == 0
        && time.timezone == 0
        && time.daylight == 0
}

fn requested_name_matches(buffer: *mut c_void, buffer_size: usize, current_name: &str) -> bool {
    let header = core::mem::size_of::<efi_file::Info>();
    let max = (buffer_size - header) / 2;
    // A header-only request retains the current name. Otherwise require a
    // terminator; an unterminated different name must not silently succeed.
    if max == 0 {
        return true;
    }
    let ptr = unsafe { buffer.cast::<u8>().add(header).cast::<u16>() };
    let mut current = current_name.encode_utf16();
    for index in 0..max {
        let unit = unsafe { ptr.add(index).read_unaligned() };
        if unit == 0 {
            return index == 0 || current.next().is_none();
        }
        if current.next() != Some(unit) {
            return false;
        }
    }
    false
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

fn path_str(path: &[u8; MAX_PATH_LEN], len: usize) -> &str {
    core::str::from_utf8(&path[..len]).unwrap_or("")
}

fn utf16_to_utf8(src: *mut Char16, dst: &mut [u8]) -> Result<usize, Status> {
    let mut len = 0;
    let mut terminated = false;
    let units = (0..MAX_PATH_LEN)
        .map(|index| unsafe { *src.add(index) })
        .take_while(|&unit| {
            if unit == 0 {
                terminated = true;
                false
            } else {
                true
            }
        });
    for ch in core::char::decode_utf16(units) {
        let ch = ch.map_err(|_| Status::INVALID_PARAMETER)?;
        if len + ch.len_utf8() >= dst.len() {
            return Err(Status::INVALID_PARAMETER);
        }
        len += ch.encode_utf8(&mut dst[len..]).len();
    }
    // Reject an unterminated source instead of silently truncating a name.
    if !terminated {
        return Err(Status::INVALID_PARAMETER);
    }
    dst[len] = 0;
    Ok(len)
}

fn strip_device_path_prefix(path: &str) -> &str {
    if !["PciRoot(", "Pci(", "HD(", "Acpi("]
        .iter()
        .any(|prefix| path.starts_with(prefix))
    {
        return path;
    }
    path.rfind(")\\")
        .or_else(|| path.rfind(")/"))
        .map_or(path, |index| &path[index + 2..])
}

fn build_full_path(
    parent: &[u8],
    name: &str,
    output: &mut [u8; MAX_PATH_LEN],
) -> Result<usize, Status> {
    let mut path = heapless::String::<MAX_PATH_LEN>::new();
    if !name.starts_with(['/', '\\']) {
        path.push_str(core::str::from_utf8(parent).map_err(|_| Status::INVALID_PARAMETER)?)
            .map_err(|_| Status::INVALID_PARAMETER)?;
        if !path.is_empty() {
            path.push('/').map_err(|_| Status::INVALID_PARAMETER)?;
        }
    }
    path.push_str(name).map_err(|_| Status::INVALID_PARAMETER)?;
    let mut len = 0;
    for part in path
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != ".")
    {
        if part == ".." {
            len = output[..len]
                .iter()
                .rposition(|&byte| byte == b'/')
                .unwrap_or(0);
            continue;
        }
        if len != 0 {
            output[len] = b'/';
            len += 1;
        }
        if len + part.len() >= output.len() {
            return Err(Status::INVALID_PARAMETER);
        }
        output[len..len + part.len()].copy_from_slice(part.as_bytes());
        len += part.len();
    }
    output[len] = 0;
    Ok(len)
}

fn fill_file_info(
    entry: crate::fs::fat::DirectoryEntry,
    name: &str,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    let required = core::mem::size_of::<efi_file::Info>() + (name.encode_utf16().count() + 1) * 2;
    if unsafe { *buffer_size } < required {
        unsafe {
            *buffer_size = required;
        }
        return Status::BUFFER_TOO_SMALL;
    }
    if buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let info = buffer.cast::<efi_file::Info>();
    unsafe {
        info.write_unaligned(efi_file::Info {
            size: required as u64,
            file_size: entry.file_size() as u64,
            physical_size: entry.file_size() as u64,
            create_time: core::mem::zeroed(),
            last_access_time: core::mem::zeroed(),
            modification_time: core::mem::zeroed(),
            attribute: entry.attributes() as u64,
            file_name: [],
        });
        let ptr = buffer
            .cast::<u8>()
            .add(core::mem::size_of::<efi_file::Info>())
            .cast::<u16>();
        for (index, unit) in name.encode_utf16().chain([0]).enumerate() {
            ptr.add(index).write_unaligned(unit);
        }
        *buffer_size = required;
    }
    Status::SUCCESS
}

fn read_directory(
    buffer_size: *mut usize,
    buffer: *mut c_void,
    index: usize,
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
                FILES.lock().handles[index].position += 1;
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

//! EFI Simple File System Protocol
//!
//! This module provides the EFI_SIMPLE_FILE_SYSTEM_PROTOCOL and EFI_FILE_PROTOCOL
//! which allow UEFI applications to access files on the boot filesystem.

use core::ffi::c_void;
use r_efi::efi::{Char16, Guid, Status};
use r_efi::protocols::file as efi_file;
use r_efi::protocols::simple_file_system as efi_sfs;
use spin::Mutex;

use crate::state;

// Re-export FilesystemState for backward compatibility with lib.rs
pub use crate::state::FilesystemState;

/// Re-export GUIDs
pub const SIMPLE_FILE_SYSTEM_GUID: Guid = efi_sfs::PROTOCOL_GUID;
pub const FILE_INFO_GUID: Guid = efi_file::INFO_ID;
pub const FILE_SYSTEM_INFO_GUID: Guid = efi_file::SYSTEM_INFO_ID;

/// Maximum path length supported
const MAX_PATH_LEN: usize = 256;

/// Maximum number of open file handles
const MAX_FILE_HANDLES: usize = 32;

/// File open modes
pub const FILE_MODE_READ: u64 = efi_file::MODE_READ;
pub const FILE_MODE_WRITE: u64 = efi_file::MODE_WRITE;
pub const FILE_MODE_CREATE: u64 = efi_file::MODE_CREATE;

/// File attributes
pub const FILE_DIRECTORY: u64 = efi_file::DIRECTORY;

/// File handle state
struct FileHandle {
    /// Whether this handle is in use
    in_use: bool,
    /// Path (UTF-8, normalized)
    path: [u8; MAX_PATH_LEN],
    /// Path length
    path_len: usize,
    /// Current position in file
    position: u64,
    /// File size (0 for directories)
    file_size: u64,
    /// First cluster of file
    first_cluster: u32,
    /// Is this a directory?
    is_directory: bool,
    /// The File Protocol struct for this handle
    protocol: efi_file::Protocol,
}

impl FileHandle {
    const fn empty() -> Self {
        Self {
            in_use: false,
            path: [0; MAX_PATH_LEN],
            path_len: 0,
            position: 0,
            file_size: 0,
            first_cluster: 0,
            is_directory: false,
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

/// Global file handle pool
/// Note: This remains a static because FileHandle contains efi_file::Protocol
/// with function pointers that reference back to the handles.
static FILE_HANDLES: Mutex<[FileHandle; MAX_FILE_HANDLES]> =
    Mutex::new([const { FileHandle::empty() }; MAX_FILE_HANDLES]);

/// Simple File System Protocol instance
static mut SFS_PROTOCOL: efi_sfs::Protocol = efi_sfs::Protocol {
    revision: efi_sfs::REVISION,
    open_volume: sfs_open_volume,
};

/// Initialize the simple file system protocol with filesystem parameters
pub fn init(
    fs_state: FilesystemState,
    read_fn: fn(u64, &mut [u8]) -> Result<(), ()>,
) -> *mut efi_sfs::Protocol {
    state::with_efi_mut(|efi| {
        efi.filesystem = Some(fs_state);
        efi.disk_read_fn = Some(read_fn);
    });

    log::info!(
        "SimpleFileSystem: initialized with partition at LBA {}",
        fs_state.partition_start
    );

    &raw mut SFS_PROTOCOL
}

/// Get the Simple File System Protocol GUID
pub fn get_guid() -> &'static Guid {
    &SIMPLE_FILE_SYSTEM_GUID
}

// ============================================================================
// Simple File System Protocol Functions
// ============================================================================

extern "efiapi" fn sfs_open_volume(
    _this: *mut efi_sfs::Protocol,
    root: *mut *mut efi_file::Protocol,
) -> Status {
    log::debug!("SFS.OpenVolume()");

    if root.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Allocate a file handle for the root directory
    let mut handles = FILE_HANDLES.lock();

    // Find a free handle slot
    let handle_idx = match handles.iter().position(|h| !h.in_use) {
        Some(idx) => idx,
        None => {
            log::error!("SFS.OpenVolume: no free file handles");
            return Status::OUT_OF_RESOURCES;
        }
    };

    // Initialize as root directory
    let fs_state = match state::efi().filesystem {
        Some(s) => s,
        None => {
            log::error!("SFS.OpenVolume: filesystem not initialized");
            return Status::NOT_READY;
        }
    };

    handles[handle_idx].in_use = true;
    handles[handle_idx].path[0] = 0;
    handles[handle_idx].path_len = 0;
    handles[handle_idx].position = 0;
    handles[handle_idx].file_size = 0;
    handles[handle_idx].first_cluster = fs_state.root_cluster;
    handles[handle_idx].is_directory = true;

    // Return pointer to the protocol in this handle
    unsafe {
        *root = &raw mut handles[handle_idx].protocol;
    }

    log::debug!(
        "SFS.OpenVolume: opened root directory, handle_idx={}",
        handle_idx
    );
    Status::SUCCESS
}

// ============================================================================
// File Protocol Functions
// ============================================================================

extern "efiapi" fn file_open(
    this: *mut efi_file::Protocol,
    new_handle: *mut *mut efi_file::Protocol,
    file_name: *mut Char16,
    open_mode: u64,
    _attributes: u64,
) -> Status {
    if this.is_null() || new_handle.is_null() || file_name.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Only read mode is supported
    if open_mode != FILE_MODE_READ {
        log::debug!("File.Open: only read mode supported, got {:#x}", open_mode);
        return Status::UNSUPPORTED;
    }

    // Convert UTF-16 filename to UTF-8
    let mut utf8_name = [0u8; MAX_PATH_LEN];
    let name_len = utf16_to_utf8(file_name, &mut utf8_name);
    let name_str = core::str::from_utf8(&utf8_name[..name_len]).unwrap_or("");

    log::info!("File.Open({:?})", name_str);

    // Get parent handle info
    let (parent_path, parent_path_len) = {
        let handles = FILE_HANDLES.lock();
        let parent_idx = match find_handle_index_unlocked(&handles, this) {
            Some(idx) => idx,
            None => return Status::INVALID_PARAMETER,
        };
        let mut path = [0u8; MAX_PATH_LEN];
        let len = handles[parent_idx].path_len;
        path[..len].copy_from_slice(&handles[parent_idx].path[..len]);
        (path, len)
    };

    // Build full path
    let mut full_path = [0u8; MAX_PATH_LEN];
    let full_path_len = build_full_path(&parent_path[..parent_path_len], name_str, &mut full_path);
    let full_path_str = core::str::from_utf8(&full_path[..full_path_len]).unwrap_or("");

    log::info!("File.Open: full path = {:?}", full_path_str);

    // Look up the file in the filesystem
    let efi = state::efi();
    let fs_state = match efi.filesystem {
        Some(s) => s,
        None => return Status::NOT_READY,
    };

    let read_fn = match efi.disk_read_fn {
        Some(f) => f,
        None => return Status::NOT_READY,
    };

    // Find the file
    match find_file(&fs_state, read_fn, full_path_str) {
        Ok((cluster, size, is_dir)) => {
            // Allocate a new file handle
            let mut handles = FILE_HANDLES.lock();
            let handle_idx = match handles.iter().position(|h| !h.in_use) {
                Some(idx) => idx,
                None => return Status::OUT_OF_RESOURCES,
            };

            handles[handle_idx].in_use = true;
            handles[handle_idx].path[..full_path_len].copy_from_slice(&full_path[..full_path_len]);
            handles[handle_idx].path_len = full_path_len;
            handles[handle_idx].position = 0;
            handles[handle_idx].file_size = size as u64;
            handles[handle_idx].first_cluster = cluster;
            handles[handle_idx].is_directory = is_dir;

            unsafe {
                *new_handle = &raw mut handles[handle_idx].protocol;
            }

            log::debug!(
                "File.Open: success, cluster={}, size={}, is_dir={}",
                cluster,
                size,
                is_dir
            );
            Status::SUCCESS
        }
        Err(e) => {
            log::debug!("File.Open: not found ({:?})", e);
            Status::NOT_FOUND
        }
    }
}

extern "efiapi" fn file_close(this: *mut efi_file::Protocol) -> Status {
    log::debug!("File.Close()");

    let mut handles = FILE_HANDLES.lock();
    if let Some(idx) = find_handle_index_unlocked(&handles, this) {
        handles[idx].in_use = false;
        handles[idx].path_len = 0;
        handles[idx].position = 0;
        Status::SUCCESS
    } else {
        Status::INVALID_PARAMETER
    }
}

extern "efiapi" fn file_delete(_this: *mut efi_file::Protocol) -> Status {
    log::debug!("File.Delete() -> UNSUPPORTED");
    Status::UNSUPPORTED
}

extern "efiapi" fn file_read(
    this: *mut efi_file::Protocol,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    if this.is_null() || buffer_size.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let requested_size = unsafe { *buffer_size };

    // Get handle info
    let (is_dir, file_size, position, first_cluster, handle_idx) = {
        let handles = FILE_HANDLES.lock();
        let idx = match find_handle_index_unlocked(&handles, this) {
            Some(i) => i,
            None => return Status::INVALID_PARAMETER,
        };
        (
            handles[idx].is_directory,
            handles[idx].file_size,
            handles[idx].position,
            handles[idx].first_cluster,
            idx,
        )
    };

    if is_dir {
        return read_directory(this, buffer_size, buffer, handle_idx);
    }

    // File read
    if buffer.is_null() && requested_size > 0 {
        return Status::INVALID_PARAMETER;
    }

    // Check EOF
    if position >= file_size {
        unsafe { *buffer_size = 0 };
        return Status::SUCCESS;
    }

    let bytes_to_read = core::cmp::min(requested_size as u64, file_size - position) as usize;

    if bytes_to_read == 0 {
        unsafe { *buffer_size = 0 };
        return Status::SUCCESS;
    }

    let efi = state::efi();
    let fs_state = match efi.filesystem {
        Some(s) => s,
        None => return Status::NOT_READY,
    };

    let read_fn = match efi.disk_read_fn {
        Some(f) => f,
        None => return Status::NOT_READY,
    };

    let buf_slice = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, bytes_to_read) };

    match read_file_data(
        &fs_state,
        read_fn,
        first_cluster,
        position as u32,
        buf_slice,
    ) {
        Ok(bytes_read) => {
            // Update position
            {
                let mut handles = FILE_HANDLES.lock();
                handles[handle_idx].position += bytes_read as u64;
            }

            unsafe { *buffer_size = bytes_read };
            log::trace!("File.Read: read {} bytes", bytes_read);
            Status::SUCCESS
        }
        Err(_) => {
            log::error!("File.Read: device error");
            Status::DEVICE_ERROR
        }
    }
}

extern "efiapi" fn file_write(
    _this: *mut efi_file::Protocol,
    _buffer_size: *mut usize,
    _buffer: *mut c_void,
) -> Status {
    log::debug!("File.Write() -> UNSUPPORTED");
    Status::UNSUPPORTED
}

extern "efiapi" fn file_get_position(this: *mut efi_file::Protocol, position: *mut u64) -> Status {
    if this.is_null() || position.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let handles = FILE_HANDLES.lock();
    if let Some(idx) = find_handle_index_unlocked(&handles, this) {
        if handles[idx].is_directory {
            return Status::UNSUPPORTED;
        }
        unsafe { *position = handles[idx].position };
        Status::SUCCESS
    } else {
        Status::INVALID_PARAMETER
    }
}

extern "efiapi" fn file_set_position(this: *mut efi_file::Protocol, position: u64) -> Status {
    if this.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let mut handles = FILE_HANDLES.lock();
    if let Some(idx) = find_handle_index_unlocked(&handles, this) {
        if handles[idx].is_directory {
            // For directories, only 0 is allowed (reset enumeration)
            if position != 0 {
                return Status::UNSUPPORTED;
            }
            handles[idx].position = 0;
            return Status::SUCCESS;
        }

        // 0xFFFF_FFFF_FFFF_FFFF means seek to end
        if position == u64::MAX {
            handles[idx].position = handles[idx].file_size;
        } else {
            handles[idx].position = position;
        }
        Status::SUCCESS
    } else {
        Status::INVALID_PARAMETER
    }
}

extern "efiapi" fn file_get_info(
    this: *mut efi_file::Protocol,
    info_type: *mut Guid,
    buffer_size: *mut usize,
    buffer: *mut c_void,
) -> Status {
    if this.is_null() || info_type.is_null() || buffer_size.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let guid = unsafe { *info_type };
    let requested_size = unsafe { *buffer_size };

    // Get handle info
    let (path, path_len, file_size, is_directory) = {
        let handles = FILE_HANDLES.lock();
        let idx = match find_handle_index_unlocked(&handles, this) {
            Some(i) => i,
            None => return Status::INVALID_PARAMETER,
        };
        let mut path = [0u8; MAX_PATH_LEN];
        let len = handles[idx].path_len;
        path[..len].copy_from_slice(&handles[idx].path[..len]);
        (path, len, handles[idx].file_size, handles[idx].is_directory)
    };

    if guid_eq(&guid, &FILE_INFO_GUID) {
        // EFI_FILE_INFO
        let path_str = core::str::from_utf8(&path[..path_len]).unwrap_or("");
        let filename = path_str.rsplit(['/', '\\']).next().unwrap_or("");
        let filename_u16_len = filename.len() + 1; // +1 for null terminator

        // Size = struct + filename in UTF-16
        let required_size = core::mem::size_of::<efi_file::Info>() + filename_u16_len * 2;

        if requested_size < required_size {
            unsafe { *buffer_size = required_size };
            return Status::BUFFER_TOO_SMALL;
        }

        if buffer.is_null() {
            return Status::INVALID_PARAMETER;
        }

        // Fill in the info
        let info = buffer as *mut efi_file::Info;
        unsafe {
            (*info).size = required_size as u64;
            (*info).file_size = file_size;
            (*info).physical_size = file_size;
            // Zero out times (not tracked)
            (*info).create_time = core::mem::zeroed();
            (*info).last_access_time = core::mem::zeroed();
            (*info).modification_time = core::mem::zeroed();
            (*info).attribute = if is_directory { FILE_DIRECTORY } else { 0 };

            // Write filename as UTF-16 after the struct
            let filename_ptr =
                (info as *mut u8).add(core::mem::size_of::<efi_file::Info>()) as *mut u16;
            for (i, c) in filename.chars().enumerate() {
                *filename_ptr.add(i) = c as u16;
            }
            *filename_ptr.add(filename.len()) = 0; // null terminator
        }

        unsafe { *buffer_size = required_size };
        log::debug!(
            "File.GetInfo(FILE_INFO): size={}, is_dir={}",
            file_size,
            is_directory
        );
        Status::SUCCESS
    } else if guid_eq(&guid, &FILE_SYSTEM_INFO_GUID) {
        // EFI_FILE_SYSTEM_INFO
        let label = "EFI";
        let label_u16_len = label.len() + 1;
        let required_size = core::mem::size_of::<efi_file::SystemInfo>() + label_u16_len * 2;

        if requested_size < required_size {
            unsafe { *buffer_size = required_size };
            return Status::BUFFER_TOO_SMALL;
        }

        if buffer.is_null() {
            return Status::INVALID_PARAMETER;
        }

        let fs_state = match state::efi().filesystem {
            Some(s) => s,
            None => return Status::NOT_READY,
        };

        let info = buffer as *mut efi_file::SystemInfo;
        unsafe {
            (*info).size = required_size as u64;
            (*info).read_only = r_efi::efi::Boolean::TRUE; // Read-only
            (*info).volume_size = 0; // Unknown
            (*info).free_space = 0;
            (*info).block_size = fs_state.bytes_per_sector as u32;

            // Write label as UTF-16 after the struct
            let label_ptr =
                (info as *mut u8).add(core::mem::size_of::<efi_file::SystemInfo>()) as *mut u16;
            for (i, c) in label.chars().enumerate() {
                *label_ptr.add(i) = c as u16;
            }
            *label_ptr.add(label.len()) = 0;
        }

        unsafe { *buffer_size = required_size };
        log::debug!("File.GetInfo(FILE_SYSTEM_INFO)");
        Status::SUCCESS
    } else {
        log::debug!("File.GetInfo: unknown info type");
        Status::UNSUPPORTED
    }
}

extern "efiapi" fn file_set_info(
    _this: *mut efi_file::Protocol,
    _info_type: *mut Guid,
    _buffer_size: usize,
    _buffer: *mut c_void,
) -> Status {
    log::debug!("File.SetInfo() -> UNSUPPORTED");
    Status::UNSUPPORTED
}

extern "efiapi" fn file_flush(_this: *mut efi_file::Protocol) -> Status {
    // Read-only filesystem, nothing to flush
    Status::SUCCESS
}

// Async operations - not supported
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

// ============================================================================
// Helper Functions
// ============================================================================

/// Find handle index without holding the lock (for use when we already have it)
fn find_handle_index_unlocked(
    handles: &[FileHandle; MAX_FILE_HANDLES],
    protocol: *mut efi_file::Protocol,
) -> Option<usize> {
    for (i, h) in handles.iter().enumerate() {
        if h.in_use && core::ptr::eq(&h.protocol as *const _, protocol as *const _) {
            return Some(i);
        }
    }
    None
}

/// Convert UTF-16 to UTF-8
fn utf16_to_utf8(src: *mut Char16, dst: &mut [u8]) -> usize {
    let mut len = 0;
    let mut i = 0;

    while len < dst.len() - 1 {
        let c = unsafe { *src.add(i) };
        if c == 0 {
            break;
        }

        // Simple ASCII conversion (good enough for file paths)
        if c < 128 {
            dst[len] = c as u8;
            len += 1;
        } else {
            // Replace non-ASCII with '?'
            dst[len] = b'?';
            len += 1;
        }
        i += 1;
    }

    dst[len] = 0;
    len
}

/// Build a full path from parent path and relative name
fn build_full_path(parent: &[u8], name: &str, out: &mut [u8; MAX_PATH_LEN]) -> usize {
    let mut len = 0;

    // Handle absolute paths
    if name.starts_with('\\') || name.starts_with('/') {
        // Absolute path - use name directly
        for c in name.bytes() {
            if len >= MAX_PATH_LEN - 1 {
                break;
            }
            // Normalize backslashes to forward slashes
            out[len] = if c == b'\\' { b'/' } else { c };
            len += 1;
        }
    } else {
        // Relative path - combine with parent
        // Copy parent
        for &c in parent {
            if c == 0 {
                break;
            }
            if len >= MAX_PATH_LEN - 1 {
                break;
            }
            out[len] = if c == b'\\' { b'/' } else { c };
            len += 1;
        }

        // Add separator if needed
        if len > 0 && out[len - 1] != b'/' && len < MAX_PATH_LEN - 1 {
            out[len] = b'/';
            len += 1;
        }

        // Add name
        for c in name.bytes() {
            if len >= MAX_PATH_LEN - 1 {
                break;
            }
            out[len] = if c == b'\\' { b'/' } else { c };
            len += 1;
        }
    }

    // Remove trailing slash (unless root)
    if len > 1 && out[len - 1] == b'/' {
        len -= 1;
    }

    // Null terminate
    out[len] = 0;

    // Handle . and .. components
    normalize_path(out, len)
}

/// Normalize a path by handling . and .. components
fn normalize_path(path: &mut [u8; MAX_PATH_LEN], len: usize) -> usize {
    // Simple normalization - just remove leading slash for FAT lookup
    let start = if len > 0 && path[0] == b'/' { 1 } else { 0 };
    if start > 0 {
        for i in start..=len {
            path[i - start] = path[i];
        }
        len - start
    } else {
        len
    }
}

// Use common guid_eq from utils module
use crate::efi::utils::guid_eq;

// ============================================================================
// FAT Filesystem Access
// ============================================================================

/// Find a file by path, returns (first_cluster, size, is_directory)
fn find_file(
    state: &FilesystemState,
    read_fn: fn(u64, &mut [u8]) -> Result<(), ()>,
    path: &str,
) -> Result<(u32, u32, bool), ()> {
    let path = path.trim_start_matches('/');

    if path.is_empty() {
        // Root directory
        return Ok((state.root_cluster, 0, true));
    }

    let mut current_cluster = state.root_cluster;

    for (i, part) in path.split('/').filter(|s| !s.is_empty()).enumerate() {
        let is_last = i == path.split('/').filter(|s| !s.is_empty()).count() - 1;

        match find_in_directory(state, read_fn, current_cluster, part) {
            Ok(entry) => {
                if is_last {
                    let cluster =
                        ((entry.first_cluster_hi as u32) << 16) | (entry.first_cluster_lo as u32);
                    let is_dir = (entry.attr & 0x10) != 0;
                    return Ok((cluster, entry.file_size, is_dir));
                }

                // Not last component - must be directory
                if (entry.attr & 0x10) == 0 {
                    return Err(());
                }

                current_cluster =
                    ((entry.first_cluster_hi as u32) << 16) | (entry.first_cluster_lo as u32);
            }
            Err(_) => return Err(()),
        }
    }

    Err(())
}

/// FAT directory entry (from fs/fat.rs)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DirEntry {
    name: [u8; 8],
    ext: [u8; 3],
    attr: u8,
    nt_reserved: u8,
    creation_time_tenths: u8,
    creation_time: u16,
    creation_date: u16,
    last_access_date: u16,
    first_cluster_hi: u16,
    modification_time: u16,
    modification_date: u16,
    first_cluster_lo: u16,
    file_size: u32,
}

/// Find an entry in a directory
fn find_in_directory(
    state: &FilesystemState,
    read_fn: fn(u64, &mut [u8]) -> Result<(), ()>,
    cluster: u32,
    name: &str,
) -> Result<DirEntry, ()> {
    let mut buffer = [0u8; 4096];
    let cluster_size = state.sectors_per_cluster as usize * state.bytes_per_sector as usize;
    let entries_per_cluster = cluster_size / 32;

    // Handle FAT12/16 root directory (fixed location)
    if cluster == 0 && state.fat_type != 32 {
        for sector_idx in 0..state.root_dir_sectors {
            let sector = state.partition_start + (state.root_dir_start + sector_idx) as u64;
            read_fn(sector, &mut buffer[..state.bytes_per_sector as usize])?;

            let entries_per_sector = state.bytes_per_sector as usize / 32;
            for i in 0..entries_per_sector {
                let offset = i * 32;
                let entry = unsafe {
                    core::ptr::read_unaligned(buffer[offset..].as_ptr() as *const DirEntry)
                };

                if entry.name[0] == 0x00 {
                    return Err(());
                }
                if entry.name[0] == 0xE5 || (entry.attr & 0x0F) == 0x0F || (entry.attr & 0x08) != 0
                {
                    continue;
                }

                if matches_name(&entry, name) {
                    return Ok(entry);
                }
            }
        }
        return Err(());
    }

    // Cluster chain directory
    let mut current_cluster = cluster;

    loop {
        // Read cluster
        let start_sector = cluster_to_sector(state, current_cluster);
        for s in 0..state.sectors_per_cluster {
            let offset = s as usize * state.bytes_per_sector as usize;
            read_fn(
                start_sector + s as u64,
                &mut buffer[offset..offset + state.bytes_per_sector as usize],
            )?;
        }

        // Search entries
        for i in 0..entries_per_cluster {
            let offset = i * 32;
            let entry =
                unsafe { core::ptr::read_unaligned(buffer[offset..].as_ptr() as *const DirEntry) };

            if entry.name[0] == 0x00 {
                return Err(());
            }
            if entry.name[0] == 0xE5 || (entry.attr & 0x0F) == 0x0F || (entry.attr & 0x08) != 0 {
                continue;
            }

            if matches_name(&entry, name) {
                return Ok(entry);
            }
        }

        // Get next cluster
        current_cluster = match next_cluster(state, read_fn, current_cluster)? {
            Some(c) => c,
            None => return Err(()),
        };
    }
}

/// Check if a directory entry matches a name (case-insensitive)
fn matches_name(entry: &DirEntry, name: &str) -> bool {
    // Build short name from entry
    let mut entry_name = heapless::String::<12>::new();
    for &c in &entry.name {
        if c == 0x20 {
            break;
        }
        let _ = entry_name.push(c as char);
    }
    if entry.ext[0] != 0x20 {
        let _ = entry_name.push('.');
        for &c in &entry.ext {
            if c == 0x20 {
                break;
            }
            let _ = entry_name.push(c as char);
        }
    }

    // Case-insensitive comparison
    if entry_name.len() != name.len() {
        return false;
    }
    for (a, b) in entry_name.bytes().zip(name.bytes()) {
        if !a.eq_ignore_ascii_case(&b) {
            return false;
        }
    }
    true
}

/// Convert cluster number to sector
fn cluster_to_sector(state: &FilesystemState, cluster: u32) -> u64 {
    let sector = state.data_start + (cluster - 2) * state.sectors_per_cluster as u32;
    state.partition_start + sector as u64
}

/// Get next cluster from FAT
fn next_cluster(
    state: &FilesystemState,
    read_fn: fn(u64, &mut [u8]) -> Result<(), ()>,
    cluster: u32,
) -> Result<Option<u32>, ()> {
    let mut buffer = [0u8; 512];

    let (fat_offset, sector_offset) = match state.fat_type {
        12 => {
            let offset = cluster + (cluster / 2);
            let sector = state.fat_start + (offset / state.bytes_per_sector as u32);
            (offset % state.bytes_per_sector as u32, sector)
        }
        16 => {
            let offset = cluster * 2;
            let sector = state.fat_start + (offset / state.bytes_per_sector as u32);
            (offset % state.bytes_per_sector as u32, sector)
        }
        32 => {
            let offset = cluster * 4;
            let sector = state.fat_start + (offset / state.bytes_per_sector as u32);
            (offset % state.bytes_per_sector as u32, sector)
        }
        _ => return Err(()),
    };

    read_fn(
        state.partition_start + sector_offset as u64,
        &mut buffer[..state.bytes_per_sector as usize],
    )?;

    let next = match state.fat_type {
        12 => {
            // FAT12 entries are 1.5 bytes and can span sector boundaries
            let byte1 = buffer[fat_offset as usize];
            let byte2 = if fat_offset + 1 >= state.bytes_per_sector as u32 {
                // Entry spans sector boundary - need to read next sector
                let mut next_buffer = [0u8; 512];
                read_fn(
                    state.partition_start + sector_offset as u64 + 1,
                    &mut next_buffer[..state.bytes_per_sector as usize],
                )?;
                next_buffer[0]
            } else {
                buffer[(fat_offset + 1) as usize]
            };

            let entry = byte1 as u16 | ((byte2 as u16) << 8);
            let val = if cluster & 1 != 0 {
                entry >> 4
            } else {
                entry & 0x0FFF
            };
            if val >= 0x0FF8 {
                None
            } else {
                Some(val as u32)
            }
        }
        16 => {
            let entry = u16::from_le_bytes([
                buffer[fat_offset as usize],
                buffer[(fat_offset + 1) as usize],
            ]);
            if entry >= 0xFFF8 {
                None
            } else {
                Some(entry as u32)
            }
        }
        32 => {
            let entry = u32::from_le_bytes([
                buffer[fat_offset as usize],
                buffer[(fat_offset + 1) as usize],
                buffer[(fat_offset + 2) as usize],
                buffer[(fat_offset + 3) as usize],
            ]) & 0x0FFFFFFF;
            if entry >= 0x0FFFFFF8 {
                None
            } else {
                Some(entry)
            }
        }
        _ => return Err(()),
    };

    Ok(next)
}

/// Read file data starting at offset
fn read_file_data(
    state: &FilesystemState,
    read_fn: fn(u64, &mut [u8]) -> Result<(), ()>,
    first_cluster: u32,
    offset: u32,
    buffer: &mut [u8],
) -> Result<usize, ()> {
    let cluster_size = state.sectors_per_cluster as u32 * state.bytes_per_sector as u32;

    // Find starting cluster
    let mut cluster = first_cluster;
    let skip_clusters = offset / cluster_size;
    let cluster_offset = (offset % cluster_size) as usize;

    for _ in 0..skip_clusters {
        cluster = match next_cluster(state, read_fn, cluster)? {
            Some(c) => c,
            None => return Ok(0),
        };
    }

    let mut bytes_read = 0;
    let mut cluster_buffer = [0u8; 4096];

    // Read first (potentially partial) cluster
    if cluster_offset > 0 || buffer.len() < cluster_size as usize {
        read_cluster(
            state,
            read_fn,
            cluster,
            &mut cluster_buffer[..cluster_size as usize],
        )?;

        let copy_len = core::cmp::min(buffer.len(), cluster_size as usize - cluster_offset);
        buffer[..copy_len]
            .copy_from_slice(&cluster_buffer[cluster_offset..cluster_offset + copy_len]);
        bytes_read += copy_len;

        cluster = match next_cluster(state, read_fn, cluster)? {
            Some(c) => c,
            None => return Ok(bytes_read),
        };
    }

    // Read full clusters
    while bytes_read + cluster_size as usize <= buffer.len() {
        read_cluster(
            state,
            read_fn,
            cluster,
            &mut buffer[bytes_read..bytes_read + cluster_size as usize],
        )?;
        bytes_read += cluster_size as usize;

        cluster = match next_cluster(state, read_fn, cluster)? {
            Some(c) => c,
            None => return Ok(bytes_read),
        };
    }

    // Read last partial cluster
    if bytes_read < buffer.len() {
        read_cluster(
            state,
            read_fn,
            cluster,
            &mut cluster_buffer[..cluster_size as usize],
        )?;
        let remaining = buffer.len() - bytes_read;
        buffer[bytes_read..].copy_from_slice(&cluster_buffer[..remaining]);
        bytes_read += remaining;
    }

    Ok(bytes_read)
}

/// Read a single cluster
fn read_cluster(
    state: &FilesystemState,
    read_fn: fn(u64, &mut [u8]) -> Result<(), ()>,
    cluster: u32,
    buffer: &mut [u8],
) -> Result<(), ()> {
    let start_sector = cluster_to_sector(state, cluster);
    for s in 0..state.sectors_per_cluster {
        let offset = s as usize * state.bytes_per_sector as usize;
        read_fn(
            start_sector + s as u64,
            &mut buffer[offset..offset + state.bytes_per_sector as usize],
        )?;
    }
    Ok(())
}

/// Read directory entries
fn read_directory(
    _this: *mut efi_file::Protocol,
    buffer_size: *mut usize,
    buffer: *mut c_void,
    handle_idx: usize,
) -> Status {
    let efi = state::efi();
    let fs_state = match efi.filesystem {
        Some(s) => s,
        None => return Status::NOT_READY,
    };

    let read_fn = match efi.disk_read_fn {
        Some(f) => f,
        None => return Status::NOT_READY,
    };

    let (cluster, position) = {
        let handles = FILE_HANDLES.lock();
        (
            handles[handle_idx].first_cluster,
            handles[handle_idx].position as usize,
        )
    };

    // Find the entry at current position
    let entry_result = get_directory_entry_at_position(&fs_state, read_fn, cluster, position);

    match entry_result {
        Ok(Some(entry)) => {
            // Build filename
            let mut filename = heapless::String::<12>::new();
            for &c in &entry.name {
                if c == 0x20 {
                    break;
                }
                let _ = filename.push(c as char);
            }
            if entry.ext[0] != 0x20 {
                let _ = filename.push('.');
                for &c in &entry.ext {
                    if c == 0x20 {
                        break;
                    }
                    let _ = filename.push(c as char);
                }
            }

            let filename_u16_len = filename.len() + 1;
            let required_size = core::mem::size_of::<efi_file::Info>() + filename_u16_len * 2;
            let requested_size = unsafe { *buffer_size };

            if requested_size < required_size {
                unsafe { *buffer_size = required_size };
                return Status::BUFFER_TOO_SMALL;
            }

            if buffer.is_null() {
                return Status::INVALID_PARAMETER;
            }

            // Fill info
            let info = buffer as *mut efi_file::Info;
            let is_dir = (entry.attr & 0x10) != 0;
            unsafe {
                (*info).size = required_size as u64;
                (*info).file_size = entry.file_size as u64;
                (*info).physical_size = entry.file_size as u64;
                (*info).create_time = core::mem::zeroed();
                (*info).last_access_time = core::mem::zeroed();
                (*info).modification_time = core::mem::zeroed();
                (*info).attribute = if is_dir { FILE_DIRECTORY } else { 0 };

                let filename_ptr =
                    (info as *mut u8).add(core::mem::size_of::<efi_file::Info>()) as *mut u16;
                for (i, c) in filename.chars().enumerate() {
                    *filename_ptr.add(i) = c as u16;
                }
                *filename_ptr.add(filename.len()) = 0;
            }

            // Increment position
            {
                let mut handles = FILE_HANDLES.lock();
                handles[handle_idx].position += 1;
            }

            unsafe { *buffer_size = required_size };
            Status::SUCCESS
        }
        Ok(None) => {
            // End of directory
            unsafe { *buffer_size = 0 };
            Status::SUCCESS
        }
        Err(_) => Status::DEVICE_ERROR,
    }
}

/// Get directory entry at a specific position (index)
fn get_directory_entry_at_position(
    state: &FilesystemState,
    read_fn: fn(u64, &mut [u8]) -> Result<(), ()>,
    cluster: u32,
    position: usize,
) -> Result<Option<DirEntry>, ()> {
    let mut buffer = [0u8; 4096];
    let cluster_size = state.sectors_per_cluster as usize * state.bytes_per_sector as usize;
    let entries_per_cluster = cluster_size / 32;
    let mut current_position = 0usize;

    // Handle FAT12/16 root directory
    if cluster == 0 && state.fat_type != 32 {
        for sector_idx in 0..state.root_dir_sectors {
            let sector = state.partition_start + (state.root_dir_start + sector_idx) as u64;
            read_fn(sector, &mut buffer[..state.bytes_per_sector as usize])?;

            let entries_per_sector = state.bytes_per_sector as usize / 32;
            for i in 0..entries_per_sector {
                let offset = i * 32;
                let entry = unsafe {
                    core::ptr::read_unaligned(buffer[offset..].as_ptr() as *const DirEntry)
                };

                if entry.name[0] == 0x00 {
                    return Ok(None);
                }
                if entry.name[0] == 0xE5 || (entry.attr & 0x0F) == 0x0F || (entry.attr & 0x08) != 0
                {
                    continue;
                }

                if current_position == position {
                    return Ok(Some(entry));
                }
                current_position += 1;
            }
        }
        return Ok(None);
    }

    // Cluster chain directory
    let mut current_cluster = cluster;

    loop {
        // Read cluster
        let start_sector = cluster_to_sector(state, current_cluster);
        for s in 0..state.sectors_per_cluster {
            let offset = s as usize * state.bytes_per_sector as usize;
            read_fn(
                start_sector + s as u64,
                &mut buffer[offset..offset + state.bytes_per_sector as usize],
            )?;
        }

        // Search entries
        for i in 0..entries_per_cluster {
            let offset = i * 32;
            let entry =
                unsafe { core::ptr::read_unaligned(buffer[offset..].as_ptr() as *const DirEntry) };

            if entry.name[0] == 0x00 {
                return Ok(None);
            }
            if entry.name[0] == 0xE5 || (entry.attr & 0x0F) == 0x0F || (entry.attr & 0x08) != 0 {
                continue;
            }

            if current_position == position {
                return Ok(Some(entry));
            }
            current_position += 1;
        }

        // Get next cluster
        current_cluster = match next_cluster(state, read_fn, current_cluster)? {
            Some(c) => c,
            None => return Ok(None),
        };
    }
}

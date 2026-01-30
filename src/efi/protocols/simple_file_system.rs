//! EFI Simple File System Protocol
//!
//! This module provides the EFI_SIMPLE_FILE_SYSTEM_PROTOCOL and EFI_FILE_PROTOCOL
//! which allow UEFI applications to access files on the boot filesystem.
//!
//! File operations delegate to `FatFilesystem` from `fs/fat.rs` for all FAT-specific
//! logic, avoiding code duplication.

use core::ffi::c_void;
use r_efi::efi::{Char16, Guid, Status};
use r_efi::protocols::file as efi_file;
use r_efi::protocols::simple_file_system as efi_sfs;
use spin::Mutex;

use crate::drivers::block::{AnyBlockDevice, BlockDevice};
use crate::fs::fat::{DirectoryEntry, FatFilesystem, FatType};
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

/// Initialize the simple file system protocol with a block device
///
/// # Arguments
/// * `block_device` - The block device containing the FAT filesystem
/// * `partition_start` - LBA of the partition start
///
/// # Returns
/// Pointer to the SimpleFileSystem protocol, or null on failure
pub fn init(block_device: AnyBlockDevice, partition_start: u64) -> *mut efi_sfs::Protocol {
    // Get device info before creating FatFilesystem to avoid borrow conflicts
    let mut temp_device = block_device;
    let device_block_size = temp_device.info().block_size;

    // Create a temporary FatFilesystem to get filesystem info
    let fs_state = match FatFilesystem::new(&mut temp_device, partition_start) {
        Ok(fat) => {
            let fat_type = fat.fat_type();
            let root_cluster = fat.root_cluster();
            FilesystemState {
                partition_start,
                fat_type: match fat_type {
                    FatType::Fat12 => 12,
                    FatType::Fat16 => 16,
                    FatType::Fat32 => 32,
                },
                bytes_per_sector: 512, // Standard FAT sector size
                device_block_size,
                sectors_per_cluster: 0, // Not needed anymore
                fat_start: 0,           // Not needed anymore
                sectors_per_fat: 0,     // Not needed anymore
                data_start: 0,          // Not needed anymore
                root_cluster,
                root_dir_start: 0,   // Not needed anymore
                root_dir_sectors: 0, // Not needed anymore
            }
        }
        Err(e) => {
            log::error!("SimpleFileSystem: failed to mount FAT filesystem: {:?}", e);
            return core::ptr::null_mut();
        }
    };

    state::with_efi_mut(|efi| {
        efi.filesystem = Some(fs_state);
        efi.block_device = Some(temp_device);
    });

    log::info!(
        "SimpleFileSystem: initialized with partition at LBA {}",
        partition_start
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

    // Get partition start
    let partition_start = match state::efi().filesystem {
        Some(s) => s.partition_start,
        None => return Status::NOT_READY,
    };

    // Find the file using FatFilesystem
    let result = state::with_block_device_mut(|device| {
        let mut fat = match FatFilesystem::new(device, partition_start) {
            Ok(f) => f,
            Err(_) => return Err(()),
        };

        match fat.find_file(full_path_str) {
            Ok(entry) => Ok((
                entry.first_cluster(),
                entry.file_size(),
                entry.is_directory(),
            )),
            Err(_) => Err(()),
        }
    });

    match result {
        Some(Ok((cluster, size, is_dir))) => {
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
        Some(Err(_)) => {
            log::debug!("File.Open: not found");
            Status::NOT_FOUND
        }
        None => {
            log::error!("File.Open: block device not available");
            Status::NOT_READY
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
        return read_directory(buffer_size, buffer, handle_idx);
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

    let partition_start = match state::efi().filesystem {
        Some(s) => s.partition_start,
        None => return Status::NOT_READY,
    };

    let buf_slice = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, bytes_to_read) };

    // Create a fake DirectoryEntry for read_file
    // We need to read using the stored cluster and position
    let result = state::with_block_device_mut(|device| {
        let mut fat = match FatFilesystem::new(device, partition_start) {
            Ok(f) => f,
            Err(_) => return Err(()),
        };

        // Create a minimal entry for reading
        let entry = create_file_entry(first_cluster, file_size as u32);
        fat.read_file(&entry, position as u32, buf_slice)
            .map_err(|_| ())
    });

    match result {
        Some(Ok(bytes_read)) => {
            // Update position
            {
                let mut handles = FILE_HANDLES.lock();
                handles[handle_idx].position += bytes_read as u64;
            }

            unsafe { *buffer_size = bytes_read };
            log::trace!("File.Read: read {} bytes", bytes_read);
            Status::SUCCESS
        }
        Some(Err(_)) => {
            log::error!("File.Read: device error");
            Status::DEVICE_ERROR
        }
        None => {
            log::error!("File.Read: block device not available");
            Status::NOT_READY
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
            (*info).block_size = fs_state.device_block_size;

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

/// Create a minimal DirectoryEntry for file reading
///
/// This is needed because FatFilesystem::read_file takes a DirectoryEntry,
/// but we only have the cluster and size stored in our handle.
fn create_file_entry(first_cluster: u32, file_size: u32) -> DirectoryEntry {
    // DirectoryEntry is #[repr(C, packed)], so we create it via raw bytes
    let mut bytes = [0u8; 32];

    // first_cluster_hi at offset 20 (2 bytes)
    let hi = (first_cluster >> 16) as u16;
    bytes[20] = hi as u8;
    bytes[21] = (hi >> 8) as u8;

    // first_cluster_lo at offset 26 (2 bytes)
    let lo = first_cluster as u16;
    bytes[26] = lo as u8;
    bytes[27] = (lo >> 8) as u8;

    // file_size at offset 28 (4 bytes)
    bytes[28] = file_size as u8;
    bytes[29] = (file_size >> 8) as u8;
    bytes[30] = (file_size >> 16) as u8;
    bytes[31] = (file_size >> 24) as u8;

    // attr at offset 11 - set to 0 (regular file)
    bytes[11] = 0;

    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const DirectoryEntry) }
}

/// Read directory entries
fn read_directory(buffer_size: *mut usize, buffer: *mut c_void, handle_idx: usize) -> Status {
    let partition_start = match state::efi().filesystem {
        Some(s) => s.partition_start,
        None => return Status::NOT_READY,
    };

    let (cluster, position) = {
        let handles = FILE_HANDLES.lock();
        (
            handles[handle_idx].first_cluster,
            handles[handle_idx].position as usize,
        )
    };

    // Get directory entry at current position
    let entry_result = state::with_block_device_mut(|device| {
        let mut fat = match FatFilesystem::new(device, partition_start) {
            Ok(f) => f,
            Err(_) => return Err(()),
        };

        fat.get_directory_entry_at_position(cluster, position)
            .map_err(|_| ())
    });

    match entry_result {
        Some(Ok(Some(entry))) => {
            // Build filename from entry
            let filename = entry.short_name();

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
            let is_dir = entry.is_directory();
            let file_size = entry.file_size();
            unsafe {
                (*info).size = required_size as u64;
                (*info).file_size = file_size as u64;
                (*info).physical_size = file_size as u64;
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
        Some(Ok(None)) => {
            // End of directory
            unsafe { *buffer_size = 0 };
            Status::SUCCESS
        }
        Some(Err(_)) | None => Status::DEVICE_ERROR,
    }
}

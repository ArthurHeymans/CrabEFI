//! EFI Image Loader Helpers
//!
//! Device path parsing, SFS handle matching, and file loading utilities
//! used by the `load_image` Boot Service.

use core::ffi::c_void;

use r_efi::efi::{Guid, Handle, Status};
use r_efi::protocols::device_path::{self, Media, Protocol as DevicePathProtocol};
use r_efi::protocols::file::Protocol as FileProtocol;
use r_efi::protocols::simple_file_system::Protocol as SimpleFileSystemProtocol;

use super::allocator::{self, MemoryType};
use super::boot_services;
use super::protocols::loaded_image::LOADED_IMAGE_PROTOCOL_GUID;
use super::protocols::simple_file_system::SIMPLE_FILE_SYSTEM_GUID;
use crate::state;

/// Device path type for Media
const DEVICE_PATH_TYPE_MEDIA: u8 = device_path::TYPE_MEDIA;
/// Device path subtype for File Path
const DEVICE_PATH_SUBTYPE_FILE_PATH: u8 = Media::SUBTYPE_FILE_PATH;
/// Device path type for End
const DEVICE_PATH_TYPE_END: u8 = device_path::TYPE_END;

/// Maximum device path depth to prevent runaway walks on corrupted paths.
const MAX_DEVICE_PATH_NODES: usize = 64;

/// Extract file path string from a device path
///
/// Walks the device path nodes looking for a Media File Path node,
/// then extracts the UTF-16 path string from it.
///
/// # Arguments
/// * `device_path` - The device path to parse
///
/// # Returns
/// A tuple of (file_path_utf16, length_in_u16_chars) or None if no file path found
fn extract_file_path_from_device_path(
    device_path: *mut DevicePathProtocol,
) -> Option<(*const u16, usize)> {
    if device_path.is_null() {
        return None;
    }

    let mut current = device_path;

    unsafe {
        loop {
            let node_type = (*current).r#type;
            let node_subtype = (*current).sub_type;
            let node_length =
                u16::from_le_bytes([(*current).length[0], (*current).length[1]]) as usize;

            // Check for end of device path
            if node_type == DEVICE_PATH_TYPE_END {
                break;
            }

            // Check for file path node
            if node_type == DEVICE_PATH_TYPE_MEDIA && node_subtype == DEVICE_PATH_SUBTYPE_FILE_PATH
            {
                // File path node: header (4 bytes) + UTF-16 path
                if node_length > 4 {
                    let path_ptr = (current as *const u8).add(4) as *const u16;
                    let path_len = (node_length - 4) / 2; // Convert bytes to UTF-16 chars
                    return Some((path_ptr, path_len));
                }
            }

            // Move to next node
            if node_length < 4 {
                break; // Invalid length
            }
            current = (current as *const u8).add(node_length) as *mut DevicePathProtocol;
        }
    }

    None
}

/// Look up a protocol interface pointer on a handle by GUID.
///
/// Delegates to [`boot_services::get_protocol_on_handle`] and filters out
/// null interface pointers.
fn get_protocol_on_handle(handle: Handle, guid: &Guid) -> Option<*mut c_void> {
    let ptr = boot_services::get_protocol_on_handle(handle, guid);
    if ptr.is_null() { None } else { Some(ptr) }
}

/// Load an image from a device path
///
/// This function is called when LoadImage is invoked with source_buffer=NULL.
/// It parses the device path to find the file path, locates the SimpleFileSystem
/// protocol, opens and reads the file, then returns the data.
///
/// # Arguments
/// * `device_path` - The device path containing a file path node
///
/// # Returns
/// A tuple of (buffer_ptr, buffer_size, device_handle) on success, or an error status
pub(crate) fn load_image_from_device_path(
    device_path: *mut DevicePathProtocol,
) -> Result<(*mut c_void, usize, Handle), Status> {
    // Extract the file path from the device path
    let (path_ptr, path_len) =
        extract_file_path_from_device_path(device_path).ok_or_else(|| {
            log::error!("BS.LoadImage: No file path found in device path");
            Status::INVALID_PARAMETER
        })?;

    // Log the file path for debugging
    let mut path_str = [0u8; 256];
    let mut str_len = 0;
    unsafe {
        for i in 0..path_len {
            let c = *path_ptr.add(i);
            if c == 0 {
                break;
            }
            if str_len < path_str.len() - 1 && c < 128 {
                path_str[str_len] = c as u8;
                str_len += 1;
            }
        }
    }
    let path_display = core::str::from_utf8(&path_str[..str_len]).unwrap_or("<invalid>");
    log::info!("BS.LoadImage: Loading from device path: {}", path_display);

    // Find the best matching SFS handle by comparing device paths.
    // Walk the input device path's non-file-path prefix and score each SFS handle
    // by how many leading device path nodes match.
    let sfs_handle = find_best_sfs_handle_for_device_path(device_path)
        .or_else(|| {
            log::warn!("BS.LoadImage: No device path match, falling back to first SFS handle");
            find_handle_with_protocol(&SIMPLE_FILE_SYSTEM_GUID)
        })
        .ok_or_else(|| {
            log::error!("BS.LoadImage: No SimpleFileSystem handle found");
            Status::NOT_FOUND
        })?;

    // Get the SimpleFileSystem protocol
    let sfs_interface =
        get_protocol_on_handle(sfs_handle, &SIMPLE_FILE_SYSTEM_GUID).ok_or_else(|| {
            log::error!("BS.LoadImage: Failed to get SimpleFileSystem protocol");
            Status::NOT_FOUND
        })?;

    let sfs = sfs_interface as *mut SimpleFileSystemProtocol;

    // Open the volume (root directory)
    let mut root: *mut FileProtocol = core::ptr::null_mut();
    let status = unsafe { ((*sfs).open_volume)(sfs, &mut root) };

    if status != Status::SUCCESS || root.is_null() {
        log::error!("BS.LoadImage: Failed to open volume: {:?}", status);
        return Err(status);
    }

    // Open the file
    let mut file: *mut FileProtocol = core::ptr::null_mut();
    let status = unsafe {
        ((*root).open)(
            root,
            &mut file,
            path_ptr as *mut u16,
            r_efi::protocols::file::MODE_READ,
            0,
        )
    };

    if status != Status::SUCCESS || file.is_null() {
        log::error!("BS.LoadImage: Failed to open file: {:?}", status);
        unsafe { ((*root).close)(root) };
        return Err(status);
    }

    // Get file size using GetInfo
    let mut info_buffer = [0u8; 256];
    let mut info_size = info_buffer.len();

    let status = unsafe {
        ((*file).get_info)(
            file,
            &r_efi::protocols::file::INFO_ID as *const Guid as *mut Guid,
            &mut info_size,
            info_buffer.as_mut_ptr() as *mut c_void,
        )
    };

    if status != Status::SUCCESS || info_size < 16 {
        log::error!(
            "BS.LoadImage: Failed to get file info: {:?}, info_size={}",
            status,
            info_size
        );
        unsafe {
            ((*file).close)(file);
            ((*root).close)(root);
        }
        return Err(Status::DEVICE_ERROR);
    }

    // EFI_FILE_INFO starts with Size (8 bytes) then FileSize (8 bytes)
    let file_size = u64::from_le_bytes(info_buffer[8..16].try_into().unwrap_or([0; 8]));
    log::debug!("BS.LoadImage: File size = {} bytes", file_size);

    if file_size == 0 || file_size > 256 * 1024 * 1024 {
        // Sanity check: reject empty files or files > 256MB
        log::error!("BS.LoadImage: Invalid file size: {}", file_size);
        unsafe {
            ((*file).close)(file);
            ((*root).close)(root);
        }
        return Err(Status::INVALID_PARAMETER);
    }

    // Allocate buffer for the file
    let buffer = match allocator::allocate_pool(MemoryType::BootServicesData, file_size as usize) {
        Ok(ptr) => ptr,
        Err(status) => {
            log::error!("BS.LoadImage: Failed to allocate {} bytes", file_size);
            unsafe {
                ((*file).close)(file);
                ((*root).close)(root);
            }
            return Err(status);
        }
    };

    // Read the file
    let mut read_size = file_size as usize;
    let status = unsafe { ((*file).read)(file, &mut read_size, buffer as *mut c_void) };

    // Close file handles
    unsafe {
        ((*file).close)(file);
        ((*root).close)(root);
    }

    if status != Status::SUCCESS {
        log::error!("BS.LoadImage: Failed to read file: {:?}", status);
        let _ = allocator::free_pool(buffer);
        return Err(status);
    }

    log::info!(
        "BS.LoadImage: Successfully loaded {} bytes from device path",
        read_size
    );

    Ok((buffer as *mut c_void, read_size, sfs_handle))
}

/// Find a handle that has a specific protocol installed
pub(crate) fn find_handle_with_protocol(protocol_guid: &Guid) -> Option<Handle> {
    let efi_state = unsafe { &*state::efi_ptr() };

    efi_state.handles[..efi_state.handle_count]
        .iter()
        .find(|e| {
            e.protocols[..e.protocol_count]
                .iter()
                .any(|p| p.guid == *protocol_guid)
        })
        .map(|e| e.handle)
}

/// Compare two device path node sequences byte-by-byte, returning the number of
/// consecutive matching nodes from the start.
unsafe fn match_device_path_prefix(
    input_dp: *const DevicePathProtocol,
    handle_dp: *const DevicePathProtocol,
) -> usize {
    unsafe {
        let mut matches = 0usize;
        let mut inp = input_dp;
        let mut hdl = handle_dp;

        for _ in 0..MAX_DEVICE_PATH_NODES {
            let inp_type = (*inp).r#type;
            let inp_sub = (*inp).sub_type;
            let inp_len = u16::from_le_bytes([(*inp).length[0], (*inp).length[1]]) as usize;

            let hdl_type = (*hdl).r#type;
            let hdl_sub = (*hdl).sub_type;
            let hdl_len = u16::from_le_bytes([(*hdl).length[0], (*hdl).length[1]]) as usize;

            // Stop at End or FilePath nodes on either side
            if inp_type == DEVICE_PATH_TYPE_END || hdl_type == DEVICE_PATH_TYPE_END {
                break;
            }
            if (inp_type == DEVICE_PATH_TYPE_MEDIA && inp_sub == DEVICE_PATH_SUBTYPE_FILE_PATH)
                || (hdl_type == DEVICE_PATH_TYPE_MEDIA && hdl_sub == DEVICE_PATH_SUBTYPE_FILE_PATH)
            {
                break;
            }

            // Compare nodes: type, subtype, length, then content
            if inp_type != hdl_type || inp_sub != hdl_sub || inp_len != hdl_len {
                break;
            }
            if inp_len < 4 || hdl_len < 4 {
                break;
            }

            // Byte-compare the full node
            let inp_bytes = core::slice::from_raw_parts(inp as *const u8, inp_len);
            let hdl_bytes = core::slice::from_raw_parts(hdl as *const u8, hdl_len);
            if inp_bytes != hdl_bytes {
                break;
            }

            matches += 1;
            inp = (inp as *const u8).add(inp_len) as *const DevicePathProtocol;
            hdl = (hdl as *const u8).add(hdl_len) as *const DevicePathProtocol;
        }

        matches
    }
}

/// Count the number of device path nodes before the End or FilePath node
unsafe fn count_device_path_prefix_nodes(dp: *const DevicePathProtocol) -> usize {
    unsafe {
        let mut count = 0usize;
        let mut current = dp;
        for _ in 0..MAX_DEVICE_PATH_NODES {
            let node_type = (*current).r#type;
            let node_subtype = (*current).sub_type;
            let node_length =
                u16::from_le_bytes([(*current).length[0], (*current).length[1]]) as usize;

            // Stop at End node
            if node_type == DEVICE_PATH_TYPE_END {
                break;
            }
            // Stop at File Path node (that's the file-specific part, not device identity)
            if node_type == DEVICE_PATH_TYPE_MEDIA && node_subtype == DEVICE_PATH_SUBTYPE_FILE_PATH
            {
                break;
            }
            if node_length < 4 {
                break;
            }
            count += 1;
            current = (current as *const u8).add(node_length) as *const DevicePathProtocol;
        }
        count
    }
}

/// Find the SFS handle whose device path best matches the input device path.
/// Returns the handle with the most matching prefix nodes, or None.
fn find_best_sfs_handle_for_device_path(device_path: *mut DevicePathProtocol) -> Option<Handle> {
    if device_path.is_null() {
        return None;
    }

    let input_prefix_count = unsafe { count_device_path_prefix_nodes(device_path) };
    if input_prefix_count == 0 {
        return None;
    }

    let efi_state = unsafe { &*state::efi_ptr() };
    let dp_guid = r_efi::protocols::device_path::PROTOCOL_GUID;

    let mut best_handle: Option<Handle> = None;
    let mut best_score: usize = 0;

    for entry in &efi_state.handles[..efi_state.handle_count] {
        // Must have SimpleFileSystem
        let has_sfs = entry.protocols[..entry.protocol_count]
            .iter()
            .any(|p| p.guid == SIMPLE_FILE_SYSTEM_GUID);
        if !has_sfs {
            continue;
        }

        // Get handle's device path
        let handle_dp = entry.protocols[..entry.protocol_count]
            .iter()
            .find(|p| p.guid == dp_guid)
            .map(|p| p.interface as *const DevicePathProtocol);

        if let Some(hdp) = handle_dp
            && !hdp.is_null()
        {
            let score = unsafe { match_device_path_prefix(device_path, hdp) };
            if score > best_score {
                best_score = score;
                best_handle = Some(entry.handle);
            }
        }
    }

    if best_score > 0 {
        log::info!(
            "BS.LoadImage: Best SFS handle {:?} matched {} device path nodes",
            best_handle,
            best_score
        );
    }

    best_handle
}

/// Get the device handle from a parent image's LoadedImageProtocol
pub(crate) fn get_device_handle_from_parent(parent_handle: Handle) -> Handle {
    if parent_handle.is_null() {
        return core::ptr::null_mut();
    }

    // Try to get the LoadedImageProtocol from the parent
    let efi_state = unsafe { &*state::efi_ptr() };
    efi_state
        .handles
        .iter()
        .find(|entry| entry.handle == parent_handle)
        .and_then(|entry| {
            entry.protocols[..entry.protocol_count]
                .iter()
                .find(|proto| {
                    proto.guid == LOADED_IMAGE_PROTOCOL_GUID && !proto.interface.is_null()
                })
                .map(|proto| {
                    let loaded_image = unsafe {
                        &*(proto.interface as *const r_efi::protocols::loaded_image::Protocol)
                    };
                    loaded_image.device_handle
                })
        })
        .unwrap_or(core::ptr::null_mut())
}

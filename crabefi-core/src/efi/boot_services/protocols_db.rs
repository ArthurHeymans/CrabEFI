//! EFI Boot Services handle and protocol database.
//!
//! Install/locate/open/close protocol interfaces on handles.

use super::super::guid_fmt::GuidFmt;
use super::super::system_table;
use super::super::tables::{
    MAX_HANDLES, MAX_PROTOCOLS_PER_HANDLE, ProtocolEntry, tables, with_tables_mut,
};
use core::ffi::c_void;
use r_efi::efi::{self, Guid, Handle, Status};
use r_efi::protocols::device_path::Protocol as DevicePathProtocol;

// ============================================================================
// Protocol Handler Functions
// ============================================================================

pub(super) extern "efiapi" fn install_protocol_interface(
    handle: *mut Handle,
    protocol: *mut Guid,
    interface_type: efi::InterfaceType,
    interface: *mut c_void,
) -> Status {
    if handle.is_null() || protocol.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Only native interface type is supported
    if interface_type != efi::NATIVE_INTERFACE {
        return Status::INVALID_PARAMETER;
    }

    let guid = unsafe { *protocol };
    let handle_ptr = unsafe { *handle };

    with_tables_mut(|efi_state| {
        // If handle is null, create a new handle
        if handle_ptr.is_null() {
            if efi_state.handle_count >= MAX_HANDLES {
                return Status::OUT_OF_RESOURCES;
            }

            let new_handle = efi_state.next_handle as *mut c_void;
            efi_state.next_handle += 1;

            let idx = efi_state.handle_count;
            efi_state.handles[idx].handle = new_handle;
            efi_state.handles[idx].protocols[0] = ProtocolEntry { guid, interface };
            efi_state.handles[idx].protocol_count = 1;
            efi_state.handle_count += 1;

            unsafe { *handle = new_handle };
            return Status::SUCCESS;
        }

        // Find existing handle
        if let Some(entry) = efi_state.handles[..efi_state.handle_count]
            .iter_mut()
            .find(|e| e.handle == handle_ptr)
        {
            // Check if protocol already installed
            if entry.protocols[..entry.protocol_count]
                .iter()
                .any(|p| p.guid == guid)
            {
                return Status::INVALID_PARAMETER; // Protocol already installed
            }

            // Add new protocol
            if entry.protocol_count >= MAX_PROTOCOLS_PER_HANDLE {
                return Status::OUT_OF_RESOURCES;
            }

            entry.protocols[entry.protocol_count] = ProtocolEntry { guid, interface };
            entry.protocol_count += 1;
            return Status::SUCCESS;
        }

        Status::INVALID_PARAMETER
    })
}

pub(super) extern "efiapi" fn reinstall_protocol_interface(
    _handle: Handle,
    _protocol: *mut Guid,
    _old_interface: *mut c_void,
    _new_interface: *mut c_void,
) -> Status {
    Status::NOT_FOUND
}

pub(super) extern "efiapi" fn uninstall_protocol_interface(
    _handle: Handle,
    _protocol: *mut Guid,
    _interface: *mut c_void,
) -> Status {
    Status::NOT_FOUND
}

pub(super) extern "efiapi" fn handle_protocol(
    handle: Handle,
    protocol: *mut Guid,
    interface: *mut *mut c_void,
) -> Status {
    let guid = if protocol.is_null() {
        Guid::from_fields(0, 0, 0, 0, 0, &[0; 6])
    } else {
        unsafe { *protocol }
    };
    log::debug!(
        "BS.HandleProtocol(handle={:?}, protocol={})",
        handle,
        GuidFmt(guid)
    );

    // Forward to open_protocol with simpler semantics
    let status = super::open_protocol(
        handle,
        protocol,
        interface,
        core::ptr::null_mut(), // agent_handle
        core::ptr::null_mut(), // controller_handle
        efi::OPEN_PROTOCOL_BY_HANDLE_PROTOCOL,
    );

    if status != Status::SUCCESS {
        log::debug!("  -> {:?}", status);
    }

    status
}

pub(super) extern "efiapi" fn register_protocol_notify(
    _protocol: *mut Guid,
    _event: efi::Event,
    _registration: *mut *mut c_void,
) -> Status {
    Status::UNSUPPORTED
}

pub(super) extern "efiapi" fn locate_handle(
    search_type: efi::LocateSearchType,
    protocol: *mut Guid,
    _search_key: *mut c_void,
    buffer_size: *mut usize,
    buffer: *mut Handle,
) -> Status {
    if buffer_size.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let guid_display = if protocol.is_null() {
        None
    } else {
        Some(GuidFmt(unsafe { *protocol }))
    };

    log::debug!(
        "BS.LocateHandle(type={}, protocol={}, buf_size={}, buf={:?})",
        search_type,
        guid_display
            .as_ref()
            .map(|g| g as &dyn core::fmt::Display)
            .unwrap_or(&"NULL" as &dyn core::fmt::Display),
        unsafe { *buffer_size },
        buffer
    );

    let efi_state = tables();

    // Collect matching handles based on search type
    let matching: heapless::Vec<Handle, MAX_HANDLES> = match search_type {
        efi::ALL_HANDLES => efi_state.handles[..efi_state.handle_count]
            .iter()
            .map(|entry| entry.handle)
            .collect(),
        efi::BY_REGISTER_NOTIFY => {
            log::debug!("  -> NOT_FOUND (BY_REGISTER_NOTIFY not fully supported)");
            return Status::NOT_FOUND;
        }
        efi::BY_PROTOCOL => {
            if protocol.is_null() {
                return Status::INVALID_PARAMETER;
            }
            let guid = unsafe { *protocol };
            efi_state.handles[..efi_state.handle_count]
                .iter()
                .filter(|entry| {
                    entry.protocols[..entry.protocol_count]
                        .iter()
                        .any(|p| p.guid == guid)
                })
                .map(|entry| entry.handle)
                .collect()
        }
        _ => {
            log::debug!(
                "  -> INVALID_PARAMETER (unknown search type {})",
                search_type
            );
            return Status::INVALID_PARAMETER;
        }
    };

    // Check for no matches FIRST, before buffer size checks
    if matching.is_empty() {
        log::debug!("  -> NOT_FOUND (no matching handles)");
        return Status::NOT_FOUND;
    }

    let required_size = matching.len() * core::mem::size_of::<Handle>();

    if buffer.is_null() || unsafe { *buffer_size } < required_size {
        unsafe { *buffer_size = required_size };
        log::debug!("  -> BUFFER_TOO_SMALL (need {} bytes)", required_size);
        return Status::BUFFER_TOO_SMALL;
    }

    // Copy handles to buffer using slice copy
    let dest = unsafe { core::slice::from_raw_parts_mut(buffer, matching.len()) };
    dest.copy_from_slice(&matching[..]);
    unsafe { *buffer_size = required_size };

    log::debug!("  -> found {} handles: {:?}", matching.len(), &matching[..]);
    Status::SUCCESS
}

unsafe fn device_path_node_len(dp: *mut DevicePathProtocol) -> Option<usize> {
    let len = unsafe { u16::from_le_bytes([(*dp).length[0], (*dp).length[1]]) as usize };
    (len >= 4).then_some(len)
}

unsafe fn is_device_path_end(dp: *mut DevicePathProtocol) -> bool {
    unsafe { (*dp).r#type == 0x7f && (*dp).sub_type == 0xff }
}

unsafe fn device_path_prefix_match(
    handle_dp: *mut DevicePathProtocol,
    input_dp: *mut DevicePathProtocol,
) -> Option<*mut DevicePathProtocol> {
    let mut handle_node = handle_dp;
    let mut input_node = input_dp;

    // Device paths are small. Bound the walk so malformed paths cannot loop forever.
    for _ in 0..128 {
        if unsafe { is_device_path_end(handle_node) } {
            return Some(input_node);
        }
        if unsafe { is_device_path_end(input_node) } {
            return None;
        }

        let handle_len = unsafe { device_path_node_len(handle_node)? };
        let input_len = unsafe { device_path_node_len(input_node)? };
        if handle_len != input_len {
            return None;
        }

        let handle_bytes =
            unsafe { core::slice::from_raw_parts(handle_node as *const u8, handle_len) };
        let input_bytes =
            unsafe { core::slice::from_raw_parts(input_node as *const u8, input_len) };
        if handle_bytes != input_bytes {
            return None;
        }

        handle_node =
            unsafe { (handle_node as *const u8).add(handle_len) as *mut DevicePathProtocol };
        input_node = unsafe { (input_node as *const u8).add(input_len) as *mut DevicePathProtocol };
    }

    None
}

pub(super) extern "efiapi" fn locate_device_path(
    protocol: *mut Guid,
    device_path: *mut *mut DevicePathProtocol,
    device: *mut Handle,
) -> Status {
    if protocol.is_null() || device_path.is_null() || device.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let guid = unsafe { *protocol };
    log::debug!("BS.LocateDevicePath(protocol={})", GuidFmt(guid));

    let input_dp = unsafe { *device_path };
    if input_dp.is_null() {
        log::debug!("  -> INVALID_PARAMETER (device_path is NULL)");
        return Status::INVALID_PARAMETER;
    }

    // Find a handle with both the specified protocol and a DEVICE_PATH protocol
    let efi_state = tables();

    let found = efi_state.handles[..efi_state.handle_count]
        .iter()
        .find_map(|entry| {
            let protocols = &entry.protocols[..entry.protocol_count];

            let has_protocol = protocols.iter().any(|p| p.guid == guid);
            if !has_protocol {
                return None;
            }

            let handle_dp = protocols
                .iter()
                .find(|p| p.guid == r_efi::protocols::device_path::PROTOCOL_GUID)
                .map(|p| p.interface as *mut DevicePathProtocol)?;
            if handle_dp.is_null() {
                return None;
            }

            let remaining = unsafe { device_path_prefix_match(handle_dp, input_dp) }?;
            Some((entry.handle, remaining))
        });

    if let Some((handle, remaining)) = found {
        log::debug!(
            "  -> SUCCESS (handle={:?}, remaining_device_path={:?})",
            handle,
            remaining
        );
        unsafe {
            *device = handle;
            *device_path = remaining;
        }
        return Status::SUCCESS;
    }

    log::debug!("  -> NOT_FOUND");
    Status::NOT_FOUND
}

pub(super) extern "efiapi" fn install_configuration_table(
    guid: *mut Guid,
    table: *mut c_void,
) -> Status {
    if guid.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let guid_ref = unsafe { &*guid };
    system_table::install_configuration_table(guid_ref, table)
}

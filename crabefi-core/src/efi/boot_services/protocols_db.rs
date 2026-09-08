//! EFI Boot Services handle and protocol database.
//!
//! Install/locate/open/close protocol interfaces on handles.

use super::super::guid_fmt::GuidFmt;
use super::super::system_table;
use super::super::tables::{
    HandleEntry, MAX_PROTOCOL_NOTIFIES, ProtocolEntry, ProtocolNotifyEntry, Tables, tables,
    with_tables_mut,
};
use super::events::{event_id_for_handle, signal_event};
use super::{create_handle, install_protocol, protocol_open_blocks_removal, remove_protocol};
use alloc::vec::Vec;
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

    if interface_type != efi::NATIVE_INTERFACE {
        return Status::INVALID_PARAMETER;
    }

    let target_handle = if unsafe { (*handle).is_null() } {
        let Some(new_handle) = create_handle() else {
            return Status::OUT_OF_RESOURCES;
        };
        unsafe { *handle = new_handle };
        new_handle
    } else {
        unsafe { *handle }
    };

    install_protocol(target_handle, &unsafe { *protocol }, interface)
}

pub(super) extern "efiapi" fn reinstall_protocol_interface(
    handle: Handle,
    protocol: *mut Guid,
    old_interface: *mut c_void,
    new_interface: *mut c_void,
) -> Status {
    if handle.is_null() || protocol.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let guid = unsafe { *protocol };
    let (status, notify_events) = with_tables_mut(|efi_state| {
        let Some(entry) = efi_state.handles[..efi_state.handle_count]
            .iter_mut()
            .find(|entry| entry.handle == handle)
        else {
            return (Status::NOT_FOUND, heapless::Vec::new());
        };
        let Some(protocol_entry) = entry.protocols[..entry.protocol_count]
            .iter_mut()
            .find(|entry| entry.guid == guid && entry.interface == old_interface)
        else {
            return (Status::NOT_FOUND, heapless::Vec::new());
        };
        if efi_state.open_protocols.iter().any(|open| {
            open.handle == handle
                && open.protocol == guid
                && protocol_open_blocks_removal(open.attributes)
        }) {
            // Built-in drivers have no DisconnectController implementation. Do not
            // replace an interface while a driver or exclusive user still holds it.
            return (Status::ACCESS_DENIED, heapless::Vec::new());
        }
        efi_state
            .open_protocols
            .retain(|open| open.handle != handle || open.protocol != guid);
        let Some(generation) = efi_state.protocol_generation.checked_add(1) else {
            return (Status::OUT_OF_RESOURCES, heapless::Vec::new());
        };
        efi_state.protocol_generation = generation;
        protocol_entry.generation = generation;
        protocol_entry.interface = new_interface;
        // Per the UEFI spec a reinstall notifies registrations just like an
        // install, so drivers can rebind to the replacement interface.
        let events = protocol_notification_events(efi_state, &guid);
        (Status::SUCCESS, events)
    });

    for event in notify_events {
        signal_event(event);
    }

    status
}

pub(super) extern "efiapi" fn uninstall_protocol_interface(
    handle: Handle,
    protocol: *mut Guid,
    interface: *mut c_void,
) -> Status {
    if handle.is_null() || protocol.is_null() {
        return Status::INVALID_PARAMETER;
    }
    remove_protocol(handle, &unsafe { *protocol }, Some(interface))
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
    protocol: *mut Guid,
    event: efi::Event,
    registration: *mut *mut c_void,
) -> Status {
    if protocol.is_null() || registration.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let guid = unsafe { *protocol };
    log::debug!("BS.RegisterProtocolNotify(protocol={})", GuidFmt(guid));

    match with_tables_mut(|state| register_notify(state, guid, event)) {
        Ok(token) => {
            unsafe { *registration = token as *mut c_void };
            log::debug!("  -> SUCCESS (registration={:#x})", token);
            Status::SUCCESS
        }
        Err(status) => status,
    }
}

/// Validate the live event and allocate its notification registration together.
fn register_notify(state: &mut Tables, protocol: Guid, event: efi::Event) -> Result<usize, Status> {
    if event_id_for_handle(&state.events, event).is_none() {
        return Err(Status::INVALID_PARAMETER);
    }
    if state.protocol_notifies.len() >= MAX_PROTOCOL_NOTIFIES
        || state.protocol_notifies.try_reserve(1).is_err()
    {
        return Err(Status::OUT_OF_RESOURCES);
    }
    let token = state.next_registration;
    state.next_registration = token.checked_add(1).ok_or(Status::OUT_OF_RESOURCES)?;
    state.protocol_notifies.push(ProtocolNotifyEntry {
        registration: token,
        protocol,
        event,
        cursor: 0,
    });
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efi::boot_services::events::event_handle;
    use crate::efi::tables::{EventEntry, MAX_EVENTS};

    #[test]
    fn notification_registration_validates_event_generations() {
        let mut state = Tables::new();
        state.events.resize(MAX_EVENTS, EventEntry::empty());
        let slot = 3;
        state.events[slot].in_use = true;
        state.events[slot].generation = 1;
        let event = event_handle(slot, 1);
        let guid = Guid::from_fields(1, 2, 3, 4, 5, &[6; 6]);

        assert!(register_notify(&mut state, guid, event).is_ok());
        assert_eq!(
            protocol_notification_events(&state, &guid).as_slice(),
            &[event]
        );
        state.events[slot].generation = 2;
        assert_eq!(
            register_notify(&mut state, guid, event),
            Err(Status::INVALID_PARAMETER)
        );
        let replacement = event_handle(slot, 2);
        assert!(register_notify(&mut state, guid, replacement).is_ok());
        state.events[slot].in_use = false;
        assert_eq!(
            register_notify(&mut state, guid, replacement),
            Err(Status::INVALID_PARAMETER)
        );
        assert_eq!(state.protocol_notifies.len(), 2);
    }
}

/// Collect events to signal after releasing the database borrow.
pub(super) fn protocol_notification_events(
    efi_state: &Tables,
    guid: &Guid,
) -> heapless::Vec<efi::Event, MAX_PROTOCOL_NOTIFIES> {
    efi_state
        .protocol_notifies
        .iter()
        .filter(|notify| notify.protocol == *guid)
        .map(|notify| notify.event)
        .collect()
}

/// Peek the next live instance without advancing a registration's shared cursor.
pub(super) fn next_registered_protocol(
    efi_state: &Tables,
    token: usize,
    protocol: Option<Guid>,
) -> Result<(usize, Handle, ProtocolEntry), Status> {
    let (index, notify) = efi_state
        .protocol_notifies
        .iter()
        .enumerate()
        .find(|(_, notify)| notify.registration == token)
        .ok_or(Status::INVALID_PARAMETER)?;
    if protocol.is_some_and(|guid| guid != notify.protocol) {
        return Err(Status::INVALID_PARAMETER);
    }
    efi_state.handles[..efi_state.handle_count]
        .iter()
        .flat_map(|handle| {
            handle.protocols[..handle.protocol_count]
                .iter()
                .map(move |entry| (index, handle.handle, *entry))
        })
        .filter(|(_, _, entry)| entry.guid == notify.protocol && entry.generation > notify.cursor)
        .min_by_key(|(_, _, entry)| entry.generation)
        .ok_or(Status::NOT_FOUND)
}

pub(super) extern "efiapi" fn locate_handle(
    search_type: efi::LocateSearchType,
    protocol: *mut Guid,
    search_key: *mut c_void,
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

    if search_type == efi::BY_REGISTER_NOTIFY {
        return with_tables_mut(|efi_state| {
            let (index, handle, entry) =
                match next_registered_protocol(efi_state, search_key as usize, None) {
                    Ok(next) => next,
                    Err(status) => return status,
                };
            let required_size = core::mem::size_of::<Handle>();
            let capacity = unsafe { *buffer_size };
            unsafe { *buffer_size = required_size };
            if buffer.is_null() || capacity < required_size {
                return Status::BUFFER_TOO_SMALL;
            }
            unsafe { *buffer = handle };
            efi_state.protocol_notifies[index].cursor = entry.generation;
            Status::SUCCESS
        });
    }

    // Collect matching handles based on search type. The handle database grows
    // past its preallocated size, so this collects onto the heap rather than
    // into a fixed-capacity buffer that would silently truncate the result.
    //
    let matching = {
        let efi_state = tables();
        match search_type {
            efi::ALL_HANDLES => match collect_handles(&efi_state, |_| true) {
                Ok(handles) => handles,
                Err(status) => return status,
            },
            efi::BY_PROTOCOL => {
                if protocol.is_null() {
                    return Status::INVALID_PARAMETER;
                }
                let guid = unsafe { *protocol };
                match collect_handles(&efi_state, |entry| {
                    entry.protocols[..entry.protocol_count]
                        .iter()
                        .any(|p| p.guid == guid)
                }) {
                    Ok(handles) => handles,
                    Err(status) => return status,
                }
            }
            _ => {
                log::debug!(
                    "  -> INVALID_PARAMETER (unknown search type {})",
                    search_type
                );
                return Status::INVALID_PARAMETER;
            }
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

/// Collect the handles matching `filter` onto the firmware heap.
///
/// # Arguments
/// * `efi_state` - Borrowed EFI state.
/// * `filter` - Predicate applied to each live handle entry.
///
/// # Returns
/// The matching handles, or `Err(OUT_OF_RESOURCES)` when the heap cannot hold them.
fn collect_handles(
    efi_state: &Tables,
    filter: impl Fn(&HandleEntry) -> bool,
) -> Result<Vec<Handle>, Status> {
    let mut handles = Vec::new();
    if handles.try_reserve_exact(efi_state.handle_count).is_err() {
        return Err(Status::OUT_OF_RESOURCES);
    }
    handles.extend(
        efi_state.handles[..efi_state.handle_count]
            .iter()
            .filter(|entry| filter(entry))
            .map(|entry| entry.handle),
    );
    Ok(handles)
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

    // Find the handle with both the specified protocol and a DEVICE_PATH protocol.
    // UEFI requires the longest matching prefix, so evaluate every candidate
    // and keep the one that consumes the most bytes of the input path.
    let efi_state = tables();

    let found = efi_state.handles[..efi_state.handle_count]
        .iter()
        .filter_map(|entry| {
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
            // `remaining` points into the input path past the matched prefix,
            // so its offset from the input start is the consumed length.
            let consumed = (remaining as usize).wrapping_sub(input_dp as usize);
            Some((consumed, entry.handle, remaining))
        })
        .max_by_key(|(consumed, _, _)| *consumed)
        .map(|(_, handle, remaining)| (handle, remaining));

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

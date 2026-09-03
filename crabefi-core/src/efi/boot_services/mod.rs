//! EFI Boot Services
//!
//! This module implements the EFI Boot Services table, which provides
//! memory allocation, protocol handling, and image loading services.
//!
//! # State Management
//!
//! Boot Services state (handles, events, loaded images) lives in
//! [`super::tables`]. Access it via `tables()` and `with_tables_mut()`.

mod events;
mod images;
mod memory;
mod protocols_db;

pub use events::KEYBOARD_EVENT_ID;
#[cfg(feature = "ui")]
pub use events::POINTER_EVENT_ID;
pub(crate) use events::{measure_efi_application_return, measure_efi_application_start};
pub(crate) use images::serialize_tcg_image_load_event;

use super::allocator::{self, MemoryType};
use super::guid_fmt::GuidFmt;
use super::tables::{
    MAX_HANDLES, MAX_PROTOCOLS_PER_HANDLE, ProtocolEntry, tables, with_tables_mut,
};
use crate::cell::StaticMut;
use core::ffi::c_void;
use r_efi::protocols::device_path::Protocol as DevicePathProtocol;

use crabefi_efi_types::crc32;
use r_efi::efi::{self, Boolean, Guid, Handle, Status, TableHeader, Tpl};

/// Boot Services signature "BOOTSERV"
const EFI_BOOT_SERVICES_SIGNATURE: u64 = 0x56524553544F4F42;

/// Boot Services revision (matches system table)
const EFI_BOOT_SERVICES_REVISION: u32 = (2 << 16) | 100;

/// Static boot services table
static BOOT_SERVICES: StaticMut<efi::BootServices> = StaticMut::new(efi::BootServices {
    hdr: TableHeader {
        signature: EFI_BOOT_SERVICES_SIGNATURE,
        revision: EFI_BOOT_SERVICES_REVISION,
        header_size: core::mem::size_of::<efi::BootServices>() as u32,
        crc32: 0,
        reserved: 0,
    },
    raise_tpl,
    restore_tpl,
    allocate_pages: memory::allocate_pages,
    free_pages: memory::free_pages,
    get_memory_map: memory::get_memory_map,
    allocate_pool: memory::allocate_pool,
    free_pool: memory::free_pool,
    create_event: events::create_event,
    set_timer: events::set_timer,
    wait_for_event: events::wait_for_event,
    signal_event: events::signal_event,
    close_event: events::close_event,
    check_event: events::check_event,
    install_protocol_interface: protocols_db::install_protocol_interface,
    reinstall_protocol_interface: protocols_db::reinstall_protocol_interface,
    uninstall_protocol_interface: protocols_db::uninstall_protocol_interface,
    handle_protocol: protocols_db::handle_protocol,
    reserved: core::ptr::null_mut(),
    register_protocol_notify: protocols_db::register_protocol_notify,
    locate_handle: protocols_db::locate_handle,
    locate_device_path: protocols_db::locate_device_path,
    install_configuration_table: protocols_db::install_configuration_table,
    load_image: images::load_image,
    start_image: images::start_image,
    exit: images::exit,
    unload_image: images::unload_image,
    exit_boot_services: images::exit_boot_services,
    get_next_monotonic_count,
    stall,
    set_watchdog_timer,
    connect_controller,
    disconnect_controller,
    open_protocol,
    close_protocol,
    open_protocol_information,
    protocols_per_handle,
    locate_handle_buffer,
    locate_protocol,
    // These are variadic functions - we use transmute to cast our extended-signature
    // functions to the expected type. The caller passes all args regardless of signature.
    install_multiple_protocol_interfaces: unsafe {
        core::mem::transmute::<
            extern "efiapi" fn(
                *mut Handle,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
            ) -> Status,
            extern "efiapi" fn(*mut Handle, *mut c_void, *mut c_void) -> Status,
        >(install_multiple_protocol_interfaces)
    },
    uninstall_multiple_protocol_interfaces: unsafe {
        core::mem::transmute::<
            extern "efiapi" fn(
                Handle,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut c_void,
            ) -> Status,
            extern "efiapi" fn(Handle, *mut c_void, *mut c_void) -> Status,
        >(uninstall_multiple_protocol_interfaces)
    },
    calculate_crc32,
    copy_mem,
    set_mem,
    create_event_ex: events::create_event_ex,
});

/// Get a pointer to the boot services table
pub fn get_boot_services() -> *mut efi::BootServices {
    BOOT_SERVICES.get()
}

// ============================================================================
// TPL (Task Priority Level) Functions
// ============================================================================

extern "efiapi" fn raise_tpl(new_tpl: Tpl) -> Tpl {
    log::debug!("BS.RaiseTpl({:?})", new_tpl);
    // No interrupt handling, return current TPL (APPLICATION)
    efi::TPL_APPLICATION
}

extern "efiapi" fn restore_tpl(old_tpl: Tpl) {
    log::debug!("BS.RestoreTpl({:?})", old_tpl);
    // No-op
}

// ============================================================================
// Miscellaneous Functions
// ============================================================================

extern "efiapi" fn get_next_monotonic_count(count: *mut u64) -> Status {
    if count.is_null() {
        return Status::INVALID_PARAMETER;
    }

    with_tables_mut(|efi_state| {
        efi_state.monotonic_count += 1;
        unsafe { *count = efi_state.monotonic_count };
        Status::SUCCESS
    })
}

extern "efiapi" fn stall(microseconds: usize) -> Status {
    log::debug!("BS.Stall({}us)", microseconds);
    // Use TSC-calibrated delay for accurate timing
    crate::time::delay_us(microseconds as u64);
    Status::SUCCESS
}

extern "efiapi" fn set_watchdog_timer(
    timeout: usize,
    watchdog_code: u64,
    _data_size: usize,
    _watchdog_data: *mut u16,
) -> Status {
    log::debug!(
        "BS.SetWatchdogTimer(timeout={}, code={:#x})",
        timeout,
        watchdog_code
    );
    // Accept the call but don't implement actual watchdog.
    // The UEFI spec default is a 5-minute watchdog that bootloaders disable
    // by calling SetWatchdogTimer(0, 0, 0, NULL). Returning SUCCESS lets
    // Windows Boot Manager proceed without error.
    Status::SUCCESS
}

extern "efiapi" fn connect_controller(
    controller_handle: Handle,
    _driver_image_handle: *mut Handle,
    _remaining_device_path: *mut DevicePathProtocol,
    _recursive: Boolean,
) -> Status {
    log::debug!("BS.ConnectController(handle={:?})", controller_handle);
    // CrabEFI doesn't use the UEFI driver model -- all drivers are built-in.
    // Return SUCCESS so callers (like Windows Boot Manager) don't fail.
    if controller_handle.is_null() {
        return Status::INVALID_PARAMETER;
    }
    Status::SUCCESS
}

extern "efiapi" fn disconnect_controller(
    controller_handle: Handle,
    _driver_image_handle: Handle,
    _child_handle: Handle,
) -> Status {
    log::debug!("BS.DisconnectController(handle={:?})", controller_handle);
    // No-op for the same reason as ConnectController.
    if controller_handle.is_null() {
        return Status::INVALID_PARAMETER;
    }
    Status::SUCCESS
}

pub(super) extern "efiapi" fn open_protocol(
    handle: Handle,
    protocol: *mut Guid,
    interface: *mut *mut c_void,
    _agent_handle: Handle,
    _controller_handle: Handle,
    attributes: u32,
) -> Status {
    if handle.is_null() || protocol.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let guid = unsafe { *protocol };
    let guid_name = super::guid_fmt::lookup_guid_name(&guid);
    log::debug!(
        "BS.OpenProtocol(handle={:?}, protocol={}, attr={:#x})",
        handle,
        GuidFmt(guid),
        attributes
    );

    let efi_state = tables();

    // Find the handle entry
    let handle_entry = efi_state.handles[..efi_state.handle_count]
        .iter()
        .find(|entry| entry.handle == handle);

    let Some(entry) = handle_entry else {
        log::warn!("  -> INVALID_PARAMETER (handle not found)");
        return Status::INVALID_PARAMETER;
    };

    // Find the protocol on this handle
    let proto = entry.protocols[..entry.protocol_count]
        .iter()
        .find(|p| p.guid == guid);

    let Some(proto) = proto else {
        log::warn!("  -> UNSUPPORTED (protocol not on handle)");
        return Status::UNSUPPORTED;
    };

    let iface = proto.interface;
    if !interface.is_null() {
        unsafe { *interface = iface };
    }
    log::trace!("  -> SUCCESS (interface={:?})", iface);

    // For LOADED_IMAGE, log important fields
    if guid_name == "LOADED_IMAGE" && !iface.is_null() {
        let lip = iface as *const r_efi::protocols::loaded_image::Protocol;
        let dev_handle = unsafe { (*lip).device_handle };
        let sys_table = unsafe { (*lip).system_table };
        log::trace!("  -> LOADED_IMAGE.DeviceHandle = {:?}", dev_handle);
        log::trace!("  -> LOADED_IMAGE.SystemTable = {:?}", sys_table);
        // Check if SystemTable looks valid
        if !sys_table.is_null() {
            let bs = unsafe { (*sys_table).boot_services };
            log::trace!("  -> LOADED_IMAGE.SystemTable->BootServices = {:?}", bs);
        } else {
            log::error!("  -> LOADED_IMAGE.SystemTable is NULL!");
        }
    }

    Status::SUCCESS
}

extern "efiapi" fn close_protocol(
    handle: Handle,
    protocol: *mut Guid,
    _agent_handle: Handle,
    _controller_handle: Handle,
) -> Status {
    let guid = if protocol.is_null() {
        log::debug!("BS.CloseProtocol: protocol is NULL");
        return Status::INVALID_PARAMETER;
    } else {
        unsafe { *protocol }
    };

    log::debug!(
        "BS.CloseProtocol(handle={:?}, protocol={})",
        handle,
        GuidFmt(guid)
    );

    if handle.is_null() {
        log::debug!("  -> INVALID_PARAMETER (handle is NULL)");
        return Status::INVALID_PARAMETER;
    }

    // Verify the handle exists and has this protocol
    let efi_state = tables();
    let handle_exists = efi_state.handles[..efi_state.handle_count]
        .iter()
        .any(|entry| {
            entry.handle == handle
                && entry.protocols[..entry.protocol_count]
                    .iter()
                    .any(|p| p.guid == guid)
        });

    if !handle_exists {
        log::debug!("  -> NOT_FOUND");
        return Status::NOT_FOUND;
    }

    // In our simple implementation, we don't track open protocol usage,
    // so close is effectively a no-op but we return SUCCESS
    log::debug!("  -> SUCCESS");
    Status::SUCCESS
}

extern "efiapi" fn open_protocol_information(
    handle: Handle,
    protocol: *mut Guid,
    entry_buffer: *mut *mut efi::OpenProtocolInformationEntry,
    entry_count: *mut usize,
) -> Status {
    log::debug!("BS.OpenProtocolInformation(handle={:?})", handle);

    if handle.is_null() || protocol.is_null() || entry_buffer.is_null() || entry_count.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // We don't track protocol open/close agents in our simple implementation.
    // Return an empty list -- this is valid per UEFI spec (zero agents have opened it).
    unsafe {
        *entry_buffer = core::ptr::null_mut();
        *entry_count = 0;
    }

    Status::SUCCESS
}

extern "efiapi" fn protocols_per_handle(
    handle: Handle,
    protocol_buffer: *mut *mut *mut Guid,
    protocol_buffer_count: *mut usize,
) -> Status {
    log::debug!("BS.ProtocolsPerHandle(handle={:?})", handle);

    if handle.is_null() || protocol_buffer.is_null() || protocol_buffer_count.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let efi_state = tables();

    // Find the handle entry
    let entry = match efi_state.handles[..efi_state.handle_count]
        .iter()
        .find(|e| e.handle == handle)
    {
        Some(e) => e,
        None => {
            log::debug!("  -> NOT_FOUND");
            return Status::NOT_FOUND;
        }
    };

    let count = entry.protocol_count;

    if count == 0 {
        // No protocols on this handle -- return empty buffer
        unsafe {
            *protocol_buffer = core::ptr::null_mut();
            *protocol_buffer_count = 0;
        }
        log::debug!("  -> SUCCESS (0 protocols)");
        return Status::SUCCESS;
    }

    // Allocate a single contiguous buffer: array of Guid pointers followed by
    // the Guid values themselves. Per UEFI spec, the caller frees only the
    // returned buffer with a single FreePool call, so all data must live in
    // one allocation.
    let ptrs_size = count * core::mem::size_of::<*mut Guid>();
    let guids_size = count * core::mem::size_of::<Guid>();
    let total_size = ptrs_size + guids_size;
    let buf = match allocator::allocate_pool(MemoryType::BootServicesData, total_size) {
        Ok(ptr) => ptr,
        Err(_) => return Status::OUT_OF_RESOURCES,
    };

    // Layout: [*mut Guid; count] [Guid; count]
    let ptr_array = buf as *mut *mut Guid;
    let guid_array = unsafe { buf.add(ptrs_size) } as *mut Guid;

    for (i, protocol) in entry.protocols.iter().take(count).enumerate() {
        unsafe {
            let guid_ptr = guid_array.add(i);
            *guid_ptr = protocol.guid;
            *ptr_array.add(i) = guid_ptr;
        }
    }

    unsafe {
        *protocol_buffer = ptr_array;
        *protocol_buffer_count = count;
    }

    log::debug!("  -> SUCCESS ({} protocols)", count);
    Status::SUCCESS
}

extern "efiapi" fn locate_handle_buffer(
    search_type: efi::LocateSearchType,
    protocol: *mut Guid,
    search_key: *mut c_void,
    no_handles: *mut usize,
    buffer: *mut *mut Handle,
) -> Status {
    let guid_display = if protocol.is_null() {
        None
    } else {
        Some(GuidFmt(unsafe { *protocol }))
    };

    log::debug!(
        "BS.LocateHandleBuffer(type={}, protocol={})",
        search_type,
        guid_display
            .as_ref()
            .map(|g| g as &dyn core::fmt::Display)
            .unwrap_or(&"NULL" as &dyn core::fmt::Display)
    );

    if no_handles.is_null() || buffer.is_null() {
        log::debug!("  -> INVALID_PARAMETER");
        return Status::INVALID_PARAMETER;
    }

    // First, call locate_handle with null buffer to get required size
    let mut buffer_size: usize = 0;
    let status = protocols_db::locate_handle(
        search_type,
        protocol,
        search_key,
        &mut buffer_size as *mut usize,
        core::ptr::null_mut(),
    );

    // If no handles found, buffer_size is 0
    if status == Status::NOT_FOUND {
        unsafe {
            *no_handles = 0;
            *buffer = core::ptr::null_mut();
        }
        log::warn!("  -> NOT_FOUND");
        return Status::NOT_FOUND;
    }

    // Should get BUFFER_TOO_SMALL with required size
    if status != Status::BUFFER_TOO_SMALL {
        log::debug!("  -> {:?} (unexpected from locate_handle)", status);
        return status;
    }

    // Calculate number of handles
    let handle_count = buffer_size / core::mem::size_of::<Handle>();

    // Allocate buffer for handles
    let alloc_result = allocator::allocate_pool(MemoryType::BootServicesData, buffer_size);
    let handle_buffer = match alloc_result {
        Ok(ptr) => ptr as *mut Handle,
        Err(e) => {
            log::warn!("  -> OUT_OF_RESOURCES (pool allocation failed: {:?})", e);
            return Status::OUT_OF_RESOURCES;
        }
    };

    // Call locate_handle again with the allocated buffer
    let status = protocols_db::locate_handle(
        search_type,
        protocol,
        search_key,
        &mut buffer_size as *mut usize,
        handle_buffer,
    );

    if status != Status::SUCCESS {
        // Free the allocated buffer on failure
        let _ = allocator::free_pool(handle_buffer as *mut u8);
        log::debug!("  -> {:?} (second locate_handle call failed)", status);
        return status;
    }

    // Return results to caller
    unsafe {
        *no_handles = handle_count;
        *buffer = handle_buffer;
    }

    log::debug!("  -> SUCCESS ({} handles)", handle_count);
    Status::SUCCESS
}

extern "efiapi" fn locate_protocol(
    protocol: *mut Guid,
    _registration: *mut c_void,
    interface: *mut *mut c_void,
) -> Status {
    if protocol.is_null() || interface.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let guid = unsafe { *protocol };
    log::trace!("BS.LocateProtocol(protocol={})", GuidFmt(guid));

    let efi_state = tables();

    // Find first handle with this protocol
    let found = efi_state.handles[..efi_state.handle_count]
        .iter()
        .flat_map(|entry| entry.protocols[..entry.protocol_count].iter())
        .find(|proto| proto.guid == guid);

    if let Some(proto) = found {
        unsafe { *interface = proto.interface };
        log::trace!("  -> SUCCESS (interface={:p})", proto.interface);
        return Status::SUCCESS;
    }

    log::trace!("  -> NOT_FOUND");
    Status::NOT_FOUND
}

// Note: These are variadic in the real UEFI spec. We handle this by accepting
// enough arguments for the common case (up to 4 protocol pairs) and iterating
// until we find a NULL GUID terminator.
extern "efiapi" fn install_multiple_protocol_interfaces(
    handle: *mut Handle,
    // Variadic args come as pairs: (GUID*, interface*), terminated by NULL
    arg1: *mut c_void,
    arg2: *mut c_void,
    arg3: *mut c_void,
    arg4: *mut c_void,
    arg5: *mut c_void,
    arg6: *mut c_void,
    arg7: *mut c_void,
    arg8: *mut c_void,
) -> Status {
    if handle.is_null() {
        log::debug!("BS.InstallMultipleProtocolInterfaces: handle ptr is NULL");
        return Status::INVALID_PARAMETER;
    }

    // Collect the argument pairs
    let args = [(arg1, arg2), (arg3, arg4), (arg5, arg6), (arg7, arg8)];

    // Count how many valid protocol pairs we have (until NULL GUID)
    let pair_count = args
        .iter()
        .take_while(|(guid_ptr, _)| !guid_ptr.is_null())
        .count();

    log::debug!(
        "BS.InstallMultipleProtocolInterfaces(handle={:?}, {} protocols)",
        unsafe { *handle },
        pair_count
    );

    if pair_count == 0 {
        // No protocols to install, just return success
        return Status::SUCCESS;
    }

    // If handle points to NULL, create a new handle
    let target_handle = if unsafe { (*handle).is_null() } {
        match create_handle() {
            Some(h) => {
                unsafe { *handle = h };
                log::debug!("  Created new handle: {:?}", h);
                h
            }
            None => {
                log::error!("  Failed to create handle");
                return Status::OUT_OF_RESOURCES;
            }
        }
    } else {
        unsafe { *handle }
    };

    // Install each protocol, rolling back on failure
    for i in 0..pair_count {
        let guid_ptr = args[i].0 as *mut Guid;
        let interface = args[i].1;

        if guid_ptr.is_null() {
            break;
        }

        let guid = unsafe { *guid_ptr };
        log::debug!("  Installing protocol: {}", GuidFmt(guid));

        let status = install_protocol(target_handle, &guid, interface);
        if status != Status::SUCCESS {
            log::error!(
                "  Failed to install protocol {}: {:?}",
                GuidFmt(guid),
                status
            );
            // Rollback: uninstall previously installed protocols from this call
            for j in (0..i).rev() {
                let prev_guid_ptr = args[j].0 as *const Guid;
                if !prev_guid_ptr.is_null() {
                    let prev_guid = unsafe { *prev_guid_ptr };
                    with_tables_mut(|efi_state| {
                        if let Some(entry) = efi_state.handles[..efi_state.handle_count]
                            .iter_mut()
                            .find(|e| e.handle == target_handle)
                            && let Some(pos) = entry.protocols[..entry.protocol_count]
                                .iter()
                                .position(|p| p.guid == prev_guid)
                        {
                            entry
                                .protocols
                                .copy_within(pos + 1..entry.protocol_count, pos);
                            entry.protocol_count -= 1;
                        }
                    });
                }
            }
            return status;
        }
    }

    log::trace!("  -> SUCCESS");
    Status::SUCCESS
}

extern "efiapi" fn uninstall_multiple_protocol_interfaces(
    handle: Handle,
    arg1: *mut c_void,
    arg2: *mut c_void,
    arg3: *mut c_void,
    arg4: *mut c_void,
    arg5: *mut c_void,
    arg6: *mut c_void,
    arg7: *mut c_void,
    arg8: *mut c_void,
) -> Status {
    log::debug!(
        "BS.UninstallMultipleProtocolInterfaces(handle={:?})",
        handle
    );

    if handle.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let args = [(arg1, arg2), (arg3, arg4), (arg5, arg6), (arg7, arg8)];

    // Uninstall each protocol
    for (guid_ptr, _) in args.iter().take_while(|(g, _)| !g.is_null()) {
        let guid = unsafe { *(*guid_ptr as *const Guid) };
        log::debug!("  Uninstalling protocol: {}", GuidFmt(guid));

        // Find and remove the protocol from the handle
        with_tables_mut(|efi_state| {
            if let Some(entry) = efi_state.handles[..efi_state.handle_count]
                .iter_mut()
                .find(|e| e.handle == handle)
                && let Some(j) = entry.protocols[..entry.protocol_count]
                    .iter()
                    .position(|p| p.guid == guid)
            {
                // Remove by shifting remaining protocols down
                entry.protocols.copy_within(j + 1..entry.protocol_count, j);
                entry.protocol_count -= 1;
            }
        });
    }

    log::trace!("  -> SUCCESS");
    Status::SUCCESS
}

extern "efiapi" fn calculate_crc32(data: *mut c_void, data_size: usize, crc32: *mut u32) -> Status {
    if data.is_null() || crc32.is_null() || data_size == 0 {
        return Status::INVALID_PARAMETER;
    }

    let slice = unsafe { core::slice::from_raw_parts(data as *const u8, data_size) };
    let result = crc32::calculate(slice);
    unsafe { *crc32 = result };
    Status::SUCCESS
}

extern "efiapi" fn copy_mem(destination: *mut c_void, source: *mut c_void, length: usize) {
    if destination.is_null() || source.is_null() {
        return;
    }

    unsafe {
        core::ptr::copy(source as *const u8, destination as *mut u8, length);
    }
}

extern "efiapi" fn set_mem(buffer: *mut c_void, size: usize, value: u8) {
    if buffer.is_null() {
        return;
    }

    unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, size).fill(value) };
}

/// Create a new handle and register it
pub fn create_handle() -> Option<Handle> {
    with_tables_mut(|efi_state| {
        if efi_state.handle_count >= MAX_HANDLES {
            return None;
        }

        let handle = efi_state.next_handle as *mut c_void;
        efi_state.next_handle += 1;

        let idx = efi_state.handle_count;
        efi_state.handles[idx].handle = handle;
        efi_state.handles[idx].protocol_count = 0;
        efi_state.handle_count += 1;

        Some(handle)
    })
}

/// Install a protocol on an existing handle
pub fn install_protocol(handle: Handle, guid: &Guid, interface: *mut c_void) -> Status {
    with_tables_mut(|efi_state| {
        if let Some(entry) = efi_state.handles[..efi_state.handle_count]
            .iter_mut()
            .find(|e| e.handle == handle)
        {
            // Check if protocol already installed
            if entry.protocols[..entry.protocol_count]
                .iter()
                .any(|p| p.guid == *guid)
            {
                return Status::INVALID_PARAMETER;
            }

            if entry.protocol_count >= MAX_PROTOCOLS_PER_HANDLE {
                return Status::OUT_OF_RESOURCES;
            }

            entry.protocols[entry.protocol_count] = ProtocolEntry {
                guid: *guid,
                interface,
            };
            entry.protocol_count += 1;
            return Status::SUCCESS;
        }

        Status::INVALID_PARAMETER
    })
}

/// Look up a protocol interface on a handle (internal helper).
///
/// Returns the interface pointer, or null if not found.
pub fn get_protocol_on_handle(handle: Handle, guid: &Guid) -> *mut c_void {
    let efi_state = tables();

    efi_state.handles[..efi_state.handle_count]
        .iter()
        .find(|e| e.handle == handle)
        .and_then(|e| {
            e.protocols[..e.protocol_count]
                .iter()
                .find(|p| p.guid == *guid)
        })
        .map_or(core::ptr::null_mut(), |p| p.interface)
}

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
use super::protocols::loaded_image::LOADED_IMAGE_PROTOCOL_GUID;
use super::tables::{
    HandleEntry, MAX_PROTOCOL_NOTIFIES, MAX_PROTOCOLS_PER_HANDLE, OpenProtocolEntry, ProtocolEntry,
    tables, with_tables_mut,
};
use crate::cell::StaticMut;
use alloc::vec::Vec;
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
    // r-efi's function-pointer aliases omit the variadic tail. These entry
    // points preserve the real UEFI ABI and parse protocol/interface pairs
    // through the terminating NULL protocol argument.
    install_multiple_protocol_interfaces: INSTALL_MULTIPLE_PROTOCOL_INTERFACES,
    uninstall_multiple_protocol_interfaces: UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES,
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
    agent_handle: Handle,
    controller_handle: Handle,
    attributes: u32,
) -> Status {
    if handle.is_null() || protocol.is_null() {
        return Status::INVALID_PARAMETER;
    }

    const DRIVER_EXCLUSIVE: u32 = efi::OPEN_PROTOCOL_BY_DRIVER | efi::OPEN_PROTOCOL_EXCLUSIVE;
    let base_attributes = attributes & !efi::OPEN_PROTOCOL_EXCLUSIVE;
    if !matches!(
        attributes,
        efi::OPEN_PROTOCOL_BY_HANDLE_PROTOCOL
            | efi::OPEN_PROTOCOL_GET_PROTOCOL
            | efi::OPEN_PROTOCOL_TEST_PROTOCOL
            | efi::OPEN_PROTOCOL_BY_CHILD_CONTROLLER
            | efi::OPEN_PROTOCOL_BY_DRIVER
            | efi::OPEN_PROTOCOL_EXCLUSIVE
            | DRIVER_EXCLUSIVE
    ) || ((matches!(
        base_attributes,
        efi::OPEN_PROTOCOL_BY_CHILD_CONTROLLER | efi::OPEN_PROTOCOL_BY_DRIVER
    ) || attributes & efi::OPEN_PROTOCOL_EXCLUSIVE != 0)
        && agent_handle.is_null())
        || (attributes != efi::OPEN_PROTOCOL_TEST_PROTOCOL && interface.is_null())
        || (matches!(
            base_attributes,
            efi::OPEN_PROTOCOL_BY_CHILD_CONTROLLER | efi::OPEN_PROTOCOL_BY_DRIVER
        ) && controller_handle.is_null())
        || (base_attributes == efi::OPEN_PROTOCOL_BY_CHILD_CONTROLLER
            && controller_handle == handle)
    {
        return Status::INVALID_PARAMETER;
    }

    let guid = unsafe { *protocol };
    log::debug!(
        "BS.OpenProtocol(handle={:?}, protocol={}, attr={:#x})",
        handle,
        GuidFmt(guid),
        attributes
    );

    let result = with_tables_mut(|efi_state| {
        let Some(handle_entry) = efi_state.handles[..efi_state.handle_count]
            .iter()
            .find(|entry| entry.handle == handle)
        else {
            return Err(Status::INVALID_PARAMETER);
        };
        let Some(protocol_entry) = handle_entry.protocols[..handle_entry.protocol_count]
            .iter()
            .find(|entry| entry.guid == guid)
        else {
            return Err(Status::UNSUPPORTED);
        };
        let protocol_interface = protocol_entry.interface;
        let exclusive = attributes & efi::OPEN_PROTOCOL_EXCLUSIVE != 0;

        // Ordinary opens with an agent are observable through OpenProtocolInformation
        // and CloseProtocol, but do not prevent interface teardown.
        if agent_handle.is_null() {
            return Ok(protocol_interface);
        }

        // A repeated driver open returns its existing interface without adding
        // another relationship, including BY_DRIVER | EXCLUSIVE.
        if attributes & efi::OPEN_PROTOCOL_BY_DRIVER != 0
            && efi_state.open_protocols.iter().any(|open| {
                open.handle == handle
                    && open.protocol == guid
                    && open.agent_handle == agent_handle
                    && open.controller_handle == controller_handle
                    && open.attributes == attributes
            })
        {
            unsafe { *interface = protocol_interface };
            return Err(Status::ALREADY_STARTED);
        }

        // There is no driver-disconnect implementation to evict an existing
        // owner. Reject rather than pretending to grant exclusive access.
        if (exclusive || base_attributes == efi::OPEN_PROTOCOL_BY_DRIVER)
            && efi_state.open_protocols.iter().any(|open| {
                open.handle == handle
                    && open.protocol == guid
                    && open.attributes
                        & (efi::OPEN_PROTOCOL_BY_DRIVER | efi::OPEN_PROTOCOL_EXCLUSIVE)
                        != 0
            })
        {
            return Err(Status::ACCESS_DENIED);
        }

        if let Some(open) = efi_state.open_protocols.iter_mut().find(|open| {
            open.handle == handle
                && open.protocol == guid
                && open.agent_handle == agent_handle
                && open.controller_handle == controller_handle
                && open.attributes == attributes
        }) {
            open.open_count = open.open_count.saturating_add(1);
        } else {
            if efi_state.open_protocols.try_reserve(1).is_err() {
                return Err(Status::OUT_OF_RESOURCES);
            }
            efi_state.open_protocols.push(OpenProtocolEntry {
                handle,
                protocol: guid,
                agent_handle,
                controller_handle,
                attributes,
                open_count: 1,
            });
        }

        Ok(protocol_interface)
    });

    let iface = match result {
        Ok(iface) => iface,
        Err(status) => return status,
    };
    if attributes != efi::OPEN_PROTOCOL_TEST_PROTOCOL && !interface.is_null() {
        unsafe { *interface = iface };
    }

    if guid == LOADED_IMAGE_PROTOCOL_GUID && !iface.is_null() {
        let lip = iface as *const r_efi::protocols::loaded_image::Protocol;
        log::trace!(
            "  -> LOADED_IMAGE(DeviceHandle={:?}, SystemTable={:?})",
            unsafe { (*lip).device_handle },
            unsafe { (*lip).system_table }
        );
    }

    Status::SUCCESS
}

extern "efiapi" fn close_protocol(
    handle: Handle,
    protocol: *mut Guid,
    agent_handle: Handle,
    controller_handle: Handle,
) -> Status {
    if handle.is_null() || protocol.is_null() || agent_handle.is_null() {
        return Status::INVALID_PARAMETER;
    }
    let guid = unsafe { *protocol };

    with_tables_mut(|efi_state| {
        let previous_len = efi_state.open_protocols.len();
        // CloseProtocol closes all matching records, regardless of OpenCount.
        efi_state.open_protocols.retain(|open| {
            !(open.handle == handle
                && open.protocol == guid
                && open.agent_handle == agent_handle
                && open.controller_handle == controller_handle)
        });
        if efi_state.open_protocols.len() == previous_len {
            Status::NOT_FOUND
        } else {
            Status::SUCCESS
        }
    })
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

    let guid = unsafe { *protocol };
    let record_count = with_tables_mut(|efi_state| {
        let protocol_exists = efi_state.handles[..efi_state.handle_count]
            .iter()
            .any(|entry| {
                entry.handle == handle
                    && entry.protocols[..entry.protocol_count]
                        .iter()
                        .any(|entry| entry.guid == guid)
            });
        protocol_exists.then(|| {
            efi_state
                .open_protocols
                .iter()
                .filter(|open| open.handle == handle && open.protocol == guid)
                .count()
        })
    });
    let Some(record_count) = record_count else {
        return Status::NOT_FOUND;
    };

    if record_count == 0 {
        unsafe {
            *entry_buffer = core::ptr::null_mut();
            *entry_count = 0;
        }
        return Status::SUCCESS;
    }

    let size = record_count * core::mem::size_of::<efi::OpenProtocolInformationEntry>();
    let buffer = match allocator::allocate_pool(MemoryType::BootServicesData, size) {
        Ok(buffer) => buffer as *mut efi::OpenProtocolInformationEntry,
        Err(status) => return status,
    };
    with_tables_mut(|efi_state| {
        for (index, open) in efi_state
            .open_protocols
            .iter()
            .filter(|open| open.handle == handle && open.protocol == guid)
            .enumerate()
        {
            unsafe {
                buffer.add(index).write(efi::OpenProtocolInformationEntry {
                    agent_handle: open.agent_handle,
                    controller_handle: open.controller_handle,
                    attributes: open.attributes,
                    open_count: open.open_count,
                });
            }
        }
    });
    unsafe {
        *entry_buffer = buffer;
        *entry_count = record_count;
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
    registration: *mut c_void,
    interface: *mut *mut c_void,
) -> Status {
    if protocol.is_null() || interface.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let guid = unsafe { *protocol };
    log::trace!("BS.LocateProtocol(protocol={})", GuidFmt(guid));

    if !registration.is_null() {
        return with_tables_mut(|efi_state| {
            let (index, _, entry) = match protocols_db::next_registered_protocol(
                efi_state,
                registration as usize,
                Some(guid),
            ) {
                Ok(next) => next,
                Err(status) => return status,
            };
            unsafe { *interface = entry.interface };
            efi_state.protocol_notifies[index].cursor = entry.generation;
            Status::SUCCESS
        });
    }

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

type InstallMultipleFn = extern "efiapi" fn(*mut Handle, *mut c_void, *mut c_void) -> Status;
type UninstallMultipleFn = extern "efiapi" fn(Handle, *mut c_void, *mut c_void) -> Status;

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(
    r#"
    .global crabefi_install_multiple_protocol_interfaces_entry
    .type crabefi_install_multiple_protocol_interfaces_entry,@function
crabefi_install_multiple_protocol_interfaces_entry:
    mov r10, rsp
    sub rsp, 40
    lea rax, [r10 + 40]
    mov [rsp + 32], rax
    call crabefi_install_multiple_protocol_interfaces_x64
    add rsp, 40
    ret

    .global crabefi_uninstall_multiple_protocol_interfaces_entry
    .type crabefi_uninstall_multiple_protocol_interfaces_entry,@function
crabefi_uninstall_multiple_protocol_interfaces_entry:
    mov r10, rsp
    sub rsp, 40
    lea rax, [r10 + 40]
    mov [rsp + 32], rax
    call crabefi_uninstall_multiple_protocol_interfaces_x64
    add rsp, 40
    ret
"#
);

#[cfg(target_arch = "x86_64")]
unsafe extern "efiapi" {
    fn crabefi_install_multiple_protocol_interfaces_entry(
        handle: *mut Handle,
        protocol: *mut c_void,
        interface: *mut c_void,
    ) -> Status;
    fn crabefi_uninstall_multiple_protocol_interfaces_entry(
        handle: Handle,
        protocol: *mut c_void,
        interface: *mut c_void,
    ) -> Status;
}

#[cfg(target_arch = "x86_64")]
const INSTALL_MULTIPLE_PROTOCOL_INTERFACES: InstallMultipleFn = unsafe {
    core::mem::transmute::<
        unsafe extern "efiapi" fn(*mut Handle, *mut c_void, *mut c_void) -> Status,
        InstallMultipleFn,
    >(crabefi_install_multiple_protocol_interfaces_entry)
};

#[cfg(target_arch = "x86_64")]
const UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES: UninstallMultipleFn = unsafe {
    core::mem::transmute::<
        unsafe extern "efiapi" fn(Handle, *mut c_void, *mut c_void) -> Status,
        UninstallMultipleFn,
    >(crabefi_uninstall_multiple_protocol_interfaces_entry)
};

#[cfg(not(target_arch = "x86_64"))]
const INSTALL_MULTIPLE_PROTOCOL_INTERFACES: InstallMultipleFn = unsafe {
    core::mem::transmute::<
        unsafe extern "C" fn(*mut Handle, *mut c_void, *mut c_void, ...) -> Status,
        InstallMultipleFn,
    >(install_multiple_protocol_interfaces_c)
};

#[cfg(not(target_arch = "x86_64"))]
const UNINSTALL_MULTIPLE_PROTOCOL_INTERFACES: UninstallMultipleFn = unsafe {
    core::mem::transmute::<
        unsafe extern "C" fn(Handle, *mut c_void, *mut c_void, ...) -> Status,
        UninstallMultipleFn,
    >(uninstall_multiple_protocol_interfaces_c)
};

const MAX_PROTOCOL_PAIRS: usize = 16;

fn collect_protocol_pair(
    pairs: &mut Vec<(Guid, *mut c_void)>,
    protocol: *mut c_void,
    interface: *mut c_void,
) -> Result<bool, Status> {
    if protocol.is_null() {
        return Ok(false);
    }
    if pairs.len() >= MAX_PROTOCOL_PAIRS {
        return Err(Status::INVALID_PARAMETER);
    }
    if pairs.try_reserve(1).is_err() {
        return Err(Status::OUT_OF_RESOURCES);
    }
    pairs.push((unsafe { *(protocol as *const Guid) }, interface));
    Ok(true)
}

fn install_multiple_pairs(handle: *mut Handle, pairs: &[(Guid, *mut c_void)]) -> Status {
    if handle.is_null() || pairs.is_empty() {
        return Status::INVALID_PARAMETER;
    }

    let created_handle = unsafe { (*handle).is_null() };
    let target_handle = if created_handle {
        let Some(new_handle) = create_handle() else {
            return Status::OUT_OF_RESOURCES;
        };
        unsafe { *handle = new_handle };
        new_handle
    } else {
        unsafe { *handle }
    };

    for (index, (guid, interface)) in pairs.iter().enumerate() {
        // No callbacks may observe a partial transaction or acquire opens that
        // prevent rollback. Publish notifications only after every pair succeeds.
        let status = install_protocol_internal(target_handle, guid, *interface, false);
        if status != Status::SUCCESS {
            let mut rollback_complete = true;
            for (installed_guid, installed_interface) in pairs[..index].iter().rev() {
                let rollback_status =
                    remove_protocol(target_handle, installed_guid, Some(*installed_interface));
                if rollback_status != Status::SUCCESS {
                    rollback_complete = false;
                    log::error!(
                        "InstallMultipleProtocolInterfaces rollback failed for {} on {:?}: {:?}",
                        GuidFmt(*installed_guid),
                        target_handle,
                        rollback_status
                    );
                }
            }
            if created_handle && rollback_complete && reclaim_empty_handle(target_handle) {
                unsafe { *handle = core::ptr::null_mut() };
            }
            return status;
        }
    }
    let events: heapless::Vec<efi::Event, MAX_PROTOCOL_NOTIFIES> = {
        let efi_state = tables();
        efi_state
            .protocol_notifies
            .iter()
            .filter(|notify| pairs.iter().any(|(guid, _)| *guid == notify.protocol))
            .map(|notify| notify.event)
            .collect()
    };
    for event in events {
        events::signal_event(event);
    }
    Status::SUCCESS
}

fn reclaim_empty_handle(handle: Handle) -> bool {
    with_tables_mut(|efi_state| {
        let Some(index) = efi_state.handles[..efi_state.handle_count]
            .iter()
            .position(|entry| entry.handle == handle)
        else {
            // Removing the final installed protocol already reclaimed it.
            return true;
        };
        if efi_state.handles[index].protocol_count != 0 {
            return false;
        }
        efi_state
            .handles
            .copy_within(index + 1..efi_state.handle_count, index);
        efi_state.handle_count -= 1;
        efi_state.handles[efi_state.handle_count] = HandleEntry::empty();
        true
    })
}

fn uninstall_multiple_pairs(handle: Handle, pairs: &[(Guid, *mut c_void)]) -> Status {
    if handle.is_null() || pairs.is_empty() {
        return Status::INVALID_PARAMETER;
    }
    for (index, pair) in pairs.iter().enumerate() {
        if pairs[..index].contains(pair) {
            return Status::INVALID_PARAMETER;
        }
    }

    let validation = tables();
    let Some(handle_entry) = validation.handles[..validation.handle_count]
        .iter()
        .find(|entry| entry.handle == handle)
    else {
        return Status::INVALID_PARAMETER;
    };
    for (guid, interface) in pairs {
        if !handle_entry.protocols[..handle_entry.protocol_count]
            .iter()
            .any(|entry| entry.guid == *guid && entry.interface == *interface)
        {
            return Status::NOT_FOUND;
        }
        if validation.open_protocols.iter().any(|open| {
            open.handle == handle
                && open.protocol == *guid
                && protocol_open_blocks_removal(open.attributes)
        }) {
            return Status::ACCESS_DENIED;
        }
    }

    // Mutation must not overlap the validation borrow of the handle database.
    drop(validation);
    for (guid, interface) in pairs {
        let status = remove_protocol(handle, guid, Some(*interface));
        if status != Status::SUCCESS {
            return status;
        }
    }
    Status::SUCCESS
}

#[cfg(target_arch = "x86_64")]
unsafe fn collect_x64_pairs(
    first_protocol: *mut c_void,
    first_interface: *mut c_void,
    second_protocol: *mut c_void,
    stack_arguments: *const *mut c_void,
) -> Result<Vec<(Guid, *mut c_void)>, Status> {
    let mut pairs = Vec::new();
    if !collect_protocol_pair(&mut pairs, first_protocol, first_interface)? {
        return Ok(pairs);
    }

    let mut protocol = second_protocol;
    let mut arguments = stack_arguments;
    while !protocol.is_null() {
        let interface = unsafe { *arguments };
        collect_protocol_pair(&mut pairs, protocol, interface)?;
        protocol = unsafe { *arguments.add(1) };
        arguments = unsafe { arguments.add(2) };
    }
    Ok(pairs)
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
extern "efiapi" fn crabefi_install_multiple_protocol_interfaces_x64(
    handle: *mut Handle,
    first_protocol: *mut c_void,
    first_interface: *mut c_void,
    second_protocol: *mut c_void,
    stack_arguments: *const *mut c_void,
) -> Status {
    let pairs = match unsafe {
        collect_x64_pairs(
            first_protocol,
            first_interface,
            second_protocol,
            stack_arguments,
        )
    } {
        Ok(pairs) => pairs,
        Err(status) => return status,
    };
    install_multiple_pairs(handle, &pairs)
}

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
extern "efiapi" fn crabefi_uninstall_multiple_protocol_interfaces_x64(
    handle: Handle,
    first_protocol: *mut c_void,
    first_interface: *mut c_void,
    second_protocol: *mut c_void,
    stack_arguments: *const *mut c_void,
) -> Status {
    let pairs = match unsafe {
        collect_x64_pairs(
            first_protocol,
            first_interface,
            second_protocol,
            stack_arguments,
        )
    } {
        Ok(pairs) => pairs,
        Err(status) => return status,
    };
    uninstall_multiple_pairs(handle, &pairs)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe extern "C" fn install_multiple_protocol_interfaces_c(
    handle: *mut Handle,
    first_protocol: *mut c_void,
    first_interface: *mut c_void,
    mut arguments: ...
) -> Status {
    let mut pairs = Vec::new();
    match collect_protocol_pair(&mut pairs, first_protocol, first_interface) {
        Ok(true) => {}
        Ok(false) => return Status::INVALID_PARAMETER,
        Err(status) => return status,
    }
    loop {
        let protocol: *mut c_void = unsafe { arguments.next_arg() };
        if protocol.is_null() {
            break;
        }
        let interface: *mut c_void = unsafe { arguments.next_arg() };
        if let Err(status) = collect_protocol_pair(&mut pairs, protocol, interface) {
            return status;
        }
    }
    install_multiple_pairs(handle, &pairs)
}

#[cfg(not(target_arch = "x86_64"))]
unsafe extern "C" fn uninstall_multiple_protocol_interfaces_c(
    handle: Handle,
    first_protocol: *mut c_void,
    first_interface: *mut c_void,
    mut arguments: ...
) -> Status {
    let mut pairs = Vec::new();
    match collect_protocol_pair(&mut pairs, first_protocol, first_interface) {
        Ok(true) => {}
        Ok(false) => return Status::INVALID_PARAMETER,
        Err(status) => return status,
    }
    loop {
        let protocol: *mut c_void = unsafe { arguments.next_arg() };
        if protocol.is_null() {
            break;
        }
        let interface: *mut c_void = unsafe { arguments.next_arg() };
        if let Err(status) = collect_protocol_pair(&mut pairs, protocol, interface) {
            return status;
        }
    }
    uninstall_multiple_pairs(handle, &pairs)
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
        if efi_state.handle_count == efi_state.handles.len()
            && efi_state.handles.try_reserve(1).is_err()
        {
            return None;
        }

        let handle = efi_state.next_handle as *mut c_void;
        efi_state.next_handle += 1;

        if efi_state.handle_count == efi_state.handles.len() {
            efi_state.handles.push(HandleEntry::empty());
        }
        let idx = efi_state.handle_count;
        efi_state.handles[idx].handle = handle;
        efi_state.handles[idx].protocol_count = 0;
        efi_state.handle_count += 1;

        Some(handle)
    })
}

/// Driver, child-controller and exclusive relationships require an explicit close.
pub(super) fn protocol_open_blocks_removal(attributes: u32) -> bool {
    attributes
        & (efi::OPEN_PROTOCOL_BY_DRIVER
            | efi::OPEN_PROTOCOL_BY_CHILD_CONTROLLER
            | efi::OPEN_PROTOCOL_EXCLUSIVE)
        != 0
}

/// Remove one protocol interface and reclaim an empty handle slot.
pub(super) fn remove_protocol(
    handle: Handle,
    guid: &Guid,
    interface: Option<*mut c_void>,
) -> Status {
    with_tables_mut(|efi_state| {
        if efi_state.open_protocols.iter().any(|open| {
            open.handle == handle
                && open.protocol == *guid
                && protocol_open_blocks_removal(open.attributes)
        }) {
            return Status::ACCESS_DENIED;
        }

        let Some(handle_index) = efi_state.handles[..efi_state.handle_count]
            .iter()
            .position(|entry| entry.handle == handle)
        else {
            return Status::NOT_FOUND;
        };
        let entry = &mut efi_state.handles[handle_index];
        let Some(protocol_index) =
            entry.protocols[..entry.protocol_count]
                .iter()
                .position(|entry| {
                    entry.guid == *guid && interface.is_none_or(|iface| entry.interface == iface)
                })
        else {
            return Status::NOT_FOUND;
        };

        efi_state
            .open_protocols
            .retain(|open| open.handle != handle || open.protocol != *guid);
        entry
            .protocols
            .copy_within(protocol_index + 1..entry.protocol_count, protocol_index);
        entry.protocol_count -= 1;
        entry.protocols[entry.protocol_count] = ProtocolEntry::empty();

        if entry.protocol_count == 0 {
            efi_state
                .handles
                .copy_within(handle_index + 1..efi_state.handle_count, handle_index);
            efi_state.handle_count -= 1;
            efi_state.handles[efi_state.handle_count] = HandleEntry::empty();
        }

        Status::SUCCESS
    })
}

/// Install a protocol on an existing handle
pub fn install_protocol(handle: Handle, guid: &Guid, interface: *mut c_void) -> Status {
    install_protocol_internal(handle, guid, interface, true)
}

/// Install an instance, optionally deferring notification until a transaction commits.
fn install_protocol_internal(
    handle: Handle,
    guid: &Guid,
    interface: *mut c_void,
    notify: bool,
) -> Status {
    let (status, notify_events) = with_tables_mut(|efi_state| {
        if let Some(entry) = efi_state.handles[..efi_state.handle_count]
            .iter_mut()
            .find(|e| e.handle == handle)
        {
            // Check if protocol already installed
            if entry.protocols[..entry.protocol_count]
                .iter()
                .any(|p| p.guid == *guid)
            {
                return (Status::INVALID_PARAMETER, heapless::Vec::new());
            }

            if entry.protocol_count >= MAX_PROTOCOLS_PER_HANDLE {
                return (Status::OUT_OF_RESOURCES, heapless::Vec::new());
            }

            let Some(generation) = efi_state.protocol_generation.checked_add(1) else {
                return (Status::OUT_OF_RESOURCES, heapless::Vec::new());
            };
            efi_state.protocol_generation = generation;
            entry.protocols[entry.protocol_count] = ProtocolEntry {
                guid: *guid,
                interface,
                generation,
            };
            entry.protocol_count += 1;
            let events = if notify {
                protocols_db::protocol_notification_events(efi_state, guid)
            } else {
                heapless::Vec::new()
            };
            return (Status::SUCCESS, events);
        }

        (Status::INVALID_PARAMETER, heapless::Vec::new())
    });

    // Signaled outside the state borrow: notify callbacks call back into Boot
    // Services, and a nested mutable borrow trips the state re-entrancy guard.
    for event in notify_events {
        events::signal_event(event);
    }

    status
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

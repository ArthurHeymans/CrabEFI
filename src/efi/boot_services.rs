//! EFI Boot Services
//!
//! This module implements the EFI Boot Services table, which provides
//! memory allocation, protocol handling, and image loading services.
//!
//! # State Management
//!
//! Boot Services state (handles, events, loaded images) is stored in the
//! centralized `FirmwareState` structure. Access it via `crate::state::efi_mut()`.

use super::allocator::{self, AllocateType, MemoryDescriptor, MemoryType};
use super::protocols::loaded_image::{create_loaded_image_protocol, LOADED_IMAGE_PROTOCOL_GUID};
use super::system_table;
use crate::pe;
use crate::state::{
    self, EventEntry, LoadedImageEntry, ProtocolEntry, MAX_EVENTS, MAX_HANDLES,
    MAX_PROTOCOLS_PER_HANDLE,
};
use core::ffi::c_void;
use r_efi::efi::{self, Boolean, Guid, Handle, Status, SystemTable, TableHeader, Tpl};
use r_efi::protocols::device_path::Protocol as DevicePathProtocol;

/// Boot Services signature "BOOTSERV"
const EFI_BOOT_SERVICES_SIGNATURE: u64 = 0x56524553544F4F42;

/// Boot Services revision (matches system table)
const EFI_BOOT_SERVICES_REVISION: u32 = (2 << 16) | 100;

/// Event types
pub const EVT_TIMER: u32 = 0x80000000;
pub const EVT_RUNTIME: u32 = 0x40000000;
pub const EVT_NOTIFY_WAIT: u32 = 0x00000100;
pub const EVT_NOTIFY_SIGNAL: u32 = 0x00000200;
pub const EVT_SIGNAL_EXIT_BOOT_SERVICES: u32 = 0x00000201;
pub const EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE: u32 = 0x60000202;

/// Special event ID for keyboard input
pub const KEYBOARD_EVENT_ID: usize = 1;

/// Static boot services table
static mut BOOT_SERVICES: efi::BootServices = efi::BootServices {
    hdr: TableHeader {
        signature: EFI_BOOT_SERVICES_SIGNATURE,
        revision: EFI_BOOT_SERVICES_REVISION,
        header_size: core::mem::size_of::<efi::BootServices>() as u32,
        crc32: 0,
        reserved: 0,
    },
    raise_tpl: raise_tpl,
    restore_tpl: restore_tpl,
    allocate_pages: allocate_pages,
    free_pages: free_pages,
    get_memory_map: get_memory_map,
    allocate_pool: allocate_pool,
    free_pool: free_pool,
    create_event: create_event,
    set_timer: set_timer,
    wait_for_event: wait_for_event,
    signal_event: signal_event,
    close_event: close_event,
    check_event: check_event,
    install_protocol_interface: install_protocol_interface,
    reinstall_protocol_interface: reinstall_protocol_interface,
    uninstall_protocol_interface: uninstall_protocol_interface,
    handle_protocol: handle_protocol,
    reserved: core::ptr::null_mut(),
    register_protocol_notify: register_protocol_notify,
    locate_handle: locate_handle,
    locate_device_path: locate_device_path,
    install_configuration_table: install_configuration_table,
    load_image: load_image,
    start_image: start_image,
    exit: exit,
    unload_image: unload_image,
    exit_boot_services: exit_boot_services,
    get_next_monotonic_count: get_next_monotonic_count,
    stall: stall,
    set_watchdog_timer: set_watchdog_timer,
    connect_controller: connect_controller,
    disconnect_controller: disconnect_controller,
    open_protocol: open_protocol,
    close_protocol: close_protocol,
    open_protocol_information: open_protocol_information,
    protocols_per_handle: protocols_per_handle,
    locate_handle_buffer: locate_handle_buffer,
    locate_protocol: locate_protocol,
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
    calculate_crc32: calculate_crc32,
    copy_mem: copy_mem,
    set_mem: set_mem,
    create_event_ex: create_event_ex,
};

/// Get a pointer to the boot services table
pub fn get_boot_services() -> *mut efi::BootServices {
    &raw mut BOOT_SERVICES
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
// Memory Allocation Functions
// ============================================================================

extern "efiapi" fn allocate_pages(
    alloc_type: efi::AllocateType,
    memory_type: efi::MemoryType,
    pages: usize,
    memory: *mut efi::PhysicalAddress,
) -> Status {
    log::debug!(
        "BS.AllocatePages(type={}, mem_type={}, pages={}, addr={:#x})",
        alloc_type,
        memory_type,
        pages,
        if memory.is_null() {
            0
        } else {
            unsafe { *memory }
        }
    );

    if memory.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let alloc_type = match alloc_type {
        0 => AllocateType::AllocateAnyPages,
        1 => AllocateType::AllocateMaxAddress,
        2 => AllocateType::AllocateAddress,
        _ => return Status::INVALID_PARAMETER,
    };

    let mem_type = match MemoryType::from_u32(memory_type) {
        Some(t) => t,
        None => return Status::INVALID_PARAMETER,
    };

    let mut addr = unsafe { *memory };
    let status = allocator::allocate_pages(alloc_type, mem_type, pages as u64, &mut addr);

    if status == Status::SUCCESS {
        unsafe { *memory = addr };
        log::debug!("  -> allocated at {:#x}", addr);
    } else {
        log::debug!("  -> failed: {:?}", status);
    }

    status
}

extern "efiapi" fn free_pages(memory: efi::PhysicalAddress, pages: usize) -> Status {
    allocator::free_pages(memory, pages as u64)
}

extern "efiapi" fn get_memory_map(
    memory_map_size: *mut usize,
    memory_map: *mut efi::MemoryDescriptor,
    map_key: *mut usize,
    descriptor_size: *mut usize,
    descriptor_version: *mut u32,
) -> Status {
    log::debug!(
        "BS.GetMemoryMap(buf_size={:?}, map={:?})",
        if memory_map_size.is_null() {
            0
        } else {
            unsafe { *memory_map_size }
        },
        memory_map
    );

    if memory_map_size.is_null()
        || map_key.is_null()
        || descriptor_size.is_null()
        || descriptor_version.is_null()
    {
        return Status::INVALID_PARAMETER;
    }

    let mut size = unsafe { *memory_map_size };
    let mut key = 0usize;
    let mut desc_size = 0usize;
    let mut desc_version = 0u32;

    // Convert memory_map pointer to a slice if not null
    let map_opt = if memory_map.is_null() {
        None
    } else {
        let num_entries = size / core::mem::size_of::<MemoryDescriptor>();
        Some(unsafe {
            core::slice::from_raw_parts_mut(memory_map as *mut MemoryDescriptor, num_entries)
        })
    };

    let status = allocator::get_memory_map(
        &mut size,
        map_opt,
        &mut key,
        &mut desc_size,
        &mut desc_version,
    );

    unsafe {
        *memory_map_size = size;
        *map_key = key;
        *descriptor_size = desc_size;
        *descriptor_version = desc_version;
    }

    log::debug!("  -> {:?} (size={}, key={:#x})", status, size, key);
    status
}

extern "efiapi" fn allocate_pool(
    pool_type: efi::MemoryType,
    size: usize,
    buffer: *mut *mut c_void,
) -> Status {
    log::trace!("BS.AllocatePool(type={}, size={})", pool_type, size);

    if buffer.is_null() || size == 0 {
        return Status::INVALID_PARAMETER;
    }

    let mem_type = match MemoryType::from_u32(pool_type) {
        Some(t) => t,
        None => return Status::INVALID_PARAMETER,
    };

    match allocator::allocate_pool(mem_type, size) {
        Ok(ptr) => {
            unsafe { *buffer = ptr as *mut c_void };
            Status::SUCCESS
        }
        Err(status) => status,
    }
}

extern "efiapi" fn free_pool(buffer: *mut c_void) -> Status {
    log::trace!("BS.FreePool({:?})", buffer);
    if buffer.is_null() {
        return Status::INVALID_PARAMETER;
    }

    allocator::free_pool(buffer as *mut u8)
}

// ============================================================================
// Event Functions (mostly unsupported)
// ============================================================================

extern "efiapi" fn create_event(
    event_type: u32,
    notify_tpl: Tpl,
    _notify_function: Option<efi::EventNotify>,
    _notify_context: *mut c_void,
    event: *mut efi::Event,
) -> Status {
    log::debug!(
        "BS.CreateEvent(type={:#x}, tpl={:?})",
        event_type,
        notify_tpl
    );

    if event.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Allocate an event ID from centralized state
    state::with_efi_mut(|efi_state| {
        let event_id = efi_state.next_event_id;

        if event_id >= MAX_EVENTS {
            log::error!("  -> OUT_OF_RESOURCES (no more event slots)");
            return Status::OUT_OF_RESOURCES;
        }

        efi_state.next_event_id += 1;

        // Store event info
        efi_state.events[event_id] = EventEntry {
            event_type,
            notify_tpl,
            signaled: false,
            is_keyboard_event: false,
        };

        // Return the event ID as the event handle
        unsafe {
            *event = event_id as *mut c_void;
        }

        log::debug!("  -> SUCCESS (event={:#x})", event_id);
        Status::SUCCESS
    })
}

extern "efiapi" fn set_timer(
    event: efi::Event,
    timer_type: efi::TimerDelay,
    trigger_time: u64,
) -> Status {
    log::debug!(
        "BS.SetTimer(event={:?}, type={}, time={})",
        event,
        timer_type,
        trigger_time
    );
    // Timer events are not fully implemented, but we accept the call
    // to allow bootloaders to proceed
    log::debug!("  -> SUCCESS (stubbed)");
    Status::SUCCESS
}

extern "efiapi" fn wait_for_event(
    number_of_events: usize,
    event: *mut efi::Event,
    index: *mut usize,
) -> Status {
    log::debug!("BS.WaitForEvent(count={})", number_of_events);

    if number_of_events == 0 || event.is_null() || index.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Get the list of events to wait on
    let events_to_wait = unsafe { core::slice::from_raw_parts(event, number_of_events) };

    // Check if any of the events is a keyboard event
    let has_keyboard_event = events_to_wait.iter().any(|e| {
        let event_id = *e as usize;
        event_id == KEYBOARD_EVENT_ID
    });

    // Poll for keyboard input
    // In a real implementation, we'd use proper async I/O
    // Here we poll the serial port for input
    loop {
        // Check each event
        for (i, &evt) in events_to_wait.iter().enumerate() {
            let event_id = evt as usize;

            // Check if it's the keyboard event and there's input
            if event_id == KEYBOARD_EVENT_ID || has_keyboard_event {
                // Check if serial port or PS/2 keyboard has data
                if crate::drivers::serial::has_input() || crate::drivers::keyboard::has_key() {
                    unsafe { *index = i };
                    log::debug!("  -> SUCCESS (keyboard input ready, index={})", i);
                    return Status::SUCCESS;
                }
            }

            // Check if a regular event is signaled
            if event_id > 0 && event_id < MAX_EVENTS {
                let efi_state = state::efi();
                if efi_state.events[event_id].signaled {
                    unsafe { *index = i };
                    log::debug!("  -> SUCCESS (event signaled, index={})", i);
                    return Status::SUCCESS;
                }
            }
        }

        // Small delay to avoid busy-waiting too aggressively
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
}

extern "efiapi" fn signal_event(event: efi::Event) -> Status {
    let event_id = event as usize;
    log::debug!("BS.SignalEvent(event={})", event_id);

    if event_id > 0 && event_id < MAX_EVENTS {
        state::with_efi_mut(|efi_state| {
            efi_state.events[event_id].signaled = true;
        });
    }

    Status::SUCCESS
}

extern "efiapi" fn close_event(event: efi::Event) -> Status {
    let event_id = event as usize;
    log::debug!("BS.CloseEvent(event={})", event_id);

    if event_id > 0 && event_id < MAX_EVENTS {
        state::with_efi_mut(|efi_state| {
            efi_state.events[event_id] = EventEntry::empty();
        });
    }

    Status::SUCCESS
}

extern "efiapi" fn check_event(event: efi::Event) -> Status {
    let event_id = event as usize;
    log::debug!("BS.CheckEvent(event={})", event_id);

    // Special case for keyboard event
    if event_id == KEYBOARD_EVENT_ID {
        // Check serial port or PS/2 keyboard for input
        if crate::drivers::serial::has_input() || crate::drivers::keyboard::has_key() {
            return Status::SUCCESS;
        } else {
            return Status::NOT_READY;
        }
    }

    // Check regular events
    if event_id > 0 && event_id < MAX_EVENTS {
        let efi_state = state::efi();
        if efi_state.events[event_id].signaled {
            return Status::SUCCESS;
        }
    }

    Status::NOT_READY
}

extern "efiapi" fn create_event_ex(
    event_type: u32,
    notify_tpl: Tpl,
    _notify_function: Option<efi::EventNotify>,
    _notify_context: *const c_void,
    _event_group: *const Guid,
    event: *mut efi::Event,
) -> Status {
    log::debug!(
        "BS.CreateEventEx(type={:#x}, tpl={:?})",
        event_type,
        notify_tpl
    );

    // Forward to create_event (ignoring event_group for now)
    create_event(event_type, notify_tpl, None, core::ptr::null_mut(), event)
}

// ============================================================================
// Protocol Handler Functions
// ============================================================================

extern "efiapi" fn install_protocol_interface(
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

    state::with_efi_mut(|efi_state| {
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
                .any(|p| guid_eq(&p.guid, &guid))
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

extern "efiapi" fn reinstall_protocol_interface(
    _handle: Handle,
    _protocol: *mut Guid,
    _old_interface: *mut c_void,
    _new_interface: *mut c_void,
) -> Status {
    Status::NOT_FOUND
}

extern "efiapi" fn uninstall_protocol_interface(
    _handle: Handle,
    _protocol: *mut Guid,
    _interface: *mut c_void,
) -> Status {
    Status::NOT_FOUND
}

extern "efiapi" fn handle_protocol(
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
    let status = open_protocol(
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

extern "efiapi" fn register_protocol_notify(
    _protocol: *mut Guid,
    _event: efi::Event,
    _registration: *mut *mut c_void,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn locate_handle(
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

    // Only ByProtocol search is supported
    if search_type != efi::BY_PROTOCOL {
        log::debug!("  -> UNSUPPORTED (only BY_PROTOCOL supported)");
        return Status::UNSUPPORTED;
    }

    if protocol.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let guid = unsafe { *protocol };
    let efi_state = state::efi();

    // Collect matching handles
    let matching: heapless::Vec<Handle, MAX_HANDLES> = efi_state.handles[..efi_state.handle_count]
        .iter()
        .filter(|entry| {
            entry.protocols[..entry.protocol_count]
                .iter()
                .any(|p| guid_eq(&p.guid, &guid))
        })
        .map(|entry| entry.handle)
        .collect();

    let required_size = matching.len() * core::mem::size_of::<Handle>();

    if buffer.is_null() || unsafe { *buffer_size } < required_size {
        unsafe { *buffer_size = required_size };
        return Status::BUFFER_TOO_SMALL;
    }

    // Copy handles to buffer
    for (i, h) in matching.iter().enumerate() {
        unsafe { *buffer.add(i) = *h };
    }
    unsafe { *buffer_size = required_size };

    if matching.is_empty() {
        log::info!("  -> NOT_FOUND");
        Status::NOT_FOUND
    } else {
        log::info!("  -> found {} handles: {:?}", matching.len(), &matching[..]);
        log::info!("  -> returning from LocateHandle");
        Status::SUCCESS
    }
}

extern "efiapi" fn locate_device_path(
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

    // Find all handles with the specified protocol
    let efi_state = state::efi();

    for i in 0..efi_state.handle_count {
        let mut has_protocol = false;
        let mut handle_dp: *mut DevicePathProtocol = core::ptr::null_mut();

        for j in 0..efi_state.handles[i].protocol_count {
            if guid_eq(&efi_state.handles[i].protocols[j].guid, &guid) {
                has_protocol = true;
            }
            // Also look for DEVICE_PATH protocol to get the device path
            if guid_eq(
                &efi_state.handles[i].protocols[j].guid,
                &r_efi::protocols::device_path::PROTOCOL_GUID,
            ) {
                handle_dp = efi_state.handles[i].protocols[j].interface as *mut DevicePathProtocol;
            }
        }

        if has_protocol && !handle_dp.is_null() {
            // For the initrd case, GRUB installs a handle with LOAD_FILE2 and a vendor media
            // device path. The kernel passes in that same device path to find it.

            log::debug!(
                "  -> SUCCESS (handle={:?}, device_path={:?})",
                efi_state.handles[i].handle,
                handle_dp
            );
            unsafe {
                *device = efi_state.handles[i].handle;
                // Update device_path to point to the End node of the handle's device path.
                // The LoadFile2 protocol expects the remaining path after the match.
                // Walk to the end of the device path and point to the End node.
                let mut dp = handle_dp;
                loop {
                    let dp_type = (*dp).r#type;
                    let dp_subtype = (*dp).sub_type;
                    // End of device path: type 0x7F, subtype 0xFF
                    if dp_type == 0x7f && dp_subtype == 0xff {
                        break;
                    }
                    // Get length and move to next node
                    let len = u16::from_le_bytes([(*dp).length[0], (*dp).length[1]]) as usize;
                    if len < 4 {
                        break; // Invalid length, stop
                    }
                    dp = (dp as *const u8).add(len) as *mut DevicePathProtocol;
                }
                *device_path = dp;
            }
            return Status::SUCCESS;
        }
    }

    log::debug!("  -> NOT_FOUND");
    Status::NOT_FOUND
}

extern "efiapi" fn install_configuration_table(guid: *mut Guid, table: *mut c_void) -> Status {
    if guid.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let guid_ref = unsafe { &*guid };
    system_table::install_configuration_table(guid_ref, table)
}

// ============================================================================
// Image Functions
// ============================================================================

extern "efiapi" fn load_image(
    boot_policy: Boolean,
    parent_image_handle: Handle,
    device_path: *mut DevicePathProtocol,
    source_buffer: *mut c_void,
    source_size: usize,
    image_handle: *mut Handle,
) -> Status {
    log::debug!(
        "BS.LoadImage(boot_policy={:?}, parent={:?}, device_path={:?}, buf={:?}, size={})",
        boot_policy,
        parent_image_handle,
        device_path,
        source_buffer,
        source_size
    );

    // Validate parameters
    if image_handle.is_null() {
        log::error!("BS.LoadImage: image_handle is NULL");
        return Status::INVALID_PARAMETER;
    }

    // We only support loading from a memory buffer currently
    if source_buffer.is_null() || source_size == 0 {
        log::error!("BS.LoadImage: source_buffer is NULL or size is 0");
        return Status::INVALID_PARAMETER;
    }

    // Create a slice from the source buffer
    let data = unsafe { core::slice::from_raw_parts(source_buffer as *const u8, source_size) };

    // Load the PE image using our PE loader
    let loaded_image = match pe::load_image(data) {
        Ok(img) => img,
        Err(status) => {
            log::error!("BS.LoadImage: Failed to load PE image: {:?}", status);
            return status;
        }
    };

    log::debug!(
        "BS.LoadImage: PE loaded at {:#x}, entry={:#x}, size={:#x}",
        loaded_image.image_base,
        loaded_image.entry_point,
        loaded_image.image_size
    );

    // Create a new handle for this image
    let new_handle = match create_handle() {
        Some(h) => h,
        None => {
            log::error!("BS.LoadImage: Failed to create handle");
            pe::unload_image(&loaded_image);
            return Status::OUT_OF_RESOURCES;
        }
    };

    // Create LoadedImageProtocol for this image
    // Get the parent's device handle if available
    let device_handle = get_device_handle_from_parent(parent_image_handle);

    let system_table = super::get_system_table();
    let loaded_image_protocol = create_loaded_image_protocol(
        parent_image_handle,
        system_table,
        device_handle,
        loaded_image.image_base,
        loaded_image.image_size,
    );

    if loaded_image_protocol.is_null() {
        log::error!("BS.LoadImage: Failed to create LoadedImageProtocol");
        pe::unload_image(&loaded_image);
        return Status::OUT_OF_RESOURCES;
    }

    // Set the device path on the loaded image if provided
    if !device_path.is_null() {
        unsafe {
            super::protocols::loaded_image::set_file_path(loaded_image_protocol, device_path);
        }
    }

    // Install the LoadedImageProtocol on the handle
    let status = install_protocol(
        new_handle,
        &LOADED_IMAGE_PROTOCOL_GUID,
        loaded_image_protocol as *mut c_void,
    );

    if status != Status::SUCCESS {
        log::error!(
            "BS.LoadImage: Failed to install LoadedImageProtocol: {:?}",
            status
        );
        pe::unload_image(&loaded_image);
        return status;
    }

    // Store the loaded image info so StartImage can find it
    let store_result = state::with_efi_mut(|efi_state| {
        let slot = efi_state
            .loaded_images
            .iter_mut()
            .find(|entry| entry.handle.is_null());

        match slot {
            Some(entry) => {
                entry.handle = new_handle;
                entry.image_base = loaded_image.image_base;
                entry.image_size = loaded_image.image_size;
                entry.entry_point = loaded_image.entry_point;
                entry.num_pages = loaded_image.num_pages;
                entry.parent_handle = parent_image_handle;
                true
            }
            None => false,
        }
    });

    if !store_result {
        log::error!("BS.LoadImage: No space in loaded images table");
        pe::unload_image(&loaded_image);
        return Status::OUT_OF_RESOURCES;
    }

    // Return the new handle
    unsafe {
        *image_handle = new_handle;
    }

    log::info!(
        "BS.LoadImage: SUCCESS - handle={:?}, base={:#x}, entry={:#x}",
        new_handle,
        loaded_image.image_base,
        loaded_image.entry_point
    );

    Status::SUCCESS
}

/// Get the device handle from a parent image's LoadedImageProtocol
fn get_device_handle_from_parent(parent_handle: Handle) -> Handle {
    if parent_handle.is_null() {
        return core::ptr::null_mut();
    }

    // Try to get the LoadedImageProtocol from the parent
    let efi_state = state::efi();
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

extern "efiapi" fn start_image(
    image_handle: Handle,
    exit_data_size: *mut usize,
    exit_data: *mut *mut u16,
) -> Status {
    log::debug!("BS.StartImage(handle={:?})", image_handle);

    if image_handle.is_null() {
        log::error!("BS.StartImage: image_handle is NULL");
        return Status::INVALID_PARAMETER;
    }

    // Find the loaded image entry
    let (entry_point, image_base) = {
        let efi_state = state::efi();
        match efi_state
            .loaded_images
            .iter()
            .find(|entry| entry.handle == image_handle)
            .map(|entry| (entry.entry_point, entry.image_base))
        {
            Some(info) => info,
            None => {
                log::error!(
                    "BS.StartImage: handle {:?} not found in loaded images",
                    image_handle
                );
                return Status::INVALID_PARAMETER;
            }
        }
    };

    log::info!(
        "BS.StartImage: Executing image at {:#x} (base={:#x})",
        entry_point,
        image_base
    );

    // Get the system table
    let system_table = super::get_system_table();

    // Define the entry point function type
    type EfiEntryPoint = extern "efiapi" fn(Handle, *mut SystemTable) -> Status;

    // Call the entry point
    let entry: EfiEntryPoint = unsafe { core::mem::transmute(entry_point) };
    let status = entry(image_handle, system_table);

    log::info!("BS.StartImage: Image returned with status: {:?}", status);

    // Set exit data if provided (we don't support exit data currently)
    if !exit_data_size.is_null() {
        unsafe {
            *exit_data_size = 0;
        }
    }
    if !exit_data.is_null() {
        unsafe {
            *exit_data = core::ptr::null_mut();
        }
    }

    status
}

extern "efiapi" fn exit(
    image_handle: Handle,
    exit_status: Status,
    exit_data_size: usize,
    _exit_data: *mut u16,
) -> Status {
    log::info!(
        "BS.Exit(handle={:?}, status={:?}, data_size={})",
        image_handle,
        exit_status,
        exit_data_size
    );
    // Note: A proper Exit implementation would use longjmp to return
    // from the corresponding StartImage call. For now, we just return
    // the status - this works for simple cases but won't properly unwind
    // nested image calls.
    exit_status
}

extern "efiapi" fn unload_image(image_handle: Handle) -> Status {
    log::debug!("BS.UnloadImage(handle={:?})", image_handle);

    if image_handle.is_null() {
        log::error!("BS.UnloadImage: image_handle is NULL");
        return Status::INVALID_PARAMETER;
    }

    // Find and remove the loaded image entry
    let image_info = state::with_efi_mut(|efi_state| {
        efi_state
            .loaded_images
            .iter_mut()
            .find(|entry| entry.handle == image_handle)
            .map(|entry| {
                let result = (entry.image_base, entry.num_pages);
                // Clear the entry
                *entry = LoadedImageEntry::empty();
                result
            })
    });

    match image_info {
        Some((image_base, num_pages)) => {
            // Free the image memory
            let status = allocator::free_pages(image_base, num_pages);
            if status != Status::SUCCESS {
                log::warn!(
                    "BS.UnloadImage: Failed to free pages at {:#x}: {:?}",
                    image_base,
                    status
                );
            }

            // Remove protocols from the handle
            // Note: In a full implementation, we should uninstall all protocols
            // For now, we just log success
            log::debug!("BS.UnloadImage: SUCCESS");
            Status::SUCCESS
        }
        None => {
            log::warn!(
                "BS.UnloadImage: handle {:?} not found in loaded images",
                image_handle
            );
            // Return success anyway - the handle might have been loaded differently
            Status::SUCCESS
        }
    }
}

extern "efiapi" fn exit_boot_services(image_handle: Handle, map_key: usize) -> Status {
    log::info!(
        "BS.ExitBootServices(handle={:?}, map_key={:#x})",
        image_handle,
        map_key
    );

    let status = allocator::exit_boot_services(map_key);

    if status == Status::SUCCESS {
        log::info!("ExitBootServices SUCCESS - transitioning to OS");

        // Clean up hardware state for OS handoff
        // Re-enable keyboard interrupts so Linux's i8042 driver works
        crate::drivers::keyboard::cleanup();

        // Stop and reset USB controllers so Linux can reinitialize them
        crate::drivers::usb::cleanup();

        // CRITICAL: Set boot_services pointer to NULL in SystemTable
        // This is REQUIRED by UEFI spec and Linux checks for this!
        unsafe {
            system_table::clear_boot_services();
        }
    } else {
        log::warn!("ExitBootServices FAILED: {:?}", status);
    }

    status
}

// ============================================================================
// Miscellaneous Functions
// ============================================================================

extern "efiapi" fn get_next_monotonic_count(_count: *mut u64) -> Status {
    Status::DEVICE_ERROR
}

extern "efiapi" fn stall(microseconds: usize) -> Status {
    log::debug!("BS.Stall({}us)", microseconds);
    // Busy-wait using CPU cycles
    // This is a rough approximation - real implementation would use TSC or HPET
    for _ in 0..microseconds {
        for _ in 0..1000 {
            core::hint::spin_loop();
        }
    }
    Status::SUCCESS
}

extern "efiapi" fn set_watchdog_timer(
    _timeout: usize,
    _watchdog_code: u64,
    _data_size: usize,
    _watchdog_data: *mut u16,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn connect_controller(
    _controller_handle: Handle,
    _driver_image_handle: *mut Handle,
    _remaining_device_path: *mut DevicePathProtocol,
    _recursive: Boolean,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn disconnect_controller(
    _controller_handle: Handle,
    _driver_image_handle: Handle,
    _child_handle: Handle,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn open_protocol(
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
    let guid_name = format_guid(&guid);
    log::debug!(
        "BS.OpenProtocol(handle={:?}, protocol={}, attr={:#x})",
        handle,
        GuidFmt(guid),
        attributes
    );

    let efi_state = state::efi();

    for i in 0..efi_state.handle_count {
        if efi_state.handles[i].handle == handle {
            for j in 0..efi_state.handles[i].protocol_count {
                if guid_eq(&efi_state.handles[i].protocols[j].guid, &guid) {
                    let iface = efi_state.handles[i].protocols[j].interface;
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
                    return Status::SUCCESS;
                }
            }
            log::warn!("  -> UNSUPPORTED (protocol not on handle)");
            return Status::UNSUPPORTED; // Handle exists but protocol not found
        }
    }

    log::warn!("  -> INVALID_PARAMETER (handle not found)");
    Status::INVALID_PARAMETER // Handle not found
}

extern "efiapi" fn close_protocol(
    _handle: Handle,
    _protocol: *mut Guid,
    _agent_handle: Handle,
    _controller_handle: Handle,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn open_protocol_information(
    _handle: Handle,
    _protocol: *mut Guid,
    _entry_buffer: *mut *mut efi::OpenProtocolInformationEntry,
    _entry_count: *mut usize,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn protocols_per_handle(
    _handle: Handle,
    _protocol_buffer: *mut *mut *mut Guid,
    _protocol_buffer_count: *mut usize,
) -> Status {
    Status::UNSUPPORTED
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
    let status = locate_handle(
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
    let status = locate_handle(
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

    let efi_state = state::efi();

    // Find first handle with this protocol
    let found = efi_state.handles[..efi_state.handle_count]
        .iter()
        .flat_map(|entry| entry.protocols[..entry.protocol_count].iter())
        .find(|proto| guid_eq(&proto.guid, &guid));

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

    // Install each protocol
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
            // On failure, we should uninstall previously installed protocols
            // For simplicity, we just return the error
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
        state::with_efi_mut(|efi_state| {
            if let Some(entry) = efi_state.handles[..efi_state.handle_count]
                .iter_mut()
                .find(|e| e.handle == handle)
            {
                if let Some(j) = entry.protocols[..entry.protocol_count]
                    .iter()
                    .position(|p| guid_eq(&p.guid, &guid))
                {
                    // Remove by shifting remaining protocols down
                    entry.protocols.copy_within(j + 1..entry.protocol_count, j);
                    entry.protocol_count -= 1;
                }
            }
        });
    }

    log::trace!("  -> SUCCESS");
    Status::SUCCESS
}

extern "efiapi" fn calculate_crc32(
    _data: *mut c_void,
    _data_size: usize,
    _crc32: *mut u32,
) -> Status {
    Status::UNSUPPORTED
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

    unsafe {
        core::ptr::write_bytes(buffer as *mut u8, value, size);
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

// Use common guid_eq from utils module
use super::utils::guid_eq;

/// Wrapper for GUID that displays name if known, raw GUID if unknown
pub struct GuidFmt(pub Guid);

impl core::fmt::Display for GuidFmt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = format_guid(&self.0);
        if name != "UNKNOWN" {
            write!(f, "{}", name)
        } else {
            // Format as standard GUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            let bytes =
                unsafe { core::slice::from_raw_parts(&self.0 as *const Guid as *const u8, 16) };
            write!(
                f,
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                bytes[3],
                bytes[2],
                bytes[1],
                bytes[0], // Data1 (LE)
                bytes[5],
                bytes[4], // Data2 (LE)
                bytes[7],
                bytes[6], // Data3 (LE)
                bytes[8],
                bytes[9], // Data4[0-1]
                bytes[10],
                bytes[11],
                bytes[12],
                bytes[13],
                bytes[14],
                bytes[15]
            )
        }
    }
}

/// Format a GUID for logging with well-known names
fn format_guid(guid: &Guid) -> &'static str {
    // Well-known GUID lookup table
    const GUID_NAMES: &[(Guid, &str)] = &[
        (
            Guid::from_fields(
                0x5B1B31A1,
                0x9562,
                0x11d2,
                0x8E,
                0x3F,
                &[0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
            ),
            "LOADED_IMAGE",
        ),
        (
            Guid::from_fields(
                0x09576e91,
                0x6d3f,
                0x11d2,
                0x8e,
                0x39,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "DEVICE_PATH",
        ),
        (
            Guid::from_fields(
                0x0964e5b22,
                0x6459,
                0x11d2,
                0x8e,
                0x39,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "SIMPLE_FILE_SYSTEM",
        ),
        (
            Guid::from_fields(
                0x9042a9de,
                0x23dc,
                0x4a38,
                0x96,
                0xfb,
                &[0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
            ),
            "GRAPHICS_OUTPUT (GOP)",
        ),
        (
            Guid::from_fields(
                0x387477c1,
                0x69c7,
                0x11d2,
                0x8e,
                0x39,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "SIMPLE_TEXT_INPUT",
        ),
        (
            Guid::from_fields(
                0x387477c2,
                0x69c7,
                0x11d2,
                0x8e,
                0x39,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "SIMPLE_TEXT_OUTPUT",
        ),
        (
            Guid::from_fields(
                0x964e5b21,
                0x6459,
                0x11d2,
                0x8e,
                0x39,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "BLOCK_IO",
        ),
        (
            Guid::from_fields(
                0xCE345171,
                0xBA0B,
                0x11d2,
                0x8e,
                0x4F,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "DISK_IO",
        ),
        (
            Guid::from_fields(
                0xeb9d2d30,
                0x2d88,
                0x11d3,
                0x9a,
                0x16,
                &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
            ),
            "ACPI_TABLE",
        ),
        (
            Guid::from_fields(
                0xeb9d2d31,
                0x2d88,
                0x11d3,
                0x9a,
                0x16,
                &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
            ),
            "SMBIOS_TABLE",
        ),
        (
            Guid::from_fields(
                0x56EC3091,
                0x954C,
                0x11d2,
                0x8e,
                0x3f,
                &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
            ),
            "LOAD_FILE",
        ),
        (
            Guid::from_fields(
                0x4006c0c1,
                0xfcb3,
                0x403e,
                0x99,
                0x6d,
                &[0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d],
            ),
            "LOAD_FILE2",
        ),
        (
            Guid::from_fields(
                0xBB25CF6F,
                0xF1D4,
                0x11D2,
                0x9a,
                0x0c,
                &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0xfd],
            ),
            "SERIAL_IO",
        ),
        (
            Guid::from_fields(
                0x03C4E603,
                0xAC28,
                0x11d3,
                0x9a,
                0x2d,
                &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
            ),
            "PXE_BASE_CODE",
        ),
        (
            Guid::from_fields(
                0xef9fc172,
                0xa1b2,
                0x4693,
                0xb3,
                0x27,
                &[0x6d, 0x32, 0xfc, 0x41, 0x60, 0x42],
            ),
            "HII_DATABASE",
        ),
        (
            Guid::from_fields(
                0x587e72d7,
                0xcc50,
                0x4f79,
                0x82,
                0x09,
                &[0xca, 0x29, 0x1f, 0xc1, 0xa1, 0x0f],
            ),
            "HII_CONFIG_ROUTING",
        ),
        (
            Guid::from_fields(
                0x1C0C34F6,
                0xD380,
                0x41FA,
                0xA0,
                0x49,
                &[0x8a, 0xd0, 0x6c, 0x1a, 0x66, 0xaa],
            ),
            "EDID_DISCOVERED",
        ),
        (
            Guid::from_fields(
                0xBD8C1056,
                0x9F36,
                0x44EC,
                0x92,
                0xA8,
                &[0xa6, 0x33, 0x7f, 0x81, 0x79, 0x86],
            ),
            "EDID_ACTIVE",
        ),
        (
            Guid::from_fields(
                0x1d85cd7f,
                0xf43d,
                0x11d2,
                0x9a,
                0x0c,
                &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
            ),
            "UNICODE_COLLATION",
        ),
        (
            Guid::from_fields(
                0x605dab50,
                0xe046,
                0x4300,
                0xab,
                0xb6,
                &[0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23],
            ),
            "SHIM_LOCK",
        ),
        (
            Guid::from_fields(
                0x752f3136,
                0x4e16,
                0x4fdc,
                0xa2,
                0x2a,
                &[0xe5, 0xf4, 0x68, 0x12, 0xf4, 0xca],
            ),
            "SHELL_PARAMETERS",
        ),
        (
            Guid::from_fields(
                0x5568e427,
                0x68fc,
                0x4f3d,
                0xac,
                0x74,
                &[0xca, 0x55, 0x52, 0x31, 0xcc, 0x68],
            ),
            "LINUX_INITRD_MEDIA",
        ),
        (
            Guid::from_fields(
                0xf42f7782,
                0x012e,
                0x4c12,
                0x99,
                0x56,
                &[0x49, 0xf9, 0x43, 0x04, 0xf7, 0x21],
            ),
            "CONSOLE_CONTROL",
        ),
        (
            Guid::from_fields(
                0xf4560cf6,
                0x40ec,
                0x4b4a,
                0xa1,
                0x92,
                &[0xbf, 0x1d, 0x57, 0xd0, 0xb1, 0x89],
            ),
            "MEMORY_ATTRIBUTE",
        ),
        (
            Guid::from_fields(
                0xf541796d,
                0xa62e,
                0x4954,
                0xa7,
                0x75,
                &[0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd],
            ),
            "TCG (TPM 1.2)",
        ),
        (
            Guid::from_fields(
                0x607f766c,
                0x7455,
                0x42be,
                0x93,
                0x0b,
                &[0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f],
            ),
            "TCG2 (TPM 2.0)",
        ),
        (
            Guid::from_fields(
                0x96751a3d,
                0x72f4,
                0x41a6,
                0xa7,
                0x94,
                &[0xed, 0x5d, 0x0e, 0x67, 0xae, 0x6b],
            ),
            "CC_MEASUREMENT",
        ),
        (
            Guid::from_fields(
                0xdd9e7534,
                0x7762,
                0x4698,
                0x8c,
                0x14,
                &[0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa],
            ),
            "SIMPLE_TEXT_INPUT_EX",
        ),
    ];

    GUID_NAMES
        .iter()
        .find(|(g, _)| guid_eq(guid, g))
        .map(|(_, name)| *name)
        .unwrap_or("UNKNOWN")
}

/// Create a new handle and register it
pub fn create_handle() -> Option<Handle> {
    state::with_efi_mut(|efi_state| {
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
    state::with_efi_mut(|efi_state| {
        if let Some(entry) = efi_state.handles[..efi_state.handle_count]
            .iter_mut()
            .find(|e| e.handle == handle)
        {
            // Check if protocol already installed
            if entry.protocols[..entry.protocol_count]
                .iter()
                .any(|p| guid_eq(&p.guid, guid))
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

//! EFI Boot Services
//!
//! This module implements the EFI Boot Services table, which provides
//! memory allocation, protocol handling, and image loading services.

use super::allocator::{self, AllocateType, MemoryDescriptor, MemoryType};
use super::system_table;
use core::ffi::c_void;
use r_efi::efi::{self, Boolean, Guid, Handle, Status, TableHeader, Tpl};
use r_efi::protocols::device_path::Protocol as DevicePathProtocol;
use spin::Mutex;

/// Boot Services signature "BOOTSERV"
const EFI_BOOT_SERVICES_SIGNATURE: u64 = 0x56524553544F4F42;

/// Boot Services revision (matches system table)
const EFI_BOOT_SERVICES_REVISION: u32 = (2 << 16) | 100;

/// Maximum number of handles we can track
const MAX_HANDLES: usize = 64;

/// Maximum number of protocols per handle
const MAX_PROTOCOLS_PER_HANDLE: usize = 8;

/// Maximum number of events we can track
const MAX_EVENTS: usize = 32;

/// Event types
pub const EVT_TIMER: u32 = 0x80000000;
pub const EVT_RUNTIME: u32 = 0x40000000;
pub const EVT_NOTIFY_WAIT: u32 = 0x00000100;
pub const EVT_NOTIFY_SIGNAL: u32 = 0x00000200;
pub const EVT_SIGNAL_EXIT_BOOT_SERVICES: u32 = 0x00000201;
pub const EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE: u32 = 0x60000202;

/// Special event ID for keyboard input
pub const KEYBOARD_EVENT_ID: usize = 1;

/// Protocol interface entry
#[derive(Clone, Copy)]
struct ProtocolEntry {
    guid: Guid,
    interface: *mut c_void,
}

// Safety: ProtocolEntry contains raw pointers but we only access them
// while holding the HANDLES lock, ensuring thread safety.
unsafe impl Send for ProtocolEntry {}

impl ProtocolEntry {
    const fn empty() -> Self {
        Self {
            guid: Guid::from_fields(0, 0, 0, 0, 0, &[0, 0, 0, 0, 0, 0]),
            interface: core::ptr::null_mut(),
        }
    }
}

/// Handle entry
struct HandleEntry {
    handle: Handle,
    protocols: [ProtocolEntry; MAX_PROTOCOLS_PER_HANDLE],
    protocol_count: usize,
}

// Safety: HandleEntry contains raw pointers but we only access them
// while holding the HANDLES lock, ensuring thread safety.
unsafe impl Send for HandleEntry {}

impl HandleEntry {
    const fn empty() -> Self {
        Self {
            handle: core::ptr::null_mut(),
            protocols: [ProtocolEntry::empty(); MAX_PROTOCOLS_PER_HANDLE],
            protocol_count: 0,
        }
    }
}

/// Event entry for tracking created events
#[derive(Clone, Copy)]
struct EventEntry {
    event_type: u32,
    notify_tpl: Tpl,
    signaled: bool,
    is_keyboard_event: bool,
}

impl EventEntry {
    const fn empty() -> Self {
        Self {
            event_type: 0,
            notify_tpl: 0,
            signaled: false,
            is_keyboard_event: false,
        }
    }
}

/// Handle database
static HANDLES: Mutex<[HandleEntry; MAX_HANDLES]> =
    Mutex::new([const { HandleEntry::empty() }; MAX_HANDLES]);
static HANDLE_COUNT: Mutex<usize> = Mutex::new(0);

/// Next handle value (used as a unique identifier)
static NEXT_HANDLE: Mutex<usize> = Mutex::new(1);

/// Event database
static EVENTS: Mutex<[EventEntry; MAX_EVENTS]> =
    Mutex::new([const { EventEntry::empty() }; MAX_EVENTS]);
static NEXT_EVENT_ID: Mutex<usize> = Mutex::new(2); // Start at 2, reserve 1 for keyboard

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
    install_multiple_protocol_interfaces: install_multiple_protocol_interfaces,
    uninstall_multiple_protocol_interfaces: uninstall_multiple_protocol_interfaces,
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
    log::trace!("BS.RaiseTpl({:?})", new_tpl);
    // No interrupt handling, return current TPL (APPLICATION)
    efi::TPL_APPLICATION
}

extern "efiapi" fn restore_tpl(old_tpl: Tpl) {
    log::trace!("BS.RestoreTpl({:?})", old_tpl);
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
        "BS.AllocatePages(type={}, mem_type={}, pages={})",
        alloc_type,
        memory_type,
        pages
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
        "BS.GetMemoryMap(buf_size={:?})",
        if memory_map_size.is_null() {
            0
        } else {
            unsafe { *memory_map_size }
        }
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

    // Allocate an event ID
    let mut next_id = NEXT_EVENT_ID.lock();
    let event_id = *next_id;

    if event_id >= MAX_EVENTS {
        log::error!("  -> OUT_OF_RESOURCES (no more event slots)");
        return Status::OUT_OF_RESOURCES;
    }

    *next_id += 1;
    drop(next_id);

    // Store event info
    let mut events = EVENTS.lock();
    events[event_id] = EventEntry {
        event_type,
        notify_tpl,
        signaled: false,
        is_keyboard_event: false,
    };
    drop(events);

    // Return the event ID as the event handle
    unsafe {
        *event = event_id as *mut c_void;
    }

    log::debug!("  -> SUCCESS (event={:#x})", event_id);
    Status::SUCCESS
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
                // Check if serial port has data
                if crate::drivers::serial::has_input() {
                    unsafe { *index = i };
                    log::debug!("  -> SUCCESS (keyboard input ready, index={})", i);
                    return Status::SUCCESS;
                }
            }

            // Check if a regular event is signaled
            if event_id > 0 && event_id < MAX_EVENTS {
                let events = EVENTS.lock();
                if events[event_id].signaled {
                    drop(events);
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
    log::trace!("BS.SignalEvent(event={})", event_id);

    if event_id > 0 && event_id < MAX_EVENTS {
        let mut events = EVENTS.lock();
        events[event_id].signaled = true;
    }

    Status::SUCCESS
}

extern "efiapi" fn close_event(event: efi::Event) -> Status {
    let event_id = event as usize;
    log::trace!("BS.CloseEvent(event={})", event_id);

    if event_id > 0 && event_id < MAX_EVENTS {
        let mut events = EVENTS.lock();
        events[event_id] = EventEntry::empty();
    }

    Status::SUCCESS
}

extern "efiapi" fn check_event(event: efi::Event) -> Status {
    let event_id = event as usize;
    log::trace!("BS.CheckEvent(event={})", event_id);

    // Special case for keyboard event
    if event_id == KEYBOARD_EVENT_ID {
        if crate::drivers::serial::has_input() {
            return Status::SUCCESS;
        } else {
            return Status::NOT_READY;
        }
    }

    // Check regular events
    if event_id > 0 && event_id < MAX_EVENTS {
        let events = EVENTS.lock();
        if events[event_id].signaled {
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

    let mut handles = HANDLES.lock();
    let mut count = HANDLE_COUNT.lock();

    // If handle is null, create a new handle
    if handle_ptr.is_null() {
        if *count >= MAX_HANDLES {
            return Status::OUT_OF_RESOURCES;
        }

        let mut next = NEXT_HANDLE.lock();
        let new_handle = *next as *mut c_void;
        *next += 1;

        handles[*count].handle = new_handle;
        handles[*count].protocols[0] = ProtocolEntry { guid, interface };
        handles[*count].protocol_count = 1;
        *count += 1;

        unsafe { *handle = new_handle };
        return Status::SUCCESS;
    }

    // Find existing handle
    for i in 0..*count {
        if handles[i].handle == handle_ptr {
            // Check if protocol already installed
            for j in 0..handles[i].protocol_count {
                if guid_eq(&handles[i].protocols[j].guid, &guid) {
                    return Status::INVALID_PARAMETER; // Protocol already installed
                }
            }

            // Add new protocol
            if handles[i].protocol_count >= MAX_PROTOCOLS_PER_HANDLE {
                return Status::OUT_OF_RESOURCES;
            }

            let idx = handles[i].protocol_count;
            handles[i].protocols[idx] = ProtocolEntry { guid, interface };
            handles[i].protocol_count += 1;
            return Status::SUCCESS;
        }
    }

    Status::INVALID_PARAMETER
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
        format_guid(&guid)
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

    let guid_name = if protocol.is_null() {
        "NULL"
    } else {
        format_guid(unsafe { &*protocol })
    };
    log::debug!(
        "BS.LocateHandle(type={}, protocol={})",
        search_type,
        guid_name
    );

    // Log raw GUID if unknown
    if !protocol.is_null() && guid_name == "UNKNOWN" {
        log_guid(unsafe { &*protocol });
    }

    // Only ByProtocol search is supported
    if search_type != efi::BY_PROTOCOL {
        log::debug!("  -> UNSUPPORTED (only BY_PROTOCOL supported)");
        return Status::UNSUPPORTED;
    }

    if protocol.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let guid = unsafe { *protocol };
    let handles = HANDLES.lock();
    let count = HANDLE_COUNT.lock();

    // Count matching handles
    let mut matching: heapless::Vec<Handle, MAX_HANDLES> = heapless::Vec::new();
    for i in 0..*count {
        for j in 0..handles[i].protocol_count {
            if guid_eq(&handles[i].protocols[j].guid, &guid) {
                let _ = matching.push(handles[i].handle);
                break;
            }
        }
    }

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
        log::debug!("  -> NOT_FOUND");
        Status::NOT_FOUND
    } else {
        log::debug!("  -> found {} handles", matching.len());
        Status::SUCCESS
    }
}

extern "efiapi" fn locate_device_path(
    _protocol: *mut Guid,
    _device_path: *mut *mut DevicePathProtocol,
    _device: *mut Handle,
) -> Status {
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
    _device_path: *mut DevicePathProtocol,
    source_buffer: *mut c_void,
    source_size: usize,
    _image_handle: *mut Handle,
) -> Status {
    log::debug!(
        "BS.LoadImage(boot_policy={:?}, parent={:?}, buf={:?}, size={}) -> UNSUPPORTED",
        boot_policy,
        parent_image_handle,
        source_buffer,
        source_size
    );
    Status::UNSUPPORTED
}

extern "efiapi" fn start_image(
    image_handle: Handle,
    _exit_data_size: *mut usize,
    _exit_data: *mut *mut u16,
) -> Status {
    log::debug!("BS.StartImage(handle={:?}) -> UNSUPPORTED", image_handle);
    Status::UNSUPPORTED
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
    Status::UNSUPPORTED
}

extern "efiapi" fn unload_image(image_handle: Handle) -> Status {
    log::debug!("BS.UnloadImage(handle={:?}) -> UNSUPPORTED", image_handle);
    Status::UNSUPPORTED
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
        guid_name,
        attributes
    );

    // Log raw GUID if unknown
    if guid_name == "UNKNOWN" {
        log_guid(&guid);
    }

    let handles = HANDLES.lock();
    let count = HANDLE_COUNT.lock();

    for i in 0..*count {
        if handles[i].handle == handle {
            for j in 0..handles[i].protocol_count {
                if guid_eq(&handles[i].protocols[j].guid, &guid) {
                    let iface = handles[i].protocols[j].interface;
                    if !interface.is_null() {
                        unsafe { *interface = iface };
                    }
                    log::debug!("  -> SUCCESS (interface={:?})", iface);

                    // For LOADED_IMAGE, log the DeviceHandle the bootloader will use
                    if guid_name == "LOADED_IMAGE" && !iface.is_null() {
                        let lip = iface as *const r_efi::protocols::loaded_image::Protocol;
                        let dev_handle = unsafe { (*lip).device_handle };
                        log::debug!("  -> LOADED_IMAGE.DeviceHandle = {:?}", dev_handle);
                    }
                    return Status::SUCCESS;
                }
            }
            log::debug!("  -> UNSUPPORTED (protocol not on handle)");
            return Status::UNSUPPORTED; // Handle exists but protocol not found
        }
    }

    log::debug!("  -> INVALID_PARAMETER (handle not found)");
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
    _search_key: *mut c_void,
    _no_handles: *mut usize,
    _buffer: *mut *mut Handle,
) -> Status {
    let guid_name = if protocol.is_null() {
        "NULL"
    } else {
        format_guid(unsafe { &*protocol })
    };
    log::debug!(
        "BS.LocateHandleBuffer(type={}, protocol={}) -> UNSUPPORTED",
        search_type,
        guid_name
    );
    Status::UNSUPPORTED
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
    let guid_name = format_guid(&guid);
    log::debug!("BS.LocateProtocol(protocol={})", guid_name);

    // Log raw GUID if unknown
    if guid_name == "UNKNOWN" {
        log_guid(&guid);
    }

    let handles = HANDLES.lock();
    let count = HANDLE_COUNT.lock();

    // Find first handle with this protocol
    for i in 0..*count {
        for j in 0..handles[i].protocol_count {
            if guid_eq(&handles[i].protocols[j].guid, &guid) {
                unsafe { *interface = handles[i].protocols[j].interface };
                return Status::SUCCESS;
            }
        }
    }

    log::debug!("  -> NOT_FOUND");
    Status::NOT_FOUND
}

// Note: These are variadic in the real UEFI spec, but Rust doesn't support
// variadic functions with efiapi calling convention. We implement them as
// fixed-argument stubs that always return UNSUPPORTED.
extern "efiapi" fn install_multiple_protocol_interfaces(
    _handle: *mut Handle,
    _arg1: *mut c_void,
    _arg2: *mut c_void,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn uninstall_multiple_protocol_interfaces(
    _handle: Handle,
    _arg1: *mut c_void,
    _arg2: *mut c_void,
) -> Status {
    Status::UNSUPPORTED
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

/// Compare two GUIDs for equality
fn guid_eq(a: &Guid, b: &Guid) -> bool {
    let a_bytes = unsafe { core::slice::from_raw_parts(a as *const Guid as *const u8, 16) };
    let b_bytes = unsafe { core::slice::from_raw_parts(b as *const Guid as *const u8, 16) };
    a_bytes == b_bytes
}

/// Log a GUID with its raw bytes (for debugging unknown GUIDs)
fn log_guid(guid: &Guid) {
    let bytes = unsafe { core::slice::from_raw_parts(guid as *const Guid as *const u8, 16) };
    // Format as standard GUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    log::debug!(
        "  GUID: {:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[3], bytes[2], bytes[1], bytes[0],  // Data1 (LE)
        bytes[5], bytes[4],                       // Data2 (LE)
        bytes[7], bytes[6],                       // Data3 (LE)
        bytes[8], bytes[9],                       // Data4[0-1]
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]  // Data4[2-7]
    );
}

/// Format a GUID for logging with well-known names
fn format_guid(guid: &Guid) -> &'static str {
    // Well-known GUIDs
    const LOADED_IMAGE_GUID: Guid = Guid::from_fields(
        0x5B1B31A1,
        0x9562,
        0x11d2,
        0x8E,
        0x3F,
        &[0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
    );
    const DEVICE_PATH_GUID: Guid = Guid::from_fields(
        0x09576e91,
        0x6d3f,
        0x11d2,
        0x8e,
        0x39,
        &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );
    const SIMPLE_FILE_SYSTEM_GUID: Guid = Guid::from_fields(
        0x0964e5b22,
        0x6459,
        0x11d2,
        0x8e,
        0x39,
        &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );
    const GOP_GUID: Guid = Guid::from_fields(
        0x9042a9de,
        0x23dc,
        0x4a38,
        0x96,
        0xfb,
        &[0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a],
    );
    const SIMPLE_TEXT_INPUT_GUID: Guid = Guid::from_fields(
        0x387477c1,
        0x69c7,
        0x11d2,
        0x8e,
        0x39,
        &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );
    const SIMPLE_TEXT_OUTPUT_GUID: Guid = Guid::from_fields(
        0x387477c2,
        0x69c7,
        0x11d2,
        0x8e,
        0x39,
        &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );
    const BLOCK_IO_GUID: Guid = Guid::from_fields(
        0x964e5b21,
        0x6459,
        0x11d2,
        0x8e,
        0x39,
        &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );
    const DISK_IO_GUID: Guid = Guid::from_fields(
        0xCE345171,
        0xBA0B,
        0x11d2,
        0x8e,
        0x4F,
        &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );
    const ACPI_TABLE_GUID: Guid = Guid::from_fields(
        0xeb9d2d30,
        0x2d88,
        0x11d3,
        0x9a,
        0x16,
        &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
    );
    const SMBIOS_TABLE_GUID: Guid = Guid::from_fields(
        0xeb9d2d31,
        0x2d88,
        0x11d3,
        0x9a,
        0x16,
        &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
    );
    const LOAD_FILE_GUID: Guid = Guid::from_fields(
        0x56EC3091,
        0x954C,
        0x11d2,
        0x8e,
        0x3f,
        &[0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b],
    );
    const LOAD_FILE2_GUID: Guid = Guid::from_fields(
        0x4006c0c1,
        0xfcb3,
        0x403e,
        0x99,
        0x6d,
        &[0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d],
    );
    const SERIAL_IO_GUID: Guid = Guid::from_fields(
        0xBB25CF6F,
        0xF1D4,
        0x11D2,
        0x9a,
        0x0c,
        &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0xfd],
    );
    const PXE_BASE_CODE_GUID: Guid = Guid::from_fields(
        0x03C4E603,
        0xAC28,
        0x11d3,
        0x9a,
        0x2d,
        &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
    );
    const HII_DATABASE_GUID: Guid = Guid::from_fields(
        0xef9fc172,
        0xa1b2,
        0x4693,
        0xb3,
        0x27,
        &[0x6d, 0x32, 0xfc, 0x41, 0x60, 0x42],
    );
    const HII_CONFIG_ROUTING_GUID: Guid = Guid::from_fields(
        0x587e72d7,
        0xcc50,
        0x4f79,
        0x82,
        0x09,
        &[0xca, 0x29, 0x1f, 0xc1, 0xa1, 0x0f],
    );
    const EDID_DISCOVERED_GUID: Guid = Guid::from_fields(
        0x1C0C34F6,
        0xD380,
        0x41FA,
        0xA0,
        0x49,
        &[0x8a, 0xd0, 0x6c, 0x1a, 0x66, 0xaa],
    );
    const EDID_ACTIVE_GUID: Guid = Guid::from_fields(
        0xBD8C1056,
        0x9F36,
        0x44EC,
        0x92,
        0xA8,
        &[0xa6, 0x33, 0x7f, 0x81, 0x79, 0x86],
    );
    // Unicode Collation Protocol
    const UNICODE_COLLATION_GUID: Guid = Guid::from_fields(
        0x1d85cd7f,
        0xf43d,
        0x11d2,
        0x9a,
        0x0c,
        &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
    );
    // SHIM Lock Protocol (Secure Boot)
    const SHIM_LOCK_GUID: Guid = Guid::from_fields(
        0x605dab50,
        0xe046,
        0x4300,
        0xab,
        0xb6,
        &[0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23],
    );
    // Shell Parameters Protocol
    const SHELL_PARAMETERS_GUID: Guid = Guid::from_fields(
        0x752f3136,
        0x4e16,
        0x4fdc,
        0xa2,
        0x2a,
        &[0xe5, 0xf4, 0x68, 0x12, 0xf4, 0xca],
    );
    // Load File 2 (initrd loading)
    const LINUX_INITRD_MEDIA_GUID: Guid = Guid::from_fields(
        0x5568e427,
        0x68fc,
        0x4f3d,
        0xac,
        0x74,
        &[0xca, 0x55, 0x52, 0x31, 0xcc, 0x68],
    );
    // Unknown GUID from bootloader: f42f7782-012e-4c12-9956-49f94304f721
    const UNKNOWN_BOOTLOADER_GUID: Guid = Guid::from_fields(
        0xf42f7782,
        0x012e,
        0x4c12,
        0x99,
        0x56,
        &[0x49, 0xf9, 0x43, 0x04, 0xf7, 0x21],
    );
    // EFI Memory Attribute Protocol (UEFI 2.10) - memory protection attributes
    const MEMORY_ATTRIBUTE_GUID: Guid = Guid::from_fields(
        0xf4560cf6,
        0x40ec,
        0x4b4a,
        0xa1,
        0x92,
        &[0xbf, 0x1d, 0x57, 0xd0, 0xb1, 0x89],
    );
    // EFI TCG Protocol (TPM 1.2)
    const TCG_GUID: Guid = Guid::from_fields(
        0xf541796d,
        0xa62e,
        0x4954,
        0xa7,
        0x75,
        &[0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd],
    );
    // EFI TCG2 Protocol (TPM 2.0)
    const TCG2_GUID: Guid = Guid::from_fields(
        0x607f766c,
        0x7455,
        0x42be,
        0x93,
        0x0b,
        &[0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f],
    );
    // EFI CC Measurement Protocol (Confidential Computing)
    const CC_MEASUREMENT_GUID: Guid = Guid::from_fields(
        0x96751a3d,
        0x72f4,
        0x41a6,
        0xa7,
        0x94,
        &[0xed, 0x5d, 0x0e, 0x67, 0xae, 0x6b],
    );
    // EFI Simple Text Input Ex Protocol
    const SIMPLE_TEXT_INPUT_EX_GUID: Guid = Guid::from_fields(
        0xdd9e7534,
        0x7762,
        0x4698,
        0x8c,
        0x14,
        &[0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa],
    );

    if guid_eq(guid, &LOADED_IMAGE_GUID) {
        return "LOADED_IMAGE";
    }
    if guid_eq(guid, &DEVICE_PATH_GUID) {
        return "DEVICE_PATH";
    }
    if guid_eq(guid, &SIMPLE_FILE_SYSTEM_GUID) {
        return "SIMPLE_FILE_SYSTEM";
    }
    if guid_eq(guid, &GOP_GUID) {
        return "GRAPHICS_OUTPUT (GOP)";
    }
    if guid_eq(guid, &SIMPLE_TEXT_INPUT_GUID) {
        return "SIMPLE_TEXT_INPUT";
    }
    if guid_eq(guid, &SIMPLE_TEXT_OUTPUT_GUID) {
        return "SIMPLE_TEXT_OUTPUT";
    }
    if guid_eq(guid, &BLOCK_IO_GUID) {
        return "BLOCK_IO";
    }
    if guid_eq(guid, &DISK_IO_GUID) {
        return "DISK_IO";
    }
    if guid_eq(guid, &ACPI_TABLE_GUID) {
        return "ACPI_TABLE";
    }
    if guid_eq(guid, &SMBIOS_TABLE_GUID) {
        return "SMBIOS_TABLE";
    }
    if guid_eq(guid, &LOAD_FILE_GUID) {
        return "LOAD_FILE";
    }
    if guid_eq(guid, &LOAD_FILE2_GUID) {
        return "LOAD_FILE2";
    }
    if guid_eq(guid, &SERIAL_IO_GUID) {
        return "SERIAL_IO";
    }
    if guid_eq(guid, &PXE_BASE_CODE_GUID) {
        return "PXE_BASE_CODE";
    }
    if guid_eq(guid, &HII_DATABASE_GUID) {
        return "HII_DATABASE";
    }
    if guid_eq(guid, &HII_CONFIG_ROUTING_GUID) {
        return "HII_CONFIG_ROUTING";
    }
    if guid_eq(guid, &EDID_DISCOVERED_GUID) {
        return "EDID_DISCOVERED";
    }
    if guid_eq(guid, &EDID_ACTIVE_GUID) {
        return "EDID_ACTIVE";
    }
    if guid_eq(guid, &UNICODE_COLLATION_GUID) {
        return "UNICODE_COLLATION";
    }
    if guid_eq(guid, &SHIM_LOCK_GUID) {
        return "SHIM_LOCK";
    }
    if guid_eq(guid, &SHELL_PARAMETERS_GUID) {
        return "SHELL_PARAMETERS";
    }
    if guid_eq(guid, &LINUX_INITRD_MEDIA_GUID) {
        return "LINUX_INITRD_MEDIA";
    }
    if guid_eq(guid, &UNKNOWN_BOOTLOADER_GUID) {
        return "UNKNOWN_BOOTLOADER_F42F7782";
    }
    if guid_eq(guid, &MEMORY_ATTRIBUTE_GUID) {
        return "MEMORY_ATTRIBUTE";
    }
    if guid_eq(guid, &TCG_GUID) {
        return "TCG (TPM 1.2)";
    }
    if guid_eq(guid, &TCG2_GUID) {
        return "TCG2 (TPM 2.0)";
    }
    if guid_eq(guid, &CC_MEASUREMENT_GUID) {
        return "CC_MEASUREMENT";
    }
    if guid_eq(guid, &SIMPLE_TEXT_INPUT_EX_GUID) {
        return "SIMPLE_TEXT_INPUT_EX";
    }

    "UNKNOWN"
}

/// Create a new handle and register it
pub fn create_handle() -> Option<Handle> {
    let mut handles = HANDLES.lock();
    let mut count = HANDLE_COUNT.lock();

    if *count >= MAX_HANDLES {
        return None;
    }

    let mut next = NEXT_HANDLE.lock();
    let handle = *next as *mut c_void;
    *next += 1;

    handles[*count].handle = handle;
    handles[*count].protocol_count = 0;
    *count += 1;

    Some(handle)
}

/// Install a protocol on an existing handle
pub fn install_protocol(handle: Handle, guid: &Guid, interface: *mut c_void) -> Status {
    let mut handles = HANDLES.lock();
    let count = HANDLE_COUNT.lock();

    for i in 0..*count {
        if handles[i].handle == handle {
            // Check if protocol already installed
            for j in 0..handles[i].protocol_count {
                if guid_eq(&handles[i].protocols[j].guid, guid) {
                    return Status::INVALID_PARAMETER;
                }
            }

            if handles[i].protocol_count >= MAX_PROTOCOLS_PER_HANDLE {
                return Status::OUT_OF_RESOURCES;
            }

            let idx = handles[i].protocol_count;
            handles[i].protocols[idx] = ProtocolEntry {
                guid: *guid,
                interface,
            };
            handles[i].protocol_count += 1;
            return Status::SUCCESS;
        }
    }

    Status::INVALID_PARAMETER
}

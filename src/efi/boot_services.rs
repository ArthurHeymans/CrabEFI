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

/// Handle database
static HANDLES: Mutex<[HandleEntry; MAX_HANDLES]> =
    Mutex::new([const { HandleEntry::empty() }; MAX_HANDLES]);
static HANDLE_COUNT: Mutex<usize> = Mutex::new(0);

/// Next handle value (used as a unique identifier)
static NEXT_HANDLE: Mutex<usize> = Mutex::new(1);

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

extern "efiapi" fn raise_tpl(_new_tpl: Tpl) -> Tpl {
    // No interrupt handling, return current TPL (APPLICATION)
    efi::TPL_APPLICATION
}

extern "efiapi" fn restore_tpl(_old_tpl: Tpl) {
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

    status
}

extern "efiapi" fn allocate_pool(
    pool_type: efi::MemoryType,
    size: usize,
    buffer: *mut *mut c_void,
) -> Status {
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
    _event_type: u32,
    _notify_tpl: Tpl,
    _notify_function: Option<efi::EventNotify>,
    _notify_context: *mut c_void,
    _event: *mut efi::Event,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn set_timer(
    _event: efi::Event,
    _timer_type: efi::TimerDelay,
    _trigger_time: u64,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn wait_for_event(
    _number_of_events: usize,
    _event: *mut efi::Event,
    _index: *mut usize,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn signal_event(_event: efi::Event) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn close_event(_event: efi::Event) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn check_event(_event: efi::Event) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn create_event_ex(
    _event_type: u32,
    _notify_tpl: Tpl,
    _notify_function: Option<efi::EventNotify>,
    _notify_context: *const c_void,
    _event_group: *const Guid,
    _event: *mut efi::Event,
) -> Status {
    Status::UNSUPPORTED
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
    // Forward to open_protocol with simpler semantics
    open_protocol(
        handle,
        protocol,
        interface,
        core::ptr::null_mut(), // agent_handle
        core::ptr::null_mut(), // controller_handle
        efi::OPEN_PROTOCOL_BY_HANDLE_PROTOCOL,
    )
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

    // Only ByProtocol search is supported
    if search_type != efi::BY_PROTOCOL {
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
        Status::NOT_FOUND
    } else {
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
    _boot_policy: Boolean,
    _parent_image_handle: Handle,
    _device_path: *mut DevicePathProtocol,
    _source_buffer: *mut c_void,
    _source_size: usize,
    _image_handle: *mut Handle,
) -> Status {
    // TODO: Implement PE loader
    Status::UNSUPPORTED
}

extern "efiapi" fn start_image(
    _image_handle: Handle,
    _exit_data_size: *mut usize,
    _exit_data: *mut *mut u16,
) -> Status {
    // TODO: Implement image execution
    Status::UNSUPPORTED
}

extern "efiapi" fn exit(
    _image_handle: Handle,
    _exit_status: Status,
    _exit_data_size: usize,
    _exit_data: *mut u16,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn unload_image(_image_handle: Handle) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn exit_boot_services(_image_handle: Handle, map_key: usize) -> Status {
    let status = allocator::exit_boot_services(map_key);

    if status == Status::SUCCESS {
        log::info!("ExitBootServices called, transitioning to OS");
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
    _attributes: u32,
) -> Status {
    if handle.is_null() || protocol.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let guid = unsafe { *protocol };
    let handles = HANDLES.lock();
    let count = HANDLE_COUNT.lock();

    for i in 0..*count {
        if handles[i].handle == handle {
            for j in 0..handles[i].protocol_count {
                if guid_eq(&handles[i].protocols[j].guid, &guid) {
                    if !interface.is_null() {
                        unsafe { *interface = handles[i].protocols[j].interface };
                    }
                    return Status::SUCCESS;
                }
            }
            return Status::UNSUPPORTED; // Handle exists but protocol not found
        }
    }

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
    _search_type: efi::LocateSearchType,
    _protocol: *mut Guid,
    _search_key: *mut c_void,
    _no_handles: *mut usize,
    _buffer: *mut *mut Handle,
) -> Status {
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

//! EFI Boot Services
//!
//! This module implements the EFI Boot Services table, which provides
//! memory allocation, protocol handling, and image loading services.
//!
//! # State Management
//!
//! Boot Services state (handles, events, loaded images) lives in the
//! `crate::state` EFI cell. Access it via `crate::state::efi()` and
//! `crate::state::with_efi_mut()`.

use super::allocator::{self, AllocateType, MemoryDescriptor, MemoryType};
use super::image_loader;
use super::protocols::loaded_image::{LOADED_IMAGE_PROTOCOL_GUID, create_loaded_image_protocol};
use super::system_table;
use crate::pe;
use crate::state::{
    self, EventEntry, LoadedImageEntry, MAX_EVENTS, MAX_HANDLES, MAX_PROTOCOLS_PER_HANDLE,
    ProtocolEntry,
};
use alloc::vec::Vec;
use core::ffi::c_void;

use crabefi_efi_types::crc32;
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

/// Special event ID for pointer (mouse) input
#[cfg(feature = "ui")]
pub const POINTER_EVENT_ID: usize = 2;

/// Static boot services table
static mut BOOT_SERVICES: efi::BootServices = efi::BootServices {
    hdr: TableHeader {
        signature: EFI_BOOT_SERVICES_SIGNATURE,
        revision: EFI_BOOT_SERVICES_REVISION,
        header_size: core::mem::size_of::<efi::BootServices>() as u32,
        crc32: 0,
        reserved: 0,
    },
    raise_tpl,
    restore_tpl,
    allocate_pages,
    free_pages,
    get_memory_map,
    allocate_pool,
    free_pool,
    create_event,
    set_timer,
    wait_for_event,
    signal_event,
    close_event,
    check_event,
    install_protocol_interface,
    reinstall_protocol_interface,
    uninstall_protocol_interface,
    handle_protocol,
    reserved: core::ptr::null_mut(),
    register_protocol_notify,
    locate_handle,
    locate_device_path,
    install_configuration_table,
    load_image,
    start_image,
    exit,
    unload_image,
    exit_boot_services,
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
    create_event_ex,
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

    let alloc_type = match AllocateType::try_from(alloc_type) {
        Ok(t) => t,
        Err(_) => return Status::INVALID_PARAMETER,
    };

    let mem_type = match MemoryType::try_from(memory_type) {
        Ok(t) => t,
        Err(_) => return Status::INVALID_PARAMETER,
    };

    let mut addr = unsafe { *memory };
    let status = allocator::allocate_pages(alloc_type, mem_type, pages as u64, &mut addr);

    if status == Status::SUCCESS {
        unsafe { *memory = addr };
        log::debug!("  -> allocated at {:#x}", addr);
    } else {
        log::warn!("  -> failed: {:?}", status);
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

    let mem_type = match MemoryType::try_from(pool_type) {
        Ok(t) => t,
        Err(_) => return Status::INVALID_PARAMETER,
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

const fn boot_event_type_supported(event_type: u32) -> bool {
    event_type & EVT_RUNTIME == 0
}

extern "efiapi" fn create_event(
    event_type: u32,
    notify_tpl: Tpl,
    notify_function: Option<efi::EventNotify>,
    notify_context: *mut c_void,
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
    if !boot_event_type_supported(event_type) {
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

        // Store event info including notify callback
        efi_state.events[event_id] = EventEntry {
            event_type,
            notify_tpl,
            signaled: false,
            is_keyboard_event: false,
            notify_function,
            notify_context,
            event_group: None,
            timer_type: state::TimerType::Cancel,
            timer_trigger_time: 0,
            timer_deadline_tsc: 0,
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

    let event_id = event as usize;
    if event_id == 0 || event_id >= MAX_EVENTS {
        return Status::INVALID_PARAMETER;
    }

    let timer = match state::TimerType::try_from(timer_type) {
        Ok(t) => t,
        Err(_) => return Status::INVALID_PARAMETER,
    };

    state::with_efi_mut(|efi_state| {
        let entry = &mut efi_state.events[event_id];

        // Verify this is a timer event
        if entry.event_type & EVT_TIMER == 0 {
            log::debug!("  -> INVALID_PARAMETER (not a timer event)");
            return Status::INVALID_PARAMETER;
        }

        entry.timer_type = timer;
        entry.timer_trigger_time = trigger_time;

        match timer {
            state::TimerType::Cancel => {
                entry.timer_deadline_tsc = 0;
                entry.signaled = false;
                log::debug!("  -> SUCCESS (timer cancelled)");
            }
            state::TimerType::Periodic | state::TimerType::Relative => {
                // Convert 100ns units to TSC ticks
                let tsc_freq = crate::time::tsc_frequency();
                if tsc_freq == 0 {
                    log::error!("  -> DEVICE_ERROR (TSC not calibrated)");
                    return Status::DEVICE_ERROR;
                }
                let tsc_per_us = tsc_freq / 1_000_000;
                let us = trigger_time / 10;
                let tsc_offset = us * tsc_per_us.max(1);
                let now = crate::time::rdtsc();
                entry.timer_deadline_tsc = now + tsc_offset;
                log::debug!("  -> SUCCESS (deadline in {}us)", us);
            }
        }

        Status::SUCCESS
    })
}

fn notify_wait_event(event_id: usize, event: efi::Event) {
    let notify_fn = state::with_efi_mut(|efi_state| {
        let entry = &efi_state.events[event_id];
        if !entry.signaled && entry.event_type & EVT_NOTIFY_WAIT != 0 {
            entry.notify_function.map(|f| (f, entry.notify_context))
        } else {
            None
        }
    });

    if let Some((func, context)) = notify_fn {
        log::trace!(
            "  -> Calling EVT_NOTIFY_WAIT function for event {}",
            event_id
        );
        func(event, context);
    }
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

    // Poll for events (keyboard input, timers, signaled events)
    loop {
        // Check each event
        for (i, &evt) in events_to_wait.iter().enumerate() {
            let event_id = evt as usize;

            // Check if it's the keyboard event and there's actual key input.
            // We do a real read-ahead (not just peek at status registers) to
            // avoid false positives from modifier keys, mouse data, etc.
            if event_id == KEYBOARD_EVENT_ID
                && crate::efi::protocols::console::keyboard_check_ready()
            {
                unsafe { *index = i };
                log::debug!("  -> SUCCESS (keyboard input ready, index={})", i);
                return Status::SUCCESS;
            }

            // Check if it's the pointer event and there's mouse input.
            #[cfg(feature = "ui")]
            if event_id == POINTER_EVENT_ID
                && crate::efi::protocols::simple_pointer::pointer_check_ready()
            {
                unsafe { *index = i };
                log::debug!("  -> SUCCESS (pointer input ready, index={})", i);
                return Status::SUCCESS;
            }

            // Check if a regular event is signaled (including timer check)
            if event_id > 0 && event_id < MAX_EVENTS {
                notify_wait_event(event_id, evt);
                check_timer_event(event_id);

                // Per UEFI spec: WaitForEvent clears the signaled state
                // of the event that triggered the return.
                let signaled = state::with_efi_mut(|efi_state| {
                    let was_signaled = efi_state.events[event_id].signaled;
                    if was_signaled {
                        efi_state.events[event_id].signaled = false;
                    }
                    was_signaled
                });
                if signaled {
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
        // Get notify function if present, then mark signaled
        let notify_fn = state::with_efi_mut(|efi_state| {
            efi_state.events[event_id].signaled = true;
            let entry = &efi_state.events[event_id];
            if entry.event_type & EVT_NOTIFY_SIGNAL != 0 {
                entry.notify_function.map(|f| (f, entry.notify_context))
            } else {
                None
            }
        });

        // Call notify function outside the state borrow
        if let Some((func, context)) = notify_fn {
            log::debug!("  -> Calling notify function for event {}", event_id);
            func(event, context);
        }
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
    log::trace!("BS.CheckEvent(event={})", event_id);

    // Special case for keyboard event — do a real read-ahead check
    if event_id == KEYBOARD_EVENT_ID {
        if crate::efi::protocols::console::keyboard_check_ready() {
            return Status::SUCCESS;
        } else {
            return Status::NOT_READY;
        }
    }

    // Special case for pointer event — poll hardware and peek
    #[cfg(feature = "ui")]
    if event_id == POINTER_EVENT_ID {
        if crate::efi::protocols::simple_pointer::pointer_check_ready() {
            return Status::SUCCESS;
        } else {
            return Status::NOT_READY;
        }
    }

    // Check regular events
    if event_id > 0 && event_id < MAX_EVENTS {
        notify_wait_event(event_id, event);

        // Check timer expiration
        check_timer_event(event_id);

        // Per UEFI spec: CheckEvent clears the signaled state when
        // returning SUCCESS (for EVT_NOTIFY_WAIT events, the notify
        // function is called first, then the event is cleared).
        let signaled = state::with_efi_mut(|efi_state| {
            let was_signaled = efi_state.events[event_id].signaled;
            if was_signaled {
                efi_state.events[event_id].signaled = false;
            }
            was_signaled
        });
        if signaled {
            return Status::SUCCESS;
        }
    }

    Status::NOT_READY
}

/// Check if a timer event has expired and signal it if so
fn check_timer_event(event_id: usize) {
    state::with_efi_mut(|efi_state| {
        let entry = &mut efi_state.events[event_id];

        // Only process timer events with an active deadline
        if entry.event_type & EVT_TIMER == 0 || entry.timer_type == state::TimerType::Cancel {
            return;
        }

        if entry.timer_deadline_tsc == 0 {
            return;
        }

        let now = crate::time::rdtsc();
        if now >= entry.timer_deadline_tsc {
            entry.signaled = true;

            match entry.timer_type {
                state::TimerType::Periodic => {
                    // Reset deadline for next period
                    let tsc_per_us = (crate::time::tsc_frequency() / 1_000_000).max(1);
                    let us = entry.timer_trigger_time / 10;
                    let tsc_offset = us * tsc_per_us;
                    entry.timer_deadline_tsc = now + tsc_offset;
                }
                state::TimerType::Relative => {
                    // One-shot: clear the deadline
                    entry.timer_deadline_tsc = 0;
                }
                state::TimerType::Cancel => {}
            }
        }
    });
}

/// EFI_EVENT_GROUP_READY_TO_BOOT GUID
const EFI_EVENT_GROUP_READY_TO_BOOT: Guid = Guid::from_fields(
    0x7CE88FB3,
    0x4BD7,
    0x4679,
    0x87,
    0xA8,
    &[0xA8, 0xD8, 0xDE, 0xE5, 0x0D, 0x2B],
);

/// EFI_EVENT_GROUP_EXIT_BOOT_SERVICES GUID
const EFI_EVENT_GROUP_EXIT_BOOT_SERVICES: Guid = Guid::from_fields(
    0x27ABF055,
    0xB1B8,
    0x4C26,
    0x80,
    0x48,
    &[0x74, 0x8F, 0x37, 0xBA, 0xA2, 0xDF],
);

/// Signal all events belonging to a specific event group
fn signal_event_group(group_guid: &Guid) {
    // Collect events to signal (must not hold a state borrow during callbacks)
    let mut events_to_signal: heapless::Vec<
        (usize, Option<efi::EventNotify>, *mut c_void),
        MAX_EVENTS,
    > = heapless::Vec::new();

    state::with_efi_mut(|efi_state| {
        for (i, entry) in efi_state.events.iter_mut().enumerate() {
            if let Some(ref group) = entry.event_group
                && *group == *group_guid
            {
                entry.signaled = true;
                let notify = if entry.event_type & EVT_NOTIFY_SIGNAL != 0 {
                    entry.notify_function.map(|f| (f, entry.notify_context))
                } else {
                    None
                };
                let _ = events_to_signal.push((
                    i,
                    notify.map(|(f, _)| f),
                    notify.map(|(_, c)| c).unwrap_or(core::ptr::null_mut()),
                ));
            }
        }
    });

    // Call notify functions outside the state borrow
    for (event_id, notify_fn, context) in &events_to_signal {
        if let Some(func) = notify_fn {
            log::debug!("signal_event_group: calling notify for event {}", event_id);
            func(*event_id as efi::Event, *context);
        }
    }

    if !events_to_signal.is_empty() {
        log::info!(
            "signal_event_group: signaled {} events",
            events_to_signal.len()
        );
    }
}

/// Measure the beginning of an EFI boot application attempt.
///
/// The first attempt performs the ReadyToBoot measured-boot sequence and
/// signals the ReadyToBoot event group. Subsequent attempts only add the boot
/// action event so separators are not duplicated.
pub(crate) fn measure_efi_application_start(is_application: bool) {
    if !is_application {
        return;
    }

    let should_signal = crate::state::with_efi_mut(|efi| {
        if !efi.ready_to_boot_signaled {
            efi.ready_to_boot_signaled = true;
            true
        } else {
            false
        }
    });

    if should_signal {
        // TCG measured boot: measure pre-OS handoff state, boot variables,
        // boot action, and separators before the first boot attempt, per TCG
        // PFP / EDK2 ReadyToBoot ordering.
        super::tcg::measured_boot::measure_handoff_tables_all();
        super::tcg::measured_boot::measure_boot_variables_all();
        super::tcg::measured_boot::measure_action_all(
            4,
            "Calling EFI Application from Boot Option",
        );

        // Measure separator events into PCR 0-6.
        // PCR 7 already has its separator from Secure Boot variable measurement.
        super::tcg::measured_boot::measure_all_separators_all();

        signal_event_group(&EFI_EVENT_GROUP_READY_TO_BOOT);
    } else {
        super::tcg::measured_boot::measure_action_all(
            4,
            "Calling EFI Application from Boot Option",
        );
    }
}

/// Measure return from an EFI boot application attempt.
pub(crate) fn measure_efi_application_return(is_application: bool) {
    if is_application && crate::state::efi().ready_to_boot_signaled {
        super::tcg::measured_boot::measure_action_all(
            4,
            "Returning from EFI Application from Boot Option",
        );
    }
}

extern "efiapi" fn create_event_ex(
    event_type: u32,
    notify_tpl: Tpl,
    notify_function: Option<efi::EventNotify>,
    notify_context: *const c_void,
    event_group: *const Guid,
    event: *mut efi::Event,
) -> Status {
    let group_display = if event_group.is_null() {
        None
    } else {
        Some(GuidFmt(unsafe { *event_group }))
    };
    log::debug!(
        "BS.CreateEventEx(type={:#x}, tpl={:?}, group={})",
        event_type,
        notify_tpl,
        group_display
            .as_ref()
            .map(|g| g as &dyn core::fmt::Display)
            .unwrap_or(&"NULL" as &dyn core::fmt::Display)
    );

    if event.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Create the event with full parameters
    let status = create_event(
        event_type,
        notify_tpl,
        notify_function,
        notify_context as *mut c_void,
        event,
    );

    if status == Status::SUCCESS && !event_group.is_null() {
        // Store the event group GUID on the newly created event
        let event_id = unsafe { *event } as usize;
        if event_id > 0 && event_id < MAX_EVENTS {
            state::with_efi_mut(|efi_state| {
                efi_state.events[event_id].event_group = Some(unsafe { *event_group });
            });
        }
    }

    status
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

    let efi_state = state::efi();

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

    // Find a handle with both the specified protocol and a DEVICE_PATH protocol
    let efi_state = state::efi();

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
// Device path parsing and file loading helpers are in `super::image_loader`.

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

    // Determine the image source: either a caller-provided buffer or loaded from device path.
    enum ImageSource {
        /// Caller-provided buffer — not owned by us, must not be freed
        Buffer {
            data_ptr: *mut c_void,
            data_size: usize,
        },
        /// Loaded from device path — we allocated this buffer and must free it
        DevicePath {
            data_ptr: *mut c_void,
            data_size: usize,
            device_handle: Handle,
        },
    }

    let source = if !source_buffer.is_null() && source_size > 0 {
        ImageSource::Buffer {
            data_ptr: source_buffer,
            data_size: source_size,
        }
    } else if !device_path.is_null() {
        match image_loader::load_image_from_device_path(device_path) {
            Ok((ptr, size, dev_handle)) => ImageSource::DevicePath {
                data_ptr: ptr,
                data_size: size,
                device_handle: dev_handle,
            },
            Err(status) => {
                log::error!(
                    "BS.LoadImage: Failed to load from device path: {:?}",
                    status
                );
                return status;
            }
        }
    } else {
        log::error!("BS.LoadImage: No source buffer and no device path provided");
        return Status::INVALID_PARAMETER;
    };

    let (data_ptr, data_size) = match &source {
        ImageSource::Buffer {
            data_ptr,
            data_size,
        } => (*data_ptr, *data_size),
        ImageSource::DevicePath {
            data_ptr,
            data_size,
            ..
        } => (*data_ptr, *data_size),
    };

    // Create a slice from the source buffer
    let data = unsafe { core::slice::from_raw_parts(data_ptr as *const u8, data_size) };

    // Helper to free the buffer only if we own it (loaded from device path)
    let free_if_owned = |source: &ImageSource| {
        if let ImageSource::DevicePath { data_ptr, .. } = source {
            let _ = allocator::free_pool(*data_ptr as *mut u8);
        }
    };

    // Secure Boot verification (if enabled)
    if super::auth::is_secure_boot_enabled() {
        log::debug!("BS.LoadImage: Secure Boot verification required");
        match super::auth::verify_pe_image_secure_boot(data) {
            Ok(true) => {
                log::info!("BS.LoadImage: Secure Boot verification passed");
            }
            Ok(false) => {
                log::error!("BS.LoadImage: Secure Boot verification FAILED - image not authorized");
                crate::display_secure_boot_error();
                free_if_owned(&source);
                return Status::SECURITY_VIOLATION;
            }
            Err(e) => {
                log::error!("BS.LoadImage: Secure Boot verification error: {:?}", e);
                crate::display_secure_boot_error();
                free_if_owned(&source);
                return Status::SECURITY_VIOLATION;
            }
        }
    }

    // Load the PE image using our PE loader
    let loaded_image = match pe::load_image(data) {
        Ok(img) => img,
        Err(status) => {
            log::error!("BS.LoadImage: Failed to load PE image: {:?}", status);
            free_if_owned(&source);
            return status;
        }
    };

    log::debug!(
        "BS.LoadImage: PE loaded at {:#x}, entry={:#x}, size={:#x}",
        loaded_image.image_base,
        loaded_image.entry_point,
        loaded_image.image_size
    );

    // Preserve metadata before releasing an owned source buffer.
    let image_subsystem = pe::parse_headers(data)
        .map(|headers| headers.subsystem())
        .unwrap_or(0);

    // TCG measured boot: drivers are measured now; applications are deferred
    // until StartImage after ReadyToBoot, with digests computed before freeing data.
    let deferred_measurement = measure_pe_image_for_tcg(
        data,
        &loaded_image,
        device_path as *const DevicePathProtocol,
    );

    // Free the buffer now that PE is loaded and measured (PE loading makes its own copy).
    free_if_owned(&source);

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
    // Use the device handle from loading if we loaded from device path,
    // otherwise try to get it from the parent
    let device_handle = match &source {
        ImageSource::DevicePath { device_handle, .. } => *device_handle,
        _ => image_loader::get_device_handle_from_parent(parent_image_handle),
    };

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
        if let Some(measurement) = deferred_measurement {
            let _ = allocator::free_pool(measurement.event_data);
        }
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
        if let Some(measurement) = deferred_measurement {
            let _ = allocator::free_pool(measurement.event_data);
        }
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
                entry.alloc_base = loaded_image.alloc_base;
                entry.num_pages = loaded_image.num_pages;
                entry.parent_handle = parent_image_handle;
                entry.subsystem = image_subsystem;
                if let Some(measurement) = deferred_measurement {
                    entry.measurement_pcr = measurement.pcr_index;
                    entry.measurement_event_type = measurement.event_type;
                    entry.measurement_digest_count = measurement.digest_count;
                    entry.measurement_digests = measurement.digests;
                    entry.measurement_event_data = measurement.event_data;
                    entry.measurement_event_data_size = measurement.event_data_size;
                }
                true
            }
            None => false,
        }
    });

    if !store_result {
        log::error!("BS.LoadImage: No space in loaded images table");
        if let Some(measurement) = deferred_measurement {
            let _ = allocator::free_pool(measurement.event_data);
        }
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
    let (entry_point, image_base, image_subsystem) = {
        let efi_state = state::efi();
        match efi_state
            .loaded_images
            .iter()
            .find(|entry| entry.handle == image_handle)
            .map(|entry| (entry.entry_point, entry.image_base, entry.subsystem))
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

    // Signal EFI_EVENT_GROUP_READY_TO_BOOT before the first image is started
    // and measure boot-attempt action events without duplicating separators.
    let is_application = image_subsystem == 10;
    measure_efi_application_start(is_application);

    let deferred_measurement = state::with_efi_mut(|efi_state| {
        efi_state
            .loaded_images
            .iter_mut()
            .find(|entry| entry.handle == image_handle)
            .and_then(|entry| {
                if entry.measurement_event_data.is_null() {
                    return None;
                }
                let measurement = DeferredImageMeasurement {
                    pcr_index: entry.measurement_pcr,
                    event_type: entry.measurement_event_type,
                    digest_count: entry.measurement_digest_count,
                    digests: entry.measurement_digests,
                    event_data: entry.measurement_event_data,
                    event_data_size: entry.measurement_event_data_size,
                };
                entry.measurement_event_data = core::ptr::null_mut();
                entry.measurement_event_data_size = 0;
                entry.measurement_digest_count = 0;
                Some(measurement)
            })
    });

    if let Some(measurement) = deferred_measurement {
        let event_data = unsafe {
            // SAFETY: deferred measurement event data was allocated and filled in
            // LoadImage and remains owned by this loaded-image entry until now.
            core::slice::from_raw_parts(measurement.event_data, measurement.event_data_size)
        };
        if let Err(e) = super::tcg::measured_boot::measure_pe_image_digests_all(
            measurement.pcr_index,
            measurement.event_type,
            &measurement.digests[..measurement.digest_count],
            event_data,
        ) {
            log::warn!("Failed to measure PE image: {:?}", e);
        }
        let _ = allocator::free_pool(measurement.event_data);
    }

    // Update table CRC32s one final time before handing off to the image
    // (config tables may have changed since efi::init())
    super::system_table::update_crc32();

    // Get the system table
    let system_table = super::get_system_table();

    // Define the entry point function type
    type EfiEntryPoint = extern "efiapi" fn(Handle, *mut SystemTable) -> Status;

    // Call the entry point
    let entry: EfiEntryPoint = unsafe { core::mem::transmute(entry_point) };
    let status = entry(image_handle, system_table);

    log::info!("BS.StartImage: Image returned with status: {:?}", status);
    measure_efi_application_return(is_application);

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

/// EFI Boot Service: Exit
///
/// UEFI Spec Compliance Note: A fully conformant `Exit()` implementation must
/// perform a non-local return (longjmp) back to the corresponding `StartImage()`
/// call, unwinding the call stack. This requires saving the execution context
/// (registers, stack pointer) in `StartImage()` via setjmp, and restoring it here.
///
/// Current limitation: This implementation simply returns `exit_status` to the
/// caller, which means `Exit()` only works correctly when called directly from
/// the image's entry point (the common case for UEFI bootloaders like shim and
/// GRUB). It will NOT correctly unwind nested image calls or calls from deep
/// within a loaded image's call stack.
///
/// This is acceptable for our boot use case (shim → GRUB → Linux), but would
/// need a proper setjmp/longjmp implementation for full UEFI application support.
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
                let result = (
                    entry.alloc_base,
                    entry.num_pages,
                    entry.measurement_event_data,
                );
                // Clear the entry
                *entry = LoadedImageEntry::empty();
                result
            })
    });

    match image_info {
        Some((alloc_base, num_pages, measurement_event_data)) => {
            // Free the image memory (using alloc_base, not image_base,
            // since the image may have been aligned within the allocation)
            let status = allocator::free_pages(alloc_base, num_pages);
            if status != Status::SUCCESS {
                log::warn!(
                    "BS.UnloadImage: Failed to free pages at {:#x}: {:?}",
                    alloc_base,
                    status
                );
            }

            if !measurement_event_data.is_null() {
                let _ = allocator::free_pool(measurement_event_data);
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

    // Reject a stale key before callbacks, measurements, or any irreversible
    // transition. The allocator repeats this check at the actual commit point
    // in case an EBS callback changes the map.
    let key_status = allocator::validate_map_key(map_key);
    if key_status != Status::SUCCESS {
        return key_status;
    }
    let Some(runtime_image) = crate::state::runtime_image() else {
        log::error!("ExitBootServices refused: runtime image client is missing");
        return Status::DEVICE_ERROR;
    };

    // TCG measured boot: measure ExitBootServices action into PCR 5.
    super::tcg::measured_boot::measure_action_all(5, "Exit Boot Services Invocation");

    // Signal EXIT_BOOT_SERVICES event group BEFORE finalizing the memory map.
    // Windows Boot Manager registers callbacks that must run before we lock
    // the memory map.
    signal_event_group(&EFI_EVENT_GROUP_EXIT_BOOT_SERVICES);

    // Also signal any legacy EVT_SIGNAL_EXIT_BOOT_SERVICES events
    {
        let mut legacy_events: heapless::Vec<usize, MAX_EVENTS> = heapless::Vec::new();
        state::with_efi_mut(|efi_state| {
            for (i, event) in efi_state.events.iter_mut().enumerate() {
                if event.event_type == EVT_SIGNAL_EXIT_BOOT_SERVICES {
                    event.signaled = true;
                    let _ = legacy_events.push(i);
                }
            }
        });
        for event_id in &legacy_events {
            let notify_fn = {
                let efi_state = state::efi();
                let entry = &efi_state.events[*event_id];
                entry.notify_function.map(|f| (f, entry.notify_context))
            };
            if let Some((func, context)) = notify_fn {
                func(*event_id as efi::Event, context);
            }
        }
    }

    // Rebuild the Memory Attributes Table in-place BEFORE locking the allocator.
    // Runtime image and retained-buffer regions are registered after the
    // initial table setup, so the final MAT must be rebuilt from the allocator.
    // A stale MEMATTR table with missing entries causes Windows to crash.
    // We use the in-place variant that overwrites the existing page without
    // calling allocate_pages(), so the map_key stays valid for the caller.
    let prepare_status = system_table::rebuild_memory_attributes_table_in_place();
    if prepare_status != Status::SUCCESS {
        return prepare_status;
    }

    // Event callbacks and MAT rebuilding may have changed the memory map. Do a
    // final key check before any irreversible hardware quiescence.
    let key_status = allocator::validate_map_key(map_key);
    if key_status != Status::SUCCESS {
        return key_status;
    }

    // Stop every firmware-owned DMA engine while BootServices allocations are
    // still typed and cannot yet be reused by the OS. Clearing BME is the final
    // safety net for devices without complete driver shutdown coverage.
    crate::drivers::pci::shutdown_drivers();
    crate::drivers::pci::disable_all_bus_mastering_for_handoff();

    let status = allocator::exit_boot_services(map_key);

    if status == Status::SUCCESS {
        // TCG measured boot: measure ExitBootServices success into PCR 5.
        super::tcg::measured_boot::measure_action_all(
            5,
            "Exit Boot Services Returned with Success",
        );

        log::info!("ExitBootServices SUCCESS - transitioning to OS");
        crate::timestamp::record(crate::timestamp::TS_CRABEFI_EXIT_BOOT_SERVICES);

        // Clean up hardware state for OS handoff.
        // Re-enable keyboard interrupts so Linux's i8042 driver works.
        crate::drivers::keyboard_common::cleanup();

        // Seal only after the allocator accepted the map key, while boot-time
        // diagnostics are still reachable. A failed seal leaves no safe way to
        // return to the OS after allocator EBS, so report it and halt explicitly.
        if let Err(seal_status) = runtime_image.seal() {
            log::error!(
                "FATAL: runtime image seal failed after allocator ExitBootServices: {:?}",
                seal_status
            );
            loop {
                crate::arch::halt();
            }
        }
        log::info!("Runtime image sealed successfully");

        // Let platform glue clean up integration-specific handoff state only
        // after the final fallible step; hooks may disable non-runtime log
        // buffers needed to diagnose a seal failure.
        if let Some(hooks) = crate::state::platform_callbacks().hooks {
            hooks.on_exit_boot_services();
        }

        // CRITICAL: Disable logging only after the final fallible runtime-image
        // transition. The OS generally does not map firmware log devices as
        // runtime memory.
        log::set_max_level(log::LevelFilter::Off);

        // Switch from Secure EL1 to Non-Secure EL1 via a RAM trampoline.
        //
        // At Secure EL1, GICv3 routes Non-Secure Group 1 interrupts (LPIs /
        // MSI-X) as FIQ. The Linux kernel only handles IRQ, so NVMe and other
        // MSI-X devices hang forever waiting for completion interrupts.
        //
        // We can't issue the SMC directly from flash because the ERET returns
        // to the instruction after the SMC — which is in Secure flash, not
        // accessible from NS-EL1 on QEMU virt. Instead, we write a small
        // trampoline to RAM that does SMC + RET. The RET returns to the EFI
        // stub (also in RAM), now at NS-EL1 with proper interrupt routing.
        //
        // Uses vendor-specific SMCCC function ID 0xC2000000 handled by
        // fstart's EL3 exception vector. No-op if no EL3 exists.
        #[cfg(target_arch = "aarch64")]
        crate::arch::aarch64::ns_switch::install_ns_trampoline();
    } else {
        super::tcg::measured_boot::measure_action_all(
            5,
            "Exit Boot Services Returned with Failure",
        );
        log::warn!("ExitBootServices FAILED: {:?}", status);
    }

    status
}

// ============================================================================
// Miscellaneous Functions
// ============================================================================

extern "efiapi" fn get_next_monotonic_count(count: *mut u64) -> Status {
    if count.is_null() {
        return Status::INVALID_PARAMETER;
    }

    state::with_efi_mut(|efi_state| {
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
    let guid_name = super::guid_fmt::lookup_guid_name(&guid);
    log::debug!(
        "BS.OpenProtocol(handle={:?}, protocol={}, attr={:#x})",
        handle,
        GuidFmt(guid),
        attributes
    );

    let efi_state = state::efi();

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
    let efi_state = state::efi();
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

    let efi_state = state::efi();

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
                    state::with_efi_mut(|efi_state| {
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
        state::with_efi_mut(|efi_state| {
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

// ============================================================================
// Helper Functions
// ============================================================================

use super::guid_fmt::GuidFmt;

// GUID name lookup table has been extracted to efi/guid_fmt.rs
// (was ~350 lines of GUID-to-name mappings)
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
    let efi_state = state::efi();

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

#[derive(Clone, Copy)]
struct DeferredImageMeasurement {
    pcr_index: u32,
    event_type: u32,
    digest_count: usize,
    digests: [super::tcg::types::TaggedDigest; 5],
    event_data: *mut u8,
    event_data_size: usize,
}

pub(crate) fn serialize_tcg_image_load_event(
    loaded_image: &pe::LoadedImage,
    image_link_time_address: u64,
    device_path_ptr: *const DevicePathProtocol,
) -> Vec<u8> {
    let device_path_size = if device_path_ptr.is_null() {
        0
    } else {
        unsafe { super::protocols::device_path::device_path_size(device_path_ptr) }
    };

    let mut event = Vec::with_capacity(32 + device_path_size);
    event.extend_from_slice(&loaded_image.image_base.to_le_bytes());
    event.extend_from_slice(&loaded_image.image_size.to_le_bytes());
    event.extend_from_slice(&image_link_time_address.to_le_bytes());
    event.extend_from_slice(&(device_path_size as u64).to_le_bytes());
    if device_path_size != 0 {
        let device_path =
            unsafe { core::slice::from_raw_parts(device_path_ptr as *const u8, device_path_size) };
        event.extend_from_slice(device_path);
    }
    event
}

/// Measure or defer a PE/COFF image for TCG measured boot.
///
/// Driver images are measured immediately. Application image digests and event
/// data are precomputed here so `StartImage()` can log them after ReadyToBoot.
fn measure_pe_image_for_tcg(
    pe_data: &[u8],
    loaded_image: &pe::LoadedImage,
    device_path: *const DevicePathProtocol,
) -> Option<DeferredImageMeasurement> {
    use super::tcg::measured_boot::{measure_pe_image_all, precompute_pe_image_digests_all};
    use super::tcg::types::*;

    let headers = pe::parse_headers(pe_data).ok()?;
    let subsystem = headers.subsystem();
    let (pcr_index, event_type) = match subsystem {
        10 => (4, EV_EFI_BOOT_SERVICES_APPLICATION),
        11 => (2, EV_EFI_BOOT_SERVICES_DRIVER),
        12 => (2, EV_EFI_RUNTIME_SERVICES_DRIVER),
        _ => (4, EV_EFI_BOOT_SERVICES_APPLICATION),
    };

    let event_data =
        serialize_tcg_image_load_event(loaded_image, headers.preferred_image_base(), device_path);

    if subsystem != 10 {
        if let Err(e) = measure_pe_image_all(pcr_index, event_type, pe_data, &event_data) {
            log::warn!("Failed to measure PE image: {:?}", e);
        }
        return None;
    }

    let (digest_count, digests) = (match precompute_pe_image_digests_all(pe_data) {
        Ok(result) => result,
        Err(e) => {
            log::warn!("Failed to precompute PE image measurement: {:?}", e);
            None
        }
    })?;

    let event_data_size = event_data.len();
    let event_data_ptr =
        match allocator::allocate_pool(MemoryType::BootServicesData, event_data_size) {
            Ok(ptr) => ptr,
            Err(status) => {
                log::warn!(
                    "Failed to allocate deferred PE measurement event data: {:?}",
                    status
                );
                return None;
            }
        };
    unsafe {
        // SAFETY: `event_data_ptr` points to `event_data_size` bytes just
        // allocated above, and `event_data` has exactly that many initialized bytes.
        core::ptr::copy_nonoverlapping(event_data.as_ptr(), event_data_ptr, event_data_size);
    }

    Some(DeferredImageMeasurement {
        pcr_index,
        event_type,
        digest_count,
        digests,
        event_data: event_data_ptr,
        event_data_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_event_rejects_all_runtime_event_types() {
        assert!(boot_event_type_supported(0));
        assert!(boot_event_type_supported(EVT_NOTIFY_SIGNAL));
        assert!(!boot_event_type_supported(EVT_RUNTIME));
        assert!(!boot_event_type_supported(
            EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE
        ));
    }
}

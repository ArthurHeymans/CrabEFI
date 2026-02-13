//! EFI Runtime Services
//!
//! This module implements the EFI Runtime Services table, which provides
//! time, variable, and system reset services that persist after ExitBootServices.

use crate::arch::x86_64::io;
use crate::efi::auth;
use crate::state::{self, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN, MAX_VARIABLES};

// ============================================================================
// Runtime Serial Logging (post-SetVirtualAddressMap)
// ============================================================================
//
// After SetVirtualAddressMap, the `log` crate is disabled because its stored
// `&dyn Log` vtable pointer becomes a stale physical address. These functions
// write directly to the serial port (COM1, 0x3F8) using x86 port I/O, which
// is completely independent of the virtual memory address space.
//
// Gated behind the `rt-debug` feature flag (default off) to avoid overhead.

#[cfg(feature = "rt-debug")]
mod rt_serial {
    use super::*;

    /// COM1 base I/O port
    const COM1: u16 = 0x3F8;

    /// Write a single byte to the serial port (blocking, waits for TX ready).
    #[inline]
    pub fn byte(b: u8) {
        unsafe {
            // Wait for Transmitter Holding Register Empty (bit 5 of LSR)
            while io::inb(COM1 + 5) & 0x20 == 0 {
                core::hint::spin_loop();
            }
            io::outb(COM1, b);
        }
    }

    /// Write a string to the serial port (with \n -> \r\n conversion).
    pub fn str(s: &str) {
        for &b in s.as_bytes() {
            if b == b'\n' {
                byte(b'\r');
            }
            byte(b);
        }
    }

    /// Write a u64 as hex to the serial port.
    pub fn hex(val: u64) {
        str("0x");
        if val == 0 {
            byte(b'0');
            return;
        }
        let mut started = false;
        for i in (0..16).rev() {
            let nibble = ((val >> (i * 4)) & 0xF) as u8;
            if nibble != 0 || started {
                started = true;
                byte(if nibble < 10 {
                    b'0' + nibble
                } else {
                    b'a' + nibble - 10
                });
            }
        }
    }
}

/// Runtime serial print -- tagged with "[RT] " prefix.
/// No-op when the `rt-debug` feature is disabled.
macro_rules! rt_serial_print {
    ($msg:expr) => {
        #[cfg(feature = "rt-debug")]
        {
            rt_serial::str("[RT] ");
            rt_serial::str($msg);
            rt_serial::str("\n");
        }
    };
    ($msg:expr, $hex:expr) => {
        #[cfg(feature = "rt-debug")]
        {
            rt_serial::str("[RT] ");
            rt_serial::str($msg);
            rt_serial::hex($hex as u64);
            rt_serial::str("\n");
        }
    };
}

// ============================================================================
// Runtime Access Control
// ============================================================================

/// Check if a variable is accessible at runtime based on its attributes.
///
/// Per UEFI Specification Section 8.2:
/// - Variables with EFI_VARIABLE_BOOTSERVICE_ACCESS but without EFI_VARIABLE_RUNTIME_ACCESS
///   are only accessible before ExitBootServices() is called.
/// - After ExitBootServices(), these boot-services-only variables should return NOT_FOUND.
///
/// Returns true if the variable is accessible, false if it should be hidden at runtime.
#[inline]
fn is_variable_accessible_at_runtime(attributes: u32) -> bool {
    // If ExitBootServices hasn't been called, all variables are accessible
    if !state::is_exit_boot_services_called() {
        return true;
    }

    // At runtime, only variables with RUNTIME_ACCESS are accessible
    (attributes & auth::attributes::RUNTIME_ACCESS) != 0
}
use alloc::vec::Vec;
use core::ffi::c_void;
use r_efi::efi::{
    self, CapsuleHeader, Guid, ResetType, Status, TableHeader, Time, TimeCapabilities,
};

/// Runtime Services signature "RUNTSERV"
const EFI_RUNTIME_SERVICES_SIGNATURE: u64 = 0x56524553544E5552;

/// Runtime Services revision
const EFI_RUNTIME_SERVICES_REVISION: u32 = (2 << 16) | 100;

/// Static runtime services table
static mut RUNTIME_SERVICES: efi::RuntimeServices = efi::RuntimeServices {
    hdr: TableHeader {
        signature: EFI_RUNTIME_SERVICES_SIGNATURE,
        revision: EFI_RUNTIME_SERVICES_REVISION,
        header_size: core::mem::size_of::<efi::RuntimeServices>() as u32,
        crc32: 0,
        reserved: 0,
    },
    get_time,
    set_time,
    get_wakeup_time,
    set_wakeup_time,
    set_virtual_address_map,
    convert_pointer,
    get_variable,
    get_next_variable_name,
    set_variable,
    get_next_high_mono_count,
    reset_system,
    update_capsule,
    query_capsule_capabilities,
    query_variable_info,
};

/// Get a pointer to the runtime services table
pub fn get_runtime_services() -> *mut efi::RuntimeServices {
    &raw mut RUNTIME_SERVICES
}

/// Get the address of runtime services code (for memory map reservation)
///
/// Returns the address of the set_virtual_address_map function, which is used
/// to determine where the runtime services code section is located.
pub fn get_runtime_code_address() -> u64 {
    set_virtual_address_map as *const () as u64
}

// ============================================================================
// Time Services
// ============================================================================

extern "efiapi" fn get_time(time: *mut Time, capabilities: *mut TimeCapabilities) -> Status {
    #[cfg(feature = "rt-debug")]
    if unsafe { VIRTUAL_MODE } {
        rt_serial_print!("GetTime");
    }
    if time.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Read time from CMOS RTC (shared implementation in auth::time)
    let (year, month, day, hour, minute, second) = crate::efi::auth::time::read_rtc_time();

    unsafe {
        (*time).year = year;
        (*time).month = month;
        (*time).day = day;
        (*time).hour = hour;
        (*time).minute = minute;
        (*time).second = second;
        (*time).nanosecond = 0;
        (*time).timezone = efi::UNSPECIFIED_TIMEZONE;
        (*time).daylight = 0;
        (*time).pad1 = 0;
        (*time).pad2 = 0;
    }

    if !capabilities.is_null() {
        unsafe {
            (*capabilities).resolution = 1; // 1 second resolution
            (*capabilities).accuracy = 50_000_000; // 50ms accuracy
            (*capabilities).sets_to_zero = efi::Boolean::from(false);
        }
    }

    Status::SUCCESS
}

extern "efiapi" fn set_time(_time: *mut Time) -> Status {
    #[cfg(feature = "rt-debug")]
    if unsafe { VIRTUAL_MODE } {
        rt_serial_print!("SetTime -> UNSUPPORTED");
    }
    Status::UNSUPPORTED
}

extern "efiapi" fn get_wakeup_time(
    _enabled: *mut efi::Boolean,
    _pending: *mut efi::Boolean,
    _time: *mut Time,
) -> Status {
    #[cfg(feature = "rt-debug")]
    if unsafe { VIRTUAL_MODE } {
        rt_serial_print!("GetWakeupTime -> UNSUPPORTED");
    }
    Status::UNSUPPORTED
}

extern "efiapi" fn set_wakeup_time(_enable: efi::Boolean, _time: *mut Time) -> Status {
    #[cfg(feature = "rt-debug")]
    if unsafe { VIRTUAL_MODE } {
        rt_serial_print!("SetWakeupTime -> UNSUPPORTED");
    }
    Status::UNSUPPORTED
}

// ============================================================================
// Virtual Memory Services
// ============================================================================

/// EFI_OPTIONAL_PTR: if set, a NULL pointer is acceptable
const EFI_OPTIONAL_PTR: usize = 0x00000001;
/// EFI_MEMORY_RUNTIME attribute bit (bit 63)
const EFI_MEMORY_RUNTIME: u64 = 0x8000000000000000;
/// Page size constant
const EFI_PAGE_SIZE: u64 = 4096;

/// Global state for ConvertPointer -- only valid during SetVirtualAddressMap.
static mut VIRTUAL_MAP_PTR: *const u8 = core::ptr::null();
static mut VIRTUAL_MAP_DESCRIPTOR_SIZE: usize = 0;
static mut VIRTUAL_MAP_ENTRY_COUNT: usize = 0;
/// Whether SetVirtualAddressMap has been called (one-shot operation)
static mut VIRTUAL_MODE: bool = false;

extern "efiapi" fn set_virtual_address_map(
    memory_map_size: usize,
    descriptor_size: usize,
    descriptor_version: u32,
    virtual_map: *mut efi::MemoryDescriptor,
) -> Status {
    log::info!(
        "RT.SetVirtualAddressMap(size={}, desc_size={}, version={}, map={:?})",
        memory_map_size,
        descriptor_size,
        descriptor_version,
        virtual_map
    );

    unsafe {
        if VIRTUAL_MODE {
            return Status::UNSUPPORTED;
        }
    }

    if virtual_map.is_null() || descriptor_size == 0 {
        return Status::INVALID_PARAMETER;
    }

    if descriptor_size < core::mem::size_of::<efi::MemoryDescriptor>() {
        return Status::INVALID_PARAMETER;
    }

    let num_entries = memory_map_size / descriptor_size;

    // Sanity check: a realistic memory map has at most a few hundred entries.
    // Reject obviously corrupted sizes to prevent walking off into unmapped memory.
    const MAX_REASONABLE_ENTRIES: usize = 4096;
    if num_entries > MAX_REASONABLE_ENTRIES {
        log::error!(
            "SetVirtualAddressMap: unreasonable entry count {} (max {})",
            num_entries,
            MAX_REASONABLE_ENTRIES
        );
        return Status::INVALID_PARAMETER;
    }

    log::info!("SetVirtualAddressMap: {} entries", num_entries);

    // Step 0: Disable CBMEM console -- its buffer is not in a runtime region
    // and would page-fault after the OS switches to virtual addressing.
    crate::coreboot::cbmem_console::disable();

    // Step 1: Commit to virtual mode
    unsafe {
        VIRTUAL_MODE = true;
    }

    // Step 2: Set up globals so ConvertPointer can access the virtual map
    unsafe {
        VIRTUAL_MAP_PTR = virtual_map as *const u8;
        VIRTUAL_MAP_DESCRIPTOR_SIZE = descriptor_size;
        VIRTUAL_MAP_ENTRY_COUNT = num_entries;
    }

    // Step 3: Signal EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE events
    {
        use crate::efi::boot_services::{
            EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE, signal_event_group_for_runtime,
        };

        const EFI_EVENT_GROUP_VIRTUAL_ADDRESS_CHANGE: efi::Guid = efi::Guid::from_fields(
            0x13FA7698,
            0xC831,
            0x49C7,
            0x87,
            0xEA,
            &[0x8F, 0x43, 0xFC, 0xC2, 0x51, 0x96],
        );
        signal_event_group_for_runtime(&EFI_EVENT_GROUP_VIRTUAL_ADDRESS_CHANGE);

        // Signal legacy EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE events
        state::with_efi_mut(|efi_state| {
            for entry in efi_state.events.iter_mut() {
                if entry.event_type == EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE {
                    entry.signaled = true;
                    if let Some(func) = entry.notify_function {
                        func(core::ptr::null_mut(), entry.notify_context);
                    }
                }
            }
        });
    }

    // Step 4: Relocate our own internal pointers
    let state_phys = state::get() as *const _ as u64;
    let rt_ptr = get_runtime_services();
    let rt_phys = rt_ptr as u64;
    let mut state_relocated = false;

    for i in 0..num_entries {
        let desc = unsafe {
            &*((virtual_map as *const u8).add(i * descriptor_size) as *const efi::MemoryDescriptor)
        };

        if (desc.attribute & EFI_MEMORY_RUNTIME) == 0 {
            continue;
        }

        let phys_start = desc.physical_start;
        let phys_end = phys_start + desc.number_of_pages * EFI_PAGE_SIZE;
        let virt_start = desc.virtual_start;

        // Relocate STATE_PTR
        if !state_relocated && state_phys >= phys_start && state_phys < phys_end {
            let offset = virt_start as i64 - phys_start as i64;
            let new_state = (state_phys as i64 + offset) as u64;
            unsafe {
                state::relocate_state_ptr(new_state as *mut state::FirmwareState);
            }
            state_relocated = true;
            log::debug!(
                "SetVirtualAddressMap: relocated state ptr {:#x} -> {:#x}",
                state_phys,
                new_state
            );
        }

        // Relocate RuntimeServices function pointers
        if rt_phys >= phys_start && rt_phys < phys_end {
            let offset = virt_start as i64 - phys_start as i64;
            // NOTE: set_virtual_address_map and convert_pointer are NOT relocated
            // per EDK2 convention -- they are never called again after this point.
            unsafe {
                let rt = &mut *rt_ptr;
                relocate_fn_ptr(&mut rt.get_time, offset);
                relocate_fn_ptr(&mut rt.set_time, offset);
                relocate_fn_ptr(&mut rt.get_wakeup_time, offset);
                relocate_fn_ptr(&mut rt.set_wakeup_time, offset);
                relocate_fn_ptr(&mut rt.get_variable, offset);
                relocate_fn_ptr(&mut rt.get_next_variable_name, offset);
                relocate_fn_ptr(&mut rt.set_variable, offset);
                relocate_fn_ptr(&mut rt.get_next_high_mono_count, offset);
                relocate_fn_ptr(&mut rt.reset_system, offset);
                relocate_fn_ptr(&mut rt.update_capsule, offset);
                relocate_fn_ptr(&mut rt.query_capsule_capabilities, offset);
                relocate_fn_ptr(&mut rt.query_variable_info, offset);
            }
            log::debug!(
                "SetVirtualAddressMap: relocated RT function pointers (offset {:#x})",
                virt_start as i64 - phys_start as i64
            );
        }
    }

    // Step 4b: Relocate GOT (Global Offset Table) entries.
    //
    // With relocation-model=pic, the compiler emits `call *GOT(%rip)` for
    // compiler_builtins intrinsics (memcpy, memset, memmove, memcmp).
    // The linker fills these GOT entries with absolute physical addresses.
    // After SVAM, the physical addresses are unmapped, so we must adjust
    // each GOT entry by the appropriate virtual offset.
    {
        unsafe extern "C" {
            static _got_start: u8;
            static _got_end: u8;
        }
        let got_start = &raw const _got_start as *mut u64;
        let got_end = &raw const _got_end;
        let got_count = (got_end as usize - got_start as usize) / core::mem::size_of::<u64>();

        for slot in 0..got_count {
            let entry_ptr = unsafe { got_start.add(slot) };
            let phys_val = unsafe { core::ptr::read_volatile(entry_ptr) };

            // Find which runtime region this GOT entry points into
            for i in 0..num_entries {
                let desc = unsafe {
                    &*((virtual_map as *const u8).add(i * descriptor_size)
                        as *const efi::MemoryDescriptor)
                };
                if (desc.attribute & EFI_MEMORY_RUNTIME) == 0 {
                    continue;
                }
                let p_start = desc.physical_start;
                let p_end = p_start + desc.number_of_pages * EFI_PAGE_SIZE;
                if phys_val >= p_start && phys_val < p_end {
                    let offset = desc.virtual_start as i64 - p_start as i64;
                    let new_val = (phys_val as i64 + offset) as u64;
                    unsafe { core::ptr::write_volatile(entry_ptr, new_val) };
                    break;
                }
            }
        }
        log::debug!("SetVirtualAddressMap: relocated {} GOT entries", got_count);
    }

    // Step 5: Recompute CRC32 on RuntimeServices table (Windows validates this)
    unsafe {
        use super::boot_services::compute_crc32;
        let rt = &mut *rt_ptr;
        rt.hdr.crc32 = 0;
        let rt_bytes =
            core::slice::from_raw_parts(rt_ptr as *const u8, rt.hdr.header_size as usize);
        rt.hdr.crc32 = compute_crc32(rt_bytes);
    }

    // Step 6: Convert System Table pointers (firmware_vendor, configuration_table, runtime_services)
    // Per EDK2, we must also convert VendorTable pointers inside each configuration
    // table entry -- otherwise the OS dereferences stale physical addresses.
    {
        use super::system_table;
        let st = system_table::get_system_table();
        unsafe {
            // Convert VendorTable pointers inside each configuration table entry.
            // This MUST happen before converting the configuration_table pointer itself,
            // since we need the physical address to access the entries.
            // (EDK2: CoreConvertPointer for each ConfigurationTable[i].VendorTable)
            if !(*st).configuration_table.is_null() {
                let config = (*st).configuration_table;
                let count = (*st).number_of_table_entries;
                for i in 0..count {
                    let entry = &mut *config.add(i);
                    if !entry.vendor_table.is_null() {
                        // Use EFI_OPTIONAL_PTR: if the pointer doesn't fall in a
                        // runtime region (e.g. ACPI tables in ACPIReclaimMemory),
                        // ConvertPointer returns NOT_FOUND and we leave it unchanged.
                        let _ = convert_pointer_internal(0, &mut entry.vendor_table);
                    }
                }
            }

            // Convert firmware_vendor
            if !(*st).firmware_vendor.is_null() {
                let mut vendor_ptr = (*st).firmware_vendor as *mut c_void;
                if convert_pointer_internal(0, &mut vendor_ptr) == Status::SUCCESS {
                    (*st).firmware_vendor = vendor_ptr as *const u16;
                }
            }

            // Convert configuration_table pointer itself
            if !(*st).configuration_table.is_null() {
                let mut config_ptr = (*st).configuration_table as *mut c_void;
                if convert_pointer_internal(EFI_OPTIONAL_PTR, &mut config_ptr) == Status::SUCCESS {
                    (*st).configuration_table = config_ptr as *mut state::ConfigurationTable;
                }
            }

            // Convert runtime_services pointer
            if !(*st).runtime_services.is_null() {
                let mut rt_svc_ptr = (*st).runtime_services as *mut c_void;
                if convert_pointer_internal(0, &mut rt_svc_ptr) == Status::SUCCESS {
                    (*st).runtime_services = rt_svc_ptr as *mut efi::RuntimeServices;
                }
            }

            // Recompute System Table CRC32
            (*st).hdr.crc32 = 0;
            let st_bytes =
                core::slice::from_raw_parts(st as *const u8, (*st).hdr.header_size as usize);
            (*st).hdr.crc32 = super::boot_services::compute_crc32(st_bytes);
        }
    }

    // Step 7: Clear virtual map globals
    unsafe {
        VIRTUAL_MAP_PTR = core::ptr::null();
        VIRTUAL_MAP_DESCRIPTOR_SIZE = 0;
        VIRTUAL_MAP_ENTRY_COUNT = 0;
    }

    log::info!("SetVirtualAddressMap: complete, disabling log crate for virtual mode");

    // CRITICAL: Disable the log crate. After SVAM returns, the OS uses virtual
    // addresses. The log crate stores a &'static dyn Log fat pointer at physical
    // addresses -- any log! call would dereference stale pointers and page-fault.
    // Setting max_level to Off makes the log! macros short-circuit before any
    // pointer dereference.
    log::set_max_level(log::LevelFilter::Off);

    #[cfg(feature = "rt-debug")]
    rt_serial::str("[RT] SetVirtualAddressMap returning SUCCESS\n");

    Status::SUCCESS
}

/// Relocate a function pointer by a signed offset.
///
/// # Safety
///
/// The offset must produce a valid function address within the relocated region.
unsafe fn relocate_fn_ptr<T>(ptr: &mut T, offset: i64) {
    let old = core::ptr::read(ptr as *const T as *const u64);
    let new = (old as i64 + offset) as u64;
    core::ptr::write(ptr as *mut T as *mut u64, new);
}

/// Internal ConvertPointer implementation used by both the EFI callback and
/// our own SetVirtualAddressMap.
fn convert_pointer_internal(debug_disposition: usize, address: &mut *mut c_void) -> Status {
    let phys_addr = *address as u64;

    if phys_addr == 0 {
        return if (debug_disposition & EFI_OPTIONAL_PTR) != 0 {
            Status::SUCCESS
        } else {
            Status::INVALID_PARAMETER
        };
    }

    unsafe {
        if VIRTUAL_MAP_PTR.is_null() {
            return Status::NOT_FOUND;
        }

        for i in 0..VIRTUAL_MAP_ENTRY_COUNT {
            let desc = &*(VIRTUAL_MAP_PTR.add(i * VIRTUAL_MAP_DESCRIPTOR_SIZE)
                as *const efi::MemoryDescriptor);

            if (desc.attribute & EFI_MEMORY_RUNTIME) == 0 {
                continue;
            }

            let phys_end = desc.physical_start + desc.number_of_pages * EFI_PAGE_SIZE;
            if phys_addr >= desc.physical_start && phys_addr < phys_end {
                *address = (phys_addr - desc.physical_start + desc.virtual_start) as *mut c_void;
                return Status::SUCCESS;
            }
        }
    }

    Status::NOT_FOUND
}

extern "efiapi" fn convert_pointer(debug_disposition: usize, address: *mut *mut c_void) -> Status {
    if address.is_null() {
        return Status::INVALID_PARAMETER;
    }
    convert_pointer_internal(debug_disposition, unsafe { &mut *address })
}

// ============================================================================
// Variable Services
// ============================================================================

extern "efiapi" fn get_variable(
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut c_void,
) -> Status {
    #[cfg(feature = "rt-debug")]
    if unsafe { VIRTUAL_MODE } {
        rt_serial::str("[RT] GetVariable name=");
        if !variable_name.is_null() {
            for i in 0..32 {
                let c = unsafe { *variable_name.add(i) };
                if c == 0 {
                    break;
                }
                rt_serial::byte(c as u8);
            }
        }
        rt_serial::str("\n");
    }
    if variable_name.is_null() || vendor_guid.is_null() || data_size.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let name = variable_name;
    let guid = unsafe { *vendor_guid };

    // Check for synthesized Secure Boot status variables
    if guid == auth::EFI_GLOBAL_VARIABLE_GUID {
        // Check for SetupMode variable
        if name_eq_const(name, auth::SETUP_MODE_NAME) {
            return get_secure_boot_status_variable(
                auth::is_setup_mode() as u8,
                attributes,
                data_size,
                data,
            );
        }

        // Check for SecureBoot variable
        if name_eq_const(name, auth::SECURE_BOOT_NAME) {
            return get_secure_boot_status_variable(
                auth::is_secure_boot_enabled() as u8,
                attributes,
                data_size,
                data,
            );
        }
    }

    let efi = state::efi();
    let variables = &efi.variables;

    // Find the variable using iterator
    let found = variables
        .iter()
        .find(|var| var.in_use && var.vendor_guid == guid && name_eq(&var.name, name));

    match found {
        Some(var) => {
            // Check if variable is accessible at runtime
            // Boot-services-only variables are hidden after ExitBootServices
            if !is_variable_accessible_at_runtime(var.attributes) {
                return Status::NOT_FOUND;
            }

            let required_size = var.data_size;

            if data.is_null() || unsafe { *data_size } < required_size {
                unsafe { *data_size = required_size };
                return Status::BUFFER_TOO_SMALL;
            }

            // Copy data
            unsafe {
                core::ptr::copy_nonoverlapping(var.data.as_ptr(), data as *mut u8, required_size);
                *data_size = required_size;
                if !attributes.is_null() {
                    *attributes = var.attributes;
                }
            }

            Status::SUCCESS
        }
        None => Status::NOT_FOUND,
    }
}

/// Helper function for returning Secure Boot status variables
fn get_secure_boot_status_variable(
    value: u8,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut c_void,
) -> Status {
    let required_size = 1usize;

    if data.is_null() || unsafe { *data_size } < required_size {
        unsafe { *data_size = required_size };
        return Status::BUFFER_TOO_SMALL;
    }

    unsafe {
        *(data as *mut u8) = value;
        *data_size = required_size;
        if !attributes.is_null() {
            // These are read-only boot services + runtime access variables
            *attributes = auth::attributes::BOOTSERVICE_ACCESS | auth::attributes::RUNTIME_ACCESS;
        }
    }

    Status::SUCCESS
}

/// Check if a stored variable would shadow a synthesized variable.
///
/// We synthesize SetupMode and SecureBoot variables with EFI_GLOBAL_VARIABLE_GUID.
/// If a stored variable has the same name and GUID, we must skip it during
/// enumeration to avoid infinite loops.
fn is_synthesized_variable(name: &[u16], guid: &Guid) -> bool {
    if *guid != auth::EFI_GLOBAL_VARIABLE_GUID {
        return false;
    }
    // Check if name matches SetupMode or SecureBoot
    name_eq_slice(name, auth::SETUP_MODE_NAME) || name_eq_slice(name, auth::SECURE_BOOT_NAME)
}

/// Compare two UCS-2 slices for equality (delegates to shared utility)
fn name_eq_slice(a: &[u16], b: &[u16]) -> bool {
    crate::efi::utils::ucs2_eq(a, b)
}

/// Compare a pointer-based UCS-2 string with a constant UCS-2 slice
///
/// Bounded by the expected slice length + 1 (for null terminator check)
/// to avoid unbounded reads from the name pointer.
fn name_eq_const(name: *const u16, expected: &[u16]) -> bool {
    let expected_len = crate::efi::utils::ucs2_len(expected);
    let matches = (0..expected_len).all(|i| {
        let a = unsafe { *name.add(i) };
        a == expected[i]
    });
    // Check that the name pointer is also null-terminated at this position
    matches && unsafe { *name.add(expected_len) == 0 }
}

extern "efiapi" fn get_next_variable_name(
    variable_name_size: *mut usize,
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
) -> Status {
    #[cfg(feature = "rt-debug")]
    if unsafe { VIRTUAL_MODE } {
        rt_serial::str("[RT] GetNextVariableName name=");
        if !variable_name.is_null() {
            for i in 0..32 {
                let c = unsafe { *variable_name.add(i) };
                if c == 0 {
                    break;
                }
                rt_serial::byte(c as u8);
            }
        }
        rt_serial::str("\n");
    }
    if variable_name_size.is_null() || variable_name.is_null() || vendor_guid.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let current_name = variable_name;
    let current_guid = unsafe { *vendor_guid };

    // Debug: log input (only first 16 chars of name to avoid huge logs)
    let mut input_name_buf = [0u8; 32];
    let input_name_len = unsafe {
        let mut i = 0;
        while i < 16 {
            let c = *current_name.add(i);
            if c == 0 {
                break;
            }
            input_name_buf[i] = c as u8;
            i += 1;
        }
        i
    };
    let input_name_str = core::str::from_utf8(&input_name_buf[..input_name_len]).unwrap_or("?");
    // Convert GUID to bytes for logging (first 4 bytes)
    let guid_bytes: [u8; 16] = unsafe { core::mem::transmute(current_guid) };
    log::trace!(
        "GetNextVariableName: input name='{}' guid={:02x}{:02x}{:02x}{:02x}-...",
        input_name_str,
        guid_bytes[0],
        guid_bytes[1],
        guid_bytes[2],
        guid_bytes[3]
    );

    // If name is empty, return first synthesized variable (SetupMode)
    let is_first = unsafe { *current_name == 0 };

    if is_first {
        log::trace!("GetNextVariableName: first call, returning SetupMode");
        // Return SetupMode as the first variable
        return copy_variable_name(
            auth::SETUP_MODE_NAME,
            auth::EFI_GLOBAL_VARIABLE_GUID,
            variable_name_size,
            variable_name,
            vendor_guid,
        );
    }

    // Check if current variable is a synthesized Secure Boot variable
    // and return the next one in sequence
    if current_guid == auth::EFI_GLOBAL_VARIABLE_GUID {
        if name_eq_const(current_name, auth::SETUP_MODE_NAME) {
            log::trace!("GetNextVariableName: after SetupMode, returning SecureBoot");
            // After SetupMode, return SecureBoot
            return copy_variable_name(
                auth::SECURE_BOOT_NAME,
                auth::EFI_GLOBAL_VARIABLE_GUID,
                variable_name_size,
                variable_name,
                vendor_guid,
            );
        }

        if name_eq_const(current_name, auth::SECURE_BOOT_NAME) {
            // After SecureBoot, continue with the first stored variable
            // that is accessible at runtime (if we're at runtime)
            // IMPORTANT: Skip any stored variables that shadow our synthesized
            // variables (SetupMode, SecureBoot with EFI_GLOBAL_VARIABLE_GUID)
            // to avoid infinite enumeration loops.
            let efi = state::efi();
            let variables = &efi.variables;

            if let Some(var) = variables.iter().find(|var| {
                var.in_use
                    && is_variable_accessible_at_runtime(var.attributes)
                    && !is_synthesized_variable(&var.name, &var.vendor_guid)
            }) {
                log::trace!("GetNextVariableName: after SecureBoot, returning first stored var");
                return copy_stored_variable_name(
                    var,
                    variable_name_size,
                    variable_name,
                    vendor_guid,
                );
            }
            log::trace!(
                "GetNextVariableName: after SecureBoot, no stored vars, returning NOT_FOUND"
            );
            return Status::NOT_FOUND;
        }
    }

    // Search in stored variables
    let efi = state::efi();
    let variables = &efi.variables;

    // Count how many variables are accessible (excluding synthesized ones)
    let accessible_count = variables
        .iter()
        .filter(|var| {
            var.in_use
                && is_variable_accessible_at_runtime(var.attributes)
                && !is_synthesized_variable(&var.name, &var.vendor_guid)
        })
        .count();

    // Create iterator over in-use variables and skip to next after current
    // Filter by runtime accessibility to hide boot-services-only variables after ExitBootServices
    // Also skip synthesized variables (SetupMode, SecureBoot) which we handle separately
    let next_var = variables
        .iter()
        .filter(|var| {
            var.in_use
                && is_variable_accessible_at_runtime(var.attributes)
                && !is_synthesized_variable(&var.name, &var.vendor_guid)
        })
        .skip_while(|var| !(var.vendor_guid == current_guid && name_eq(&var.name, current_name)))
        .nth(1); // Skip the current one and get the next

    match next_var {
        Some(var) => {
            log::trace!(
                "GetNextVariableName: returning next stored var (total accessible: {})",
                accessible_count
            );
            copy_stored_variable_name(var, variable_name_size, variable_name, vendor_guid)
        }
        None => {
            log::trace!(
                "GetNextVariableName: no more vars, returning NOT_FOUND (total accessible: {})",
                accessible_count
            );
            Status::NOT_FOUND
        }
    }
}

/// Copy a constant variable name to the output buffer
fn copy_variable_name(
    name: &[u16],
    guid: Guid,
    variable_name_size: *mut usize,
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
) -> Status {
    let name_len = name.iter().position(|&c| c == 0).unwrap_or(name.len()) + 1;
    let required_size = name_len * 2;

    if unsafe { *variable_name_size } < required_size {
        unsafe { *variable_name_size = required_size };
        return Status::BUFFER_TOO_SMALL;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(name.as_ptr(), variable_name, name_len);
        *vendor_guid = guid;
        *variable_name_size = required_size;
    }

    Status::SUCCESS
}

/// Copy a stored variable name to the output buffer
fn copy_stored_variable_name(
    var: &crate::state::VariableEntry,
    variable_name_size: *mut usize,
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
) -> Status {
    let name_len = crate::efi::utils::ucs2_len(&var.name) + 1; // Include null terminator
    let required_size = name_len * 2;

    if unsafe { *variable_name_size } < required_size {
        unsafe { *variable_name_size = required_size };
        return Status::BUFFER_TOO_SMALL;
    }

    unsafe {
        core::ptr::copy_nonoverlapping(var.name.as_ptr(), variable_name, name_len);
        *vendor_guid = var.vendor_guid;
        *variable_name_size = required_size;
    }

    Status::SUCCESS
}

extern "efiapi" fn set_variable(
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
    attributes: u32,
    data_size: usize,
    data: *mut c_void,
) -> Status {
    #[cfg(feature = "rt-debug")]
    if unsafe { VIRTUAL_MODE } {
        rt_serial::str("[RT] SetVariable name=");
        if !variable_name.is_null() {
            for i in 0..32 {
                let c = unsafe { *variable_name.add(i) };
                if c == 0 {
                    break;
                }
                rt_serial::byte(c as u8);
            }
        }
        rt_serial::str(" attr=");
        rt_serial::hex(attributes as u64);
        rt_serial::str(" size=");
        rt_serial::hex(data_size as u64);
        rt_serial::str("\n");
    }
    if variable_name.is_null() || vendor_guid.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let name = variable_name;
    let guid = unsafe { *vendor_guid };

    // Check name length
    let name_len = ucs2_strlen_ptr(name);
    if name_len == 0 || name_len >= MAX_VARIABLE_NAME_LEN {
        return Status::INVALID_PARAMETER;
    }

    // Check data size
    if data_size > MAX_VARIABLE_DATA_SIZE {
        return Status::OUT_OF_RESOURCES;
    }

    if data_size > 0 && data.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Check if we're at runtime and trying to modify a boot-services-only variable
    // Per UEFI spec, BS-only variables cannot be modified at runtime
    if state::is_exit_boot_services_called() {
        let has_runtime_access = (attributes & auth::attributes::RUNTIME_ACCESS) != 0;
        if !has_runtime_access {
            log::debug!(
                "Rejecting SetVariable at runtime: variable lacks RUNTIME_ACCESS attribute"
            );
            return Status::INVALID_PARAMETER;
        }
    }

    // Check if this is a read-only variable that cannot be written via SetVariable
    // SecureBoot and SetupMode are computed status variables, not writable
    let name_slice = unsafe { core::slice::from_raw_parts(name, name_len + 1) };
    if guid == auth::EFI_GLOBAL_VARIABLE_GUID
        && (name_slice == auth::SECURE_BOOT_NAME || name_slice == auth::SETUP_MODE_NAME)
    {
        log::debug!(
            "Rejecting write to read-only variable: {:?}",
            if name_slice == auth::SECURE_BOOT_NAME {
                "SecureBoot"
            } else {
                "SetupMode"
            }
        );
        return Status::WRITE_PROTECTED;
    }

    // Check if this is an authenticated variable write
    let is_authenticated =
        (attributes & auth::attributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS) != 0;
    let is_append = (attributes & auth::attributes::APPEND_WRITE) != 0;

    // Process the data - for authenticated writes, we need to verify and extract
    let (actual_data, actual_data_size) = if is_authenticated && data_size > 0 {
        // Convert the data to a slice for the auth module
        let raw_data = unsafe { core::slice::from_raw_parts(data as *const u8, data_size) };

        // Convert name to slice for the auth module
        let name_slice = unsafe { core::slice::from_raw_parts(name, name_len + 1) };

        // Verify the authenticated variable and extract the actual data
        match auth::verify_authenticated_variable(name_slice, &guid, attributes, raw_data) {
            Ok(verified_data) => {
                // Store the verified data temporarily
                // Note: This will be copied into the variable store
                (Some(verified_data), 0usize) // size will be taken from Vec
            }
            Err(e) => {
                log::warn!("Authenticated variable verification failed: {:?}", e);
                return e.into();
            }
        }
    } else {
        (None, data_size)
    };

    // Get the actual data slice to store
    let (data_ptr, final_data_size): (*const u8, usize) = match &actual_data {
        Some(vec) => (vec.as_ptr(), vec.len()),
        None => (data as *const u8, actual_data_size),
    };

    // Check if this is a Secure Boot key database variable
    let secure_boot_var = auth::identify_key_database(
        unsafe { core::slice::from_raw_parts(name, name_len + 1) },
        &guid,
    );

    state::with_efi_mut(|efi| {
        let variables = &mut efi.variables;

        // Find existing variable using position()
        let existing_idx = variables
            .iter()
            .position(|var| var.in_use && var.vendor_guid == guid && name_eq(&var.name, name));

        // Find first free slot using position()
        let free_idx = variables.iter().position(|var| !var.in_use);

        // Delete variable if data_size is 0 (for authenticated vars, this means empty after header)
        if final_data_size == 0 {
            if let Some(idx) = existing_idx {
                variables[idx].in_use = false;

                // Handle Secure Boot state changes
                if let Some(var_type) = secure_boot_var {
                    handle_secure_boot_variable_delete(var_type);
                }

                // Persist the deletion to storage
                let name_slice = unsafe { core::slice::from_raw_parts(name, name_len + 1) };
                if let Err(e) = crate::efi::varstore::delete_variable(&guid, name_slice) {
                    log::debug!("Variable deletion not persisted: {:?}", e);
                }

                return Status::SUCCESS;
            }
            return Status::NOT_FOUND;
        }

        // Handle APPEND_WRITE for signature databases
        if is_append
            && let Some(idx) = existing_idx
            && let Some(var_type) = secure_boot_var
        {
            let existing_data = &variables[idx].data[..variables[idx].data_size];

            // Append the new signature lists to existing data
            match append_signature_data(existing_data, data_ptr, final_data_size, var_type) {
                Ok(combined) => {
                    if combined.len() > MAX_VARIABLE_DATA_SIZE {
                        return Status::OUT_OF_RESOURCES;
                    }

                    variables[idx].data[..combined.len()].copy_from_slice(&combined);
                    variables[idx].data_size = combined.len();

                    // Update the key database
                    update_key_database(var_type, &combined);

                    // Persist the updated variable
                    if (attributes & crate::efi::auth::attributes::NON_VOLATILE) != 0 {
                        let name_slice = unsafe { core::slice::from_raw_parts(name, name_len + 1) };
                        if let Err(e) = crate::efi::varstore::persist_variable(
                            &guid, name_slice, attributes, &combined,
                        ) {
                            log::debug!("Variable not persisted: {:?}", e);
                        }
                    }

                    return Status::SUCCESS;
                }
                Err(e) => return e.into(),
            }
        }

        // Update or create variable
        let idx = match existing_idx {
            Some(i) => i,
            None => match free_idx {
                Some(i) => i,
                None => return Status::OUT_OF_RESOURCES,
            },
        };

        // Check final data size fits
        if final_data_size > MAX_VARIABLE_DATA_SIZE {
            return Status::OUT_OF_RESOURCES;
        }

        // Copy name using slice operations
        let src = unsafe { core::slice::from_raw_parts(name, name_len + 1) };
        variables[idx].name[..name_len + 1].copy_from_slice(src);
        variables[idx].name[name_len + 1..].fill(0);

        // Copy data
        unsafe {
            core::ptr::copy_nonoverlapping(
                data_ptr,
                variables[idx].data.as_mut_ptr(),
                final_data_size,
            );
        }

        variables[idx].vendor_guid = guid;
        variables[idx].attributes = attributes;
        variables[idx].data_size = final_data_size;
        variables[idx].in_use = true;

        // Update Secure Boot key databases and state
        if let Some(var_type) = secure_boot_var {
            let var_data = &variables[idx].data[..final_data_size];
            update_key_database(var_type, var_data);
            handle_secure_boot_variable_update(var_type);
        }

        // Persist variable to storage (SPI flash or ESP file)
        // Only persist non-volatile variables
        if (attributes & crate::efi::auth::attributes::NON_VOLATILE) != 0 {
            let name_slice = unsafe { core::slice::from_raw_parts(name, name_len + 1) };
            let data_slice = unsafe { core::slice::from_raw_parts(data_ptr, final_data_size) };
            if let Err(e) =
                crate::efi::varstore::persist_variable(&guid, name_slice, attributes, data_slice)
            {
                log::debug!("Variable not persisted: {:?}", e);
                // Don't fail the operation - in-memory storage succeeded
            }
        }

        Status::SUCCESS
    })
}

/// Handle Secure Boot state changes when a key database variable is updated
fn handle_secure_boot_variable_update(var_type: auth::SecureBootVariable) {
    match var_type {
        auth::SecureBootVariable::PK => {
            // PK enrollment transitions from Setup Mode to User Mode
            if auth::is_setup_mode() {
                auth::enter_user_mode();
                auth::enable_secure_boot();
            }
        }
        _ => {
            // Other variables don't change Secure Boot state
        }
    }
}

/// Handle Secure Boot state changes when a key database variable is deleted
fn handle_secure_boot_variable_delete(var_type: auth::SecureBootVariable) {
    match var_type {
        auth::SecureBootVariable::PK => {
            // PK deletion transitions from User Mode to Setup Mode
            auth::enter_setup_mode();
            // Clear the PK database
            auth::pk_database().clear();
        }
        auth::SecureBootVariable::KEK => {
            auth::kek_database().clear();
        }
        auth::SecureBootVariable::Db => {
            auth::db_database().clear();
        }
        auth::SecureBootVariable::Dbx => {
            auth::dbx_database().clear();
        }
    }
}

/// Update the in-memory key database from variable data
fn update_key_database(var_type: auth::SecureBootVariable, data: &[u8]) {
    let result = match var_type {
        auth::SecureBootVariable::PK => {
            let mut db = auth::pk_database();
            db.clear();
            db.load_from_signature_lists(data)
        }
        auth::SecureBootVariable::KEK => {
            let mut db = auth::kek_database();
            db.clear();
            db.load_from_signature_lists(data)
        }
        auth::SecureBootVariable::Db => {
            let mut db = auth::db_database();
            db.clear();
            db.load_from_signature_lists(data)
        }
        auth::SecureBootVariable::Dbx => {
            let mut db = auth::dbx_database();
            db.clear();
            db.load_from_signature_lists(data)
        }
    };

    if let Err(e) = result {
        log::warn!(
            "Failed to parse signature lists for {:?}: {:?}",
            var_type,
            e
        );
    }
}

/// Append signature data for APPEND_WRITE operations
fn append_signature_data(
    existing: &[u8],
    new_data: *const u8,
    new_size: usize,
    _var_type: auth::SecureBootVariable,
) -> Result<Vec<u8>, auth::AuthError> {
    // For signature databases, we concatenate the signature lists
    let mut combined = Vec::with_capacity(existing.len() + new_size);
    combined.extend_from_slice(existing);

    let new_slice = unsafe { core::slice::from_raw_parts(new_data, new_size) };
    combined.extend_from_slice(new_slice);

    Ok(combined)
}

extern "efiapi" fn query_variable_info(
    attributes: u32,
    maximum_variable_storage_size: *mut u64,
    remaining_variable_storage_size: *mut u64,
    maximum_variable_size: *mut u64,
) -> Status {
    #[cfg(feature = "rt-debug")]
    if unsafe { VIRTUAL_MODE } {
        rt_serial_print!("QueryVariableInfo attr=", attributes);
    }
    if maximum_variable_storage_size.is_null()
        || remaining_variable_storage_size.is_null()
        || maximum_variable_size.is_null()
    {
        return Status::INVALID_PARAMETER;
    }

    // We don't really care about attributes for our in-memory store
    let _ = attributes;

    let efi = state::efi();
    let variables = &efi.variables;
    let total_size = MAX_VARIABLES * MAX_VARIABLE_DATA_SIZE;

    let used_size: usize = variables
        .iter()
        .filter(|var| var.in_use)
        .map(|var| var.data_size)
        .sum();

    unsafe {
        *maximum_variable_storage_size = total_size as u64;
        *remaining_variable_storage_size = (total_size - used_size) as u64;
        *maximum_variable_size = MAX_VARIABLE_DATA_SIZE as u64;
    }

    Status::SUCCESS
}

// ============================================================================
// Miscellaneous Services
// ============================================================================

extern "efiapi" fn get_next_high_mono_count(_high_count: *mut u32) -> Status {
    #[cfg(feature = "rt-debug")]
    if unsafe { VIRTUAL_MODE } {
        rt_serial_print!("GetNextHighMonoCount -> UNSUPPORTED");
    }
    Status::UNSUPPORTED
}

extern "efiapi" fn reset_system(
    reset_type: ResetType,
    _reset_status: Status,
    _data_size: usize,
    _reset_data: *mut c_void,
) {
    // Use rt_serial_print! instead of log:: — after SetVirtualAddressMap the log
    // crate's vtable pointer is stale and would page-fault.
    rt_serial_print!("ResetSystem called");

    // Try different reset methods
    match reset_type {
        efi::RESET_COLD | efi::RESET_WARM => {
            // Try keyboard controller reset
            unsafe {
                // Wait for keyboard controller to be ready
                for _ in 0..1000 {
                    let status = x86_in8(0x64);
                    if status & 0x02 == 0 {
                        break;
                    }
                }
                // Send reset command
                x86_out8(0x64, 0xFE);
            }

            // If that didn't work, try triple fault
            unsafe {
                // Load a null IDT and trigger an interrupt
                let null_idt: [u8; 6] = [0; 6];
                core::arch::asm!(
                    "lidt [{}]",
                    "int3",
                    in(reg) null_idt.as_ptr(),
                    options(noreturn)
                );
            }
        }
        efi::RESET_SHUTDOWN => {
            rt_serial_print!("Shutdown not implemented, halting");
        }
        _ => {}
    }

    // If all else fails, halt
    loop {
        unsafe { core::arch::asm!("hlt") };
    }
}

extern "efiapi" fn update_capsule(
    _capsule_header_array: *mut *mut CapsuleHeader,
    _capsule_count: usize,
    _scatter_gather_list: efi::PhysicalAddress,
) -> Status {
    #[cfg(feature = "rt-debug")]
    if unsafe { VIRTUAL_MODE } {
        rt_serial_print!("UpdateCapsule -> UNSUPPORTED");
    }
    Status::UNSUPPORTED
}

extern "efiapi" fn query_capsule_capabilities(
    _capsule_header_array: *mut *mut CapsuleHeader,
    _capsule_count: usize,
    _maximum_capsule_size: *mut u64,
    _reset_type: *mut ResetType,
) -> Status {
    #[cfg(feature = "rt-debug")]
    if unsafe { VIRTUAL_MODE } {
        rt_serial_print!("QueryCapsuleCapabilities -> UNSUPPORTED");
    }
    Status::UNSUPPORTED
}

// ============================================================================
// Helper Functions
// ============================================================================

// read_rtc_time is now shared via crate::efi::auth::time::read_rtc_time()

/// Port I/O functions - wrapper for arch module
#[inline]
unsafe fn x86_out8(port: u16, value: u8) {
    io::outb(port, value);
}

#[inline]
unsafe fn x86_in8(port: u16) -> u8 {
    io::inb(port)
}

/// Compare a UCS-2 string in array with a pointer
fn name_eq(stored: &[u16], name: *const u16) -> bool {
    let mut i = 0;
    loop {
        let a = stored.get(i).copied().unwrap_or(0);
        let b = unsafe { *name.add(i) };
        if a != b {
            return false;
        }
        if a == 0 {
            return true;
        }
        i += 1;
    }
}

// ucs2_strlen consolidated into crate::efi::utils::ucs2_len

/// Get length of UCS-2 string from pointer (not including null terminator)
///
/// Bounded to MAX_VARIABLE_NAME_LEN to prevent unbounded reads from
/// potentially malformed (non-null-terminated) buffers.
fn ucs2_strlen_ptr(s: *const u16) -> usize {
    let mut len = 0;
    unsafe {
        while len < MAX_VARIABLE_NAME_LEN && *s.add(len) != 0 {
            len += 1;
        }
    }
    len
}

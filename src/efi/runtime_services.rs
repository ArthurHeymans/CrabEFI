//! EFI Runtime Services
//!
//! This module implements the EFI Runtime Services table, which provides
//! time, variable, and system reset services that persist after ExitBootServices.

use core::ffi::c_void;
use r_efi::efi::{
    self, CapsuleHeader, Guid, ResetType, Status, TableHeader, Time, TimeCapabilities,
};
use spin::Mutex;

/// Runtime Services signature "RUNTSERV"
const EFI_RUNTIME_SERVICES_SIGNATURE: u64 = 0x56524553544E5552;

/// Runtime Services revision
const EFI_RUNTIME_SERVICES_REVISION: u32 = (2 << 16) | 100;

/// Maximum number of EFI variables we can store
const MAX_VARIABLES: usize = 64;

/// Maximum variable name length (in characters)
const MAX_VARIABLE_NAME_LEN: usize = 64;

/// Maximum variable data size
const MAX_VARIABLE_DATA_SIZE: usize = 1024;

/// EFI Variable entry
struct VariableEntry {
    /// Variable name (UCS-2, null-terminated)
    name: [u16; MAX_VARIABLE_NAME_LEN],
    /// Vendor GUID
    vendor_guid: Guid,
    /// Variable attributes
    attributes: u32,
    /// Data
    data: [u8; MAX_VARIABLE_DATA_SIZE],
    /// Data size
    data_size: usize,
    /// Whether this entry is in use
    in_use: bool,
}

impl VariableEntry {
    const fn empty() -> Self {
        Self {
            name: [0u16; MAX_VARIABLE_NAME_LEN],
            vendor_guid: Guid::from_fields(0, 0, 0, 0, 0, &[0, 0, 0, 0, 0, 0]),
            attributes: 0,
            data: [0u8; MAX_VARIABLE_DATA_SIZE],
            data_size: 0,
            in_use: false,
        }
    }
}

/// Variable store
static VARIABLES: Mutex<[VariableEntry; MAX_VARIABLES]> =
    Mutex::new([const { VariableEntry::empty() }; MAX_VARIABLES]);

/// Static runtime services table
static mut RUNTIME_SERVICES: efi::RuntimeServices = efi::RuntimeServices {
    hdr: TableHeader {
        signature: EFI_RUNTIME_SERVICES_SIGNATURE,
        revision: EFI_RUNTIME_SERVICES_REVISION,
        header_size: core::mem::size_of::<efi::RuntimeServices>() as u32,
        crc32: 0,
        reserved: 0,
    },
    get_time: get_time,
    set_time: set_time,
    get_wakeup_time: get_wakeup_time,
    set_wakeup_time: set_wakeup_time,
    set_virtual_address_map: set_virtual_address_map,
    convert_pointer: convert_pointer,
    get_variable: get_variable,
    get_next_variable_name: get_next_variable_name,
    set_variable: set_variable,
    get_next_high_mono_count: get_next_high_mono_count,
    reset_system: reset_system,
    update_capsule: update_capsule,
    query_capsule_capabilities: query_capsule_capabilities,
    query_variable_info: query_variable_info,
};

/// Get a pointer to the runtime services table
pub fn get_runtime_services() -> *mut efi::RuntimeServices {
    &raw mut RUNTIME_SERVICES
}

// ============================================================================
// Time Services
// ============================================================================

extern "efiapi" fn get_time(time: *mut Time, capabilities: *mut TimeCapabilities) -> Status {
    if time.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Read time from CMOS RTC
    let (year, month, day, hour, minute, second) = read_rtc_time();

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
    // Writing to RTC is typically not needed for boot
    Status::UNSUPPORTED
}

extern "efiapi" fn get_wakeup_time(
    _enabled: *mut efi::Boolean,
    _pending: *mut efi::Boolean,
    _time: *mut Time,
) -> Status {
    Status::UNSUPPORTED
}

extern "efiapi" fn set_wakeup_time(_enable: efi::Boolean, _time: *mut Time) -> Status {
    Status::UNSUPPORTED
}

// ============================================================================
// Virtual Memory Services
// ============================================================================

extern "efiapi" fn set_virtual_address_map(
    _memory_map_size: usize,
    _descriptor_size: usize,
    _descriptor_version: u32,
    _virtual_map: *mut efi::MemoryDescriptor,
) -> Status {
    // For now, we don't support virtual address remapping
    // The OS can use identity mapping
    Status::SUCCESS
}

extern "efiapi" fn convert_pointer(
    _debug_disposition: usize,
    _address: *mut *mut c_void,
) -> Status {
    Status::UNSUPPORTED
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
    if variable_name.is_null() || vendor_guid.is_null() || data_size.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let name = variable_name;
    let guid = unsafe { *vendor_guid };
    let variables = VARIABLES.lock();

    // Find the variable
    for var in variables.iter() {
        if !var.in_use {
            continue;
        }

        if guid_eq(&var.vendor_guid, &guid) && name_eq(&var.name, name) {
            // Found it
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

            return Status::SUCCESS;
        }
    }

    Status::NOT_FOUND
}

extern "efiapi" fn get_next_variable_name(
    variable_name_size: *mut usize,
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
) -> Status {
    if variable_name_size.is_null() || variable_name.is_null() || vendor_guid.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let variables = VARIABLES.lock();
    let current_name = variable_name;
    let current_guid = unsafe { *vendor_guid };

    // If name is empty, return first variable
    let is_first = unsafe { *current_name == 0 };

    let mut found_current = is_first;
    for var in variables.iter() {
        if !var.in_use {
            continue;
        }

        if found_current {
            // Return this variable
            let name_len = ucs2_strlen(&var.name) + 1; // Include null terminator
            let required_size = name_len * 2;

            if unsafe { *variable_name_size } < required_size {
                unsafe { *variable_name_size = required_size };
                return Status::BUFFER_TOO_SMALL;
            }

            // Copy name and GUID
            unsafe {
                core::ptr::copy_nonoverlapping(var.name.as_ptr(), variable_name, name_len);
                *vendor_guid = var.vendor_guid;
                *variable_name_size = required_size;
            }

            return Status::SUCCESS;
        }

        // Check if this is the current variable
        if guid_eq(&var.vendor_guid, &current_guid) && name_eq(&var.name, current_name) {
            found_current = true;
        }
    }

    Status::NOT_FOUND
}

extern "efiapi" fn set_variable(
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
    attributes: u32,
    data_size: usize,
    data: *mut c_void,
) -> Status {
    if variable_name.is_null() || vendor_guid.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let name = variable_name;
    let guid = unsafe { *vendor_guid };
    let mut variables = VARIABLES.lock();

    // Check name length
    let name_len = ucs2_strlen_ptr(name);
    if name_len == 0 || name_len >= MAX_VARIABLE_NAME_LEN {
        return Status::INVALID_PARAMETER;
    }

    // Find existing variable or free slot
    let mut existing_idx: Option<usize> = None;
    let mut free_idx: Option<usize> = None;

    for (i, var) in variables.iter().enumerate() {
        if var.in_use {
            if guid_eq(&var.vendor_guid, &guid) && name_eq(&var.name, name) {
                existing_idx = Some(i);
                break;
            }
        } else if free_idx.is_none() {
            free_idx = Some(i);
        }
    }

    // Delete variable if data_size is 0
    if data_size == 0 {
        if let Some(idx) = existing_idx {
            variables[idx].in_use = false;
            return Status::SUCCESS;
        }
        return Status::NOT_FOUND;
    }

    // Check data size
    if data_size > MAX_VARIABLE_DATA_SIZE {
        return Status::OUT_OF_RESOURCES;
    }

    if data.is_null() {
        return Status::INVALID_PARAMETER;
    }

    // Update or create variable
    let idx = match existing_idx {
        Some(i) => i,
        None => match free_idx {
            Some(i) => i,
            None => return Status::OUT_OF_RESOURCES,
        },
    };

    // Copy name
    for i in 0..=name_len {
        variables[idx].name[i] = unsafe { *name.add(i) };
    }
    for i in (name_len + 1)..MAX_VARIABLE_NAME_LEN {
        variables[idx].name[i] = 0;
    }

    // Copy data
    unsafe {
        core::ptr::copy_nonoverlapping(
            data as *const u8,
            variables[idx].data.as_mut_ptr(),
            data_size,
        );
    }

    variables[idx].vendor_guid = guid;
    variables[idx].attributes = attributes;
    variables[idx].data_size = data_size;
    variables[idx].in_use = true;

    Status::SUCCESS
}

extern "efiapi" fn query_variable_info(
    attributes: u32,
    maximum_variable_storage_size: *mut u64,
    remaining_variable_storage_size: *mut u64,
    maximum_variable_size: *mut u64,
) -> Status {
    if maximum_variable_storage_size.is_null()
        || remaining_variable_storage_size.is_null()
        || maximum_variable_size.is_null()
    {
        return Status::INVALID_PARAMETER;
    }

    // We don't really care about attributes for our in-memory store
    let _ = attributes;

    let variables = VARIABLES.lock();
    let total_size = MAX_VARIABLES * MAX_VARIABLE_DATA_SIZE;
    let mut used_size = 0usize;

    for var in variables.iter() {
        if var.in_use {
            used_size += var.data_size;
        }
    }

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
    Status::UNSUPPORTED
}

extern "efiapi" fn reset_system(
    reset_type: ResetType,
    _reset_status: Status,
    _data_size: usize,
    _reset_data: *mut c_void,
) {
    log::info!("ResetSystem called with type {:?}", reset_type);

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
            // Try ACPI shutdown (S5)
            // This requires parsing ACPI tables which we don't do yet
            log::warn!("Shutdown not implemented, halting instead");
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
    Status::UNSUPPORTED
}

extern "efiapi" fn query_capsule_capabilities(
    _capsule_header_array: *mut *mut CapsuleHeader,
    _capsule_count: usize,
    _maximum_capsule_size: *mut u64,
    _reset_type: *mut ResetType,
) -> Status {
    Status::UNSUPPORTED
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Read time from CMOS RTC
fn read_rtc_time() -> (u16, u8, u8, u8, u8, u8) {
    // Wait for RTC update to complete
    unsafe {
        loop {
            x86_out8(0x70, 0x0A);
            if x86_in8(0x71) & 0x80 == 0 {
                break;
            }
        }
    }

    // Read RTC registers
    let second = read_cmos(0x00);
    let minute = read_cmos(0x02);
    let hour = read_cmos(0x04);
    let day = read_cmos(0x07);
    let month = read_cmos(0x08);
    let year = read_cmos(0x09);
    let century = read_cmos(0x32); // May not be available

    // Check if BCD mode
    let status_b = read_cmos(0x0B);
    let is_bcd = (status_b & 0x04) == 0;

    let convert = |val: u8| -> u8 {
        if is_bcd {
            (val & 0x0F) + ((val >> 4) * 10)
        } else {
            val
        }
    };

    let second = convert(second);
    let minute = convert(minute);
    let hour = convert(hour);
    let day = convert(day);
    let month = convert(month);
    let year = convert(year);
    let century = if century > 0 { convert(century) } else { 20 };

    let full_year = (century as u16) * 100 + (year as u16);

    (full_year, month, day, hour, minute, second)
}

/// Read a CMOS register
fn read_cmos(reg: u8) -> u8 {
    unsafe {
        x86_out8(0x70, reg);
        x86_in8(0x71)
    }
}

/// Port I/O functions
#[inline]
unsafe fn x86_out8(port: u16, value: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nostack, preserves_flags));
}

#[inline]
unsafe fn x86_in8(port: u16) -> u8 {
    let value: u8;
    core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nostack, preserves_flags));
    value
}

/// Compare two GUIDs for equality
fn guid_eq(a: &Guid, b: &Guid) -> bool {
    let a_bytes = unsafe { core::slice::from_raw_parts(a as *const Guid as *const u8, 16) };
    let b_bytes = unsafe { core::slice::from_raw_parts(b as *const Guid as *const u8, 16) };
    a_bytes == b_bytes
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

/// Get length of UCS-2 string in array (not including null terminator)
fn ucs2_strlen(s: &[u16]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

/// Get length of UCS-2 string from pointer (not including null terminator)
fn ucs2_strlen_ptr(s: *const u16) -> usize {
    let mut len = 0;
    unsafe {
        while *s.add(len) != 0 {
            len += 1;
        }
    }
    len
}

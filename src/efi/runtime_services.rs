//! EFI Runtime Services
//!
//! This module implements the EFI Runtime Services table, which provides
//! time, variable, and system reset services that persist after ExitBootServices.

use crate::arch::x86_64::io;
use crate::efi::auth;
use crate::state::{self, MAX_VARIABLES, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN};
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

/// Compare a pointer-based UCS-2 string with a constant UCS-2 slice
fn name_eq_const(name: *const u16, expected: &[u16]) -> bool {
    let mut i = 0;
    loop {
        let a = unsafe { *name.add(i) };
        let b = expected.get(i).copied().unwrap_or(0);

        if a == 0 && b == 0 {
            return true;
        }
        if a != b {
            return false;
        }
        i += 1;
    }
}

extern "efiapi" fn get_next_variable_name(
    variable_name_size: *mut usize,
    variable_name: *mut u16,
    vendor_guid: *mut Guid,
) -> Status {
    if variable_name_size.is_null() || variable_name.is_null() || vendor_guid.is_null() {
        return Status::INVALID_PARAMETER;
    }

    let current_name = variable_name;
    let current_guid = unsafe { *vendor_guid };

    // If name is empty, return first synthesized variable (SetupMode)
    let is_first = unsafe { *current_name == 0 };

    if is_first {
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
            let efi = state::efi();
            let variables = &efi.variables;

            if let Some(var) = variables.iter().find(|var| var.in_use) {
                return copy_stored_variable_name(
                    var,
                    variable_name_size,
                    variable_name,
                    vendor_guid,
                );
            }
            return Status::NOT_FOUND;
        }
    }

    // Search in stored variables
    let efi = state::efi();
    let variables = &efi.variables;

    // Create iterator over in-use variables and skip to next after current
    let next_var = variables
        .iter()
        .filter(|var| var.in_use)
        .skip_while(|var| !(var.vendor_guid == current_guid && name_eq(&var.name, current_name)))
        .nth(1); // Skip the current one and get the next

    match next_var {
        Some(var) => copy_stored_variable_name(var, variable_name_size, variable_name, vendor_guid),
        None => Status::NOT_FOUND,
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
    let name_len = ucs2_strlen(&var.name) + 1; // Include null terminator
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
        if is_append && existing_idx.is_some() {
            if let Some(var_type) = secure_boot_var {
                let idx = existing_idx.unwrap();
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
                            let name_slice =
                                unsafe { core::slice::from_raw_parts(name, name_len + 1) };
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

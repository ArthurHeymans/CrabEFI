use super::{
    DeferredSink, VariableContext, VariableRequest, apply_variable, validate_set_arguments,
};
use crate::{
    efi::{self, VariableAttributes},
    state::{self, Phase},
    store::VariableStore,
};
use core::ffi::c_void;
use crabefi_efi_types::secure_boot;
use crabefi_runtime_abi::{MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN};

pub extern "efiapi" fn get_variable(
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut c_void,
) -> efi::Status {
    #[cfg(all(target_arch = "x86_64", not(feature = "mm")))]
    if crate::proxy::active() {
        return crate::proxy::get_variable(variable_name, vendor_guid, attributes, data_size, data);
    }
    efi::status(read_variable(
        variable_name,
        vendor_guid,
        attributes,
        data_size,
        data,
    ))
}

fn read_variable(
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut c_void,
) -> Result<(), efi::Status> {
    if vendor_guid.is_null() || data_size.is_null() {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let name = read_name(variable_name)?;
    // SAFETY: vendor_guid is non-null and UEFI guarantees readable GUID storage.
    let guid = *unsafe { vendor_guid.read() }.as_bytes();
    let lease = state::lease()?;
    if guid == secure_boot::EFI_GLOBAL_VARIABLE_GUID {
        let value = if secure_boot::name_matches(name.as_slice(), secure_boot::SETUP_MODE_NAME) {
            Some(u8::from(lease.variables().setup_mode()))
        } else if secure_boot::name_matches(name.as_slice(), secure_boot::SECURE_BOOT_NAME) {
            Some(u8::from(lease.variables().secure_boot_enabled()))
        } else {
            None
        };
        if let Some(value) = value {
            return write_variable_result(
                &[value],
                VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS,
                attributes,
                data_size,
                data,
            );
        }
    }
    let runtime_only = lease.phase().runtime();
    let slot = lease
        .variables()
        .find(&guid, name.as_slice(), runtime_only)
        .ok_or(efi::Status::NOT_FOUND)?;
    let value = lease
        .variables()
        .data(slot)
        .ok_or(efi::Status::DEVICE_ERROR)?;
    write_variable_result(value, slot.attributes, attributes, data_size, data)
}

fn write_variable_result(
    value: &[u8],
    variable_attributes: VariableAttributes,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut c_void,
) -> Result<(), efi::Status> {
    // SAFETY: the caller supplied the required writable size pointer.
    let supplied = unsafe { data_size.read() };
    if supplied < value.len() || (!value.is_empty() && data.is_null()) {
        unsafe { data_size.write(value.len()) };
        return Err(efi::Status::BUFFER_TOO_SMALL);
    }
    if !value.is_empty() {
        // SAFETY: the caller reports a writable buffer large enough for value.
        unsafe { core::ptr::copy_nonoverlapping(value.as_ptr(), data.cast::<u8>(), value.len()) };
    }
    unsafe {
        data_size.write(value.len());
        if !attributes.is_null() {
            attributes.write(variable_attributes.bits());
        }
    }
    Ok(())
}

pub extern "efiapi" fn get_next_variable_name(
    variable_name_size: *mut usize,
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
) -> efi::Status {
    #[cfg(all(target_arch = "x86_64", not(feature = "mm")))]
    if crate::proxy::active() {
        return crate::proxy::get_next_variable_name(
            variable_name_size,
            variable_name,
            vendor_guid,
        );
    }
    efi::status(next_variable_name(
        variable_name_size,
        variable_name,
        vendor_guid,
    ))
}

fn next_variable_name(
    variable_name_size: *mut usize,
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
) -> Result<(), efi::Status> {
    if variable_name_size.is_null() || variable_name.is_null() || vendor_guid.is_null() {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    // SAFETY: required inputs are non-null by the checks above.
    let supplied = unsafe { variable_name_size.read() };
    if supplied < 2 {
        // SAFETY: writable size output is required by UEFI.
        unsafe { variable_name_size.write(2) };
        return Err(efi::Status::BUFFER_TOO_SMALL);
    }
    // SAFETY: at least one UTF-16 unit is available because supplied >= 2.
    let first = unsafe { variable_name.read() };
    let current_name = if first == 0 {
        Name::new()
    } else {
        read_name_bounded(variable_name, supplied / core::mem::size_of::<u16>())?
    };
    // SAFETY: non-null GUID input.
    let current_guid = *unsafe { vendor_guid.read() }.as_bytes();
    let lease = state::lease()?;
    let output = NameOutput {
        supplied,
        variable_name_size,
        variable_name,
        vendor_guid,
    };
    if current_name.is_empty() {
        return output.write(
            secure_boot::SETUP_MODE_NAME,
            secure_boot::EFI_GLOBAL_VARIABLE_GUID,
        );
    }
    let is_global = |name| {
        current_guid == secure_boot::EFI_GLOBAL_VARIABLE_GUID
            && secure_boot::name_matches(current_name.as_slice(), name)
    };
    if is_global(secure_boot::SETUP_MODE_NAME) {
        return output.write(secure_boot::SECURE_BOOT_NAME, current_guid);
    }
    let mut visible = lease.variables().visible_slots(lease.phase().runtime());
    if !is_global(secure_boot::SECURE_BOOT_NAME) {
        visible
            .by_ref()
            .position(|slot| slot.matches(&current_guid, current_name.as_slice()))
            .ok_or(efi::Status::INVALID_PARAMETER)?;
    }
    let slot = visible.next().ok_or(efi::Status::NOT_FOUND)?;
    let name = slot
        .name
        .get(..usize::from(slot.name_len))
        .ok_or(efi::Status::DEVICE_ERROR)?;
    output.write(name, slot.guid)
}

/// Caller-supplied GetNextVariableName output buffers.
struct NameOutput {
    supplied: usize,
    variable_name_size: *mut usize,
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
}

impl NameOutput {
    fn write(&self, name: &[u16], guid: [u8; 16]) -> Result<(), efi::Status> {
        let required = name.len().saturating_add(1).saturating_mul(2);
        if self.supplied < required {
            // SAFETY: writable size output is required by UEFI.
            unsafe { self.variable_name_size.write(required) };
            return Err(efi::Status::BUFFER_TOO_SMALL);
        }
        // SAFETY: the caller supplied `required` writable bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(name.as_ptr(), self.variable_name, name.len());
            self.variable_name.add(name.len()).write(0);
            self.vendor_guid.write(efi::Guid::from_bytes(&guid));
            self.variable_name_size.write(required);
        }
        Ok(())
    }
}

pub extern "efiapi" fn set_variable(
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
    attributes: u32,
    data_size: usize,
    data: *mut c_void,
) -> efi::Status {
    #[cfg(all(target_arch = "x86_64", not(feature = "mm")))]
    if crate::proxy::active() {
        return crate::proxy::set_variable(variable_name, vendor_guid, attributes, data_size, data);
    }
    efi::status(write_variable(
        variable_name,
        vendor_guid,
        attributes,
        data_size,
        data,
    ))
}

fn write_variable(
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
    attributes: u32,
    data_size: usize,
    data: *mut c_void,
) -> Result<(), efi::Status> {
    if vendor_guid.is_null() || (data_size != 0 && data.is_null()) {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let attributes =
        VariableAttributes::from_bits(attributes).ok_or(efi::Status::INVALID_PARAMETER)?;
    validate_set_arguments(attributes, data_size)?;
    let name = read_name(variable_name)?;
    // SAFETY: required pointers and input length were validated above.
    let guid = *unsafe { vendor_guid.read() }.as_bytes();
    let data = if data_size == 0 {
        &[]
    } else {
        // SAFETY: UEFI caller promises `data_size` readable bytes.
        unsafe { core::slice::from_raw_parts(data.cast::<u8>(), data_size) }
    };
    let mut lease = state::lease()?;
    let phase = lease.phase();
    if matches!(phase, Phase::Uninitialized | Phase::Loaded) {
        return Err(efi::Status::DEVICE_ERROR);
    }
    let (runtime, variables) = lease.parts_mut();
    let bridge = runtime.boot_bridge;
    let deferred = runtime.deferred_region().map(|region| DeferredSink {
        transaction: &mut variables.deferred_transaction,
        region,
    });
    apply_variable(
        VariableContext {
            store: &mut variables.store,
            transaction: &mut variables.transaction,
            phase,
            bridge,
            deferred,
        },
        VariableRequest {
            guid,
            name: name.as_slice(),
            attributes,
            data,
        },
    )
}

pub extern "efiapi" fn query_variable_info(
    attributes: u32,
    maximum_variable_storage_size: *mut u64,
    remaining_variable_storage_size: *mut u64,
    maximum_variable_size: *mut u64,
) -> efi::Status {
    #[cfg(all(target_arch = "x86_64", not(feature = "mm")))]
    if crate::proxy::active() {
        return crate::proxy::query_variable_info(
            attributes,
            maximum_variable_storage_size,
            remaining_variable_storage_size,
            maximum_variable_size,
        );
    }
    efi::status(variable_info(
        attributes,
        maximum_variable_storage_size,
        remaining_variable_storage_size,
        maximum_variable_size,
    ))
}

fn variable_info(
    attributes: u32,
    maximum_variable_storage_size: *mut u64,
    remaining_variable_storage_size: *mut u64,
    maximum_variable_size: *mut u64,
) -> Result<(), efi::Status> {
    if maximum_variable_storage_size.is_null()
        || remaining_variable_storage_size.is_null()
        || maximum_variable_size.is_null()
    {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let phase = Phase::current();
    validate_query_attributes(attributes, phase.boot_services() && !phase.runtime())?;
    let lease = state::lease()?;
    // Without retained staging the RAM store still answers: runtime-visible
    // volatile variables stay readable (they are writable only before
    // ExitBootServices) and SetVariable stays the authority on NV failures.
    // SAFETY: all required outputs were checked non-null.
    unsafe {
        maximum_variable_storage_size.write(VariableStore::maximum_storage());
        remaining_variable_storage_size.write(lease.variables().remaining_storage());
        maximum_variable_size.write(MAX_VARIABLE_DATA_SIZE as u64);
    }
    Ok(())
}

/// QueryVariableInfo attribute checks (UEFI 2.10 §8.2.6, as EDK II's
/// variable driver): volatile and non-volatile queries are both valid, and
/// so is `APPEND_WRITE` (Linux asks with the attributes of an appending
/// write). Volatile and non-volatile variables share one arena, so both
/// get the same answer.
fn validate_query_attributes(attributes: u32, boot_services: bool) -> Result<(), efi::Status> {
    let attributes =
        VariableAttributes::from_bits(attributes).ok_or(efi::Status::INVALID_PARAMETER)?;
    if attributes.is_empty() {
        return Err(efi::Status::UNSUPPORTED);
    }
    if !attributes.contains(VariableAttributes::BOOTSERVICE_ACCESS) {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    if !boot_services && !attributes.contains(VariableAttributes::RUNTIME_ACCESS) {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    if attributes.contains(VariableAttributes::HARDWARE_ERROR_RECORD) {
        return Err(if attributes.contains(VariableAttributes::NON_VOLATILE) {
            efi::Status::UNSUPPORTED
        } else {
            efi::Status::INVALID_PARAMETER
        });
    }
    if attributes.contains(VariableAttributes::AUTHENTICATED_WRITE_ACCESS) {
        return Err(efi::Status::UNSUPPORTED);
    }
    if !cfg!(feature = "secure-boot")
        && attributes.contains(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
    {
        return Err(efi::Status::UNSUPPORTED);
    }
    Ok(())
}

/// Variable name copied out of caller memory, without its terminator.
type Name = heapless::Vec<u16, MAX_VARIABLE_NAME_LEN>;

fn read_name(pointer: *const u16) -> Result<Name, efi::Status> {
    read_name_bounded(pointer, MAX_VARIABLE_NAME_LEN + 1)
}

fn read_name_bounded(pointer: *const u16, available_units: usize) -> Result<Name, efi::Status> {
    if pointer.is_null() {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let mut name = Name::new();
    while name.len() < MAX_VARIABLE_NAME_LEN && name.len() < available_units {
        // SAFETY: the bounded walk stays within both the ABI maximum and the
        // caller-declared buffer extent.
        let unit = unsafe { pointer.add(name.len()).read() };
        if unit == 0 {
            return if name.is_empty() {
                Err(efi::Status::INVALID_PARAMETER)
            } else {
                Ok(name)
            };
        }
        name.push(unit)
            .map_err(|_| efi::Status::INVALID_PARAMETER)?;
    }
    // SAFETY: one final unit is read only when the caller's declared buffer
    // includes it.
    if available_units > MAX_VARIABLE_NAME_LEN
        && unsafe { pointer.add(MAX_VARIABLE_NAME_LEN).read() } == 0
    {
        Ok(name)
    } else {
        Err(efi::Status::INVALID_PARAMETER)
    }
}

#[cfg(all(test, feature = "secure-boot"))]
mod tests {
    use super::*;

    #[test]
    fn bounded_name_read_rejects_missing_terminator_without_exceeding_declared_extent() {
        let name = [b'A' as u16];
        assert!(matches!(
            read_name_bounded(name.as_ptr(), name.len()),
            Err(status) if status == efi::Status::INVALID_PARAMETER
        ));
    }
}

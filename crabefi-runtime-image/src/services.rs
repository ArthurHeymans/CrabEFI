//! Image-local EFI Runtime Services entry points.

use core::ffi::c_void;

use crabefi_efi_types::{authentication::validate_signature_database, secure_boot};
use crabefi_runtime_abi::{
    BridgeRequest, MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN, VariableTimestamp,
    bridge_operation, capsule, phase, time_mechanism,
};

use crate::{
    arch, auth, deferred, efi, state,
    store::{VariableStore, VariableTransaction},
    svam,
};

const MAX_CAPSULE_SIZE: u64 = 16 * 1024 * 1024;
const CAPSULE_FLAGS_PERSIST_ACROSS_RESET: u32 = 0x0001_0000;
const CAPSULE_UPDATE_GUID: efi::Guid = efi::Guid::from_fields(
    0x711c703f,
    0xc285,
    0x4b10,
    0xa3,
    0xb0,
    &[0x36, 0xec, 0xbd, 0x3c, 0x8b, 0xe2],
);
const CAPSULE_UPDATE_NAME: &[u16] = &[
    b'C' as u16,
    b'a' as u16,
    b'p' as u16,
    b's' as u16,
    b'u' as u16,
    b'l' as u16,
    b'e' as u16,
    b'U' as u16,
    b'p' as u16,
    b'd' as u16,
    b'a' as u16,
    b't' as u16,
    b'e' as u16,
    b'D' as u16,
    b'a' as u16,
    b't' as u16,
    b'a' as u16,
];

pub extern "efiapi" fn get_time(
    time: *mut efi::Time,
    capabilities: *mut efi::TimeCapabilities,
) -> efi::Status {
    if time.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(status) => return status,
    };
    let config = lease.state().time;
    // SAFETY: UEFI requires `time` to name writable EFI_TIME storage. We have
    // checked null and write exactly one value.
    let result = unsafe { arch::read_time(config, &mut *time) };
    if let Err(status) = result {
        return status;
    }
    if !capabilities.is_null() {
        // SAFETY: optional output is written only when non-null.
        unsafe {
            capabilities.write(efi::TimeCapabilities {
                resolution: 1,
                accuracy: 50_000_000,
                sets_to_zero: efi::Boolean::FALSE,
            })
        };
    }
    efi::Status::SUCCESS
}

pub extern "efiapi" fn set_time(_time: *mut efi::Time) -> efi::Status {
    efi::Status::UNSUPPORTED
}

pub extern "efiapi" fn get_wakeup_time(
    _enabled: *mut efi::Boolean,
    _pending: *mut efi::Boolean,
    _time: *mut efi::Time,
) -> efi::Status {
    efi::Status::UNSUPPORTED
}

pub extern "efiapi" fn set_wakeup_time(
    _enable: efi::Boolean,
    _time: *mut efi::Time,
) -> efi::Status {
    efi::Status::UNSUPPORTED
}

pub extern "efiapi" fn set_virtual_address_map(
    memory_map_size: usize,
    descriptor_size: usize,
    descriptor_version: u32,
    virtual_map: *mut efi::MemoryDescriptor,
) -> efi::Status {
    svam::set_virtual_address_map(
        memory_map_size,
        descriptor_size,
        descriptor_version,
        virtual_map,
    )
}

pub extern "efiapi" fn convert_pointer(
    debug_disposition: usize,
    address: *mut *mut c_void,
) -> efi::Status {
    const OPTIONAL_POINTER: usize = 1;
    if address.is_null() || debug_disposition & !OPTIONAL_POINTER != 0 {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: address is the required writable pointer-to-pointer argument.
    let physical = unsafe { address.read() } as u64;
    if physical == 0 {
        return if debug_disposition & OPTIONAL_POINTER != 0 {
            efi::Status::SUCCESS
        } else {
            efi::Status::INVALID_PARAMETER
        };
    }
    if state::phase_value() != phase::VIRTUAL {
        return efi::Status::NOT_STARTED;
    }
    let lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(status) => return status,
    };
    let converted = lease
        .state()
        .sections
        .iter()
        .take(lease.state().section_count)
        .find_map(|section| {
            let offset = physical.checked_sub(section.physical_base)?;
            (offset < u64::from(section.byte_len))
                .then(|| section.virtual_base.checked_add(offset))?
        })
        .or_else(|| {
            lease
                .state()
                .ranges
                .iter()
                .take(lease.state().range_count)
                .find_map(|range| {
                    let offset = physical.checked_sub(range.physical_base)?;
                    (offset < range.byte_len).then(|| range.virtual_base.checked_add(offset))?
                })
        })
        .or_else(|| {
            let runtime = lease.state();
            let offset = physical.checked_sub(runtime.deferred_buffer_physical)?;
            (offset < runtime.deferred_buffer_size as u64)
                .then(|| runtime.deferred_buffer_virtual.checked_add(offset))?
        });
    let Some(converted) = converted else {
        return efi::Status::NOT_FOUND;
    };
    // SAFETY: address is writable as required by the protocol call.
    unsafe { address.write(converted as *mut c_void) };
    efi::Status::SUCCESS
}

pub extern "efiapi" fn get_variable(
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut c_void,
) -> efi::Status {
    if vendor_guid.is_null() || data_size.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let name = match read_name(variable_name) {
        Ok(name) => name,
        Err(status) => return status,
    };
    // SAFETY: vendor_guid is non-null and UEFI guarantees readable GUID storage.
    let guid = *unsafe { vendor_guid.read() }.as_bytes();
    let lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(status) => return status,
    };
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
                efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS,
                attributes,
                data_size,
                data,
            );
        }
    }
    let runtime_only = lease.state().runtime_only();
    let Some(slot) = lease.variables().find(&guid, name.as_slice(), runtime_only) else {
        return efi::Status::NOT_FOUND;
    };
    let Some(value) = lease.variables().data(slot) else {
        return efi::Status::DEVICE_ERROR;
    };
    write_variable_result(value, slot.attributes, attributes, data_size, data)
}

fn write_variable_result(
    value: &[u8],
    variable_attributes: u32,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut c_void,
) -> efi::Status {
    // SAFETY: the caller supplied the required writable size pointer.
    let supplied = unsafe { data_size.read() };
    if supplied < value.len() || (!value.is_empty() && data.is_null()) {
        unsafe { data_size.write(value.len()) };
        return efi::Status::BUFFER_TOO_SMALL;
    }
    if !value.is_empty() {
        // SAFETY: the caller reports a writable buffer large enough for value.
        unsafe { core::ptr::copy_nonoverlapping(value.as_ptr(), data.cast::<u8>(), value.len()) };
    }
    unsafe {
        data_size.write(value.len());
        if !attributes.is_null() {
            attributes.write(variable_attributes);
        }
    }
    efi::Status::SUCCESS
}

pub extern "efiapi" fn get_next_variable_name(
    variable_name_size: *mut usize,
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
) -> efi::Status {
    if variable_name_size.is_null() || variable_name.is_null() || vendor_guid.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: required inputs are non-null by the checks above.
    let supplied = unsafe { variable_name_size.read() };
    if supplied < 2 {
        // SAFETY: writable size output is required by UEFI.
        unsafe { variable_name_size.write(2) };
        return efi::Status::BUFFER_TOO_SMALL;
    }
    // SAFETY: at least one UTF-16 unit is available because supplied >= 2.
    let first = unsafe { variable_name.read() };
    let current_name = if first == 0 {
        Name::empty()
    } else {
        match read_name(variable_name) {
            Ok(name) => name,
            Err(status) => return status,
        }
    };
    // SAFETY: non-null GUID input.
    let current_guid = *unsafe { vendor_guid.read() }.as_bytes();
    let lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(status) => return status,
    };
    if current_name.len == 0 {
        return write_next_name(
            secure_boot::SETUP_MODE_NAME,
            secure_boot::EFI_GLOBAL_VARIABLE_GUID,
            supplied,
            variable_name_size,
            variable_name,
            vendor_guid,
        );
    }
    if current_guid == secure_boot::EFI_GLOBAL_VARIABLE_GUID
        && secure_boot::name_matches(current_name.as_slice(), secure_boot::SETUP_MODE_NAME)
    {
        return write_next_name(
            secure_boot::SECURE_BOOT_NAME,
            current_guid,
            supplied,
            variable_name_size,
            variable_name,
            vendor_guid,
        );
    }
    let runtime_only = lease.state().runtime_only();
    let mut visible = lease.variables().visible_slots(runtime_only);
    let next = if current_guid == secure_boot::EFI_GLOBAL_VARIABLE_GUID
        && secure_boot::name_matches(current_name.as_slice(), secure_boot::SECURE_BOOT_NAME)
    {
        visible.next()
    } else {
        let mut found = false;
        let next = visible.find(|slot| {
            if found {
                true
            } else {
                found = slot.matches(&current_guid, current_name.as_slice());
                false
            }
        });
        if !found {
            return efi::Status::INVALID_PARAMETER;
        }
        next
    };
    let Some(slot) = next else {
        return efi::Status::NOT_FOUND;
    };
    let Some(name) = slot.name.get(..usize::from(slot.name_len)) else {
        return efi::Status::DEVICE_ERROR;
    };
    write_next_name(
        name,
        slot.guid,
        supplied,
        variable_name_size,
        variable_name,
        vendor_guid,
    )
}

fn write_next_name(
    name: &[u16],
    guid: [u8; 16],
    supplied: usize,
    variable_name_size: *mut usize,
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
) -> efi::Status {
    let required = name.len().saturating_add(1).saturating_mul(2);
    if supplied < required {
        // SAFETY: writable size output is required by UEFI.
        unsafe { variable_name_size.write(required) };
        return efi::Status::BUFFER_TOO_SMALL;
    }
    // SAFETY: the caller supplied `required` writable bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(name.as_ptr(), variable_name, name.len());
        variable_name.add(name.len()).write(0);
        vendor_guid.write(efi::Guid::from_bytes(&guid));
        variable_name_size.write(required);
    }
    efi::Status::SUCCESS
}

pub extern "efiapi" fn set_variable(
    variable_name: *mut u16,
    vendor_guid: *mut efi::Guid,
    attributes: u32,
    data_size: usize,
    data: *mut c_void,
) -> efi::Status {
    if vendor_guid.is_null() || (data_size != 0 && data.is_null()) {
        return efi::Status::INVALID_PARAMETER;
    }
    if let Err(status) = validate_set_arguments(attributes, data_size) {
        return status;
    }
    let name = match read_name(variable_name) {
        Ok(name) => name,
        Err(status) => return status,
    };
    // SAFETY: required pointers and input length were validated above.
    let guid = *unsafe { vendor_guid.read() }.as_bytes();
    let input = if data_size == 0 {
        &[]
    } else {
        // SAFETY: UEFI caller promises `data_size` readable bytes.
        unsafe { core::slice::from_raw_parts(data.cast::<u8>(), data_size) }
    };
    let mut lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(status) => return status,
    };
    set_variable_locked(&mut lease, guid, name.as_slice(), attributes, input)
}

fn validate_set_arguments(attributes: u32, data_size: usize) -> Result<(), efi::Status> {
    if attributes & !efi::VARIABLE_KNOWN_ATTRIBUTES != 0
        || (data_size != 0 && attributes & efi::VARIABLE_BOOTSERVICE_ACCESS == 0)
        || (attributes & efi::VARIABLE_RUNTIME_ACCESS != 0
            && attributes & efi::VARIABLE_BOOTSERVICE_ACCESS == 0)
    {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    if attributes & efi::VARIABLE_AUTHENTICATED_WRITE_ACCESS != 0 {
        return Err(efi::Status::UNSUPPORTED);
    }
    let maximum = if attributes & efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0 {
        auth::MAX_AUTHENTICATED_ENVELOPE_SIZE
    } else {
        MAX_VARIABLE_DATA_SIZE
    };
    if data_size > maximum {
        return Err(efi::Status::OUT_OF_RESOURCES);
    }
    Ok(())
}

fn set_variable_locked(
    lease: &mut state::Lease,
    guid: [u8; 16],
    name: &[u16],
    attributes: u32,
    input: &[u8],
) -> efi::Status {
    let current_phase = state::phase_value();
    if current_phase == phase::UNINITIALIZED {
        return efi::Status::DEVICE_ERROR;
    }
    let bridge = lease.state().boot_bridge;
    let buffer = lease.state().deferred_buffer();
    let (store, transaction, deferred_transaction) = lease.variable_state_mut();
    apply_variable(
        store,
        transaction,
        Some(deferred_transaction),
        current_phase,
        bridge,
        buffer,
        guid,
        name,
        attributes,
        input,
    )
}

#[allow(clippy::too_many_arguments)]
fn apply_variable(
    store: &mut VariableStore,
    transaction: &mut VariableTransaction,
    deferred_transaction: Option<&mut deferred::DeferredTransaction>,
    current_phase: u8,
    bridge: u64,
    buffer: (*mut u8, usize),
    guid: [u8; 16],
    name: &[u16],
    attributes: u32,
    input: &[u8],
) -> efi::Status {
    if let Err(status) = validate_set_arguments(attributes, input.len()) {
        return status;
    }
    if secure_boot::is_status_variable(&guid, name)
        || capsule::is_esrt_last_attempt_variable(&guid, name)
    {
        return efi::Status::WRITE_PROTECTED;
    }
    let secure_variable = secure_boot::identify_key_database(&guid, name);
    let authenticated = attributes & efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0;
    if secure_variable.is_some() && !authenticated && !store.setup_mode() {
        return efi::Status::SECURITY_VIOLATION;
    }
    let (payload, timestamp, authenticated_variable) = if authenticated {
        match auth::verify_authenticated_variable(store, name, &guid, attributes, input) {
            Ok(verified) => (
                verified.payload,
                Some(auth::timestamp_from_efi_time(verified.timestamp)),
                verified.secure_variable,
            ),
            Err(error) => return error.into(),
        }
    } else {
        (input, None, None)
    };
    if payload.len() > MAX_VARIABLE_DATA_SIZE {
        return efi::Status::OUT_OF_RESOURCES;
    }
    let append = attributes & efi::VARIABLE_APPEND_WRITE != 0;
    let delete = payload.is_empty() && !append;
    if current_phase != phase::BOOT_ACTIVE {
        let existing = store.find(&guid, name, false);
        if delete {
            match existing {
                Some(slot) if slot.attributes & efi::VARIABLE_RUNTIME_ACCESS != 0 => {}
                Some(_) => return efi::Status::INVALID_PARAMETER,
                None => return efi::Status::NOT_FOUND,
            }
        } else if attributes & efi::VARIABLE_RUNTIME_ACCESS == 0 {
            return efi::Status::INVALID_PARAMETER;
        }
    }

    let mut prepared = match store.prepare(guid, name, attributes, payload.len()) {
        Ok(prepared) => prepared,
        Err(status) => return status,
    };
    let staged_len = match store.stage(transaction, &mut prepared, payload, append) {
        Ok(staged) => staged.len(),
        Err(status) => return status,
    };
    let Some(staged) = transaction.data(staged_len) else {
        return efi::Status::DEVICE_ERROR;
    };
    if secure_variable.is_some() && !prepared.delete && !validate_signature_database(staged) {
        return efi::Status::INVALID_PARAMETER;
    }

    if prepared.attributes & efi::VARIABLE_NON_VOLATILE != 0 {
        if current_phase == phase::BOOT_ACTIVE {
            let request = BridgeRequest {
                operation: if prepared.delete {
                    bridge_operation::PERSIST_DELETE
                } else {
                    bridge_operation::PERSIST_WRITE
                },
                attributes: prepared.attributes,
                guid,
                name_address: name.as_ptr() as u64,
                name_len: name.len() as u32,
                data_len: staged_len as u32,
                data_address: staged.as_ptr() as u64,
                timestamp_valid: u32::from(timestamp.is_some()),
                reserved: 0,
                timestamp: timestamp.unwrap_or_default(),
            };
            if let Err(status) = call_boot_bridge(bridge, &request) {
                return status;
            }
        } else {
            let Some(deferred_transaction) = deferred_transaction else {
                return efi::Status::DEVICE_ERROR;
            };
            let queued = if authenticated {
                deferred::queue_write(
                    buffer.0,
                    buffer.1,
                    deferred_transaction,
                    deferred::DeferredWrite {
                        guid,
                        name,
                        attributes,
                        data: input,
                        timestamp: timestamp.unwrap_or_default(),
                        authenticated: true,
                        deletion: prepared.delete,
                    },
                )
            } else {
                deferred::queue_write(
                    buffer.0,
                    buffer.1,
                    deferred_transaction,
                    deferred::DeferredWrite {
                        guid,
                        name,
                        attributes: if prepared.delete {
                            0
                        } else {
                            prepared.attributes
                        },
                        data: staged,
                        timestamp: VariableTimestamp::default(),
                        authenticated: false,
                        deletion: prepared.delete,
                    },
                )
            };
            if let Err(status) = queued {
                return status;
            }
        }
    }

    if let Err(status) = store.commit(transaction, prepared, name) {
        return status;
    }
    if let (Some(variable), Some(timestamp)) = (authenticated_variable, timestamp) {
        store.commit_auth_timestamp(variable, timestamp);
    }
    store.refresh_policy();
    efi::Status::SUCCESS
}

pub fn prepare_retained_staging(lease: &mut state::Lease) -> Result<(), efi::Status> {
    let bridge = lease.state().boot_bridge;
    let buffer = lease.state().deferred_buffer();
    if bridge == 0 {
        return Err(efi::Status::WRITE_PROTECTED);
    }
    let pointer = deferred::prepare_retained(buffer.0, buffer.1)?;
    let data = pointer.to_le_bytes();
    let guid = *CAPSULE_UPDATE_GUID.as_bytes();
    let (store, transaction, _) = lease.variable_state_mut();
    if store
        .find(&guid, CAPSULE_UPDATE_NAME, false)
        .and_then(|slot| store.data(slot))
        == Some(data.as_slice())
    {
        return Ok(());
    }
    let status = apply_variable(
        store,
        transaction,
        None,
        phase::BOOT_ACTIVE,
        bridge,
        buffer,
        guid,
        CAPSULE_UPDATE_NAME,
        efi::VARIABLE_NON_VOLATILE
            | efi::VARIABLE_BOOTSERVICE_ACCESS
            | efi::VARIABLE_RUNTIME_ACCESS,
        &data,
    );
    if status == efi::Status::SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

pub fn replay_deferred(lease: &mut state::Lease) -> Result<usize, efi::Status> {
    let bridge = lease.state().boot_bridge;
    let buffer = lease.state().deferred_buffer();
    if bridge == 0 {
        return Err(efi::Status::WRITE_PROTECTED);
    }
    let (store, transaction, deferred_transaction) = lease.variable_state_mut();
    deferred::replay(
        buffer.0,
        buffer.1,
        deferred_transaction,
        |record, authenticated, deletion| {
            if authenticated
                != (record.attributes & efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0)
                || (!authenticated && deletion != record.deleted())
            {
                return Err(efi::Status::DEVICE_ERROR);
            }
            let name_len = record
                .name
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(record.name.len());
            if name_len == 0 || name_len > MAX_VARIABLE_NAME_LEN {
                return Err(efi::Status::DEVICE_ERROR);
            }
            let name = &record.name[..name_len];
            if authenticated
                && let Some(variable) = secure_boot::identify_key_database(&record.guid.bytes, name)
            {
                let floor = store.auth_timestamp(variable);
                if floor == record.timestamp {
                    // Persistence committed before the retained acknowledgement.
                    // The imported floor proves this authenticated operation has
                    // already taken effect, including append and deletion.
                    return Ok(());
                }
            }
            let status = apply_variable(
                store,
                transaction,
                None,
                phase::BOOT_ACTIVE,
                bridge,
                buffer,
                record.guid.bytes,
                name,
                record.attributes,
                record.data,
            );
            replay_apply_result(status, authenticated, deletion)
        },
    )
}

fn replay_apply_result(
    status: efi::Status,
    authenticated: bool,
    deletion: bool,
) -> Result<(), efi::Status> {
    if status == efi::Status::SUCCESS
        || (!authenticated && deletion && status == efi::Status::NOT_FOUND)
    {
        // A raw deletion may have reached durable storage before reset while
        // its retained acknowledgement was lost. The absent imported value is
        // then the requested final state, so replay can consume the record.
        Ok(())
    } else {
        Err(status)
    }
}

pub extern "efiapi" fn get_next_high_mono_count(_high_count: *mut u32) -> efi::Status {
    efi::Status::UNSUPPORTED
}

pub extern "efiapi" fn reset_system(
    reset_type: efi::ResetType,
    _reset_status: efi::Status,
    _data_size: usize,
    _reset_data: *mut c_void,
) {
    arch::reset(state::reset_config(), reset_type)
}

pub extern "efiapi" fn update_capsule(
    capsule_header_array: *mut *mut efi::CapsuleHeader,
    capsule_count: usize,
    scatter_gather_list: efi::PhysicalAddress,
) -> efi::Status {
    if capsule_header_array.is_null() || capsule_count == 0 {
        return efi::Status::INVALID_PARAMETER;
    }
    if capsule_count > 1 {
        return efi::Status::UNSUPPORTED;
    }
    if state::phase_value() == phase::BOOT_ACTIVE {
        return efi::Status::UNSUPPORTED;
    }
    if state::phase_value() < phase::SEALED_PHYSICAL || scatter_gather_list == 0 {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: one pointer entry is required by the validated count.
    let header = unsafe { capsule_header_array.read() };
    if header.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: the UEFI caller supplies a readable capsule header.
    let header = unsafe { &*header };
    if header.flags & CAPSULE_FLAGS_PERSIST_ACROSS_RESET == 0
        || header.header_size < core::mem::size_of::<efi::CapsuleHeader>() as u32
        || header.capsule_image_size < header.header_size
        || u64::from(header.capsule_image_size) > MAX_CAPSULE_SIZE
    {
        return efi::Status::INVALID_PARAMETER;
    }

    let lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(_) => return efi::Status::DEVICE_ERROR,
    };
    let buffer = lease.state().deferred_buffer();
    match deferred::stage_capsule(
        buffer.0,
        buffer.1,
        header.capsule_image_size,
        scatter_gather_list,
    ) {
        Ok(()) => efi::Status::SUCCESS,
        Err(status) => status,
    }
}

pub extern "efiapi" fn query_capsule_capabilities(
    capsule_header_array: *mut *mut efi::CapsuleHeader,
    capsule_count: usize,
    maximum_capsule_size: *mut u64,
    reset_type: *mut efi::ResetType,
) -> efi::Status {
    if capsule_header_array.is_null()
        || capsule_count == 0
        || maximum_capsule_size.is_null()
        || reset_type.is_null()
    {
        return efi::Status::INVALID_PARAMETER;
    }
    if capsule_count > 1 {
        return efi::Status::UNSUPPORTED;
    }
    // SAFETY: one pointer entry is required by the validated count.
    let header = unsafe { capsule_header_array.read() };
    if header.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: the UEFI caller supplies a readable capsule header and writable
    // output pointers.
    let header = unsafe { &*header };
    if header.flags & CAPSULE_FLAGS_PERSIST_ACROSS_RESET == 0
        || u64::from(header.capsule_image_size) > MAX_CAPSULE_SIZE
    {
        return efi::Status::UNSUPPORTED;
    }
    unsafe {
        maximum_capsule_size.write(MAX_CAPSULE_SIZE);
        reset_type.write(efi::RESET_WARM);
    }
    efi::Status::SUCCESS
}

pub extern "efiapi" fn query_variable_info(
    attributes: u32,
    maximum_variable_storage_size: *mut u64,
    remaining_variable_storage_size: *mut u64,
    maximum_variable_size: *mut u64,
) -> efi::Status {
    if maximum_variable_storage_size.is_null()
        || remaining_variable_storage_size.is_null()
        || maximum_variable_size.is_null()
        || attributes == 0
        || attributes & !efi::VARIABLE_KNOWN_ATTRIBUTES != 0
    {
        return efi::Status::INVALID_PARAMETER;
    }
    if attributes & (efi::VARIABLE_NON_VOLATILE | efi::VARIABLE_BOOTSERVICE_ACCESS)
        != efi::VARIABLE_NON_VOLATILE | efi::VARIABLE_BOOTSERVICE_ACCESS
        || attributes & efi::VARIABLE_APPEND_WRITE != 0
    {
        return efi::Status::INVALID_PARAMETER;
    }
    let lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(status) => return status,
    };
    // SAFETY: all required outputs were checked non-null.
    unsafe {
        maximum_variable_storage_size.write(crate::store::VariableStore::maximum_storage());
        remaining_variable_storage_size.write(lease.variables().remaining_storage());
        maximum_variable_size.write(MAX_VARIABLE_DATA_SIZE as u64);
    }
    efi::Status::SUCCESS
}

fn call_boot_bridge(address: u64, request: &BridgeRequest) -> Result<(), efi::Status> {
    if address == 0 {
        return Err(efi::Status::WRITE_PROTECTED);
    }
    type Bridge = extern "C" fn(*const BridgeRequest) -> usize;
    // SAFETY: runtime initialization receives this one audited bridge address
    // from the boot loader. It is used only in BootActive and zeroed at seal.
    let bridge: Bridge = unsafe { core::mem::transmute(address as usize) };
    let status = efi::Status::from_usize(bridge(request));
    if status == efi::Status::SUCCESS {
        Ok(())
    } else {
        Err(status)
    }
}

struct Name {
    units: [u16; MAX_VARIABLE_NAME_LEN],
    len: usize,
}

impl Name {
    const fn empty() -> Self {
        Self {
            units: [0; MAX_VARIABLE_NAME_LEN],
            len: 0,
        }
    }

    fn as_slice(&self) -> &[u16] {
        self.units.get(..self.len).unwrap_or(&[])
    }
}

fn read_name(pointer: *const u16) -> Result<Name, efi::Status> {
    if pointer.is_null() {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let mut name = Name::empty();
    while name.len < MAX_VARIABLE_NAME_LEN {
        // SAFETY: UEFI variable names are NUL-terminated. The bounded walk
        // reads at most the ABI maximum plus its required terminator.
        let unit = unsafe { pointer.add(name.len).read() };
        if unit == 0 {
            return if name.len == 0 {
                Err(efi::Status::INVALID_PARAMETER)
            } else {
                Ok(name)
            };
        }
        name.units[name.len] = unit;
        name.len += 1;
    }
    // SAFETY: one final unit is required to terminate a maximum-length name.
    if unsafe { pointer.add(MAX_VARIABLE_NAME_LEN).read() } == 0 {
        Ok(name)
    } else {
        Err(efi::Status::INVALID_PARAMETER)
    }
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
pub fn time_from_unix(seconds: u64, out: &mut efi::Time) -> Result<(), efi::Status> {
    let days = i64::try_from(seconds / 86_400).map_err(|_| efi::Status::DEVICE_ERROR)?;
    let day_seconds = seconds % 86_400;
    let z = days.checked_add(719_468).ok_or(efi::Status::DEVICE_ERROR)?;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += (month <= 2) as i64;
    if !(1900..=9999).contains(&year) {
        return Err(efi::Status::DEVICE_ERROR);
    }
    out.year = year as u16;
    out.month = month as u8;
    out.day = day as u8;
    out.hour = (day_seconds / 3_600) as u8;
    out.minute = ((day_seconds % 3_600) / 60) as u8;
    out.second = (day_seconds % 60) as u8;
    out.pad1 = 0;
    out.nanosecond = 0;
    out.timezone = 0x07ff;
    out.daylight = 0;
    out.pad2 = 0;
    Ok(())
}

pub fn time_is_supported(mechanism: u32) -> bool {
    #[cfg(target_arch = "x86_64")]
    return mechanism == time_mechanism::X86_CMOS;
    #[cfg(target_arch = "aarch64")]
    return mechanism == time_mechanism::PL031;
    #[cfg(target_arch = "riscv64")]
    return mechanism == time_mechanism::GOLDFISH_RTC;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crabefi_efi_types::authentication::EfiVariableAuthentication2;

    use crate::{
        auth,
        store::{VariableStore, VariableTransaction},
    };

    const AUTH_ATTRIBUTES: u32 = efi::VARIABLE_NON_VOLATILE
        | efi::VARIABLE_BOOTSERVICE_ACCESS
        | efi::VARIABLE_RUNTIME_ACCESS
        | efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
    const RAW_ATTRIBUTES: u32 = efi::VARIABLE_NON_VOLATILE
        | efi::VARIABLE_BOOTSERVICE_ACCESS
        | efi::VARIABLE_RUNTIME_ACCESS;

    extern "C" fn successful_bridge(request: *const BridgeRequest) -> usize {
        if request.is_null() {
            efi::Status::INVALID_PARAMETER.as_usize()
        } else {
            efi::Status::SUCCESS.as_usize()
        }
    }

    fn fixture_payload(data: &'static [u8]) -> &'static [u8] {
        EfiVariableAuthentication2::from_bytes(data)
            .and_then(|authentication| authentication.variable_data(data))
            .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn apply(
        store: &mut VariableStore,
        transaction: &mut VariableTransaction,
        deferred_transaction: &mut deferred::DeferredTransaction,
        buffer: &mut [u8],
        current_phase: u8,
        variable: secure_boot::SecureBootVariable,
        attributes: u32,
        data: &[u8],
    ) -> efi::Status {
        let checkpoint = crate::scratch::checkpoint_for_test();
        let status = apply_variable(
            store,
            transaction,
            Some(deferred_transaction),
            current_phase,
            successful_bridge as *const () as u64,
            (buffer.as_mut_ptr(), buffer.len()),
            *variable.guid(),
            variable.name(),
            attributes,
            data,
        );
        // SAFETY: `apply_variable` returned, so no scratch-backed value remains live.
        unsafe { crate::scratch::rewind_for_test(checkpoint) };
        status
    }

    fn enroll_raw(
        store: &mut VariableStore,
        transaction: &mut VariableTransaction,
        deferred_transaction: &mut deferred::DeferredTransaction,
        buffer: &mut [u8],
    ) {
        let pk = include_bytes!("../tests/fixtures/pk.esl");
        for variable in [
            secure_boot::SecureBootVariable::Kek,
            secure_boot::SecureBootVariable::Db,
            secure_boot::SecureBootVariable::Dbx,
            secure_boot::SecureBootVariable::PK,
        ] {
            assert_eq!(
                apply(
                    store,
                    transaction,
                    deferred_transaction,
                    buffer,
                    phase::BOOT_ACTIVE,
                    variable,
                    RAW_ATTRIBUTES,
                    pk,
                ),
                efi::Status::SUCCESS
            );
        }
        assert!(!store.setup_mode());
    }

    #[test]
    fn firmware_imports_private_attempt_state_but_public_writes_cannot_forge_it() {
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        let mut deferred_transaction = deferred::DeferredTransaction::new();
        let mut buffer = vec![0u8; 4096];
        let guid = capsule::CAPSULE_REPORT_VARIABLE_GUID;
        let name = capsule::ESRT_LAST_ATTEMPT_VARIABLE_NAME;

        store
            .import(
                &mut transaction,
                guid,
                name,
                RAW_ATTRIBUTES,
                b"firmware",
                None,
            )
            .unwrap();

        for (attributes, value) in [
            (RAW_ATTRIBUTES, b"forged".as_slice()),
            (
                RAW_ATTRIBUTES | efi::VARIABLE_APPEND_WRITE,
                b"append".as_slice(),
            ),
            (0, b"".as_slice()),
        ] {
            assert_eq!(
                apply_variable(
                    &mut store,
                    &mut transaction,
                    Some(&mut deferred_transaction),
                    phase::BOOT_ACTIVE,
                    successful_bridge as *const () as u64,
                    (buffer.as_mut_ptr(), buffer.len()),
                    guid,
                    name,
                    attributes,
                    value,
                ),
                efi::Status::WRITE_PROTECTED
            );
        }

        let slot = store.find(&guid, name, false).unwrap();
        assert_eq!(store.data(slot), Some(b"firmware".as_slice()));
    }

    #[test]
    fn real_service_path_covers_all_secure_databases_and_exhaustion() {
        let _guard = crate::scratch::test_lock();
        crate::scratch::activate();
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        let mut deferred_transaction = deferred::DeferredTransaction::new();
        let mut buffer = vec![0u8; 64 * 1024];
        deferred::prepare_retained(buffer.as_mut_ptr(), buffer.len()).unwrap();
        enroll_raw(
            &mut store,
            &mut transaction,
            &mut deferred_transaction,
            &mut buffer,
        );

        assert_eq!(
            apply(
                &mut store,
                &mut transaction,
                &mut deferred_transaction,
                &mut buffer,
                phase::BOOT_ACTIVE,
                secure_boot::SecureBootVariable::Kek,
                AUTH_ATTRIBUTES,
                include_bytes!("../tests/fixtures/unauthorized-update.bin"),
            ),
            efi::Status::SECURITY_VIOLATION
        );

        let operations = [
            (
                secure_boot::SecureBootVariable::Db,
                include_bytes!("../tests/fixtures/db-update.bin").as_slice(),
                include_bytes!("../tests/fixtures/db-append.bin").as_slice(),
                include_bytes!("../tests/fixtures/db-delete.bin").as_slice(),
            ),
            (
                secure_boot::SecureBootVariable::Dbx,
                include_bytes!("../tests/fixtures/dbx-update.bin").as_slice(),
                include_bytes!("../tests/fixtures/dbx-append.bin").as_slice(),
                include_bytes!("../tests/fixtures/dbx-delete.bin").as_slice(),
            ),
            (
                secure_boot::SecureBootVariable::Kek,
                include_bytes!("../tests/fixtures/kek-update.bin").as_slice(),
                include_bytes!("../tests/fixtures/kek-append.bin").as_slice(),
                include_bytes!("../tests/fixtures/kek-delete.bin").as_slice(),
            ),
            (
                secure_boot::SecureBootVariable::PK,
                include_bytes!("../tests/fixtures/pk-update.bin").as_slice(),
                include_bytes!("../tests/fixtures/pk-append.bin").as_slice(),
                include_bytes!("../tests/fixtures/pk-delete.bin").as_slice(),
            ),
        ];
        for (variable, update, append, delete) in operations {
            assert_eq!(
                apply(
                    &mut store,
                    &mut transaction,
                    &mut deferred_transaction,
                    &mut buffer,
                    phase::BOOT_ACTIVE,
                    variable,
                    AUTH_ATTRIBUTES,
                    update,
                ),
                efi::Status::SUCCESS
            );
            assert_eq!(
                apply(
                    &mut store,
                    &mut transaction,
                    &mut deferred_transaction,
                    &mut buffer,
                    phase::BOOT_ACTIVE,
                    variable,
                    AUTH_ATTRIBUTES,
                    update,
                ),
                efi::Status::SECURITY_VIOLATION
            );
            assert_eq!(
                apply(
                    &mut store,
                    &mut transaction,
                    &mut deferred_transaction,
                    &mut buffer,
                    phase::BOOT_ACTIVE,
                    variable,
                    AUTH_ATTRIBUTES | efi::VARIABLE_APPEND_WRITE,
                    append,
                ),
                efi::Status::SUCCESS
            );
            assert!(validate_signature_database(
                store.key_database_data(variable).unwrap()
            ));
            assert_eq!(
                apply(
                    &mut store,
                    &mut transaction,
                    &mut deferred_transaction,
                    &mut buffer,
                    phase::BOOT_ACTIVE,
                    variable,
                    AUTH_ATTRIBUTES,
                    delete,
                ),
                efi::Status::SUCCESS
            );
            assert_eq!(
                apply(
                    &mut store,
                    &mut transaction,
                    &mut deferred_transaction,
                    &mut buffer,
                    phase::BOOT_ACTIVE,
                    variable,
                    AUTH_ATTRIBUTES,
                    delete,
                ),
                efi::Status::SECURITY_VIOLATION
            );
        }
        assert!(store.setup_mode());
        assert!(!store.secure_boot_enabled());
        assert!(crate::scratch::high_water_for_test() < auth::AUTH_OPERATION_SCRATCH_BOUND);

        let mut exhausted_store = VariableStore::new();
        enroll_raw(
            &mut exhausted_store,
            &mut transaction,
            &mut deferred_transaction,
            &mut buffer,
        );
        crate::scratch::set_limit_for_test(auth::AUTH_OPERATION_SCRATCH_BOUND - 1);
        assert_eq!(
            apply(
                &mut exhausted_store,
                &mut transaction,
                &mut deferred_transaction,
                &mut buffer,
                phase::BOOT_ACTIVE,
                secure_boot::SecureBootVariable::Kek,
                AUTH_ATTRIBUTES,
                include_bytes!("../tests/fixtures/kek-update.bin"),
            ),
            efi::Status::OUT_OF_RESOURCES
        );
        crate::scratch::set_limit_for_test(crate::scratch::SCRATCH_SIZE);
        crate::scratch::reset();
    }

    #[test]
    fn replay_consumes_already_persisted_raw_delete_and_continues() {
        const GUID: [u8; 16] = [0x42; 16];
        let _guard = crate::scratch::test_lock();
        crate::scratch::activate();
        let mut buffer = vec![0u8; 64 * 1024];
        let mut transaction = deferred::DeferredTransaction::new();
        deferred::prepare_retained(buffer.as_mut_ptr(), buffer.len()).unwrap();
        for (name, deletion) in [(&[b'D' as u16][..], true), (&[b'N' as u16][..], false)] {
            deferred::queue_write(
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut transaction,
                deferred::DeferredWrite {
                    guid: GUID,
                    name,
                    attributes: if deletion { 0 } else { RAW_ATTRIBUTES },
                    data: if deletion { &[] } else { b"next" },
                    timestamp: VariableTimestamp::default(),
                    authenticated: false,
                    deletion,
                },
            )
            .unwrap();
        }

        let mut seen = 0usize;
        assert_eq!(
            deferred::replay(
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut transaction,
                |_, authenticated, deletion| {
                    seen += 1;
                    replay_apply_result(
                        if deletion {
                            efi::Status::NOT_FOUND
                        } else {
                            efi::Status::SUCCESS
                        },
                        authenticated,
                        deletion,
                    )
                },
            ),
            Ok(2)
        );
        assert_eq!(seen, 2);
        assert_eq!(
            deferred::replay(
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut transaction,
                |_, _, _| panic!("acknowledged records replayed twice"),
            ),
            Ok(0)
        );
        assert_eq!(
            replay_apply_result(efi::Status::NOT_FOUND, true, true),
            Err(efi::Status::NOT_FOUND)
        );
        crate::scratch::reset();
    }

    #[test]
    fn raw_post_ebs_write_replays_exact_bytes_once_through_service_logic() {
        const GUID: [u8; 16] = [
            0x11, 0x7c, 0x2c, 0xa5, 0xf4, 0x61, 0xb7, 0x4e, 0xa2, 0x19, 0x5a, 0x96, 0xb8, 0x0d,
            0xa1, 0x02,
        ];
        const NAME: &[u16] = &[
            b'R' as u16,
            b't' as u16,
            b'D' as u16,
            b'e' as u16,
            b'f' as u16,
            b'e' as u16,
            b'r' as u16,
            b'r' as u16,
            b'e' as u16,
            b'd' as u16,
        ];
        const VALUE: &[u8] = b"CrabRT";

        let _guard = crate::scratch::test_lock();
        crate::scratch::activate();
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        let mut deferred_transaction = deferred::DeferredTransaction::new();
        let mut buffer = vec![0u8; 64 * 1024];
        deferred::prepare_retained(buffer.as_mut_ptr(), buffer.len()).unwrap();
        assert_eq!(
            apply_variable(
                &mut store,
                &mut transaction,
                Some(&mut deferred_transaction),
                phase::SEALED_PHYSICAL,
                successful_bridge as *const () as u64,
                (buffer.as_mut_ptr(), buffer.len()),
                GUID,
                NAME,
                RAW_ATTRIBUTES,
                VALUE,
            ),
            efi::Status::SUCCESS
        );

        let mut reboot_store = VariableStore::new();
        let mut reboot_transaction = VariableTransaction::new();
        let mut persisted = 0usize;
        let processed = deferred::replay(
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut deferred_transaction,
            |record, authenticated, deletion| {
                assert!(!authenticated);
                assert!(!deletion);
                assert_eq!(record.attributes, RAW_ATTRIBUTES);
                assert_eq!(record.data, VALUE);
                let name_len = record.name.iter().position(|unit| *unit == 0).unwrap();
                assert_eq!(&record.name[..name_len], NAME);
                let status = apply_variable(
                    &mut reboot_store,
                    &mut reboot_transaction,
                    None,
                    phase::BOOT_ACTIVE,
                    successful_bridge as *const () as u64,
                    (buffer.as_mut_ptr(), buffer.len()),
                    record.guid.bytes,
                    &record.name[..name_len],
                    record.attributes,
                    record.data,
                );
                if status == efi::Status::SUCCESS {
                    persisted += 1;
                    Ok(())
                } else {
                    Err(status)
                }
            },
        )
        .unwrap();
        assert_eq!(processed, 1);
        assert_eq!(persisted, 1);
        let slot = reboot_store.find(&GUID, NAME, false).unwrap();
        assert_eq!(slot.attributes, RAW_ATTRIBUTES);
        assert_eq!(reboot_store.data(slot), Some(VALUE));
        assert_eq!(
            deferred::replay(
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut deferred_transaction,
                |_, _, _| panic!("acknowledged raw record replayed twice"),
            ),
            Ok(0)
        );
        crate::scratch::reset();
    }

    #[test]
    fn authenticated_post_ebs_write_replays_once_through_service_logic() {
        let _guard = crate::scratch::test_lock();
        crate::scratch::activate();
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        let mut deferred_transaction = deferred::DeferredTransaction::new();
        let mut buffer = vec![0u8; 64 * 1024];
        deferred::prepare_retained(buffer.as_mut_ptr(), buffer.len()).unwrap();
        enroll_raw(
            &mut store,
            &mut transaction,
            &mut deferred_transaction,
            &mut buffer,
        );
        assert_eq!(
            apply(
                &mut store,
                &mut transaction,
                &mut deferred_transaction,
                &mut buffer,
                phase::SEALED_PHYSICAL,
                secure_boot::SecureBootVariable::Db,
                AUTH_ATTRIBUTES,
                include_bytes!("../tests/fixtures/db-update.bin"),
            ),
            efi::Status::SUCCESS
        );

        let mut reboot_store = VariableStore::new();
        let mut reboot_transaction = VariableTransaction::new();
        enroll_raw(
            &mut reboot_store,
            &mut reboot_transaction,
            &mut deferred_transaction,
            &mut buffer,
        );
        let processed = deferred::replay(
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut deferred_transaction,
            |record, authenticated, _| {
                assert!(authenticated);
                let name_len = record.name.iter().position(|unit| *unit == 0).unwrap();
                let status = apply_variable(
                    &mut reboot_store,
                    &mut reboot_transaction,
                    None,
                    phase::BOOT_ACTIVE,
                    successful_bridge as *const () as u64,
                    (buffer.as_mut_ptr(), buffer.len()),
                    record.guid.bytes,
                    &record.name[..name_len],
                    record.attributes,
                    record.data,
                );
                if status == efi::Status::SUCCESS {
                    Ok(())
                } else {
                    Err(status)
                }
            },
        )
        .unwrap();
        assert_eq!(processed, 1);
        assert_eq!(
            deferred::replay(
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut deferred_transaction,
                |_, _, _| panic!("acknowledged record replayed twice"),
            ),
            Ok(0)
        );
        assert_eq!(
            reboot_store.key_database_data(secure_boot::SecureBootVariable::Db),
            Some(fixture_payload(include_bytes!(
                "../tests/fixtures/db-update.bin"
            )))
        );
        crate::scratch::reset();
    }
}

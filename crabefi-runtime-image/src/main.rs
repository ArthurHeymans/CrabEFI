//! CrabEFI separately linked EFI runtime image with bounded scratch allocation.

#![cfg_attr(all(not(test), target_os = "none"), no_std)]
#![cfg_attr(all(not(test), target_os = "none"), no_main)]
#![cfg_attr(all(not(test), target_os = "none"), feature(alloc_error_handler))]
#![deny(unsafe_op_in_unsafe_fn)]
// Exported C ABI entry points validate every pointer and copy all retained
// fields immediately; keeping them safe matches firmware caller conventions.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

extern crate alloc;

mod arch;
mod auth;
mod deferred;
mod efi;
mod scratch;
mod services;
mod state;
mod store;
mod svam;
mod tables;

#[cfg(all(not(test), target_os = "none"))]
use core::panic::PanicInfo;

use crabefi_runtime_abi::{
    ConfigurationRegistration, ConsoleRegistration, EsrtRegistration, RelocationImport,
    RuntimeHandoff, VariableImport, phase,
};

#[cfg(all(not(test), target_os = "none"))]
#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(all(not(test), target_os = "none"))]
#[alloc_error_handler]
fn allocation_error(_layout: core::alloc::Layout) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(all(not(test), not(target_os = "none")))]
fn main() {}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_init(handoff: *const RuntimeHandoff) -> usize {
    if handoff.is_null() || state::phase_value() != phase::UNINITIALIZED {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    // SAFETY: the boot loader passes a readable handoff for this immediate call;
    // RuntimeState copies every retained field and stores no reference to it.
    let handoff = unsafe { &*handoff };
    let mut lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(status) => return status.as_usize(),
    };
    match lease.state_mut().initialize(handoff) {
        Ok(()) => efi::Status::SUCCESS.as_usize(),
        Err(status) => status.as_usize(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_import_relocation(relocation: *const RelocationImport) -> usize {
    if relocation.is_null()
        || !matches!(
            state::phase_value(),
            phase::UNINITIALIZED | phase::BOOT_ACTIVE
        )
    {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    let mut lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(status) => return status.as_usize(),
    };
    if !lease.state().initialized {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    // SAFETY: immediate boot export call; no pointer is retained.
    match lease.state_mut().import_relocation(unsafe { &*relocation }) {
        Ok(()) => efi::Status::SUCCESS.as_usize(),
        Err(status) => status.as_usize(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_import_variable(import: *const VariableImport) -> usize {
    if import.is_null()
        || !matches!(
            state::phase_value(),
            phase::UNINITIALIZED | phase::BOOT_ACTIVE
        )
    {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    // SAFETY: immediate import call. Address/length records point to boot-owned
    // readable buffers for this call only and are copied into the image store.
    let import = unsafe { &*import };
    let name_len = match usize::try_from(import.name_len) {
        Ok(length) if length != 0 && length <= crabefi_runtime_abi::MAX_VARIABLE_NAME_LEN => length,
        _ => return efi::Status::INVALID_PARAMETER.as_usize(),
    };
    let data_len = match usize::try_from(import.data_len) {
        Ok(length) if length <= crabefi_runtime_abi::MAX_VARIABLE_DATA_SIZE => length,
        _ => return efi::Status::OUT_OF_RESOURCES.as_usize(),
    };
    if import.name_address == 0
        || !import
            .name_address
            .is_multiple_of(core::mem::align_of::<u16>() as u64)
        || (data_len != 0 && import.data_address == 0)
    {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    // SAFETY: lengths are ABI-bounded and the boot importer guarantees readable
    // buffers for the duration of this direct call.
    let name = unsafe { core::slice::from_raw_parts(import.name_address as *const u16, name_len) };
    let data = if data_len == 0 {
        &[]
    } else {
        // SAFETY: same immediate-call contract as `name`.
        unsafe { core::slice::from_raw_parts(import.data_address as *const u8, data_len) }
    };
    let mut lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(status) => return status.as_usize(),
    };
    if !lease.state().initialized {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    if lease.state().import_finished {
        return efi::Status::UNSUPPORTED.as_usize();
    }
    if import.timestamp_valid > 1 {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    let timestamp = (import.timestamp_valid != 0).then_some(import.timestamp);
    let (store, transaction) = lease.variables_mut();
    match store.import(
        transaction,
        import.guid,
        name,
        import.attributes,
        data,
        timestamp,
    ) {
        Ok(()) => efi::Status::SUCCESS.as_usize(),
        Err(status) => status.as_usize(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_finish_import(operation: u32) -> usize {
    if !matches!(
        state::phase_value(),
        phase::UNINITIALIZED | phase::BOOT_ACTIVE
    ) {
        return efi::Status::UNSUPPORTED.as_usize();
    }
    let mut lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(status) => return status.as_usize(),
    };
    if !lease.state().initialized || lease.state().import_finished {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    match operation {
        crabefi_runtime_abi::finish_import_operation::PREPARE_RETAINED_STAGING => {
            match services::prepare_retained_staging(&mut lease) {
                Ok(()) => efi::Status::SUCCESS.as_usize(),
                Err(status) => status.as_usize(),
            }
        }
        crabefi_runtime_abi::finish_import_operation::REPLAY_DEFERRED => {
            match services::replay_deferred(&mut lease) {
                Ok(_) => efi::Status::SUCCESS.as_usize(),
                Err(status) => status.as_usize(),
            }
        }
        crabefi_runtime_abi::finish_import_operation::COMPLETE_IMPORT => {
            let (store, _) = lease.variables_mut();
            store.refresh_policy();
            lease.state_mut().import_finished = true;
            efi::Status::SUCCESS.as_usize()
        }
        _ => efi::Status::INVALID_PARAMETER.as_usize(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_activate(boot_services: u64) -> usize {
    if state::phase_value() != phase::UNINITIALIZED || boot_services == 0 {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    let mut lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(status) => return status.as_usize(),
    };
    let runtime = lease.state_mut();
    if !runtime.initialized {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    let time_supported = services::time_is_supported(runtime.time.mechanism);
    if let Err(status) = runtime.tables.initialize(boot_services, time_supported) {
        return status.as_usize();
    }
    drop(lease);
    match state::set_phase(phase::UNINITIALIZED, phase::BOOT_ACTIVE) {
        Ok(()) => efi::Status::SUCCESS.as_usize(),
        Err(status) => status.as_usize(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_register_configuration(
    registration: *const ConfigurationRegistration,
) -> usize {
    if registration.is_null() {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    let mut lease = match state::try_lease_phase(phase::BOOT_ACTIVE) {
        Ok(lease) => lease,
        Err(status) => return status.as_usize(),
    };
    // SAFETY: immediate value-only registration call.
    match lease.state_mut().tables.install(unsafe { *registration }) {
        Ok(()) => efi::Status::SUCCESS.as_usize(),
        Err(status) => status.as_usize(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_set_console(registration: *const ConsoleRegistration) -> usize {
    if registration.is_null() {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    let mut lease = match state::try_lease_phase(phase::BOOT_ACTIVE) {
        Ok(lease) => lease,
        Err(status) => return status.as_usize(),
    };
    // SAFETY: immediate value-only registration call.
    match lease
        .state_mut()
        .tables
        .set_console(unsafe { *registration })
    {
        Ok(()) => efi::Status::SUCCESS.as_usize(),
        Err(status) => status.as_usize(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_install_esrt(registration: *const EsrtRegistration) -> usize {
    if registration.is_null() {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    let mut lease = match state::try_lease_phase(phase::BOOT_ACTIVE) {
        Ok(lease) => lease,
        Err(status) => return status.as_usize(),
    };
    // SAFETY: immediate value-only registration call.
    match lease
        .state_mut()
        .tables
        .install_esrt(unsafe { *registration })
    {
        Ok(()) => efi::Status::SUCCESS.as_usize(),
        Err(status) => status.as_usize(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_prepare_ebs(
    descriptors: *const efi::MemoryDescriptor,
    descriptor_count: usize,
) -> usize {
    if descriptors.is_null() || descriptor_count > 32 {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    let mut lease = match state::try_lease_phase(phase::BOOT_ACTIVE) {
        Ok(lease) => lease,
        Err(status) => return status.as_usize(),
    };
    // SAFETY: boot allocator supplies exactly descriptor_count initialized
    // descriptors for this allocation-free immediate call.
    let descriptors = unsafe { core::slice::from_raw_parts(descriptors, descriptor_count) };
    let runtime = lease.state_mut();
    let sections = runtime.sections;
    let ranges = runtime.ranges;
    match runtime.tables.prepare_memory_attributes(
        descriptors,
        &sections[..runtime.section_count],
        &ranges[..runtime.range_count],
    ) {
        Ok(()) => efi::Status::SUCCESS.as_usize(),
        Err(status) => status.as_usize(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_seal() -> usize {
    let mut lease = match state::try_lease_phase(phase::BOOT_ACTIVE) {
        Ok(lease) => lease,
        Err(status) => return status.as_usize(),
    };
    let runtime = lease.state_mut();
    runtime.tables.seal();
    runtime.boot_bridge = 0;
    drop(lease);
    match state::set_phase(phase::BOOT_ACTIVE, phase::SEALED_PHYSICAL) {
        Ok(()) => efi::Status::SUCCESS.as_usize(),
        Err(status) => status.as_usize(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_get_runtime_services() -> u64 {
    let lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(_) => return 0,
    };
    core::ptr::addr_of!(lease.state().tables.runtime) as u64
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_get_system_table() -> u64 {
    let lease = match state::try_lease() {
        Ok(lease) => lease,
        Err(_) => return 0,
    };
    core::ptr::addr_of!(lease.state().tables.system) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_import_rejects_odd_utf16_address_before_dereference() {
        let import = VariableImport {
            name_address: 1,
            name_len: 1,
            ..VariableImport::default()
        };
        assert_eq!(
            runtime_image_import_variable(&import),
            efi::Status::INVALID_PARAMETER.as_usize()
        );
    }
}

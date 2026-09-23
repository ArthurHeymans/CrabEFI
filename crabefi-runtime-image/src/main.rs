//! CrabEFI separately linked EFI runtime image with stack-bounded RSA verification.

#![cfg_attr(all(not(test), target_os = "none"), no_std)]
#![cfg_attr(all(not(test), target_os = "none"), no_main)]
#![deny(unsafe_op_in_unsafe_fn)]
// Exported C ABI entry points validate every pointer and copy all retained
// fields immediately; keeping them safe matches firmware caller conventions.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

mod arch;
#[cfg(feature = "secure-boot")]
mod auth;
mod deferred;
mod efi;
mod services;
mod state;
mod store;
mod svam;
mod tables;

#[cfg(all(not(test), target_os = "none"))]
use core::panic::PanicInfo;

/// Source-selected capabilities read by the normalizer from the linked ELF.
#[used]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".runtime.capabilities")]
pub static RUNTIME_IMAGE_FEATURE_BITS: u64 = crabefi_runtime_abi::feature_bits::REQUIRED
    | if cfg!(feature = "secure-boot") {
        crabefi_runtime_abi::feature_bits::SECURE_BOOT
    } else {
        0
    };

use crabefi_runtime_abi::{
    ConfigurationRegistration, ConsoleRegistration, EsrtRegistration, MAX_RUNTIME_DESCRIPTORS,
    MemoryDescriptor, RelocationImport, RuntimeHandoff, VariableImport,
};

use state::Phase;

macro_rules! check_export_signatures {
    ($($field:ident: $symbol:ident => $signature:ty;)*) => {
        $(const _: $signature = $symbol;)*
    };
}
crabefi_runtime_abi::runtime_exports!(check_export_signatures);

#[cfg(all(not(test), target_os = "none"))]
#[panic_handler]
#[inline(never)]
fn panic(_info: &PanicInfo<'_>) -> ! {
    crabefi_runtime_panic_is_possible();
    loop {
        core::hint::spin_loop();
    }
}

/// Stable panic sink used by the audited runtime build.
///
/// The runtime ELF retains panic support for its freestanding panic lang item,
/// so the audit examines direct callers and permits this sink only from that
/// support code. Any service path reaching a panic helper fails the build.
#[cfg(all(not(test), target_os = "none"))]
#[unsafe(no_mangle)]
#[inline(never)]
fn crabefi_runtime_panic_is_possible() {
    core::hint::black_box(());
}

#[cfg(all(not(test), not(target_os = "none")))]
fn main() {}

/// Status returned across the image boundary for an export's result.
fn export_status(result: Result<(), efi::Status>) -> usize {
    efi::status(result).as_usize()
}

/// # Safety
///
/// `handoff` must be null or point to an initialized, readable
/// `RuntimeHandoff` for the duration of this call. Every nonzero
/// address/length pair in the handoff must describe memory satisfying the
/// runtime ABI contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn runtime_image_init(handoff: *const RuntimeHandoff) -> usize {
    // SAFETY: RuntimeState copies every retained field and stores no reference.
    export_status(init(unsafe { handoff.as_ref() }))
}

fn init(handoff: Option<&RuntimeHandoff>) -> Result<(), efi::Status> {
    let handoff = handoff.ok_or(efi::Status::INVALID_PARAMETER)?;
    let mut lease = state::lease_in(&[Phase::Uninitialized])?;
    lease.state_mut().initialize(handoff)?;
    lease.advance(Phase::Loaded);
    Ok(())
}

/// # Safety
///
/// `relocation` must be null or point to an initialized, readable
/// `RelocationImport` for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn runtime_image_import_relocation(
    relocation: *const RelocationImport,
) -> usize {
    // SAFETY: immediate boot export call; no pointer is retained.
    let relocation = unsafe { relocation.as_ref() };
    export_status(
        relocation
            .ok_or(efi::Status::INVALID_PARAMETER)
            .and_then(|relocation| {
                state::lease_in(&[Phase::Loaded])?
                    .state_mut()
                    .import_relocation(relocation)
            }),
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_activate(boot_services: u64) -> usize {
    export_status(activate(boot_services))
}

fn activate(boot_services: u64) -> Result<(), efi::Status> {
    if boot_services == 0 {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let mut lease = state::lease_in(&[Phase::Loaded])?;
    let runtime = lease.state_mut();
    let time_supported = services::time_is_supported(runtime.time.mechanism);
    runtime.tables.initialize(boot_services, time_supported)?;
    lease.advance(Phase::Importing);
    Ok(())
}

/// # Safety
///
/// `import` must be null or point to an initialized, readable
/// `VariableImport`. Its name and data address/length pairs must remain
/// readable for the duration of this call and must not be concurrently mutated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn runtime_image_import_variable(import: *const VariableImport) -> usize {
    // SAFETY: immediate import call. Address/length records point to boot-owned
    // readable buffers for this call only and are copied into the image store.
    export_status(unsafe { import_variable(import.as_ref()) })
}

/// # Safety
///
/// The name and data address/length pairs of `import` must be readable for
/// the duration of this call.
unsafe fn import_variable(import: Option<&VariableImport>) -> Result<(), efi::Status> {
    let import = import.ok_or(efi::Status::INVALID_PARAMETER)?;
    let name_len = usize::try_from(import.name_len)
        .ok()
        .filter(|length| (1..=crabefi_runtime_abi::MAX_VARIABLE_NAME_LEN).contains(length))
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    let data_len = usize::try_from(import.data_len)
        .ok()
        .filter(|length| *length <= crabefi_runtime_abi::MAX_VARIABLE_DATA_SIZE)
        .ok_or(efi::Status::OUT_OF_RESOURCES)?;
    if import.name_address == 0
        || !import
            .name_address
            .is_multiple_of(core::mem::align_of::<u16>() as u64)
        || (data_len != 0 && import.data_address == 0)
    {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    // SAFETY: lengths are ABI-bounded and the caller guarantees readable
    // buffers for the duration of this direct call.
    let name = unsafe { core::slice::from_raw_parts(import.name_address as *const u16, name_len) };
    let data = if data_len == 0 {
        &[]
    } else {
        // SAFETY: same immediate-call contract as `name`.
        unsafe { core::slice::from_raw_parts(import.data_address as *const u8, data_len) }
    };
    let timestamp = match import.timestamp_valid {
        0 => None,
        1 => Some(import.timestamp),
        _ => return Err(efi::Status::INVALID_PARAMETER),
    };
    let mut lease = state::lease_in(&[Phase::Importing])?;
    let (_, variables) = lease.parts_mut();
    variables.store.import(
        &mut variables.transaction,
        import.guid,
        name,
        import.attributes,
        data,
        timestamp,
    )
}

/// Initialize retained staging and publish its capsule pointer.
#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_prepare_retained_staging() -> usize {
    export_status(
        state::lease_in(&[Phase::Importing])
            .and_then(|mut lease| services::prepare_retained_staging(&mut lease)),
    )
}

/// Replay and durably consume retained deferred writes.
#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_replay_deferred() -> usize {
    export_status(
        state::lease_in(&[Phase::Importing])
            .and_then(|mut lease| services::replay_deferred(&mut lease).map(drop)),
    )
}

/// Confirm that boot can consume staged capsules and persist their results.
#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_enable_capsule_delivery() -> usize {
    export_status(state::lease_in(&[Phase::Importing]).map(|mut lease| {
        lease.state_mut().capsule_delivery_enabled = true;
    }))
}

/// Derive final policy and reject all subsequent boot imports.
#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_complete_import() -> usize {
    export_status(state::lease_in(&[Phase::Importing]).map(|mut lease| {
        lease.parts_mut().1.store.refresh_policy();
        lease.advance(Phase::BootActive);
    }))
}

/// # Safety
///
/// `registration` must be null or point to an initialized, readable
/// registration value for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn runtime_image_register_configuration(
    registration: *const ConfigurationRegistration,
) -> usize {
    // SAFETY: immediate value-only registration call.
    let registration = unsafe { registration.as_ref() };
    export_status(
        registration
            .ok_or(efi::Status::INVALID_PARAMETER)
            .and_then(|registration| {
                state::lease_in(Phase::BOOT_SERVICES)?
                    .state_mut()
                    .tables
                    .install(*registration)
            }),
    )
}

/// # Safety
///
/// `registration` must be null or point to an initialized, readable
/// registration value for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn runtime_image_set_console(
    registration: *const ConsoleRegistration,
) -> usize {
    // SAFETY: immediate value-only registration call.
    let registration = unsafe { registration.as_ref() };
    export_status(
        registration
            .ok_or(efi::Status::INVALID_PARAMETER)
            .and_then(|registration| {
                state::lease_in(Phase::BOOT_SERVICES)?
                    .state_mut()
                    .tables
                    .set_console(*registration)
            }),
    )
}

/// # Safety
///
/// `registration` must be null or point to an initialized, readable
/// registration value for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn runtime_image_install_esrt(
    registration: *const EsrtRegistration,
) -> usize {
    // SAFETY: immediate value-only registration call.
    let registration = unsafe { registration.as_ref() };
    export_status(
        registration
            .ok_or(efi::Status::INVALID_PARAMETER)
            .and_then(|registration| {
                state::lease_in(Phase::BOOT_SERVICES)?
                    .state_mut()
                    .tables
                    .install_esrt(*registration)
            }),
    )
}

/// # Safety
///
/// `descriptors` must point to `descriptor_count` initialized, readable memory
/// descriptors for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn runtime_image_prepare_ebs(
    descriptors: *const MemoryDescriptor,
    descriptor_count: usize,
) -> usize {
    if descriptors.is_null() || descriptor_count > MAX_RUNTIME_DESCRIPTORS {
        return efi::Status::INVALID_PARAMETER.as_usize();
    }
    // SAFETY: the boot allocator supplies exactly `descriptor_count`
    // initialized descriptors for this allocation-free immediate call.
    let descriptors = unsafe { core::slice::from_raw_parts(descriptors, descriptor_count) };
    export_status(state::lease_in(Phase::BOOT_SERVICES).and_then(|mut lease| {
        let runtime = lease.state_mut();
        runtime
            .tables
            .prepare_memory_attributes(descriptors, &runtime.sections)
    }))
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_seal() -> usize {
    export_status(state::lease_in(Phase::BOOT_SERVICES).map(|mut lease| {
        let runtime = lease.state_mut();
        runtime.tables.seal();
        runtime.boot_bridge = 0;
        lease.advance(Phase::SealedPhysical);
    }))
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_get_runtime_services() -> u64 {
    state::lease().map_or(0, |lease| {
        core::ptr::addr_of!(lease.state().tables.runtime) as u64
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn runtime_image_get_system_table() -> u64 {
    state::lease().map_or(0, |lease| {
        core::ptr::addr_of!(lease.state().tables.system) as u64
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    static RUNTIME_TEST: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn seal_erases_boot_bridge_and_runtime_nv_never_calls_it() {
        use core::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        extern "C" fn boot_only(_request: *const crabefi_runtime_abi::BridgeRequest) -> usize {
            CALLS.fetch_add(1, Ordering::Relaxed);
            efi::Status::DEVICE_ERROR.as_usize()
        }
        let _guard = RUNTIME_TEST.lock().unwrap();
        {
            let mut lease = state::lease().unwrap();
            lease.advance(Phase::BootActive);
            lease.state_mut().boot_bridge = boot_only as *const () as u64;
        }
        assert_eq!(runtime_image_seal(), efi::Status::SUCCESS.as_usize());
        assert_eq!(Phase::current(), Phase::SealedPhysical);
        {
            let lease = state::lease().unwrap();
            assert_eq!(lease.state().boot_bridge, 0);
            assert!(lease.state().tables.system.boot_services.is_null());
        }
        let name = [b'N' as u16, 0];
        let guid = efi::Guid::from_bytes(&[0x42; 16]);
        let data = [1u8];
        let status = services::set_variable(
            name.as_ptr().cast_mut(),
            &guid as *const _ as *mut _,
            efi::VARIABLE_NON_VOLATILE
                | efi::VARIABLE_BOOTSERVICE_ACCESS
                | efi::VARIABLE_RUNTIME_ACCESS,
            data.len(),
            data.as_ptr().cast_mut().cast(),
        );
        assert_ne!(status, efi::Status::SUCCESS);
        assert_eq!(CALLS.load(Ordering::Relaxed), 0);
        state::lease().unwrap().advance(Phase::Uninitialized);
    }

    #[test]
    fn variable_import_rejects_odd_utf16_address_before_dereference() {
        let _guard = RUNTIME_TEST.lock().unwrap();
        let import = VariableImport {
            name_address: 1,
            name_len: 1,
            ..VariableImport::default()
        };
        assert_eq!(
            unsafe { runtime_image_import_variable(&import) },
            efi::Status::INVALID_PARAMETER.as_usize()
        );
    }
}

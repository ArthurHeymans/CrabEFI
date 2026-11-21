use crate::{
    efi,
    state::{self, Phase},
};

const MAX_CAPSULE_SIZE: u64 = 16 * 1024 * 1024;
const CAPSULE_FLAGS_PERSIST_ACROSS_RESET: u32 = 0x0001_0000;
pub(super) const CAPSULE_UPDATE_GUID: efi::Guid = efi::Guid::from_fields(
    0x711c703f,
    0xc285,
    0x4b10,
    0xa3,
    0xb0,
    &[0x36, 0xec, 0xbd, 0x3c, 0x8b, 0xe2],
);
pub(super) const CAPSULE_UPDATE_NAME: &[u16] = &[
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

/// The retained capsule staging reservation (`CapsuleUpdateData`).
#[cfg(feature = "mm")]
pub fn is_capsule_staging_variable(guid: &[u8; 16], name: &[u16]) -> bool {
    guid == CAPSULE_UPDATE_GUID.as_bytes() && name == CAPSULE_UPDATE_NAME
}

pub extern "efiapi" fn update_capsule(
    capsule_header_array: *mut *mut efi::CapsuleHeader,
    capsule_count: usize,
    scatter_gather_list: efi::PhysicalAddress,
) -> efi::Status {
    efi::status(stage_capsule(
        capsule_header_array,
        capsule_count,
        scatter_gather_list,
    ))
}

fn stage_capsule(
    capsule_header_array: *mut *mut efi::CapsuleHeader,
    capsule_count: usize,
    scatter_gather_list: efi::PhysicalAddress,
) -> Result<(), efi::Status> {
    if capsule_header_array.is_null() || capsule_count == 0 {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    if capsule_count > 1 {
        return Err(efi::Status::UNSUPPORTED);
    }
    let phase = Phase::current();
    if phase.boot_services() {
        return Err(efi::Status::UNSUPPORTED);
    }
    if !phase.runtime() || scatter_gather_list == 0 {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    // SAFETY: one pointer entry is required by the validated count.
    let header = unsafe { capsule_header_array.read() };
    if header.is_null() {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    // SAFETY: the UEFI caller supplies a readable capsule header.
    let header = unsafe { &*header };
    if header.flags & CAPSULE_FLAGS_PERSIST_ACROSS_RESET == 0
        || header.header_size < core::mem::size_of::<efi::CapsuleHeader>() as u32
        || header.capsule_image_size < header.header_size
        || u64::from(header.capsule_image_size) > MAX_CAPSULE_SIZE
    {
        return Err(efi::Status::INVALID_PARAMETER);
    }

    let mut lease = state::lease().map_err(|_| efi::Status::DEVICE_ERROR)?;
    if !capsule_delivery_available(lease.state()) {
        return Err(efi::Status::UNSUPPORTED);
    }
    if !scatter_gather_list.is_multiple_of(8) {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    // The list is physical and is only linked, never dereferenced, here:
    // see DeferredRegion::stage_capsule.
    lease
        .state_mut()
        .deferred_region()
        .ok_or(efi::Status::UNSUPPORTED)?
        .stage_capsule(scatter_gather_list)
}

/// Capsule staging requires retained storage and boot-time confirmation that
/// the platform can apply capsules and persist their results. ESRT contents are
/// discovery data and never control the runtime service.
fn capsule_delivery_available(runtime: &state::RuntimeState) -> bool {
    runtime.capsule_delivery_enabled && runtime.retained.is_some()
}

pub extern "efiapi" fn query_capsule_capabilities(
    capsule_header_array: *mut *mut efi::CapsuleHeader,
    capsule_count: usize,
    maximum_capsule_size: *mut u64,
    reset_type: *mut efi::ResetType,
) -> efi::Status {
    efi::status(capsule_capabilities(
        capsule_header_array,
        capsule_count,
        maximum_capsule_size,
        reset_type,
    ))
}

fn capsule_capabilities(
    capsule_header_array: *mut *mut efi::CapsuleHeader,
    capsule_count: usize,
    maximum_capsule_size: *mut u64,
    reset_type: *mut efi::ResetType,
) -> Result<(), efi::Status> {
    if capsule_header_array.is_null()
        || capsule_count == 0
        || maximum_capsule_size.is_null()
        || reset_type.is_null()
    {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    if capsule_count > 1 {
        return Err(efi::Status::UNSUPPORTED);
    }
    // SAFETY: one pointer entry is required by the validated count.
    let header = unsafe { capsule_header_array.read() };
    if header.is_null() {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    // SAFETY: the UEFI caller supplies a readable capsule header and writable
    // output pointers.
    let header = unsafe { &*header };
    if header.flags & CAPSULE_FLAGS_PERSIST_ACROSS_RESET == 0
        || u64::from(header.capsule_image_size) > MAX_CAPSULE_SIZE
    {
        return Err(efi::Status::UNSUPPORTED);
    }
    // Match `update_capsule`'s structural header checks so a capsule cannot
    // pass the capability query and then fail the update itself.
    if header.header_size < core::mem::size_of::<efi::CapsuleHeader>() as u32
        || header.capsule_image_size < header.header_size
    {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let lease = state::lease()?;
    if !capsule_delivery_available(lease.state()) {
        return Err(efi::Status::UNSUPPORTED);
    }
    unsafe {
        maximum_capsule_size.write(MAX_CAPSULE_SIZE);
        reset_type.write(efi::RESET_WARM);
    }
    Ok(())
}

#[cfg(all(test, feature = "secure-boot"))]
mod tests {
    use super::*;

    #[test]
    fn query_capsule_capabilities_validates_header_like_update_capsule() {
        let _guard = crate::tests::RUNTIME_TEST.lock().unwrap();
        let saved = {
            let mut lease = state::lease().unwrap();
            let runtime = lease.state_mut();
            let saved = (runtime.retained, runtime.capsule_delivery_enabled);
            runtime.retained = Some(state::RetainedBuffer {
                physical_base: 0x30_0000,
                virtual_base: 0,
                size: 0x1_0000,
            });
            runtime.capsule_delivery_enabled = true;
            saved
        };
        let header = efi::CapsuleHeader {
            capsule_guid: efi::Guid::from_bytes(&[0; 16]),
            header_size: core::mem::size_of::<efi::CapsuleHeader>() as u32,
            flags: CAPSULE_FLAGS_PERSIST_ACROSS_RESET,
            capsule_image_size: core::mem::size_of::<efi::CapsuleHeader>() as u32 - 1,
        };
        let mut array = [&header as *const efi::CapsuleHeader as *mut efi::CapsuleHeader];
        let mut maximum = 0u64;
        let mut reset_type = efi::RESET_COLD;
        assert_eq!(
            query_capsule_capabilities(
                array.as_mut_ptr(),
                array.len(),
                &mut maximum,
                &mut reset_type,
            ),
            efi::Status::INVALID_PARAMETER
        );

        let truncated = efi::CapsuleHeader {
            header_size: core::mem::size_of::<efi::CapsuleHeader>() as u32 - 1,
            capsule_image_size: 4096,
            ..header
        };
        let mut array = [&truncated as *const efi::CapsuleHeader as *mut efi::CapsuleHeader];
        assert_eq!(
            query_capsule_capabilities(
                array.as_mut_ptr(),
                array.len(),
                &mut maximum,
                &mut reset_type,
            ),
            efi::Status::INVALID_PARAMETER
        );

        let valid = efi::CapsuleHeader {
            capsule_image_size: 4096,
            ..header
        };
        let mut array = [&valid as *const efi::CapsuleHeader as *mut efi::CapsuleHeader];
        assert_eq!(
            query_capsule_capabilities(
                array.as_mut_ptr(),
                array.len(),
                &mut maximum,
                &mut reset_type,
            ),
            efi::Status::SUCCESS
        );
        assert_eq!(maximum, MAX_CAPSULE_SIZE);
        assert_eq!(reset_type, efi::RESET_WARM);

        state::lease().unwrap().state_mut().capsule_delivery_enabled = false;
        maximum = u64::MAX;
        reset_type = efi::RESET_COLD;
        assert_eq!(
            query_capsule_capabilities(
                array.as_mut_ptr(),
                array.len(),
                &mut maximum,
                &mut reset_type,
            ),
            efi::Status::UNSUPPORTED
        );
        assert_eq!((maximum, reset_type), (u64::MAX, efi::RESET_COLD));
        let mut lease = state::lease().unwrap();
        let runtime = lease.state_mut();
        (runtime.retained, runtime.capsule_delivery_enabled) = saved;
    }
}

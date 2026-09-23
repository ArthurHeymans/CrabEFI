//! BootActive persistence bridge called by the runtime image.

use crabefi_runtime_abi::BridgeRequest;
#[cfg(feature = "variable-store")]
use crabefi_runtime_abi::bridge_operation;
#[cfg(any(feature = "variable-store", test))]
use r_efi::efi::Guid;
use r_efi::efi::Status;

#[cfg(feature = "variable-store")]
use crate::efi::varstore::VarStoreError;

/// Firmware without direct-flash persistence rejects every bridge operation.
#[cfg(not(feature = "variable-store"))]
pub extern "C" fn dispatch(_request: *const BridgeRequest) -> usize {
    Status::UNSUPPORTED.as_usize()
}

/// Persist one variable write or deletion requested by the runtime image.
///
/// # Safety
///
/// `request` must be null or point to a readable `BridgeRequest` whose name
/// and data address/length pairs are readable for the duration of this call.
#[cfg(feature = "variable-store")]
pub unsafe extern "C" fn dispatch(request: *const BridgeRequest) -> usize {
    // SAFETY: forwarded from the caller; nothing is retained after return.
    let result = unsafe { request.as_ref() }
        .ok_or(Status::INVALID_PARAMETER)
        .and_then(|request| unsafe { persist(request) });
    match result {
        Ok(()) => Status::SUCCESS.as_usize(),
        Err(status) => status.as_usize(),
    }
}

/// # Safety
///
/// The name and data address/length pairs of `request` must be readable for
/// the duration of this call.
#[cfg(feature = "variable-store")]
unsafe fn persist(request: &BridgeRequest) -> Result<(), Status> {
    use crabefi_runtime_abi::{MAX_VARIABLE_DATA_SIZE, MAX_VARIABLE_NAME_LEN};

    let name_len = usize::try_from(request.name_len)
        .ok()
        .filter(|length| (1..=MAX_VARIABLE_NAME_LEN).contains(length))
        .ok_or(Status::INVALID_PARAMETER)?;
    let data_len = usize::try_from(request.data_len)
        .ok()
        .filter(|length| *length <= MAX_VARIABLE_DATA_SIZE)
        .ok_or(Status::OUT_OF_RESOURCES)?;
    if request.name_address == 0 || (data_len != 0 && request.data_address == 0) {
        return Err(Status::INVALID_PARAMETER);
    }
    // SAFETY: the caller guarantees readable buffers of the ABI-bounded
    // lengths checked above.
    let name = unsafe { core::slice::from_raw_parts(request.name_address as *const u16, name_len) };
    let data = if data_len == 0 {
        &[]
    } else {
        // SAFETY: same contract as `name`.
        unsafe { core::slice::from_raw_parts(request.data_address as *const u8, data_len) }
    };
    let mut terminated_name = [0u16; MAX_VARIABLE_NAME_LEN + 1];
    terminated_name[..name_len].copy_from_slice(name);
    let name = &terminated_name[..=name_len];
    if request.timestamp_valid > 1 || request.reserved != 0 {
        return Err(Status::INVALID_PARAMETER);
    }
    let timestamp = (request.timestamp_valid != 0).then_some(request.timestamp);
    let guid = Guid::from_bytes(&request.guid);
    match request.operation {
        bridge_operation::PERSIST_WRITE => {
            crate::efi::varstore::persistence::write_variable_to_storage_internal(
                &guid,
                name,
                request.attributes,
                data,
                timestamp,
            )
        }
        bridge_operation::PERSIST_DELETE => {
            crate::efi::varstore::persistence::write_variable_deletion_internal(
                &guid,
                name,
                request.attributes,
                timestamp,
            )
        }
        _ => return Err(Status::UNSUPPORTED),
    }
    .map_err(|error| match error {
        VarStoreError::NotInitialized | VarStoreError::WriteProtected => Status::WRITE_PROTECTED,
        VarStoreError::StoreFull => Status::OUT_OF_RESOURCES,
        VarStoreError::InvalidArgument
        | VarStoreError::NameTooLong
        | VarStoreError::DataTooLarge => Status::INVALID_PARAMETER,
        _ => Status::DEVICE_ERROR,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_bytes_use_r_efi_mixed_endian_conversion() {
        let bytes = [
            0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let guid = Guid::from_bytes(&bytes);
        assert_eq!(guid.as_bytes(), &bytes);
        let expected = Guid::from_fields(
            0x1234_5678,
            0x9abc,
            0xdef0,
            0x11,
            0x22,
            &[0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        );
        assert_eq!(guid.as_bytes(), expected.as_bytes());
    }
}

//! Audited BootActive persistence bridge consumed by runtime-image seal.

use crabefi_runtime_abi::{BridgeRequest, bridge_operation};
use r_efi::efi::{Guid, Status};

use crate::efi::varstore::VarStoreError;

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn dispatch(request: *const BridgeRequest) -> usize {
    if request.is_null() {
        return Status::INVALID_PARAMETER.as_usize();
    }
    // SAFETY: the image calls the bridge synchronously while BootActive and
    // retains neither the request nor its referenced immediate buffers.
    let request = unsafe { &*request };
    let name_len = match usize::try_from(request.name_len) {
        Ok(length) if length != 0 && length <= crabefi_runtime_abi::MAX_VARIABLE_NAME_LEN => length,
        _ => return Status::INVALID_PARAMETER.as_usize(),
    };
    let data_len = match usize::try_from(request.data_len) {
        Ok(length) if length <= crabefi_runtime_abi::MAX_VARIABLE_DATA_SIZE => length,
        _ => return Status::OUT_OF_RESOURCES.as_usize(),
    };
    if request.name_address == 0 || (data_len != 0 && request.data_address == 0) {
        return Status::INVALID_PARAMETER.as_usize();
    }
    // SAFETY: addresses originate in the active runtime service call and are
    // bounded by the checked ABI limits for this synchronous dispatch.
    let name = unsafe { core::slice::from_raw_parts(request.name_address as *const u16, name_len) };
    let data = if data_len == 0 {
        &[]
    } else {
        // SAFETY: same immediate-call contract as `name`.
        unsafe { core::slice::from_raw_parts(request.data_address as *const u8, data_len) }
    };
    let mut terminated_name = [0u16; crabefi_runtime_abi::MAX_VARIABLE_NAME_LEN + 1];
    terminated_name[..name_len].copy_from_slice(name);
    let name = &terminated_name[..=name_len];
    if request.timestamp_valid > 1 || request.reserved != 0 {
        return Status::INVALID_PARAMETER.as_usize();
    }
    let timestamp = (request.timestamp_valid != 0).then_some(request.timestamp);
    let guid = guid_from_bytes(request.guid);
    let result = match request.operation {
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
        _ => return Status::UNSUPPORTED.as_usize(),
    };
    match result {
        Ok(()) => Status::SUCCESS.as_usize(),
        Err(VarStoreError::NotInitialized) => Status::WRITE_PROTECTED.as_usize(),
        Err(VarStoreError::StoreFull) => Status::OUT_OF_RESOURCES.as_usize(),
        Err(
            VarStoreError::InvalidArgument
            | VarStoreError::NameTooLong
            | VarStoreError::DataTooLarge,
        ) => Status::INVALID_PARAMETER.as_usize(),
        Err(_) => Status::DEVICE_ERROR.as_usize(),
    }
}

fn guid_from_bytes(bytes: [u8; 16]) -> Guid {
    Guid::from_fields(
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        bytes[8],
        bytes[9],
        &[
            bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ],
    )
}

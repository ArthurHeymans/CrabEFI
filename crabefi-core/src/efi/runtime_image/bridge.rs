//! BootActive persistence bridge called by the runtime image.

use crabefi_runtime_abi::BridgeRequest;
#[cfg(feature = "variable-store")]
use crabefi_runtime_abi::bridge_operation;
#[cfg(any(feature = "variable-store", test))]
use r_efi::efi::Guid;
use r_efi::efi::Status;

#[cfg(feature = "variable-store")]
use crate::efi::varstore::VarStoreError;

#[cfg(feature = "variable-store")]
static SETUP_PK_DELETE_ACTIVE: crate::cell::LocalCell<bool> = crate::cell::LocalCell::new(false);

/// Delete PK through the normal persist-before-commit variable transaction.
/// Only the synchronous physical-presence setup action opens this scope; no
/// public UEFI service can grant this authorization, and it is never retained.
#[cfg(feature = "secure-boot")]
pub(crate) fn delete_pk_from_setup() -> Status {
    #[cfg(not(feature = "variable-store"))]
    return Status::UNSUPPORTED;

    #[cfg(feature = "variable-store")]
    {
        if SETUP_PK_DELETE_ACTIVE.get() {
            return Status::ACCESS_DENIED;
        }
        struct ResetAuthorization;
        impl Drop for ResetAuthorization {
            fn drop(&mut self) {
                SETUP_PK_DELETE_ACTIVE.set(false);
            }
        }
        SETUP_PK_DELETE_ACTIVE.set(true);
        let _scope = ResetAuthorization;
        super::client::variables::set(
            &Guid::from_bytes(&crabefi_efi_types::secure_boot::EFI_GLOBAL_VARIABLE_GUID),
            crabefi_efi_types::secure_boot::PK_NAME,
            0,
            &[],
        )
    }
}

#[cfg(feature = "variable-store")]
fn setup_pk_delete_authorized(request: &BridgeRequest, name: &[u16], active: bool) -> bool {
    use crabefi_efi_types::secure_boot::{EFI_GLOBAL_VARIABLE_GUID, PK_NAME, name_matches};
    active
        && request.guid == EFI_GLOBAL_VARIABLE_GUID
        && name_matches(name, PK_NAME)
        && request.attributes == 0
        && request.data_len == 0
        && request.data_address == 0
        && request.timestamp_valid == 0
        && request.reserved == 0
}

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
        bridge_operation::AUTHORIZE_SETUP_PK_DELETE => {
            return if setup_pk_delete_authorized(request, name, SETUP_PK_DELETE_ACTIVE.get()) {
                Ok(())
            } else {
                Err(Status::ACCESS_DENIED)
            };
        }
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

    #[cfg(feature = "variable-store")]
    #[test]
    fn setup_authorization_only_accepts_an_active_empty_pk_delete() {
        use crabefi_efi_types::secure_boot::{EFI_GLOBAL_VARIABLE_GUID, KEK_NAME, PK_NAME};
        let request = BridgeRequest {
            operation: bridge_operation::AUTHORIZE_SETUP_PK_DELETE,
            guid: EFI_GLOBAL_VARIABLE_GUID,
            name_address: PK_NAME.as_ptr() as u64,
            name_len: PK_NAME.len() as u32,
            ..BridgeRequest::default()
        };
        assert!(!setup_pk_delete_authorized(&request, PK_NAME, false));
        assert!(setup_pk_delete_authorized(&request, PK_NAME, true));
        assert!(!setup_pk_delete_authorized(&request, KEK_NAME, true));
        for invalid in [
            BridgeRequest {
                guid: [0x42; 16],
                ..request
            },
            BridgeRequest {
                attributes: 7,
                ..request
            },
            BridgeRequest {
                data_len: 1,
                ..request
            },
            BridgeRequest {
                data_address: 1,
                ..request
            },
            BridgeRequest {
                timestamp_valid: 1,
                ..request
            },
            BridgeRequest {
                reserved: 1,
                ..request
            },
        ] {
            assert!(!setup_pk_delete_authorized(&invalid, PK_NAME, true));
        }
        // An ordinary bridge caller cannot grant itself setup authorization.
        assert_eq!(
            unsafe { dispatch(&request) },
            Status::ACCESS_DENIED.as_usize()
        );
    }

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

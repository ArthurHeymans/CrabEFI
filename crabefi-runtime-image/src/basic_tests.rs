//! Runtime policy checks without UEFI authentication support.

use crate::{
    efi::{self, VariableAttributes},
    services::{VariableContext, VariableRequest, apply_variable, capsule_delivery_available},
    state::{Phase, RetainedBuffer, RuntimeState},
    store::{VariableStore, VariableTransaction},
};
use crabefi_efi_types::secure_boot;

const ATTRIBUTES: VariableAttributes =
    VariableAttributes::BOOTSERVICE_ACCESS.union(VariableAttributes::RUNTIME_ACCESS);

/// Apply a request without a boot bridge or retained buffer.
fn apply(
    store: &mut VariableStore,
    transaction: &mut VariableTransaction,
    phase: Phase,
    request: VariableRequest<'_>,
) -> efi::Status {
    let context = VariableContext {
        phase,
        ..VariableContext::boot(store, transaction, 0)
    };
    efi::status(apply_variable(context, request))
}

#[test]
fn capsule_delivery_requires_boot_consumer_enablement() {
    let mut runtime = RuntimeState::new();
    runtime.retained = Some(RetainedBuffer {
        physical_base: 0x1000,
        virtual_base: 0,
        size: 0x1000,
    });
    assert!(!capsule_delivery_available(&runtime));

    runtime.capsule_delivery_enabled = true;
    assert!(capsule_delivery_available(&runtime));
}

#[test]
fn ordinary_variables_work_at_boot_and_runtime_without_authentication() {
    let mut store = VariableStore::new();
    let mut transaction = VariableTransaction::new();
    let guid = [0x42; 16];
    let name = [b'T' as u16];
    for (phase, data) in [
        (Phase::BootActive, b"boot".as_slice()),
        (Phase::SealedPhysical, b"runtime".as_slice()),
    ] {
        assert_eq!(
            apply(
                &mut store,
                &mut transaction,
                phase,
                VariableRequest {
                    guid,
                    name: &name,
                    attributes: ATTRIBUTES,
                    data,
                },
            ),
            efi::Status::SUCCESS
        );
        let slot = store.find(&guid, &name, true).unwrap();
        assert_eq!(store.data(slot), Some(data));
    }
}

#[test]
fn authentication_and_key_writes_are_unsupported_not_silently_accepted() {
    let mut store = VariableStore::new();
    let mut transaction = VariableTransaction::new();
    for (guid, name, attributes) in [
        (
            [0x42; 16],
            &[b'A' as u16][..],
            ATTRIBUTES | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
        ),
        (
            secure_boot::EFI_GLOBAL_VARIABLE_GUID,
            secure_boot::PK_NAME,
            ATTRIBUTES,
        ),
        (
            secure_boot::EFI_GLOBAL_VARIABLE_GUID,
            secure_boot::SECURE_BOOT_ENABLE_NAME,
            ATTRIBUTES,
        ),
    ] {
        assert_eq!(
            apply(
                &mut store,
                &mut transaction,
                Phase::BootActive,
                VariableRequest {
                    guid,
                    name,
                    attributes,
                    data: b"invalid",
                },
            ),
            efi::Status::UNSUPPORTED
        );
        assert!(store.find(&guid, name, false).is_none());
    }
    assert!(store.setup_mode());
    assert!(!store.secure_boot_enabled());
}

#[test]
fn status_variables_are_write_protected_and_missing_nv_backend_does_not_succeed() {
    let mut store = VariableStore::new();
    let mut transaction = VariableTransaction::new();
    for name in [secure_boot::SETUP_MODE_NAME, secure_boot::SECURE_BOOT_NAME] {
        assert_eq!(
            apply(
                &mut store,
                &mut transaction,
                Phase::BootActive,
                VariableRequest {
                    guid: secure_boot::EFI_GLOBAL_VARIABLE_GUID,
                    name,
                    attributes: ATTRIBUTES,
                    data: &[1],
                },
            ),
            efi::Status::WRITE_PROTECTED
        );
    }
    let name = [b'N' as u16];
    for (phase, expected) in [
        (Phase::BootActive, efi::Status::WRITE_PROTECTED),
        (Phase::SealedPhysical, efi::Status::UNSUPPORTED),
    ] {
        assert_eq!(
            apply(
                &mut store,
                &mut transaction,
                phase,
                VariableRequest {
                    guid: [0x42; 16],
                    name: &name,
                    attributes: ATTRIBUTES | VariableAttributes::NON_VOLATILE,
                    data: b"nv",
                },
            ),
            expected
        );
        assert!(store.find(&[0x42; 16], &name, false).is_none());
    }
}

#[test]
fn persisted_keys_cannot_enable_an_authentication_free_runtime() {
    let mut store = VariableStore::new();
    let mut transaction = VariableTransaction::new();
    for (name, data) in [
        (secure_boot::PK_NAME, b"old-key".as_slice()),
        (secure_boot::SECURE_BOOT_ENABLE_NAME, &[1][..]),
    ] {
        store
            .import(
                &mut transaction,
                secure_boot::EFI_GLOBAL_VARIABLE_GUID,
                name,
                ATTRIBUTES,
                data,
                None,
            )
            .unwrap();
    }
    assert!(store.setup_mode());
    assert!(!store.secure_boot_enabled());
}

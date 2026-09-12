//! Runtime policy checks without UEFI authentication support.

use crate::{
    efi,
    services::{apply_variable, capsule_delivery_available},
    state::RuntimeState,
    store::{VariableStore, VariableTransaction},
};
use crabefi_efi_types::secure_boot;
use crabefi_runtime_abi::phase;

const ATTRIBUTES: u32 = efi::VARIABLE_BOOTSERVICE_ACCESS | efi::VARIABLE_RUNTIME_ACCESS;

#[test]
fn capsule_delivery_requires_boot_consumer_enablement() {
    let mut runtime = RuntimeState::new();
    runtime.deferred_buffer_physical = 0x1000;
    runtime.deferred_buffer_size = 0x1000;
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
        (phase::BOOT_ACTIVE, b"boot".as_slice()),
        (phase::SEALED_PHYSICAL, b"runtime".as_slice()),
    ] {
        assert_eq!(
            apply_variable(
                &mut store,
                &mut transaction,
                None,
                phase,
                0,
                (core::ptr::null_mut(), 0),
                guid,
                &name,
                ATTRIBUTES,
                data
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
            ATTRIBUTES | efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
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
            apply_variable(
                &mut store,
                &mut transaction,
                None,
                phase::BOOT_ACTIVE,
                0,
                (core::ptr::null_mut(), 0),
                guid,
                name,
                attributes,
                b"invalid"
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
            apply_variable(
                &mut store,
                &mut transaction,
                None,
                phase::BOOT_ACTIVE,
                0,
                (core::ptr::null_mut(), 0),
                secure_boot::EFI_GLOBAL_VARIABLE_GUID,
                name,
                ATTRIBUTES,
                &[1]
            ),
            efi::Status::WRITE_PROTECTED
        );
    }
    let name = [b'N' as u16];
    for (phase, expected) in [
        (phase::BOOT_ACTIVE, efi::Status::WRITE_PROTECTED),
        (phase::SEALED_PHYSICAL, efi::Status::UNSUPPORTED),
    ] {
        assert_eq!(
            apply_variable(
                &mut store,
                &mut transaction,
                None,
                phase,
                0,
                (core::ptr::null_mut(), 0),
                [0x42; 16],
                &name,
                ATTRIBUTES | efi::VARIABLE_NON_VOLATILE,
                b"nv"
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

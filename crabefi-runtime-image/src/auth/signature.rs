//! Authentication-envelope parsing and Secure Boot authorization selection.

use alloc::vec::Vec;

use zerocopy::IntoBytes;

use super::structures::{
    EfiTime, EfiVariableAuthentication2, SignatureIterator, SignatureListIterator,
};
use super::variables::{EFI_CERT_X509_GUID, SecureBootVariable, identify_key_database};
use super::{
    AuthError, MAX_AUTHENTICATED_ENVELOPE_SIZE, WIN_CERT_REVISION, WIN_CERT_TYPE_EFI_GUID,
};
use crate::{efi, store::VariableStore};

const EFI_CERT_TYPE_PKCS7_GUID_BYTES: [u8; 16] = [
    0x9d, 0xd2, 0xaf, 0x4a, 0xdf, 0x68, 0xee, 0x49, 0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7,
];
const MAX_DATABASE_CERTIFICATES: usize = 32;

#[derive(Debug)]
pub struct VerifiedVariable<'a> {
    pub payload: &'a [u8],
    pub timestamp: EfiTime,
    pub secure_variable: Option<SecureBootVariable>,
}

pub fn verify_authenticated_variable<'a>(
    store: &VariableStore,
    variable_name: &[u16],
    vendor_guid: &[u8; 16],
    attributes: u32,
    data: &'a [u8],
) -> Result<VerifiedVariable<'a>, AuthError> {
    if data.len() > MAX_AUTHENTICATED_ENVELOPE_SIZE {
        return Err(AuthError::OutOfResources);
    }
    let authentication =
        EfiVariableAuthentication2::from_bytes(data).ok_or(AuthError::InvalidHeader)?;
    if (authentication.auth_info.hdr.dw_length as usize)
        < super::structures::WinCertificateUefiGuid::HEADER_SIZE
        || authentication.auth_info.hdr.w_revision != WIN_CERT_REVISION
        || authentication.auth_info.hdr.w_certificate_type != WIN_CERT_TYPE_EFI_GUID
        || authentication.auth_info.cert_type != EFI_CERT_TYPE_PKCS7_GUID_BYTES
        || authentication
            .total_size()
            .is_none_or(|size| size > data.len())
        || !authentication.time_stamp.is_valid()
    {
        return Err(AuthError::InvalidHeader);
    }
    let signature = authentication
        .cert_data(data)
        .ok_or(AuthError::InvalidHeader)?;
    let payload = authentication
        .variable_data(data)
        .ok_or(AuthError::InvalidHeader)?;
    let secure_variable = identify_key_database(vendor_guid, variable_name);

    if let Some(variable) = secure_variable {
        let previous = EfiTime::from_serialized(store.auth_timestamp(variable));
        if !authentication.time_stamp.is_after(&previous) {
            return Err(AuthError::InvalidTimestamp);
        }
    }

    if !store.setup_mode() || secure_variable.is_none() {
        if signature.is_empty() {
            return Err(AuthError::InvalidHeader);
        }
        let signed = build_signed_data(
            variable_name,
            vendor_guid,
            attributes,
            &authentication.time_stamp,
            payload,
        )?;
        let authorized = if let Some(variable) = secure_variable {
            let database = variable.authorizing_database();
            verify_database(store, database, signature, &signed)?
                || (database == SecureBootVariable::Kek
                    && verify_database(store, SecureBootVariable::PK, signature, &signed)?)
        } else {
            verify_database(store, SecureBootVariable::Db, signature, &signed)?
        };
        if !authorized {
            return Err(AuthError::SignatureVerificationFailed);
        }
    }

    Ok(VerifiedVariable {
        payload,
        timestamp: authentication.time_stamp,
        secure_variable,
    })
}

fn verify_database(
    store: &VariableStore,
    database: SecureBootVariable,
    signature: &[u8],
    signed_data: &[u8],
) -> Result<bool, AuthError> {
    let Some(data) = store.key_database_data(database) else {
        return Ok(false);
    };
    let x509 = *EFI_CERT_X509_GUID.as_bytes();
    let mut count = 0usize;
    for (list, list_data) in SignatureListIterator::new(data) {
        if list.signature_type != x509 {
            continue;
        }
        for (_, certificate) in SignatureIterator::new(list, list_data) {
            count += 1;
            if count > MAX_DATABASE_CERTIFICATES {
                return Err(AuthError::OutOfResources);
            }
            match super::crypto::verify_pkcs7_signature(signature, signed_data, certificate) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(AuthError::InvalidHeader | AuthError::CertificateParseError) => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(false)
}

fn build_signed_data(
    name: &[u16],
    guid: &[u8; 16],
    attributes: u32,
    timestamp: &EfiTime,
    data: &[u8],
) -> Result<Vec<u8>, AuthError> {
    let capacity = name
        .len()
        .checked_mul(2)
        .and_then(|size| size.checked_add(16 + 4 + 16))
        .and_then(|size| size.checked_add(data.len()))
        .ok_or(AuthError::OutOfResources)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(capacity)
        .map_err(|_| AuthError::OutOfResources)?;
    for unit in name.iter().take_while(|unit| **unit != 0) {
        result.extend_from_slice(&unit.to_le_bytes());
    }
    result.extend_from_slice(guid);
    result.extend_from_slice(&attributes.to_le_bytes());
    result.extend_from_slice(timestamp.as_bytes());
    result.extend_from_slice(data);
    Ok(result)
}

const _: () = assert!(core::mem::size_of::<efi::Time>() == core::mem::size_of::<EfiTime>());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::variables::PK_NAME,
        store::{VariableStore, VariableTransaction},
    };

    const ATTRIBUTES: u32 = efi::VARIABLE_NON_VOLATILE
        | efi::VARIABLE_BOOTSERVICE_ACCESS
        | efi::VARIABLE_RUNTIME_ACCESS
        | efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS;

    fn setup_envelope(year: u16, payload: &[u8]) -> Vec<u8> {
        let timestamp = EfiTime {
            year,
            month: 1,
            day: 2,
            hour: 3,
            minute: 4,
            second: 5,
            pad1: 0,
            nanosecond: 6,
            timezone: 0,
            daylight: 0,
            pad2: 0,
        };
        let mut envelope = Vec::new();
        envelope.extend_from_slice(timestamp.as_bytes());
        envelope.extend_from_slice(&24u32.to_le_bytes());
        envelope.extend_from_slice(&WIN_CERT_REVISION.to_le_bytes());
        envelope.extend_from_slice(&WIN_CERT_TYPE_EFI_GUID.to_le_bytes());
        envelope.extend_from_slice(&EFI_CERT_TYPE_PKCS7_GUID_BYTES);
        envelope.extend_from_slice(payload);
        envelope
    }

    #[test]
    fn signed_pk_kek_db_append_delete_and_unauthorized_paths() {
        let _guard = crate::scratch::test_lock();
        crate::scratch::activate();
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        let global = *super::super::EFI_GLOBAL_VARIABLE_GUID.as_bytes();
        let database = *super::super::variables::EFI_IMAGE_SECURITY_DATABASE_GUID.as_bytes();
        store
            .import(
                &mut transaction,
                global,
                PK_NAME,
                ATTRIBUTES,
                include_bytes!("../../tests/fixtures/pk.esl"),
                None,
            )
            .unwrap();

        assert_eq!(
            verify_authenticated_variable(
                &store,
                super::super::variables::KEK_NAME,
                &global,
                ATTRIBUTES,
                include_bytes!("../../tests/fixtures/unauthorized-update.bin"),
            )
            .unwrap_err(),
            AuthError::SignatureVerificationFailed
        );

        let kek = verify_authenticated_variable(
            &store,
            super::super::variables::KEK_NAME,
            &global,
            ATTRIBUTES,
            include_bytes!("../../tests/fixtures/kek-update.bin"),
        )
        .unwrap();
        store
            .import(
                &mut transaction,
                global,
                super::super::variables::KEK_NAME,
                ATTRIBUTES,
                kek.payload,
                Some(kek.timestamp.to_serialized()),
            )
            .unwrap();
        assert_eq!(
            verify_authenticated_variable(
                &store,
                super::super::variables::KEK_NAME,
                &global,
                ATTRIBUTES,
                include_bytes!("../../tests/fixtures/kek-update.bin"),
            )
            .unwrap_err(),
            AuthError::InvalidTimestamp
        );
        let mut older = include_bytes!("../../tests/fixtures/kek-update.bin").to_vec();
        older[..2].copy_from_slice(&2024u16.to_le_bytes());
        assert_eq!(
            verify_authenticated_variable(
                &store,
                super::super::variables::KEK_NAME,
                &global,
                ATTRIBUTES,
                &older,
            )
            .unwrap_err(),
            AuthError::InvalidTimestamp
        );

        let db = verify_authenticated_variable(
            &store,
            super::super::variables::DB_NAME,
            &database,
            ATTRIBUTES,
            include_bytes!("../../tests/fixtures/db-update.bin"),
        )
        .unwrap();
        store
            .import(
                &mut transaction,
                database,
                super::super::variables::DB_NAME,
                ATTRIBUTES,
                db.payload,
                Some(db.timestamp.to_serialized()),
            )
            .unwrap();

        let append_attributes = ATTRIBUTES | efi::VARIABLE_APPEND_WRITE;
        let append = verify_authenticated_variable(
            &store,
            super::super::variables::DB_NAME,
            &database,
            append_attributes,
            include_bytes!("../../tests/fixtures/db-append.bin"),
        )
        .unwrap();
        let mut expected_database = db.payload.to_vec();
        expected_database.extend_from_slice(append.payload);
        let mut prepared = store
            .prepare(
                database,
                super::super::variables::DB_NAME,
                append_attributes,
                append.payload.len(),
            )
            .unwrap();
        store
            .stage(&mut transaction, &mut prepared, append.payload, true)
            .unwrap();
        store.commit(&transaction, prepared, super::super::variables::DB_NAME);
        store.commit_auth_timestamp(SecureBootVariable::Db, append.timestamp.to_serialized());
        assert_eq!(
            store.key_database_data(SecureBootVariable::Db).unwrap(),
            expected_database
        );

        let deletion = verify_authenticated_variable(
            &store,
            super::super::variables::DB_NAME,
            &database,
            ATTRIBUTES,
            include_bytes!("../../tests/fixtures/db-delete.bin"),
        )
        .unwrap();
        assert!(deletion.payload.is_empty());
        let mut prepared = store
            .prepare(database, super::super::variables::DB_NAME, ATTRIBUTES, 0)
            .unwrap();
        store
            .stage(&mut transaction, &mut prepared, &[], false)
            .unwrap();
        store.commit(&transaction, prepared, super::super::variables::DB_NAME);
        store.commit_auth_timestamp(SecureBootVariable::Db, deletion.timestamp.to_serialized());
        assert!(store.key_database_data(SecureBootVariable::Db).is_none());
        assert!(crate::scratch::high_water_for_test() < crate::scratch::SCRATCH_SIZE);
        crate::scratch::reset();
    }

    #[test]
    fn maximum_authenticated_input_stays_within_scratch() {
        let _guard = crate::scratch::test_lock();
        crate::scratch::activate();
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        let global = *super::super::EFI_GLOBAL_VARIABLE_GUID.as_bytes();
        store
            .import(
                &mut transaction,
                global,
                PK_NAME,
                ATTRIBUTES,
                include_bytes!("../../tests/fixtures/pk.esl"),
                None,
            )
            .unwrap();
        let mut maximum = include_bytes!("../../tests/fixtures/kek-update.bin").to_vec();
        maximum.resize(super::super::MAX_AUTHENTICATED_ENVELOPE_SIZE, 0);
        assert_eq!(
            verify_authenticated_variable(
                &store,
                super::super::variables::KEK_NAME,
                &global,
                ATTRIBUTES,
                &maximum,
            )
            .unwrap_err(),
            AuthError::SignatureVerificationFailed
        );
        assert!(crate::scratch::high_water_for_test() < 384 * 1024);
        crate::scratch::reset();
    }

    #[test]
    fn setup_enrollment_replay_rejection_and_pk_mode_transition() {
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        let guid = *super::super::EFI_GLOBAL_VARIABLE_GUID.as_bytes();
        let pk = include_bytes!("../../tests/fixtures/pk.esl");
        let envelope = setup_envelope(2025, pk);
        let verified =
            verify_authenticated_variable(&store, PK_NAME, &guid, ATTRIBUTES, &envelope).unwrap();
        assert_eq!(verified.payload, pk);
        let timestamp = verified.timestamp.to_serialized();
        let mut prepared = store
            .prepare(guid, PK_NAME, ATTRIBUTES, verified.payload.len())
            .unwrap();
        store
            .stage(&mut transaction, &mut prepared, verified.payload, false)
            .unwrap();
        store.commit(&transaction, prepared, PK_NAME);
        store.commit_auth_timestamp(SecureBootVariable::PK, timestamp);
        assert!(!store.setup_mode());

        assert_eq!(
            verify_authenticated_variable(&store, PK_NAME, &guid, ATTRIBUTES, &envelope,)
                .unwrap_err(),
            AuthError::InvalidTimestamp
        );

        let mut deletion = store.prepare(guid, PK_NAME, ATTRIBUTES, 0).unwrap();
        store
            .stage(&mut transaction, &mut deletion, &[], false)
            .unwrap();
        store.commit(&transaction, deletion, PK_NAME);
        assert!(store.setup_mode());
        assert!(!store.secure_boot_enabled());
        assert_eq!(store.auth_timestamp(SecureBootVariable::PK), timestamp);
    }
}

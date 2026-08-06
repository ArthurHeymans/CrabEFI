//! Authentication-envelope parsing and Secure Boot authorization selection.

use crabefi_efi_types::{
    authentication::{
        EfiTime, EfiVariableAuthentication2, SignatureIterator, SignatureListIterator,
        WinCertificateUefiGuid,
    },
    secure_boot::{
        EFI_CERT_TYPE_PKCS7_GUID, EFI_CERT_X509_GUID, SecureBootVariable, identify_key_database,
    },
};
use sha2::{Digest, Sha256};
use zerocopy::IntoBytes;

use super::{
    AuthError, MAX_AUTHENTICATED_ENVELOPE_SIZE, WIN_CERT_REVISION, WIN_CERT_TYPE_EFI_GUID,
};
use crate::{efi, store::VariableStore};

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
    if (authentication.auth_info.hdr.dw_length as usize) < WinCertificateUefiGuid::HEADER_SIZE
        || authentication.auth_info.hdr.w_revision != WIN_CERT_REVISION
        || authentication.auth_info.hdr.w_certificate_type != WIN_CERT_TYPE_EFI_GUID
        || authentication.auth_info.cert_type != EFI_CERT_TYPE_PKCS7_GUID
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
        let previous = super::efi_time_from_timestamp(store.auth_timestamp(variable));
        if !authentication.time_stamp.is_after(&previous) {
            return Err(AuthError::InvalidTimestamp);
        }
    }

    if !store.setup_mode() || secure_variable.is_none() {
        if signature.is_empty() {
            return Err(AuthError::InvalidHeader);
        }
        let signed_hash = signed_data_hash(
            variable_name,
            vendor_guid,
            attributes,
            &authentication.time_stamp,
            payload,
        );
        let authorized = if let Some(variable) = secure_variable {
            let database = variable.authorizing_database();
            verify_database(store, database, signature, &signed_hash)?
                || (database == SecureBootVariable::Kek
                    && verify_database(store, SecureBootVariable::PK, signature, &signed_hash)?)
        } else {
            verify_database(store, SecureBootVariable::Db, signature, &signed_hash)?
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
    signed_hash: &[u8; 32],
) -> Result<bool, AuthError> {
    let Some(data) = store.key_database_data(database) else {
        return Ok(false);
    };
    let x509 = EFI_CERT_X509_GUID;
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
            match super::crypto::verify_pkcs7_signature_hash(signature, signed_hash, certificate) {
                Ok(true) => return Ok(true),
                Ok(false) => {}
                Err(AuthError::InvalidHeader | AuthError::CertificateParseError) => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(false)
}

fn signed_data_hash(
    name: &[u16],
    guid: &[u8; 16],
    attributes: u32,
    timestamp: &EfiTime,
    data: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    for unit in name.iter().take_while(|unit| **unit != 0) {
        hash.update(unit.to_le_bytes());
    }
    hash.update(guid);
    hash.update(attributes.to_le_bytes());
    hash.update(timestamp.as_bytes());
    hash.update(data);
    hash.finalize().into()
}

const _: () = assert!(core::mem::size_of::<efi::Time>() == core::mem::size_of::<EfiTime>());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{VariableStore, VariableTransaction};
    use crabefi_efi_types::secure_boot::{
        DB_NAME, EFI_GLOBAL_VARIABLE_GUID, EFI_IMAGE_SECURITY_DATABASE_GUID, KEK_NAME, PK_NAME,
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
        envelope.extend_from_slice(&EFI_CERT_TYPE_PKCS7_GUID);
        envelope.extend_from_slice(payload);
        envelope
    }

    #[test]
    fn signed_pk_kek_db_append_delete_and_unauthorized_paths() {
        let _guard = crate::scratch::test_lock();
        crate::scratch::activate();
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        let global = EFI_GLOBAL_VARIABLE_GUID;
        let database = EFI_IMAGE_SECURITY_DATABASE_GUID;
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
                KEK_NAME,
                &global,
                ATTRIBUTES,
                include_bytes!("../../tests/fixtures/unauthorized-update.bin"),
            )
            .unwrap_err(),
            AuthError::SignatureVerificationFailed
        );

        let kek = verify_authenticated_variable(
            &store,
            KEK_NAME,
            &global,
            ATTRIBUTES,
            include_bytes!("../../tests/fixtures/kek-update.bin"),
        )
        .unwrap();
        store
            .import(
                &mut transaction,
                global,
                KEK_NAME,
                ATTRIBUTES,
                kek.payload,
                Some(crate::auth::timestamp_from_efi_time(kek.timestamp)),
            )
            .unwrap();
        assert_eq!(
            verify_authenticated_variable(
                &store,
                KEK_NAME,
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
            verify_authenticated_variable(&store, KEK_NAME, &global, ATTRIBUTES, &older,)
                .unwrap_err(),
            AuthError::InvalidTimestamp
        );

        let db = verify_authenticated_variable(
            &store,
            DB_NAME,
            &database,
            ATTRIBUTES,
            include_bytes!("../../tests/fixtures/db-update.bin"),
        )
        .unwrap();
        store
            .import(
                &mut transaction,
                database,
                DB_NAME,
                ATTRIBUTES,
                db.payload,
                Some(crate::auth::timestamp_from_efi_time(db.timestamp)),
            )
            .unwrap();

        let append_attributes = ATTRIBUTES | efi::VARIABLE_APPEND_WRITE;
        let append = verify_authenticated_variable(
            &store,
            DB_NAME,
            &database,
            append_attributes,
            include_bytes!("../../tests/fixtures/db-append.bin"),
        )
        .unwrap();
        let mut expected_database = db.payload.to_vec();
        expected_database.extend_from_slice(append.payload);
        let mut prepared = store
            .prepare(database, DB_NAME, append_attributes, append.payload.len())
            .unwrap();
        store
            .stage(&mut transaction, &mut prepared, append.payload, true)
            .unwrap();
        store.commit(&transaction, prepared, DB_NAME).unwrap();
        store.commit_auth_timestamp(
            SecureBootVariable::Db,
            crate::auth::timestamp_from_efi_time(append.timestamp),
        );
        assert_eq!(
            store.key_database_data(SecureBootVariable::Db).unwrap(),
            expected_database
        );

        let deletion = verify_authenticated_variable(
            &store,
            DB_NAME,
            &database,
            ATTRIBUTES,
            include_bytes!("../../tests/fixtures/db-delete.bin"),
        )
        .unwrap();
        assert!(deletion.payload.is_empty());
        let mut prepared = store.prepare(database, DB_NAME, ATTRIBUTES, 0).unwrap();
        store
            .stage(&mut transaction, &mut prepared, &[], false)
            .unwrap();
        store.commit(&transaction, prepared, DB_NAME).unwrap();
        store.commit_auth_timestamp(
            SecureBootVariable::Db,
            crate::auth::timestamp_from_efi_time(deletion.timestamp),
        );
        assert!(store.key_database_data(SecureBootVariable::Db).is_none());
        assert!(
            crate::scratch::high_water_for_test() <= super::super::AUTH_OPERATION_SCRATCH_BOUND
        );
        crate::scratch::reset();
    }

    #[test]
    fn maximum_authenticated_input_stays_within_scratch() {
        let _guard = crate::scratch::test_lock();
        crate::scratch::activate();
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        let global = EFI_GLOBAL_VARIABLE_GUID;
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
            verify_authenticated_variable(&store, KEK_NAME, &global, ATTRIBUTES, &maximum,)
                .unwrap_err(),
            AuthError::SignatureVerificationFailed
        );
        assert!(
            crate::scratch::high_water_for_test() <= super::super::AUTH_OPERATION_SCRATCH_BOUND
        );
        crate::scratch::reset();
    }

    #[test]
    fn setup_enrollment_replay_rejection_and_pk_mode_transition() {
        let mut store = VariableStore::new();
        let mut transaction = VariableTransaction::new();
        let guid = EFI_GLOBAL_VARIABLE_GUID;
        let pk = include_bytes!("../../tests/fixtures/pk.esl");
        let envelope = setup_envelope(2025, pk);
        let verified =
            verify_authenticated_variable(&store, PK_NAME, &guid, ATTRIBUTES, &envelope).unwrap();
        assert_eq!(verified.payload, pk);
        let timestamp = crate::auth::timestamp_from_efi_time(verified.timestamp);
        let mut prepared = store
            .prepare(guid, PK_NAME, ATTRIBUTES, verified.payload.len())
            .unwrap();
        store
            .stage(&mut transaction, &mut prepared, verified.payload, false)
            .unwrap();
        store.commit(&transaction, prepared, PK_NAME).unwrap();
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
        store.commit(&transaction, deletion, PK_NAME).unwrap();
        assert!(store.setup_mode());
        assert!(!store.secure_boot_enabled());
        assert_eq!(store.auth_timestamp(SecureBootVariable::PK), timestamp);
    }
}

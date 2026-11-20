//! Variable write policy and transaction handling.

mod bridge;
mod io;
mod journal;

pub use io::{get_next_variable_name, get_variable, query_variable_info, set_variable};
pub use journal::{prepare_retained_staging, replay_deferred};

use bridge::{
    persist_through_bridge, setup_pk_delete_authorized, setup_secure_boot_enable_authorized,
};
use journal::queue_deferred;

use crabefi_efi_types::{
    authentication::validate_signature_database,
    secure_boot::{self, SecureBootVariable},
};

#[cfg(feature = "mm")]
use crate::state;
use crate::{
    deferred::{self, DeferredRegion},
    efi::{self, VariableAttributes},
    state::Phase,
    store::{VariableStore, VariableTransaction},
};
use crabefi_runtime_abi::{MAX_VARIABLE_DATA_SIZE, VariableTimestamp, capsule, event_log};

#[cfg(feature = "secure-boot")]
use crate::auth;

const KEY_DATABASE_ATTRIBUTES: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS)
    .union(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS);

fn validate_set_arguments(
    attributes: VariableAttributes,
    data_size: usize,
) -> Result<(), efi::Status> {
    let boot_access = attributes.contains(VariableAttributes::BOOTSERVICE_ACCESS);
    if (data_size != 0 || attributes.contains(VariableAttributes::RUNTIME_ACCESS)) && !boot_access {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let time_based = attributes.contains(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS);
    if attributes.contains(VariableAttributes::AUTHENTICATED_WRITE_ACCESS)
        || (!cfg!(feature = "secure-boot") && time_based)
    {
        return Err(efi::Status::UNSUPPORTED);
    }
    #[cfg(feature = "secure-boot")]
    let maximum = if time_based {
        auth::MAX_AUTHENTICATED_ENVELOPE_SIZE
    } else {
        MAX_VARIABLE_DATA_SIZE
    };
    #[cfg(not(feature = "secure-boot"))]
    let maximum = MAX_VARIABLE_DATA_SIZE;
    if data_size > maximum {
        return Err(efi::Status::OUT_OF_RESOURCES);
    }
    Ok(())
}

/// One SetVariable request as supplied by the caller.
#[derive(Clone, Copy)]
struct VariableRequest<'a> {
    guid: [u8; 16],
    name: &'a [u16],
    attributes: VariableAttributes,
    data: &'a [u8],
}

impl VariableRequest<'_> {
    fn authenticated(&self) -> bool {
        self.attributes
            .contains(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
    }

    fn append(&self) -> bool {
        self.attributes.contains(VariableAttributes::APPEND_WRITE)
    }

    /// A deletion without an authentication envelope.
    fn raw_delete(&self) -> bool {
        self.attributes.is_empty() || (self.data.is_empty() && !self.append())
    }

    /// The request creates, updates or deletes a non-volatile variable.
    fn nonvolatile(&self, store: &VariableStore) -> bool {
        self.attributes.contains(VariableAttributes::NON_VOLATILE)
            || (self.data.is_empty()
                && store
                    .find(&self.guid, self.name, false)
                    .is_some_and(|slot| slot.attributes.contains(VariableAttributes::NON_VOLATILE)))
    }
}

/// Retained journal receiving non-volatile writes after ExitBootServices.
struct DeferredSink<'a> {
    transaction: &'a mut deferred::DeferredTransaction,
    region: DeferredRegion<'a>,
}

/// Store and persistence targets of one variable write.
struct VariableContext<'a> {
    store: &'a mut VariableStore,
    transaction: &'a mut VariableTransaction,
    phase: Phase,
    bridge: u64,
    deferred: Option<DeferredSink<'a>>,
}

impl<'a> VariableContext<'a> {
    /// Boot-time context persisting through the boot bridge.
    fn boot(
        store: &'a mut VariableStore,
        transaction: &'a mut VariableTransaction,
        bridge: u64,
    ) -> Self {
        Self {
            store,
            transaction,
            phase: Phase::BootActive,
            bridge,
            deferred: None,
        }
    }
}

/// Request payload after authentication.
struct Verified<'a> {
    payload: &'a [u8],
    timestamp: Option<VariableTimestamp>,
    secure_variable: Option<SecureBootVariable>,
    /// Signer binding of a private authenticated variable.
    #[cfg(feature = "secure-boot")]
    private_signer: Option<[u8; auth::cert_db::DIGEST_SIZE]>,
}

/// Validate, authenticate, persist and commit one variable write.
fn apply_variable(
    context: VariableContext<'_>,
    request: VariableRequest<'_>,
) -> Result<(), efi::Status> {
    let VariableContext {
        store,
        transaction,
        phase,
        bridge,
        mut deferred,
    } = context;
    validate_set_arguments(request.attributes, request.data.len())?;
    if phase.runtime() {
        check_runtime_target(store, &request)?;
    }
    if !phase.boot_services() && request.nonvolatile(store) {
        deferred
            .as_ref()
            .ok_or(efi::Status::UNSUPPORTED)?
            .region
            .validate_profile()?;
    }
    let (secure_variable, verified) = if setup_pk_delete_authorized(store, &request, phase, bridge)
    {
        // Physical-presence setup can remove PK without its private key. Keep
        // the existing authentication floor on the deletion tombstone; only
        // authentication is bypassed, not staging, persistence or live commit.
        (
            Some(SecureBootVariable::PK),
            Verified {
                payload: &[],
                timestamp: store.auth_history_timestamp(&request.guid, request.name),
                secure_variable: Some(SecureBootVariable::PK),
                #[cfg(feature = "secure-boot")]
                private_signer: None,
            },
        )
    } else {
        (
            check_write_policy(store, &request, phase, bridge)?,
            verify(store, &request)?,
        )
    };
    if verified.payload.len() > MAX_VARIABLE_DATA_SIZE {
        return Err(efi::Status::OUT_OF_RESOURCES);
    }
    #[cfg(feature = "secure-boot")]
    let delete = verified.payload.is_empty() && !request.append();
    if phase.runtime() {
        check_runtime_access(store, &request, verified.payload.is_empty())?;
    }
    // Before ExitBootServices (and always in MM) bindings persist at once;
    // after it, replaying the journalled envelope rebuilds them.
    #[cfg(feature = "secure-boot")]
    let persist = phase.boot_services().then_some(bridge);
    // A private authenticated variable is bound to the signer of its first
    // write. Record the binding before the variable exists, so none ever
    // lacks one; a binding left by a failed write is replaced on creation.
    #[cfg(feature = "secure-boot")]
    let unbind = match verified.private_signer {
        Some(signer) => match store
            .find(&request.guid, request.name, false)
            .map(|slot| slot.attributes.contains(VariableAttributes::NON_VOLATILE))
        {
            // EDK2: an empty append to an absent variable creates nothing.
            None if verified.payload.is_empty() && request.append() => return Ok(()),
            None if !delete => {
                let nonvolatile = request
                    .attributes
                    .contains(VariableAttributes::NON_VOLATILE);
                bind_signer(
                    store,
                    transaction,
                    persist,
                    nonvolatile,
                    &request,
                    Some(&signer),
                )?;
                Some((nonvolatile, true))
            }
            Some(nonvolatile) if delete => Some((nonvolatile, false)),
            _ => None,
        },
        None => None,
    };

    // A creation that fails after its signer was bound drops the binding
    // again, so failed writes leave nothing behind in the signer database.
    let result = (|| -> Result<(), efi::Status> {
        // As in EDK2, appending nothing to a variable that does not exist
        // succeeds without creating it.
        if request.append()
            && verified.payload.is_empty()
            && store.find(&request.guid, request.name, false).is_none()
        {
            return Ok(());
        }
        let mut prepared = store.prepare(
            request.guid,
            request.name,
            request.attributes,
            verified.payload.len(),
        )?;
        // Authenticated commits (including deletions) record their timestamp so
        // later envelopes must be strictly newer.
        let recorded = verified.timestamp.map(|timestamp| {
            recorded_timestamp(store, &request, verified.secure_variable, timestamp)
        });
        prepared.timestamp = recorded.unwrap_or_default();
        let staged_len = store
            .stage(
                transaction,
                &mut prepared,
                verified.payload,
                request.append(),
            )?
            .len();
        let staged = transaction
            .data(staged_len)
            .ok_or(efi::Status::DEVICE_ERROR)?;
        if secure_variable.is_some() && !prepared.delete && !validate_signature_database(staged) {
            return Err(efi::Status::INVALID_PARAMETER);
        }
        // An append that adds nothing and does not advance the timestamp leaves
        // the variable as it is. Do not rewrite flash for it.
        if request.append()
            && store
                .find(&request.guid, request.name, false)
                .is_some_and(|slot| {
                    usize::from(slot.data_len) == staged_len && slot.timestamp == prepared.timestamp
                })
        {
            return Ok(());
        }

        if prepared
            .attributes
            .contains(VariableAttributes::NON_VOLATILE)
        {
            if phase.boot_services() {
                persist_through_bridge(bridge, &request, &prepared, staged, recorded)?;
            } else {
                let sink = deferred.as_mut().ok_or(efi::Status::DEVICE_ERROR)?;
                queue_deferred(sink, &request, &prepared, staged, verified.timestamp)?;
            }
        }

        store.commit(transaction, prepared, request.name)?;
        if let (Some(variable), Some(timestamp)) = (verified.secure_variable, recorded) {
            store.commit_auth_timestamp(variable, timestamp);
        }
        store.refresh_policy();
        Ok(())
    })();
    #[cfg(feature = "secure-boot")]
    if let Some((nonvolatile, created)) = unbind
        && (created != result.is_ok())
    {
        // Deleted, or a creation that failed: drop the binding. One that
        // stays behind after a failure here is harmless, as creating the
        // variable again replaces it.
        let _ = bind_signer(store, transaction, persist, nonvolatile, &request, None);
    }
    result
}

/// Bind the private authenticated variable of `owner` to `signer`, or drop
/// its binding, in the signer database (EDK2 certdb layout). It is written
/// like any variable, but never journalled: after ExitBootServices
/// replaying the variable's envelope rebuilds it.
#[cfg(feature = "secure-boot")]
fn bind_signer(
    store: &mut VariableStore,
    transaction: &mut VariableTransaction,
    persist: Option<u64>,
    nonvolatile: bool,
    owner: &VariableRequest<'_>,
    signer: Option<&[u8; auth::cert_db::DIGEST_SIZE]>,
) -> Result<(), efi::Status> {
    let name = auth::cert_db::name(nonvolatile);
    let attributes = auth::cert_db::attributes(nonvolatile);
    let current = store
        .find(&auth::cert_db::GUID, name, false)
        .and_then(|slot| store.data(slot))
        .unwrap_or_default();
    let length = auth::cert_db::stage(transaction, current, &owner.guid, owner.name, signer)?;
    let mut prepared = store.prepare(auth::cert_db::GUID, name, attributes, length)?;
    store.accept_staged(&mut prepared, length)?;
    if let (true, Some(bridge)) = (nonvolatile, persist) {
        let request = VariableRequest {
            guid: auth::cert_db::GUID,
            name,
            attributes,
            data: &[],
        };
        let staged = transaction.data(length).ok_or(efi::Status::DEVICE_ERROR)?;
        persist_through_bridge(bridge, &request, &prepared, staged, None)?;
    }
    store.commit(transaction, prepared, name)
}

/// The newest authenticated timestamp recorded for `guid`/`name` (see
/// `mm_protocol::command::AUTH_TIMESTAMP`), for boot firmware issuing its own
/// authenticated writes while payload MM holds the store.
#[cfg(feature = "mm")]
pub fn auth_timestamp_floor(
    guid: &[u8; 16],
    name: &[u16],
) -> Result<Option<VariableTimestamp>, efi::Status> {
    // Only firmware key enrollment needs it, for the key databases.
    let variable =
        secure_boot::identify_key_database(guid, name).ok_or(efi::Status::INVALID_PARAMETER)?;
    let lease = state::lease()?;
    let store = lease.variables();
    let secure = Some(store.auth_timestamp(variable))
        .filter(|timestamp| *timestamp != VariableTimestamp::default());
    Ok([secure, store.auth_history_timestamp(guid, name)]
        .into_iter()
        .flatten()
        .reduce(|newest, floor| {
            if timestamp_is_after(floor, newest) {
                floor
            } else {
                newest
            }
        }))
}

/// Timestamp to record for an authenticated write: the envelope's own, unless
/// an append carried an older one than the variable already has. An append
/// must not lower the floor later replacements and deletions are held to.
fn recorded_timestamp(
    store: &VariableStore,
    request: &VariableRequest<'_>,
    secure_variable: Option<SecureBootVariable>,
    timestamp: VariableTimestamp,
) -> VariableTimestamp {
    let history = store.auth_history_timestamp(&request.guid, request.name);
    [
        secure_variable.map(|variable| store.auth_timestamp(variable)),
        history,
    ]
    .into_iter()
    .flatten()
    .fold(timestamp, |newest, floor| {
        if timestamp_is_after(floor, newest) {
            floor
        } else {
            newest
        }
    })
}

#[cfg(feature = "secure-boot")]
fn timestamp_is_after(timestamp: VariableTimestamp, other: VariableTimestamp) -> bool {
    auth::efi_time_from_timestamp(timestamp).is_after(&auth::efi_time_from_timestamp(other))
}

/// Without authenticated variables no write carries a timestamp.
#[cfg(not(feature = "secure-boot"))]
fn timestamp_is_after(_timestamp: VariableTimestamp, _other: VariableTimestamp) -> bool {
    false
}

/// SecureBootEnable switches enforcement off, so outside Setup Mode only
/// CrabEFI's physical-presence setup action may change it, and nothing may
/// after ExitBootServices.
fn check_secure_boot_enable(
    store: &VariableStore,
    request: &VariableRequest<'_>,
    phase: Phase,
    bridge: u64,
) -> Result<(), efi::Status> {
    if phase.runtime() || !phase.boot_services() {
        Err(efi::Status::WRITE_PROTECTED)
    } else if store.setup_mode() || setup_secure_boot_enable_authorized(request, phase, bridge) {
        Ok(())
    } else {
        Err(efi::Status::SECURITY_VIOLATION)
    }
}

/// Signer bindings are firmware-owned, as EDK2 makes certdb read-only.
fn is_signer_database(guid: &[u8; 16], name: &[u16]) -> bool {
    #[cfg(feature = "secure-boot")]
    return auth::cert_db::is_cert_db(guid, name);
    #[cfg(not(feature = "secure-boot"))]
    {
        let _ = (guid, name);
        false
    }
}

/// Reject writes to protected variables and raw writes to authenticated ones.
fn check_write_policy(
    store: &VariableStore,
    request: &VariableRequest<'_>,
    phase: Phase,
    bridge: u64,
) -> Result<Option<SecureBootVariable>, efi::Status> {
    let (guid, name) = (&request.guid, request.name);
    if secure_boot::is_status_variable(guid, name)
        || capsule::is_esrt_last_attempt_variable(guid, name)
        || event_log::is_event_log_variable(guid, name)
        || is_signer_database(guid, name)
    {
        return Err(efi::Status::WRITE_PROTECTED);
    }
    let secure_variable = secure_boot::identify_key_database(guid, name);
    #[cfg(not(feature = "secure-boot"))]
    if secure_variable.is_some() || secure_boot::is_secure_boot_enable(guid, name) {
        return Err(efi::Status::UNSUPPORTED);
    }
    if secure_boot::is_secure_boot_enable(guid, name) {
        check_secure_boot_enable(store, request, phase, bridge)?;
    }
    if secure_variable.is_some() && !request.authenticated() && !store.setup_mode() {
        return Err(efi::Status::SECURITY_VIOLATION);
    }
    // EDK2 parity (AuthService.c `ProcessVariable`): a variable with
    // time-based authentication history keeps requiring an authenticated
    // envelope for every later update, append, and deletion, whatever its
    // GUID. This includes tombstones left by authenticated deletions, so a
    // deleted variable cannot be silently re-created with raw content.
    if !request.authenticated() && store.auth_history_timestamp(guid, name).is_some() {
        return Err(efi::Status::WRITE_PROTECTED);
    }
    // UEFI 2.10 3.3 (Table 3-1) and 8.2: PK, KEK, db and dbx are
    // NV|BS|RT|TIME_BASED_AUTHENTICATED_WRITE_ACCESS; APPEND_WRITE may be
    // added. Raw deletions are left to the checks above, as in EDK2's
    // VarCheck. EDK2 checks attributes first; checking them last keeps
    // CrabEFI's statuses for raw writes in User Mode and over history.
    if secure_variable.is_some()
        && !request.raw_delete()
        && request
            .attributes
            .difference(VariableAttributes::APPEND_WRITE)
            != KEY_DATABASE_ATTRIBUTES
    {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    Ok(secure_variable)
}

#[cfg(feature = "secure-boot")]
fn verify<'a>(
    store: &VariableStore,
    request: &VariableRequest<'a>,
) -> Result<Verified<'a>, efi::Status> {
    if !request.authenticated() {
        return Ok(Verified {
            payload: request.data,
            timestamp: None,
            secure_variable: None,
            private_signer: None,
        });
    }
    let verified = auth::verify_authenticated_variable(
        store,
        request.name,
        &request.guid,
        request.attributes.bits(),
        request.data,
    )?;
    Ok(Verified {
        payload: verified.payload,
        timestamp: Some(auth::timestamp_from_efi_time(verified.timestamp)),
        secure_variable: verified.secure_variable,
        private_signer: verified.private_signer,
    })
}

#[cfg(not(feature = "secure-boot"))]
fn verify<'a>(
    _store: &VariableStore,
    request: &VariableRequest<'a>,
) -> Result<Verified<'a>, efi::Status> {
    Ok(Verified {
        payload: request.data,
        timestamp: None,
        secure_variable: None,
    })
}

const RUNTIME_WRITABLE: VariableAttributes =
    VariableAttributes::NON_VOLATILE.union(VariableAttributes::RUNTIME_ACCESS);

/// After ExitBootServices only non-volatile, runtime-accessible variables
/// may be written, appended to or deleted (UEFI 2.10, 8.2). As in EDK2's
/// `VariableServiceSetVariable`, the stored variable decides first, before any
/// other check: boot-only variables are invisible at runtime and volatile ones
/// read-only, so both answer `WRITE_PROTECTED` whatever the request says.
/// Checking only the request let an append change a boot-only variable,
/// because an append keeps the stored attributes.
fn check_runtime_target(
    store: &VariableStore,
    request: &VariableRequest<'_>,
) -> Result<(), efi::Status> {
    // Boot-only settings are never runtime-writable, even while absent.
    if crabefi_runtime_abi::settings::is_boot_only_setting(&request.guid, request.name) {
        return Err(efi::Status::WRITE_PROTECTED);
    }
    if store
        .find(&request.guid, request.name, false)
        .is_some_and(|slot| !slot.attributes.contains(RUNTIME_WRITABLE))
    {
        return Err(efi::Status::WRITE_PROTECTED);
    }
    Ok(())
}

/// [`check_runtime_target`], then the request, as in EDK2: with nothing
/// stored, a deletion fails with `NOT_FOUND` and an empty append succeeds
/// without effect; otherwise a request that could only create a variable the
/// runtime may not write fails with `INVALID_PARAMETER` (attributes 0 is a
/// deletion). `payload_empty` refers to the authenticated payload.
fn check_runtime_access(
    store: &VariableStore,
    request: &VariableRequest<'_>,
    payload_empty: bool,
) -> Result<(), efi::Status> {
    check_runtime_target(store, request)?;
    if payload_empty && store.find(&request.guid, request.name, false).is_none() {
        return if request.append() {
            Ok(())
        } else {
            Err(efi::Status::NOT_FOUND)
        };
    }
    if !request.attributes.is_empty() && !request.attributes.contains(RUNTIME_WRITABLE) {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    Ok(())
}

#[cfg(all(test, not(feature = "secure-boot")))]
mod basic_tests;
#[cfg(all(test, feature = "secure-boot"))]
mod tests;

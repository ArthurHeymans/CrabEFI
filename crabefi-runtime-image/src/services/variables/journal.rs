//! Retained staging and replay of runtime variable writes.

use super::super::capsule::{CAPSULE_UPDATE_GUID, CAPSULE_UPDATE_NAME};
use super::{
    DeferredSink, VariableContext, VariableRequest, apply_variable, check_runtime_access,
    timestamp_is_after,
};
use crate::{
    deferred,
    efi::{self, VariableAttributes},
    state,
    store::{PreparedWrite, VariableStore, VariableTransaction},
};
use crabefi_efi_types::secure_boot;
use crabefi_runtime_abi::{MAX_VARIABLE_NAME_LEN, VariableTimestamp};

/// Journal a runtime write for replay on the next boot. Authenticated
/// requests keep their envelope so replay re-verifies it.
pub(super) fn queue_deferred(
    sink: &mut DeferredSink<'_>,
    request: &VariableRequest<'_>,
    prepared: &PreparedWrite,
    staged: &[u8],
    timestamp: Option<VariableTimestamp>,
) -> Result<(), efi::Status> {
    let (attributes, data) = if request.authenticated() {
        (request.attributes, request.data)
    } else if prepared.delete {
        (VariableAttributes::empty(), staged)
    } else {
        (prepared.attributes, staged)
    };
    // Raw writes journal the final value, so replaying one twice is harmless.
    // An authenticated append journals its envelope instead, to be verified
    // again; record what it leaves behind so replay can tell it is applied.
    let result_digest = if request.authenticated() && request.append() && !prepared.delete {
        append_result_digest(staged)
    } else {
        0
    };
    sink.region.queue_write(
        sink.transaction,
        deferred::DeferredWrite {
            guid: request.guid,
            name: request.name,
            attributes,
            data,
            timestamp: timestamp.unwrap_or_default(),
            authenticated: request.authenticated(),
            deletion: prepared.delete,
            result_digest,
        },
    )
}

/// Nonzero 64-bit digest of a variable's data, for [`deferred::VariableRecord::result_digest`].
#[cfg(feature = "secure-boot")]
fn append_result_digest(data: &[u8]) -> u64 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(prefix).max(1)
}

/// Authenticated writes need the secure-boot build.
#[cfg(not(feature = "secure-boot"))]
fn append_result_digest(_data: &[u8]) -> u64 {
    0
}

pub fn prepare_retained_staging(lease: &mut state::Lease) -> Result<(), efi::Status> {
    let (runtime, variables) = lease.parts_mut();
    let bridge = runtime.boot_bridge;
    let mut region = runtime.deferred_region().ok_or(efi::Status::UNSUPPORTED)?;
    if bridge == 0 {
        return Err(efi::Status::WRITE_PROTECTED);
    }
    let data = region.prepare_retained()?.to_le_bytes();
    let guid = *CAPSULE_UPDATE_GUID.as_bytes();
    let (store, transaction) = (&mut variables.store, &mut variables.transaction);
    if store
        .find(&guid, CAPSULE_UPDATE_NAME, false)
        .and_then(|slot| store.data(slot))
        == Some(data.as_slice())
    {
        return Ok(());
    }
    apply_variable(
        VariableContext::boot(store, transaction, bridge),
        VariableRequest {
            guid,
            name: CAPSULE_UPDATE_NAME,
            attributes: VariableAttributes::NON_VOLATILE
                | VariableAttributes::BOOTSERVICE_ACCESS
                | VariableAttributes::RUNTIME_ACCESS,
            data: &data,
        },
    )
}

pub fn replay_deferred(lease: &mut state::Lease) -> Result<usize, efi::Status> {
    let (runtime, variables) = lease.parts_mut();
    let bridge = runtime.boot_bridge;
    let mut region = runtime.deferred_region().ok_or(efi::Status::UNSUPPORTED)?;
    if bridge == 0 {
        return Err(efi::Status::WRITE_PROTECTED);
    }
    let (store, transaction) = (&mut variables.store, &mut variables.transaction);
    region.replay(|record, authenticated, deletion| {
        replay_record(store, transaction, bridge, record, authenticated, deletion)
    })
}

/// Apply one journalled write through the ordinary service path.
pub(super) fn replay_record(
    store: &mut VariableStore,
    transaction: &mut VariableTransaction,
    bridge: u64,
    record: &deferred::VariableRecord<'_>,
    authenticated: bool,
    deletion: bool,
) -> Result<(), efi::Status> {
    if authenticated
        != (record.attributes & efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS != 0)
        || (!authenticated && deletion != record.deleted())
    {
        return Err(efi::Status::DEVICE_ERROR);
    }
    let name_len = record
        .name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(record.name.len());
    if name_len == 0 || name_len > MAX_VARIABLE_NAME_LEN {
        return Err(efi::Status::DEVICE_ERROR);
    }
    let name = &record.name[..name_len];
    if secure_boot::is_secure_boot_enable(&record.guid.bytes, name) {
        // Never writable after ExitBootServices, so a journalled request comes
        // from an older image or forged retained memory: consume it unapplied.
        return Ok(());
    }
    let secure_variable = secure_boot::identify_key_database(&record.guid.bytes, name);
    // An append may carry any timestamp, so the floor says nothing about
    // whether it was applied. Replaying one to a signature database is
    // harmless, as signatures it already holds are skipped. Another
    // variable can get the data twice if power fails between persisting and
    // acknowledging it; skipping instead would lose appends whose timestamp
    // equals the floor.
    let replayable = record.attributes & efi::VARIABLE_APPEND_WRITE != 0;
    // Persisted before a reset lost its acknowledgement: applying the
    // append again would duplicate its data. The data alone does not prove
    // it: an append that only advances the timestamp (signatures the
    // database already holds) leaves the data as it was, so the stored
    // timestamp must have reached the envelope's too.
    if authenticated
        && replayable
        && record.result_digest != 0
        && store
            .find(&record.guid.bytes, name, false)
            .and_then(|slot| store.data(slot))
            .is_some_and(|data| append_result_digest(data) == record.result_digest)
        && store
            .auth_history_timestamp(&record.guid.bytes, name)
            .is_some_and(|stored| !timestamp_is_after(record.timestamp, stored))
    {
        return Ok(());
    }
    if authenticated && !replayable {
        let secure_floor = secure_variable.map(|variable| store.auth_timestamp(variable));
        let already_applied = secure_floor == Some(record.timestamp)
            || store.auth_history_timestamp(&record.guid.bytes, name) == Some(record.timestamp);
        if already_applied {
            // Persistence committed before the retained acknowledgement.
            // The recorded floor proves this authenticated operation has
            // already taken effect, including deletion.
            return Ok(());
        }
    }
    let Some(attributes) = VariableAttributes::from_bits(record.attributes) else {
        return replay_apply_result(Err(efi::Status::INVALID_PARAMETER), authenticated, deletion);
    };
    let request = VariableRequest {
        guid: record.guid.bytes,
        name,
        attributes,
        data: record.data,
    };
    // Only runtime writes are journaled, and replay runs with boot-time
    // rights. Hold each record to the runtime rules against the imported
    // store, so a record the runtime would refuse (one queued by an older
    // runtime, or written into the journal directly) changes nothing.
    // Consume it so later records still replay.
    // A deletion record carries no payload; others carry data or an
    // authenticated envelope.
    if check_runtime_access(store, &request, deletion).is_err() {
        return Ok(());
    }
    // An older runtime journaled an empty append to a missing variable as an
    // empty raw write without APPEND_WRITE. Applying it would delete a
    // variable of that name, or stall replay on NOT_FOUND; it meant nothing.
    if !authenticated && !deletion && record.data.is_empty() {
        return Ok(());
    }
    let result = apply_variable(VariableContext::boot(store, transaction, bridge), request);
    replay_apply_result(result, authenticated, deletion)
}

/// A raw deletion may have reached durable storage before reset while its
/// retained acknowledgement was lost. The absent imported value is then the
/// requested final state, so replay can consume the record.
pub(super) fn replay_apply_result(
    result: Result<(), efi::Status>,
    authenticated: bool,
    deletion: bool,
) -> Result<(), efi::Status> {
    match result {
        Err(status) if status == efi::Status::NOT_FOUND && !authenticated && deletion => Ok(()),
        result => result,
    }
}

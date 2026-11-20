//! Boot-time authorization and persistence callbacks.

use super::VariableRequest;
use crate::{
    efi,
    state::Phase,
    store::{PreparedWrite, VariableStore},
};
use crabefi_efi_types::secure_boot::{self, SecureBootVariable};
use crabefi_runtime_abi::{BridgeRequest, VariableTimestamp, bridge_operation};

/// Ask boot setup for narrowly scoped physical-presence authorization. Never
/// consult boot callbacks at runtime, or authorize enrollment/other databases.
pub(super) fn setup_pk_delete_authorized(
    store: &VariableStore,
    request: &VariableRequest<'_>,
    phase: Phase,
    bridge: u64,
) -> bool {
    cfg!(feature = "secure-boot")
        && phase == Phase::BootActive
        && !store.setup_mode()
        && secure_boot::identify_key_database(&request.guid, request.name)
            == Some(SecureBootVariable::PK)
        && request.data.is_empty()
        && !request.authenticated()
        && !request.append()
        && call_boot_bridge(
            bridge,
            &BridgeRequest {
                operation: bridge_operation::AUTHORIZE_SETUP_PK_DELETE,
                guid: request.guid,
                name_address: request.name.as_ptr() as u64,
                name_len: request.name.len() as u32,
                ..BridgeRequest::default()
            },
        )
        .is_ok()
}

/// Ask boot setup whether its physical-presence action is writing exactly
/// this SecureBootEnable value. Never consulted after ExitBootServices.
pub(super) fn setup_secure_boot_enable_authorized(
    request: &VariableRequest<'_>,
    phase: Phase,
    bridge: u64,
) -> bool {
    phase == Phase::BootActive
        && !phase.runtime()
        && !request.authenticated()
        && call_boot_bridge(
            bridge,
            &BridgeRequest {
                operation: bridge_operation::AUTHORIZE_SETUP_SECURE_BOOT_ENABLE,
                attributes: request.attributes.bits(),
                guid: request.guid,
                name_address: request.name.as_ptr() as u64,
                name_len: request.name.len() as u32,
                data_len: request.data.len() as u32,
                data_address: request.data.as_ptr() as u64,
                ..BridgeRequest::default()
            },
        )
        .is_ok()
}

pub(super) fn persist_through_bridge(
    bridge: u64,
    request: &VariableRequest<'_>,
    prepared: &PreparedWrite,
    staged: &[u8],
    timestamp: Option<VariableTimestamp>,
) -> Result<(), efi::Status> {
    call_boot_bridge(
        bridge,
        &BridgeRequest {
            operation: if prepared.delete {
                bridge_operation::PERSIST_DELETE
            } else {
                bridge_operation::PERSIST_WRITE
            },
            attributes: prepared.attributes.bits(),
            guid: request.guid,
            name_address: request.name.as_ptr() as u64,
            name_len: request.name.len() as u32,
            data_len: staged.len() as u32,
            data_address: staged.as_ptr() as u64,
            timestamp_valid: u32::from(timestamp.is_some()),
            reserved: 0,
            timestamp: timestamp.unwrap_or_default(),
        },
    )
}

// The image audit allows a single register call site for the bridge, and the
// link-time stack audit excuses this function's one indirect call by name.
// Keep it a distinct symbol.
#[inline(never)]
fn call_boot_bridge(address: u64, request: &BridgeRequest) -> Result<(), efi::Status> {
    if address == 0 {
        return Err(efi::Status::WRITE_PROTECTED);
    }
    type Bridge = unsafe extern "C" fn(*const BridgeRequest) -> usize;
    // The loader passes the bridge as an integer address. Recover the provenance
    // the boot image exposed for it; a bare integer is not a callable pointer.
    let bridge = core::ptr::with_exposed_provenance::<u8>(address as usize);
    // SAFETY: runtime initialization receives this bridge address from the
    // boot loader. It is used only in BootActive and zeroed at seal.
    let bridge: Bridge = unsafe { core::mem::transmute(bridge) };
    // SAFETY: `request` and the buffers it names outlive this synchronous call.
    match efi::Status::from_usize(unsafe { bridge(request) }) {
        efi::Status::SUCCESS => Ok(()),
        status => Err(status),
    }
}

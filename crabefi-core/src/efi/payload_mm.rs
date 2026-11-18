//! Boot firmware's channel to the payload MM image (crabefi-runtime-image's
//! `mm` build in SMM), which owns the variable store when the platform
//! configured an MM proxy.
//!
//! Variable services reach MM through the ring-0 runtime image. This module
//! carries the firmware-only requests MM accepts until READY_TO_BOOT: setup
//! authorizations, firmware (capsule) flash writes and protected status
//! variables.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crabefi_runtime_abi::mm::{self, DATA_MAX, DATA_OFFSET, NAME_CAPACITY, Request, command};
use r_efi::efi::{Guid, Status};

pub use crabefi_runtime_abi::mm::MIN_STORE_SIZE;

static COMM: AtomicU64 = AtomicU64::new(0);
static COMM_SIZE: AtomicU64 = AtomicU64::new(0);
static APM_CMD: AtomicU64 = AtomicU64::new(0);
static READY_TO_BOOT_SENT: AtomicBool = AtomicBool::new(false);

/// Use the MM proxy buffer of the runtime platform configuration.
pub fn configure(proxy: crabefi_runtime_abi::MmProxyConfig) {
    if proxy.enabled == 0 {
        return;
    }
    COMM_SIZE.store(proxy.comm_size, Ordering::Relaxed);
    APM_CMD.store(u64::from(proxy.apm_cmd), Ordering::Relaxed);
    COMM.store(proxy.comm_base, Ordering::Release);
}

/// The variable store belongs to payload MM.
pub fn active() -> bool {
    COMM.load(Ordering::Acquire) != 0
}

fn data_capacity() -> usize {
    (COMM_SIZE
        .load(Ordering::Relaxed)
        .saturating_sub(DATA_OFFSET) as usize)
        .min(DATA_MAX)
}

fn call(request: Request, name: &[u16], data: &[u8]) -> Status {
    match call_for_reply(request, name, data) {
        Ok(reply) => Status::from_usize(reply.status as usize),
        Err(status) => status,
    }
}

/// Run `request` and return MM's reply header.
fn call_for_reply(request: Request, name: &[u16], data: &[u8]) -> Result<Request, Status> {
    let base = COMM.load(Ordering::Acquire);
    if base == 0 {
        return Err(Status::NOT_READY);
    }
    if name.len() * 2 > NAME_CAPACITY || data.len() > data_capacity() {
        return Err(Status::BAD_BUFFER_SIZE);
    }
    let apm = APM_CMD.load(Ordering::Relaxed) as u8;
    let mut raise_smi = || {
        // SAFETY: writing the APM control port only raises a software SMI.
        unsafe { core::arch::asm!("out 0xb2, al", in("al") apm, options(nostack, preserves_flags)) }
    };
    let mut pause = || crate::time::delay_us(10);
    // SAFETY: the buffer is boot-reserved RuntimeServicesData, page aligned
    // and shared only with MM.
    let mut buffer = unsafe {
        mm::SharedBuffer::new(
            base,
            COMM_SIZE.load(Ordering::Relaxed),
            &mut raise_smi,
            &mut pause,
        )
    };
    match mm::exchange(&mut buffer, request, name, data) {
        mm::Outcome::Answered { reply, smis, polls } => {
            if smis > 1 || polls > 0 {
                log::warn!(
                    "payload MM: command {} done after SMI {} and {} us",
                    request.command,
                    smis,
                    polls * 10
                );
            }
            Ok(reply)
        }
        mm::Outcome::Lost => {
            log::error!("payload MM: command {} not handled", request.command);
            Err(Status::DEVICE_ERROR)
        }
    }
}

fn request(command: u32) -> Request {
    Request {
        magic: 0,
        version: 0,
        command,
        status: 0,
        guid: [0; 16],
        attributes: 0,
        name_size: 0,
        data_size: 0,
        maximum_storage: 0,
        remaining_storage: 0,
        maximum_variable: 0,
        offset: 0,
    }
}

/// End the firmware phase before the first boot option or other third-party
/// code runs. Idempotent.
///
/// Until MM confirms, it still accepts firmware-only commands (setup
/// authorizations, firmware flash writes, protected variables). Third-party
/// code must never get to send those, so a failure stops the boot here.
pub fn ready_to_boot() {
    if !active() || READY_TO_BOOT_SENT.load(Ordering::Acquire) {
        return;
    }
    // The fault-injection build sends a command MM refuses, as if the request
    // had been lost.
    let command = if cfg!(feature = "payload-mm-test-lose-ready-to-boot") {
        u32::MAX
    } else {
        command::READY_TO_BOOT
    };
    let status = call(request(command), &[], &[]);
    if status == Status::SUCCESS {
        READY_TO_BOOT_SENT.store(true, Ordering::Release);
        return;
    }
    log::error!(
        "payload MM did not end the firmware phase ({:?}); not starting third-party code",
        status
    );
    loop {
        crate::arch::halt();
    }
}

/// Before a kernel starts without ExitBootServices (direct Linux boot): end
/// the firmware phase and give later callers MM's runtime view only, as the
/// runtime image's seal does for EFI boots. Stops the boot if MM does not
/// confirm.
pub fn enter_runtime() {
    if !active() {
        return;
    }
    ready_to_boot();
    let status = call(request(command::EXIT_BOOT_SERVICES), &[], &[]);
    if status != Status::SUCCESS {
        log::error!(
            "payload MM did not switch to the runtime view ({:?}); not starting the kernel",
            status
        );
        loop {
            crate::arch::halt();
        }
    }
}

/// Open (`true`) or close a physical-presence setup authorization
/// (`bridge_operation::AUTHORIZE_SETUP_*`).
pub fn setup_authorize(operation: u32, open: bool) -> Status {
    let mut setup = request(command::SETUP_AUTHORIZE);
    setup.attributes = operation;
    setup.data_size = u64::from(open);
    call(setup, &[], &[])
}

/// Erase a flash range outside the variable store (firmware phase only), in
/// 64 KiB requests so no single SMI holds all CPUs for long.
pub fn firmware_erase(offset: u64, length: u64) -> Status {
    const CHUNK: u64 = 64 * 1024;
    let mut done = 0;
    while done < length {
        let mut erase = request(command::FIRMWARE_ERASE);
        erase.offset = offset + done;
        erase.data_size = (length - done).min(CHUNK);
        let status = call(erase, &[], &[]);
        if status != Status::SUCCESS {
            return status;
        }
        done += erase.data_size;
    }
    Status::SUCCESS
}

/// Program flash outside the variable store (firmware phase only).
pub fn firmware_write(offset: u64, data: &[u8]) -> Status {
    let chunk = data_capacity().max(1);
    for (index, part) in data.chunks(chunk).enumerate() {
        let mut write = request(command::FIRMWARE_WRITE);
        write.offset = offset + (index * chunk) as u64;
        write.data_size = part.len() as u64;
        let status = call(write, &[], part);
        if status != Status::SUCCESS {
            return status;
        }
    }
    Status::SUCCESS
}

/// The newest authenticated timestamp MM recorded for `guid`/`name`, deletions
/// included, as the 16 bytes of an EFI_TIME; `None` when it has none.
pub fn auth_timestamp(guid: &Guid, name: &[u16]) -> Result<Option<[u8; 16]>, Status> {
    let length = name
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(name.len());
    let mut terminated = [0u16; NAME_CAPACITY / 2];
    if length == 0 || length >= terminated.len() {
        return Err(Status::INVALID_PARAMETER);
    }
    terminated[..length].copy_from_slice(&name[..length]);
    let mut query = request(command::AUTH_TIMESTAMP);
    query.guid = *guid.as_bytes();
    query.name_size = ((length + 1) * 2) as u32;
    let reply = call_for_reply(query, &terminated[..=length], &[])?;
    match Status::from_usize(reply.status as usize) {
        Status::SUCCESS => Ok(Some(mm::unpack_timestamp(&reply))),
        Status::NOT_FOUND => Ok(None),
        status => Err(status),
    }
}

/// Write a protected firmware status variable (firmware phase only).
pub fn set_firmware_variable(guid: &Guid, name: &[u16], attributes: u32, data: &[u8]) -> Status {
    let length = name
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(name.len());
    let mut terminated = [0u16; NAME_CAPACITY / 2];
    if length == 0 || length >= terminated.len() {
        return Status::INVALID_PARAMETER;
    }
    terminated[..length].copy_from_slice(&name[..length]);
    let mut set = request(command::SET_FIRMWARE_VARIABLE);
    set.guid = *guid.as_bytes();
    set.attributes = attributes;
    set.name_size = ((length + 1) * 2) as u32;
    set.data_size = data.len() as u64;
    call(set, &terminated[..=length], data)
}

/// Run a physical-presence setup action with its MM authorization open. Does
/// nothing extra when variables are not served by payload MM.
pub fn with_setup_authorization<R>(operation: u32, action: impl FnOnce() -> R) -> R {
    if !active() {
        return action();
    }
    let opened = setup_authorize(operation, true);
    if opened != Status::SUCCESS {
        log::warn!(
            "payload MM refused setup authorization {operation}: {:?}",
            opened
        );
    }
    let result = action();
    let _ = setup_authorize(operation, false);
    result
}

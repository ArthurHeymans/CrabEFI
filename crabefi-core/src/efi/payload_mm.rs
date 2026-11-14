//! Boot firmware's channel to the payload MM image (crabefi-runtime-image's
//! `mm` build in SMM), which owns the variable store when the platform
//! configured an MM proxy.
//!
//! Variable services reach MM through the ring-0 runtime image. This module
//! carries the firmware-only requests MM accepts until READY_TO_BOOT: setup
//! authorizations, firmware (capsule) flash writes and protected status
//! variables.

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crabefi_runtime_abi::mm::{
    COMM_MAGIC, COMM_VERSION, DATA_MAX, DATA_OFFSET, NAME_CAPACITY, NAME_OFFSET, Request,
    STATUS_PENDING, command,
};
use r_efi::efi::{Guid, Status};

static COMM: AtomicU64 = AtomicU64::new(0);
/// SMIs raised per request, and the time outside SMM to wait for each.
const SMI_ATTEMPTS: u64 = 3;
const SMI_WAIT_US: u64 = 50_000;
const SMI_POLL_US: u64 = 10;
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

fn call(mut request: Request, name: &[u16], data: &[u8]) -> Status {
    let base = COMM.load(Ordering::Acquire);
    if base == 0 {
        return Status::NOT_READY;
    }
    if name.len() * 2 > NAME_CAPACITY || data.len() > data_capacity() {
        return Status::BAD_BUFFER_SIZE;
    }
    // SAFETY: the buffer is boot-reserved RuntimeServicesData shared only with MM.
    unsafe {
        let name_area = (base + NAME_OFFSET) as *mut u8;
        for (i, unit) in name.iter().enumerate() {
            let bytes = unit.to_le_bytes();
            write_volatile(name_area.add(i * 2), bytes[0]);
            write_volatile(name_area.add(i * 2 + 1), bytes[1]);
        }
        let data_area = (base + DATA_OFFSET) as *mut u8;
        for (i, &byte) in data.iter().enumerate() {
            write_volatile(data_area.add(i), byte);
        }
        request.magic = COMM_MAGIC;
        request.version = COMM_VERSION;
        request.status = STATUS_PENDING;
        write_volatile(base as *mut Request, request);
        let apm = APM_CMD.load(Ordering::Relaxed) as u8;
        let status = core::ptr::addr_of!((*(base as *const Request)).status);
        // The SMI normally completes before the OUT retires. If it comes late or is
        // lost, wait and raise it again: MM skips a request that is no longer pending,
        // so a late SMI cannot run it twice.
        for attempt in 1..=SMI_ATTEMPTS {
            core::arch::asm!("out 0xb2, al", in("al") apm, options(nostack, preserves_flags));
            for waited in 0..=SMI_WAIT_US / SMI_POLL_US {
                let now = read_volatile(status);
                if now != STATUS_PENDING {
                    if attempt > 1 || waited > 0 {
                        log::warn!(
                            "payload MM: command {} done after SMI {} and {} us",
                            request.command,
                            attempt,
                            waited * SMI_POLL_US
                        );
                    }
                    return Status::from_usize(now as usize);
                }
                crate::time::delay_us(SMI_POLL_US);
            }
        }
        log::error!("payload MM: command {} not handled", request.command);
        Status::DEVICE_ERROR
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
pub fn ready_to_boot() {
    if !active() || READY_TO_BOOT_SENT.swap(true, Ordering::AcqRel) {
        return;
    }
    let status = call(request(command::READY_TO_BOOT), &[], &[]);
    if status != Status::SUCCESS {
        log::error!("payload MM refused READY_TO_BOOT: {:?}", status);
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

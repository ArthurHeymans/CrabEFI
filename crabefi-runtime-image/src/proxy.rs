//! Ring-0 side of payload MM variables: when the boot loader configured an MM
//! proxy, the variable services forward to the image's MM build in SMM, which
//! is the only variable authority (verification and flash writes).

use core::ffi::c_void;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::efi;
use crate::mm_protocol::{
    COMM_MAGIC, COMM_VERSION, DATA_OFFSET, NAME_CAPACITY, NAME_OFFSET, Request, STATUS_PENDING,
    command,
};

/// Current (physical, then virtual after SetVirtualAddressMap) buffer address;
/// 0 when variables are served locally.
static COMM: AtomicU64 = AtomicU64::new(0);
static COMM_PHYSICAL: AtomicU64 = AtomicU64::new(0);
static COMM_SIZE: AtomicU64 = AtomicU64::new(0);
static APM_CMD: AtomicU64 = AtomicU64::new(0);

pub fn configure(physical: u64, size: u64, apm_cmd: u8) {
    COMM_PHYSICAL.store(physical, Ordering::Relaxed);
    COMM_SIZE.store(size, Ordering::Relaxed);
    APM_CMD.store(u64::from(apm_cmd), Ordering::Relaxed);
    COMM.store(physical, Ordering::Release);
}

pub fn physical() -> Option<(u64, u64)> {
    let base = COMM_PHYSICAL.load(Ordering::Relaxed);
    (base != 0).then(|| (base, COMM_SIZE.load(Ordering::Relaxed)))
}

/// Publish the buffer's virtual address once SetVirtualAddressMap committed.
pub fn set_virtual(address: u64) {
    COMM.store(address, Ordering::Release);
}

pub fn active() -> bool {
    COMM.load(Ordering::Acquire) != 0
}

fn data_capacity() -> usize {
    COMM_SIZE
        .load(Ordering::Relaxed)
        .saturating_sub(DATA_OFFSET) as usize
}

fn trigger_smi() {
    let apm = APM_CMD.load(Ordering::Relaxed) as u8;
    // SAFETY: the APM control port only raises an SMI; MM writes the reply
    // into the buffer before the OUT instruction retires.
    unsafe {
        core::arch::asm!("out 0xb2, al", in("al") apm, options(nostack, preserves_flags));
    }
}

/// One request/reply round trip. `name` (with terminator) and `data` are
/// copied into the buffer before the SMI.
fn call(request: &mut Request, name: &[u16], data: &[u8]) -> efi::Status {
    let base = COMM.load(Ordering::Acquire);
    if base == 0 || name.len() * 2 > NAME_CAPACITY || data.len() > data_capacity() {
        return efi::Status::INVALID_PARAMETER;
    }
    let name_area = (base + NAME_OFFSET) as *mut u8;
    let data_area = (base + DATA_OFFSET) as *mut u8;
    // SAFETY: the buffer is runtime memory owned by this image and MM only.
    unsafe {
        for (i, unit) in name.iter().enumerate() {
            let bytes = unit.to_le_bytes();
            write_volatile(name_area.add(i * 2), bytes[0]);
            write_volatile(name_area.add(i * 2 + 1), bytes[1]);
        }
        for (i, &byte) in data.iter().enumerate() {
            write_volatile(data_area.add(i), byte);
        }
        request.magic = COMM_MAGIC;
        request.version = COMM_VERSION;
        request.status = STATUS_PENDING;
        write_volatile(base as *mut Request, *request);
    }
    trigger_smi();
    // SAFETY: as above.
    *request = unsafe { read_volatile(base as *const Request) };
    if request.status == STATUS_PENDING {
        return efi::Status::DEVICE_ERROR; // MM did not answer.
    }
    efi::Status::from_usize(request.status as usize)
}

fn read_reply(offset: u64, out: &mut [u8]) {
    let base = COMM.load(Ordering::Acquire);
    for (i, byte) in out.iter_mut().enumerate() {
        // SAFETY: bounded by the reply sizes checked by the callers.
        *byte = unsafe { read_volatile((base + offset + i as u64) as *const u8) };
    }
}

/// Caller name up to and including its terminator, bounded by the buffer.
fn caller_name(
    name: *const u16,
    limit_units: usize,
    out: &mut [u16; NAME_CAPACITY / 2],
) -> Option<usize> {
    if name.is_null() || !name.is_aligned() {
        return None;
    }
    for i in 0..limit_units.min(out.len()) {
        // SAFETY: UEFI callers pass a terminated name; reading stops at it.
        let unit = unsafe { name.add(i).read() };
        out[i] = unit;
        if unit == 0 {
            return Some(i + 1);
        }
    }
    None
}

pub fn get_variable(
    name: *mut u16,
    guid: *mut efi::Guid,
    attributes: *mut u32,
    data_size: *mut usize,
    data: *mut c_void,
) -> efi::Status {
    let mut units = [0u16; NAME_CAPACITY / 2];
    let (Some(length), false, false) = (
        caller_name(name, NAME_CAPACITY / 2, &mut units),
        guid.is_null(),
        data_size.is_null(),
    ) else {
        return efi::Status::INVALID_PARAMETER;
    };
    // SAFETY: checked non-null above.
    let capacity = unsafe { data_size.read() };
    if capacity != 0 && data.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let mut request = Request {
        command: command::GET_VARIABLE,
        // SAFETY: checked non-null above.
        guid: *unsafe { guid.read() }.as_bytes(),
        name_size: (length * 2) as u32,
        data_size: capacity.min(data_capacity()) as u64,
        ..empty()
    };
    let status = call(&mut request, &units[..length], &[]);
    let size = request.data_size as usize;
    // SAFETY: caller pointers checked above.
    unsafe { data_size.write(size) };
    if status == efi::Status::SUCCESS {
        if size > capacity || size > data_capacity() {
            return efi::Status::DEVICE_ERROR;
        }
        if !attributes.is_null() {
            // SAFETY: optional output pointer supplied by the caller.
            unsafe { attributes.write(request.attributes) };
        }
        // SAFETY: the caller's buffer holds `capacity >= size` bytes.
        read_reply(DATA_OFFSET, unsafe {
            core::slice::from_raw_parts_mut(data.cast::<u8>(), size)
        });
    }
    status
}

pub fn get_next_variable_name(
    name_size: *mut usize,
    name: *mut u16,
    guid: *mut efi::Guid,
) -> efi::Status {
    if name_size.is_null() || guid.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    // SAFETY: checked non-null above.
    let capacity = unsafe { name_size.read() };
    let mut units = [0u16; NAME_CAPACITY / 2];
    let Some(length) = caller_name(name, capacity / 2, &mut units) else {
        return efi::Status::INVALID_PARAMETER;
    };
    let mut request = Request {
        command: command::GET_NEXT_VARIABLE_NAME,
        // SAFETY: checked non-null above.
        guid: *unsafe { guid.read() }.as_bytes(),
        name_size: (length * 2) as u32,
        // The caller's name buffer capacity travels in data_size.
        data_size: capacity.min(NAME_CAPACITY) as u64,
        ..empty()
    };
    let status = call(&mut request, &units[..length], &[]);
    let size = request.name_size as usize;
    // SAFETY: checked non-null above.
    unsafe { name_size.write(size) };
    if status == efi::Status::SUCCESS {
        if size > capacity || size > NAME_CAPACITY {
            return efi::Status::DEVICE_ERROR;
        }
        // SAFETY: caller buffer holds `capacity >= size` bytes; guid checked above.
        unsafe {
            read_reply(
                NAME_OFFSET,
                core::slice::from_raw_parts_mut(name.cast::<u8>(), size),
            );
            guid.write(efi::Guid::from_bytes(&request.guid));
        }
    }
    status
}

pub fn set_variable(
    name: *mut u16,
    guid: *mut efi::Guid,
    attributes: u32,
    data_size: usize,
    data: *mut c_void,
) -> efi::Status {
    let mut units = [0u16; NAME_CAPACITY / 2];
    let Some(length) = caller_name(name, NAME_CAPACITY / 2, &mut units) else {
        return efi::Status::INVALID_PARAMETER;
    };
    if guid.is_null() || (data_size != 0 && data.is_null()) {
        return efi::Status::INVALID_PARAMETER;
    }
    if data_size > data_capacity() {
        return efi::Status::OUT_OF_RESOURCES;
    }
    let payload = if data_size == 0 {
        &[][..]
    } else {
        // SAFETY: UEFI caller provides `data_size` readable bytes.
        unsafe { core::slice::from_raw_parts(data.cast::<u8>(), data_size) }
    };
    let mut request = Request {
        command: command::SET_VARIABLE,
        // SAFETY: checked non-null above.
        guid: *unsafe { guid.read() }.as_bytes(),
        attributes,
        name_size: (length * 2) as u32,
        data_size: data_size as u64,
        ..empty()
    };
    call(&mut request, &units[..length], payload)
}

pub fn query_variable_info(
    attributes: u32,
    maximum_storage: *mut u64,
    remaining_storage: *mut u64,
    maximum_variable: *mut u64,
) -> efi::Status {
    if maximum_storage.is_null() || remaining_storage.is_null() || maximum_variable.is_null() {
        return efi::Status::INVALID_PARAMETER;
    }
    let mut request = Request {
        command: command::QUERY_VARIABLE_INFO,
        attributes,
        ..empty()
    };
    let status = call(&mut request, &[], &[]);
    if status == efi::Status::SUCCESS {
        // SAFETY: checked non-null above.
        unsafe {
            maximum_storage.write(request.maximum_storage);
            remaining_storage.write(request.remaining_storage);
            maximum_variable.write(request.maximum_variable);
        }
    }
    status
}

/// Tell MM that boot services end: callers only get the runtime view now.
pub fn exit_boot_services() -> efi::Status {
    let mut request = Request {
        command: command::EXIT_BOOT_SERVICES,
        ..empty()
    };
    call(&mut request, &[], &[])
}

const fn empty() -> Request {
    Request {
        magic: 0,
        version: 0,
        command: 0,
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

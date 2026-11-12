//! Payload MM build of the runtime image (feature `mm`).
//!
//! coreboot owns SMM and loads this image once into the SMRAM area it reserves
//! for the payload (coreboot `drivers/payload_mm_interface`). Here the image is
//! the only variable authority: it imports the flash store at init, verifies
//! every write (authenticated variables, PK/KEK/db/dbx policy) and persists it
//! to flash from SMM. Ring 0 only forwards requests through a communication
//! buffer, so it can neither bypass verification nor write the flash itself
//! (AMD ROM Armor 3, QEMU secure pflash).

mod flash;
mod nvstore;

use core::arch::global_asm;
use core::ffi::c_void;
use core::ptr::{
    addr_of, addr_of_mut, read_unaligned, read_volatile, write_unaligned, write_volatile,
};
use core::sync::atomic::{AtomicBool, Ordering};

use crabefi_runtime_abi::{BridgeRequest, MAX_VARIABLE_NAME_LEN, bridge_operation};

use crate::efi;
use crate::mm_protocol::{
    COMM_MAGIC, COMM_VERSION, DATA_OFFSET, NAME_CAPACITY, NAME_OFFSET, Request, STATUS_PENDING,
    command,
};
use crate::services;
use crate::state::{self, MM_RUNTIME_LATCH, Phase};
use flash::Flash;
use nvstore::NvStore;

/// coreboot `struct payload_mm_core_call_context`.
#[repr(C, packed)]
struct CallContext {
    arg1: u64,
    arg2: u64,
    arg3: u64,
    implementation_private_data: u64,
}

/// coreboot `struct payload_mm_shared_info`, at the start of the payload MM area.
#[repr(C, packed)]
struct SharedInfo {
    header_magic: u64,
    shared_info_size: u16,
    header_revision: u8,
    reserved: u8,
    mm_entrypoint_address: u32,
}

const SHARED_INFO_MAGIC: u64 = 0x5f4d_4d5f_444c_505f; // "_PLD_MM_"

/// Boot-time configuration from the trusted payload (`arg1`), copied once.
#[repr(C)]
#[derive(Clone, Copy)]
struct InitConfig {
    magic: u64,
    version: u32,
    size: u32,
    mm_area_base: u64,
    mm_area_size: u64,
    comm_base: u64,
    comm_size: u64,
    flash_base: u64,
    flash_size: u64,
    store_offset: u64,
    store_size: u64,
}

const INIT_MAGIC: u64 = 0x4749_4643_4d4d_4243; // "CBMMCFIG"
const INIT_VERSION: u32 = 2;

const DATA_CAPACITY: usize = crate::auth::MAX_AUTHENTICATED_ENVELOPE_SIZE;

struct Context {
    config: InitConfig,
    ready: bool,
}

static mut CONTEXT: Context = Context {
    config: InitConfig {
        magic: 0,
        version: 0,
        size: 0,
        mm_area_base: 0,
        mm_area_size: 0,
        comm_base: 0,
        comm_size: 0,
        flash_base: 0,
        flash_size: 0,
        store_offset: 0,
        store_size: 0,
    },
    ready: false,
};
static mut STORE: NvStore = NvStore::empty();
static READY_TO_BOOT: AtomicBool = AtomicBool::new(false);

// Requests are copied here before they are checked or used (no TOCTOU on ring-0 memory).
static mut NAME: [u16; NAME_CAPACITY / 2] = [0; NAME_CAPACITY / 2];
static mut DATA: [u8; DATA_CAPACITY] = [0; DATA_CAPACITY];

const STACK_SIZE: usize = 128 * 1024;
#[repr(C, align(16))]
struct Stack([u8; STACK_SIZE]);
static mut MM_STACK: Stack = Stack([0; STACK_SIZE]);

// coreboot calls both entry points on its small SMM stack; switch to our own.
global_asm!(
    ".section .text.crabefi_mm_entry,\"ax\"",
    ".global crabefi_mm_init",
    "crabefi_mm_init:",
    "push rbp",
    "mov rbp, rsp",
    "lea rsp, [rip + {stack}]",
    "add rsp, {size}",
    "call {init}",
    "mov rsp, rbp",
    "pop rbp",
    "ret",
    ".global crabefi_mm_runtime",
    "crabefi_mm_runtime:",
    "push rbp",
    "mov rbp, rsp",
    "lea rsp, [rip + {stack}]",
    "add rsp, {size}",
    "call {runtime}",
    "mov rsp, rbp",
    "pop rbp",
    "ret",
    stack = sym MM_STACK,
    size = const STACK_SIZE,
    init = sym mm_init,
    runtime = sym mm_runtime,
);

unsafe extern "C" {
    fn crabefi_mm_runtime(argument: *mut u8);
}

fn ranges_overlap(a: u64, a_len: u64, b: u64, b_len: u64) -> bool {
    let (Some(a_end), Some(b_end)) = (a.checked_add(a_len), b.checked_add(b_len)) else {
        return true;
    };
    a < b_end && b < a_end
}

/// First and only entry from coreboot's LOAD_AND_CALL_CORE. Returns 0 on success.
extern "sysv64" fn mm_init(context: *const CallContext) -> u8 {
    match init(context) {
        Ok(()) => 0,
        Err(()) => 1,
    }
}

fn init(context: *const CallContext) -> Result<(), ()> {
    // SAFETY: coreboot passes its call context in the shared page it maps.
    let config_ptr = unsafe { read_unaligned(addr_of!((*context).arg1)) } as *const InitConfig;
    if config_ptr.is_null() {
        return Err(());
    }
    // SAFETY: the trusted boot-time payload owns this structure; copy it once.
    let config = unsafe { read_unaligned(config_ptr) };
    if config.magic != INIT_MAGIC
        || config.version != INIT_VERSION
        || config.size as usize != core::mem::size_of::<InitConfig>()
        || config.comm_size < DATA_OFFSET + 1
        || ranges_overlap(
            config.comm_base,
            config.comm_size,
            config.mm_area_base,
            config.mm_area_size,
        )
        || config
            .store_offset
            .checked_add(config.store_size)
            .is_none_or(|end| end > config.flash_size)
        || config.store_size > u32::MAX as u64
    {
        return Err(());
    }

    // SAFETY: single-threaded SMM init.
    let store = unsafe { &mut *addr_of_mut!(STORE) };
    store
        .open(
            Flash::new(config.flash_base, config.flash_size),
            config.store_offset,
            config.store_size as u32,
        )
        .map_err(drop)?;

    {
        let mut lease = state::lease_in(&[Phase::Uninitialized]).map_err(drop)?;
        lease.state_mut().boot_bridge = bridge as *const () as u64;
        lease.advance(Phase::Loaded);
        lease.advance(Phase::Importing);
    }
    // SAFETY: single-threaded SMM init; NAME/DATA are MM-private scratch.
    let (name_buf, data_buf) = unsafe { (&mut *addr_of_mut!(NAME), &mut *addr_of_mut!(DATA)) };
    store
        .for_each_live(name_buf, data_buf, &mut |record, name, data| {
            let length = name
                .iter()
                .position(|&unit| unit == 0)
                .unwrap_or(name.len());
            if length == 0 || length > MAX_VARIABLE_NAME_LEN {
                return Err(nvstore::Error::Invalid);
            }
            let mut lease =
                state::lease_in(&[Phase::Importing]).map_err(|_| nvstore::Error::Invalid)?;
            let (_, variables) = lease.parts_mut();
            variables
                .store
                .import(
                    &mut variables.transaction,
                    record.guid,
                    &name[..length],
                    efi::VariableAttributes::from_bits_retain(record.attributes),
                    data,
                    Some(record.timestamp),
                )
                .map_err(|_| nvstore::Error::Full)
        })
        .map_err(drop)?;
    {
        let mut lease = state::lease_in(&[Phase::Importing]).map_err(drop)?;
        lease.parts_mut().1.store.refresh_policy();
        lease.advance(Phase::BootActive);
    }

    // SAFETY: single-threaded SMM init.
    unsafe {
        let context = &mut *addr_of_mut!(CONTEXT);
        context.config = config;
        context.ready = true;
        write_unaligned(
            config.mm_area_base as *mut SharedInfo,
            SharedInfo {
                header_magic: SHARED_INFO_MAGIC,
                shared_info_size: core::mem::size_of::<SharedInfo>() as u16,
                header_revision: 1,
                reserved: 0,
                mm_entrypoint_address: crabefi_mm_runtime as *const () as usize as u32,
            },
        );
    }
    Ok(())
}

/// Persistence for the variable services: the image calls this "boot bridge"
/// after verifying and staging a write, before committing it to its store.
unsafe extern "C" fn bridge(request: *const BridgeRequest) -> usize {
    // SAFETY: the image passes a request whose buffers live in SMRAM.
    let request = unsafe { &*request };
    let status = match persist(request) {
        Ok(()) => efi::Status::SUCCESS,
        Err(status) => status,
    };
    status.as_usize()
}

fn persist(request: &BridgeRequest) -> Result<(), efi::Status> {
    let name_len = request.name_len as usize;
    if name_len == 0 || name_len > MAX_VARIABLE_NAME_LEN || request.name_address == 0 {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let mut name = [0u16; MAX_VARIABLE_NAME_LEN + 1];
    // SAFETY: image-owned SMRAM buffers of the given lengths.
    name[..name_len].copy_from_slice(unsafe {
        core::slice::from_raw_parts(request.name_address as *const u16, name_len)
    });
    let name = &name[..=name_len];
    let data_len = request.data_len as usize;
    let data = if data_len == 0 {
        &[][..]
    } else {
        // SAFETY: as above.
        unsafe { core::slice::from_raw_parts(request.data_address as *const u8, data_len) }
    };
    let timestamp = (request.timestamp_valid != 0).then_some(request.timestamp);
    // SAFETY: single-threaded SMM.
    let store = unsafe { &mut *addr_of_mut!(STORE) };
    let result = match request.operation {
        bridge_operation::PERSIST_WRITE => {
            store.write(&request.guid, name, request.attributes, data, timestamp)
        }
        // An empty authenticated record keeps the deletion replay floor.
        bridge_operation::PERSIST_DELETE if timestamp.is_some() => {
            store.write(&request.guid, name, request.attributes, &[], timestamp)
        }
        bridge_operation::PERSIST_DELETE => store.retire(&request.guid, name, None),
        // Physical-presence PK deletion needs a firmware-only command that is
        // gated by READY_TO_BOOT; not offered yet.
        bridge_operation::AUTHORIZE_SETUP_PK_DELETE => return Err(efi::Status::ACCESS_DENIED),
        _ => return Err(efi::Status::UNSUPPORTED),
    };
    result.map_err(|error| match error {
        nvstore::Error::Full => efi::Status::OUT_OF_RESOURCES,
        nvstore::Error::Invalid => efi::Status::INVALID_PARAMETER,
        nvstore::Error::Device => efi::Status::DEVICE_ERROR,
    })
}

/// Called by coreboot on every software SMI once registered.
extern "sysv64" fn mm_runtime(_argument: *mut u8) {
    // SAFETY: single-threaded SMM.
    let context = unsafe { &*addr_of!(CONTEXT) };
    if !context.ready {
        return;
    }
    let comm = context.config.comm_base;
    let header_ptr = comm as *mut Request;
    // SAFETY: comm_base was checked at init not to overlap SMRAM we own; ring 0
    // owns this memory, so read it once and work on the copy.
    let request = unsafe { read_volatile(header_ptr) };
    if request.magic != COMM_MAGIC || request.status != STATUS_PENDING {
        return; // Not addressed to us.
    }
    let mut reply = request;
    let status = if request.version != COMM_VERSION {
        efi::Status::INVALID_PARAMETER
    } else {
        dispatch(&context.config, &mut reply)
    };
    reply.status = status.as_usize() as u64;
    // SAFETY: as above; the status is written last.
    unsafe {
        write_volatile(addr_of_mut!((*header_ptr).guid), reply.guid);
        write_volatile(addr_of_mut!((*header_ptr).attributes), reply.attributes);
        write_volatile(addr_of_mut!((*header_ptr).name_size), reply.name_size);
        write_volatile(addr_of_mut!((*header_ptr).data_size), reply.data_size);
        write_volatile(
            addr_of_mut!((*header_ptr).maximum_storage),
            reply.maximum_storage,
        );
        write_volatile(
            addr_of_mut!((*header_ptr).remaining_storage),
            reply.remaining_storage,
        );
        write_volatile(
            addr_of_mut!((*header_ptr).maximum_variable),
            reply.maximum_variable,
        );
        write_volatile(addr_of_mut!((*header_ptr).status), reply.status);
    }
}

fn copy_in(source: u64, target: &mut [u8]) {
    for (i, byte) in target.iter_mut().enumerate() {
        // SAFETY: callers bound `source..source+len` inside the comm buffer.
        *byte = unsafe { read_volatile((source + i as u64) as *const u8) };
    }
}

fn copy_out(source: &[u8], target: u64) {
    for (i, &byte) in source.iter().enumerate() {
        // SAFETY: callers bound `target..target+len` inside the comm buffer.
        unsafe { write_volatile((target + i as u64) as *mut u8, byte) };
    }
}

/// Copy the request name (terminated, at most NAME_CAPACITY bytes) into SMRAM.
fn load_name(config: &InitConfig, request: &Request, name: &mut [u16]) -> Result<(), efi::Status> {
    let size = request.name_size as usize;
    if size < 2 || size % 2 != 0 || size > NAME_CAPACITY {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let mut bytes = [0u8; NAME_CAPACITY];
    copy_in(config.comm_base + NAME_OFFSET, &mut bytes[..size]);
    name.fill(0);
    for (unit, b) in name.iter_mut().zip(bytes[..size].chunks_exact(2)) {
        *unit = u16::from_le_bytes([b[0], b[1]]);
    }
    // Always terminated inside the buffer, whatever ring 0 sent.
    if let Some(last) = name.last_mut() {
        *last = 0;
    }
    Ok(())
}

fn dispatch(config: &InitConfig, request: &mut Request) -> efi::Status {
    let data_capacity = (config.comm_size - DATA_OFFSET).min(DATA_CAPACITY as u64) as usize;
    // SAFETY: single-threaded SMM; MM-private scratch.
    let (name, data) = unsafe { (&mut *addr_of_mut!(NAME), &mut *addr_of_mut!(DATA)) };
    let mut guid = efi::Guid::from_bytes(&request.guid);
    match request.command {
        command::PING => efi::Status::SUCCESS,
        command::READY_TO_BOOT => {
            READY_TO_BOOT.store(true, Ordering::Release);
            efi::Status::SUCCESS
        }
        command::EXIT_BOOT_SERVICES => {
            READY_TO_BOOT.store(true, Ordering::Release);
            MM_RUNTIME_LATCH.store(true, Ordering::Release);
            efi::Status::SUCCESS
        }
        command::GET_VARIABLE => {
            if let Err(status) = load_name(config, request, name) {
                return status;
            }
            let mut attributes = 0u32;
            let mut size = (request.data_size as usize).min(data_capacity);
            let status = services::get_variable(
                name.as_mut_ptr(),
                &mut guid,
                &mut attributes,
                &mut size,
                data.as_mut_ptr().cast::<c_void>(),
            );
            request.attributes = attributes;
            request.data_size = size as u64;
            if status == efi::Status::SUCCESS {
                copy_out(&data[..size], config.comm_base + DATA_OFFSET);
            }
            status
        }
        command::GET_NEXT_VARIABLE_NAME => {
            if let Err(status) = load_name(config, request, name) {
                return status;
            }
            let mut size = NAME_CAPACITY.min(request.data_size.max(2) as usize);
            let status = services::get_next_variable_name(&mut size, name.as_mut_ptr(), &mut guid);
            request.name_size = size as u32;
            if status == efi::Status::SUCCESS {
                let mut bytes = [0u8; NAME_CAPACITY];
                for (b, unit) in bytes.chunks_exact_mut(2).zip(name.iter()) {
                    b.copy_from_slice(&unit.to_le_bytes());
                }
                copy_out(
                    &bytes[..size.min(NAME_CAPACITY)],
                    config.comm_base + NAME_OFFSET,
                );
                request.guid = *guid.as_bytes();
            }
            status
        }
        command::SET_VARIABLE => {
            if let Err(status) = load_name(config, request, name) {
                return status;
            }
            let size = request.data_size as usize;
            if size > data_capacity {
                return efi::Status::OUT_OF_RESOURCES;
            }
            copy_in(config.comm_base + DATA_OFFSET, &mut data[..size]);
            services::set_variable(
                name.as_mut_ptr(),
                &mut guid,
                request.attributes,
                size,
                data.as_mut_ptr().cast::<c_void>(),
            )
        }
        command::QUERY_VARIABLE_INFO => services::query_variable_info(
            request.attributes,
            &mut request.maximum_storage,
            &mut request.remaining_storage,
            &mut request.maximum_variable,
        ),
        _ => efi::Status::UNSUPPORTED,
    }
}

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
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crabefi_runtime_abi::{BridgeRequest, MAX_VARIABLE_NAME_LEN, bridge_operation};

use crate::efi;
use crate::mm_protocol::{
    COMM_MAGIC, COMM_VERSION, DATA_OFFSET, NAME_CAPACITY, NAME_OFFSET, Request, STATUS_BUSY,
    STATUS_PENDING, command,
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

const DATA_CAPACITY: usize = crabefi_runtime_abi::mm::DATA_MAX;
const _: () = assert!(DATA_CAPACITY >= crate::auth::MAX_AUTHENTICATED_ENVELOPE_SIZE);

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
/// Flash access chosen at init (coreboot services or QEMU pflash commands).
static mut FLASH: Flash = Flash::empty();
static READY_TO_BOOT: AtomicBool = AtomicBool::new(false);
/// Setup authorization opened by the firmware (bridge operation), 0 if none.
static SETUP_AUTHORIZATION: AtomicU32 = AtomicU32::new(0);

/// Full reset through the PCH/FCH reset control register (0xCF9), from the
/// panic handler: a panic in SMM must not leave every CPU spinning here.
pub fn reset_after_panic() -> ! {
    // SAFETY: port 0xCF9 on x86 PC platforms; 0x02 then 0x0E requests a full
    // reset, after which nothing here runs again.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") 0xcf9u16, in("al") 0x02u8, options(nomem, nostack));
        core::arch::asm!("out dx, al", in("dx") 0xcf9u16, in("al") 0x0eu8, options(nomem, nostack));
    }
    loop {
        core::hint::spin_loop();
    }
}

/// Firmware-only commands are refused once third-party code may have run.
fn firmware_phase() -> bool {
    !READY_TO_BOOT.load(Ordering::Acquire)
}

fn end_firmware_phase() {
    READY_TO_BOOT.store(true, Ordering::Release);
    SETUP_AUTHORIZATION.store(0, Ordering::Release);
}

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
    let flash = Flash::new(config.flash_base, config.flash_size)
        .with_coreboot_services(config.mm_area_base, config.store_offset);
    // SAFETY: single-threaded SMM init.
    unsafe { *addr_of_mut!(FLASH) = flash };
    store
        .open(flash, config.store_offset, config.store_size as u32)
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
            let Some(name) = name
                .get(..length)
                .filter(|_| length <= MAX_VARIABLE_NAME_LEN)
            else {
                return Err(nvstore::Error::Invalid);
            };
            if length == 0 {
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
                    name,
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
    let mut terminated = [0u16; MAX_VARIABLE_NAME_LEN + 1];
    // SAFETY: image-owned SMRAM buffers of the given lengths.
    let source =
        unsafe { core::slice::from_raw_parts(request.name_address as *const u16, name_len) };
    for (unit, &source) in terminated.iter_mut().zip(source) {
        *unit = source;
    }
    let name = terminated
        .get(..=name_len)
        .ok_or(efi::Status::INVALID_PARAMETER)?;
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
        // Physical-presence setup actions, opened by the firmware before any
        // boot option ran (SETUP_AUTHORIZE).
        bridge_operation::AUTHORIZE_SETUP_PK_DELETE
        | bridge_operation::AUTHORIZE_SETUP_SECURE_BOOT_ENABLE => {
            return if firmware_phase()
                && SETUP_AUTHORIZATION.load(Ordering::Acquire) == request.operation
            {
                Ok(())
            } else {
                Err(efi::Status::ACCESS_DENIED)
            };
        }
        _ => return Err(efi::Status::UNSUPPORTED),
    };
    result.map_err(|error| match error {
        nvstore::Error::Full => efi::Status::OUT_OF_RESOURCES,
        nvstore::Error::Invalid => efi::Status::INVALID_PARAMETER,
        nvstore::Error::Device => efi::Status::DEVICE_ERROR,
        nvstore::Error::Corrupt => efi::Status::VOLUME_CORRUPTED,
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
    // Claim the request before reading anything else: from here on ring 0
    // leaves the buffer alone until the status below answers it.
    // SAFETY: comm_base was checked at init not to overlap SMRAM we own and
    // is page aligned, so its status word is an aligned u64.
    let status = unsafe { AtomicU64::from_ptr(addr_of_mut!((*header_ptr).status)) };
    if status
        .compare_exchange(
            STATUS_PENDING,
            STATUS_BUSY,
            Ordering::Acquire,
            Ordering::Relaxed,
        )
        .is_err()
    {
        return; // Not addressed to us.
    }
    // SAFETY: as above; ring 0 owns this memory, so read it once and work on
    // the copy.
    let request = unsafe { read_volatile(header_ptr) };
    if request.magic != COMM_MAGIC {
        status.store(
            efi::Status::INVALID_PARAMETER.as_usize() as u64,
            Ordering::Release,
        );
        return;
    }
    let mut reply = request;
    let answer = if request.version != COMM_VERSION {
        efi::Status::INVALID_PARAMETER
    } else {
        dispatch(&context.config, &mut reply)
    };
    // SAFETY: as above; the status is stored last, with release ordering.
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
    }
    status.store(answer.as_usize() as u64, Ordering::Release);
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
    if size < 2 || !size.is_multiple_of(2) || size > NAME_CAPACITY {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let mut bytes = [0u8; NAME_CAPACITY];
    let bytes = bytes
        .get_mut(..size)
        .ok_or(efi::Status::INVALID_PARAMETER)?;
    copy_in(config.comm_base + NAME_OFFSET, bytes);
    name.fill(0);
    for (unit, b) in name.iter_mut().zip(bytes.as_chunks::<2>().0) {
        *unit = u16::from_le_bytes(*b);
    }
    // Always terminated inside the buffer, whatever ring 0 sent.
    if let Some(last) = name.last_mut() {
        *last = 0;
    }
    Ok(())
}

/// Firmware update writes, anywhere in flash except the variable store, which
/// only changes through the verified variable services.
fn firmware_flash(
    config: &InitConfig,
    request: &Request,
    data_capacity: usize,
    data: &mut [u8],
) -> efi::Status {
    let (offset, length) = (request.offset, request.data_size);
    let Some(end) = offset.checked_add(length) else {
        return efi::Status::INVALID_PARAMETER;
    };
    // SAFETY: single-threaded SMM; set once at init.
    let flash = unsafe { *addr_of!(FLASH) };
    if length == 0
        || end > flash.limit()
        || ranges_overlap(offset, length, config.store_offset, config.store_size)
    {
        return efi::Status::ACCESS_DENIED;
    }
    if flash.uses_coreboot_services() && !flash.firmware_writable() {
        return efi::Status::WRITE_PROTECTED; // Not a firmware-update boot.
    }
    let done = if request.command == command::FIRMWARE_ERASE {
        flash.erase(offset, length)
    } else {
        let Some(chunk) = data
            .get_mut(..length as usize)
            .filter(|chunk| chunk.len() <= data_capacity)
        else {
            return efi::Status::BAD_BUFFER_SIZE;
        };
        copy_in(config.comm_base + DATA_OFFSET, chunk);
        flash.program(offset, chunk)
    };
    if done {
        efi::Status::SUCCESS
    } else {
        efi::Status::DEVICE_ERROR
    }
}

/// Variables the boot firmware writes through SET_FIRMWARE_VARIABLE: status
/// it owns that SetVariable refuses, and its capsule staging reservation.
/// Everything else, Secure Boot keys and signer bindings included, only
/// changes through the verified variable services.
fn firmware_owned(guid: &[u8; 16], name: &[u16]) -> bool {
    crabefi_runtime_abi::capsule::is_esrt_last_attempt_variable(guid, name)
        || services::is_capsule_staging_variable(guid, name)
}

/// Persist and publish a firmware-owned variable ([`firmware_owned`]) that
/// SetVariable protects, for example the ESRT last-attempt status.
fn set_firmware_variable(request: &Request, name: &[u16], data: &[u8]) -> efi::Status {
    let length = name
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(name.len());
    let (Some(unterminated), Some(terminated)) = (name.get(..length), name.get(..=length)) else {
        return efi::Status::INVALID_PARAMETER;
    };
    if length == 0 || length > MAX_VARIABLE_NAME_LEN {
        return efi::Status::INVALID_PARAMETER;
    }
    let guid = request.guid;
    if !firmware_owned(&guid, unterminated)
        || request.attributes
            & (efi::VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS | efi::VARIABLE_APPEND_WRITE)
            != 0
    {
        return efi::Status::ACCESS_DENIED;
    }
    // SAFETY: single-threaded SMM.
    let store = unsafe { &mut *addr_of_mut!(STORE) };
    if let Err(error) = store.write(&guid, terminated, request.attributes, data, None) {
        return match error {
            nvstore::Error::Full => efi::Status::OUT_OF_RESOURCES,
            _ => efi::Status::DEVICE_ERROR,
        };
    }
    let Ok(mut lease) = state::lease_in(&[Phase::BootActive]) else {
        return efi::Status::DEVICE_ERROR;
    };
    let (_, variables) = lease.parts_mut();
    match variables.store.import(
        &mut variables.transaction,
        guid,
        unterminated,
        efi::VariableAttributes::from_bits_retain(request.attributes),
        data,
        None,
    ) {
        Ok(()) => efi::Status::SUCCESS,
        Err(status) => status,
    }
}

fn dispatch(config: &InitConfig, request: &mut Request) -> efi::Status {
    let data_capacity = (config.comm_size - DATA_OFFSET).min(DATA_CAPACITY as u64) as usize;
    // SAFETY: single-threaded SMM; MM-private scratch.
    let (name, data) = unsafe { (&mut *addr_of_mut!(NAME), &mut *addr_of_mut!(DATA)) };
    let mut guid = efi::Guid::from_bytes(&request.guid);
    match request.command {
        command::PING => {
            // Report the flash path: bit 0 = coreboot's flash services,
            // bit 1 = firmware writable through them in this boot.
            // SAFETY: single-threaded SMM; set once at init.
            let flash = unsafe { *addr_of!(FLASH) };
            request.attributes = u32::from(flash.uses_coreboot_services())
                | u32::from(flash.firmware_writable()) << 1;
            efi::Status::SUCCESS
        }
        command::READY_TO_BOOT => {
            end_firmware_phase();
            efi::Status::SUCCESS
        }
        command::EXIT_BOOT_SERVICES => {
            end_firmware_phase();
            MM_RUNTIME_LATCH.store(true, Ordering::Release);
            efi::Status::SUCCESS
        }
        command::SETUP_AUTHORIZE
        | command::FIRMWARE_ERASE
        | command::FIRMWARE_WRITE
        | command::SET_FIRMWARE_VARIABLE
            if !firmware_phase() =>
        {
            efi::Status::ACCESS_DENIED
        }
        // Setup can still enroll keys after a boot option returned, so only
        // ExitBootServices closes this read.
        command::AUTH_TIMESTAMP if MM_RUNTIME_LATCH.load(Ordering::Acquire) => {
            efi::Status::ACCESS_DENIED
        }
        command::SETUP_AUTHORIZE => match (request.attributes, request.data_size) {
            (
                bridge_operation::AUTHORIZE_SETUP_PK_DELETE
                | bridge_operation::AUTHORIZE_SETUP_SECURE_BOOT_ENABLE,
                1,
            ) => {
                SETUP_AUTHORIZATION.store(request.attributes, Ordering::Release);
                efi::Status::SUCCESS
            }
            (_, 0) => {
                SETUP_AUTHORIZATION.store(0, Ordering::Release);
                efi::Status::SUCCESS
            }
            _ => efi::Status::INVALID_PARAMETER,
        },
        command::FIRMWARE_ERASE | command::FIRMWARE_WRITE => {
            firmware_flash(config, request, data_capacity, data)
        }
        command::SET_FIRMWARE_VARIABLE => {
            if let Err(status) = load_name(config, request, name) {
                return status;
            }
            let size = request.data_size as usize;
            if size == 0 || size > data_capacity.min(crabefi_runtime_abi::MAX_VARIABLE_DATA_SIZE) {
                return efi::Status::INVALID_PARAMETER;
            }
            let Some(data) = data.get_mut(..size) else {
                return efi::Status::INVALID_PARAMETER;
            };
            copy_in(config.comm_base + DATA_OFFSET, data);
            set_firmware_variable(request, name, data)
        }
        command::AUTH_TIMESTAMP => {
            if let Err(status) = load_name(config, request, name) {
                return status;
            }
            let length = name
                .iter()
                .position(|&unit| unit == 0)
                .unwrap_or(name.len());
            match services::auth_timestamp_floor(&request.guid, &name[..length]) {
                Ok(Some(timestamp)) => {
                    let mut bytes = [0u8; 16];
                    bytes[..2].copy_from_slice(&timestamp.year.to_le_bytes());
                    bytes[2..8].copy_from_slice(&[
                        timestamp.month,
                        timestamp.day,
                        timestamp.hour,
                        timestamp.minute,
                        timestamp.second,
                        0,
                    ]);
                    bytes[8..12].copy_from_slice(&timestamp.nanosecond.to_le_bytes());
                    bytes[12..14].copy_from_slice(&timestamp.timezone.to_le_bytes());
                    bytes[14] = timestamp.daylight;
                    crate::mm_protocol::pack_timestamp(bytes, request);
                    efi::Status::SUCCESS
                }
                Ok(None) => efi::Status::NOT_FOUND,
                Err(status) => status,
            }
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
            if status == efi::Status::SUCCESS
                && let Some(data) = data.get(..size)
            {
                copy_out(data, config.comm_base + DATA_OFFSET);
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
                for (b, unit) in bytes.as_chunks_mut::<2>().0.iter_mut().zip(name.iter()) {
                    *b = unit.to_le_bytes();
                }
                if let Some(bytes) = bytes.get(..size) {
                    copy_out(bytes, config.comm_base + NAME_OFFSET);
                }
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
            let Some(staged) = data.get_mut(..size) else {
                return efi::Status::OUT_OF_RESOURCES;
            };
            copy_in(config.comm_base + DATA_OFFSET, staged);
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

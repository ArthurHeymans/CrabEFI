//! CrabEFI payload MM image.
//!
//! coreboot owns SMM and reserves an SMRAM area for the payload (coreboot
//! `drivers/payload_mm_interface`). The boot-time payload copies this image there
//! once through `PAYLOAD_MM_CMD_LOAD_AND_CALL_CORE`; coreboot then calls
//! [`crabefi_mm_runtime`] on every software SMI.
//!
//! Milestone 1 only moves flash writes into SMM: erase/write of the variable
//! store region, requested through a communication buffer in normal RAM. This
//! is NOT a secure interface yet (any ring-0 caller can write the store); the
//! authenticated variable services replace these commands in milestone 2.

#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::ptr::{
    addr_of, addr_of_mut, read_unaligned, read_volatile, write_unaligned, write_volatile,
};

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
const SHARED_INFO_REVISION: u8 = 1;

/// Boot-time configuration from the trusted payload (`arg1`), copied once.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InitConfig {
    pub magic: u64,
    pub version: u32,
    pub size: u32,
    /// Payload MM area: shared page followed by the area this image runs in.
    pub mm_area_base: u64,
    pub mm_area_size: u64,
    /// Ring-0 communication buffer (normal RAM).
    pub comm_base: u64,
    pub comm_size: u64,
    /// Memory-mapped flash and the variable store inside it (flash offsets).
    pub flash_base: u64,
    pub flash_size: u64,
    pub store_offset: u64,
    pub store_size: u64,
}

const INIT_MAGIC: u64 = 0x4749_4643_4d4d_4243; // "CBMMCFIG"
const INIT_VERSION: u32 = 1;

/// Request header at the start of the communication buffer.
#[repr(C)]
#[derive(Clone, Copy)]
struct CommHeader {
    magic: u64,
    version: u32,
    command: u32,
    status: u32,
    offset: u32,
    length: u32,
    reserved: u32,
}

const COMM_MAGIC: u64 = 0x0043_4d4d_4241_5243; // "CRABMMC\0"
const COMM_VERSION: u32 = 1;
const COMM_HEADER_SIZE: u64 = core::mem::size_of::<CommHeader>() as u64;

const CMD_PING: u32 = 1;
const CMD_ERASE: u32 = 2;
const CMD_WRITE: u32 = 3;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID: u32 = 1;
const STATUS_RANGE: u32 = 2;
const STATUS_FLASH: u32 = 3;
const STATUS_PENDING: u32 = 0xffff_ffff;

const ERASE_BLOCK: u64 = 4096;
const MAX_TRANSFER: usize = 64 * 1024;

struct State {
    ready: bool,
    config: InitConfig,
}

static mut STATE: State = State {
    ready: false,
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
};

/// Requests are copied here before they are checked or used (no TOCTOU on ring-0 memory).
static mut TRANSFER: [u8; MAX_TRANSFER] = [0; MAX_TRANSFER];

const STACK_SIZE: usize = 64 * 1024;
#[repr(C, align(16))]
struct Stack([u8; STACK_SIZE]);
static mut MM_STACK: Stack = Stack([0; STACK_SIZE]);

// coreboot calls both entry points on its 2 KiB SMM stack; switch to our own.
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
    fn crabefi_mm_runtime(arg: *mut u8);
}

fn ranges_overlap(a: u64, a_len: u64, b: u64, b_len: u64) -> bool {
    let (Some(a_end), Some(b_end)) = (a.checked_add(a_len), b.checked_add(b_len)) else {
        return true;
    };
    a < b_end && b < a_end
}

/// First and only entry from coreboot's LOAD_AND_CALL_CORE. Returns 0 on success.
extern "sysv64" fn mm_init(context: *const CallContext) -> u8 {
    // SAFETY: coreboot passes its call context in the shared page it maps.
    let config_ptr = unsafe { read_unaligned(addr_of!((*context).arg1)) } as *const InitConfig;
    if config_ptr.is_null() {
        return 1;
    }
    // SAFETY: the trusted boot-time payload owns this structure; copy it once.
    let config = unsafe { read_unaligned(config_ptr) };
    if config.magic != INIT_MAGIC
        || config.version != INIT_VERSION
        || config.size as usize != core::mem::size_of::<InitConfig>()
        || config.comm_size <= COMM_HEADER_SIZE
        || config.store_size == 0
        || config.store_offset % ERASE_BLOCK != 0
        || config.store_size % ERASE_BLOCK != 0
        || config
            .store_offset
            .checked_add(config.store_size)
            .is_none_or(|end| end > config.flash_size)
        || ranges_overlap(
            config.comm_base,
            config.comm_size,
            config.mm_area_base,
            config.mm_area_size,
        )
    {
        return 1;
    }

    // SAFETY: single-threaded SMM; coreboot serializes SMIs.
    unsafe {
        let state = &mut *addr_of_mut!(STATE);
        state.config = config;
        state.ready = true;

        let shared = config.mm_area_base as *mut SharedInfo;
        write_unaligned(
            shared,
            SharedInfo {
                header_magic: SHARED_INFO_MAGIC,
                shared_info_size: core::mem::size_of::<SharedInfo>() as u16,
                header_revision: SHARED_INFO_REVISION,
                reserved: 0,
                mm_entrypoint_address: crabefi_mm_runtime as *const () as usize as u32,
            },
        );
    }
    0
}

/// Called by coreboot on every software SMI once registered.
extern "sysv64" fn mm_runtime(_argument: *mut u8) {
    // SAFETY: single-threaded SMM.
    let state = unsafe { &*addr_of!(STATE) };
    if !state.ready {
        return;
    }
    let config = state.config;
    let header_ptr = config.comm_base as *mut CommHeader;
    // SAFETY: comm_base was checked at init not to overlap the MM area; volatile because ring 0 owns it.
    let header = unsafe { read_volatile(header_ptr) };
    if header.magic != COMM_MAGIC || header.status != STATUS_PENDING {
        return; // Not addressed to us.
    }
    let status = if header.version != COMM_VERSION {
        STATUS_INVALID
    } else {
        handle(&config, &header)
    };
    // SAFETY: as above.
    unsafe { write_volatile(addr_of_mut!((*header_ptr).status), status) };
}

fn handle(config: &InitConfig, header: &CommHeader) -> u32 {
    let offset = u64::from(header.offset);
    let length = u64::from(header.length);
    match header.command {
        CMD_PING => STATUS_SUCCESS,
        CMD_ERASE | CMD_WRITE => {
            let Some(end) = offset.checked_add(length) else {
                return STATUS_RANGE;
            };
            if length == 0
                || offset < config.store_offset
                || end > config.store_offset + config.store_size
            {
                return STATUS_RANGE;
            }
            if header.command == CMD_ERASE {
                if offset % ERASE_BLOCK != 0 || length % ERASE_BLOCK != 0 {
                    return STATUS_RANGE;
                }
                flash_erase(config, offset, length)
            } else {
                if length > MAX_TRANSFER as u64 || length > config.comm_size - COMM_HEADER_SIZE {
                    return STATUS_RANGE;
                }
                // SAFETY: TRANSFER is MM-private; the source range lies in the checked comm buffer.
                let data = unsafe {
                    let transfer = &mut *addr_of_mut!(TRANSFER);
                    let source = (config.comm_base + COMM_HEADER_SIZE) as *const u8;
                    for (i, byte) in transfer[..length as usize].iter_mut().enumerate() {
                        *byte = read_volatile(source.add(i));
                    }
                    &transfer[..length as usize]
                };
                flash_write(config, offset, data)
            }
        }
        _ => STATUS_INVALID,
    }
}

// QEMU cfi.pflash01 command set (milestone 1 targets QEMU; AMD ROM Armor comes later).
const CFI_READ_ARRAY: u8 = 0xff;
const CFI_WRITE_BYTE: u8 = 0x10;
const CFI_ERASE_SETUP: u8 = 0x20;
const CFI_ERASE_CONFIRM: u8 = 0xd0;

fn flash_ptr(config: &InitConfig, offset: u64) -> *mut u8 {
    (config.flash_base + offset) as *mut u8
}

fn flash_erase(config: &InitConfig, offset: u64, length: u64) -> u32 {
    let mut block = offset;
    while block < offset + length {
        // SAFETY: inside the store range checked by the caller; flash is MMIO.
        unsafe {
            write_volatile(flash_ptr(config, block), CFI_ERASE_SETUP);
            write_volatile(flash_ptr(config, block), CFI_ERASE_CONFIRM);
        }
        block += ERASE_BLOCK;
    }
    // SAFETY: as above.
    unsafe { write_volatile(flash_ptr(config, offset), CFI_READ_ARRAY) };
    for i in 0..length {
        // SAFETY: as above.
        if unsafe { read_volatile(flash_ptr(config, offset + i)) } != 0xff {
            return STATUS_FLASH;
        }
    }
    STATUS_SUCCESS
}

fn flash_write(config: &InitConfig, offset: u64, data: &[u8]) -> u32 {
    for (i, &byte) in data.iter().enumerate() {
        let target = flash_ptr(config, offset + i as u64);
        // SAFETY: inside the store range checked by the caller; flash is MMIO.
        unsafe {
            write_volatile(target, CFI_WRITE_BYTE);
            write_volatile(target, byte);
        }
    }
    // SAFETY: as above.
    unsafe { write_volatile(flash_ptr(config, offset), CFI_READ_ARRAY) };
    for (i, &byte) in data.iter().enumerate() {
        // SAFETY: as above.
        if unsafe { read_volatile(flash_ptr(config, offset + i as u64)) } != byte {
            return STATUS_FLASH;
        }
    }
    STATUS_SUCCESS
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

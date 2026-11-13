//! Payload MM gate test: runs as a boot option, i.e. after CrabEFI ended MM's
//! firmware phase, and checks that ring 0 cannot use firmware-only MM
//! commands, write the flash directly or load a second MM image.
//!
//! Prints `MMGATE PASS|FAIL <check>` lines and `MMGATE DONE` on COM1.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
use r_efi::efi::{self, Handle, Status, SystemTable};

const COMM_MAGIC: u64 = 0x0056_4d4d_4241_5243; // "CRABMMV\0"
const COMM_VERSION: u32 = 2;
const STATUS_PENDING: u64 = u64::MAX;
const NAME_OFFSET: u64 = 0x100;
const DATA_OFFSET: u64 = 0x300;
const ACCESS_DENIED: u64 = 0x8000_0000_0000_000f;

const CMD_PING: u32 = 1;
const CMD_SETUP_AUTHORIZE: u32 = 8;
const CMD_FIRMWARE_WRITE: u32 = 10;
const CMD_SET_FIRMWARE_VARIABLE: u32 = 11;

#[repr(C)]
#[derive(Clone, Copy)]
struct Request {
    magic: u64,
    version: u32,
    command: u32,
    status: u64,
    guid: [u8; 16],
    attributes: u32,
    name_size: u32,
    data_size: u64,
    maximum_storage: u64,
    remaining_storage: u64,
    maximum_variable: u64,
    offset: u64,
}

fn outb(port: u16, value: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack))
    };
}

fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe {
        core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack))
    };
    value
}

fn serial(text: &str) {
    for byte in text.bytes() {
        for _ in 0..100_000 {
            if inb(0x3fd) & 0x20 != 0 {
                break;
            }
        }
        outb(0x3f8, byte);
    }
}

fn result(pass: bool, name: &str) {
    serial(if pass { "MMGATE PASS " } else { "MMGATE FAIL " });
    serial(name);
    serial("\r\n");
}

/// Find the MM request buffer: a RuntimeServicesData page starting with its magic.
unsafe fn find_comm(system_table: *mut SystemTable) -> Option<u64> {
    let bs = (*system_table).boot_services;
    let mut map = [0u8; 16384];
    let mut size = map.len();
    let (mut key, mut descriptor_size, mut version) = (0usize, 0usize, 0u32);
    let status = ((*bs).get_memory_map)(
        &mut size,
        map.as_mut_ptr().cast(),
        &mut key,
        &mut descriptor_size,
        &mut version,
    );
    if status != Status::SUCCESS || descriptor_size == 0 {
        return None;
    }
    for offset in (0..size).step_by(descriptor_size) {
        let descriptor = map
            .as_ptr()
            .add(offset)
            .cast::<efi::MemoryDescriptor>()
            .read_unaligned();
        if descriptor.r#type != efi::RUNTIME_SERVICES_DATA {
            continue;
        }
        for page in 0..descriptor.number_of_pages {
            let address = descriptor.physical_start + page * 4096;
            if read_volatile(address as *const u64) == COMM_MAGIC {
                return Some(address);
            }
        }
    }
    None
}

unsafe fn mm_call(comm: u64, mut request: Request, name: &[u16], data: &[u8]) -> u64 {
    for (i, unit) in name.iter().enumerate() {
        write_volatile((comm + NAME_OFFSET + i as u64 * 2) as *mut u16, *unit);
    }
    for (i, byte) in data.iter().enumerate() {
        write_volatile((comm + DATA_OFFSET + i as u64) as *mut u8, *byte);
    }
    request.magic = COMM_MAGIC;
    request.version = COMM_VERSION;
    request.status = STATUS_PENDING;
    write_volatile(comm as *mut Request, request);
    outb(0xb2, 0);
    read_volatile(core::ptr::addr_of!((*(comm as *const Request)).status))
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

/// Flash offset and size of an FMAP area in the memory-mapped flash below 4 GiB.
unsafe fn fmap_area(flash_base: u64, flash_size: u64, wanted: &[u8]) -> Option<(u64, u64)> {
    let mut offset = 0;
    while offset + 8 <= flash_size {
        if read_volatile((flash_base + offset) as *const [u8; 8]) == *b"__FMAP__" {
            let fmap = flash_base + offset;
            let areas = read_volatile((fmap + 54) as *const u16) as u64;
            for i in 0..areas.min(64) {
                let area = fmap + 56 + i * 42;
                let name = read_volatile((area + 8) as *const [u8; 32]);
                let len = name.iter().position(|&b| b == 0).unwrap_or(32);
                if &name[..len] == wanted {
                    return Some((
                        read_volatile(area as *const u32) as u64,
                        read_volatile((area + 4) as *const u32) as u64,
                    ));
                }
            }
            return None;
        }
        offset += 4096;
    }
    None
}

#[no_mangle]
pub extern "efiapi" fn efi_main(_image_handle: Handle, system_table: *mut SystemTable) -> Status {
    serial("MMGATE START\r\n");
    let Some(comm) = (unsafe { find_comm(system_table) }) else {
        serial("MMGATE SKIP no payload MM request buffer\r\n");
        serial("MMGATE DONE\r\n");
        return Status::SUCCESS;
    };
    unsafe {
        // Positive control: MM answers, and says which flash path it uses.
        result(mm_call(comm, request(CMD_PING), &[], &[]) == 0, "ping");
        let services = read_volatile(core::ptr::addr_of!((*(comm as *const Request)).attributes));
        serial(if services & 1 != 0 {
            "MMGATE INFO flash path: coreboot flash services\r\n"
        } else {
            "MMGATE INFO flash path: MM drives the flash itself\r\n"
        });

        // Firmware-only commands after READY_TO_BOOT.
        let mut write = request(CMD_FIRMWARE_WRITE);
        write.offset = 0;
        write.data_size = 1;
        result(
            mm_call(comm, write, &[], &[0]) == ACCESS_DENIED,
            "firmware-write-denied",
        );

        let pk: [u16; 3] = [b'P' as u16, b'K' as u16, 0];
        let mut set = request(CMD_SET_FIRMWARE_VARIABLE);
        set.guid = [
            0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03,
            0x2b, 0x8c,
        ];
        set.attributes = 0x27;
        set.name_size = 6;
        set.data_size = 1;
        result(
            mm_call(comm, set, &pk, &[0]) == ACCESS_DENIED,
            "firmware-variable-denied",
        );

        let mut authorize = request(CMD_SETUP_AUTHORIZE);
        authorize.attributes = 3;
        authorize.data_size = 1;
        result(
            mm_call(comm, authorize, &[], &[]) == ACCESS_DENIED,
            "setup-authorize-denied",
        );

        // Direct flash write to the variable store from ring 0.
        let (flash_size, flash_base) = (8u64 << 20, (1u64 << 32) - (8u64 << 20));
        match fmap_area(flash_base, flash_size, b"SMMSTORE") {
            Some((store, _)) => {
                let target = (flash_base + store + 0x28) as *mut u8; // "_FVH" signature
                let before = read_volatile(target);
                write_volatile(target, 0x10); // CFI byte program
                write_volatile(target, 0x00);
                write_volatile(target, 0xff); // read array
                result(read_volatile(target) == before, "ring0-flash-write-blocked");
            }
            None => result(false, "ring0-flash-write-blocked (no SMMSTORE in FMAP)"),
        }

        // A second payload MM load must be refused by coreboot.
        let mut eax: u32 = (1 << 8) | 0xe8;
        let context = [0u8; 64];
        core::arch::asm!(
            "xchg {ctx}, rbx",
            "out 0xb2, al",
            "xchg {ctx}, rbx",
            ctx = inout(reg) context.as_ptr() as u64 => _,
            inout("eax") eax,
            options(nostack),
        );
        result(eax & 0xff == 1, "second-load-refused");
        result(
            mm_call(comm, request(CMD_PING), &[], &[]) == 0,
            "mm-still-answers",
        );
    }
    serial("MMGATE DONE\r\n");
    Status::SUCCESS
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

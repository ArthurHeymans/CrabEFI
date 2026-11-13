//! Boot event log (`CrabEFIEventLog`): one record per boot, the oldest boot
//! dropped after 32, and only firmware writes it. Every boot runs this app
//! and resets, all in one QEMU process so CMOS survives the resets.
//! Driven by `./crabefi test --app boot-events-test` on x86-64 QEMU.
#![no_std]
#![no_main]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::panic::PanicInfo;
use core::ptr;
use r_efi::efi::{self, BootServices, Guid, Handle, RuntimeServices, Status, SystemTable};

const SETTINGS: Guid = Guid::from_fields(
    0x9e80634c,
    0xcdc7,
    0x41d5,
    0xa3,
    0x45,
    &[0x4a, 0x29, 0x7f, 0x9c, 0x7d, 0x1a],
);
const GLOBAL: Guid = Guid::from_fields(
    0x8be4df61,
    0x93ca,
    0x11d2,
    0xaa,
    0x0d,
    &[0, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
);
const TEST: Guid = Guid::from_fields(0x6d2a7f1e, 0x40c3, 0x4b8e, 0x9d, 0x21, &[1, 2, 3, 4, 5, 6]);
const NV_BS_RT: u32 = 7;
const LOG: &str = "CrabEFIEventLog";
const STATE: &str = "BootEventsTestState";
/// Boots CrabEFI keeps (`boot_event_log::MAX_BOOTS`).
const MAX_BOOTS: u32 = 32;
const TYPE_BOOT: u8 = 0x17;
const TYPE_LAST_POST_CODE: u8 = 0xa3;
/// coreboot CMOS_POST layout at the q35 test ROM's CONFIG_CMOS_POST_OFFSET.
const CMOS_POST_OFFSET: u8 = 0x70;
const INJECTED_POST_CODE: u8 = 0x77;

fn name(text: &str) -> [u16; 32] {
    let mut out = [0; 32];
    for (dest, ch) in out.iter_mut().zip(text.encode_utf16()) {
        *dest = ch;
    }
    out
}

fn get(rt: *mut RuntimeServices, guid: &Guid, key: &str, data: &mut [u8]) -> (Status, u32, usize) {
    let mut len = data.len();
    let mut attrs = 0;
    let status = unsafe {
        ((*rt).get_variable)(
            name(key).as_ptr().cast_mut(),
            (guid as *const Guid).cast_mut(),
            &mut attrs,
            &mut len,
            data.as_mut_ptr().cast(),
        )
    };
    (status, attrs, len)
}

fn set(rt: *mut RuntimeServices, guid: &Guid, key: &str, attrs: u32, data: &[u8]) -> Status {
    unsafe {
        ((*rt).set_variable)(
            name(key).as_ptr().cast_mut(),
            (guid as *const Guid).cast_mut(),
            attrs,
            data.len(),
            data.as_ptr().cast_mut().cast(),
        )
    }
}

/// Boot this app straight away on the next boots: Boot0001 + BootOrder,
/// no menu timeout.
fn boot_without_menu(rt: *mut RuntimeServices) {
    let path = "\\EFI\\BOOT\\BOOTX64.EFI";
    let mut option = [0u8; 128];
    option[..4].copy_from_slice(&1u32.to_le_bytes()); // LOAD_OPTION_ACTIVE
    let mut pos = 6;
    for ch in "Boot events test\0".encode_utf16() {
        option[pos..pos + 2].copy_from_slice(&ch.to_le_bytes());
        pos += 2;
    }
    let start = pos;
    let node_len = 4 + (path.encode_utf16().count() + 1) * 2;
    option[pos..pos + 4].copy_from_slice(&[4, 4, node_len as u8, 0]);
    pos += 4;
    for ch in path.encode_utf16().chain(core::iter::once(0)) {
        option[pos..pos + 2].copy_from_slice(&ch.to_le_bytes());
        pos += 2;
    }
    option[pos..pos + 4].copy_from_slice(&[0x7f, 0xff, 4, 0]);
    pos += 4;
    option[4..6].copy_from_slice(&((pos - start) as u16).to_le_bytes());
    for (key, data) in [
        ("Boot0001", &option[..pos]),
        ("BootOrder", &1u16.to_le_bytes()[..]),
        ("Timeout", &0u16.to_le_bytes()[..]),
    ] {
        check(
            set(rt, &GLOBAL, key, NV_BS_RT, data) == Status::SUCCESS,
            "SetVariable boot option",
        );
    }
}

struct Log {
    data: [u8; 4096],
    len: usize,
}

fn read_log(rt: *mut RuntimeServices) -> Log {
    let mut log = Log {
        data: [0; 4096],
        len: 0,
    };
    let (status, attrs, len) = get(rt, &SETTINGS, LOG, &mut log.data);
    check(status == Status::SUCCESS, "CrabEFIEventLog missing");
    check(
        attrs == NV_BS_RT,
        "CrabEFIEventLog attributes are not NV|BS|RT",
    );
    log.len = len;
    log
}

#[derive(Default)]
struct Summary {
    records: u32,
    first: u32,
    last: u32,
    /// Event types of the last boot, after its boot event.
    events: [u8; 16],
    event_count: usize,
    last_post_code: Option<u16>,
}

/// Check the ELOG image and summarize its boots.
fn parse(log: &[u8]) -> Summary {
    check(log.len() >= 9 && &log[..6] == b"ELOG\x01\x08", "log header");
    check(log[log.len() - 1] == 0xff, "log does not end with 0xff");
    let mut summary = Summary::default();
    let mut offset = 8;
    while log[offset] != 0xff {
        let len = usize::from(log[offset + 1]);
        check(
            (9..=0x7f).contains(&len) && offset + len < log.len(),
            "event length",
        );
        let event = &log[offset..offset + len];
        check(
            event.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)) == 0,
            "event checksum",
        );
        if event[0] == TYPE_BOOT {
            check(len == 13, "boot event length");
            let boot = u32::from_le_bytes([event[8], event[9], event[10], event[11]]);
            if summary.records == 0 {
                summary.first = boot;
            } else {
                check(boot == summary.last + 1, "boot numbers not consecutive");
            }
            summary.records += 1;
            summary.last = boot;
            summary.event_count = 0;
            summary.last_post_code = None;
        } else {
            check(summary.records != 0, "event before the first boot");
            if summary.event_count < summary.events.len() {
                summary.events[summary.event_count] = event[0];
                summary.event_count += 1;
            }
            if event[0] == TYPE_LAST_POST_CODE {
                summary.last_post_code = Some(u16::from_le_bytes([event[8], event[9]]));
            }
        }
        offset += len;
    }
    check(offset == log.len() - 1, "data after the end marker");
    summary
}

/// The firmware-phase and OS-phase write attempts that must all fail.
fn writes_refused(rt: *mut RuntimeServices, log: &Log) -> bool {
    let forged = [0xffu8; 16];
    [
        set(rt, &SETTINGS, LOG, NV_BS_RT, &forged),
        set(rt, &SETTINGS, LOG, NV_BS_RT, &log.data[..log.len]),
        set(
            rt,
            &SETTINGS,
            LOG,
            NV_BS_RT | efi::VARIABLE_APPEND_WRITE,
            &forged,
        ),
        set(rt, &SETTINGS, LOG, 0, &[]),
    ]
    .iter()
    .all(|status| *status == Status::WRITE_PROTECTED)
}

fn unchanged(rt: *mut RuntimeServices, log: &Log) -> bool {
    let again = read_log(rt);
    again.data[..again.len] == log.data[..log.len]
}

fn cmos_read(index: u8) -> u8 {
    let value: u8;
    unsafe {
        core::arch::asm!("out dx, al", in("dx") 0x70u16, in("al") index, options(nomem, nostack));
        core::arch::asm!("in al, dx", in("dx") 0x71u16, out("al") value, options(nomem, nostack));
    }
    value
}

fn cmos_write(index: u8, value: u8) {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") 0x70u16, in("al") index, options(nomem, nostack));
        core::arch::asm!("out dx, al", in("dx") 0x71u16, in("al") value, options(nomem, nostack));
    }
}

/// Pretend this boot stopped at an unexpected POST code: write it to the
/// active coreboot CMOS_POST bank. False without CMOS_POST at the offset.
fn inject_post_code() -> bool {
    let code = match cmos_read(CMOS_POST_OFFSET) {
        0x80 => CMOS_POST_OFFSET + 1,
        0x81 => CMOS_POST_OFFSET + 2,
        _ => return false,
    };
    cmos_write(code, INJECTED_POST_CODE);
    true
}

fn check(ok: bool, message: &str) {
    if !ok {
        serial("BEVT TEST FAILED: ");
        serial(message);
        serial("\r\n");
        exit();
    }
}

fn exit_boot_services(image: Handle, bs: &BootServices) {
    #[repr(align(16))]
    struct Map([u8; 32 * 1024]);
    let mut map = Map([0; 32 * 1024]);
    let mut size = map.0.len();
    let mut key = 0;
    let mut desc_size = 0;
    let mut version = 0;
    let status = unsafe {
        (bs.get_memory_map)(
            &mut size,
            map.0.as_mut_ptr().cast(),
            &mut key,
            &mut desc_size,
            &mut version,
        )
    };
    check(status == Status::SUCCESS, "GetMemoryMap");
    let status = unsafe { (bs.exit_boot_services)(image, key) };
    check(status == Status::SUCCESS, "ExitBootServices");
}

fn reset(rt: *mut RuntimeServices) -> ! {
    unsafe { ((*rt).reset_system)(efi::RESET_COLD, Status::SUCCESS, 0, ptr::null_mut()) };
    check(false, "ResetSystem returned");
    exit()
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system: *mut SystemTable) -> Status {
    let rt = unsafe { (*system).runtime_services };
    let bs = unsafe { &*(*system).boot_services };

    // phase, records, first, last boot, post code injected
    let mut state = [0u8; 20];
    let (status, _, _) = get(rt, &TEST, STATE, &mut state);
    let word = |state: &[u8; 20], i: usize| {
        u32::from_le_bytes(state[i * 4..i * 4 + 4].try_into().unwrap())
    };
    let (phase, records, first, last, injected) = if status == Status::SUCCESS {
        (
            word(&state, 0),
            word(&state, 1),
            word(&state, 2),
            word(&state, 3),
            word(&state, 4) != 0,
        )
    } else {
        (0, 0, 0, 0, false)
    };

    let log = read_log(rt);
    let summary = parse(&log.data[..log.len]);
    serial("BEVT BOOT phase=");
    serial_dec(phase);
    serial(" records=");
    serial_dec(summary.records);
    serial(" boots=");
    serial_dec(summary.first);
    serial("..");
    serial_dec(summary.last);
    serial(" bytes=");
    serial_dec(log.len as u32);
    serial(" events=");
    serial_hex(&summary.events[..summary.event_count]);
    serial("\r\n");

    let mut wrapped = false;
    if phase == 0 {
        check(summary.records >= 1, "no record for this boot");
        check(
            writes_refused(rt, &log),
            "firmware-phase SetVariable changed the log",
        );
        check(unchanged(rt, &log), "log changed by refused writes");
        serial("BEVT BOOT SERVICES WRITE REFUSED PASSED\r\n");
        boot_without_menu(rt);
    } else {
        check(summary.last == last + 1, "not one new boot record");
        if records < MAX_BOOTS {
            check(
                summary.records == records + 1 && summary.first == first,
                "log did not grow by one record",
            );
        } else {
            check(
                summary.records == MAX_BOOTS && summary.first == first + 1,
                "oldest boot not dropped at the limit",
            );
            wrapped = true;
            serial("BEVT GROWTH PASSED\r\nBEVT WRAP PASSED\r\n");
        }
    }

    if injected {
        check(
            summary.last_post_code == Some(u16::from(INJECTED_POST_CODE)),
            "coreboot did not hand over the previous boot's POST code",
        );
        serial("BEVT COREBOOT HANDOFF PASSED\r\n");
    }
    let inject = phase == 1 && inject_post_code();
    if phase == 1 && !inject {
        serial("BEVT COREBOOT HANDOFF SKIPPED (no CMOS_POST at 0x70)\r\n");
    }

    if wrapped {
        exit_boot_services(image, bs);
        check(
            writes_refused(rt, &log),
            "OS SetVariable changed or deleted the log",
        );
        check(unchanged(rt, &log), "log changed after ExitBootServices");
        serial("BEVT OS WRITE REFUSED PASSED\r\nBEVT TEST PASSED\r\n");
        exit();
    }

    let next = [
        phase + 1,
        summary.records,
        summary.first,
        summary.last,
        u32::from(inject),
    ];
    for (chunk, value) in state.chunks_exact_mut(4).zip(next) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    check(
        set(rt, &TEST, STATE, NV_BS_RT, &state) == Status::SUCCESS,
        "SetVariable test state",
    );
    reset(rt)
}

fn serial_dec(mut value: u32) {
    let mut digits = [0u8; 10];
    let mut len = 0;
    loop {
        digits[len] = b'0' + (value % 10) as u8;
        len += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for &digit in digits[..len].iter().rev() {
        serial_byte(digit);
    }
}

fn serial_hex(bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        serial_byte(HEX[usize::from(byte >> 4)]);
        serial_byte(HEX[usize::from(byte & 0xf)]);
        serial_byte(b' ');
    }
}

/// Log directly to QEMU's UART, including after ExitBootServices.
fn serial(text: &str) {
    text.bytes().for_each(serial_byte);
}

fn serial_byte(byte: u8) {
    unsafe {
        let mut ready: u8;
        loop {
            core::arch::asm!("in al, dx", in("dx") 0x3fdu16, out("al") ready, options(nomem, nostack));
            if ready & 0x20 != 0 {
                break;
            }
        }
        core::arch::asm!("out dx, al", in("dx") 0x3f8u16, in("al") byte, options(nomem, nostack));
    }
}

/// Terminate QEMU through its debug-exit device; markers determine success.
fn exit() -> ! {
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") 0xf4u16, in("eax") 0x10u32, options(nomem, nostack));
    }
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    serial("BEVT TEST FAILED: panic\r\n");
    exit()
}

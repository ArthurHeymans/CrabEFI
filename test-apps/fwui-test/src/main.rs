//! GRUB fwsetup/systemd-boot equivalent: persistent OsIndications + ResetSystem.
//! Driven by `./crabefi test --app fwui-test --disable-kvm` on x86-64 QEMU.
#![no_std]
#![no_main]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::panic::PanicInfo;
use r_efi::efi::{self, Guid, Handle, RuntimeServices, Status, SystemTable};

const GLOBAL: Guid = Guid::from_fields(
    0x8be4df61,
    0x93ca,
    0x11d2,
    0xaa,
    0x0d,
    &[0, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
);
const TEST: Guid = Guid::from_fields(0x54dbdb16, 0x1970, 0x40e2, 0x93, 0xf0, &[1, 2, 3, 4, 5, 6]);
const OTHER_BIT: u64 = 1 << 63;

fn name(text: &str) -> [u16; 32] {
    let mut out = [0; 32];
    for (dest, ch) in out.iter_mut().zip(text.encode_utf16()) {
        *dest = ch;
    }
    out
}

fn get(rt: *mut RuntimeServices, guid: &Guid, key: &str) -> Option<(u32, [u8; 8], usize)> {
    let mut data = [0; 8];
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
    (status == Status::SUCCESS).then_some((attrs, data, len))
}

fn set(rt: *mut RuntimeServices, guid: &Guid, key: &str, data: &[u8]) {
    let status = unsafe {
        ((*rt).set_variable)(
            name(key).as_ptr().cast_mut(),
            (guid as *const Guid).cast_mut(),
            7,
            data.len(),
            data.as_ptr().cast_mut().cast(),
        )
    };
    check(status == Status::SUCCESS, "SetVariable");
}

fn value(rt: *mut RuntimeServices, key: &str, expected: &[u8]) -> bool {
    get(rt, &GLOBAL, key).is_some_and(|(attrs, bytes, len)| {
        attrs == 7 && len == expected.len() && bytes[..len] == *expected
    })
}

fn check(ok: bool, message: &str) {
    if !ok {
        serial("FWUI TEST FAILED: ");
        serial(message);
        serial("\r\n");
        exit();
    }
}

fn exit_boot_services(image: Handle, system: *mut SystemTable) {
    #[repr(align(16))]
    struct Map([u8; 32 * 1024]);
    let mut map = Map([0; 32 * 1024]);
    let mut size = map.0.len();
    let mut key = 0;
    let mut desc_size = 0;
    let mut version = 0;
    let bs = unsafe { &*(*system).boot_services };
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
    unsafe { ((*rt).reset_system)(efi::RESET_COLD, Status::SUCCESS, 0, core::ptr::null_mut()) };
    check(false, "ResetSystem returned");
    exit()
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system: *mut SystemTable) -> Status {
    let rt = unsafe { (*system).runtime_services };
    let (attrs, supported, len) = get(rt, &GLOBAL, "OsIndicationsSupported").unwrap_or_else(|| {
        check(false, "missing support");
        exit()
    });
    check(
        attrs == 6 && len == 8 && u64::from_le_bytes(supported) & 1 != 0,
        "support bit/attributes",
    );
    serial("FWUI SUPPORTED PASSED\r\n");
    let phase = get(rt, &TEST, "FwUiTestPhase").map_or(0, |(_, data, _)| data[0]);
    match phase {
        0 => {
            // A real load option, used by both BootNext and BootOrder. The file
            // path node intentionally works on any of the test storage buses.
            let mut option = [0u8; 256];
            option[..4].copy_from_slice(&1u32.to_le_bytes()); // LOAD_OPTION_ACTIVE
            let mut pos = 6;
            for ch in "Firmware UI regression\0".encode_utf16() {
                option[pos..pos + 2].copy_from_slice(&ch.to_le_bytes());
                pos += 2;
            }
            let start = pos;
            let path = "\\EFI\\BOOT\\BOOTX64.EFI\0";
            let node_len = 4 + path.encode_utf16().count() * 2;
            option[pos..pos + 4].copy_from_slice(&[4, 4, node_len as u8, 0]);
            pos += 4;
            for ch in path.encode_utf16() {
                option[pos..pos + 2].copy_from_slice(&ch.to_le_bytes());
                pos += 2;
            }
            option[pos..pos + 4].copy_from_slice(&[0x7f, 0xff, 4, 0]);
            pos += 4;
            option[4..6].copy_from_slice(&((pos - start) as u16).to_le_bytes());
            set(rt, &GLOBAL, "BootFFFF", &option[..pos]);
            set(rt, &GLOBAL, "BootNext", &0xffffu16.to_le_bytes());
            set(rt, &GLOBAL, "BootOrder", &0xffffu16.to_le_bytes());
            set(rt, &GLOBAL, "Timeout", &2u16.to_le_bytes());
            set(rt, &TEST, "FwUiTestPhase", &[1]);
            let previous = get(rt, &GLOBAL, "OsIndications")
                .map_or(0, |(_, data, _)| u64::from_le_bytes(data));
            set(
                rt,
                &GLOBAL,
                "OsIndications",
                &(previous | OTHER_BIT | 1).to_le_bytes(),
            );
            serial("FWUI REQUEST WRITTEN; RESETTING\r\n");
            reset(rt);
        }
        1 => {
            check(
                value(rt, "OsIndications", &OTHER_BIT.to_le_bytes()),
                "clear preserved unrelated bit/attributes",
            );
            check(
                value(rt, "BootNext", &0xffffu16.to_le_bytes()),
                "setup consumed BootNext",
            );
            serial("FWUI MANUAL BOOT: REQUEST CLEARED AND BOOTNEXT PRESERVED\r\n");
            set(rt, &TEST, "FwUiTestPhase", &[2]);
            reset(rt);
        }
        2 | 3 | 5 => {
            check(
                value(rt, "OsIndications", &OTHER_BIT.to_le_bytes()),
                "clear did not persist across reset",
            );
            check(
                get(rt, &GLOBAL, "BootNext").is_none(),
                "normal boot failed to consume BootNext",
            );
            let current = get(rt, &GLOBAL, "BootCurrent");
            check(
                current.is_some_and(|(_, bytes, len)| len == 2 && bytes[..2] == [0xff, 0xff]),
                "normal boot did not use BootFFFF",
            );
            if phase == 2 {
                serial("FWUI NORMAL BOOTNEXT PASSED\r\n");
                set(rt, &TEST, "FwUiTestPhase", &[3]);
                reset(rt);
            }
            if phase == 3 {
                serial("FWUI NORMAL BOOTORDER PASSED\r\n");
                set(rt, &TEST, "FwUiTestPhase", &[4]);
                exit_boot_services(image, system);
                // OS-equivalent request: only runtime services remain. This
                // goes through the retained journal, then replays on reboot.
                set(rt, &GLOBAL, "OsIndications", &(OTHER_BIT | 1).to_le_bytes());
                serial("FWUI RUNTIME REQUEST WRITTEN; RESETTING\r\n");
                unsafe {
                    ((*rt).reset_system)(efi::RESET_WARM, Status::SUCCESS, 0, core::ptr::null_mut())
                };
                check(false, "runtime ResetSystem returned");
            }
            serial("FWUI RUNTIME SUBSEQUENT BOOT PASSED\r\nFWUI TEST PASSED\r\n");
            exit();
        }
        4 => {
            check(
                value(rt, "OsIndications", &OTHER_BIT.to_le_bytes()),
                "runtime request clear",
            );
            check(
                get(rt, &GLOBAL, "BootNext").is_none(),
                "unexpected BootNext after runtime setup",
            );
            serial("FWUI RUNTIME MANUAL BOOT: REQUEST CLEARED\r\n");
            set(rt, &TEST, "FwUiTestPhase", &[5]);
            reset(rt);
        }
        _ => check(false, "unexpected phase"),
    }
    Status::SUCCESS
}

fn serial(text: &str) {
    for byte in text.bytes() {
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
}

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
    serial("FWUI TEST FAILED: panic\r\n");
    exit()
}

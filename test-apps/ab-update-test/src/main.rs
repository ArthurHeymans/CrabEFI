//! A/B firmware update test: reports the trial and ESRT state on every boot
//! and plays the OS part of an update from marker files on its ESP.
//!
//! - `\AB\DELIVER`: request capsule-on-disk delivery (OsIndications bit 2).
//! - `\AB\CONFIRM`: confirm the firmware on trial (`CrabEFIFirmwareConfirm`).
//!
//! Each boot ends with `ABTEST DONE` and a cold reset; the host runs QEMU with
//! -no-reboot and places capsules and markers between boots.
//! Driven by `./crabefi test --app ab-update-test` on x86-64 payload MM QEMU.
#![no_std]
#![no_main]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::fmt::Write;
use core::panic::PanicInfo;
use core::ptr;
use r_efi::efi::{self, BootServices, Guid, Handle, RuntimeServices, Status, SystemTable};
use r_efi::protocols::{file, loaded_image, simple_file_system};

const GLOBAL: Guid = Guid::from_fields(
    0x8be4df61,
    0x93ca,
    0x11d2,
    0xaa,
    0x0d,
    &[0, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
);
const SETTINGS: Guid = Guid::from_fields(
    0x9e80634c,
    0xcdc7,
    0x41d5,
    0xa3,
    0x45,
    &[0x4a, 0x29, 0x7f, 0x9c, 0x7d, 0x1a],
);
const ESRT: Guid = Guid::from_fields(
    0xb122a263,
    0x3661,
    0x4f68,
    0x99,
    0x29,
    &[0x78, 0xf8, 0xb0, 0xd6, 0x21, 0x80],
);
/// FwClass of the system firmware ESRT entry (and capsule UpdateImageTypeId).
const FW_CLASS: Guid = Guid::from_fields(
    0x00112233,
    0x4455,
    0x6677,
    0x88,
    0x99,
    &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
);
const NV_BS_RT: u32 = 7;
const FILE_CAPSULE_DELIVERY: u64 = 0x4;
/// Info: shows the firmware's slot, trial and capsule decisions.
const LOG_LEVEL_INFO: u8 = 3;

#[repr(C)]
struct EsrtHeader {
    count: u32,
    count_max: u32,
    version: u64,
}

#[repr(C)]
struct EsrtEntry {
    fw_class: Guid,
    fw_type: u32,
    fw_version: u32,
    lowest_supported_fw_version: u32,
    capsule_flags: u32,
    last_attempt_version: u32,
    last_attempt_status: u32,
}

/// Encode the short variable names as NUL-terminated UTF-16.
fn name(text: &str) -> [u16; 32] {
    let mut out = [0; 32];
    for (dest, ch) in out.iter_mut().zip(text.encode_utf16()) {
        *dest = ch;
    }
    out
}

/// Read a variable of at most 8 bytes; returns its status, size and data.
fn get(rt: *mut RuntimeServices, guid: &Guid, key: &str) -> (Status, usize, [u8; 8]) {
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
    (status, len, data)
}

fn set(rt: *mut RuntimeServices, guid: &Guid, key: &str, attrs: u32, data: &[u8]) {
    let status = unsafe {
        ((*rt).set_variable)(
            name(key).as_ptr().cast_mut(),
            (guid as *const Guid).cast_mut(),
            attrs,
            data.len(),
            data.as_ptr().cast_mut().cast(),
        )
    };
    if status != Status::SUCCESS {
        let _ = writeln!(
            Serial,
            "ABTEST FAILED: SetVariable {key}: {:#x}\r",
            status.as_usize()
        );
        reset(rt);
    }
}

/// The ESRT entry of the system firmware, if the firmware installed one.
fn esrt_entry(system: &SystemTable) -> Option<&'static EsrtEntry> {
    let tables = unsafe {
        core::slice::from_raw_parts(system.configuration_table, system.number_of_table_entries)
    };
    let table = tables.iter().find(|table| table.vendor_guid == ESRT)?;
    let header = unsafe { &*table.vendor_table.cast::<EsrtHeader>() };
    let entries = unsafe {
        core::slice::from_raw_parts(
            table
                .vendor_table
                .cast::<u8>()
                .add(core::mem::size_of::<EsrtHeader>())
                .cast::<EsrtEntry>(),
            header.count as usize,
        )
    };
    entries.iter().find(|entry| entry.fw_class == FW_CLASS)
}

/// Whether `path` exists on the volume this app was loaded from.
fn marker(bs: &BootServices, image: Handle, path: &str) -> bool {
    let mut interface = ptr::null_mut();
    let mut guid = loaded_image::PROTOCOL_GUID;
    if unsafe { (bs.handle_protocol)(image, &mut guid, &mut interface) } != Status::SUCCESS {
        return false;
    }
    let device = unsafe { (*interface.cast::<loaded_image::Protocol>()).device_handle };
    let mut guid = simple_file_system::PROTOCOL_GUID;
    let mut interface = ptr::null_mut();
    if unsafe { (bs.handle_protocol)(device, &mut guid, &mut interface) } != Status::SUCCESS {
        return false;
    }
    let fs = interface.cast::<simple_file_system::Protocol>();
    let mut root = ptr::null_mut();
    if unsafe { ((*fs).open_volume)(fs, &mut root) } != Status::SUCCESS {
        return false;
    }
    let mut path16 = [0u16; 32];
    for (dest, ch) in path16.iter_mut().zip(path.encode_utf16()) {
        *dest = ch;
    }
    let mut handle = ptr::null_mut();
    let status =
        unsafe { ((*root).open)(root, &mut handle, path16.as_mut_ptr(), file::MODE_READ, 0) };
    if status == Status::SUCCESS {
        unsafe { ((*handle).close)(handle) };
    }
    unsafe { ((*root).close)(root) };
    status == Status::SUCCESS
}

/// Reset through firmware; the host runs every boot with -no-reboot.
fn reset(rt: *mut RuntimeServices) -> ! {
    unsafe { ((*rt).reset_system)(efi::RESET_COLD, Status::SUCCESS, 0, ptr::null_mut()) };
    serial("ABTEST FAILED: ResetSystem returned\r\n");
    exit()
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system: *mut SystemTable) -> Status {
    let st = unsafe { &*system };
    let rt = st.runtime_services;
    let bs = unsafe { &*st.boot_services };

    let (status, len, level) = get(rt, &SETTINGS, "CrabEFILogLevel");
    if status != Status::SUCCESS || len != 1 || level[0] != LOG_LEVEL_INFO {
        set(
            rt,
            &SETTINGS,
            "CrabEFILogLevel",
            NV_BS_RT,
            &[LOG_LEVEL_INFO],
        );
        serial("ABTEST LOGLEVEL info\r\n");
    }

    // Only its existence matters; the firmware stores one byte.
    let (status, _, _) = get(rt, &SETTINGS, "CrabEFIFirmwareTrialPending");
    let pending = status == Status::SUCCESS || status == Status::BUFFER_TOO_SMALL;
    let _ = writeln!(
        Serial,
        "ABTEST TRIAL {}\r",
        if pending { "pending" } else { "none" }
    );

    match esrt_entry(st) {
        Some(entry) => {
            let _ = writeln!(
                Serial,
                "ABTEST ESRT current={:#010x} lsv={:#010x} version={:#010x} status={}\r",
                entry.fw_version,
                entry.lowest_supported_fw_version,
                entry.last_attempt_version,
                entry.last_attempt_status
            );
        }
        None => serial("ABTEST ESRT missing\r\n"),
    }

    let (status, len, data) = get(rt, &GLOBAL, "OsIndications");
    let indications = if status == Status::SUCCESS && len == 8 {
        u64::from_le_bytes(data)
    } else {
        0
    };
    let _ = writeln!(Serial, "ABTEST OSINDICATIONS {indications:#x}\r");

    if marker(bs, image, "\\AB\\CONFIRM") {
        set(rt, &SETTINGS, "CrabEFIFirmwareConfirm", NV_BS_RT, &[1]);
        serial("ABTEST CONFIRM\r\n");
    }
    if marker(bs, image, "\\AB\\DELIVER") {
        let value = indications | FILE_CAPSULE_DELIVERY;
        set(rt, &GLOBAL, "OsIndications", NV_BS_RT, &value.to_le_bytes());
        serial("ABTEST DELIVER\r\n");
    }

    serial("ABTEST DONE\r\n");
    reset(rt)
}

/// `core::fmt` sink for QEMU's UART.
struct Serial;

impl Write for Serial {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        serial(text);
        Ok(())
    }
}

/// Log directly to QEMU's UART, interleaved with the firmware log.
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

/// Terminate QEMU through its debug-exit device.
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
    serial("ABTEST FAILED: panic\r\n");
    exit()
}

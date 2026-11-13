//! On-demand USB and the external boot policy, across cold boots that share
//! one variable store. The NVMe disk holds this app as the removable-media
//! default and an unloadable \EFI\POLICY\BROKEN.EFI; the USB disk holds it as
//! the default and as \EFI\POLICY\USB.EFI.
//! Driven by `./crabefi test --app boot-policy-test` on x86-64 QEMU.
#![no_std]
#![no_main]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use core::panic::PanicInfo;
use core::ptr;
use r_efi::efi::{self, BootServices, Guid, Handle, RuntimeServices, Status, SystemTable};
use r_efi::protocols::{device_path, loaded_image};

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
const SHIM_LOCK: Guid = Guid::from_fields(
    0x605dab50,
    0xe046,
    0x4300,
    0xab,
    0xb6,
    &[0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23],
);
const TEST: Guid = Guid::from_fields(0x0b9d1c3e, 0x5a2f, 0x4e61, 0x9c, 0x4d, &[1, 2, 3, 4, 5, 6]);
/// Installed only for USB mass storage.
const EXT_SCSI_PASS_THRU: Guid = Guid::from_fields(
    0x143b7632,
    0xb81b,
    0x4cb7,
    0xab,
    0xd3,
    &[0xb6, 0x25, 0xa5, 0xb9, 0xbf, 0xfe],
);
const NV_BS: u32 = 3;
const NV_BS_RT: u32 = 7;

/// Encode the short variable names as NUL-terminated UTF-16.
fn name(text: &str) -> [u16; 32] {
    let mut out = [0; 32];
    for (dest, ch) in out.iter_mut().zip(text.encode_utf16()) {
        *dest = ch;
    }
    out
}

fn get(rt: *mut RuntimeServices, guid: &Guid, key: &str) -> Option<[u8; 8]> {
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
    (status == Status::SUCCESS).then_some(data)
}

fn try_set(rt: *mut RuntimeServices, guid: &Guid, key: &str, attrs: u32, data: &[u8]) -> Status {
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

fn set(rt: *mut RuntimeServices, guid: &Guid, key: &str, attrs: u32, data: &[u8]) {
    check(
        try_set(rt, guid, key, attrs, data) == Status::SUCCESS,
        "SetVariable",
    );
}

/// Write an active Boot#### option with a file-only device path.
fn set_boot_option(rt: *mut RuntimeServices, key: &str, path: &str) {
    let mut option = [0u8; 256];
    option[..4].copy_from_slice(&1u32.to_le_bytes()); // LOAD_OPTION_ACTIVE
    let mut pos = 6;
    for ch in "Boot policy test\0".encode_utf16() {
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
    set(rt, &GLOBAL, key, NV_BS_RT, &option[..pos]);
}

fn set_boot_order(rt: *mut RuntimeServices, options: &[u16]) {
    let mut order = [0u8; 8];
    for (chunk, option) in order.chunks_exact_mut(2).zip(options) {
        chunk.copy_from_slice(&option.to_le_bytes());
    }
    set(
        rt,
        &GLOBAL,
        "BootOrder",
        NV_BS_RT,
        &order[..options.len() * 2],
    );
}

#[derive(PartialEq)]
enum Media {
    Nvme,
    Usb,
    Other,
}

/// Classify the disk this image was loaded from by its messaging node.
fn boot_media(bs: &BootServices, image: Handle) -> Media {
    let mut interface = ptr::null_mut();
    let mut guid = loaded_image::PROTOCOL_GUID;
    if unsafe { (bs.handle_protocol)(image, &mut guid, &mut interface) } != Status::SUCCESS {
        return Media::Other;
    }
    let device = unsafe { (*interface.cast::<loaded_image::Protocol>()).device_handle };
    let mut guid = device_path::PROTOCOL_GUID;
    let mut interface = ptr::null_mut();
    if unsafe { (bs.handle_protocol)(device, &mut guid, &mut interface) } != Status::SUCCESS {
        return Media::Other;
    }
    let mut node = interface.cast::<u8>().cast_const();
    for _ in 0..32 {
        let (kind, subtype, len) = unsafe {
            (
                *node,
                *node.add(1),
                u16::from_le_bytes([*node.add(2), *node.add(3)]),
            )
        };
        match (kind, subtype) {
            (0x7f, 0xff) => break,
            (3, 0x17) => return Media::Nvme,
            (3, 0x05) => return Media::Usb,
            _ => {}
        }
        if len < 4 {
            break;
        }
        node = unsafe { node.add(usize::from(len)) };
    }
    Media::Other
}

/// Whether any USB mass-storage pass-through handle exists.
fn usb_storage_initialized(bs: &BootServices) -> bool {
    let mut count = 0;
    let mut handles = ptr::null_mut();
    let mut guid = EXT_SCSI_PASS_THRU;
    let status = unsafe {
        (bs.locate_handle_buffer)(
            efi::BY_PROTOCOL,
            &mut guid,
            ptr::null_mut(),
            &mut count,
            &mut handles,
        )
    };
    if status == Status::SUCCESS {
        unsafe { (bs.free_pool)(handles.cast()) };
    }
    status == Status::SUCCESS && count != 0
}

/// Report an assertion failure to the host and terminate the guest.
fn check(ok: bool, message: &str) {
    if !ok {
        serial("BPOL TEST FAILED: ");
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

/// Reset through firmware; the host runs every boot with -no-reboot.
fn reset(rt: *mut RuntimeServices) -> ! {
    unsafe { ((*rt).reset_system)(efi::RESET_COLD, Status::SUCCESS, 0, ptr::null_mut()) };
    check(false, "ResetSystem returned");
    exit()
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system: *mut SystemTable) -> Status {
    let rt = unsafe { (*system).runtime_services };
    let bs = unsafe { &*(*system).boot_services };
    let media = boot_media(bs, image);
    let usb = usb_storage_initialized(bs);
    let phase = get(rt, &TEST, "BootPolicyTestPhase").map_or(0, |data| data[0]);
    match phase {
        // Fresh store: the removable-media default path started us.
        0 => {
            check(
                media == Media::Nvme,
                "fallback did not start the NVMe default",
            );
            check(usb, "USB mass storage missing after the fallback menu");
            // Info level shows the firmware's USB and policy decisions.
            set(rt, &SETTINGS, "CrabEFILogLevel", NV_BS_RT, &[3]);
            set_boot_option(rt, "Boot0001", "\\EFI\\BOOT\\BOOTX64.EFI");
            set_boot_order(rt, &[1]);
            set(rt, &GLOBAL, "Timeout", NV_BS_RT, &1u16.to_le_bytes());
            set(rt, &TEST, "BootPolicyTestPhase", NV_BS_RT, &[1]);
            serial("BPOL FALLBACK PASSED\r\n");
            reset(rt);
        }
        1 => {
            check(media == Media::Nvme, "BootOrder did not start from NVMe");
            check(!usb, "USB mass storage was initialized for an NVMe boot");
            // BROKEN.EFI is on NVMe but does not load; USB.EFI is on USB only.
            set_boot_option(rt, "Boot0002", "\\EFI\\POLICY\\BROKEN.EFI");
            set_boot_option(rt, "Boot0003", "\\EFI\\POLICY\\USB.EFI");
            set_boot_order(rt, &[2, 3]);
            set(rt, &TEST, "BootPolicyTestPhase", NV_BS_RT, &[2]);
            serial("BPOL INTERNAL PASSED\r\n");
            reset(rt);
        }
        2 => {
            check(
                media == Media::Usb,
                "failed internal boot did not fall back to USB",
            );
            check(usb, "USB mass storage missing after the USB fallback");
            set(rt, &SETTINGS, "CrabEFIExternalBoot", NV_BS, &[2]);
            set(rt, &TEST, "BootPolicyTestPhase", NV_BS_RT, &[3]);
            serial("BPOL USB FALLBACK PASSED\r\n");
            reset(rt);
        }
        // Deny: Boot0003 is refused and the menu only offers NVMe.
        3 => {
            check(media == Media::Nvme, "Deny policy booted external media");
            set(rt, &SETTINGS, "CrabEFIExternalBoot", NV_BS, &[1]);
            // A pending MokManager request needs USB before automatic boot.
            set(rt, &SHIM_LOCK, "MokSB", NV_BS_RT, &[0]);
            set(rt, &TEST, "BootPolicyTestPhase", NV_BS_RT, &[4]);
            serial("BPOL DENY PASSED\r\n");
            reset(rt);
        }
        // MenuOnly: USB is up for MokManager, Boot0003 on USB is refused and
        // the menu times out into NVMe.
        4 => {
            check(
                media == Media::Nvme,
                "MenuOnly policy booted external media",
            );
            exit_boot_services(image, bs);
            check(
                try_set(rt, &SETTINGS, "CrabEFIExternalBoot", NV_BS_RT, &[0]) != Status::SUCCESS,
                "OS loosened the policy",
            );
            check(
                try_set(rt, &SETTINGS, "CrabEFIExternalBoot", 0, &[]) != Status::SUCCESS,
                "OS deleted the policy",
            );
            serial("BPOL MENU ONLY PASSED\r\nBPOL TEST PASSED\r\n");
            exit();
        }
        _ => check(false, "unexpected phase"),
    }
    Status::SUCCESS
}

/// Log directly to QEMU's UART, including after ExitBootServices.
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
    serial("BPOL TEST FAILED: panic\r\n");
    exit()
}

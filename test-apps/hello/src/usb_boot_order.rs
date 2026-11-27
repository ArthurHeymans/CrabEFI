//! Seed a USB-first BootOrder from the NVMe disk in the hotplug fixture.
use core::ptr;
use r_efi::efi::{self, Guid, Handle, Status, SystemTable};
use r_efi::protocols::{device_path, loaded_image};

const GLOBAL: Guid = Guid::from_fields(
    0x8be4df61,
    0x93ca,
    0x11d2,
    0xaa,
    0x0d,
    &[0, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
);

fn name(key: &str) -> [u16; 16] {
    let mut name = [0; 16];
    for (slot, ch) in name.iter_mut().zip(key.encode_utf16()) {
        *slot = ch;
    }
    name
}

fn file_option(path: &str) -> ([u8; 160], usize) {
    let mut option = [0; 160];
    option[..4].copy_from_slice(&1u32.to_le_bytes()); // Active.
    let mut pos = 6;
    for ch in "Cold USB fixture\0".encode_utf16() {
        option[pos..pos + 2].copy_from_slice(&ch.to_le_bytes());
        pos += 2;
    }
    let node_len = 4 + 2 * (path.encode_utf16().count() + 1);
    option[4..6].copy_from_slice(&((node_len + 4) as u16).to_le_bytes());
    option[pos..pos + 4].copy_from_slice(&[4, 4, node_len as u8, 0]);
    pos += 4;
    for ch in path.encode_utf16().chain(core::iter::once(0)) {
        option[pos..pos + 2].copy_from_slice(&ch.to_le_bytes());
        pos += 2;
    }
    option[pos..pos + 4].copy_from_slice(&[0x7f, 0xff, 4, 0]);
    (option, pos + 4)
}

fn loaded_from_nvme(table: *mut SystemTable, image: Handle) -> bool {
    let bs = unsafe { &*(*table).boot_services };
    let mut interface = ptr::null_mut();
    let mut guid = loaded_image::PROTOCOL_GUID;
    if unsafe { (bs.handle_protocol)(image, &mut guid, &mut interface) } != Status::SUCCESS {
        return false;
    }
    let device = unsafe { (*interface.cast::<loaded_image::Protocol>()).device_handle };
    let mut guid = device_path::PROTOCOL_GUID;
    if unsafe { (bs.handle_protocol)(device, &mut guid, &mut interface) } != Status::SUCCESS {
        return false;
    }
    let mut node = interface.cast::<u8>().cast_const();
    for _ in 0..32 {
        let header = unsafe { core::slice::from_raw_parts(node, 4) };
        match (header[0], header[1]) {
            (3, 0x17) => return true,
            (0x7f, _) => return false,
            _ => {}
        }
        let len = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if len < 4 {
            return false;
        }
        node = unsafe { node.add(len) };
    }
    false
}

pub fn seed_if_nvme(table: *mut SystemTable, image: Handle) -> Result<(), Status> {
    if !loaded_from_nvme(table, image) {
        return Ok(());
    }
    let rt = unsafe { &*(*table).runtime_services };
    let mut guid = GLOBAL;
    let mut order = [0; 4];
    let mut len = order.len();
    let status = unsafe {
        (rt.get_variable)(
            name("BootOrder").as_mut_ptr(),
            &mut guid,
            ptr::null_mut(),
            &mut len,
            order.as_mut_ptr().cast(),
        )
    };
    if status != Status::NOT_FOUND {
        super::print_line(table, "USB BOOT ORDER: NVMe fallback reached\r\n");
        return Err(Status::ABORTED);
    }
    let (usb, usb_len) = file_option("\\EFI\\POLICY\\USB.EFI");
    let (fallback, fallback_len) = file_option("\\EFI\\BOOT\\BOOTX64.EFI");
    for (key, data) in [
        ("Boot0000", &usb[..usb_len]),
        ("Boot0001", &fallback[..fallback_len]),
        ("BootOrder", &[0, 0, 1, 0]),
    ] {
        let status = unsafe {
            (rt.set_variable)(
                name(key).as_mut_ptr(),
                &mut guid,
                7,
                data.len(),
                data.as_ptr().cast_mut().cast(),
            )
        };
        if status != Status::SUCCESS {
            super::print_line(table, "USB BOOT ORDER: seed failed\r\n");
            return Err(status);
        }
    }
    super::print_line(table, "USB BOOT ORDER: seed installed\r\n");
    unsafe { (rt.reset_system)(efi::RESET_COLD, Status::SUCCESS, 0, ptr::null_mut()) };
    Err(Status::ABORTED)
}

//! Reload this application from the same disk as a child and grandchild.
//! Each child exits from a helper; its parent checks status, copied UTF-16 data,
//! and removal of the child's Loaded Image protocol before continuing.

#![no_std]
#![no_main]

use core::{ffi::c_void, panic::PanicInfo, ptr};

use r_efi::efi::{self, BootServices, Handle, Status, SystemTable};
use r_efi::protocols::{device_path, loaded_image};

const OUTER: &[u16] = &[111, 117, 116, 101, 114, 32, 101, 120, 105, 116, 0];
const INNER: &[u16] = &[105, 110, 110, 101, 114, 32, 101, 120, 105, 116, 0];
const WARNING: &[u16] = &[119, 97, 114, 110, 105, 110, 103, 0];

fn print(st: *mut SystemTable, text: &str) {
    let mut message = [0u16; 160];
    for (out, byte) in message.iter_mut().zip(text.bytes()) {
        *out = u16::from(byte);
    }
    // SAFETY: firmware supplies the system table; this terminated stack buffer
    // remains live for the synchronous console call.
    unsafe {
        let console = (*st).con_out;
        if !console.is_null() {
            ((*console).output_string)(console, message.as_mut_ptr());
        }
    }
}

fn fail(st: *mut SystemTable, reason: &str) -> Status {
    print(st, "[FAIL] image_exit: ");
    print(st, reason);
    print(st, "\r\n");
    Status::ABORTED
}

fn loaded(bs: &BootServices, handle: Handle) -> Result<*mut loaded_image::Protocol, Status> {
    let mut interface = ptr::null_mut();
    let mut guid = loaded_image::PROTOCOL_GUID;
    let status = (bs.handle_protocol)(handle, &mut guid, &mut interface);
    if status != Status::SUCCESS || interface.is_null() {
        Err(Status::NOT_FOUND)
    } else {
        Ok(interface.cast())
    }
}

/// Size of a firmware-owned device path, including its end node.
unsafe fn path_size(path: *const device_path::Protocol) -> Option<usize> {
    if path.is_null() {
        return None;
    }
    let mut offset = 0;
    while offset <= 4092 {
        // SAFETY: callers provide protocol-owned valid device paths. Bound the
        // destination size and reject malformed node lengths before copying.
        let node = unsafe {
            &*path
                .cast::<u8>()
                .add(offset)
                .cast::<device_path::Protocol>()
        };
        let length = usize::from(u16::from_le_bytes(node.length));
        if length < 4 || offset + length > 4096 {
            return None;
        }
        offset += length;
        if node.r#type == 0x7f && node.sub_type == 0xff {
            return (length == 4).then_some(offset);
        }
    }
    None
}

#[repr(C, align(8))]
struct PathBuffer([u8; 8192]);

/// Build an absolute path to this image using its own boot device, not whichever
/// filesystem happens to be enumerated first.
fn self_path(bs: &BootServices, image: &loaded_image::Protocol) -> Option<PathBuffer> {
    let path = image.file_path;
    // SAFETY: file_path is owned by the installed Loaded Image protocol.
    let file_size = unsafe { path_size(path) }?;
    let mut result = PathBuffer([0; 8192]);
    // A file-only path needs the device handle's path prepended. CrabEFI also
    // supplies complete paths, which must not have their device prefix doubled.
    let file_only = unsafe { (*path).r#type == 4 && (*path).sub_type == 4 };
    let prefix = if file_only {
        let mut device: *mut c_void = ptr::null_mut();
        let mut guid = device_path::PROTOCOL_GUID;
        if (bs.handle_protocol)(image.device_handle, &mut guid, &mut device) != Status::SUCCESS {
            return None;
        }
        let prefix = unsafe { path_size(device.cast()) }?.checked_sub(4)?;
        unsafe { ptr::copy_nonoverlapping(device.cast::<u8>(), result.0.as_mut_ptr(), prefix) };
        prefix
    } else {
        0
    };
    unsafe {
        ptr::copy_nonoverlapping(
            path.cast::<u8>(),
            result.0.as_mut_ptr().add(prefix),
            file_size,
        )
    };
    Some(result)
}

fn run_child(handle: Handle, st: *mut SystemTable, depth: u32) -> Result<(), &'static str> {
    let bs = unsafe { &*(*st).boot_services };
    let image = loaded(bs, handle).map_err(|_| "parent protocol missing")?;
    let mut path = self_path(bs, unsafe { &*image }).ok_or("self path unavailable")?;
    let mut child = ptr::null_mut();
    let status = (bs.load_image)(
        efi::Boolean::FALSE,
        handle,
        path.0.as_mut_ptr().cast(),
        ptr::null_mut(),
        0,
        &mut child,
    );
    if status != Status::SUCCESS || child.is_null() {
        return Err("LoadImage from disk failed");
    }
    let child_protocol = match loaded(bs, child) {
        Ok(protocol) => protocol,
        Err(_) => {
            (bs.unload_image)(child);
            return Err("child protocol missing before StartImage");
        }
    };
    // The load-option storage and full path live until StartImage finishes.
    unsafe {
        (*child_protocol).load_options = ptr::from_ref(&depth).cast_mut().cast();
        (*child_protocol).load_options_size = size_of::<u32>() as u32;
    }
    let mut size = 0usize;
    let mut data = ptr::null_mut();
    let status = (bs.start_image)(child, &mut size, &mut data);
    let (expected_status, expected_data) = expected(depth);
    let correct = status == expected_status
        && size == size_of_val(expected_data)
        && !data.is_null()
        && unsafe { core::slice::from_raw_parts(data, expected_data.len()) == expected_data };
    // FreePool is the caller's responsibility, even when assertions fail.
    let free_status = if data.is_null() {
        Status::SUCCESS
    } else {
        (bs.free_pool)(data.cast())
    };
    if !correct {
        return Err("StartImage status or UTF16 exit data mismatch");
    }
    if free_status != Status::SUCCESS {
        return Err("exit data FreePool failed");
    }
    let mut stale = ptr::null_mut();
    let mut guid = loaded_image::PROTOCOL_GUID;
    if (bs.handle_protocol)(child, &mut guid, &mut stale) == Status::SUCCESS {
        return Err("unloaded child protocol remains accessible");
    }
    Ok(())
}

fn expected(depth: u32) -> (Status, &'static [u16]) {
    match depth {
        1 => (Status::ABORTED, OUTER),
        2 => (Status::ACCESS_DENIED, INNER),
        _ => (Status::WARN_UNKNOWN_GLYPH, WARNING),
    }
}

// Force a real helper call. The code after Exit is a failure, never a success
// return path: an implementation that merely returns the requested status fails.
#[inline(never)]
fn exit_from_helper(handle: Handle, st: *mut SystemTable, depth: u32) -> Status {
    let (status, data) = expected(depth);
    let bs = unsafe { &*(*st).boot_services };
    (bs.exit)(handle, status, size_of_val(data), data.as_ptr().cast_mut());
    fail(st, "Exit returned to its helper")
}

/// EFI entry point.
///
/// # Arguments
/// Firmware supplies the image handle and system table.
/// # Returns
/// SUCCESS only after all parent-side assertions pass; children use Exit.
/// # Safety
/// The firmware must provide a valid system table and installed image handle.
#[unsafe(no_mangle)]
pub unsafe extern "efiapi" fn efi_main(handle: Handle, st: *mut SystemTable) -> Status {
    let bs = unsafe { &*(*st).boot_services };
    let image = match loaded(bs, handle) {
        Ok(image) => image,
        Err(_) => return fail(st, "entry protocol missing"),
    };
    let depth = unsafe {
        if (*image).load_options_size == size_of::<u32>() as u32 && !(*image).load_options.is_null()
        {
            ptr::read_unaligned((*image).load_options.cast::<u32>())
        } else {
            0
        }
    };
    if depth == 0 {
        for child in [1, 3] {
            if let Err(reason) = run_child(handle, st, child) {
                return fail(st, reason);
            }
        }
        print(st, "All image exit tests passed!\r\n");
        Status::SUCCESS
    } else {
        if depth == 1
            && let Err(reason) = run_child(handle, st, 2)
        {
            return fail(st, reason);
        }
        exit_from_helper(handle, st, depth)
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

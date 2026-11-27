//! Minimal EFI test application
//!
//! This application prints a message to the console and returns.
//! Used to test CrabEFI's ability to load and execute EFI applications.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use r_efi::efi::{Char16, Handle, Status, SystemTable};

/// EFI entry point
#[no_mangle]
pub extern "efiapi" fn efi_main(_image_handle: Handle, system_table: *mut SystemTable) -> Status {
    // Get console output protocol
    let con_out = unsafe { (*system_table).con_out };
    if con_out.is_null() {
        return Status::UNSUPPORTED;
    }

    // Print hello message
    let msg: &[Char16] = &[
        'H' as Char16,
        'e' as Char16,
        'l' as Char16,
        'l' as Char16,
        'o' as Char16,
        ' ' as Char16,
        'f' as Char16,
        'r' as Char16,
        'o' as Char16,
        'm' as Char16,
        ' ' as Char16,
        'C' as Char16,
        'r' as Char16,
        'a' as Char16,
        'b' as Char16,
        'E' as Char16,
        'F' as Char16,
        'I' as Char16,
        '!' as Char16,
        '\r' as Char16,
        '\n' as Char16,
        0, // Null terminator
    ];

    unsafe {
        let output_string = (*con_out).output_string;
        output_string(con_out, msg.as_ptr() as *mut Char16);
    }

    #[cfg(feature = "hotplug-input")]
    if let Err(status) = wait_for_hotplug_key(system_table) {
        return status;
    }

    // Print success message
    let success_msg: &[Char16] = &[
        'E' as Char16,
        'F' as Char16,
        'I' as Char16,
        ' ' as Char16,
        'a' as Char16,
        'p' as Char16,
        'p' as Char16,
        ' ' as Char16,
        'e' as Char16,
        'x' as Char16,
        'e' as Char16,
        'c' as Char16,
        'u' as Char16,
        't' as Char16,
        'e' as Char16,
        'd' as Char16,
        ' ' as Char16,
        's' as Char16,
        'u' as Char16,
        'c' as Char16,
        'c' as Char16,
        'e' as Char16,
        's' as Char16,
        's' as Char16,
        'f' as Char16,
        'u' as Char16,
        'l' as Char16,
        'l' as Char16,
        'y' as Char16,
        '!' as Char16,
        '\r' as Char16,
        '\n' as Char16,
        0,
    ];

    unsafe {
        let output_string = (*con_out).output_string;
        output_string(con_out, success_msg.as_ptr() as *mut Char16);
    }

    Status::SUCCESS
}

#[cfg(feature = "hotplug-input")]
fn wait_for_hotplug_key(system_table: *mut SystemTable) -> Result<(), Status> {
    use r_efi::protocols::simple_text_input::InputKey;

    let (input, output, boot_services) = unsafe {
        (
            (*system_table).con_in,
            (*system_table).con_out,
            (*system_table).boot_services,
        )
    };
    if input.is_null() || boot_services.is_null() {
        return Err(Status::UNSUPPORTED);
    }
    let print = |line: &str| {
        let mut chars = [0; 64];
        for (out, unit) in chars.iter_mut().zip(line.encode_utf16()) {
            *out = unit;
        }
        unsafe { ((*output).output_string)(output, chars.as_mut_ptr()) };
    };
    print("USB HOTPLUG: waiting for keyboard\r\n");
    let (mut event, mut index) = (unsafe { (*input).wait_for_key }, 0);
    loop {
        let status = unsafe { ((*boot_services).wait_for_event)(1, &mut event, &mut index) };
        if status != Status::SUCCESS {
            return Err(status);
        }
        let mut key = InputKey::default();
        if unsafe { ((*input).read_key_stroke)(input, &mut key) } == Status::SUCCESS
            && key.unicode_char == u16::from(b'h')
        {
            print("USB HOTPLUG: received h\r\n");
            return Ok(());
        }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

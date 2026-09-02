//! EFI RegisterProtocolNotify Test Application
//!
//! Exercises the notify registration path end to end:
//! 1. RegisterProtocolNotify with a private GUID returns a registration token
//! 2. LocateHandle(ByRegisterNotify) reports NOT_FOUND before any install
//! 3. InstallProtocolInterface signals the registered event
//! 4. LocateHandle(ByRegisterNotify) yields the new handle exactly once
//! 5. LocateHandleBuffer(ByRegisterNotify) survives its two-pass size/fill
//!    sequence, which a destructive peek would break
//! 6. An unknown registration token is rejected
//! 7. CloseEvent drops the registration

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;

use r_efi::efi::{Char16, Guid, Handle, Status, SystemTable};
use r_efi::protocols::simple_text_output::Protocol as SimpleTextOutput;

/// Private protocol GUID used only by this test {6F1E2B44-9C3A-4D7E-B1F0-2A5C8D3E7401}
const TEST_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x6f1e2b44,
    0x9c3a,
    0x4d7e,
    0xb1,
    0xf0,
    &[0x2a, 0x5c, 0x8d, 0x3e, 0x74, 0x01],
);

/// Second private GUID, used to prove registrations are GUID-scoped.
const OTHER_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x6f1e2b44,
    0x9c3a,
    0x4d7e,
    0xb1,
    0xf0,
    &[0x2a, 0x5c, 0x8d, 0x3e, 0x74, 0x02],
);

static mut SYSTEM_TABLE: *mut SystemTable = core::ptr::null_mut();
static mut CON_OUT: *mut SimpleTextOutput = core::ptr::null_mut();

/// Dummy interface body. Only its address matters to the handle database.
static mut TEST_INTERFACE: u64 = 0xA5A5_A5A5_A5A5_A5A5;

#[no_mangle]
pub extern "efiapi" fn efi_main(_image_handle: Handle, system_table: *mut SystemTable) -> Status {
    unsafe {
        SYSTEM_TABLE = system_table;
        CON_OUT = (*system_table).con_out;
    }

    print_line("=== RegisterProtocolNotify Test ===");
    print_line("");

    let mut passed = 0u32;
    let mut failed = 0u32;

    let bs = unsafe { (*SYSTEM_TABLE).boot_services };
    if bs.is_null() {
        print_line("[FAIL] boot_services: BootServices table is NULL");
        print_summary(1, 0);
        return Status::SUCCESS;
    }

    // Test 1: create an event and register it against our private GUID.
    print("  [1] RegisterProtocolNotify... ");
    let mut event: r_efi::efi::Event = core::ptr::null_mut();
    let status = unsafe {
        ((*bs).create_event)(
            r_efi::efi::EVT_NOTIFY_SIGNAL,
            r_efi::efi::TPL_CALLBACK,
            Some(notify_callback),
            core::ptr::null_mut(),
            &mut event,
        )
    };
    if status != Status::SUCCESS {
        print_line("[FAIL] register_notify: CreateEvent failed");
        print_summary(passed, failed + 1);
        return Status::SUCCESS;
    }

    let mut registration: *mut c_void = core::ptr::null_mut();
    let mut guid = TEST_PROTOCOL_GUID;
    let status =
        unsafe { ((*bs).register_protocol_notify)(&mut guid, event, &mut registration) };
    if status == Status::SUCCESS {
        print_line("[PASS] register_notify: registration created");
        passed += 1;
    } else {
        print_line("[FAIL] register_notify: RegisterProtocolNotify failed");
        print_summary(passed, failed + 1);
        return Status::SUCCESS;
    }

    // Test 2: nothing installed yet, so the queue must be empty.
    print("  [2] Empty queue... ");
    if locate_by_notify(bs, registration).is_none() {
        print_line("[PASS] empty_queue: NOT_FOUND before any install");
        passed += 1;
    } else {
        print_line("[FAIL] empty_queue: reported a handle before any install");
        failed += 1;
    }

    // Test 3: installing a matching interface signals the event.
    print("  [3] Install signals event... ");
    let mut handle: Handle = core::ptr::null_mut();
    let mut guid = TEST_PROTOCOL_GUID;
    let status = unsafe {
        ((*bs).install_protocol_interface)(
            &mut handle,
            &mut guid,
            r_efi::efi::NATIVE_INTERFACE,
            &raw mut TEST_INTERFACE as *mut c_void,
        )
    };
    if status != Status::SUCCESS || handle.is_null() {
        print_line("[FAIL] install_signals: InstallProtocolInterface failed");
        print_summary(passed, failed + 1);
        return Status::SUCCESS;
    }
    if unsafe { NOTIFY_FIRED } {
        print_line("[PASS] install_signals: notify callback ran");
        passed += 1;
    } else {
        print_line("[FAIL] install_signals: notify callback did not run");
        failed += 1;
    }

    // Test 4: the new handle is delivered exactly once.
    print("  [4] Drain once... ");
    let first = locate_by_notify(bs, registration);
    let second = locate_by_notify(bs, registration);
    if first == Some(handle) && second.is_none() {
        print_line("[PASS] drain_once: handle delivered exactly once");
        passed += 1;
    } else if first != Some(handle) {
        print_line("[FAIL] drain_once: wrong handle reported");
        failed += 1;
    } else {
        print_line("[FAIL] drain_once: handle delivered more than once");
        failed += 1;
    }

    // Test 5: LocateHandleBuffer runs LocateHandle twice (size, then fill), so a
    // queue that popped during sizing would lose the handle before delivery.
    print("  [5] LocateHandleBuffer... ");
    let mut second_handle: Handle = core::ptr::null_mut();
    let mut guid = TEST_PROTOCOL_GUID;
    let installed = unsafe {
        ((*bs).install_protocol_interface)(
            &mut second_handle,
            &mut guid,
            r_efi::efi::NATIVE_INTERFACE,
            &raw mut TEST_INTERFACE as *mut c_void,
        )
    };
    if installed == Status::SUCCESS {
        let mut count: usize = 0;
        let mut buffer: *mut Handle = core::ptr::null_mut();
        let status = unsafe {
            ((*bs).locate_handle_buffer)(
                r_efi::efi::BY_REGISTER_NOTIFY,
                core::ptr::null_mut(),
                registration,
                &mut count,
                &mut buffer,
            )
        };
        if status == Status::SUCCESS && count == 1 && !buffer.is_null() {
            let reported = unsafe { *buffer };
            unsafe { ((*bs).free_pool)(buffer as *mut c_void) };
            if reported == second_handle {
                print_line("[PASS] locate_handle_buffer: two-pass lookup delivered handle");
                passed += 1;
            } else {
                print_line("[FAIL] locate_handle_buffer: wrong handle reported");
                failed += 1;
            }
        } else {
            print_line("[FAIL] locate_handle_buffer: lookup failed");
            failed += 1;
        }
    } else {
        print_line("[FAIL] locate_handle_buffer: setup install failed");
        failed += 1;
    }

    // Test 6: a registration only fires for its own GUID.
    print("  [6] GUID scoping... ");
    let mut unrelated_handle: Handle = core::ptr::null_mut();
    let mut other = OTHER_PROTOCOL_GUID;
    let installed = unsafe {
        ((*bs).install_protocol_interface)(
            &mut unrelated_handle,
            &mut other,
            r_efi::efi::NATIVE_INTERFACE,
            &raw mut TEST_INTERFACE as *mut c_void,
        )
    };
    if installed != Status::SUCCESS {
        print_line("[FAIL] guid_scoping: setup install failed");
        failed += 1;
    } else if locate_by_notify(bs, registration).is_none() {
        print_line("[PASS] guid_scoping: unrelated GUID did not enqueue");
        passed += 1;
    } else {
        print_line("[FAIL] guid_scoping: unrelated GUID enqueued a handle");
        failed += 1;
    }

    // Test 7: a registration token we never handed out must be rejected, not
    // silently treated as an empty queue.
    print("  [7] Unknown registration... ");
    let mut size: usize = 0;
    let status = unsafe {
        ((*bs).locate_handle)(
            r_efi::efi::BY_REGISTER_NOTIFY,
            core::ptr::null_mut(),
            0xDEAD_BEEF_usize as *mut c_void,
            &mut size,
            core::ptr::null_mut(),
        )
    };
    if status == Status::INVALID_PARAMETER {
        print_line("[PASS] unknown_registration: rejected");
        passed += 1;
    } else {
        print_line("[FAIL] unknown_registration: not rejected");
        failed += 1;
    }

    // Test 8: closing the event must retire the registration with it.
    print("  [8] CloseEvent retires registration... ");
    unsafe { ((*bs).close_event)(event) };
    let mut size: usize = 0;
    let status = unsafe {
        ((*bs).locate_handle)(
            r_efi::efi::BY_REGISTER_NOTIFY,
            core::ptr::null_mut(),
            registration,
            &mut size,
            core::ptr::null_mut(),
        )
    };
    if status == Status::INVALID_PARAMETER {
        print_line("[PASS] close_event: registration retired");
        passed += 1;
    } else {
        print_line("[FAIL] close_event: registration still live");
        failed += 1;
    }

    print_summary(passed, failed);
    Status::SUCCESS
}

static mut NOTIFY_FIRED: bool = false;

extern "efiapi" fn notify_callback(_event: r_efi::efi::Event, _context: *mut c_void) {
    unsafe { NOTIFY_FIRED = true };
}

/// Fetch one handle from a notify registration.
///
/// # Arguments
/// * `bs` - Boot Services table.
/// * `registration` - Token from RegisterProtocolNotify.
///
/// # Returns
/// The next queued handle, or `None` when the queue is empty.
fn locate_by_notify(bs: *mut r_efi::efi::BootServices, registration: *mut c_void) -> Option<Handle> {
    let mut handle: Handle = core::ptr::null_mut();
    let mut size = core::mem::size_of::<Handle>();
    let status = unsafe {
        ((*bs).locate_handle)(
            r_efi::efi::BY_REGISTER_NOTIFY,
            core::ptr::null_mut(),
            registration,
            &mut size,
            &mut handle,
        )
    };
    (status == Status::SUCCESS).then_some(handle)
}

fn print(s: &str) {
    let con_out = unsafe { CON_OUT };
    if con_out.is_null() {
        return;
    }

    let mut buffer: [Char16; 128] = [0; 128];
    let mut idx = 0;

    for c in s.chars() {
        if c == '\n' {
            buffer[idx] = '\r' as Char16;
            idx += 1;
            if idx >= buffer.len() - 2 {
                buffer[idx] = 0;
                output_buffer(con_out, &buffer);
                idx = 0;
            }
        }
        buffer[idx] = if (c as u32) <= 0xFFFF {
            c as Char16
        } else {
            '?' as Char16
        };
        idx += 1;
        if idx >= buffer.len() - 2 {
            buffer[idx] = 0;
            output_buffer(con_out, &buffer);
            idx = 0;
        }
    }

    if idx > 0 {
        buffer[idx] = 0;
        output_buffer(con_out, &buffer);
    }
}

fn print_line(s: &str) {
    print(s);
    print("\r\n");
}

fn print_dec(value: u64) {
    let mut buf = [0u8; 20];
    let mut idx = 20;
    let mut v = value;
    if v == 0 {
        print("0");
        return;
    }
    while v > 0 {
        idx -= 1;
        buf[idx] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    // Safe: buf[idx..20] contains only ASCII digits
    let s = unsafe { core::str::from_utf8_unchecked(&buf[idx..20]) };
    print(s);
}

fn print_summary(passed: u32, failed: u32) {
    print("Results: ");
    print_dec(passed as u64);
    print(" passed, ");
    print_dec(failed as u64);
    print_line(" failed");
    print_line("");
    if failed == 0 {
        print_line("All protocol notify tests passed!");
    } else {
        print_line("Some protocol notify tests FAILED!");
    }
}

fn output_buffer(con_out: *mut SimpleTextOutput, buffer: &[Char16]) {
    unsafe {
        ((*con_out).output_string)(con_out, buffer.as_ptr() as *mut Char16);
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

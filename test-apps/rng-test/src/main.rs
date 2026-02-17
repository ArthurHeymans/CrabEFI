//! EFI RNG Protocol Test Application
//!
//! Tests the EFI_RNG_PROTOCOL by:
//! 1. Locating the protocol via LocateProtocol
//! 2. Calling GetInfo to enumerate algorithms
//! 3. Calling GetRNG to generate random bytes
//! 4. Verifying output is not all zeros or all identical
//! 5. Calling GetRNG multiple times and checking for variation

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;

use r_efi::efi::{Char16, Guid, Handle, Status, SystemTable};
use r_efi::protocols::simple_text_output::Protocol as SimpleTextOutput;

/// EFI_RNG_PROTOCOL GUID {3152BCA5-EADE-433D-862E-C01CDC291F44}
const RNG_PROTOCOL_GUID: Guid = Guid::from_fields(
    0x3152bca5,
    0xeade,
    0x433d,
    0x86,
    0x2e,
    &[0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44],
);

/// SP800-90 CTR-256 algorithm GUID
const ALGORITHM_SP800_90_CTR_256: Guid = Guid::from_fields(
    0x44f0de6e,
    0x4d8c,
    0x4045,
    0xa8,
    0xc7,
    &[0x4d, 0xd1, 0x68, 0x85, 0x6b, 0x9e],
);

/// EFI_RNG_PROTOCOL structure
#[repr(C)]
struct RngProtocol {
    get_info: extern "efiapi" fn(
        this: *mut RngProtocol,
        algorithm_list_size: *mut usize,
        algorithm_list: *mut Guid,
    ) -> Status,
    get_rng: extern "efiapi" fn(
        this: *mut RngProtocol,
        algorithm: *mut Guid,
        value_length: usize,
        value: *mut u8,
    ) -> Status,
}

static mut SYSTEM_TABLE: *mut SystemTable = core::ptr::null_mut();
static mut CON_OUT: *mut SimpleTextOutput = core::ptr::null_mut();

#[no_mangle]
pub extern "efiapi" fn efi_main(_image_handle: Handle, system_table: *mut SystemTable) -> Status {
    unsafe {
        SYSTEM_TABLE = system_table;
        CON_OUT = (*system_table).con_out;
    }

    print_line("=== RNG Protocol Test ===");
    print_line("");

    let mut passed = 0u32;
    let mut failed = 0u32;

    // Test 1: Locate the RNG protocol
    print("  [1] LocateProtocol... ");
    let rng = locate_rng_protocol();
    if rng.is_null() {
        print_line("[FAIL] locate_protocol: RNG protocol not found");
        failed += 1;
        print_summary(passed, failed);
        return Status::SUCCESS;
    }
    print_line("[PASS] locate_protocol: RNG protocol found");
    passed += 1;

    // Test 2: GetInfo - query supported algorithms
    print("  [2] GetInfo... ");
    let mut algo_count: usize = 0;
    let status = unsafe { ((*rng).get_info)(rng, &mut algo_count, core::ptr::null_mut()) };
    if status == Status::BUFFER_TOO_SMALL && algo_count > 0 {
        let mut algos: [Guid; 4] = [Guid::from_fields(0, 0, 0, 0, 0, &[0; 6]); 4];
        let mut size = algos.len();
        let status = unsafe { ((*rng).get_info)(rng, &mut size, algos.as_mut_ptr()) };
        if status == Status::SUCCESS && size > 0 {
            print_line("[PASS] get_info: algorithms enumerated");
            passed += 1;

            // Test 3: Check that SP800-90-CTR-256 is in the list
            print("  [3] Algorithm check... ");
            let has_ctr256 = algos[..size]
                .iter()
                .any(|a| guid_eq(a, &ALGORITHM_SP800_90_CTR_256));
            if has_ctr256 {
                print_line("[PASS] algorithm_ctr256: SP800-90-CTR-256 supported");
                passed += 1;
            } else {
                print_line("[FAIL] algorithm_ctr256: SP800-90-CTR-256 not found");
                failed += 1;
            }
        } else {
            print_line("[FAIL] get_info: second call failed");
            failed += 1;
        }
    } else {
        print_line("[FAIL] get_info: expected BUFFER_TOO_SMALL");
        failed += 1;
    }

    // Test 4: GetRNG with NULL algorithm (default)
    print("  [4] GetRNG (default)... ");
    let mut buf = [0u8; 32];
    let status =
        unsafe { ((*rng).get_rng)(rng, core::ptr::null_mut(), buf.len(), buf.as_mut_ptr()) };
    if status == Status::SUCCESS {
        // Verify not all zeros
        if buf.iter().all(|&b| b == 0) {
            print_line("[FAIL] get_rng_default: returned all zeros");
            failed += 1;
        } else {
            print_line("[PASS] get_rng_default: got random bytes");
            passed += 1;
        }
    } else {
        print_line("[FAIL] get_rng_default: call failed");
        failed += 1;
    }

    // Test 5: GetRNG with explicit CTR-256 algorithm
    print("  [5] GetRNG (CTR-256)... ");
    let mut buf2 = [0u8; 32];
    let mut algo = ALGORITHM_SP800_90_CTR_256;
    let status = unsafe { ((*rng).get_rng)(rng, &mut algo, buf2.len(), buf2.as_mut_ptr()) };
    if status == Status::SUCCESS {
        if buf2.iter().all(|&b| b == 0) {
            print_line("[FAIL] get_rng_ctr256: returned all zeros");
            failed += 1;
        } else {
            print_line("[PASS] get_rng_ctr256: got random bytes");
            passed += 1;
        }
    } else {
        print_line("[FAIL] get_rng_ctr256: call failed");
        failed += 1;
    }

    // Test 6: Two calls should produce different output
    print("  [6] Uniqueness... ");
    if buf != buf2 {
        print_line("[PASS] uniqueness: two calls returned different data");
        passed += 1;
    } else {
        print_line("[FAIL] uniqueness: two calls returned identical data");
        failed += 1;
    }

    // Test 7: Small request (1 byte)
    print("  [7] GetRNG (1 byte)... ");
    let mut one = [0u8; 1];
    let status = unsafe { ((*rng).get_rng)(rng, core::ptr::null_mut(), 1, one.as_mut_ptr()) };
    if status == Status::SUCCESS {
        print_line("[PASS] get_rng_1byte: single byte request succeeded");
        passed += 1;
    } else {
        print_line("[FAIL] get_rng_1byte: single byte request failed");
        failed += 1;
    }

    // Test 8: Large request (256 bytes)
    print("  [8] GetRNG (256 bytes)... ");
    let mut large = [0u8; 256];
    let status =
        unsafe { ((*rng).get_rng)(rng, core::ptr::null_mut(), large.len(), large.as_mut_ptr()) };
    if status == Status::SUCCESS {
        // Count unique bytes - random data should have good distribution
        let mut seen = [false; 256];
        for &b in &large {
            seen[b as usize] = true;
        }
        let unique = seen.iter().filter(|&&s| s).count();
        // 256 random bytes should have at least 100 unique values
        if unique >= 100 {
            print_line("[PASS] get_rng_large: 256 bytes with good distribution");
            passed += 1;
        } else {
            print_line("[FAIL] get_rng_large: poor distribution");
            failed += 1;
        }
    } else {
        print_line("[FAIL] get_rng_large: call failed");
        failed += 1;
    }

    // Test 9: Unsupported algorithm should return UNSUPPORTED
    print("  [9] Unsupported algo... ");
    let mut bogus_algo = Guid::from_fields(0xdeadbeef, 0, 0, 0, 0, &[0; 6]);
    let mut dummy = [0u8; 8];
    let status = unsafe { ((*rng).get_rng)(rng, &mut bogus_algo, dummy.len(), dummy.as_mut_ptr()) };
    if status == Status::UNSUPPORTED {
        print_line("[PASS] unsupported_algo: correctly rejected");
        passed += 1;
    } else {
        print_line("[FAIL] unsupported_algo: unexpected status");
        failed += 1;
    }

    print_line("");
    print_summary(passed, failed);

    Status::SUCCESS
}

fn print_summary(passed: u32, failed: u32) {
    print("Results: ");
    print_dec(passed as u64);
    print(" passed, ");
    print_dec(failed as u64);
    print_line(" failed");
    print_line("");
    if failed == 0 {
        print_line("All RNG tests passed!");
    } else {
        print_line("Some RNG tests FAILED!");
    }
}

/// Locate the EFI_RNG_PROTOCOL via LocateProtocol
fn locate_rng_protocol() -> *mut RngProtocol {
    let bs = unsafe { (*SYSTEM_TABLE).boot_services };
    if bs.is_null() {
        return core::ptr::null_mut();
    }

    let mut interface: *mut c_void = core::ptr::null_mut();
    let status = unsafe {
        ((*bs).locate_protocol)(
            &RNG_PROTOCOL_GUID as *const Guid as *mut Guid,
            core::ptr::null_mut(),
            &mut interface,
        )
    };

    if status == Status::SUCCESS {
        interface as *mut RngProtocol
    } else {
        core::ptr::null_mut()
    }
}

/// Compare two GUIDs for equality
fn guid_eq(a: &Guid, b: &Guid) -> bool {
    let (a1, a2, a3, a4, a5, a6) = a.as_fields();
    let (b1, b2, b3, b4, b5, b6) = b.as_fields();
    a1 == b1 && a2 == b2 && a3 == b3 && a4 == b4 && a5 == b5 && a6 == b6
}

// ============================================================================
// Simple console output (no alloc, UCS-2 only)
// ============================================================================

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

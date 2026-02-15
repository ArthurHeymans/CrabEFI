//! Directory Enumeration Test Application
//!
//! This EFI application tests that CrabEFI correctly returns Long File Names
//! when enumerating directory contents via the SimpleFileSystem protocol.
//!
//! It opens \EFI\Linux\ and reads every directory entry, printing each
//! filename. The test harness checks that filenames longer than 64 characters
//! are returned intact (regression test for the heapless::String<64> truncation
//! bug).

#![no_std]
#![no_main]

use core::ffi::c_void;
use core::panic::PanicInfo;
use r_efi::efi::{self, Char16, Handle, Status, SystemTable};
use r_efi::protocols::simple_file_system;

// EFI_FILE_PROTOCOL GUIDs / constants
const EFI_FILE_MODE_READ: u64 = 0x0000000000000001;

/// Minimal EFI_FILE_INFO layout (we only care about Size, Attribute, and the
/// FileName that follows the fixed header).
#[repr(C)]
struct FileInfo {
    size: u64,
    file_size: u64,
    physical_size: u64,
    create_time: [u8; 16],
    last_access_time: [u8; 16],
    modification_time: [u8; 16],
    attribute: u64,
    // FileName (CHAR16[]) follows immediately
}

const EFI_FILE_DIRECTORY: u64 = 0x0000000000000010;

/// Scratch buffer for File.Read on directory handles.
/// 1 KiB is plenty for a single EFI_FILE_INFO + 255-char filename.
static mut INFO_BUF: [u8; 1024] = [0u8; 1024];

/// UTF-16 → ASCII scratch buffer for printing filenames.
static mut NAME_BUF: [u8; 512] = [0u8; 512];

fn info_buf_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(INFO_BUF) as *mut u8
}
fn info_buf_len() -> usize {
    1024
}
fn name_buf_ptr() -> *mut u8 {
    core::ptr::addr_of_mut!(NAME_BUF) as *mut u8
}

static mut CON_OUT: *mut r_efi::protocols::simple_text_output::Protocol = core::ptr::null_mut();

// ── helpers ──────────────────────────────────────────────────────────────

fn print(s: &str) {
    let con_out = unsafe { CON_OUT };
    if con_out.is_null() {
        return;
    }
    let mut buf: [Char16; 128] = [0; 128];
    let mut idx = 0;
    for c in s.chars() {
        if c == '\n' {
            buf[idx] = '\r' as Char16;
            idx += 1;
            if idx >= buf.len() - 2 {
                buf[idx] = 0;
                unsafe { ((*con_out).output_string)(con_out, buf.as_ptr() as *mut Char16) };
                idx = 0;
            }
        }
        buf[idx] = c as Char16;
        idx += 1;
        if idx >= buf.len() - 2 {
            buf[idx] = 0;
            unsafe { ((*con_out).output_string)(con_out, buf.as_ptr() as *mut Char16) };
            idx = 0;
        }
    }
    if idx > 0 {
        buf[idx] = 0;
        unsafe { ((*con_out).output_string)(con_out, buf.as_ptr() as *mut Char16) };
    }
}

fn println(s: &str) {
    print(s);
    print("\n");
}

/// Convert a null-terminated CHAR16 string to a UTF-8 byte slice (ASCII only)
/// stored in the global NAME_BUF. Returns the length used.
unsafe fn char16_to_ascii(ptr: *const Char16) -> usize {
    let buf = name_buf_ptr();
    let mut i = 0;
    loop {
        let ch = *ptr.add(i);
        if ch == 0 || i >= 511 {
            break;
        }
        *buf.add(i) = if ch < 128 { ch as u8 } else { b'?' };
        i += 1;
    }
    *buf.add(i) = 0;
    i
}

// ── test logic ───────────────────────────────────────────────────────────

/// Open a SFS volume via BootServices, enumerate a directory, print every name.
fn run_tests(image_handle: Handle, system_table: *mut SystemTable) -> bool {
    let bs = unsafe { (*system_table).boot_services };
    if bs.is_null() {
        println("[FAIL] boot_services is null");
        return false;
    }

    // 1. Locate SimpleFileSystem handle(s)
    let mut handles: [Handle; 16] = [core::ptr::null_mut(); 16];
    let mut buf_size = core::mem::size_of_val(&handles);
    let mut sfs_guid = simple_file_system::PROTOCOL_GUID;

    let status = unsafe {
        ((*bs).locate_handle)(
            efi::BY_PROTOCOL,
            &mut sfs_guid,
            core::ptr::null_mut(),
            &mut buf_size,
            handles.as_mut_ptr(),
        )
    };
    if status != Status::SUCCESS {
        println("[FAIL] LocateHandle(SFS) failed");
        return false;
    }
    let handle_count = buf_size / core::mem::size_of::<Handle>();
    if handle_count == 0 {
        println("[FAIL] No SFS handles found");
        return false;
    }

    // 2. Open the SFS protocol on the first handle
    let mut sfs_ptr: *mut c_void = core::ptr::null_mut();
    let status = unsafe {
        ((*bs).open_protocol)(
            handles[0],
            &mut sfs_guid,
            &mut sfs_ptr,
            image_handle,
            core::ptr::null_mut(),
            0x00000002, // GET_PROTOCOL
        )
    };
    if status != Status::SUCCESS || sfs_ptr.is_null() {
        println("[FAIL] OpenProtocol(SFS) failed");
        return false;
    }
    let sfs = sfs_ptr as *mut simple_file_system::Protocol;

    // 3. OpenVolume → root directory
    let mut root: *mut r_efi::protocols::file::Protocol = core::ptr::null_mut();
    let status = unsafe { ((*sfs).open_volume)(sfs, &mut root) };
    if status != Status::SUCCESS || root.is_null() {
        println("[FAIL] OpenVolume failed");
        return false;
    }
    println("[PASS] OpenVolume succeeded");

    // 4. Open \EFI\Linux directory
    let dir_path_arr: [Char16; 11] = [
        '\\' as Char16,
        'E' as Char16,
        'F' as Char16,
        'I' as Char16,
        '\\' as Char16,
        'L' as Char16,
        'i' as Char16,
        'n' as Char16,
        'u' as Char16,
        'x' as Char16,
        0,
    ];
    let mut linux_dir: *mut r_efi::protocols::file::Protocol = core::ptr::null_mut();
    let status = unsafe {
        ((*root).open)(
            root,
            &mut linux_dir,
            dir_path_arr.as_ptr() as *mut Char16,
            EFI_FILE_MODE_READ,
            0,
        )
    };
    if status != Status::SUCCESS || linux_dir.is_null() {
        println("[FAIL] Open(\\EFI\\Linux) failed");
        return false;
    }
    println("[PASS] Open(\\EFI\\Linux) succeeded");

    // 5. Read directory entries – the core of the test
    let mut all_ok = true;
    let mut found_long = false;
    let mut found_short = false;
    let mut entry_count: usize = 0;

    println("Directory Enumeration Test");
    println("==========================");
    loop {
        let mut read_size: usize = info_buf_len();
        let status = unsafe {
            ((*linux_dir).read)(linux_dir, &mut read_size, info_buf_ptr() as *mut c_void)
        };

        if status != Status::SUCCESS {
            print("[FAIL] File.Read returned error on entry ");
            // print entry_count as decimal
            let mut tmp = [0u8; 20];
            let n = fmt_dec(entry_count as u64, &mut tmp);
            print(unsafe { core::str::from_utf8_unchecked(&tmp[..n]) });
            println("");
            all_ok = false;
            break;
        }

        // read_size == 0 means end-of-directory
        if read_size == 0 {
            break;
        }

        entry_count += 1;

        // Extract filename from EFI_FILE_INFO
        let info = unsafe { &*(info_buf_ptr() as *const FileInfo) };
        let name_ptr =
            unsafe { info_buf_ptr().add(core::mem::size_of::<FileInfo>()) as *const Char16 };
        let name_len = unsafe { char16_to_ascii(name_ptr) };
        let name_str = unsafe {
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(name_buf_ptr(), name_len))
        };

        // Skip "." and ".."
        if name_str == "." || name_str == ".." {
            continue;
        }

        let is_dir = (info.attribute & EFI_FILE_DIRECTORY) != 0;
        let kind = if is_dir { "DIR " } else { "FILE" };

        print("[    ] ");
        print(kind);
        print(" \"");
        print(name_str);
        print("\" (len=");
        let mut tmp = [0u8; 20];
        let n = fmt_dec(name_len as u64, &mut tmp);
        print(unsafe { core::str::from_utf8_unchecked(&tmp[..n]) });
        println(")");

        // Check for the specific long filename (71 chars)
        if name_str.len() > 64 {
            // Verify it ends with ".efi"
            if name_str.len() >= 4 {
                let suffix = &name_str[name_str.len() - 4..];
                if suffix.eq_ignore_ascii_case(".efi") {
                    println("[PASS] long_filename_suffix: Long filename ends with .efi");
                    found_long = true;
                } else {
                    print("[FAIL] long_filename_suffix: Long filename ends with \"");
                    print(suffix);
                    println("\" instead of \".efi\"");
                    all_ok = false;
                }
            }
        }
        // Check for the shorter filename
        if name_str.eq_ignore_ascii_case("nixos-6.6.0.efi") {
            println("[PASS] short_filename: Found nixos-6.6.0.efi");
            found_short = true;
        }
    }

    // Close the directory handle
    unsafe { ((*linux_dir).close)(linux_dir) };
    unsafe { ((*root).close)(root) };

    println("");

    // Summarise
    if entry_count == 0 {
        println("[FAIL] entry_count: No entries found in \\EFI\\Linux");
        all_ok = false;
    } else {
        print("[PASS] entry_count: Found ");
        let mut tmp = [0u8; 20];
        let n = fmt_dec(entry_count as u64, &mut tmp);
        print(unsafe { core::str::from_utf8_unchecked(&tmp[..n]) });
        println(" entries");
    }

    if !found_long {
        println("[FAIL] long_filename: Did not find filename longer than 64 chars");
        all_ok = false;
    } else {
        println("[PASS] long_filename: Found filename longer than 64 chars");
    }

    if !found_short {
        println("[FAIL] short_filename: Did not find nixos-6.6.0.efi");
        all_ok = false;
    }

    all_ok
}

/// Format a u64 as decimal into buf, return number of bytes written.
fn fmt_dec(mut v: u64, buf: &mut [u8; 20]) -> usize {
    if v == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut idx = 20;
    while v > 0 {
        idx -= 1;
        buf[idx] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    let len = 20 - idx;
    // Shift to start
    buf.copy_within(idx..20, 0);
    len
}

// ── entry point ──────────────────────────────────────────────────────────

#[no_mangle]
pub extern "efiapi" fn efi_main(image_handle: Handle, system_table: *mut SystemTable) -> Status {
    unsafe {
        CON_OUT = (*system_table).con_out;
    }

    println("==============================================");
    println("  CrabEFI Directory Enumeration Test");
    println("==============================================");
    println("");

    let ok = run_tests(image_handle, system_table);

    println("");
    if ok {
        println("Directory enumeration test PASSED!");
    } else {
        println("Directory enumeration test FAILED!");
    }

    Status::SUCCESS
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

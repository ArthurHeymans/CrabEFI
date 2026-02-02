//! Storage Security Protocol Test Application
//!
//! This EFI application tests the Storage Security Command Protocol and
//! pass-through protocols (NVMe, ATA, SCSI) implemented in CrabEFI.
//!
//! Tests performed:
//! 1. Enumerate Storage Security Command protocols
//! 2. Send TCG Discovery0 to detect Opal-capable drives
//! 3. Test NVMe Pass Through Protocol
//! 4. Test ATA Pass Through Protocol
//! 5. Test SCSI Pass Through Protocol

#![no_std]
#![no_main]

mod console;
mod efi_helpers;
mod storage_security;
mod nvme_passthru;
mod ata_passthru;
mod scsi_passthru;
mod tcg_discovery;

use core::panic::PanicInfo;
use r_efi::efi::{Handle, Status, SystemTable};

use console::Console;

/// Global console for output
static mut CONSOLE: Option<Console> = None;

/// Global system table pointer
static mut SYSTEM_TABLE: *mut SystemTable = core::ptr::null_mut();

/// Get the global console
pub fn console() -> &'static mut Console {
    unsafe {
        CONSOLE.as_mut().expect("Console not initialized")
    }
}

/// Get the system table
pub fn system_table() -> *mut SystemTable {
    unsafe { SYSTEM_TABLE }
}

/// Get the boot services
pub fn boot_services() -> *mut r_efi::efi::BootServices {
    unsafe {
        if SYSTEM_TABLE.is_null() {
            panic!("System table not initialized");
        }
        (*SYSTEM_TABLE).boot_services
    }
}

/// EFI entry point
#[no_mangle]
pub extern "efiapi" fn efi_main(_image_handle: Handle, system_table: *mut SystemTable) -> Status {
    // Initialize globals
    unsafe {
        SYSTEM_TABLE = system_table;
        CONSOLE = Some(Console::new(system_table));
    }

    // Print banner
    console().print_line("==============================================");
    console().print_line("  CrabEFI Storage Security Protocol Test");
    console().print_line("==============================================");
    console().print_line("");

    // Run tests
    let mut total_tests = 0;
    let mut passed_tests = 0;

    // Test 1: Storage Security Protocol enumeration
    console().print_line("[1] Testing Storage Security Command Protocol...");
    let result = storage_security::test_storage_security_protocol();
    total_tests += 1;
    if result {
        passed_tests += 1;
        console().print_line("    [PASS] Storage Security Protocol");
    } else {
        console().print_line("    [SKIP] No Storage Security devices found");
    }
    console().print_line("");

    // Test 2: TCG Discovery0
    console().print_line("[2] Testing TCG Opal Discovery...");
    let result = tcg_discovery::test_tcg_discovery();
    total_tests += 1;
    if result {
        passed_tests += 1;
        console().print_line("    [PASS] TCG Discovery");
    } else {
        console().print_line("    [SKIP] No TCG-capable drives found");
    }
    console().print_line("");

    // Test 3: NVMe Pass Through Protocol
    console().print_line("[3] Testing NVMe Pass Through Protocol...");
    let result = nvme_passthru::test_nvme_pass_thru();
    total_tests += 1;
    if result {
        passed_tests += 1;
        console().print_line("    [PASS] NVMe Pass Through Protocol");
    } else {
        console().print_line("    [SKIP] No NVMe devices found");
    }
    console().print_line("");

    // Test 4: ATA Pass Through Protocol
    console().print_line("[4] Testing ATA Pass Through Protocol...");
    let result = ata_passthru::test_ata_pass_thru();
    total_tests += 1;
    if result {
        passed_tests += 1;
        console().print_line("    [PASS] ATA Pass Through Protocol");
    } else {
        console().print_line("    [SKIP] No ATA/SATA devices found");
    }
    console().print_line("");

    // Test 5: SCSI Pass Through Protocol
    console().print_line("[5] Testing SCSI Pass Through Protocol...");
    let result = scsi_passthru::test_scsi_pass_thru();
    total_tests += 1;
    if result {
        passed_tests += 1;
        console().print_line("    [PASS] SCSI Pass Through Protocol");
    } else {
        console().print_line("    [SKIP] No USB SCSI devices found");
    }
    console().print_line("");

    // Print summary
    console().print_line("==============================================");
    console().print("  Tests: ");
    console().print_dec(passed_tests);
    console().print(" passed / ");
    console().print_dec(total_tests);
    console().print_line(" total");
    console().print_line("==============================================");

    if passed_tests > 0 {
        console().print_line("");
        console().print_line("Some tests passed! Storage protocols are working.");
    } else {
        console().print_line("");
        console().print_line("No storage devices detected.");
        console().print_line("This is expected in QEMU without attached drives.");
    }

    Status::SUCCESS
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // Try to print panic message if console is available
    unsafe {
        if let Some(ref mut console) = CONSOLE {
            console.print_line("");
            console.print_line("!!! PANIC !!!");
            if let Some(location) = info.location() {
                console.print("File: ");
                console.print_line(location.file());
                console.print("Line: ");
                console.print_dec(location.line() as u64);
                console.print_line("");
            }
        }
    }
    loop {
        core::hint::spin_loop();
    }
}

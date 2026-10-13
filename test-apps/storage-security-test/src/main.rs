//! Storage Security Protocol Test Application
//!
//! This EFI application tests the Storage Security Command Protocol and
//! pass-through protocols (NVMe, ATA, SCSI) implemented in CrabEFI.
//!
//! Tests performed:
//! 1. Validate Storage Security Command protocol argument handling
//! 2. With `hardware-security-probes`, query supported security protocols and TCG Discovery0
//! 3. Test NVMe Pass Through Protocol
//! 4. Test ATA Pass Through Protocol
//! 5. Test SCSI Pass Through Protocol

#![no_std]
#![no_main]

mod ata_passthru;
mod console;
mod efi_helpers;
mod nvme_passthru;
mod scsi_passthru;
mod storage_security;
#[cfg(feature = "hardware-security-probes")]
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
    unsafe { CONSOLE.as_mut().expect("Console not initialized") }
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

    // Ok(false) means absent hardware/capability; errors are never skips.
    type Probe = fn() -> Result<bool, Status>;
    if !cfg!(feature = "hardware-security-probes") {
        console().print_line("Active security/TCG transfers disabled; enable hardware-security-probes on capable hardware.");
    }
    let probes: &[(&str, Probe)] = &[
        (
            "Storage Security Protocol",
            storage_security::test_storage_security_protocol,
        ),
        #[cfg(feature = "hardware-security-probes")]
        ("TCG Discovery", tcg_discovery::test_tcg_discovery),
        (
            "NVMe Pass Through Protocol",
            nvme_passthru::test_nvme_pass_thru,
        ),
        (
            "ATA Pass Through Protocol",
            ata_passthru::test_ata_pass_thru,
        ),
        (
            "SCSI Pass Through Protocol",
            scsi_passthru::test_scsi_pass_thru,
        ),
    ];
    let mut passed = 0;
    let mut skipped = 0;
    let mut failed = 0;
    for (name, probe) in probes {
        console().print_line(name);
        match probe() {
            Ok(true) => {
                passed += 1;
                console().print_line("    [PASS]");
            }
            Ok(false) => {
                skipped += 1;
                console().print_line("    [SKIP] Hardware or optional capability unavailable");
            }
            Err(status) => {
                failed += 1;
                console().print("    [FAIL] Protocol operation failed: ");
                console().print_hex(status.as_usize() as u64);
                console().print_line("");
            }
        }
    }

    console().print("Tests: ");
    console().print_dec(passed);
    console().print(" passed / ");
    console().print_dec(skipped);
    console().print(" skipped / ");
    console().print_dec(failed);
    console().print_line(" failed");
    console().print_line("STORAGE SECURITY TEST COMPLETED");
    if failed == 0 {
        console().print_line("STORAGE SECURITY TEST PASSED");
        Status::SUCCESS
    } else {
        Status::DEVICE_ERROR
    }
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

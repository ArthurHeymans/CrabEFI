//! CrabEFI - Main entry point
//!
//! This is the binary entry point for CrabEFI as a coreboot payload.

#![no_std]
#![no_main]

use crabefi;

/// Rust entry point called from assembly after 64-bit mode transition
///
/// # Arguments
///
/// * `coreboot_table_ptr` - Pointer to the coreboot tables (passed in RDI)
#[unsafe(no_mangle)]
pub extern "C" fn rust_main(coreboot_table_ptr: u64) -> ! {
    crabefi::init(coreboot_table_ptr);

    // Should never reach here
    loop {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}

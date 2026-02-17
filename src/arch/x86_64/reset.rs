//! x86_64 System Reset
//!
//! Provides system reset via keyboard controller and triple fault,
//! used by both EFI runtime services and the boot menu.

use super::io;

/// Attempt system reset via the keyboard controller
///
/// Sends command 0xFE to port 0x64, which triggers a system reset
/// on most x86 platforms. This function returns if the reset doesn't
/// take effect immediately.
pub fn keyboard_controller_reset() {
    unsafe {
        // Wait for keyboard controller input buffer to be empty
        for _ in 0..1000 {
            let status = io::inb(0x64);
            if status & 0x02 == 0 {
                break;
            }
        }
        // Send reset command
        io::outb(0x64, 0xFE);
    }
}

/// Force a system reset via triple fault
///
/// Loads a null IDT and triggers an interrupt, causing a triple fault
/// which resets the CPU. This never returns.
pub fn triple_fault() -> ! {
    unsafe {
        let null_idt: [u8; 6] = [0; 6];
        core::arch::asm!(
            "lidt [{}]",
            "int3",
            in(reg) null_idt.as_ptr(),
            options(noreturn)
        );
    }
}

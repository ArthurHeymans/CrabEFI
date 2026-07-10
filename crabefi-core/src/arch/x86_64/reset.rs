//! x86_64 System Reset
//!
//! Provides system reset via keyboard controller and triple fault,
//! used by both EFI runtime services and the boot menu.

use super::io;
use x86_64::VirtAddr;
use x86_64::instructions::tables::lidt;
use x86_64::structures::DescriptorTablePointer;

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
    let null_idt = DescriptorTablePointer {
        limit: 0,
        base: VirtAddr::zero(),
    };

    // SAFETY: Installing an invalid IDT is deliberate here to force a reset.
    unsafe {
        lidt(&null_idt);
        core::arch::asm!("int3", options(noreturn));
    }
}

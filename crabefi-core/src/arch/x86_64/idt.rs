//! Interrupt Descriptor Table (IDT) for x86_64
//!
//! This module sets up basic exception handlers to catch CPU faults
//! and log diagnostic information.

use spin::Once;
use x86_64::instructions::{hlt, interrupts};
use x86_64::registers::control::Cr2;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

static IDT: Once<InterruptDescriptorTable> = Once::new();

/// Exception names for logging
static EXCEPTION_NAMES: [&str; 32] = [
    "Division Error (#DE)",
    "Debug (#DB)",
    "NMI",
    "Breakpoint (#BP)",
    "Overflow (#OF)",
    "Bound Range Exceeded (#BR)",
    "Invalid Opcode (#UD)",
    "Device Not Available (#NM)",
    "Double Fault (#DF)",
    "Coprocessor Segment Overrun",
    "Invalid TSS (#TS)",
    "Segment Not Present (#NP)",
    "Stack-Segment Fault (#SS)",
    "General Protection Fault (#GP)",
    "Page Fault (#PF)",
    "Reserved",
    "x87 FPU Error (#MF)",
    "Alignment Check (#AC)",
    "Machine Check (#MC)",
    "SIMD Exception (#XM/#XF)",
    "Virtualization Exception (#VE)",
    "Control Protection (#CP)",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Hypervisor Injection (#HV)",
    "VMM Communication (#VC)",
    "Security Exception (#SX)",
    "Reserved",
];

/// Initialize the IDT with exception handlers.
pub fn init() {
    IDT.call_once(|| {
        let mut idt = InterruptDescriptorTable::new();
        x86_64::set_general_handler!(&mut idt, exception_handler, 0..32);
        idt
    })
    .load();

    log::info!("IDT initialized with exception handlers");
}

/// Common exception handler - logs and halts.
fn exception_handler(frame: InterruptStackFrame, vector: u8, error_code: Option<u64>) {
    let error_code = error_code.unwrap_or(0);
    let name = EXCEPTION_NAMES
        .get(vector as usize)
        .copied()
        .unwrap_or("Unknown");

    log::error!("==================== CPU EXCEPTION ====================");
    log::error!("Exception: {} (vector {})", name, vector);
    log::error!("Error code: {:#x}", error_code);
    log::error!(
        "RIP: {:#x}, CS: {:#x}",
        frame.instruction_pointer.as_u64(),
        frame.code_segment.0
    );
    log::error!("RFLAGS: {:#x}", frame.cpu_flags.bits());

    if vector == 14 {
        log::error!("CR2 (fault address): {:#x}", Cr2::read_raw());
        log::error!(
            "Page fault flags: {} {} {}",
            if error_code & 1 != 0 {
                "PRESENT"
            } else {
                "NOT_PRESENT"
            },
            if error_code & 2 != 0 { "WRITE" } else { "READ" },
            if error_code & 4 != 0 {
                "USER"
            } else {
                "KERNEL"
            }
        );
    }

    log::error!("========================================================");
    log::error!("System halted.");

    interrupts::disable();
    loop {
        hlt();
    }
}

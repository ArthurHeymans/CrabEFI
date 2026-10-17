//! Interrupt Descriptor Table (IDT) for x86_64
//!
//! This module sets up basic exception handlers to catch CPU faults
//! and log diagnostic information.
//!
//! The handlers are naked assembly stubs (one per vector) instead of
//! `extern "x86-interrupt"` functions so that the crate builds on stable
//! Rust (the `abi_x86_interrupt` feature is still unstable). Each stub
//! normalizes the stack to the `ExceptionFrame` layout — pushing a dummy
//! error code for vectors that don't provide one — and jumps to a common
//! stub that calls the Rust handler. The handler only logs and halts, so
//! no register state needs to be preserved for a return that never happens.
//!
//! The table itself is a raw gate array rather than the `x86_64` crate's
//! `InterruptDescriptorTable`: that type models handler ABIs in the type
//! system and its index access panics for the error-code vectors, while
//! at the hardware level every entry here is the same interrupt gate
//! pointing at a stub.

use core::arch::naked_asm;

use spin::Once;
use x86_64::VirtAddr;
use x86_64::instructions::tables::lidt;
use x86_64::instructions::{hlt, interrupts};
use x86_64::registers::control::Cr2;
use x86_64::registers::segmentation::{CS, Segment};
use x86_64::structures::DescriptorTablePointer;

static IDT: Once<Idt> = Once::new();

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

/// Stack layout seen by [`exception_handler`] after a stub ran: the vector
/// and (real or dummy) error code pushed by the stub, followed by the
/// frame the CPU pushed. CrabEFI runs everything at ring 0, so the CPU
/// does not push RSP/SS.
#[repr(C)]
struct ExceptionFrame {
    vector: u64,
    error_code: u64,
    instruction_pointer: u64,
    code_segment: u64,
    cpu_flags: u64,
}

/// Common entry point for all vector stubs: pass the normalized frame to
/// the Rust handler with a SysV-aligned stack. The handler never returns.
/// Exception entry does not clear RFLAGS.DF, but the SysV ABI requires it
/// clear on function entry (string ops in the handler would run backwards).
#[unsafe(naked)]
extern "C" fn exception_common() {
    naked_asm!(
        "cld",
        "mov rdi, rsp",
        "and rsp, -16",
        "call {handler}",
        "2: hlt",
        "jmp 2b",
        handler = sym exception_handler,
    )
}

macro_rules! stub_no_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        extern "C" fn $name() {
            naked_asm!(
                "push 0",
                "push {vector}",
                "jmp {common}",
                vector = const $vector,
                common = sym exception_common,
            )
        }
    };
}

macro_rules! stub_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        extern "C" fn $name() {
            naked_asm!(
                "push {vector}",
                "jmp {common}",
                vector = const $vector,
                common = sym exception_common,
            )
        }
    };
}

stub_no_error!(stub_0, 0u64);
stub_no_error!(stub_1, 1u64);
stub_no_error!(stub_2, 2u64);
stub_no_error!(stub_3, 3u64);
stub_no_error!(stub_4, 4u64);
stub_no_error!(stub_5, 5u64);
stub_no_error!(stub_6, 6u64);
stub_no_error!(stub_7, 7u64);
stub_error!(stub_8, 8u64);
stub_no_error!(stub_9, 9u64);
stub_error!(stub_10, 10u64);
stub_error!(stub_11, 11u64);
stub_error!(stub_12, 12u64);
stub_error!(stub_13, 13u64);
stub_error!(stub_14, 14u64);
stub_no_error!(stub_15, 15u64);
stub_no_error!(stub_16, 16u64);
stub_error!(stub_17, 17u64);
stub_no_error!(stub_18, 18u64);
stub_no_error!(stub_19, 19u64);
stub_no_error!(stub_20, 20u64);
stub_error!(stub_21, 21u64);
stub_no_error!(stub_22, 22u64);
stub_no_error!(stub_23, 23u64);
stub_no_error!(stub_24, 24u64);
stub_no_error!(stub_25, 25u64);
stub_no_error!(stub_26, 26u64);
stub_no_error!(stub_27, 27u64);
stub_no_error!(stub_28, 28u64);
stub_error!(stub_29, 29u64);
stub_error!(stub_30, 30u64);
stub_no_error!(stub_31, 31u64);

/// Handler stub address per exception vector, in vector order.
///
/// Built at runtime because function-pointer-to-integer casts are not
/// allowed in `static` initializers.
fn exception_stubs() -> [usize; 32] {
    [
        stub_0 as *const () as usize,
        stub_1 as *const () as usize,
        stub_2 as *const () as usize,
        stub_3 as *const () as usize,
        stub_4 as *const () as usize,
        stub_5 as *const () as usize,
        stub_6 as *const () as usize,
        stub_7 as *const () as usize,
        stub_8 as *const () as usize,
        stub_9 as *const () as usize,
        stub_10 as *const () as usize,
        stub_11 as *const () as usize,
        stub_12 as *const () as usize,
        stub_13 as *const () as usize,
        stub_14 as *const () as usize,
        stub_15 as *const () as usize,
        stub_16 as *const () as usize,
        stub_17 as *const () as usize,
        stub_18 as *const () as usize,
        stub_19 as *const () as usize,
        stub_20 as *const () as usize,
        stub_21 as *const () as usize,
        stub_22 as *const () as usize,
        stub_23 as *const () as usize,
        stub_24 as *const () as usize,
        stub_25 as *const () as usize,
        stub_26 as *const () as usize,
        stub_27 as *const () as usize,
        stub_28 as *const () as usize,
        stub_29 as *const () as usize,
        stub_30 as *const () as usize,
        stub_31 as *const () as usize,
    ]
}

/// One 64-bit IDT gate descriptor (16 bytes, SDM Vol. 3A §6.14.1).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GateDescriptor {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attributes: u8,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl GateDescriptor {
    const NULL: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attributes: 0,
        offset_middle: 0,
        offset_high: 0,
        reserved: 0,
    };

    fn new(handler: usize, selector: u16) -> Self {
        Self {
            offset_low: handler as u16,
            selector,
            ist: 0,
            // Present, DPL 0, 64-bit interrupt gate.
            type_attributes: 0x8E,
            offset_middle: (handler >> 16) as u16,
            offset_high: (handler >> 32) as u32,
            reserved: 0,
        }
    }
}

/// The exception IDT: one gate per architecturally defined vector (0–31).
#[repr(C, align(16))]
struct Idt([GateDescriptor; 32]);

/// Initialize the IDT with exception handlers.
pub fn init() {
    let idt = IDT.call_once(|| {
        let selector = CS::get_reg().0;
        let mut entries = [GateDescriptor::NULL; 32];
        for (entry, stub) in entries.iter_mut().zip(exception_stubs()) {
            *entry = GateDescriptor::new(stub, selector);
        }
        Idt(entries)
    });
    let pointer = DescriptorTablePointer {
        limit: (size_of::<Idt>() - 1) as u16,
        base: VirtAddr::new(idt as *const Idt as u64),
    };
    // SAFETY: `idt` lives in a `Once` cell for the rest of the firmware's
    // lifetime, and every gate points at a stub that conforms to the
    // interrupt entry contract (see the module documentation).
    unsafe { lidt(&pointer) };

    log::info!("IDT initialized with exception handlers");
}

/// Common exception handler - logs and halts.
///
/// # Safety
///
/// Must only be called from `exception_common` with a pointer to the
/// stack frame a vector stub normalized to the `ExceptionFrame` layout.
unsafe extern "C" fn exception_handler(frame: *const ExceptionFrame) -> ! {
    // SAFETY: the caller contract guarantees `frame` points at a
    // stub-normalized exception frame that stays valid while halted here.
    let frame = unsafe { &*frame };
    let vector = frame.vector as u8;
    let error_code = frame.error_code;
    let name = EXCEPTION_NAMES
        .get(vector as usize)
        .copied()
        .unwrap_or("Unknown");

    log::error!("==================== CPU EXCEPTION ====================");
    log::error!("Exception: {} (vector {})", name, vector);
    log::error!("Error code: {:#x}", error_code);
    log::error!(
        "RIP: {:#x}, CS: {:#x}",
        frame.instruction_pointer,
        frame.code_segment
    );
    log::error!("RFLAGS: {:#x}", frame.cpu_flags);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_descriptor_splits_handler_address_across_fields() {
        let gate = GateDescriptor::new(0x1122_3344_5566_7788, 0x28);
        // Copy out of the packed struct before asserting: assert_eq!
        // would borrow the fields, which is an error for packed types.
        let (offset_low, offset_middle, offset_high, selector, ist, type_attributes, reserved) = (
            gate.offset_low,
            gate.offset_middle,
            gate.offset_high,
            gate.selector,
            gate.ist,
            gate.type_attributes,
            gate.reserved,
        );
        assert_eq!(offset_low, 0x7788);
        assert_eq!(offset_middle, 0x5566);
        assert_eq!(offset_high, 0x1122_3344);
        assert_eq!(selector, 0x28);
        assert_eq!(ist, 0);
        assert_eq!(type_attributes, 0x8E);
        assert_eq!(reserved, 0);
        assert_eq!(size_of::<GateDescriptor>(), 16);
        assert_eq!(size_of::<Idt>(), 32 * 16);
    }

    #[test]
    fn null_gate_is_not_present() {
        let gate = GateDescriptor::NULL;
        let type_attributes = gate.type_attributes;
        assert_eq!(type_attributes, 0);
    }
}

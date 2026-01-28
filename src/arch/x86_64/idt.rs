//! Interrupt Descriptor Table (IDT) for x86_64
//!
//! This module sets up basic exception handlers to catch CPU faults
//! and log diagnostic information.

use core::arch::{asm, naked_asm};
use core::ptr::{addr_of, addr_of_mut};

/// IDT entry (interrupt gate descriptor)
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    /// Low 16 bits of handler address
    offset_low: u16,
    /// Code segment selector
    selector: u16,
    /// IST (Interrupt Stack Table) offset (bits 0-2), reserved (bits 3-7)
    ist: u8,
    /// Type and attributes
    type_attr: u8,
    /// Middle 16 bits of handler address
    offset_mid: u16,
    /// High 32 bits of handler address
    offset_high: u32,
    /// Reserved
    reserved: u32,
}

impl IdtEntry {
    const fn empty() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn set_handler(&mut self, handler: u64) {
        self.offset_low = handler as u16;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = 0x08; // Code segment selector (from coreboot GDT)
        self.ist = 0;
        // Present, DPL=0, Interrupt Gate (0x8E)
        self.type_attr = 0x8E;
    }
}

/// IDT pointer structure for LIDT instruction
#[repr(C, packed)]
struct IdtPointer {
    limit: u16,
    base: u64,
}

/// The IDT - 256 entries for all possible interrupts
static mut IDT: [IdtEntry; 256] = [IdtEntry::empty(); 256];

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

/// Initialize the IDT with exception handlers
pub fn init() {
    unsafe {
        let idt = addr_of_mut!(IDT);

        // Set up exception handlers (0-31)
        (*idt)[0].set_handler(exception_0 as *const () as u64);
        (*idt)[1].set_handler(exception_1 as *const () as u64);
        (*idt)[2].set_handler(exception_2 as *const () as u64);
        (*idt)[3].set_handler(exception_3 as *const () as u64);
        (*idt)[4].set_handler(exception_4 as *const () as u64);
        (*idt)[5].set_handler(exception_5 as *const () as u64);
        (*idt)[6].set_handler(exception_6 as *const () as u64);
        (*idt)[7].set_handler(exception_7 as *const () as u64);
        (*idt)[8].set_handler(exception_8_df as *const () as u64);
        (*idt)[9].set_handler(exception_9 as *const () as u64);
        (*idt)[10].set_handler(exception_10_ec as *const () as u64);
        (*idt)[11].set_handler(exception_11_ec as *const () as u64);
        (*idt)[12].set_handler(exception_12_ec as *const () as u64);
        (*idt)[13].set_handler(exception_13_ec as *const () as u64);
        (*idt)[14].set_handler(exception_14_ec as *const () as u64);
        (*idt)[15].set_handler(exception_15 as *const () as u64);
        (*idt)[16].set_handler(exception_16 as *const () as u64);
        (*idt)[17].set_handler(exception_17_ec as *const () as u64);
        (*idt)[18].set_handler(exception_18 as *const () as u64);
        (*idt)[19].set_handler(exception_19 as *const () as u64);
        (*idt)[20].set_handler(exception_20 as *const () as u64);
        (*idt)[21].set_handler(exception_21_ec as *const () as u64);

        // Load the IDT
        let idt_ptr = IdtPointer {
            limit: (core::mem::size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: idt as u64,
        };

        asm!("lidt [{}]", in(reg) &idt_ptr, options(nostack));
    }

    log::info!("IDT initialized with exception handlers");
}

/// Read CR2 (page fault linear address)
fn read_cr2() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, cr2", out(reg) value, options(nostack));
    }
    value
}

/// Common exception handler - logs and halts
#[unsafe(no_mangle)]
extern "C" fn exception_handler(vector: u64, error_code: u64, rip: u64, cs: u64, rflags: u64) {
    let name = if vector < 32 {
        EXCEPTION_NAMES[vector as usize]
    } else {
        "Unknown"
    };

    log::error!("==================== CPU EXCEPTION ====================");
    log::error!("Exception: {} (vector {})", name, vector);
    log::error!("Error code: {:#x}", error_code);
    log::error!("RIP: {:#x}, CS: {:#x}", rip, cs);
    log::error!("RFLAGS: {:#x}", rflags);

    if vector == 14 {
        // Page fault - show CR2 (faulting address)
        let cr2 = read_cr2();
        log::error!("CR2 (fault address): {:#x}", cr2);
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

    // Halt forever
    loop {
        unsafe {
            asm!("cli; hlt", options(nostack, nomem));
        }
    }
}

// Exception handlers without error code
macro_rules! exception_no_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            naked_asm!(
                "push 0",            // Fake error code
                "push {vector}",     // Vector number
                "push rax",
                "push rbx",
                "push rcx",
                "push rdx",
                "push rsi",
                "push rdi",
                "push rbp",
                "push r8",
                "push r9",
                "push r10",
                "push r11",
                "push r12",
                "push r13",
                "push r14",
                "push r15",
                "mov rdi, {vector}", // vector
                "mov rsi, [rsp + 128]", // error_code (fake)
                "mov rdx, [rsp + 136]", // rip
                "mov rcx, [rsp + 144]", // cs
                "mov r8, [rsp + 152]",  // rflags
                "call {handler}",
                "2:",
                "hlt",
                "jmp 2b",
                vector = const $vector,
                handler = sym exception_handler,
            );
        }
    };
}

// Exception handlers with error code
macro_rules! exception_with_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            naked_asm!(
                "push {vector}",     // Vector number
                "push rax",
                "push rbx",
                "push rcx",
                "push rdx",
                "push rsi",
                "push rdi",
                "push rbp",
                "push r8",
                "push r9",
                "push r10",
                "push r11",
                "push r12",
                "push r13",
                "push r14",
                "push r15",
                "mov rdi, {vector}", // vector
                "mov rsi, [rsp + 120]", // error_code
                "mov rdx, [rsp + 128]", // rip
                "mov rcx, [rsp + 136]", // cs
                "mov r8, [rsp + 144]",  // rflags
                "call {handler}",
                "2:",
                "hlt",
                "jmp 2b",
                vector = const $vector,
                handler = sym exception_handler,
            );
        }
    };
}

exception_no_error!(exception_0, 0);
exception_no_error!(exception_1, 1);
exception_no_error!(exception_2, 2);
exception_no_error!(exception_3, 3);
exception_no_error!(exception_4, 4);
exception_no_error!(exception_5, 5);
exception_no_error!(exception_6, 6);
exception_no_error!(exception_7, 7);
exception_with_error!(exception_8_df, 8);
exception_no_error!(exception_9, 9);
exception_with_error!(exception_10_ec, 10);
exception_with_error!(exception_11_ec, 11);
exception_with_error!(exception_12_ec, 12);
exception_with_error!(exception_13_ec, 13);
exception_with_error!(exception_14_ec, 14);
exception_no_error!(exception_15, 15);
exception_no_error!(exception_16, 16);
exception_with_error!(exception_17_ec, 17);
exception_no_error!(exception_18, 18);
exception_no_error!(exception_19, 19);
exception_no_error!(exception_20, 20);
exception_with_error!(exception_21_ec, 21);

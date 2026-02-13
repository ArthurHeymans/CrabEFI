//! Assembly entry point for CrabEFI
//!
//! This module contains the 32-bit to 64-bit transition code using global_asm!.
//! Coreboot calls payloads in 32-bit protected mode.

use core::arch::global_asm;

// Static page tables in BSS - will be initialized at runtime
#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [u64; 512],
}

impl PageTable {
    pub const fn empty() -> Self {
        PageTable { entries: [0; 512] }
    }
}

// Page tables - placed in a specific section
// We need to identity-map enough memory for UEFI applications.
// 64GB requires 64 Page Directories (64 * 512 * 2MB = 64GB)
#[unsafe(no_mangle)]
#[unsafe(link_section = ".page_tables")]
pub static mut PML4: PageTable = PageTable::empty();

#[unsafe(no_mangle)]
#[unsafe(link_section = ".page_tables")]
pub static mut PDPT: PageTable = PageTable::empty();

/// Number of Page Directories for identity mapping
/// 64 PDs * 512 entries * 2MB per entry = 64GB
pub const NUM_PAGE_DIRECTORIES: usize = 64;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".page_tables")]
pub static mut PD: [PageTable; NUM_PAGE_DIRECTORIES] =
    [const { PageTable::empty() }; NUM_PAGE_DIRECTORIES];

// Assembly entry point - Intel syntax
// Note: The GDT is defined in assembly below (gdt64/gdt64_ptr)
global_asm!(
    r#"
.section .entry32, "ax"
.code32

.global _start
_start:
    cli

    // Save coreboot table pointer from stack
    mov ebx, [esp + 4]

    // Check for long mode support
    mov eax, 0x80000001
    cpuid
    test edx, 0x20000000      // Bit 29 = Long Mode
    jz .Lno_long_mode

    // Initialize page tables at runtime
    // Get address of PML4
    lea edi, [PML4]
    
    // Set up PML4[0] -> PDPT
    lea eax, [PDPT]
    or eax, 0x03              // Present + Writable
    mov [edi], eax
    mov dword ptr [edi + 4], 0
    
    // Set up PDPT[0-63] -> PD[0-63] for 64GB identity mapping
    lea eax, [PD]
    or eax, 0x03              // Present + Writable
    lea edi, [PDPT]
    mov ecx, 64               // 64 PDPT entries for 64GB
    
.Lfill_pdpt:
    mov [edi], eax
    mov dword ptr [edi + 4], 0
    add eax, 0x1000           // Next PD (4KB apart)
    add edi, 8
    dec ecx
    jnz .Lfill_pdpt
    
    // Set up PD entries - identity map first 64GB with 2MB pages
    lea edi, [PD]
    mov eax, 0x83             // Present + Writable + PageSize (2MB)
    xor edx, edx              // High 32 bits
    mov ecx, 32768            // 512 entries * 64 PDs = 32768 entries
    
.Lfill_pd:
    mov [edi], eax
    mov [edi + 4], edx
    add eax, 0x200000         // Next 2MB
    adc edx, 0                // Carry to high bits
    add edi, 8
    dec ecx
    jnz .Lfill_pd

    // Enable PAE
    mov eax, cr4
    or eax, 0x20              // CR4.PAE (bit 5)
    mov cr4, eax

    // Load PML4 into CR3
    lea eax, [PML4]
    mov cr3, eax

    // Enable long mode in EFER MSR
    mov ecx, 0xC0000080       // EFER MSR
    rdmsr
    or eax, 0x100             // EFER.LME (bit 8)
    or eax, 0x800             // EFER.NXE (bit 11)
    wrmsr

    // Enable paging
    mov eax, cr0
    or eax, 0x80000000        // CR0.PG (bit 31)
    mov cr0, eax

    // Load 64-bit GDT
    lgdt [gdt64_ptr]

    // Far jump to 64-bit code using indirect jump
    ljmp [long_mode_target]

.Lno_long_mode:
    hlt
    jmp .Lno_long_mode

// Far jump target (offset + segment)
.align 8
long_mode_target:
    .long long_mode_start
    .word 0x08

// GDT pointer structure
.align 16
gdt64_ptr:
    .word gdt64_end - gdt64 - 1
    .quad gdt64

gdt64:
    .quad 0                    // Null
gdt64_code:
    .quad 0x00af9a000000ffff   // 64-bit code
gdt64_data:
    .quad 0x00cf92000000ffff   // 64-bit data
gdt64_end:

.code64
.section .text

.global long_mode_start
long_mode_start:
    // Set up data segments
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    // Set up stack
    lea rsp, [rip + _stack_top]

    // Zero BSS
    lea rdi, [rip + _bss_start]
    lea rcx, [rip + _bss_end]
    sub rcx, rdi
    shr rcx, 3
    xor rax, rax
    rep stosq

    // Enable SSE
    mov rax, cr0
    and rax, 0xFFFFFFFFFFFFFFFB  // Clear EM (bit 2)
    or rax, 0x2                   // Set MP (bit 1)
    mov cr0, rax

    mov rax, cr4
    or rax, 0x200                 // OSFXSR (bit 9)
    or rax, 0x400                 // OSXMMEXCPT (bit 10)
    mov cr4, rax

    // Pass coreboot table pointer
    mov edi, ebx
    xor rax, rax
    mov eax, edi
    mov rdi, rax

    // Call Rust
    call rust_main

.Lhalt:
    hlt
    jmp .Lhalt
"#
);

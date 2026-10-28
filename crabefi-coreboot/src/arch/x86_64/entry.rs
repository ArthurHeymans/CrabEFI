//! CrabEFI's 64-bit x86 entry ABI (version 1).
//!
//! Enter `_start` in long mode with the physical coreboot table pointer in RDI.
//! The caller must identity-map all PT_LOAD segments, disable interrupts and
//! PCID, and leave paging enabled. Four- and five-level paging are supported.
//! No caller stack or GDT is retained. There is no 32-bit entry point.

use core::arch::global_asm;

use crabefi::cell::StaticMut;

#[repr(C, align(4096))]
pub struct PageTable {
    pub entries: [u64; 512],
}

impl PageTable {
    pub const fn empty() -> Self {
        PageTable { entries: [0; 512] }
    }
}

// Keep these outside BSS: clearing BSS must not erase the active page tables.
// 64 page directories * 512 entries * 2 MiB identity-maps the first 64 GiB.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".page_tables")]
static PML5: StaticMut<PageTable> = StaticMut::new(PageTable::empty());

#[unsafe(no_mangle)]
#[unsafe(link_section = ".page_tables")]
static PML4: StaticMut<PageTable> = StaticMut::new(PageTable::empty());

#[unsafe(no_mangle)]
#[unsafe(link_section = ".page_tables")]
static PDPT: StaticMut<PageTable> = StaticMut::new(PageTable::empty());

const NUM_PAGE_DIRECTORIES: usize = 64;

#[unsafe(no_mangle)]
#[unsafe(link_section = ".page_tables")]
static PD: StaticMut<[PageTable; NUM_PAGE_DIRECTORIES]> =
    StaticMut::new([const { PageTable::empty() }; NUM_PAGE_DIRECTORIES]);

global_asm!(
    r#"
// A dedicated PT_NOTE identifies the entry contract to ELF loaders. ELFCLASS64
// alone cannot distinguish this ABI from the old .code32 coreboot entry.
.section .note.crabefi, "a", @note
.balign 4
.long 8                      // namesz, including NUL
.long 4                      // descsz
.long 1                      // CrabEFI entry ABI note type
.asciz "CrabEFI"
.long 1                      // 64-bit entry ABI version

.section .entry64, "ax"
.code64
.global _start
_start:
    cli
    cld
    mov r12, rdi             // preserve the full-width coreboot table pointer
    lea rsp, [rip + _stack_top]
    xor ebp, ebp

    // Do not rely on the caller's initial contents of the paging structures.
    lea rdi, [rip + _page_tables_start]
    lea rcx, [rip + _page_tables_end]
    sub rcx, rdi
    shr rcx, 3
    xor eax, eax
    rep stosq

    lea rax, [rip + PML4]
    or rax, 3
    mov [rip + PML5], rax
    lea rax, [rip + PDPT]
    or rax, 3
    mov [rip + PML4], rax

    lea rax, [rip + PD]
    or rax, 3
    lea rdi, [rip + PDPT]
    mov ecx, 64
.Lfill_pdpt:
    mov [rdi], rax
    add rax, 0x1000
    add rdi, 8
    loop .Lfill_pdpt

    lea rdi, [rip + PD]
    mov eax, 0x83            // present, writable, 2 MiB page
    mov ecx, 32768
.Lfill_pd:
    mov [rdi], rax
    add rax, 0x200000
    add rdi, 8
    loop .Lfill_pd

    // Keep the caller's paging depth. LA57 cannot change with paging enabled.
    // Removing PGE makes the CR3 reload invalidate any old global mappings.
    mov rax, cr4
    and rax, -129           // clear CR4.PGE
    or rax, 0x620           // PAE, OSFXSR, OSXMMEXCPT
    mov cr4, rax
    test eax, 0x1000        // CR4.LA57
    lea rax, [rip + PML4]
    lea rdx, [rip + PML5]
    cmovnz rax, rdx
    mov cr3, rax

    // Install our GDT and reload CS without leaving long mode.
    lgdt [rip + gdt64_ptr]
    push 0x08
    lea rax, [rip + .Lsegments]
    push rax
    retfq
.Lsegments:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    lea rdi, [rip + _bss_start]
    lea rcx, [rip + _bss_end]
    sub rcx, rdi
    xor eax, eax
    rep stosb

    // No live stack data exists before the call to rust_main.
    lea rdi, [rip + _stack_bottom]
    lea rcx, [rip + _stack_top]
    sub rcx, rdi
    mov al, 0xA5
    rep stosb

    mov rax, cr0
    and rax, -13            // clear EM and TS
    or rax, 2               // MP
    mov cr0, rax
    mov ecx, 0xC0000080     // EFER
    rdmsr
    or eax, 0x800           // NXE
    wrmsr

    mov rdi, r12
    call rust_main
.Lhalt:
    hlt
    jmp .Lhalt

.balign 8
gdt64_ptr:
    .word gdt64_end - gdt64 - 1
    .quad gdt64
gdt64:
    .quad 0
    .quad 0x00af9a000000ffff
    .quad 0x00cf92000000ffff
gdt64_end:
"#
);

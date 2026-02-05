//! Payload relocation trampoline
//!
//! This module provides a mechanism to load payloads that need to be placed
//! at memory addresses that conflict with CrabEFI's own code/data.
//!
//! The approach is:
//! 1. Decompress the payload to a "bounce buffer" in safe high memory
//! 2. Set up a small trampoline routine at a fixed safe address (0x8000)
//! 3. Jump to the trampoline, which:
//!    - Copies the payload from bounce buffer to final target
//!    - Zeros the BSS section
//!    - Jumps to the entry point
//!
//! This is similar to how GRUB's relocator works.

use core::arch::global_asm;

/// Trampoline location - 0x8000 is in the BIOS data area, typically safe
/// after early boot. This is below where CrabEFI loads (0x100000).
const TRAMPOLINE_ADDR: u64 = 0x8000;

/// Maximum trampoline size (4KB should be plenty)
const TRAMPOLINE_MAX_SIZE: usize = 0x1000;

/// Parameters for the relocation trampoline (passed in registers)
///
/// Layout matches the register assignment in the trampoline:
/// - rdi: src_addr (bounce buffer)
/// - rsi: dst_addr (target)  
/// - rdx: copy_size
/// - rcx: bss_size
/// - r8:  entry_point
/// - r9:  coreboot_table_ptr
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct TrampolineParams {
    /// Source address (bounce buffer)
    pub src_addr: u64,
    /// Destination address (final target)
    pub dst_addr: u64,
    /// Number of bytes to copy
    pub copy_size: u64,
    /// Number of bytes to zero after copy (BSS)
    pub bss_size: u64,
    /// Entry point to jump to after relocation
    pub entry_point: u64,
    /// Coreboot table pointer (passed to payload in EBX)
    pub coreboot_table_ptr: u64,
}

// The trampoline code in assembly
// This is position-independent and will be copied to TRAMPOLINE_ADDR (0x8000)
//
// The trampoline:
// 1. Saves all parameters to fixed memory locations (0x7F00 area)
// 2. Switches from 64-bit long mode to 32-bit protected mode with paging DISABLED
//    (must disable paging BEFORE copying since destination may overwrite page tables)
// 3. Copies payload from bounce buffer to target address
// 4. Zeros BSS section
// 5. Jumps to the payload entry point with coreboot table pointer in EBX
//
// The 64->32 bit transition follows coreboot's exit32.inc approach:
// 1. Load GDT with 32-bit and 64-bit segments (coreboot layout)
// 2. Use iretq to switch to 32-bit compatibility mode
// 3. Set up data segments
// 4. Disable paging (CR0.PG=0)
// 5. Disable long mode (EFER.LME=0)
// 6. Disable PAE (CR4.PAE=0)
// 7. Clear page table register (CR3=0)
// 8. Copy payload and jump

global_asm!(
    r#"
    .section .text.trampoline, "ax"
    .code64
    .global trampoline_start
    .global trampoline_end

trampoline_start:
    // Parameters passed in registers:
    // rdi = src_addr (bounce buffer)
    // rsi = dst_addr (target)
    // rdx = copy_size
    // rcx = bss_size  
    // r8  = entry_point
    // r9  = coreboot_table_ptr (for passing to payload)

    // Save ALL parameters to memory at 0x7F00 IMMEDIATELY
    // (we'll switch to 32-bit mode where r8-r15 don't exist!)
    // Memory layout at 0x7F00:
    //   0x7F00: coreboot_table_ptr (4 bytes)
    //   0x7F04: entry_point (4 bytes)
    //   0x7F08: src_addr (4 bytes) 
    //   0x7F0C: dst_addr (4 bytes)
    //   0x7F10: copy_size (4 bytes)
    //   0x7F14: bss_size (4 bytes)
    //   0x7F18: GDT pointer (6 bytes)
    //   0x7F20: GDT (32 bytes)
    
    mov dword ptr [0x7F00], r9d     // coreboot_table_ptr
    mov dword ptr [0x7F04], r8d     // entry_point
    mov dword ptr [0x7F08], edi     // src_addr (low 32 bits, should be enough)
    mov dword ptr [0x7F0C], esi     // dst_addr
    mov dword ptr [0x7F10], edx     // copy_size
    mov dword ptr [0x7F14], ecx     // bss_size

    // We must disable paging BEFORE copying to 0x100000 because that
    // will overwrite CrabEFI's page tables. Switch to 32-bit mode first.
    
    // Set up GDT at 0x7F40, GDT pointer at 0x7F38
    mov word ptr [0x7F38], 31       // GDT limit (4 entries * 8 - 1)
    mov dword ptr [0x7F3A], 0x7F40  // GDT base address
    
    // Entry 0x00: Null descriptor
    mov qword ptr [0x7F40], 0
    // Entry 0x08: 32-bit code segment
    mov dword ptr [0x7F48], 0x0000FFFF
    mov dword ptr [0x7F4C], 0x00CF9B00
    // Entry 0x10: 32-bit data segment
    mov dword ptr [0x7F50], 0x0000FFFF
    mov dword ptr [0x7F54], 0x00CF9300
    // Entry 0x18: 64-bit code segment (needed for iretq target)
    mov dword ptr [0x7F58], 0x0000FFFF
    mov dword ptr [0x7F5C], 0x00AF9B00
    
    lgdt [0x7F38]

    // Switch to 32-bit compatibility mode using iretq
    mov rcx, 0x08               // 32-bit code segment selector
    mov rdx, rsp
    mov ax, ss
    push rax                    // SS
    push rdx                    // RSP
    pushfq                      // RFLAGS
    push rcx                    // CS
    lea rax, [rip + compat_mode]
    push rax                    // RIP
    iretq

    .code32
compat_mode:
    // Now in 32-bit compatibility mode (paging still enabled)
    // Set up data segments
    mov eax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax

    // Disable paging (CR0.PG = 0)
    mov eax, cr0
    and eax, 0x7FFFFFFF
    mov cr0, eax

    // Disable long mode (EFER.LME = 0)
    mov ecx, 0xC0000080
    rdmsr
    and eax, 0xFFFFFEFF
    wrmsr

    // Disable PAE
    mov eax, cr4
    and eax, 0xFFFFFFDF
    mov cr4, eax

    // Clear CR3
    xor eax, eax
    mov cr3, eax

    // Far jump to reload CS in true 32-bit protected mode
    .byte 0xEA
    .long 0x8000 + (protected_mode - trampoline_start)
    .word 0x08

protected_mode:
    // Now in 32-bit protected mode with paging DISABLED
    // Safe to copy to 0x100000 without breaking page tables
    
    // Reload data segments
    mov eax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax

    // Set up stack
    mov esp, 0x7000
    
    // Load copy parameters from memory
    mov esi, [0x7F08]       // src_addr
    mov edi, [0x7F0C]       // dst_addr
    mov ecx, [0x7F10]       // copy_size

    // Do the copy
    test ecx, ecx
    jz copy_done
    cld
    rep movsb

copy_done:
    // Zero BSS
    mov ecx, [0x7F14]       // bss_size
    test ecx, ecx
    jz bss_done
    xor eax, eax
    rep stosb
    
bss_done:
    // Load entry point and coreboot table pointer
    mov eax, [0x7F04]       // entry_point
    mov ebx, [0x7F00]       // coreboot_table_ptr

    // Jump to payload!
    jmp eax

trampoline_end:
    .previous
"#
);

unsafe extern "C" {
    static trampoline_start: u8;
    static trampoline_end: u8;
}

/// Get the trampoline code as a byte slice
fn get_trampoline_code() -> &'static [u8] {
    unsafe {
        let start = &trampoline_start as *const u8;
        let end = &trampoline_end as *const u8;
        let len = end.offset_from(start) as usize;
        core::slice::from_raw_parts(start, len)
    }
}

/// Allocate a bounce buffer using EFI page allocator
///
/// Uses the EFI page allocator to allocate large buffers that wouldn't fit
/// in the Rust heap. The buffer is allocated as BootServicesData.
///
/// # Arguments
///
/// * `size` - Size of the bounce buffer needed
///
/// # Returns
///
/// Allocated buffer as a raw slice, or None if allocation fails.
/// The caller is responsible for not freeing this memory (use `core::mem::forget`).
pub fn allocate_bounce_buffer(size: usize) -> Option<&'static mut [u8]> {
    use crate::efi::allocator::{allocate_pages, AllocateType, MemoryType, PAGE_SIZE};

    // Round up to pages
    let num_pages = (size as u64 + PAGE_SIZE - 1) / PAGE_SIZE;

    let mut addr = 0u64;
    let status = allocate_pages(
        AllocateType::AllocateAnyPages,
        MemoryType::BootServicesData,
        num_pages,
        &mut addr,
    );

    if status != r_efi::efi::Status::SUCCESS {
        log::error!(
            "Failed to allocate bounce buffer: {} pages, status={:?}",
            num_pages,
            status
        );
        return None;
    }

    log::debug!(
        "Allocated bounce buffer: {:#x}-{:#x} ({} bytes, {} pages)",
        addr,
        addr + size as u64,
        size,
        num_pages
    );

    // Create a mutable slice from the allocated memory
    let buffer = unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, size) };

    Some(buffer)
}

/// Set up and execute the relocation trampoline
///
/// This function:
/// 1. Copies the trampoline code to TRAMPOLINE_ADDR
/// 2. Disables interrupts
/// 3. Jumps to the trampoline with parameters in registers (never returns)
///
/// # Arguments
///
/// * `params` - Trampoline parameters (addresses, sizes, entry point)
///
/// # Safety
///
/// This function never returns. It will overwrite memory at `dst_addr`
/// and jump to `entry_point`. The caller must ensure:
/// - The bounce buffer contains valid payload data
/// - The target address is valid and writable
/// - The entry point is valid executable code
/// - The trampoline address (0x8000) is not in use
///
/// # Returns
///
/// This function never returns on success. Returns an error if the
/// trampoline code is too large.
pub unsafe fn execute_trampoline(params: &TrampolineParams) -> Result<!, TrampolineError> {
    log::info!("Setting up relocation trampoline:");
    log::info!("  src:    {:#x} (bounce buffer)", params.src_addr);
    log::info!("  dst:    {:#x} (target)", params.dst_addr);
    log::info!("  copy:   {} bytes", params.copy_size);
    log::info!("  bss:    {} bytes", params.bss_size);
    log::info!("  entry:  {:#x}", params.entry_point);

    // Get the trampoline code
    let code = get_trampoline_code();

    if code.len() > TRAMPOLINE_MAX_SIZE {
        log::error!(
            "Trampoline code too large: {} bytes (max {})",
            code.len(),
            TRAMPOLINE_MAX_SIZE
        );
        return Err(TrampolineError::CodeTooLarge);
    }

    log::debug!("Trampoline code: {} bytes", code.len());

    // Copy trampoline code to fixed address
    let trampoline_ptr = TRAMPOLINE_ADDR as *mut u8;
    core::ptr::copy_nonoverlapping(code.as_ptr(), trampoline_ptr, code.len());

    log::info!("Jumping to trampoline at {:#x}...", TRAMPOLINE_ADDR);

    // Disable interrupts and jump to trampoline with parameters in registers
    // Parameters: rdi=src, rsi=dst, rdx=copy_size, rcx=bss_size, r8=entry, r9=cbtable
    core::arch::asm!(
        "cli",
        "jmp {trampoline}",
        trampoline = in(reg) TRAMPOLINE_ADDR,
        in("rdi") params.src_addr,
        in("rsi") params.dst_addr,
        in("rdx") params.copy_size,
        in("rcx") params.bss_size,
        in("r8") params.entry_point,
        in("r9") params.coreboot_table_ptr,
        options(noreturn)
    );
}

/// Trampoline errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrampolineError {
    /// Generated trampoline code exceeds maximum size
    CodeTooLarge,
    /// Failed to allocate bounce buffer
    AllocationFailed,
}

//! AArch64 entry point for CrabEFI
//!
//! On QEMU SBSA with coreboot, the payload is called directly at EL2:
//!   - x0 = pointer to coreboot table
//!   - MMU state is whatever coreboot left (may be on or off)
//!   - Stack needs to be set up by us
//!
//! If the MMU is off at EL2 (as on QEMU virt after TF-A), we set up
//! a simple identity map with 1GB block descriptors before proceeding.

use core::arch::global_asm;

global_asm!(
    r#"
.section .text.entry, "ax"

.global _start
_start:
    // x0 = coreboot table pointer (passed by coreboot)
    // Save it in a callee-saved register
    mov x19, x0

    // Install our exception vector table FIRST, before anything else.
    // Coreboot's VBAR_EL2 points to ramstage memory that will be reused.
    adrp x1, exception_vectors
    add x1, x1, :lo12:exception_vectors
    msr VBAR_EL2, x1
    isb

    // Check if EL2 MMU is already enabled (SCTLR_EL2.M, bit 0)
    mrs x1, SCTLR_EL2
    tbnz x1, #0, .Lmmu_done

    // -----------------------------------------------------------------
    // MMU is off — set up identity-mapped page tables at EL2.
    //
    // Strategy: use 1GB block descriptors in L1 table.
    //   - L0[0] -> L1 table (covers first 512 GB)
    //   - L1[0]    = Device-nGnRnE (I/O space 0x00000000 - 0x3FFFFFFF)
    //   - L1[1..3] = Normal WB      (DRAM 0x40000000 - 0xFFFFFFFF)
    //   - L1[4..511] = Normal WB    (higher addresses, covers 64-bit BARs etc.)
    //
    // MAIR_EL2:
    //   Attr0 = 0x00 (Device-nGnRnE)
    //   Attr1 = 0xFF (Normal, Inner/Outer WB-WA)
    // -----------------------------------------------------------------

    // Set MAIR_EL2
    mov x1, #0xFF00             // Attr1=0xFF (Normal WB), Attr0=0x00 (Device)
    msr MAIR_EL2, x1

    // Set TCR_EL2: T0SZ=16 (48-bit VA), 4KB granule, Inner/Outer WB-WA cacheable
    //  T0SZ  = 16 (bits [5:0])
    //  IRGN0 = 01 (bits [9:8]  = WB-WA-RA)
    //  ORGN0 = 01 (bits [11:10] = WB-WA-RA)
    //  SH0   = 11 (bits [13:12] = Inner Shareable)
    //  TG0   = 00 (bits [15:14] = 4KB granule)
    //  PS    = 100 (bits [18:16] = 44-bit PA) — enough for 16TB
    // TCR_EL2: PS=100 (44-bit PA), SH0=11, ORGN0=01, IRGN0=01, T0SZ=16
    // = 0x80843510
    mov x1, #0x3510
    movk x1, #0x8084, lsl #16
    msr TCR_EL2, x1
    isb

    // Zero all page tables (L0 + 4 x L1 = 5 pages = 5 * 512 = 2560 entries)
    adrp x2, _el2_l0_table
    add x2, x2, :lo12:_el2_l0_table
    mov x3, #(5 * 512)
.Lzero_pt:
    str xzr, [x2], #8
    subs x3, x3, #1
    b.ne .Lzero_pt

    // Set up L0[0..3] -> L1 tables (covering 0 - 2 TB)
    // Block descriptor bits:
    //   [0]    = 1 (valid)
    //   [1]    = 0 (block, not table)
    //   [4:2]  = AttrIndx (0=Device, 1=Normal)
    //   [7:6]  = AP (01 = EL2 RW)
    //   [9:8]  = SH (11 = Inner Shareable for Normal, 10 for Device)
    //   [10]   = AF (Access Flag = 1)
    //   [47:30]= output address (1GB aligned)
    //
    // Device block: AttrIndx=0, SH=10, AF=1, AP=01 -> 0x641
    // Normal block: AttrIndx=1, SH=11, AF=1, AP=01 -> 0x705

    adrp x10, _el2_l0_table
    add x10, x10, :lo12:_el2_l0_table
    adrp x11, _el2_l1_table
    add x11, x11, :lo12:_el2_l1_table

    // L0[i] = &L1_tables[i] | 0x3 (table descriptor)
    mov x3, #4                  // 4 L0 entries
    mov x2, x10                 // L0 base
    mov x4, x11                 // L1 tables base
.Lfill_l0:
    orr x5, x4, #0x3            // Valid + Table descriptor
    str x5, [x2], #8
    add x4, x4, #4096           // Next L1 table
    subs x3, x3, #1
    b.ne .Lfill_l0

    // Fill all 4 L1 tables with 1GB block descriptors.
    // Total: 4 * 512 = 2048 entries covering 0 - 2 TB.
    // L1[0] of the first table is Device (I/O below 1GB), rest Normal WB.
    mov x2, x11                 // Start of L1 tables
    mov x5, xzr                 // Current physical address = 0
    mov x6, #0x40000000         // 1GB increment

    // First entry: Device block for 0x0 - 0x3FFFFFFF (I/O space)
    mov x4, #0x641              // Device-nGnRnE
    str x4, [x2], #8
    add x5, x5, x6

    // Entries 1..511 (1GB - 512GB): Normal WB (covers DRAM)
    mov x3, #511
.Lfill_l1_normal:
    mov x4, #0x705              // Normal WB block attrs
    orr x4, x4, x5              // | output address
    str x4, [x2], #8
    add x5, x5, x6
    subs x3, x3, #1
    b.ne .Lfill_l1_normal

    // Entries 512..2047 (512GB - 2TB): Device (covers high MMIO, ECAM, PCI BARs)
    mov x3, #(3 * 512)
.Lfill_l1_device:
    mov x4, #0x641              // Device-nGnRnE block
    orr x4, x4, x5              // | output address
    str x4, [x2], #8
    add x5, x5, x6
    subs x3, x3, #1
    b.ne .Lfill_l1_device

    // Set TTBR0_EL2 to L0 table
    msr TTBR0_EL2, x10
    isb

    // Enable MMU via SCTLR_EL2
    // Set M (bit 0), C (bit 2), I (bit 12) — enable MMU, data cache, instruction cache
    // Also set SA (bit 3) for stack alignment check
    mrs x1, SCTLR_EL2
    orr x1, x1, #(1 << 0)      // M  = MMU enable
    orr x1, x1, #(1 << 2)      // C  = Data cache enable
    orr x1, x1, #(1 << 12)     // I  = Instruction cache enable
    bic x1, x1, #(1 << 1)      // A  = Alignment check DISABLE
    bic x1, x1, #(1 << 19)     // WXN = Write-Execute-Never DISABLE
    msr SCTLR_EL2, x1
    isb

.Lmmu_done:

    // Set up the stack pointer
    adrp x1, _stack_top
    add x1, x1, :lo12:_stack_top
    mov sp, x1

    // Zero BSS section
    adrp x1, _bss_start
    add x1, x1, :lo12:_bss_start
    adrp x2, _bss_end
    add x2, x2, :lo12:_bss_end
    cmp x1, x2
    b.ge 2f
1:
    stp xzr, xzr, [x1], #16
    cmp x1, x2
    b.lt 1b
2:

    // Restore coreboot table pointer as first argument
    mov x0, x19

    // Call Rust entry point
    bl rust_main

    // Should not return, but halt if it does
3:
    wfe
    b 3b
"#
);

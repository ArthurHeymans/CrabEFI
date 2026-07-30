/* CrabEFI Linker Script for aarch64 coreboot payload */

OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

/*
 * Coreboot loads payloads via selfload, which places ELF segments at their
 * specified load addresses. PAYLOAD_BASE is provided at build time via
 * --defsym from build.rs (set PAYLOAD_BASE env var, or uses default).
 *
 * QEMU SBSA:    0x100_2200_0000 (DRAM at 1TB, above coreboot ramstage)
 * QEMU aarch64: 0x6200_0000     (DRAM at 1GB, above coreboot ramstage)
 */

SECTIONS
{
    . = PAYLOAD_BASE;

    /* Text section - executable code */
    .text : ALIGN(65536) {
        _text_start = .;
        KEEP(*(.text.entry))
        *(.text .text.*)
        _text_end = .;
    }

    /* Exception vector table - must be 2KB aligned, part of code */
    .vectors : ALIGN(2048) {
        _vectors_start = .;
        KEEP(*(.vectors))
        _vectors_end = .;
    }

    /* Runtime code boundaries (for UEFI memory map) */
    __runtime_code_start = _text_start;
    __runtime_code_end = _vectors_end;

    /* Runtime data starts here - everything non-executable */
    __runtime_data_start = .;

    /* Read-only data */
    .rodata : ALIGN(65536) {
        _rodata_start = .;
        *(.rodata .rodata.*)
        _rodata_end = .;
    }

    /* Global Offset Table (PIC indirect calls) */
    .got : ALIGN(8) {
        _got_start = .;
        *(.got .got.*)
        _got_end = .;
    }

    /* Initialized data */
    .data : ALIGN(65536) {
        _data_start = .;
        *(.data .data.*)
        _data_end = .;
    }

    /* Uninitialized data (BSS) */
    .bss : ALIGN(65536) {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;
    }

    /* Pointer-free state reached through the single SVAM-converted root. */
    .runtime_state (NOLOAD) : ALIGN(4096) {
        _runtime_state_start = .;
        KEEP(*(.runtime_state))
        . = ALIGN(8);
        _runtime_state_end = .;
    }

    /* Stack - 4MB; boot-only FirmwareState lives here. */
    .stack (NOLOAD) : ALIGN(65536) {
        _stack_bottom = .;
        . += 0x400000;
        _stack_top = .;
    }

    /* EL2 page tables for MMU setup (when coreboot doesn't set up EL2 MMU).
     * L0: 1 page (512 entries x 512GB = 256TB)
     * L1: 4 pages (covering L0[0]-L0[3] = 0-2TB, using 1GB block descriptors)
     */
    .page_tables (NOLOAD) : ALIGN(4096) {
        _el2_l0_table = .;
        . += 4096;
        _el2_l1_table = .;
        . += 4096 * 4;
    }

    /* Exception handler stack - 16KB (separate to avoid corruption) */
    .exc_stack (NOLOAD) : ALIGN(4096) {
        _exc_stack_bottom = .;
        . += 0x4000;
        _exc_stack_top = .;
    }

    /* Deferred variable buffer - 64KB
     * Used for queuing variable writes after ExitBootServices.
     * Included in runtime data region so OS preserves the mapping.
     */
    .deferred_buffer (NOLOAD) : ALIGN(4096) {
        _deferred_buffer_start = .;
        . += 64K;
        _deferred_buffer_end = .;
    }

    /* Runtime data ends here */
    __runtime_data_end = .;

    _end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.debug*)
        *(.ARM.exidx*)
        *(.ARM.extab*)
    }
}

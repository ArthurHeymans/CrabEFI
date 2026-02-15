/* CrabEFI Linker Script for aarch64 coreboot payload (QEMU SBSA) */

OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

/*
 * Coreboot loads payloads via selfload, which places ELF segments at their
 * specified load addresses. On QEMU SBSA, DRAM starts at 0x100_0000_0000.
 * We place the payload well above coreboot's own regions (ramstage ends
 * around 0x100_210B_0000) to avoid overlap.
 *
 * Address chosen: 0x100_2200_0000 (in DRAM, above coreboot's reserved areas)
 */
PAYLOAD_BASE = 0x10022000000;

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

    /* Stack - 3MB (increased from 2MB for large structs like FirmwareState) */
    .stack (NOLOAD) : ALIGN(65536) {
        _stack_bottom = .;
        . += 0x300000;
        _stack_top = .;
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

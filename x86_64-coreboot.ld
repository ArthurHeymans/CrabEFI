/* CrabEFI Linker Script for x86_64 coreboot payload */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

/* Coreboot loads payloads at a configurable address, typically 0x100000 (1MB) */
PAYLOAD_BASE = 0x100000;

SECTIONS
{
    . = PAYLOAD_BASE;
    
    /* Runtime code starts here - everything executable */
    __runtime_code_start = .;
    
    /* 32-bit entry code - must be first */
    .entry32 : ALIGN(4096) {
        *(.entry32)
    }

    /* Text section */
    .text : ALIGN(4096) {
        _text_start = .;
        *(.text .text.*)
        _text_end = .;
    }
    
    /* Runtime code ends here */
    __runtime_code_end = .;

    /* Runtime data starts here - everything non-executable */
    __runtime_data_start = .;

    /* Read-only data */
    .rodata : ALIGN(4096) {
        _rodata_start = .;
        *(.rodata .rodata.*)
        _rodata_end = .;
    }

    /* Global Offset Table (PIC indirect calls to memcpy/memset/etc.)
     * These entries contain absolute addresses that must be relocated
     * during SetVirtualAddressMap. */
    .got : ALIGN(8) {
        _got_start = .;
        *(.got .got.*)
        _got_end = .;
    }

    /* Initialized data */
    .data : ALIGN(4096) {
        _data_start = .;
        *(.data .data.*)
        _data_end = .;
    }

    /* Page tables - must be 4KB aligned */
    .page_tables : ALIGN(4096) {
        _page_tables_start = .;
        *(.page_tables)
        _page_tables_end = .;
    }

    /* Uninitialized data (BSS) */
    .bss : ALIGN(4096) {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;
    }

    /* Stack - 256KB (increased from 64KB for large structs) */
    .stack : ALIGN(4096) {
        _stack_bottom = .;
        . += 0x200000;
        _stack_top = .;
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

    /* Runtime data ends here (after BSS, stack, and deferred buffer) */
    __runtime_data_end = .;

    _end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.debug*)
    }
}

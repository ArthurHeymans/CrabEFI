/* CrabEFI Linker Script for x86_64 coreboot payload */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

/* Coreboot loads payloads at a configurable address, typically 0x100000 (1MB) */
PAYLOAD_BASE = 0x100000;

SECTIONS
{
    . = PAYLOAD_BASE;
    
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

    /* Read-only data */
    .rodata : ALIGN(4096) {
        _rodata_start = .;
        *(.rodata .rodata.*)
        _rodata_end = .;
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

    /* Stack - 64KB */
    .stack : ALIGN(4096) {
        _stack_bottom = .;
        . += 0x10000;
        _stack_top = .;
    }

    _end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.debug*)
    }
}

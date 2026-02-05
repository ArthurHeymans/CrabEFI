/* CrabEFI Linker Script for x86_64 coreboot payload */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

/* Coreboot loads payloads at a configurable address, typically 0x100000 (1MB) */
PAYLOAD_BASE = 0x100000;

/* Define program headers explicitly to separate LOAD and NOLOAD sections */
PHDRS
{
    text PT_LOAD FLAGS(5);   /* R-X */
    rodata PT_LOAD FLAGS(4); /* R-- */
    data PT_LOAD FLAGS(6);   /* RW- */
    bss PT_NULL FLAGS(6);    /* RW- but not loaded from file */
}

SECTIONS
{
    . = PAYLOAD_BASE;
    
    /* Runtime code starts here - everything executable */
    __runtime_code_start = .;
    
    /* 32-bit entry code - must be first */
    .entry32 : ALIGN(4096) {
        *(.entry32)
    } :text

    /* Text section */
    .text : ALIGN(4096) {
        _text_start = .;
        *(.text .text.*)
        _text_end = .;
    } :text
    
    /* Runtime code ends here */
    __runtime_code_end = .;

    /* Runtime data starts here - everything non-executable */
    __runtime_data_start = .;

    /* Read-only data */
    .rodata : ALIGN(4096) {
        _rodata_start = .;
        *(.rodata .rodata.*)
        _rodata_end = .;
    } :rodata

    /* GOT - must be writable for dynamic linking (even though we don't use it) */
    .got : ALIGN(8) {
        *(.got .got.*)
    } :data

    /* Initialized data */
    .data : ALIGN(4096) {
        _data_start = .;
        *(.data .data.*)
        _data_end = .;
    } :data

    /* Page tables - must be 4KB aligned */
    .page_tables : ALIGN(4096) {
        _page_tables_start = .;
        *(.page_tables)
        _page_tables_end = .;
    } :data

    /* Uninitialized data (BSS) - PT_NULL means no LOAD segment */
    .bss (NOLOAD) : ALIGN(4096) {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;
    } :bss

    /* Stack - 2MB */
    .stack (NOLOAD) : ALIGN(4096) {
        _stack_bottom = .;
        . += 0x200000;
        _stack_top = .;
    } :bss

    /* Runtime data ends here (after BSS and stack) */
    __runtime_data_end = .;

    /* Deferred variable buffer - 64KB
     * Used for queuing variable writes after ExitBootServices.
     * This region should survive warm reboot on most hardware.
     * Mark as EfiReservedMemoryType in the memory map.
     */
    .deferred_buffer (NOLOAD) : ALIGN(4096) {
        _deferred_buffer_start = .;
        . += 64K;
        _deferred_buffer_end = .;
    } :bss

    _end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.debug*)
    }
}

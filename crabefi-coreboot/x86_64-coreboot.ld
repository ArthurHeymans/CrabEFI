/* Boot-lifetime CrabEFI x86_64 coreboot payload. */
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)
PROVIDE(__payload_base = 0x100000);

PHDRS {
    code PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
    defer PT_NULL FLAGS(0);
}

SECTIONS {
    . = __payload_base;
    __boot_code_start = .;
    .entry32 : ALIGN(4096) { *(.entry32) } :code
    .text : ALIGN(4096) {
        _text_start = .;
        *(.text .text.*)
        _text_end = .;
    } :code
    __boot_code_end = .;

    __boot_data_start = .;
    .rodata : ALIGN(4096) {
        _rodata_start = .;
        *(.rodata .rodata.*)
        _rodata_end = .;
    } :rodata
    .got : ALIGN(8) { *(.got .got.*) } :rodata
    .data : ALIGN(4096) {
        _data_start = .;
        *(.data .data.*)
        _data_end = .;
    } :data
    .page_tables : ALIGN(4096) {
        _page_tables_start = .;
        *(.page_tables)
        _page_tables_end = .;
    } :data
    .bss : ALIGN(4096) {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;
    } :data
    .stack : ALIGN(4096) {
        _stack_bottom = .;
        . += 0x100000;
        _stack_top = .;
    } :data
    __boot_data_end = .;
    _end = .;

    /* Excluded from payload loading; coreboot reserves it through the stable
       CapsuleUpdateData reservation capsule before optional DRAM clearing. */
    .deferred_buffer ALIGN(4096) (NOLOAD) : {
        _deferred_buffer_start = .;
        . += 64K;
        _deferred_buffer_end = .;
    } :defer

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.debug*) }
}

/* Boot-lifetime CrabEFI AArch64 coreboot payload. */
OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

PHDRS {
    code PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
    defer PT_NULL FLAGS(0);
}

SECTIONS {
    . = PAYLOAD_BASE;
    __boot_code_start = .;
    .text : ALIGN(65536) {
        _text_start = .;
        KEEP(*(.text.entry))
        *(.text .text.*)
        _text_end = .;
    } :code
    .vectors : ALIGN(2048) {
        _vectors_start = .;
        KEEP(*(.vectors))
        _vectors_end = .;
    } :code
    __boot_code_end = .;

    __boot_data_start = .;
    .rodata : ALIGN(65536) {
        _rodata_start = .;
        *(.rodata .rodata.*)
        _rodata_end = .;
    } :rodata
    .got : ALIGN(8) { *(.got .got.*) } :rodata
    .data : ALIGN(65536) {
        _data_start = .;
        *(.data .data.*)
        _data_end = .;
    } :data
    .bss : ALIGN(65536) {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;
    } :data
    .stack (NOLOAD) : ALIGN(65536) {
        _stack_bottom = .;
        . += 0x100000;
        _stack_top = .;
    } :data
    .page_tables (NOLOAD) : ALIGN(4096) {
        _el2_l0_table = .;
        . += 4096;
        _el2_l1_table = .;
        . += 4096 * 4;
    } :data
    .exc_stack (NOLOAD) : ALIGN(4096) {
        _exc_stack_bottom = .;
        . += 0x4000;
        _exc_stack_top = .;
    } :data
    __boot_data_end = .;
    _end = .;

    /* Warm-reset retained and excluded from the payload's PT_LOAD extent. */
    .deferred_buffer (NOLOAD) : ALIGN(4096) {
        _deferred_buffer_start = .;
        . += 64K;
        _deferred_buffer_end = .;
    } :defer

    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.debug*) *(.ARM.exidx*) *(.ARM.extab*) }
}

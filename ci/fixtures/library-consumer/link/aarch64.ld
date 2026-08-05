OUTPUT_FORMAT("elf64-littleaarch64")
OUTPUT_ARCH(aarch64)
ENTRY(_start)

SECTIONS {
    . = 0x40000000;
    .text : ALIGN(4096) { *(.text .text.*) }
    .vectors : ALIGN(2048) { KEEP(*(.vectors)) }
    .rodata : ALIGN(4096) { *(.rodata .rodata.*) }
    .got : ALIGN(8) { *(.got .got.*) }
    .data : ALIGN(4096) { *(.data .data.*) }
    .bss (NOLOAD) : ALIGN(4096) { *(.bss .bss.*) *(COMMON) }
    .deferred_buffer (NOLOAD) : ALIGN(4096) { *(.deferred_buffer) }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.debug*) *(.ARM.exidx*) *(.ARM.extab*) }
}
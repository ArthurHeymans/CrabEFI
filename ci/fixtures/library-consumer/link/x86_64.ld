OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS {
    . = 0x100000;
    .text : ALIGN(4096) { *(.text .text.*) }
    .rodata : ALIGN(4096) { *(.rodata .rodata.*) }
    .got : ALIGN(8) { *(.got .got.*) }
    .data : ALIGN(4096) { *(.data .data.*) }
    .bss (NOLOAD) : ALIGN(4096) { *(.bss .bss.*) *(COMMON) }
    .deferred_buffer (NOLOAD) : ALIGN(4096) { *(.deferred_buffer) }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.debug*) }
}
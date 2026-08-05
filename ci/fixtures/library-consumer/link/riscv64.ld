OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS {
    . = 0x81000000;
    .text : ALIGN(4096) { *(.text .text.*) }
    .rodata : ALIGN(4096) { *(.rodata .rodata.*) }
    .got : ALIGN(8) { *(.got .got.*) }
    .data : ALIGN(4096) { *(.data .data.*) *(.sdata .sdata.*) }
    .bss (NOLOAD) : ALIGN(4096) { *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON) }
    .deferred_buffer (NOLOAD) : ALIGN(4096) { *(.deferred_buffer) }
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.debug*) *(.riscv.attributes) }
}
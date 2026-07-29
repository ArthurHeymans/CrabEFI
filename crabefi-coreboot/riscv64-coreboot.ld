/* CrabEFI Linker Script for RISC-V 64-bit coreboot payload
 *
 * RISC-V runs in S-mode (Supervisor mode) under OpenSBI.
 * No MMU (satp=0) — identity-mapped physical memory.
 *
 * QEMU virt: DRAM starts at 0x80000000.
 * PAYLOAD_BASE is provided at build time via --defsym from build.rs.
 * Default: 0x81000000 (16MB into DRAM, above coreboot data areas).
 */

OUTPUT_FORMAT("elf64-littleriscv")
OUTPUT_ARCH(riscv)
ENTRY(_start)

SECTIONS
{
    . = PAYLOAD_BASE;

    /* Text section — executable code */
    .text : ALIGN(4096) {
        _text_start = .;
        KEEP(*(.text.entry))
        *(.text .text.*)
        _text_end = .;
    }

    /* Runtime code boundaries (for UEFI memory map) */
    __runtime_code_start = _text_start;
    __runtime_code_end = _text_end;

    /* Runtime data starts here — everything non-executable */
    __runtime_data_start = .;

    /* Read-only data */
    .rodata : ALIGN(4096) {
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
    .data : ALIGN(4096) {
        _data_start = .;
        *(.data .data.*)
        *(.sdata .sdata.*)
        _data_end = .;
    }

    /* Small BSS (RISC-V uses .sbss for small objects) */
    .bss : ALIGN(4096) {
        _bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        _bss_end = .;
    }

    /* Stack — 4MB; FirmwareState carries the EFI tables inline (see x86_64 script). */
    .stack (NOLOAD) : ALIGN(4096) {
        _stack_bottom = .;
        . += 0x400000;
        _stack_top = .;
    }

    /* Deferred variable buffer — 64KB
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
        *(.riscv.attributes)
    }
}

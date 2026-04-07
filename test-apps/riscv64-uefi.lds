/* Linker script for RISC-V UEFI test applications.
 *
 * Rust has no riscv64gc-unknown-uefi target, so test apps are built as ELF
 * with riscv64gc-unknown-none-elf and post-processed to PE/COFF.  This script
 * ensures the ELF entry point is efi_main so that objcopy carries it into
 * the PE/COFF AddressOfEntryPoint field.
 */
ENTRY(efi_main);

SECTIONS
{
    . = 0;

    .text : { *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data : { *(.data .data.*) }
    .got : { *(.got .got.*) }
    .bss : { *(.bss .bss.* COMMON) }

    /DISCARD/ : {
        *(.eh_frame*)
        *(.note*)
        *(.comment*)
        *(.riscv.attributes*)
    }
}

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(crabefi_mm_init)

PHDRS
{
  text    PT_LOAD FLAGS(7);
  dynamic PT_DYNAMIC FLAGS(6);
}

/* One RWX load segment from offset 0: coreboot copies the image into SMRAM as one
   flat blob and SMM runs on coreboot's identity map without per-page permissions. */
SECTIONS
{
  . = 0;
  .text : ALIGN(16) { KEEP(*(.text.crabefi_mm_entry)) *(.text .text.*) } :text
  .rodata : ALIGN(16) { *(.rodata .rodata.*) } :text
  .data : ALIGN(16) { *(.data .data.* .data.rel.ro .data.rel.ro.*) *(.got .got.*) } :text
  .dynamic : { *(.dynamic) } :text :dynamic
  .bss : ALIGN(4096) { *(.bss .bss.*) *(COMMON) } :text
  .rela.dyn (INFO) : { *(.rela.dyn .rela.plt) }
  /DISCARD/ : { *(.eh_frame*) *(.comment*) *(.note*) *(.interp) *(.gnu.hash) *(.hash) *(.dynsym) *(.dynstr) }
}

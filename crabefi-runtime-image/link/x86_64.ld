OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(runtime_image_init)

PHDRS
{
  text    PT_LOAD FLAGS(5);
  rodata  PT_LOAD FLAGS(4);
  data    PT_LOAD FLAGS(6);
  dynamic PT_DYNAMIC FLAGS(6);
}

SECTIONS
{
  . = 0x1000;
  .text : ALIGN(0x1000)
  {
    KEEP(*(.text.runtime_image_*))
    *(.text .text.*)
    *(.plt .plt.*)
  } :text

  . = ALIGN(0x1000);
  .rodata :
  {
    *(.rodata .rodata.* .rodata.cst*)
  } :rodata

  . = ALIGN(0x1000);
  .data :
  {
    *(.data .data.* .data.rel.ro .data.rel.ro.*)
    *(.got .got.* .got.plt .got.plt.*)
  } :data

  .dynamic : { *(.dynamic) } :data :dynamic
  .bss (NOLOAD) : ALIGN(16)
  {
    *(.bss .bss.*)
    *(COMMON)
  } :data

  /* The boot loader consumes relocations from the ELF; the image itself does
     not. Keep them in the file without charging a RuntimeServicesData page. */
  .rela.dyn (INFO) : { *(.rela.dyn .rela.plt) }

  /DISCARD/ :
  {
    *(.eh_frame*)
    *(.comment*)
    *(.note*)
    *(.interp)
    *(.gnu.hash)
    *(.hash)
    *(.dynsym)
    *(.dynstr)
    *(.gnu.version*)
  }
  .orphan_alloc (INFO) :
  {
    *(.init .fini .preinit_array* .init_array* .fini_array* .tdata* .tbss*)
  }
  ASSERT(SIZEOF(.orphan_alloc) == 0, "unexpected allocated runtime-image section")
}

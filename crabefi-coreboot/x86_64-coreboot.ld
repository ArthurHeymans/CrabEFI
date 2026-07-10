/* CrabEFI Linker Script for x86_64 coreboot payload */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

/* Coreboot loads payloads at a configurable address, defaulting to 0x100000 (1MB). */
PROVIDE(__payload_base = 0x100000);

/*
 * Explicit program headers so the deferred variable buffer is NOT in any
 * PT_LOAD segment.  Without this, lld merges the NOLOAD section into the
 * preceding data segment and coreboot/cbfstool zeroes its contents on
 * every boot, destroying the buffer that must survive warm reboot.
 */
PHDRS
{
    code   PT_LOAD FLAGS(5);   /* R-X */
    rodata PT_LOAD FLAGS(4);   /* R-- */
    relro  PT_LOAD FLAGS(4);   /* R-- (GNU_RELRO covered separately by lld) */
    data   PT_LOAD FLAGS(6);   /* RW- */
    defer  PT_NULL FLAGS(6);   /* NOT loaded -- survives warm reboot */
    rtlog  PT_NULL FLAGS(6);   /* Runtime services log -- survives warm reboot */
}

SECTIONS
{
    /* ── Deferred variable buffer ─────────────────────────────────────
     *
     * 64 KB at a fixed address BELOW the payload load region.
     *
     *   • NOLOAD + PT_NULL: neither the linker, cbfstool, nor coreboot's
     *     ELF/SELF loader will write to this region.
     *   • 0x80000 sits above coreboot's SMM temp modules (0x30000-0x38000)
     *     and the 32-bit entry trampoline (~0x9000), and below the legacy
     *     video area (0xA0000).
     *   • On warm reboot the RAM content is preserved, so pending variable
     *     writes queued here after ExitBootServices survive into the next
     *     boot cycle.
     *   • Registered as RuntimeServicesData by reserve_runtime_region() so
     *     the OS keeps the mapping and SetVirtualAddressMap adjusts the
     *     GOT entry for _deferred_buffer_start.
     */
    /* ── Runtime services log buffer ─────────────────────────────────
     *
     * 64 KB at 0x70000 — same survival properties as .deferred_buffer.
     * SetVariable and other runtime paths append plain-text lines here.
     * On the next boot the contents are emitted to the coreboot log so
     * we can see exactly what the OS did at runtime.
     */
    .rt_log 0x70000 (NOLOAD) : {
        _rt_log_start = .;
        . += 64K;
        _rt_log_end = .;
    } :rtlog

    .deferred_buffer 0x80000 (NOLOAD) : {
        _deferred_buffer_start = .;
        . += 64K;
        _deferred_buffer_end = .;
    } :defer

    /* ── Payload proper ───────────────────────────────────────────── */
    . = __payload_base;
    
    /* Runtime code starts here - everything executable */
    __runtime_code_start = .;
    
    /* 32-bit entry code - must be first */
    .entry32 : ALIGN(4096) {
        *(.entry32)
    } :code

    /* Text section */
    .text : ALIGN(4096) {
        _text_start = .;
        *(.text .text.*)
        _text_end = .;
    } :code
    
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

    /* Global Offset Table (PIC indirect calls to memcpy/memset/etc.)
     * These entries contain absolute addresses that must be relocated
     * during SetVirtualAddressMap. */
    .got : ALIGN(8) {
        _got_start = .;
        *(.got .got.*)
        _got_end = .;
    } :relro

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

    /* Uninitialized data (BSS) */
    .bss : ALIGN(4096) {
        _bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        _bss_end = .;
    } :data

    /* Stack - 1MB; variable payloads are heap-backed. */
    .stack : ALIGN(4096) {
        _stack_bottom = .;
        . += 0x100000;
        _stack_top = .;
    } :data

    /* Runtime data ends here */
    __runtime_data_end = .;

    _end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
        *(.debug*)
    }
}

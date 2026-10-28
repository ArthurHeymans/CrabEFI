# x86-64 payload entry ABI, version 1

CrabEFI's x86 payload has a **64-bit-only** entry point. It does not contain a
protected-mode entry or a 32-to-64-bit transition. The previous coreboot ABI,
which passed an argument on a 32-bit stack, is not supported.

## Caller contract

The caller jumps or calls the ELF entry `_start` with:

- Ring 0 long mode active, paging enabled, interrupts disabled, and PCID and
  CET disabled. Four-level and five-level paging are both supported; entry
  preserves the incoming `CR4.LA57` setting rather than toggling paging.
- All `PT_LOAD` segments loaded at their physical addresses, with zero-filled
  tails as specified by ELF. Physical and virtual segment addresses must match.
  The caller must identity-map the complete segments, including writable page
  tables, BSS, and stack. They must be within the first 64 GiB.
- `RDI` holding the **full 64-bit physical address** of the coreboot table.
  The table and everything it references must remain valid and accessible.
  In particular, firmware RAM must not include the handoff table's storage.

No caller stack, GDT, segment selectors, or general-purpose register contents
other than RDI are retained. Entry clears DF, preserves RDI in R12, establishes
its own stack, initializes its own page tables, installs its GDT, clears BSS,
enables SSE/NX, and calls `rust_main(RDI)`. It never leaves long mode. The
payload does not return.

The new page tables identity-map the first 64 GiB using 2-MiB pages. An extra
PML5 is used when the caller has five-level paging enabled. Page tables are
outside BSS so clearing BSS cannot destroy the active address space.

## ELF identification

The ELF has an allocated `.note.crabefi` section in a `PT_NOTE` program header:

| Field | Value |
| --- | --- |
| `namesz` | 8 |
| `descsz` | 4 |
| `type` | 1 (entry ABI version) |
| owner | `CrabEFI` followed by NUL |
| descriptor | little-endian `uint32` value 1 |

Names and descriptors use standard ELF note four-byte alignment. Consumers
should inspect program headers, not require section or symbol tables. Other
ELF notes may coexist with this one. `ELFCLASS64` alone is insufficient: the
old payload was also an ELF64 file, but its entry executed 32-bit instructions.
Loaders must reject missing or unsupported ABI versions rather than attempting
a compatibility transition.

## LinuxBoot / u-root

Use u-root's native `boot.CrabEFIImage` implementation with support for this
note. Its kexec entry stub executes `cli; cld`, loads RDI with the coreboot table
address, loads RAX with the ELF entry, and jumps to RAX. Both operands are
64-bit immediates. There is no Multiboot header, external Rust launcher, or
32-bit trampoline in this path.

u-root still owns image loading, filesystem cleanup, and `kexec` execution.
The first kernel must expose the firmware map, ACPI, SMBIOS and a physical
framebuffer; see u-root's `pkg/boot/crabefi/README.md` for those requirements.

## Direct coreboot integration

Upstream coreboot currently forces payloads back into protected mode, even
when ramstage itself is 64-bit. Running only ramstage in long mode is therefore
**not sufficient** for this payload.

Apply [`firmware/coreboot-x86_64-payload.patch`](../firmware/coreboot-x86_64-payload.patch)
and enable `CONFIG_USE_X86_64_SUPPORT=y` and `CONFIG_PAYLOAD_X86_64=y`.
This keeps the payload call in long mode with the argument in RDI. There is no
fallback to the old ABI. A firmware rebuild is mandatory; replacing only the
payload in an old 32-bit-caller ROM will not work.

The Q35 test fixture and x86 example defconfigs use this caller. The patch
leaves coreboot's default for unrelated payloads unchanged. It is a dependency
of this ABI migration until coreboot provides an equivalent upstream interface.

## End-to-end validation

The ABI migration was exercised on QEMU Q35/KVM with 4 GiB RAM and NVMe:

- coreboot -> Linux 7.2.0-rc6 -> u-root's normal boot menu -> CrabEFI ->
  installed Windows 11 Pro 25H2, build 26200.6584, including a cold repeat.
- The same LinuxBoot chain with a freshly built/audited Runtime Services image.
- Direct 64-bit coreboot -> CrabEFI -> the same installed Windows image.
- `./crabefi test --app hello --nvme` using the replacement Q35 fixture.

Each Windows run used a disposable copy, networking disabled, and success and
OS-diagnostic files deleted before boot. Windows regenerated the success marker,
reported installation type `Client` and `SYSTEMDRIVE=C:`, and recorded
`explorer.exe` running. These are full installed-OS boots, not WinPE or merely
reaching Windows Boot Manager. No new Windows installation was performed.

These tests do not establish Secure Boot, BitLocker, TPM continuity or physical
board compatibility. Five-level entry is implemented but was not exercised by
this four-level-paging test setup.

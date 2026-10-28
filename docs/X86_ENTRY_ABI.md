# x86 payload entries: coreboot by default, entry64 for u-root

CrabEFI supports **both callers**, selected at compile time. Default x86 builds
keep the established coreboot entry. The optional `entry64` feature selects
the long-mode entry used by u-root/LinuxBoot. Exactly one external entry is
linked into each ELF; this is not runtime mode detection or a fallback.

| Build | Caller | Entry argument | Output from wrapper |
| --- | --- | --- | --- |
| `./crabefi build` | unmodified coreboot, 32-bit protected mode | coreboot table pointer at `[esp+4]` | `target/x86_64-unknown-none/release/crabefi` |
| `./crabefi build --entry64` | u-root/LinuxBoot, 64-bit long mode | full-width coreboot table pointer in RDI | `target/entry64/x86_64-unknown-none/release/crabefi` |

The separate wrapper output prevents an entry64 build from replacing the
payload used by normal coreboot `run`, `test` and `screenshot` commands.
The original Q35 fixture and example coreboot defconfigs are unchanged; no
coreboot caller patch or firmware ABI migration is required.

## Default coreboot entry

Both build variants are ELF64 executables, because CrabEFI itself runs in
64-bit mode. The default `_start` nevertheless executes in 32-bit protected
mode, as coreboot requires. It reads the stack argument, initializes page
tables, switches to long mode, establishes its stack, clears BSS and enters
Rust. This is the existing coreboot path, not an obsolete or unsupported ABI.
It does **not** advertise the entry64 ELF note.

Direct Cargo builds retain this default:

```sh
cargo build -p crabefi-coreboot --release --target x86_64-unknown-none
```

## Opt-in entry64 for u-root

Select the feature explicitly:

```sh
./crabefi build --arch x86-64 --entry64
# Or, using the checked-in Runtime Services bundle:
cargo build -p crabefi-coreboot --release --target x86_64-unknown-none --features entry64
```

Direct Cargo commands use the normal target path, replacing its previous ELF;
the wrapper instead keeps the two variants separate as shown above. The flag
is x86-64-only. Native coreboot `run`/`test` commands deliberately do not accept
`--entry64` and always build the default coreboot variant.

The entry64 caller jumps to `_start` with:

- Ring 0 long mode active, paging enabled, interrupts disabled, PCID and CET
  disabled. Four- and five-level paging are accepted; `CR4.LA57` is preserved.
- All identity-linked `PT_LOAD` segments loaded at their physical addresses,
  with zero-filled ELF tails. The incoming identity map must cover the complete
  segments, including writable page tables, BSS and stack, below 64 GiB.
- RDI containing the full 64-bit physical coreboot table pointer. The table and
  its references must remain valid, and its storage must be reserved rather
  than advertised as reusable firmware RAM.

This entry preserves RDI in R12, establishes its own stack, initializes its own
64-GiB identity map, installs its GDT, clears BSS, enables SSE/NX and enters
`rust_main`. It never leaves long mode or returns to the caller. Its paging
structures are outside BSS; an extra PML5 is compiled only for this variant.
No caller stack, GDT or other general-purpose register contents are retained.

## Identifying the correct ELF

Only entry64 builds have an allocated `.note.crabefi` section in `PT_NOTE`:

| Field | Value |
| --- | --- |
| `namesz` | 8 |
| `descsz` | 4 |
| `type` | 1 (entry ABI version) |
| owner | `CrabEFI` followed by NUL |
| descriptor | little-endian `uint32` value 1 |

Notes use standard ELF four-byte alignment. Loaders inspect program headers,
not symbol or section tables. u-root requires this note and rejects a default
coreboot build with an instruction to enable `entry64`; ELFCLASS64 alone is
not enough to select the right entry contract. u-root still owns ELF loading,
firmware handoff, filesystem cleanup and kexec execution, without a Multiboot
adapter, external Rust launcher or kexec-tools dependency.

CI builds and checks both variants with `ci/check-x86-entry.sh`, uploads them
as separate artifacts, and keeps the normal QEMU tests on the default build.

## End-to-end validation

Both paths booted installed Windows 11 Pro 25H2 (26200.6584) on QEMU Q35/KVM,
4 GiB RAM, NVMe, networking disabled:

- Unmodified coreboot's 32-bit payload call -> default CrabEFI -> Windows.
- coreboot -> Linux 7.2.0-rc6 -> u-root's normal boot menu -> explicitly built
  entry64 CrabEFI -> Windows.

The test used a disposable disk copy and deleted success and diagnostic files
before each boot. Windows regenerated its success marker, reported `Client`
and `SYSTEMDRIVE=C:`, and recorded `explorer.exe` running. These are installed
full-OS boots, not WinPE or merely reaching Boot Manager. No Windows image or
provisioning harness is committed. Secure Boot, BitLocker, TPM continuity,
five-level execution and physical-board compatibility were not validated.

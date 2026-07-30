# SetVirtualAddressMap Design

`SetVirtualAddressMap` (SVAM) changes every `EFI_MEMORY_RUNTIME` descriptor from
its physical address to an OS-selected virtual address. Different descriptors
may receive different offsets, so firmware cannot assume one global relocation
delta.

CrabEFI's rule is:

> Ordinary Rust pointers must not cross the physical-to-virtual transition.

## CrabEFI approach

At `ExitBootServices`, CrabEFI copies runtime-visible variables from the
unrestricted boot state into `RuntimeState`. This state lives in a dedicated
`.runtime_state` section and contains only inline values and offsets:

```text
Boot state: Vec/Box/references/trait objects allowed
                    |
                    | ExitBootServices freeze
                    v
RuntimeState: fixed metadata + offset-addressed blob arena
                    |
                    | SetVirtualAddressMap converts one root
                    v
Virtual-mode runtime services
```

The implementation has four main safeguards:

1. **Pointer-free state.** `RuntimeState` stores variable names inline and
   payloads in a compacting 256 KiB arena. Payload locations are offsets from
   the current root, not absolute pointers.
2. **Compile-time checking.** The `VamSafe` auto trait rejects raw pointers,
   references, and function pointers transitively. A const assertion requires
   `RuntimeState: VamSafe`.
3. **Restricted crate boundary.** `crabefi-runtime` is `no_std`, has no `alloc`,
   and depends only on `r-efi`. Boot code performs the one-way freeze through a
   small adapter in `crabefi-core`.
4. **Allocator tripwire.** The ordinary Rust heap uses `BootServicesData` and is
   frozen when SVAM begins. A missed runtime allocation therefore fails instead
   of walking a linked-list allocator whose pointers still contain physical
   addresses.

During SVAM, CrabEFI signals virtual-address-change events, converts the
`RuntimeState` root, converts each runtime-service function pointer according to
its own descriptor, fixes compiler-generated GOT entries, converts the relevant
system-table pointers, and recomputes table CRCs. Deferred variable records and
runtime capsule metadata are streamed directly into reserved buffers without
allocation.

The QEMU `svam-test` application then removes the physical identity mapping and
exercises time, variable, capsule, and reset services. Removing the physical
mapping is essential: otherwise a stale pointer may continue to work by
accident.

## Comparison with EDK2

EDK2 uses a distributed pointer-conversion model. Its Runtime DXE core installs
`SetVirtualAddressMap` and `ConvertPointer`; `ConvertPointer` searches the
runtime descriptors and applies the matching descriptor's physical-to-virtual
offset ([`Runtime.c`, lines 128-190](https://github.com/tianocore/edk2/blob/2cfd432ac92f58a14331fec2d2b885c795f684db/MdeModulePkg/Core/RuntimeDxe/Runtime.c#L128-L190)).
During SVAM, EDK2 signals address-change events, relocates registered runtime
PE/COFF images, converts runtime-service entry points, and updates the system
table ([`Runtime.c`, lines 240-380](https://github.com/tianocore/edk2/blob/2cfd432ac92f58a14331fec2d2b885c795f684db/MdeModulePkg/Core/RuntimeDxe/Runtime.c#L240-L380)).

Each EDK2 runtime driver is responsible for converting its own pointer graph in
an address-change callback. The variable driver, for example, explicitly
converts protocol methods, language strings, variable-store bases, caches, and
arrays of registered pointer locations ([`VariableDxe.c`, lines 263-313](https://github.com/tianocore/edk2/blob/2cfd432ac92f58a14331fec2d2b885c795f684db/MdeModulePkg/Universal/Variable/RuntimeDxe/VariableDxe.c#L263-L313)).
EDK2 also provides helpers for converting function pointers and linked lists
([`RuntimeLib.c`, lines 561-652](https://github.com/tianocore/edk2/blob/2cfd432ac92f58a14331fec2d2b885c795f684db/MdePkg/Library/UefiRuntimeLib/RuntimeLib.c#L561-L652)).

| Area                 | EDK2                                                             | CrabEFI                                                        |
|----------------------|------------------------------------------------------------------|----------------------------------------------------------------|
| Runtime state        | General C pointer graphs                                         | Pointer-free fixed state                                       |
| Conversion ownership | Every runtime driver converts its pointers                       | One converted data root plus explicit code/GOT/table fixups    |
| Runtime images       | PE/COFF images are relocated during SVAM                         | Firmware is PIC; GOT and service pointers are fixed explicitly |
| Allocation           | Runtime drivers may retain carefully managed runtime allocations | No allocation in the runtime nucleus; boot heap is frozen      |
| Extensibility        | Flexible runtime-driver model                                    | Smaller, deliberately restricted runtime surface               |
| Main failure mode    | Missing one `ConvertPointer` call                                | Laundering an address through an integer or unsafe code        |

EDK2's model is more flexible and supports independently developed runtime
DXE drivers. CrabEFI trades that flexibility for a smaller proof surface: adding
an ordinary pointer to `RuntimeState` fails compilation, and runtime code cannot
silently depend on the boot heap.

## Explicit trust boundary

`VamSafe` cannot detect an address stored as an integer. Integer addresses are
therefore explicit opt-ins and must be handled in the SVAM conversion path.
Unsafe code, compiler-generated addressing, and platform mappings are covered by
code review plus the physical-unmap QEMU test rather than by the type system.

# Memory Ownership

CrabEFI has an explicit EBS lifetime boundary.

## Boot-owned memory

The coreboot payload linker scripts expose `__boot_code_start/end` and
`__boot_data_start/end`. The allocator marks those ranges BootServicesCode and
BootServicesData. Payload text, rodata, globals, stack, page tables, drivers,
protocol databases, event callbacks, the global heap, and allocator metadata
are reclaimable after ExitBootServices.

The 4 MiB Rust allocation heap is BootServicesData and is reclaimed after
ExitBootServices. Runtime code must never retain an object allocated from that
heap: the old in-payload Runtime Services design could otherwise carry a boot
heap pointer across EBS or SetVirtualAddressMap, after the backing pages became
conventional memory or were no longer reachable at their physical address.

The separate runtime image instead has a fixed 512 KiB allocation arena in the
image's `.bss`. The arena is therefore part of the image-owned
RuntimeServicesData mapping and is converted with the rest of the image during
SetVirtualAddressMap; it never calls UEFI allocation services or depends on the
boot heap. Allocation is enabled only while the serialized runtime-operation
lease is held, is monotonic within each non-nesting scratch scope, and is fully
scrubbed and reset before the service returns.

RSA uses `allocator-api2` explicitly. A scratch scope lends a lifetime-branded
allocator to `crypto_bigint::BoxedUintIn`, so the compiler prevents RSA bigint
results or temporaries from outliving the scope which rewinds their arena
region. Authenticated-variable signed data is fed incrementally into SHA-256
rather than assembled in a `Vec`. The runtime image therefore has no global
allocator, allocation error handler, or general-purpose allocation API.

## Runtime image memory

The checked normalized image covers one contiguous allocation with page-aligned
RX code, RO/NX immutable data, and RW/NX mutable data sections. The loader
initially allocates RuntimeServicesData and uses a private allocator operation
to split the leading code range to RuntimeServicesCode; public
`AllocateAddress` cannot subclaim or independently free image-owned runtime
data. The loader then copies/zeros sections and applies only normalized
relocation slots. The image-owned MAT publishes the exact code/data protection
domains even where the EFI memory map merges adjacent data descriptors.

The audited release images currently reserve about 756 KiB of runtime address
space on both x86_64 and AArch64:

| Mapping | Size | Contents |
| --- | ---: | --- |
| RX | 60 KiB | runtime code plus leading page/alignment space |
| RO/NX | 4 KiB | immutable data |
| RW/NX | 692 KiB | variable store, runtime state, scratch arena, and padding |

Normalized on-disk images are currently about 240 KiB. The dominant resident
allocations are the 512 KiB scratch arena, roughly 170 KiB of variable-store
state, and under 5 KiB of runtime state. The remainder is code, immutable data,
dynamic metadata, small synchronization globals, and page/alignment padding.

Scratch capacity is deliberately larger than observed demand. Normal
certificate fixtures use under 8 KiB. A regression test executes repeated full
public exponentiations with maximum-width 4096-bit operands and enforces a
16 KiB per-exponentiation bound. Each RSA verification has its own non-nesting
scope, so certificate-chain and signer traversal reuse that same arena region
instead of accumulating allocations. The complete 512 KiB arena is still
scrubbed at operation end and remains reserved as image-owned runtime memory.

Every runtime descriptor is one of:

- an image code/data section;
- an explicit external MMIO range from `RuntimePlatformConfig`; or
- the mandatory retained deferred buffer.

External MMIO ranges require a platform-declared page-aligned physical address,
size, and runtime attributes. They are not inferred from payload linker
symbols. The deferred buffer is a nonzero page-aligned, exclusively owned
`RuntimeServicesData` range whose contents and physical address survive warm
reset. It holds the bounded post-EBS variable journal, capsule staging
metadata, and CrabEFI's private reservation capsule nested in a
coreboot-compatible transport wrapper; the next boot replays or processes those
records before completing variable import.

## ExitBootServices

Before the map-key transition, the image refreshes its fixed Memory Attributes
storage from the final allocator map. On successful EBS, BootServices ranges
become ConventionalMemory while image/external Runtime ranges remain. Image
seal clears every boot table pointer and the pre-seal persistence bridge.

## SetVirtualAddressMap

The image validates the complete descriptor stream before mutation. Each
section/range resolves independently, so mappings may use distinct virtual
deltas. Explicit Absolute64 slots and image-owned table pointers are converted
through physical patch aliases; no payload GOT, state pointer, callback, or
single-delta assumption participates.

# Memory Ownership

CrabEFI has an explicit EBS lifetime boundary.

## Boot-owned memory

The coreboot payload linker scripts expose `__boot_code_start/end` and
`__boot_data_start/end`. The allocator marks those ranges BootServicesCode and
BootServicesData. Payload text, rodata, globals, stack, page tables, drivers,
protocol databases, event callbacks, the global heap, and allocator metadata
are reclaimable after ExitBootServices.

The 4 MiB Rust allocation heap is BootServicesData. Runtime code has no global
allocator and cannot retain a heap object.

## Runtime image memory

The checked normalized image covers one contiguous allocation with page-aligned
RX code, RO/NX immutable data, and RW/NX mutable data sections. The loader
initially allocates RuntimeServicesData and uses a private allocator operation
to split the leading code range to RuntimeServicesCode; public
`AllocateAddress` cannot subclaim or independently free image-owned runtime
data. The loader then copies/zeros sections and applies only normalized
relocation slots. The image-owned MAT publishes the exact code/data protection
domains even where the EFI memory map merges adjacent data descriptors.

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

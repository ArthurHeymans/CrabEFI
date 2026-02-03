# Memory Management in CrabEFI

This document describes the memory layout, page tables, allocators, and memory map management in CrabEFI.

## Physical Memory Layout

CrabEFI is loaded by coreboot at `0x100000` (1 MB). The linker script (`x86_64-coreboot.ld`) defines the following layout:

```
0x00000000 ┌─────────────────────────────────────┐
           │ Real Mode IVT & BIOS Data           │
0x00100000 ├─────────────────────────────────────┤ ◄── PAYLOAD_BASE (1 MB)
           │ .entry32    (32-bit entry code)     │  ◄── __runtime_code_start
           │ .text       (64-bit code)           │
           ├─────────────────────────────────────┤  ◄── __runtime_code_end
           │ .rodata     (read-only data)        │  ◄── __runtime_data_start
           │ .data       (initialized data)      │
           │ .page_tables (4KB-aligned tables)   │
           │ .bss        (uninitialized data)    │
           │ .stack      (2 MB stack)            │
           ├─────────────────────────────────────┤  ◄── __runtime_data_end
           │ .deferred_buffer (64 KB, NOLOAD)    │
           ├─────────────────────────────────────┤  ◄── _end
           │                                     │
           │ Free Memory (Conventional)          │
           │ (Available for EFI allocations)     │
           │                                     │
0x10000000 ├─────────────────────────────────────┤  ◄── MAX_IDENTITY_MAPPED (64 GB)
           │                                     │
           │ (Memory above 64GB not mapped)      │
           │                                     │
           └─────────────────────────────────────┘
```

### Linker Sections

| Section | Description | Attributes |
|---------|-------------|------------|
| `.entry32` | 32-bit entry code for coreboot transition | Executable, 4K aligned |
| `.text` | 64-bit code | Executable, 4K aligned |
| `.rodata` | Read-only data, constants | Read-only, 4K aligned |
| `.data` | Initialized global variables | Read-write, 4K aligned |
| `.page_tables` | Page table structures | 4K aligned (required by CPU) |
| `.bss` | Zero-initialized data | Read-write, 4K aligned |
| `.stack` | Firmware stack (2 MB) | Read-write, 4K aligned |
| `.deferred_buffer` | Deferred variable writes | Reserved, NOLOAD |

### Runtime Services Regions

The linker exports symbols to mark code and data regions:

- `__runtime_code_start` / `__runtime_code_end`: Executable code
- `__runtime_data_start` / `__runtime_data_end`: Data (rodata + data + bss + stack)

These are registered as `RuntimeServicesCode` and `RuntimeServicesData` in the EFI memory map so the OS keeps them accessible after `ExitBootServices()`.

## Page Tables

### Initial Setup (Assembly)

The 32-bit entry code (`entry.rs`) sets up identity-mapped page tables:

```
PML4 (Page Map Level 4)
  └── Entry 0 → PDPT

PDPT (Page Directory Pointer Table)
  └── Entries 0-63 → PD[0-63]

PD (Page Directories, 64 total)
  └── Each entry maps 2 MB using huge pages
      Total: 64 * 512 * 2 MB = 64 GB
```

**Configuration:**
- 4-level paging (required for x86_64 long mode)
- 2 MB huge pages for simplicity
- Identity mapping (virtual = physical)
- First 64 GB mapped
- PAE and NX enabled

### Page Table Entry Flags

```rust
pub mod flags {
    pub const PRESENT: u64 = 1 << 0;      // Page is present
    pub const WRITABLE: u64 = 1 << 1;     // Page is writable
    pub const USER: u64 = 1 << 2;         // User-mode accessible
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const CACHE_DISABLE: u64 = 1 << 4;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const HUGE_PAGE: u64 = 1 << 7;    // 2 MB page (in PD)
    pub const GLOBAL: u64 = 1 << 8;
    pub const NO_EXECUTE: u64 = 1 << 63;  // NX bit
}
```

### Identity Mapping

CrabEFI uses identity mapping for simplicity:
- `virt_to_phys(addr)` returns `addr`
- `phys_to_virt(addr)` returns `addr`

This means pointers in UEFI structures can be used directly without translation.

## EFI Memory Allocator

The allocator (`efi/allocator.rs`) implements the UEFI memory allocation API.

### Memory Types

```rust
pub enum MemoryType {
    ReservedMemoryType = 0,     // Reserved, not usable
    LoaderCode = 1,             // UEFI app code
    LoaderData = 2,             // UEFI app data
    BootServicesCode = 3,       // CrabEFI code (freed after ExitBootServices)
    BootServicesData = 4,       // CrabEFI data (freed after ExitBootServices)
    RuntimeServicesCode = 5,    // Code that survives ExitBootServices
    RuntimeServicesData = 6,    // Data that survives ExitBootServices
    ConventionalMemory = 7,     // Free, usable memory
    UnusableMemory = 8,         // Memory with errors
    AcpiReclaimMemory = 9,      // ACPI tables (reclaimable after parsing)
    AcpiMemoryNvs = 10,         // ACPI NVS (must be preserved)
    MemoryMappedIo = 11,        // MMIO regions
    MemoryMappedIoPortSpace = 12,
    PalCode = 13,               // Itanium only
    PersistentMemory = 14,      // NVDIMM
}
```

### Allocation Types

```rust
pub enum AllocateType {
    AllocateAnyPages = 0,    // Allocate from anywhere
    AllocateMaxAddress = 1,  // Allocate below specified address
    AllocateAddress = 2,     // Allocate at exact address
}
```

### Memory Map Structure

The allocator maintains a sorted list of memory descriptors:

```rust
pub struct MemoryDescriptor {
    pub memory_type: u32,       // MemoryType
    pub padding: u32,
    pub physical_start: u64,    // 4KB aligned
    pub virtual_start: u64,     // For SetVirtualAddressMap
    pub number_of_pages: u64,   // 4KB pages
    pub attribute: u64,         // Memory attributes
}
```

### Memory Attributes

```rust
pub mod attributes {
    pub const EFI_MEMORY_UC: u64 = 0x01;       // Uncacheable
    pub const EFI_MEMORY_WC: u64 = 0x02;       // Write-Combining
    pub const EFI_MEMORY_WT: u64 = 0x04;       // Write-Through
    pub const EFI_MEMORY_WB: u64 = 0x08;       // Write-Back
    pub const EFI_MEMORY_UCE: u64 = 0x10;      // Uncacheable, exported
    pub const EFI_MEMORY_WP: u64 = 0x1000;     // Write-Protected
    pub const EFI_MEMORY_RP: u64 = 0x2000;     // Read-Protected
    pub const EFI_MEMORY_XP: u64 = 0x4000;     // Execute-Protected
    pub const EFI_MEMORY_NV: u64 = 0x8000;     // Non-Volatile
    pub const EFI_MEMORY_RUNTIME: u64 = 0x8000000000000000; // Runtime accessible
}
```

### Allocation Algorithm

1. **Initialization**: Import coreboot memory map, converting types
2. **Page Allocation**:
   - Find a `ConventionalMemory` region that fits
   - "Carve out" the requested pages, splitting the region if needed
   - Mark carved region with requested type
3. **Page Freeing**:
   - Find the allocation by start address and page count
   - Change type back to `ConventionalMemory`
   - Merge adjacent free regions

```
Before allocation:
  [0x1000000 - 0x2000000: ConventionalMemory]

After allocating 0x100 pages at 0x1800000:
  [0x1000000 - 0x1800000: ConventionalMemory]
  [0x1800000 - 0x1900000: BootServicesData]      ◄── Allocated
  [0x1900000 - 0x2000000: ConventionalMemory]
```

### Map Key

Every memory map modification increments a `map_key`. The key must be provided to `ExitBootServices()` to ensure the OS has the latest map.

## Pool Allocator

For arbitrary-sized allocations, the pool allocator wraps page allocation:

```rust
struct PoolHeader {
    num_pages: u64,    // Pages allocated
    magic: u64,        // Validation magic
}
// Followed by user data
```

`AllocatePool`:
1. Calculate total size (header + requested size)
2. Round up to pages
3. Allocate pages
4. Write header
5. Return pointer after header

`FreePool`:
1. Get header from pointer
2. Validate magic
3. Free the pages

## Heap Allocator

For the `alloc` crate (used by crypto libraries), CrabEFI provides a bump allocator (`heap.rs`):

```rust
struct BumpAllocator {
    heap_start: usize,      // Start of heap region
    offset: AtomicUsize,    // Current allocation offset
    heap_size: usize,       // Total heap size (2 MB)
}
```

**Characteristics:**
- 2 MB heap allocated at startup
- Fast bump-pointer allocation
- No deallocation (memory freed when boot services exit)
- Suitable for temporary firmware allocations

## Memory Map Initialization

At startup, CrabEFI:

1. **Parses coreboot tables** to get the system memory map
2. **Converts coreboot types** to EFI types:
   - `Ram` → `ConventionalMemory`
   - `Reserved` → `ReservedMemoryType`
   - `AcpiReclaimable` → `AcpiReclaimMemory`
   - `AcpiNvs` → `AcpiMemoryNvs`
   - `Table` → `BootServicesData`
3. **Reserves CrabEFI regions**:
   - Code as `RuntimeServicesCode`
   - Data as `RuntimeServicesData`
   - Deferred buffer as `ReservedMemoryType`
4. **Installs ACPI tables** and marks as `AcpiReclaimMemory`

## ExitBootServices

When `ExitBootServices()` is called:

1. Verify the provided map key matches current key
2. Set `boot_services_exited` flag
3. Convert all boot services memory to `ConventionalMemory`:
   - `BootServicesCode` → `ConventionalMemory`
   - `BootServicesData` → `ConventionalMemory`
   - `LoaderCode` → `ConventionalMemory`
   - `LoaderData` → `ConventionalMemory`
4. Merge adjacent free regions
5. Increment map key

After this:
- Only `RuntimeServicesCode/Data` remains reserved for firmware
- OS can use all other memory
- No more boot services calls allowed

## Deferred Variable Buffer

Variables written after `ExitBootServices()` can't be written to SPI flash (it's locked). Instead, they're stored in the deferred buffer:

```
.deferred_buffer (64 KB):
  ┌────────────────────────────┐
  │ Header (magic, count)      │
  │ Variable Record 1          │
  │ Variable Record 2          │
  │ ...                        │
  │ Free space                 │
  └────────────────────────────┘
```

On next boot, pending writes are applied to SPI flash before the buffer is cleared.

## Memory Constraints

### 64 GB Limit

The page tables only map the first 64 GB. Allocations above this address would cause page faults. The allocator enforces this limit:

```rust
const MAX_IDENTITY_MAPPED_ADDRESS: u64 = 0x10_0000_0000; // 64 GB
```

### 4 GB Limit for Legacy DMA

Some controllers (EHCI USB) use 32-bit DMA addresses. Use `allocate_pages_below_4g()` for these:

```rust
pub fn allocate_pages_below_4g(num_pages: u64) -> Option<&'static mut [u8]> {
    let mut addr = 0xFFFF_FFFFu64;  // Max 4GB - 1
    allocate_pages(AllocateMaxAddress, BootServicesData, num_pages, &mut addr)
}
```

### Memory Map Entry Limit

The allocator tracks up to 512 memory map entries. If fragmentation exceeds this, allocations may fail. The allocator automatically merges adjacent regions of the same type to reduce fragmentation.

## Debugging Memory Issues

### Dump Memory Map

```rust
allocator.dump_memory_map();  // Logs all entries
allocator.check_for_gaps();   // Warns about unmapped gaps
```

### Common Issues

1. **OUT_OF_RESOURCES**: Memory map full or no free region large enough
2. **NOT_FOUND**: Region to free doesn't match an allocation
3. **Page fault above 64 GB**: Allocation returned address outside mapped region

### Memory Statistics

At various points, CrabEFI logs memory information:
- Total RAM from coreboot
- Allocator initialization summary
- Runtime region reservations
- Memory map at `ExitBootServices()`

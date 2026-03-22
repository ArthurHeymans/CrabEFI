//! ACPI table platform discovery
//!
//! Extracts platform information from ACPI tables so CrabEFI can discover
//! hardware at runtime instead of relying on hardcoded SBSA addresses.
//!
//! Parses:
//! - **MADT** — GIC distributor and redistributor base addresses (aarch64)
//! - **MCFG** — PCIe ECAM configuration space base address
//! - **SPCR** — Serial port (UART) base address
//!
//! Uses the `acpi` crate for type-safe MADT entry iteration while doing
//! lightweight table walking without `alloc` (no `AcpiTables` / `Handler`).

use crate::fdt::PlatformInfo;

// ---------------------------------------------------------------------------
// ACPI table structures (for our own RSDP/XSDT/RSDT walker)
// ---------------------------------------------------------------------------

/// RSDP — Root System Description Pointer.
///
/// Found via coreboot tables. Points to the XSDT (ACPI 2.0+) or RSDT.
#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8],
    _checksum: u8,
    _oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    _length: u32,
    xsdt_address: u64,
}

/// Common ACPI SDT header (first 36 bytes of every table).
#[repr(C, packed)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    _revision: u8,
    _checksum: u8,
    _oem_id: [u8; 6],
    _oem_table_id: [u8; 8],
    _oem_revision: u32,
    _creator_id: u32,
    _creator_revision: u32,
}

const ACPI_SDT_HEADER_SIZE: usize = core::mem::size_of::<SdtHeader>();

// ---------------------------------------------------------------------------
// SPCR (Serial Port Console Redirection Table)
// ---------------------------------------------------------------------------

/// ACPI Generic Address Structure — describes a register location.
#[repr(C, packed)]
struct GenericAddress {
    address_space_id: u8,
    _register_bit_width: u8,
    _register_bit_offset: u8,
    _access_size: u8,
    address: u64,
}

/// SPCR table (ACPI DBG2 predecessor for serial console).
///
/// We only need the interface type and the base address GAS field.
#[repr(C, packed)]
struct Spcr {
    header: SdtHeader,
    interface_type: u8,
    _reserved: [u8; 3],
    base_address: GenericAddress,
}

/// SPCR interface type: ARM PL011 UART.
const SPCR_INTERFACE_PL011: u8 = 0x03;
/// SPCR interface type: ARM SBSA Generic UART (compatible with PL011).
const SPCR_INTERFACE_SBSA_GENERIC: u8 = 0x0E;

// ---------------------------------------------------------------------------
// MCFG (PCI Express Memory-mapped Configuration Space)
// ---------------------------------------------------------------------------

/// MCFG allocation entry — one per PCI segment group.
#[repr(C, packed)]
struct McfgEntry {
    base_address: u64,
    segment_group: u16,
    start_bus: u8,
    end_bus: u8,
    _reserved: u32,
}

// ---------------------------------------------------------------------------
// Table walker
// ---------------------------------------------------------------------------

/// Walk the RSDP -> XSDT/RSDT chain and call `visitor` for each table.
///
/// The visitor receives the 4-byte signature and the table's physical address.
///
/// # Safety
///
/// `rsdp_addr` must point to a valid ACPI RSDP, and all table pointers
/// reachable from it must be valid, mapped, readable physical memory.
unsafe fn walk_tables(rsdp_addr: u64, mut visitor: impl FnMut(&[u8; 4], u64)) {
    // SAFETY: caller guarantees rsdp_addr points to a valid RSDP.
    let rsdp = unsafe { &*(rsdp_addr as *const Rsdp) };
    if &rsdp.signature != b"RSD PTR " {
        log::warn!("ACPI: invalid RSDP signature at {:#x}", rsdp_addr);
        return;
    }

    let (root_addr, is_xsdt) = if rsdp.revision >= 2 && rsdp.xsdt_address != 0 {
        (rsdp.xsdt_address, true)
    } else {
        (rsdp.rsdt_address as u64, false)
    };
    if root_addr == 0 {
        return;
    }

    // SAFETY: root_addr comes from a validated RSDP and points to the XSDT/RSDT.
    let root_hdr = unsafe { &*(root_addr as *const SdtHeader) };
    let entry_size = if is_xsdt { 8 } else { 4 };
    let num_entries = (root_hdr.length as usize).saturating_sub(ACPI_SDT_HEADER_SIZE) / entry_size;
    let entries_base = root_addr + ACPI_SDT_HEADER_SIZE as u64;

    for i in 0..num_entries {
        // SAFETY: entries_base + offset is within the XSDT/RSDT as bounded
        // by num_entries derived from the header length. Packed ACPI tables
        // may be unaligned, so we use read_unaligned.
        let table_addr = if is_xsdt {
            unsafe { ((entries_base + (i * 8) as u64) as *const u64).read_unaligned() }
        } else {
            unsafe { ((entries_base + (i * 4) as u64) as *const u32).read_unaligned() as u64 }
        };
        if table_addr == 0 {
            continue;
        }
        // SAFETY: table_addr comes from the XSDT/RSDT and points to a valid
        // ACPI table header in mapped memory.
        let hdr = unsafe { &*(table_addr as *const SdtHeader) };
        visitor(&hdr.signature, table_addr);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Discover platform hardware from ACPI tables.
///
/// Walks the RSDP at `rsdp_addr` and parses MADT (GIC), MCFG (ECAM), and
/// SPCR (serial UART). Returns a [`PlatformInfo`] with the discovered values.
///
/// This function does **not** require `alloc` and can run before heap init.
///
/// # Safety
///
/// `rsdp_addr` must point to a valid ACPI RSDP in physical memory, and all
/// table pointers reachable from it must reside in mapped memory.
pub unsafe fn discover_platform(rsdp_addr: u64) -> PlatformInfo {
    let mut info = PlatformInfo::new();

    // SAFETY: caller guarantees rsdp_addr is valid; walk_tables and the
    // individual parsers only dereference ACPI table pointers reachable
    // from the RSDP, which the caller guarantees are in mapped memory.
    unsafe {
        walk_tables(rsdp_addr, |sig, addr| match sig {
            b"APIC" => parse_madt(addr, &mut info),
            b"MCFG" => parse_mcfg(addr, &mut info),
            b"SPCR" => parse_spcr(addr, &mut info),
            _ => {}
        });
    }

    log::info!("ACPI platform discovery:");
    if let Some((base, _)) = info.gicd {
        log::info!("  GICD: {:#x}", base);
    }
    if let Some((base, len)) = info.gicr {
        log::info!("  GICR: {:#x} (len {:#x})", base, len);
    }
    if let Some(base) = info.ecam_base {
        log::info!(
            "  ECAM: {:#x} (size {:#x})",
            base,
            info.ecam_size.unwrap_or(0)
        );
    }
    if let Some(base) = info.uart_base {
        log::info!("  UART: {:#x}", base);
    }

    info
}

// ---------------------------------------------------------------------------
// MADT — Multiple APIC Description Table
// ---------------------------------------------------------------------------

/// Parse the MADT for GIC distributor and redistributor entries.
///
/// Uses the `acpi` crate's [`acpi::sdt::madt::Madt`] type for safe,
/// type-checked iteration over the variable-length MADT entries.
///
/// # Safety
///
/// `table_addr` must point to a valid MADT in physical memory.
unsafe fn parse_madt(table_addr: u64, info: &mut PlatformInfo) {
    use acpi::sdt::madt::{Madt, MadtEntry};
    use core::pin::Pin;

    // SAFETY: table_addr points to a valid MADT in ACPI memory which is
    // never moved — satisfies the Pin invariant for the !Unpin Madt type.
    let madt: Pin<&Madt> = unsafe { Pin::new_unchecked(&*(table_addr as *const Madt)) };

    for entry in madt.entries() {
        match entry {
            MadtEntry::Gicd(gicd) => {
                // GICD base address; size is 64 KiB per the GIC architecture spec.
                // Copy fields out of the packed struct before use.
                let base = gicd.physical_base_address;
                let id = gicd.gic_id;
                let version = gicd.gic_version;
                if base != 0 {
                    info.gicd = Some((base, 0x10000));
                    log::debug!(
                        "ACPI MADT: GICD id={} base={:#x} version={}",
                        id,
                        base,
                        version
                    );
                }
            }
            MadtEntry::GicRedistributor(gicr) => {
                let base = gicr.discovery_range_base_address;
                let len = gicr.discovery_range_length as u64;
                if base != 0 {
                    info.gicr = Some((base, len));
                    log::debug!("ACPI MADT: GICR base={:#x} len={:#x}", base, len);
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// MCFG — PCI Express ECAM
// ---------------------------------------------------------------------------

/// Parse the MCFG table for the first PCIe ECAM base address.
///
/// # Safety
///
/// `table_addr` must point to a valid MCFG table in physical memory.
unsafe fn parse_mcfg(table_addr: u64, info: &mut PlatformInfo) {
    // SAFETY: table_addr points to a valid MCFG; we only read the header.
    let hdr = unsafe { &*(table_addr as *const SdtHeader) };
    let mcfg_len = hdr.length as usize;

    // MCFG layout: 36-byte header + 8 bytes reserved + 16-byte entries
    if mcfg_len < ACPI_SDT_HEADER_SIZE + 8 + core::mem::size_of::<McfgEntry>() {
        return;
    }

    let entry_ptr = (table_addr + ACPI_SDT_HEADER_SIZE as u64 + 8) as *const McfgEntry;
    // SAFETY: we verified the MCFG is large enough to contain at least one entry.
    let entry = unsafe { &*entry_ptr };

    // Copy fields from packed struct before use in format macros.
    let base = entry.base_address;
    let segment = entry.segment_group;
    let start_bus = entry.start_bus;
    let end_bus = entry.end_bus;

    if base != 0 {
        let num_buses = (end_bus as u64 - start_bus as u64 + 1).max(1);
        let ecam_size = num_buses * 256 * 4096; // buses * devfns(256) * 4K config space

        info.ecam_base = Some(base);
        info.ecam_size = Some(ecam_size);
        log::debug!(
            "ACPI MCFG: ECAM base={:#x} segment={} bus={}-{} size={:#x}",
            base,
            segment,
            start_bus,
            end_bus,
            ecam_size
        );
    }
}

// ---------------------------------------------------------------------------
// SPCR — Serial Port Console Redirection
// ---------------------------------------------------------------------------

/// Parse the SPCR table for the serial port (UART) base address.
///
/// # Safety
///
/// `table_addr` must point to a valid SPCR table in physical memory.
unsafe fn parse_spcr(table_addr: u64, info: &mut PlatformInfo) {
    // SAFETY: table_addr points to a valid SPCR; we only read the header first.
    let hdr = unsafe { &*(table_addr as *const SdtHeader) };
    if (hdr.length as usize) < core::mem::size_of::<Spcr>() {
        return;
    }

    // SAFETY: we verified the table is large enough to contain an Spcr.
    let spcr = unsafe { &*(table_addr as *const Spcr) };

    // We only care about memory-mapped UARTs (address space 0 = system memory).
    if spcr.base_address.address_space_id != 0 {
        return;
    }

    let base = spcr.base_address.address;
    if base == 0 {
        return;
    }

    let iface = spcr.interface_type;
    let iface_name = match iface {
        SPCR_INTERFACE_PL011 => "PL011",
        SPCR_INTERFACE_SBSA_GENERIC => "SBSA Generic UART",
        0x00 => "16550",
        0x01 => "16450",
        0x02 => "MAX311xE",
        0x12 => "16550-compatible",
        _ => "unknown",
    };
    log::debug!(
        "ACPI SPCR: UART base={:#x} type={:#x} ({})",
        base,
        iface,
        iface_name
    );

    // Accept any UART type — the base address is what matters for MMIO mapping.
    info.uart_base = Some(base);
}

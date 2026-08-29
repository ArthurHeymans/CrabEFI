//! Flattened Device Tree (FDT) platform discovery
//!
//! Extracts platform information (PCIe, GIC, memory) from a device tree blob
//! so CrabEFI can work on platforms that use FDT instead of ACPI (e.g. QEMU virt).
//!
//! Uses the `fdt` crate for parsing on aarch64; the module is a no-op on x86.

use crate::platform::PciEcamRegion;

/// Maximum number of devices discovered from DSDT.
pub const MAX_DSDT_DEVICES: usize = 16;

/// A device discovered from the ACPI DSDT namespace.
///
/// Contains the hardware ID (`_HID`), primary MMIO region and interrupt
/// from the `_CRS` resource template (`Memory32Fixed` + `Extended Interrupt`).
#[derive(Clone, Copy)]
pub struct DsdtDevice {
    /// Hardware ID string (e.g., `"ARMH0011"`, `"PNP0D10"`), null-padded.
    pub hid: [u8; 16],
    /// Length of the HID string (excluding padding).
    pub hid_len: u8,
    /// ACPI namespace name (4 chars, e.g., `COM0`).
    pub name: [u8; 4],
    /// Primary MMIO base address from `Memory32Fixed` in `_CRS`.
    pub mmio_base: u64,
    /// Primary MMIO size from `Memory32Fixed` in `_CRS`.
    pub mmio_size: u64,
    /// Primary interrupt number from `Extended Interrupt` in `_CRS`.
    pub irq: Option<u32>,
}

impl DsdtDevice {
    pub const fn empty() -> Self {
        Self {
            hid: [0; 16],
            hid_len: 0,
            name: [0; 4],
            mmio_base: 0,
            mmio_size: 0,
            irq: None,
        }
    }

    /// Return the HID as a `&str`.
    pub fn hid_str(&self) -> &str {
        core::str::from_utf8(&self.hid[..self.hid_len as usize]).unwrap_or("")
    }

    /// Return the 4-char ACPI name as a `&str`.
    pub fn name_str(&self) -> &str {
        // Trim trailing underscores (ACPI pads short names with `_`).
        let end = self
            .name
            .iter()
            .rposition(|&b| b != b'_' && b != 0)
            .map_or(0, |i| i + 1);
        core::str::from_utf8(&self.name[..end]).unwrap_or("????")
    }
}

impl Default for DsdtDevice {
    fn default() -> Self {
        Self::empty()
    }
}

impl core::fmt::Debug for DsdtDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DsdtDevice")
            .field("name", &self.name_str())
            .field("hid", &self.hid_str())
            .field(
                "mmio",
                &format_args!("{:#x}+{:#x}", self.mmio_base, self.mmio_size),
            )
            .field("irq", &self.irq)
            .finish()
    }
}

/// Maximum number of distinct PCI ECAM allocations retained from firmware.
pub const MAX_ECAM_REGIONS: usize = 8;

/// Platform information extracted from an FDT or ACPI tables.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlatformInfo {
    /// Validated PCIe ECAM allocations.
    pub ecam_regions: [PciEcamRegion; MAX_ECAM_REGIONS],
    /// Number of populated ECAM allocations.
    pub ecam_region_count: usize,
    /// PCIe 32-bit MMIO window (base, size)
    pub pcie_mmio32: Option<(u64, u64)>,
    /// PCIe 64-bit MMIO window (base, size)
    pub pcie_mmio64: Option<(u64, u64)>,
    /// PCIe I/O (PIO) window — CPU address and size
    pub pcie_pio: Option<(u64, u64)>,
    /// GIC distributor base address and size
    pub gicd: Option<(u64, u64)>,
    /// GIC redistributor base address and size (GICv3+)
    pub gicr: Option<(u64, u64)>,
    /// PL011 UART base address
    pub uart_base: Option<u64>,
    /// Devices discovered from DSDT `Device` scopes.
    pub dsdt_devices: [DsdtDevice; MAX_DSDT_DEVICES],
    /// Number of valid entries in `dsdt_devices`.
    pub dsdt_device_count: usize,
}

impl PlatformInfo {
    pub const fn new() -> Self {
        Self {
            ecam_regions: [PciEcamRegion::EMPTY; MAX_ECAM_REGIONS],
            ecam_region_count: 0,
            pcie_mmio32: None,
            pcie_mmio64: None,
            pcie_pio: None,
            gicd: None,
            gicr: None,
            uart_base: None,
            dsdt_devices: [DsdtDevice::empty(); MAX_DSDT_DEVICES],
            dsdt_device_count: 0,
        }
    }

    /// Return all discovered ECAM allocations.
    pub fn ecam_regions(&self) -> &[PciEcamRegion] {
        &self.ecam_regions[..self.ecam_region_count]
    }

    /// Retain one validated ECAM allocation, rejecting overlap and excess.
    pub fn push_ecam_region(&mut self, region: PciEcamRegion) -> bool {
        if !region.is_valid()
            || self.ecam_regions().iter().any(|current| {
                current.segment == region.segment
                    && current.bus_start <= region.bus_end
                    && region.bus_start <= current.bus_end
            })
            || self.ecam_region_count == MAX_ECAM_REGIONS
        {
            return false;
        }
        self.ecam_regions[self.ecam_region_count] = region;
        self.ecam_region_count += 1;
        true
    }

    /// Find the first DSDT device whose `_HID` matches `hid`.
    pub fn find_device(&self, hid: &str) -> Option<&DsdtDevice> {
        self.dsdt_devices[..self.dsdt_device_count]
            .iter()
            .find(|d| d.hid_str() == hid)
    }
}

/// Parse an FDT blob and extract platform information.
///
/// # Safety
///
/// `fdt_addr` must point to a valid FDT blob of at least `fdt_size` bytes.
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
pub unsafe fn parse(fdt_addr: u64, fdt_size: u32) -> Option<PlatformInfo> {
    if fdt_addr == 0 || fdt_size < 40 {
        return None;
    }

    let blob = unsafe { core::slice::from_raw_parts(fdt_addr as *const u8, fdt_size as usize) };

    let dt = match fdt::Fdt::new(blob) {
        Ok(dt) => dt,
        Err(e) => {
            log::error!("FDT: parse error: {:?}", e);
            return None;
        }
    };

    let mut info = PlatformInfo::default();

    extract_pcie(&dt, &mut info);
    extract_gic(&dt, &mut info);
    extract_uart(&dt, &mut info);

    log::info!("FDT parsed:");
    for region in info.ecam_regions() {
        log::info!(
            "  ECAM: segment {} buses {:02x}-{:02x} at {:#x}",
            region.segment,
            region.bus_start,
            region.bus_end,
            region.base
        );
    }
    if let Some((base, size)) = info.pcie_mmio32 {
        log::info!("  PCIe MMIO32: {:#x} size {:#x}", base, size);
    }
    if let Some((base, size)) = info.pcie_mmio64 {
        log::info!("  PCIe MMIO64: {:#x} size {:#x}", base, size);
    }
    if let Some((base, size)) = info.pcie_pio {
        log::info!("  PCIe PIO: {:#x} size {:#x}", base, size);
    }
    if let Some((base, size)) = info.gicd {
        log::info!("  GICD: {:#x} size {:#x}", base, size);
    }
    if let Some((base, size)) = info.gicr {
        log::info!("  GICR: {:#x} size {:#x}", base, size);
    }
    if let Some(base) = info.uart_base {
        log::info!("  UART: {:#x}", base);
    }

    Some(info)
}

/// No-op on targets that don't use FDT (x86_64).
///
/// # Safety
///
/// Same contract as the real variant — `fdt_addr` must point to a valid
/// FDT blob.  On x86_64, this is a no-op and never dereferences the
/// pointer.
#[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
pub unsafe fn parse(_fdt_addr: u64, _fdt_size: u32) -> Option<PlatformInfo> {
    None
}

// ---------------------------------------------------------------------------
// Per-subsystem extractors (aarch64 only)
// ---------------------------------------------------------------------------

/// Extract PCIe host bridge info: ECAM base/size and MMIO/PIO ranges.
///
/// Looks for nodes whose `compatible` contains `"pci-host-ecam-generic"` or
/// starts with `"pci"`.  The `reg` property gives the ECAM window and the
/// `ranges` property maps PCI child addresses to CPU addresses.
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn extract_pcie(dt: &fdt::Fdt, info: &mut PlatformInfo) {
    // Find the PCI host bridge node
    let pci_node = dt.all_nodes().find(|n| {
        n.compatible()
            .is_some_and(|c| c.all().any(|s| s.contains("pci")))
    });

    let node = match pci_node {
        Some(n) => n,
        None => return,
    };

    // ECAM from `reg`, preserving the optional declared `bus-range`.
    if let Some(mut regs) = node.reg()
        && let Some(reg) = regs.next()
    {
        let bus_range = match node.property("bus-range") {
            None => Some((0, u8::MAX)),
            Some(property) => {
                let bytes = property.value;
                if bytes.len() < 8 {
                    None
                } else {
                    let start = u32::from_be_bytes(bytes[0..4].try_into().unwrap_or_default());
                    let end = u32::from_be_bytes(bytes[4..8].try_into().unwrap_or_default());
                    (start <= u8::MAX as u32 && end <= u8::MAX as u32)
                        .then_some((start as u8, end as u8))
                }
            }
        };
        let declared_size = reg.size.map(|size| size as u64).unwrap_or(0);
        if let Some((bus_start, bus_end)) = bus_range {
            let region = PciEcamRegion {
                base: reg.starting_address as u64,
                segment: 0,
                bus_start,
                bus_end,
            };
            if region
                .byte_len()
                .is_some_and(|required| declared_size >= required)
                && info.push_ecam_region(region)
            {
                log::debug!("FDT PCI: retained ECAM region {:?}", region);
            } else {
                log::warn!(
                    "FDT PCI: invalid ECAM base/range/size ({:?}, size={:#x})",
                    region,
                    declared_size
                );
            }
        } else {
            log::warn!("FDT PCI: malformed bus-range; ECAM region skipped");
        }
    }

    // Parse `ranges` property for MMIO / PIO windows.
    // Each ranges entry maps a PCI address to a CPU address:
    //   <pci_addr_hi> <pci_addr_lo(1-2 cells)> <cpu_addr(1-2 cells)> <size(1-2 cells)>
    // pci_addr_hi encodes the space type in bits [25:24]:
    //   0x01 = I/O, 0x02 = 32-bit mem, 0x03 = 64-bit prefetchable mem
    if let Some(ranges_raw) = node.property("ranges") {
        let data = ranges_raw.value;
        // PCI nodes have #address-cells=3 (hi, mid, lo) by convention
        let child_ac: usize = node
            .property("#address-cells")
            .and_then(|p| p.as_usize())
            .unwrap_or(3);
        let child_sc: usize = node
            .property("#size-cells")
            .and_then(|p| p.as_usize())
            .unwrap_or(2);
        // Parent (CPU) #address-cells comes from root
        let parent_ac: usize = dt
            .root()
            .property("#address-cells")
            .and_then(|p| p.as_usize())
            .unwrap_or(2);

        let entry_bytes = (child_ac + parent_ac + child_sc) * 4;
        if entry_bytes > 0 {
            let mut off = 0;
            while off + entry_bytes <= data.len() {
                let pci_hi = u32::from_be_bytes(data[off..off + 4].try_into().unwrap_or_default());
                let space = (pci_hi >> 24) & 0x03;

                let cpu_off = off + child_ac * 4;
                let cpu_addr = read_cells(data, cpu_off, parent_ac);

                let size_off = cpu_off + parent_ac * 4;
                let size = read_cells(data, size_off, child_sc);

                match space {
                    0x01 => info.pcie_pio = Some((cpu_addr, size)),
                    0x02 => info.pcie_mmio32 = Some((cpu_addr, size)),
                    0x03 => info.pcie_mmio64 = Some((cpu_addr, size)),
                    _ => {}
                }

                off += entry_bytes;
            }
        }
    }
}

/// Extract interrupt controller addresses.
///
/// On aarch64: extracts GIC distributor/redistributor addresses.
/// On riscv64: extracts PLIC address (stored in `gicd` field for reuse).
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn extract_gic(dt: &fdt::Fdt, info: &mut PlatformInfo) {
    let gic_node = dt.all_nodes().find(|n| {
        n.compatible().is_some_and(|c| {
            c.all().any(|s| {
                s.contains("arm,gic")
                    || s.contains("arm,cortex")
                    || s.contains("riscv,plic")
                    || s.contains("sifive,plic")
            })
        })
    });

    let node = match gic_node {
        Some(n) => n,
        None => return,
    };

    if let Some(mut regs) = node.reg() {
        // First reg entry: GICD
        if let Some(gicd) = regs.next() {
            info.gicd = Some((gicd.starting_address as u64, gicd.size.unwrap_or(0) as u64));
        }
        // Second reg entry: GICR (GICv3) or GICC (GICv2)
        if let Some(gicr) = regs.next() {
            info.gicr = Some((gicr.starting_address as u64, gicr.size.unwrap_or(0) as u64));
        }
    }
}

/// Extract the first UART base address.
///
/// Matches only known, specific compatible strings to avoid selecting
/// unrelated nodes that happen to contain "uart" as a substring.
///
/// - aarch64: ARM PL011 (`arm,pl011`)
/// - riscv64: 16550-compatible (`ns16550`, `ns16550a`) and `uart8250`
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn extract_uart(dt: &fdt::Fdt, info: &mut PlatformInfo) {
    let uart_node = dt.all_nodes().find(|n| {
        n.compatible().is_some_and(|c| {
            c.all().any(|s| {
                s.contains("pl011") || s.contains("ns16550") || s == "uart8250" || s == "8250"
            })
        })
    });

    if let Some(node) = uart_node
        && let Some(mut regs) = node.reg()
        && let Some(reg) = regs.next()
    {
        info.uart_base = Some(reg.starting_address as u64);
    }
}

/// Read a big-endian cell value (1 or 2 cells) from a byte slice.
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
fn read_cells(data: &[u8], off: usize, cells: usize) -> u64 {
    match cells {
        1 => u32::from_be_bytes(data[off..off + 4].try_into().unwrap_or_default()) as u64,
        2 => u64::from_be_bytes(data[off..off + 8].try_into().unwrap_or_default()),
        _ => 0,
    }
}

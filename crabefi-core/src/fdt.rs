//! Flattened Device Tree (FDT) platform discovery
//!
//! Extracts platform information (PCIe, GIC, memory) from a device tree blob
//! so CrabEFI can work on platforms that use FDT instead of ACPI (e.g. QEMU virt).
//!
//! Uses the `fdt` crate for parsing on aarch64; the module is a no-op on x86.

use crate::efi::dma::DmaDomain;
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
/// Maximum number of PCI host-bridge address windows retained from firmware.
pub const MAX_PCI_WINDOWS: usize = 24;
/// Maximum number of PCI DMA domains retained from firmware.
pub const MAX_PCI_DMA_DOMAINS: usize = 8;

/// PCI host-bridge address-space kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciWindowKind {
    /// PCI I/O-port space.
    Pio,
    /// Non-prefetchable 32-bit memory space.
    Mmio32,
    /// Prefetchable 64-bit memory space.
    Mmio64,
}

/// One firmware-described PCI host-bridge CPU address window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciWindow {
    /// PCI segment owning this window.
    pub segment: u16,
    /// Address-space kind.
    pub kind: PciWindowKind,
    /// CPU-visible base address.
    pub base: u64,
    /// Window size in bytes.
    pub size: u64,
}

/// One firmware-described DMA domain for a PCI segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDmaDomain {
    /// PCI segment using this domain.
    pub segment: u16,
    /// CPU/device translation and coherency metadata.
    pub domain: DmaDomain,
}

/// Platform information extracted from an FDT or ACPI tables.
#[derive(Debug, Default, Clone)]
pub struct PlatformInfo {
    /// Validated PCIe ECAM allocations.
    pub ecam_regions: heapless::Vec<PciEcamRegion, MAX_ECAM_REGIONS>,
    /// Firmware-described PCI address windows, kept per host segment.
    pub pci_windows: heapless::Vec<PciWindow, MAX_PCI_WINDOWS>,
    /// Explicit PCI DMA translation domains.
    pub pci_dma_domains: heapless::Vec<PciDmaDomain, MAX_PCI_DMA_DOMAINS>,
    /// GIC distributor base address and size
    pub gicd: Option<(u64, u64)>,
    /// GIC redistributor base address and size (GICv3+)
    pub gicr: Option<(u64, u64)>,
    /// PL011 UART base address
    pub uart_base: Option<u64>,
    /// Devices discovered from DSDT `Device` scopes.
    pub dsdt_devices: heapless::Vec<DsdtDevice, MAX_DSDT_DEVICES>,
}

impl PlatformInfo {
    pub const fn new() -> Self {
        Self {
            ecam_regions: heapless::Vec::new(),
            pci_windows: heapless::Vec::new(),
            pci_dma_domains: heapless::Vec::new(),
            gicd: None,
            gicr: None,
            uart_base: None,
            dsdt_devices: heapless::Vec::new(),
        }
    }

    /// Return all discovered ECAM allocations.
    pub fn ecam_regions(&self) -> &[PciEcamRegion] {
        self.ecam_regions.as_slice()
    }

    /// Retain one validated ECAM allocation, rejecting overlap and excess.
    pub fn push_ecam_region(&mut self, region: PciEcamRegion) -> bool {
        if !region.is_valid()
            || self.ecam_regions().iter().any(|current| {
                current.segment == region.segment
                    && current.bus_start <= region.bus_end
                    && region.bus_start <= current.bus_end
            })
        {
            return false;
        }
        self.ecam_regions.push(region).is_ok()
    }

    /// Return the explicit DMA domain for one PCI segment.
    pub fn pci_dma_domain(&self, segment: u16) -> Option<DmaDomain> {
        self.pci_dma_domains
            .iter()
            .find(|entry| entry.segment == segment)
            .map(|entry| entry.domain)
    }

    /// Find the first DSDT device whose `_HID` matches `hid`.
    pub fn find_device(&self, hid: &str) -> Option<&DsdtDevice> {
        self.dsdt_devices.iter().find(|d| d.hid_str() == hid)
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
    for dma in &info.pci_dma_domains {
        log::info!("  PCI segment {} DMA: {:?}", dma.segment, dma.domain);
    }
    for window in &info.pci_windows {
        log::info!(
            "  PCI segment {} {:?}: {:#x} size {:#x}",
            window.segment,
            window.kind,
            window.base,
            window.size
        );
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
    for node in dt.all_nodes().filter(|node| {
        node.compatible().is_some_and(|compatible| {
            compatible
                .all()
                .any(|value| value == "pci-host-ecam-generic")
        })
    }) {
        let segment = match node.property("linux,pci-domain") {
            None => 0,
            Some(property) => {
                let Some(segment) = (property.value.len() == 4)
                    .then(|| property.as_usize())
                    .flatten()
                    .and_then(|value| u16::try_from(value).ok())
                else {
                    log::warn!("FDT PCI: host {} has malformed linux,pci-domain", node.name);
                    continue;
                };
                segment
            }
        };

        let bus_range = match node.property("bus-range") {
            None => {
                log::warn!("FDT PCI: host {} has no bus-range; skipped", node.name);
                None
            }
            Some(property) => {
                let bytes = property.value;
                if bytes.len() != 8 {
                    None
                } else {
                    let start = u32::from_be_bytes(bytes[0..4].try_into().expect("four bytes"));
                    let end = u32::from_be_bytes(bytes[4..8].try_into().expect("four bytes"));
                    (start <= end && end <= u8::MAX as u32).then_some((start as u8, end as u8))
                }
            }
        };
        let Some((bus_start, bus_end)) = bus_range else {
            log::warn!("FDT PCI: malformed bus-range; ECAM region skipped");
            continue;
        };

        let Some(mut regs) = node.reg() else {
            log::warn!("FDT PCI: host {} has no ECAM reg", node.name);
            continue;
        };
        let Some(reg) = regs.next() else {
            continue;
        };
        if regs.next().is_some() {
            log::warn!(
                "FDT PCI: host {} has ambiguous multiple reg entries",
                node.name
            );
            continue;
        }
        let Some(declared_size) = reg.size.map(|size| size as u64) else {
            log::warn!("FDT PCI: host {} ECAM reg has no size", node.name);
            continue;
        };
        let region = PciEcamRegion {
            base: reg.starting_address as u64,
            segment,
            bus_start,
            bus_end,
        };
        if !region
            .byte_len()
            .is_some_and(|required| declared_size >= required)
            || !info.push_ecam_region(region)
        {
            log::warn!(
                "FDT PCI: invalid ECAM base/range/size ({:?}, size={:#x})",
                region,
                declared_size
            );
            continue;
        }
        log::debug!("FDT PCI: retained ECAM region {:?}", region);

        let child_ac = node.property("#address-cells").and_then(|p| p.as_usize());
        let child_sc = node.property("#size-cells").and_then(|p| p.as_usize());
        let parent_ac = dt
            .root()
            .property("#address-cells")
            .and_then(|p| p.as_usize());
        if let Some(dma_ranges) = node.property("dma-ranges") {
            let data = dma_ranges.value;
            let shape = child_ac
                .zip(parent_ac)
                .zip(child_sc)
                .filter(|((child, parent), size)| {
                    *child == 3 && (1..=2).contains(parent) && (1..=2).contains(size)
                });
            if let Some(((child, parent), size_cells)) = shape {
                let entry_bytes = (child + parent + size_cells) * 4;
                if data.len() == entry_bytes {
                    let pci_hi = u32::from_be_bytes(data[0..4].try_into().expect("four bytes"));
                    let kind = (pci_hi >> 24) & 0x03;
                    let device_base = read_cells(data, 4, child - 1);
                    let cpu_off = child * 4;
                    let cpu_base = read_cells(data, cpu_off, parent);
                    let size = read_cells(data, cpu_off + parent * 4, size_cells);
                    let domain = DmaDomain {
                        cpu_base,
                        device_base,
                        size,
                        coherency: if node.property("dma-coherent").is_some() {
                            crate::efi::dma::DmaCoherency::Coherent
                        } else {
                            crate::efi::dma::DmaCoherency::NonCoherent
                        },
                    };
                    if (kind == 0x02 || kind == 0x03)
                        && size != 0
                        && cpu_base.checked_add(size).is_some()
                        && device_base.checked_add(size).is_some()
                        && info
                            .pci_dma_domains
                            .push(PciDmaDomain { segment, domain })
                            .is_ok()
                    {
                        log::debug!("FDT PCI: retained DMA domain {:?}", domain);
                    } else {
                        log::warn!("FDT PCI: invalid DMA domain for host {}", node.name);
                    }
                } else {
                    log::warn!("FDT PCI: dma-ranges must contain exactly one complete window");
                }
            } else {
                log::warn!(
                    "FDT PCI: unsupported dma-ranges cell shape for host {}",
                    node.name
                );
            }
        } else if node.property("dma-coherent").is_some() {
            let domain = DmaDomain {
                cpu_base: 0,
                device_base: 0,
                size: u64::MAX,
                coherency: crate::efi::dma::DmaCoherency::Coherent,
            };
            if info
                .pci_dma_domains
                .push(PciDmaDomain { segment, domain })
                .is_ok()
            {
                log::debug!("FDT PCI: retained coherent identity DMA domain");
            } else {
                log::warn!("FDT PCI: DMA-domain capacity exhausted");
            }
        } else {
            log::warn!(
                "FDT PCI: host {} has no dma-ranges; PCI DMA disabled",
                node.name
            );
        }

        if let Some(ranges_raw) = node.property("ranges") {
            let data = ranges_raw.value;
            let Some(child_ac) = node.property("#address-cells").and_then(|p| p.as_usize()) else {
                log::warn!("FDT PCI: host {} has no #address-cells", node.name);
                continue;
            };
            let Some(child_sc) = node.property("#size-cells").and_then(|p| p.as_usize()) else {
                log::warn!("FDT PCI: host {} has no #size-cells", node.name);
                continue;
            };
            let Some(parent_ac) = dt
                .root()
                .property("#address-cells")
                .and_then(|p| p.as_usize())
            else {
                log::warn!("FDT PCI: root has no #address-cells");
                continue;
            };
            if child_ac != 3 || !(1..=2).contains(&child_sc) || !(1..=2).contains(&parent_ac) {
                log::warn!(
                    "FDT PCI: unsupported ranges cell shape for host {}",
                    node.name
                );
                continue;
            }
            let Some(entry_bytes) = (child_ac + parent_ac + child_sc).checked_mul(4) else {
                continue;
            };
            if entry_bytes == 0 || !data.len().is_multiple_of(entry_bytes) {
                log::warn!("FDT PCI: malformed ranges length for host {}", node.name);
                continue;
            }

            for off in (0..data.len()).step_by(entry_bytes) {
                let pci_hi = u32::from_be_bytes(data[off..off + 4].try_into().expect("four bytes"));
                let kind = match (pci_hi >> 24) & 0x03 {
                    0x01 => PciWindowKind::Pio,
                    0x02 => PciWindowKind::Mmio32,
                    0x03 => PciWindowKind::Mmio64,
                    _ => continue,
                };
                let cpu_off = off + child_ac * 4;
                let cpu_addr = read_cells(data, cpu_off, parent_ac);
                let size_off = cpu_off + parent_ac * 4;
                let size = read_cells(data, size_off, child_sc);
                if size == 0 || cpu_addr.checked_add(size).is_none() {
                    log::warn!("FDT PCI: invalid {:?} window for host {}", kind, node.name);
                    continue;
                }
                if info
                    .pci_windows
                    .push(PciWindow {
                        segment,
                        kind,
                        base: cpu_addr,
                        size,
                    })
                    .is_err()
                {
                    log::warn!("FDT PCI: address-window capacity exhausted");
                    break;
                }
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

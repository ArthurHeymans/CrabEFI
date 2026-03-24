//! ACPI table platform discovery
//!
//! Uses the [`acpi`] crate (with `alloc` + `aml` features) for:
//! - **Table walking** — RSDP → XSDT/RSDT → typed table access
//! - **MADT** — GIC distributor and redistributor base addresses (aarch64)
//! - **MCFG** — PCIe ECAM configuration space base and size
//! - **SPCR** — Serial port (UART) base address
//! - **FADT → DSDT** — Full AML interpreter for platform device discovery
//!   (`_HID`, `_CRS` resource templates with all memory descriptor types)

use crate::fdt::{DsdtDevice, MAX_DSDT_DEVICES, PlatformInfo};
use acpi::{AcpiTables, Handle, Handler, PciAddress, PhysicalMapping};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};

/// ECAM base for PCI config space access from the Handler.
/// Set when we parse MCFG, before the AML interpreter runs.
static ECAM_BASE: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Handler — bridges the `acpi` crate to CrabEFI's hardware
// ---------------------------------------------------------------------------

/// ACPI handler for a firmware environment with identity-mapped physical memory.
#[derive(Clone)]
struct CrabEfiHandler;

impl Handler for CrabEfiHandler {
    // --- Physical memory mapping (identity-mapped) ---

    unsafe fn map_physical_region<T>(
        &self,
        physical_address: usize,
        size: usize,
    ) -> PhysicalMapping<Self, T> {
        PhysicalMapping {
            physical_start: physical_address,
            virtual_start: NonNull::new(physical_address as *mut T).unwrap(),
            region_length: size,
            mapped_length: size,
            handler: self.clone(),
        }
    }

    fn unmap_physical_region<T>(_region: &PhysicalMapping<Self, T>) {
        // Identity-mapped: nothing to unmap.
    }

    // --- MMIO reads/writes (volatile) ---

    fn read_u8(&self, address: usize) -> u8 {
        unsafe { core::ptr::read_volatile(address as *const u8) }
    }
    fn read_u16(&self, address: usize) -> u16 {
        unsafe { core::ptr::read_volatile(address as *const u16) }
    }
    fn read_u32(&self, address: usize) -> u32 {
        unsafe { core::ptr::read_volatile(address as *const u32) }
    }
    fn read_u64(&self, address: usize) -> u64 {
        unsafe { core::ptr::read_volatile(address as *const u64) }
    }
    fn write_u8(&self, address: usize, value: u8) {
        unsafe { core::ptr::write_volatile(address as *mut u8, value) }
    }
    fn write_u16(&self, address: usize, value: u16) {
        unsafe { core::ptr::write_volatile(address as *mut u16, value) }
    }
    fn write_u32(&self, address: usize, value: u32) {
        unsafe { core::ptr::write_volatile(address as *mut u32, value) }
    }
    fn write_u64(&self, address: usize, value: u64) {
        unsafe { core::ptr::write_volatile(address as *mut u64, value) }
    }

    // --- Port I/O ---

    fn read_io_u8(&self, port: u16) -> u8 {
        #[cfg(target_arch = "x86_64")]
        {
            unsafe { crate::arch::x86_64::io::inb(port) }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = port;
            0
        }
    }
    fn read_io_u16(&self, port: u16) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            unsafe { crate::arch::x86_64::io::inw(port) }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = port;
            0
        }
    }
    fn read_io_u32(&self, port: u16) -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            unsafe { crate::arch::x86_64::io::inl(port) }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = port;
            0
        }
    }
    fn write_io_u8(&self, port: u16, value: u8) {
        #[cfg(target_arch = "x86_64")]
        {
            unsafe { crate::arch::x86_64::io::outb(port, value) }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (port, value);
        }
    }
    fn write_io_u16(&self, port: u16, value: u16) {
        #[cfg(target_arch = "x86_64")]
        {
            unsafe { crate::arch::x86_64::io::outw(port, value) }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (port, value);
        }
    }
    fn write_io_u32(&self, port: u16, value: u32) {
        #[cfg(target_arch = "x86_64")]
        {
            unsafe { crate::arch::x86_64::io::outl(port, value) }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (port, value);
        }
    }

    // --- PCI configuration space (ECAM on aarch64, I/O CAM on x86) ---

    fn read_pci_u8(&self, address: PciAddress, offset: u16) -> u8 {
        self.read_u8(ecam_address(address, offset))
    }
    fn read_pci_u16(&self, address: PciAddress, offset: u16) -> u16 {
        self.read_u16(ecam_address(address, offset))
    }
    fn read_pci_u32(&self, address: PciAddress, offset: u16) -> u32 {
        self.read_u32(ecam_address(address, offset))
    }
    fn write_pci_u8(&self, address: PciAddress, offset: u16, value: u8) {
        self.write_u8(ecam_address(address, offset), value);
    }
    fn write_pci_u16(&self, address: PciAddress, offset: u16, value: u16) {
        self.write_u16(ecam_address(address, offset), value);
    }
    fn write_pci_u32(&self, address: PciAddress, offset: u16, value: u32) {
        self.write_u32(ecam_address(address, offset), value);
    }

    // --- Timing ---

    fn nanos_since_boot(&self) -> u64 {
        let cnt = crate::time::read_counter();
        let freq = crate::time::counter_frequency();
        if freq == 0 {
            return 0;
        }
        // Avoid overflow: split into whole seconds + remainder.
        (cnt / freq) * 1_000_000_000 + (cnt % freq) * 1_000_000_000 / freq
    }

    fn stall(&self, microseconds: u64) {
        let freq = crate::time::counter_frequency();
        if freq == 0 {
            return;
        }
        let ticks = microseconds * freq / 1_000_000;
        let start = crate::time::read_counter();
        while crate::time::read_counter().wrapping_sub(start) < ticks {
            core::hint::spin_loop();
        }
    }

    fn sleep(&self, milliseconds: u64) {
        self.stall(milliseconds * 1000);
    }

    // --- AML mutexes (single-threaded firmware: no-ops) ---

    fn create_mutex(&self) -> Handle {
        Handle(0)
    }

    fn acquire(&self, _mutex: Handle, _timeout: u16) -> Result<(), acpi::aml::AmlError> {
        Ok(())
    }

    fn release(&self, _mutex: Handle) {}
}

/// Compute the ECAM MMIO address for a PCI config space access.
fn ecam_address(address: PciAddress, offset: u16) -> usize {
    let base = ECAM_BASE.load(Ordering::Relaxed) as usize;
    base | ((address.bus() as usize) << 20)
        | ((address.device() as usize) << 15)
        | ((address.function() as usize) << 12)
        | (offset as usize & 0xFFF)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Discover platform hardware from ACPI tables.
///
/// Walks the RSDP at `rsdp_addr` and uses the `acpi` crate for typed table
/// access (MADT, MCFG, SPCR) and its AML interpreter for DSDT platform
/// device discovery.
///
/// # Safety
///
/// `rsdp_addr` must point to a valid ACPI RSDP in physical memory, and all
/// table pointers reachable from it must reside in mapped memory.
pub unsafe fn discover_platform(rsdp_addr: u64) -> PlatformInfo {
    let mut info = PlatformInfo::new();
    let handler = CrabEfiHandler;

    // 1. Parse the RSDP → XSDT/RSDT table chain.
    let tables = match unsafe { AcpiTables::from_rsdp(handler.clone(), rsdp_addr as usize) } {
        Ok(t) => t,
        Err(e) => {
            log::error!("ACPI: failed to parse tables: {:?}", e);
            return info;
        }
    };

    // 2. Extract info from individual tables (before AcpiPlatform takes ownership).
    parse_madt(&tables, &mut info);
    parse_mcfg(&tables, &mut info);
    parse_spcr(&tables, &mut info);

    // Store ECAM base for the Handler's PCI config space access.
    if let Some(base) = info.ecam_base {
        ECAM_BASE.store(base, Ordering::Relaxed);
    }

    // 3. Try to build the full AML interpreter for DSDT device discovery.
    match acpi::platform::AcpiPlatform::new(tables, handler) {
        Ok(platform) => match acpi::aml::Interpreter::new_from_platform(&platform) {
            Ok(interpreter) => discover_namespace_devices(&interpreter, &mut info),
            Err(e) => log::warn!("ACPI: AML interpreter init failed: {:?}", e),
        },
        Err(e) => log::warn!("ACPI: platform init failed: {:?}", e),
    }

    // --- Log results ---
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
    if info.dsdt_device_count > 0 {
        log::info!("  DSDT devices: {}", info.dsdt_device_count);
        for i in 0..info.dsdt_device_count {
            let dev = &info.dsdt_devices[i];
            if let Some(irq) = dev.irq {
                log::info!(
                    "    {} [{}] mmio={:#x}+{:#x} irq={}",
                    dev.name_str(),
                    dev.hid_str(),
                    dev.mmio_base,
                    dev.mmio_size,
                    irq,
                );
            } else {
                log::info!(
                    "    {} [{}] mmio={:#x}+{:#x}",
                    dev.name_str(),
                    dev.hid_str(),
                    dev.mmio_base,
                    dev.mmio_size,
                );
            }
        }
    }

    info
}

// ---------------------------------------------------------------------------
// MADT — GIC distributor and redistributor (aarch64)
// ---------------------------------------------------------------------------

fn parse_madt(tables: &AcpiTables<CrabEfiHandler>, info: &mut PlatformInfo) {
    use acpi::sdt::madt::{Madt, MadtEntry};

    let Some(madt) = tables.find_table::<Madt>() else {
        return;
    };

    for entry in madt.get().entries() {
        match entry {
            MadtEntry::Gicd(gicd) => {
                let base = gicd.physical_base_address;
                if base != 0 {
                    info.gicd = Some((base, 0x10000));
                    log::debug!(
                        "ACPI MADT: GICD base={:#x} version={}",
                        base,
                        gicd.gic_version
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
// MCFG — PCIe ECAM
// ---------------------------------------------------------------------------

fn parse_mcfg(tables: &AcpiTables<CrabEfiHandler>, info: &mut PlatformInfo) {
    use acpi::sdt::mcfg::Mcfg;

    let Some(mcfg) = tables.find_table::<Mcfg>() else {
        return;
    };

    if let Some(entry) = mcfg.entries().first() {
        let base = entry.base_address;
        let start = entry.bus_number_start;
        let end = entry.bus_number_end;
        if base != 0 {
            let num_buses = (end as u64 - start as u64 + 1).max(1);
            let ecam_size = num_buses * 256 * 4096;
            info.ecam_base = Some(base);
            info.ecam_size = Some(ecam_size);
            log::debug!(
                "ACPI MCFG: ECAM base={:#x} bus={}-{} size={:#x}",
                base,
                start,
                end,
                ecam_size,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// SPCR — Serial port UART
// ---------------------------------------------------------------------------

fn parse_spcr(tables: &AcpiTables<CrabEfiHandler>, info: &mut PlatformInfo) {
    use acpi::sdt::spcr::Spcr;

    let Some(spcr) = tables.find_table::<Spcr>() else {
        return;
    };

    if let Some(Ok(addr)) = spcr.base_address()
        && addr.address != 0
    {
        info.uart_base = Some(addr.address);
        log::debug!(
            "ACPI SPCR: UART base={:#x} type={:?}",
            addr.address,
            spcr.interface_type(),
        );
    }
}

// ---------------------------------------------------------------------------
// DSDT — platform device discovery via AML interpreter
// ---------------------------------------------------------------------------

/// Walk the AML namespace and extract platform devices with `_HID` + `_CRS`.
fn discover_namespace_devices(
    interpreter: &acpi::aml::Interpreter<CrabEfiHandler>,
    info: &mut PlatformInfo,
) {
    use acpi::aml::namespace::{AmlName, NamespaceLevelKind};
    use acpi::aml::object::Object;
    use acpi::aml::resource::{
        AddressSpaceResourceType, MemoryRangeDescriptor, Resource, resource_descriptor_list,
    };
    use alloc::vec;
    use core::str::FromStr;

    // Clone the namespace so we can traverse it without holding the lock
    // during evaluate() calls (which need to re-acquire it).
    let mut ns = interpreter.namespace.lock().clone();

    let result = ns.traverse(|path, level| {
        if level.kind != NamespaceLevelKind::Device {
            return Ok(true);
        }
        if info.dsdt_device_count >= MAX_DSDT_DEVICES {
            return Ok(false); // stop recursing, array full
        }

        // --- _HID ---
        let hid_path = AmlName::from_str("_HID")
            .map_err(|e| {
                log::trace!("ACPI: bad _HID name: {:?}", e);
                e
            })?
            .resolve(path)?;

        let hid_obj = match interpreter.evaluate_if_present(hid_path, vec![]) {
            Ok(Some(obj)) => obj,
            Ok(None) => return Ok(true), // no _HID — not a describable device
            Err(e) => {
                log::trace!("ACPI: _HID eval failed for {}: {:?}", path, e);
                return Ok(true);
            }
        };

        let mut hid_buf = [0u8; 16];
        let hid_len = match &*hid_obj {
            Object::String(s) => {
                let len = s.len().min(15);
                hid_buf[..len].copy_from_slice(&s.as_bytes()[..len]);
                len
            }
            Object::Integer(val) => decode_eisaid_into(*val, &mut hid_buf),
            _ => return Ok(true),
        };

        // --- _CRS ---
        let crs_path = AmlName::from_str("_CRS")
            .map_err(|e| {
                log::trace!("ACPI: bad _CRS name: {:?}", e);
                e
            })?
            .resolve(path)?;

        let crs_obj = match interpreter.evaluate_if_present(crs_path, vec![]) {
            Ok(Some(obj)) => obj,
            Ok(None) => return Ok(true),
            Err(e) => {
                log::trace!("ACPI: _CRS eval failed for {}: {:?}", path, e);
                return Ok(true);
            }
        };

        let resources = match resource_descriptor_list(crs_obj) {
            Ok(r) => r,
            Err(e) => {
                log::trace!("ACPI: resource parse failed for {}: {:?}", path, e);
                return Ok(true);
            }
        };

        // Extract first MMIO region and first IRQ.
        let mut mmio_base = 0u64;
        let mut mmio_size = 0u64;
        let mut irq = None;

        for res in &resources {
            match res {
                Resource::MemoryRange(MemoryRangeDescriptor::FixedLocation {
                    base_address,
                    range_length,
                    ..
                }) if mmio_base == 0 && *base_address != 0 && *range_length != 0 => {
                    mmio_base = *base_address as u64;
                    mmio_size = *range_length as u64;
                }
                Resource::AddressSpace(desc)
                    if desc.resource_type == AddressSpaceResourceType::MemoryRange
                        && desc.is_minimum_address_fixed
                        && desc.is_maximum_address_fixed
                        && mmio_base == 0
                        && desc.address_range.0 != 0
                        && desc.length != 0 =>
                {
                    mmio_base = desc.address_range.0;
                    mmio_size = desc.length;
                }
                Resource::Irq(irq_desc) if irq.is_none() => {
                    irq = Some(irq_desc.irq);
                }
                _ => {}
            }
        }

        // Only store devices that have MMIO resources.
        if mmio_base != 0 && mmio_size != 0 {
            let name = extract_device_name(path);
            info.dsdt_devices[info.dsdt_device_count] = DsdtDevice {
                hid: hid_buf,
                hid_len: hid_len as u8,
                name,
                mmio_base,
                mmio_size,
                irq,
            };
            info.dsdt_device_count += 1;
        }

        Ok(true) // continue recursing into children
    });

    if let Err(e) = result {
        log::warn!("ACPI: namespace traversal error: {:?}", e);
    }
}

/// Decode an EISA ID integer (as stored in AML `_HID`) into a 7-char string
/// like `"PNP0D10"`. Returns the number of bytes written.
fn decode_eisaid_into(val: u64, buf: &mut [u8; 16]) -> usize {
    let id = (val as u32).swap_bytes();

    let c0 = ((id >> 26) & 0x1F) as u8 + 0x40;
    let c1 = ((id >> 21) & 0x1F) as u8 + 0x40;
    let c2 = ((id >> 16) & 0x1F) as u8 + 0x40;

    fn hex(v: u8) -> u8 {
        if v < 10 { b'0' + v } else { b'A' + v - 10 }
    }

    if c0.is_ascii_uppercase() && c1.is_ascii_uppercase() && c2.is_ascii_uppercase() {
        buf[0] = c0;
        buf[1] = c1;
        buf[2] = c2;
        buf[3] = hex((id >> 12) as u8 & 0x0F);
        buf[4] = hex((id >> 8) as u8 & 0x0F);
        buf[5] = hex((id >> 4) as u8 & 0x0F);
        buf[6] = hex(id as u8 & 0x0F);
        7
    } else {
        0
    }
}

/// Extract the last NameSeg from an AmlName as a 4-byte device name.
fn extract_device_name(path: &acpi::aml::namespace::AmlName) -> [u8; 4] {
    // AmlName::as_string() gives e.g. `\_SB.COM0`. Take the last 4 chars.
    let s = path.as_string();
    let last_seg = s.rsplit('.').next().unwrap_or(&s);
    // Strip leading backslash if it's a root-level device.
    let last_seg = last_seg.trim_start_matches('\\');
    let bytes = last_seg.as_bytes();
    let mut name = [b'_'; 4];
    let len = bytes.len().min(4);
    name[..len].copy_from_slice(&bytes[..len]);
    name
}

//! ACPI table platform discovery
//!
//! Uses the [`acpi`] crate (with `alloc` + `aml` features) for:
//! - **Table walking** — RSDP → XSDT/RSDT → typed table access
//! - **MADT** — GIC distributor and redistributor base addresses (aarch64)
//! - **MCFG** — PCIe ECAM configuration space base and size
//! - **SPCR** — Serial port (UART) base address
//! - **FADT → DSDT** — Full AML interpreter for platform device discovery
//!   (`_HID`, `_CRS` resource templates with all memory descriptor types)
//!   and I2C peripherals for CrabEFI's drivers

use acpi::{AcpiTables, Handle, Handler, PciAddress, PhysicalMapping};
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ptr::NonNull;
use crabefi::PciEcamRegion;
#[cfg(target_arch = "aarch64")]
use crabefi::fdt::PciDmaDomain;
use crabefi::fdt::{DsdtDevice, MAX_ECAM_REGIONS, PlatformInfo};
use crabefi::peripheral::Peripheral;
#[cfg(target_arch = "x86_64")]
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
    little_endian::{U16, U32, U64},
};

mod connections;
mod peripherals;
#[cfg(test)]
#[path = "acpi/tests.rs"]
mod tests;

/// What ACPI describes for `init_platform()`.
pub struct Discovery {
    pub info: PlatformInfo,
    pub peripherals: Vec<Peripheral>,
}

// ---------------------------------------------------------------------------
// Handler — bridges the `acpi` crate to CrabEFI's hardware
// ---------------------------------------------------------------------------

/// ACPI handler for a firmware environment with identity-mapped physical memory.
#[derive(Clone)]
struct CrabEfiHandler {
    ecam_regions: Rc<RefCell<heapless::Vec<PciEcamRegion, MAX_ECAM_REGIONS>>>,
}

impl CrabEfiHandler {
    fn new() -> Self {
        Self {
            ecam_regions: Rc::new(RefCell::new(heapless::Vec::new())),
        }
    }

    fn set_ecam_regions(&self, regions: &[PciEcamRegion]) {
        let mut owned = self.ecam_regions.borrow_mut();
        owned.clear();
        for region in regions {
            if owned.push(*region).is_err() {
                log::warn!("ACPI AML: ECAM region capacity exhausted");
                break;
            }
        }
    }

    fn ecam_address(&self, address: PciAddress, offset: u16, width: u16) -> Option<usize> {
        if width == 0
            || !width.is_power_of_two()
            || !offset.is_multiple_of(width)
            || offset.checked_add(width - 1)? > 4095
        {
            return None;
        }
        self.ecam_regions.borrow().iter().find_map(|region| {
            if address.segment() != region.segment
                || address.bus() < region.bus_start
                || address.bus() > region.bus_end
            {
                return None;
            }
            let relative = ((address.bus() - region.bus_start) as u64) << 20
                | (address.device() as u64) << 15
                | (address.function() as u64) << 12
                | offset as u64;
            region
                .base
                .checked_add(relative)
                .and_then(|value| usize::try_from(value).ok())
        })
    }
}

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
            unsafe { crabefi::arch::x86_64::io::inb(port) }
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
            unsafe { crabefi::arch::x86_64::io::inw(port) }
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
            unsafe { crabefi::arch::x86_64::io::inl(port) }
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
            unsafe { crabefi::arch::x86_64::io::outb(port, value) }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (port, value);
        }
    }
    fn write_io_u16(&self, port: u16, value: u16) {
        #[cfg(target_arch = "x86_64")]
        {
            unsafe { crabefi::arch::x86_64::io::outw(port, value) }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (port, value);
        }
    }
    fn write_io_u32(&self, port: u16, value: u32) {
        #[cfg(target_arch = "x86_64")]
        {
            unsafe { crabefi::arch::x86_64::io::outl(port, value) }
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (port, value);
        }
    }

    // --- PCI configuration space (ECAM on aarch64, I/O CAM on x86) ---

    fn read_pci_u8(&self, address: PciAddress, offset: u16) -> u8 {
        self.ecam_address(address, offset, 1)
            .map_or(u8::MAX, |address| self.read_u8(address))
    }
    fn read_pci_u16(&self, address: PciAddress, offset: u16) -> u16 {
        self.ecam_address(address, offset, 2)
            .map_or(u16::MAX, |address| self.read_u16(address))
    }
    fn read_pci_u32(&self, address: PciAddress, offset: u16) -> u32 {
        self.ecam_address(address, offset, 4)
            .map_or(u32::MAX, |address| self.read_u32(address))
    }
    fn write_pci_u8(&self, address: PciAddress, offset: u16, value: u8) {
        if let Some(address) = self.ecam_address(address, offset, 1) {
            self.write_u8(address, value);
        }
    }
    fn write_pci_u16(&self, address: PciAddress, offset: u16, value: u16) {
        if let Some(address) = self.ecam_address(address, offset, 2) {
            self.write_u16(address, value);
        }
    }
    fn write_pci_u32(&self, address: PciAddress, offset: u16, value: u32) {
        if let Some(address) = self.ecam_address(address, offset, 4) {
            self.write_u32(address, value);
        }
    }

    // --- Timing ---

    fn nanos_since_boot(&self) -> u64 {
        let cnt = crabefi::time::read_counter();
        let freq = crabefi::time::counter_frequency();
        if freq == 0 {
            return 0;
        }
        // Avoid overflow: split into whole seconds + remainder.
        (cnt / freq) * 1_000_000_000 + (cnt % freq) * 1_000_000_000 / freq
    }

    fn stall(&self, microseconds: u64) {
        let freq = crabefi::time::counter_frequency();
        if freq == 0 {
            return;
        }
        let ticks = microseconds * freq / 1_000_000;
        let start = crabefi::time::read_counter();
        while crabefi::time::read_counter().wrapping_sub(start) < ticks {
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
/// table pointers reachable from it must reside in mapped memory. Controller
/// MMIO of described peripherals is identity mapped and owned by no other
/// CrabEFI driver.
pub unsafe fn discover_platform(rsdp_addr: u64) -> Discovery {
    let mut info = PlatformInfo::new();
    let mut connections = Vec::new();
    let mut mmio = Vec::new();
    let handler = CrabEfiHandler::new();

    // 1. Parse the RSDP → XSDT/RSDT table chain.
    let tables = match unsafe { AcpiTables::from_rsdp(handler.clone(), rsdp_addr as usize) } {
        Ok(t) => t,
        Err(e) => {
            log::error!("ACPI: failed to parse tables: {:?}", e);
            return Discovery {
                info,
                peripherals: Vec::new(),
            };
        }
    };

    // 2. Extract info from individual tables (before AcpiPlatform takes ownership).
    parse_madt(&tables, &mut info);
    parse_mcfg(&tables, &mut info);
    parse_spcr(&tables, &mut info);

    // SBSA coreboot platforms expose coherent, identity-mapped PCI DMA but
    // ACPI MCFG itself carries no DMA translation metadata.
    #[cfg(target_arch = "aarch64")]
    for region in info.ecam_regions.clone() {
        let domain = crabefi::efi::dma::DmaDomain {
            cpu_base: 0,
            device_base: 0,
            size: u64::MAX,
            coherency: crabefi::efi::dma::DmaCoherency::Coherent,
        };
        if info
            .pci_dma_domains
            .push(PciDmaDomain {
                segment: region.segment,
                domain,
            })
            .is_err()
        {
            log::warn!("ACPI: PCI DMA-domain capacity exhausted");
            break;
        }
    }

    // Give the AML handler owned access to every validated MCFG allocation.
    handler.set_ecam_regions(info.ecam_regions());

    // 3. Try to build the full AML interpreter for DSDT device discovery.
    match acpi::platform::AcpiPlatform::new(tables, handler) {
        Ok(platform) => match acpi::aml::Interpreter::new_from_platform(&platform) {
            Ok(interpreter) => {
                discover_namespace_devices(&interpreter, &mut info, &mut connections, &mut mmio)
            }
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
    for region in info.ecam_regions() {
        log::info!(
            "  ECAM: segment {} buses {:02x}-{:02x} at {:#x}",
            region.segment,
            region.bus_start,
            region.bus_end,
            region.base
        );
    }
    if let Some(base) = info.uart_base {
        log::info!("  UART: {:#x}", base);
    }
    if !info.dsdt_devices.is_empty() {
        log::info!("  DSDT devices: {}", info.dsdt_devices.len());
        for dev in &info.dsdt_devices {
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

    // SAFETY: the caller's controller contract.
    let mut peripherals = unsafe { peripherals::adopt(connections) };
    peripherals.append(&mut mmio);
    Discovery { info, peripherals }
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct RsdpV1 {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: U32,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct RsdpV2 {
    v1: RsdpV1,
    length: U32,
    xsdt_address: U64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
struct SdtHeader {
    signature: [u8; 4],
    length: U32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: U32,
    creator_id: U32,
    creator_revision: U32,
}

#[cfg(all(target_arch = "x86_64", not(feature = "native-only")))]
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct TcpaClientTable {
    header: SdtHeader,
    platform_class: U16,
    log_area_minimum_length: U32,
    log_area_start_address: U64,
}

#[cfg(all(target_arch = "x86_64", any(test, not(feature = "native-only"))))]
#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
struct Tpm2Prefix {
    header: SdtHeader,
    platform_class: U16,
    reserved: U16,
    control_area: U64,
    start_method: U32,
}

#[cfg(all(target_arch = "x86_64", any(test, not(feature = "native-only"))))]
#[repr(C)]
#[derive(FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned)]
struct Tpm2WithLogArea {
    prefix: Tpm2Prefix,
    start_method_parameters: [u8; 12],
    log_area_minimum_length: U32,
    log_area_start_address: U64,
}

/// Locate the first ACPI table with `signature`, returning its address and length.
///
/// # Safety
/// The RSDP, root table, and each referenced SDT header must be readable and
/// identity mapped. The root table must be readable for its advertised length.
#[cfg(target_arch = "x86_64")]
unsafe fn find_table(rsdp_addr: u64, signature: &[u8; 4]) -> Option<(u64, usize)> {
    if rsdp_addr == 0 {
        return None;
    }
    let rsdp = rsdp_addr as *const u8;
    let v1 =
        RsdpV1::ref_from_bytes(unsafe { core::slice::from_raw_parts(rsdp, size_of::<RsdpV1>()) })
            .ok()?;
    if &v1.signature != b"RSD PTR " {
        return None;
    }
    let xsdt = v1.revision >= 2;
    let root = if xsdt {
        RsdpV2::ref_from_bytes(unsafe { core::slice::from_raw_parts(rsdp, size_of::<RsdpV2>()) })
            .ok()?
            .xsdt_address
            .get()
    } else {
        u64::from(v1.rsdt_address.get())
    };
    if root == 0 {
        return None;
    }

    let root = root as *const u8;
    let header = SdtHeader::ref_from_bytes(unsafe {
        core::slice::from_raw_parts(root, size_of::<SdtHeader>())
    })
    .ok()?;
    let entry_bytes = (header.length.get() as usize).checked_sub(size_of::<SdtHeader>())?;
    let entries =
        unsafe { core::slice::from_raw_parts(root.add(size_of::<SdtHeader>()), entry_bytes) };
    let find = |address: u64| {
        if address == 0 {
            return None;
        }
        let header = SdtHeader::ref_from_bytes(unsafe {
            core::slice::from_raw_parts(address as *const u8, size_of::<SdtHeader>())
        })
        .ok()?;
        (&header.signature == signature).then_some((address, header.length.get() as usize))
    };
    // XSDT entries start immediately after the 36-byte header, so they need
    // not be naturally aligned even when the table itself is aligned.
    if xsdt {
        let (entries, _) = entries.as_chunks::<8>();
        entries
            .iter()
            .find_map(|&entry| find(U64::from_bytes(entry).get()))
    } else {
        let (entries, _) = entries.as_chunks::<4>();
        entries
            .iter()
            .find_map(|&entry| find(u64::from(U32::from_bytes(entry).get())))
    }
}

/// ACPI FPDT performance record header (ACPI 6.5, 5.2.24.1).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct PerformanceRecordHeader {
    kind: U16,
    length: u8,
    revision: u8,
}

/// Firmware Basic Boot Performance Pointer Record (FPDT record type 0).
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct FbptPointerRecord {
    header: PerformanceRecordHeader,
    reserved: U32,
    fbpt_address: U64,
}

/// Header of the Firmware Basic Boot Performance Table.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct FbptHeader {
    signature: [u8; 4],
    length: U32,
}

/// Firmware Basic Boot Performance Data Record (ACPI 6.5, 5.2.24.7), right
/// after the FBPT header.
#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
struct BasicBootRecord {
    header: PerformanceRecordHeader,
    reserved: U32,
    reset_end: U64,
    os_loader_load_image_start: U64,
    os_loader_start_image_start: U64,
    exit_boot_services_entry: U64,
    exit_boot_services_exit: U64,
}

#[cfg(target_arch = "x86_64")]
const BASIC_BOOT_RECORD_TYPE: u16 = 2;

/// The Firmware Basic Boot Performance Table that the FPDT points to, with
/// the bytes it spans. Its basic boot record is checked, so its fields lie at
/// the offsets the timestamp recorder writes.
///
/// `owned(start, length)` must say whether a span lies in memory the
/// producer reserved for tables; the FBPT is only read and returned if so.
///
/// # Safety
/// `rsdp_addr` and the tables it references must be identity mapped.
#[cfg(target_arch = "x86_64")]
pub unsafe fn find_fbpt(rsdp_addr: u64, owned: impl Fn(u64, u64) -> bool) -> Option<u64> {
    let (fpdt, length) = unsafe { find_table(rsdp_addr, b"FPDT") }?;
    let table = unsafe { core::slice::from_raw_parts(fpdt as *const u8, length) };
    let mut records = table.get(size_of::<SdtHeader>()..)?;
    while let Ok((header, _)) = PerformanceRecordHeader::ref_from_prefix(records) {
        let length = usize::from(header.length);
        if length < size_of::<PerformanceRecordHeader>() || length > records.len() {
            return None;
        }
        if header.kind.get() == 0 {
            let (pointer, _) = FbptPointerRecord::ref_from_prefix(&records[..length]).ok()?;
            let fbpt = pointer.fbpt_address.get();
            if fbpt == 0 {
                return None;
            }
            let span = size_of::<FbptHeader>() + size_of::<BasicBootRecord>();
            if !owned(fbpt, span as u64) {
                return None;
            }
            let bytes = unsafe { core::slice::from_raw_parts(fbpt as *const u8, span) };
            let (fbpt_header, rest) = FbptHeader::ref_from_prefix(bytes).ok()?;
            let (record, _) = BasicBootRecord::ref_from_prefix(rest).ok()?;
            let table_length = fbpt_header.length.get() as usize;
            let record_length = usize::from(record.header.length);
            let valid = &fbpt_header.signature == b"FBPT"
                && table_length >= span
                && record.header.kind.get() == BASIC_BOOT_RECORD_TYPE
                && record_length >= size_of::<BasicBootRecord>()
                && size_of::<FbptHeader>() + record_length <= table_length
                && owned(fbpt, table_length as u64);
            return valid.then_some(fbpt);
        }
        records = &records[length..];
    }
    None
}

/// Byte offsets of the basic boot record fields in the FBPT.
#[cfg(target_arch = "x86_64")]
pub mod fbpt_offsets {
    use super::{BasicBootRecord, FbptHeader};
    use core::mem::{offset_of, size_of};

    const RECORD: usize = size_of::<FbptHeader>();
    pub const OS_LOADER_LOAD_IMAGE_START: usize =
        RECORD + offset_of!(BasicBootRecord, os_loader_load_image_start);
    pub const OS_LOADER_START_IMAGE_START: usize =
        RECORD + offset_of!(BasicBootRecord, os_loader_start_image_start);
    pub const EXIT_BOOT_SERVICES_ENTRY: usize =
        RECORD + offset_of!(BasicBootRecord, exit_boot_services_entry);
    pub const EXIT_BOOT_SERVICES_EXIT: usize =
        RECORD + offset_of!(BasicBootRecord, exit_boot_services_exit);
    // timestamps.rs is also compiled alone, so it repeats these offsets.
    const _: () = assert!(
        OS_LOADER_LOAD_IMAGE_START == 24
            && OS_LOADER_START_IMAGE_START == 32
            && EXIT_BOOT_SERVICES_ENTRY == 40
            && EXIT_BOOT_SERVICES_EXIT == 48
    );
}

/// Locate a TPM 1.2 event log described by the ACPI TCPA table.
///
/// Some coreboot platforms publish the log through ACPI but do not export the
/// corresponding standard-log CBMEM entry in the coreboot table. Copying this
/// log into CrabEFI's EFI_TCG_PROTOCOL log keeps the log replayable against the
/// PCR values coreboot extended before entering the payload.
///
/// # Safety
/// `rsdp_addr` and all referenced ACPI/log memory must be identity mapped and
/// remain valid for the firmware boot-services lifetime.
#[cfg(all(target_arch = "x86_64", not(feature = "native-only")))]
pub unsafe fn find_tcpa_event_log(rsdp_addr: u64) -> Option<&'static [u8]> {
    let (address, length) = unsafe { find_table(rsdp_addr, b"TCPA") }?;
    if length < size_of::<TcpaClientTable>() {
        return None;
    }
    let table = TcpaClientTable::ref_from_bytes(unsafe {
        core::slice::from_raw_parts(address as *const u8, size_of::<TcpaClientTable>())
    })
    .ok()?;
    let maximum_length = table.log_area_minimum_length.get() as usize;
    let log_address = table.log_area_start_address.get();
    if maximum_length == 0 || log_address == 0 {
        return None;
    }

    let allocation =
        unsafe { core::slice::from_raw_parts(log_address as *const u8, maximum_length) };
    let used = tcpa_log_used_length(allocation)?;
    log::info!(
        "ACPI TCPA event log found at {:#x} ({} used of {} bytes)",
        log_address,
        used,
        maximum_length
    );
    Some(&allocation[..used])
}

/// The TPM interface the ACPI TPM2 table describes.
#[cfg(all(target_arch = "x86_64", any(test, not(feature = "native-only"))))]
pub struct Tpm2Table {
    pub start_method: u32,
    pub control_area: u64,
}

/// Read the ACPI TPM2 table.
///
/// # Safety
/// The RSDP, root table, and referenced SDT headers must be readable and
/// identity mapped. The root table and TPM2 table must be readable for their
/// advertised lengths.
#[cfg(all(target_arch = "x86_64", any(test, not(feature = "native-only"))))]
pub unsafe fn find_tpm2_table(rsdp_addr: u64) -> Option<Tpm2Table> {
    let (address, length) = unsafe { find_table(rsdp_addr, b"TPM2") }?;
    if length < size_of::<Tpm2Prefix>() {
        return None;
    }
    let table = Tpm2Prefix::ref_from_bytes(unsafe {
        core::slice::from_raw_parts(address as *const u8, size_of::<Tpm2Prefix>())
    })
    .ok()?;
    Some(Tpm2Table {
        start_method: table.start_method.get(),
        control_area: table.control_area.get(),
    })
}

/// Point the ACPI TPM2 table's log area at a new, empty area of `size` bytes
/// in memory the OS keeps, and return it for the TCG2 event log.
///
/// Linux reads the log there before the EFI one. An area coreboot described
/// holds only its own events, which the payload continues from CBMEM, and
/// has no room for the payload's.
///
/// # Safety
/// The RSDP, root table, and referenced SDT headers must be readable and
/// identity mapped. The root table must be readable for its advertised
/// length, and the TPM2 table must be exclusively accessible and writable
/// for its advertised length while this function runs.
#[cfg(all(target_arch = "x86_64", not(feature = "native-only")))]
pub unsafe fn take_tpm2_log_area(rsdp_addr: u64, size: usize) -> Option<&'static mut [u8]> {
    use crabefi::efi::allocator::{AllocateType, MemoryType, allocate_pages};

    let (table, length) = unsafe { find_table(rsdp_addr, b"TPM2") }?;
    if length < size_of::<Tpm2WithLogArea>() {
        return None;
    }
    let log_length = u32::try_from(size).ok()?;
    if log_length == 0 {
        return None;
    }
    let mut address = 0;
    let pages = size.div_ceil(4096) as u64;
    if allocate_pages(
        AllocateType::AllocateAnyPages,
        MemoryType::AcpiMemoryNvs,
        pages,
        &mut address,
    ) != r_efi::efi::Status::SUCCESS
    {
        log::warn!("No memory for the ACPI TPM2 log area");
        return None;
    }
    // SAFETY: freshly allocated pages, owned from here on.
    let area = unsafe { core::slice::from_raw_parts_mut(address as *mut u8, size) };
    area.fill(0);

    // SAFETY: the caller's contract; `length` bytes are the table.
    let table = unsafe { core::slice::from_raw_parts_mut(table as *mut u8, length) };
    // The length was checked before allocating the log area.
    set_tpm2_log_area(table, log_length, address).expect("complete TPM2 log area fields");
    log::info!(
        "ACPI TPM2 log area moved to {:#x} ({} bytes)",
        address,
        size
    );
    Some(area)
}

#[cfg(all(target_arch = "x86_64", any(test, not(feature = "native-only"))))]
fn set_tpm2_log_area(table: &mut [u8], length: u32, address: u64) -> Option<()> {
    let (fields, tail) = Tpm2WithLogArea::mut_from_prefix(table).ok()?;
    fields.log_area_minimum_length.set(length);
    fields.log_area_start_address.set(address);
    fields.prefix.header.checksum = 0;
    let sum = fields
        .as_bytes()
        .iter()
        .chain(tail.iter())
        .copied()
        .fold(0u8, u8::wrapping_add);
    fields.prefix.header.checksum = sum.wrapping_neg();
    Some(())
}

#[cfg(all(target_arch = "x86_64", not(feature = "native-only")))]
fn tcpa_log_used_length(log: &[u8]) -> Option<usize> {
    const HEADER_SIZE: usize = 4 + 4 + 20 + 4;
    let mut offset = 0usize;
    while offset + HEADER_SIZE <= log.len() {
        let header = &log[offset..offset + HEADER_SIZE];
        if header.iter().all(|byte| *byte == 0) || header.iter().all(|byte| *byte == 0xff) {
            break;
        }
        let event_size = u32::from_le_bytes(header[28..32].try_into().ok()?) as usize;
        let next = offset.checked_add(HEADER_SIZE)?.checked_add(event_size)?;
        if next > log.len() {
            return None;
        }
        offset = next;
    }
    (offset != 0).then_some(offset)
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

    for entry in mcfg.entries() {
        let region = PciEcamRegion {
            base: entry.base_address,
            segment: entry.pci_segment_group,
            bus_start: entry.bus_number_start,
            bus_end: entry.bus_number_end,
        };
        if info.push_ecam_region(region) {
            log::debug!(
                "ACPI MCFG: retained segment {} buses {:02x}-{:02x} at {:#x}",
                region.segment,
                region.bus_start,
                region.bus_end,
                region.base
            );
        } else {
            log::warn!("ACPI MCFG: skipped invalid/overlapping region {:?}", region);
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

/// Walk the AML namespace and extract platform devices with `_HID` + `_CRS`,
/// the MMIO devices and the connections of I2C devices that a CrabEFI driver
/// supports.
fn discover_namespace_devices(
    interpreter: &acpi::aml::Interpreter<CrabEfiHandler>,
    info: &mut PlatformInfo,
    connections: &mut Vec<peripherals::Connection>,
    mmio: &mut Vec<Peripheral>,
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

        // Honor _STA when present. If absent, ACPI treats the device as present.
        let sta_path = AmlName::from_str("_STA")
            .map_err(|e| {
                log::trace!("ACPI: bad _STA name: {:?}", e);
                e
            })?
            .resolve(path)?;
        if let Ok(Some(sta_obj)) = interpreter.evaluate_if_present(sta_path, vec![])
            && let Object::Integer(sta) = &*sta_obj
            && (*sta & 0x0b) != 0x0b
        {
            return Ok(true);
        }

        let ids = peripherals::ids(interpreter, path);
        if crabefi::peripheral::i2c_supported(ids.iter().map(String::as_str)) {
            connections.extend(peripherals::connection(interpreter, path, ids));
            return Ok(true);
        }

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

        // Only store MMIO devices. A full list must not stop the traversal,
        // which also finds I2C devices.
        if mmio_base != 0
            && mmio_size != 0
            && crabefi::peripheral::mmio_supported(ids.iter().map(String::as_str))
            && peripherals::present(interpreter, path)
            && peripherals::powered(interpreter, path)
        {
            mmio.push(Peripheral::Mmio(crabefi::peripheral::MmioPeripheral {
                ids: ids.clone(),
                base: mmio_base,
                size: mmio_size,
            }));
        }
        if mmio_base != 0 && mmio_size != 0 {
            let name = extract_device_name(path);
            let device = DsdtDevice {
                hid: hid_buf,
                hid_len: hid_len as u8,
                name,
                mmio_base,
                mmio_size,
                irq,
            };
            let _ = info.dsdt_devices.push(device);
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

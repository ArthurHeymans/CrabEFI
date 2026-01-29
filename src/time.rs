//! Time and delay functions
//!
//! This module provides timing primitives using the x86 TSC (Time Stamp Counter),
//! calibrated against the ACPI PM timer for accurate real-time measurements.

use crate::arch::x86_64::io;
use core::sync::atomic::{AtomicU64, Ordering};

// Re-export rdtsc from arch module for public API
pub use crate::arch::x86_64::rdtsc;

/// TSC frequency in Hz (cycles per second)
/// Default to 2 GHz as a conservative fallback
static TSC_FREQ_HZ: AtomicU64 = AtomicU64::new(2_000_000_000);

/// TSC cycles per microsecond (cached for fast access)
static TSC_CYCLES_PER_US: AtomicU64 = AtomicU64::new(2000);

/// ACPI PM timer frequency: 3.579545 MHz
const PM_TIMER_FREQ: u64 = 3_579_545;

/// PM timer I/O port (set during calibration)
static PM_TIMER_PORT: AtomicU64 = AtomicU64::new(0);

/// PM timer is 32-bit (vs 24-bit)
static PM_TIMER_32BIT: AtomicU64 = AtomicU64::new(0);

/// Read the ACPI PM timer value
#[inline]
fn read_pm_timer() -> u32 {
    let port = PM_TIMER_PORT.load(Ordering::Relaxed) as u16;
    if port == 0 {
        return 0;
    }
    unsafe { io::inl(port) }
}

/// ACPI RSDP structure (Root System Description Pointer)
#[repr(C, packed)]
struct AcpiRsdp {
    signature: [u8; 8], // "RSD PTR "
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    // ACPI 2.0+ fields
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}

/// ACPI SDT header (common to all tables)
#[repr(C, packed)]
struct AcpiSdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

/// ACPI FADT (Fixed ACPI Description Table)
#[repr(C, packed)]
struct AcpiFadt {
    header: AcpiSdtHeader,
    firmware_ctrl: u32,
    dsdt: u32,
    reserved1: u8,
    preferred_pm_profile: u8,
    sci_int: u16,
    smi_cmd: u32,
    acpi_enable: u8,
    acpi_disable: u8,
    s4bios_req: u8,
    pstate_cnt: u8,
    pm1a_evt_blk: u32,
    pm1b_evt_blk: u32,
    pm1a_cnt_blk: u32,
    pm1b_cnt_blk: u32,
    pm2_cnt_blk: u32,
    pm_tmr_blk: u32, // PM Timer I/O port address
    gpe0_blk: u32,
    gpe1_blk: u32,
    pm1_evt_len: u8,
    pm1_cnt_len: u8,
    pm2_cnt_len: u8,
    pm_tmr_len: u8, // PM Timer length (4 bytes)
    gpe0_blk_len: u8,
    gpe1_blk_len: u8,
    gpe1_base: u8,
    cst_cnt: u8,
    p_lvl2_lat: u16,
    p_lvl3_lat: u16,
    flush_size: u16,
    flush_stride: u16,
    duty_offset: u8,
    duty_width: u8,
    day_alrm: u8,
    mon_alrm: u8,
    century: u8,
    iapc_boot_arch: u16,
    reserved2: u8,
    flags: u32, // Bit 8: TMR_VAL_EXT (1 = 32-bit timer)
}

/// Find FADT in ACPI tables and extract PM timer port
unsafe fn find_pm_timer_port(rsdp_addr: u64) -> Option<(u16, bool)> {
    let rsdp = &*(rsdp_addr as *const AcpiRsdp);

    // Verify RSDP signature
    if &rsdp.signature != b"RSD PTR " {
        log::warn!("Invalid RSDP signature");
        return None;
    }

    // Get RSDT or XSDT address
    let (table_addr, is_xsdt) =
        if rsdp.revision >= 2 && core::ptr::addr_of!(rsdp.xsdt_address).read_unaligned() != 0 {
            (
                core::ptr::addr_of!(rsdp.xsdt_address).read_unaligned(),
                true,
            )
        } else {
            (rsdp.rsdt_address as u64, false)
        };

    if table_addr == 0 {
        log::warn!("No RSDT/XSDT address in RSDP");
        return None;
    }

    let header = &*(table_addr as *const AcpiSdtHeader);
    let table_len = core::ptr::addr_of!(header.length).read_unaligned() as usize;
    let header_size = core::mem::size_of::<AcpiSdtHeader>();

    // Calculate number of entries
    let entry_size = if is_xsdt { 8 } else { 4 };
    let num_entries = (table_len - header_size) / entry_size;

    log::debug!(
        "ACPI: {} at {:#x}, {} entries",
        if is_xsdt { "XSDT" } else { "RSDT" },
        table_addr,
        num_entries
    );

    // Search for FADT (signature "FACP")
    let entries_base = table_addr + header_size as u64;
    for i in 0..num_entries {
        let entry_addr = if is_xsdt {
            *((entries_base + (i * 8) as u64) as *const u64)
        } else {
            *((entries_base + (i * 4) as u64) as *const u32) as u64
        };

        if entry_addr == 0 {
            continue;
        }

        let entry_header = &*(entry_addr as *const AcpiSdtHeader);
        if &entry_header.signature == b"FACP" {
            let fadt = &*(entry_addr as *const AcpiFadt);
            let pm_tmr_blk = core::ptr::addr_of!(fadt.pm_tmr_blk).read_unaligned();
            let flags = core::ptr::addr_of!(fadt.flags).read_unaligned();
            let is_32bit = (flags & (1 << 8)) != 0; // TMR_VAL_EXT bit

            if pm_tmr_blk != 0 {
                log::debug!(
                    "ACPI FADT: PM timer at I/O port {:#x} ({})",
                    pm_tmr_blk,
                    if is_32bit { "32-bit" } else { "24-bit" }
                );
                return Some((pm_tmr_blk as u16, is_32bit));
            }
        }
    }

    log::warn!("FADT not found or PM timer not available");
    None
}

/// Calibrate TSC using ACPI PM timer
///
/// Measures TSC ticks over a known PM timer interval to determine TSC frequency.
fn calibrate_tsc_with_pm_timer() -> Option<u64> {
    let port = PM_TIMER_PORT.load(Ordering::Relaxed) as u16;
    if port == 0 {
        return None;
    }

    let is_32bit = PM_TIMER_32BIT.load(Ordering::Relaxed) != 0;
    let timer_mask: u32 = if is_32bit { 0xFFFFFFFF } else { 0x00FFFFFF };

    // Wait for PM timer to tick (synchronize)
    let mut last = read_pm_timer() & timer_mask;
    loop {
        let current = read_pm_timer() & timer_mask;
        if current != last {
            break;
        }
        last = current;
    }

    // Measure TSC ticks over ~50ms worth of PM timer ticks
    // 50ms = 178,977 PM timer ticks (at 3.579545 MHz)
    const CALIBRATION_TICKS: u32 = 178_977;

    let pm_start = read_pm_timer() & timer_mask;
    let tsc_start = rdtsc();

    // Wait for CALIBRATION_TICKS PM timer ticks
    loop {
        let pm_current = read_pm_timer() & timer_mask;
        let pm_elapsed = pm_current.wrapping_sub(pm_start) & timer_mask;
        if pm_elapsed >= CALIBRATION_TICKS {
            break;
        }
        core::hint::spin_loop();
    }

    let tsc_end = rdtsc();
    let pm_end = read_pm_timer() & timer_mask;

    // Calculate actual PM timer ticks elapsed
    let pm_elapsed = pm_end.wrapping_sub(pm_start) & timer_mask;

    // Calculate TSC ticks elapsed
    let tsc_elapsed = tsc_end.wrapping_sub(tsc_start);

    // Calculate TSC frequency: tsc_freq = tsc_elapsed * PM_TIMER_FREQ / pm_elapsed
    let tsc_freq = (tsc_elapsed as u128 * PM_TIMER_FREQ as u128 / pm_elapsed as u128) as u64;

    Some(tsc_freq)
}

/// Initialize timing subsystem
///
/// Attempts to calibrate TSC using ACPI PM timer. Falls back to default
/// frequency if calibration fails.
///
/// # Arguments
///
/// * `acpi_rsdp` - Optional ACPI RSDP physical address from coreboot
pub fn init(acpi_rsdp: Option<u64>) {
    log::debug!("Initializing timing subsystem...");

    // Try to find PM timer port from ACPI tables
    if let Some(rsdp_addr) = acpi_rsdp
        && let Some((port, is_32bit)) = unsafe { find_pm_timer_port(rsdp_addr) }
    {
        PM_TIMER_PORT.store(port as u64, Ordering::Relaxed);
        PM_TIMER_32BIT.store(if is_32bit { 1 } else { 0 }, Ordering::Relaxed);

        // Calibrate TSC using PM timer
        if let Some(freq) = calibrate_tsc_with_pm_timer() {
            let cycles_per_us = freq / 1_000_000;
            TSC_FREQ_HZ.store(freq, Ordering::Relaxed);
            TSC_CYCLES_PER_US.store(cycles_per_us, Ordering::Relaxed);

            log::info!(
                "TSC calibrated: {} MHz ({} cycles/us)",
                freq / 1_000_000,
                cycles_per_us
            );
            return;
        }
    }

    // Fallback: use default 2 GHz estimate
    log::warn!("TSC calibration failed, using default 2 GHz estimate");
}

/// Get TSC frequency in Hz
pub fn tsc_frequency() -> u64 {
    TSC_FREQ_HZ.load(Ordering::Relaxed)
}

/// Spin-wait for approximately `us` microseconds
#[inline]
pub fn delay_us(us: u64) {
    let cycles = us * TSC_CYCLES_PER_US.load(Ordering::Relaxed);
    let start = rdtsc();
    while rdtsc().wrapping_sub(start) < cycles {
        core::hint::spin_loop();
    }
}

/// Spin-wait for approximately `ms` milliseconds
#[inline]
pub fn delay_ms(ms: u64) {
    delay_us(ms * 1000);
}

/// A deadline-based timeout for polling loops
///
/// # Example
///
/// ```ignore
/// let timeout = Timeout::from_ms(1000);  // 1 second timeout
/// while !timeout.is_expired() {
///     if check_condition() {
///         return Ok(());
///     }
///     core::hint::spin_loop();
/// }
/// return Err(TimeoutError);
/// ```
#[derive(Clone, Copy)]
pub struct Timeout {
    deadline: u64,
}

impl Timeout {
    /// Create a timeout that expires after `us` microseconds
    #[inline]
    pub fn from_us(us: u64) -> Self {
        let cycles = us * TSC_CYCLES_PER_US.load(Ordering::Relaxed);
        Self {
            deadline: rdtsc().wrapping_add(cycles),
        }
    }

    /// Create a timeout that expires after `ms` milliseconds
    #[inline]
    pub fn from_ms(ms: u64) -> Self {
        Self::from_us(ms * 1000)
    }

    /// Check if the timeout has expired
    #[inline]
    pub fn is_expired(&self) -> bool {
        // Handle wraparound by using signed comparison
        let now = rdtsc();
        let diff = self.deadline.wrapping_sub(now) as i64;
        diff <= 0
    }
}

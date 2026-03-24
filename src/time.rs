//! Time and delay functions
//!
//! This module provides timing primitives using a high-resolution monotonic counter:
//! - **x86_64**: TSC (Time Stamp Counter) calibrated against the ACPI PM timer
//! - **aarch64**: ARM Generic Timer (`CNTPCT_EL0` / `CNTFRQ_EL0`)

#[cfg(target_arch = "x86_64")]
use crate::arch::x86_64::io;
#[cfg(target_arch = "x86_64")]
use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

// ============================================================================
// Architecture-agnostic counter interface
// ============================================================================

/// Read the monotonic counter value
///
/// Returns a raw counter value whose frequency is reported by `counter_frequency()`.
#[inline]
pub fn read_counter() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        crate::arch::x86_64::rdtsc()
    }
    #[cfg(target_arch = "aarch64")]
    {
        crate::arch::aarch64::read_counter()
    }
}

/// Get the counter frequency in Hz
pub fn counter_frequency() -> u64 {
    crate::state::drivers().timing.counter_freq_hz
}

// Re-export read_counter as rdtsc on x86 for backwards compat with existing callers
#[cfg(target_arch = "x86_64")]
pub use crate::arch::x86_64::rdtsc;

// On aarch64, provide rdtsc as an alias for read_counter for source compat
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn rdtsc() -> u64 {
    read_counter()
}

// Re-export counter_frequency as tsc_frequency for backwards compat
pub fn tsc_frequency() -> u64 {
    crate::state::drivers().timing.counter_freq_hz
}

// ============================================================================
// x86_64: ACPI PM Timer calibration
// ============================================================================

#[cfg(target_arch = "x86_64")]
mod x86_calibration {
    use super::*;
    use core::sync::atomic::{AtomicU64, Ordering};

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
    #[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
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
    #[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
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
    #[derive(FromBytes, Immutable, KnownLayout, Unaligned)]
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
        // Safety: caller guarantees rsdp_addr points to a valid ACPI RSDP structure
        // and all ACPI table pointers within are valid mapped memory.
        unsafe {
            let rsdp = &*(rsdp_addr as *const AcpiRsdp);

            // Verify RSDP signature
            if &rsdp.signature != b"RSD PTR " {
                log::warn!("Invalid RSDP signature");
                return None;
            }

            // Get RSDT or XSDT address
            let (table_addr, is_xsdt) = if rsdp.revision >= 2 && rsdp.xsdt_address != 0 {
                (rsdp.xsdt_address, true)
            } else {
                (rsdp.rsdt_address as u64, false)
            };

            if table_addr == 0 {
                log::warn!("No RSDT/XSDT address in RSDP");
                return None;
            }

            let header = &*(table_addr as *const AcpiSdtHeader);
            let table_len = header.length as usize;
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
                    ((entries_base + (i * 8) as u64) as *const u64).read_unaligned()
                } else {
                    ((entries_base + (i * 4) as u64) as *const u32).read_unaligned() as u64
                };

                if entry_addr == 0 {
                    continue;
                }

                let entry_header = &*(entry_addr as *const AcpiSdtHeader);
                if &entry_header.signature == b"FACP" {
                    let fadt = &*(entry_addr as *const AcpiFadt);
                    let pm_tmr_blk = fadt.pm_tmr_blk;
                    let flags = fadt.flags;
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
    }

    /// Calibrate TSC using ACPI PM timer
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
        const CALIBRATION_TICKS: u32 = 178_977;

        let pm_start = read_pm_timer() & timer_mask;
        let tsc_start = rdtsc();

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

        let pm_elapsed = pm_end.wrapping_sub(pm_start) & timer_mask;
        let tsc_elapsed = tsc_end.wrapping_sub(tsc_start);
        let tsc_freq = (tsc_elapsed as u128 * PM_TIMER_FREQ as u128 / pm_elapsed as u128) as u64;

        Some(tsc_freq)
    }

    /// Initialize x86 timing (calibrate TSC via ACPI PM timer)
    pub fn init(acpi_rsdp: Option<u64>) {
        log::debug!("Initializing timing subsystem (x86_64 TSC)...");

        if let Some(rsdp_addr) = acpi_rsdp
            && let Some((port, is_32bit)) = unsafe { find_pm_timer_port(rsdp_addr) }
        {
            PM_TIMER_PORT.store(port as u64, Ordering::Relaxed);
            PM_TIMER_32BIT.store(if is_32bit { 1 } else { 0 }, Ordering::Relaxed);

            if let Some(freq) = calibrate_tsc_with_pm_timer() {
                let cycles_per_us = freq / 1_000_000;
                // SAFETY: single-threaded init; raw pointer avoids re-entrancy
                // issues with the state lock.
                unsafe {
                    let t = &mut (*crate::state::drivers_mut_ptr()).timing;
                    t.counter_freq_hz = freq;
                    t.counter_cycles_per_us = cycles_per_us;
                }

                log::info!(
                    "TSC calibrated: {} MHz ({} cycles/us)",
                    freq / 1_000_000,
                    cycles_per_us
                );
                return;
            }
        }

        log::warn!("TSC calibration failed, using default 2 GHz estimate");
    }
}

// ============================================================================
// aarch64: ARM Generic Timer
// ============================================================================

#[cfg(target_arch = "aarch64")]
mod aarch64_timer {
    /// Initialize aarch64 timing from the Generic Timer frequency register
    pub fn init(_acpi_rsdp: Option<u64>) {
        let freq = crate::arch::aarch64::read_counter_freq();

        if freq == 0 {
            log::warn!("ARM Generic Timer frequency is 0, using 62.5 MHz fallback");
            let fallback = 62_500_000u64;
            // SAFETY: single-threaded init; raw pointer avoids re-entrancy
            // issues with the state lock.
            unsafe {
                let t = &mut (*crate::state::drivers_mut_ptr()).timing;
                t.counter_freq_hz = fallback;
                t.counter_cycles_per_us = fallback / 1_000_000;
            }
            return;
        }

        let cycles_per_us = freq / 1_000_000;
        // SAFETY: single-threaded init; raw pointer avoids re-entrancy
        // issues with the state lock.
        unsafe {
            let t = &mut (*crate::state::drivers_mut_ptr()).timing;
            t.counter_freq_hz = freq;
            t.counter_cycles_per_us = cycles_per_us.max(1);
        }

        log::info!(
            "ARM Generic Timer: {} MHz ({} cycles/us)",
            freq / 1_000_000,
            cycles_per_us
        );
    }
}

// ============================================================================
// Public API (arch-agnostic)
// ============================================================================

/// Initialize timing subsystem
///
/// # Arguments
///
/// * `acpi_rsdp` - Optional ACPI RSDP physical address from coreboot
pub fn init(acpi_rsdp: Option<u64>) {
    #[cfg(target_arch = "x86_64")]
    x86_calibration::init(acpi_rsdp);
    #[cfg(target_arch = "aarch64")]
    aarch64_timer::init(acpi_rsdp);
}

/// Initialize timing subsystem from a platform-provided [`Timer`] trait object.
///
/// Used by [`crate::init_platform()`]. The platform timer is the source of
/// truth — no architecture-specific hardware detection is attempted.
pub fn init_from_platform(timer: &dyn crate::platform::Timer) {
    let freq = timer.ticks_per_second();
    if freq == 0 {
        log::warn!("Platform timer reports 0 Hz frequency, using 1 MHz fallback");
        let fallback = 1_000_000u64;
        // SAFETY: single-threaded init; raw pointer avoids re-entrancy
        // issues with the state lock.
        unsafe {
            let t = &mut (*crate::state::drivers_mut_ptr()).timing;
            t.counter_freq_hz = fallback;
            t.counter_cycles_per_us = 1;
        }
        return;
    }

    let cycles_per_us = (freq / 1_000_000).max(1);
    // SAFETY: single-threaded init; raw pointer avoids re-entrancy
    // issues with the state lock.
    unsafe {
        let t = &mut (*crate::state::drivers_mut_ptr()).timing;
        t.counter_freq_hz = freq;
        t.counter_cycles_per_us = cycles_per_us;
        t.boot_counter = timer.current_ticks();
    }

    log::info!(
        "Platform timer: {} MHz ({} cycles/us)",
        freq / 1_000_000,
        cycles_per_us
    );
}

/// Spin-wait for approximately `us` microseconds
#[inline]
pub fn delay_us(us: u64) {
    let cycles = us * crate::state::drivers().timing.counter_cycles_per_us;
    let start = read_counter();
    while read_counter().wrapping_sub(start) < cycles {
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
        let cycles = us * crate::state::drivers().timing.counter_cycles_per_us;
        Self {
            deadline: read_counter().wrapping_add(cycles),
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
        let now = read_counter();
        let diff = self.deadline.wrapping_sub(now) as i64;
        diff <= 0
    }
}

/// Wait for a condition to become true, with timeout
///
/// Spins until `condition()` returns `true` or the timeout expires.
/// Returns `true` if the condition was met, `false` if timeout expired.
#[inline]
pub fn wait_for<F>(timeout_ms: u64, condition: F) -> bool
where
    F: Fn() -> bool,
{
    let timeout = Timeout::from_ms(timeout_ms);
    while !timeout.is_expired() {
        if condition() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Wait for a condition with a custom action on each iteration
#[inline]
pub fn wait_for_with<A, C>(timeout_ms: u64, mut action: A, condition: C) -> bool
where
    A: FnMut(),
    C: Fn() -> bool,
{
    let timeout = Timeout::from_ms(timeout_ms);
    while !timeout.is_expired() {
        action();
        if condition() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

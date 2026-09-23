//! Shared time utilities for the auth subsystem
//!
//! Provides RTC reading used by multiple auth submodules (crypto,
//! revocation, dbx_update).

use crabefi_efi_types::authentication::EfiTime;
use crabefi_pkcs7::time::DateTime;

/// Deterministic stand-in for host unit tests: the certificate fixtures in
/// crabefi-pkcs7/testdata/ and the CRLs in auth/testdata/ are valid across
/// this date (certs 2026-09-09 +825d, CRLs +30d), so time-dependent checks
/// behave deterministically.
#[cfg(test)]
pub(crate) fn read_rtc_time() -> (u16, u8, u8, u8, u8, u8) {
    (2026, 9, 10, 0, 0, 0)
}

/// Read the current date/time from the hardware RTC
///
/// Returns `(year, month, day, hour, minute, second)`.
///
/// - **x86_64**: Reads the CMOS RTC via I/O ports 0x70/0x71
/// - **aarch64**: Returns a fallback value (PL031 RTC support TODO)
#[cfg(not(test))]
pub(crate) fn read_rtc_time() -> (u16, u8, u8, u8, u8, u8) {
    #[cfg(target_arch = "x86_64")]
    {
        read_rtc_time_x86()
    }
    #[cfg(target_arch = "aarch64")]
    {
        // TODO: Implement PL031 RTC reading for aarch64 SBSA
        // For now, return a safe fallback time
        log::debug!("RTC: aarch64 PL031 not yet implemented, using fallback time");
        (2025, 1, 1, 0, 0, 0)
    }
    #[cfg(target_arch = "riscv64")]
    {
        // RISC-V has no standard RTC interface accessible from S-mode.
        // The goldfish-rtc or similar would require FDT parsing.
        log::debug!("RTC: RISC-V RTC not yet implemented, using fallback time");
        (2025, 1, 1, 0, 0, 0)
    }
}

/// x86 CMOS RTC implementation
#[cfg(target_arch = "x86_64")]
#[cfg_attr(test, allow(dead_code))] // Test builds use the stubbed read_rtc_time above.
fn read_rtc_time_x86() -> (u16, u8, u8, u8, u8, u8) {
    use crate::arch::x86_64::io;

    // Wait for RTC update to complete (bounded to avoid infinite loop)
    for _ in 0..10_000 {
        unsafe {
            io::outb(0x70, 0x0A);
            if io::inb(0x71) & 0x80 == 0 {
                break;
            }
        }
    }

    let read_cmos = |reg: u8| -> u8 {
        unsafe {
            io::outb(0x70, reg);
            io::inb(0x71)
        }
    };

    let second = read_cmos(0x00);
    let minute = read_cmos(0x02);
    let hour = read_cmos(0x04);
    let day = read_cmos(0x07);
    let month = read_cmos(0x08);
    let year = read_cmos(0x09);
    let century = read_cmos(0x32);

    // Check if BCD mode
    let status_b = read_cmos(0x0B);
    let is_bcd = (status_b & 0x04) == 0;

    let convert = |val: u8| -> u8 {
        if is_bcd {
            (val & 0x0F) + ((val >> 4) * 10)
        } else {
            val
        }
    };

    let second = convert(second);
    let minute = convert(minute);
    let hour = convert(hour);
    let day = convert(day);
    let month = convert(month);
    let year = convert(year);
    let century = if century > 0 { convert(century) } else { 20 };

    let full_year = (century as u16) * 100 + (year as u16);

    // Validate RTC values to guard against corrupted CMOS or garbage BCD data.
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        log::warn!(
            "RTC: invalid time values: {}-{:02}-{:02} {:02}:{:02}:{:02}, using fallback",
            full_year,
            month,
            day,
            hour,
            minute,
            second
        );
        return (2025, 1, 1, 0, 0, 0);
    }

    (full_year, month, day, hour, minute, second)
}

/// Read the current time as an `EfiTime` struct
///
/// Convenience wrapper around [`read_rtc_time`] for callers that need
/// the full UEFI time structure.
pub(crate) fn read_rtc_efi_time() -> EfiTime {
    let (year, month, day, hour, minute, second) = read_rtc_time();
    EfiTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
        pad1: 0,
        nanosecond: 0,
        timezone: 0x7FF, // EFI_UNSPECIFIED_TIMEZONE
        daylight: 0,
        pad2: 0,
    }
}

/// Read the current time as a Unix timestamp (seconds since epoch)
pub(crate) fn current_unix_timestamp() -> i64 {
    let (year, month, day, hour, minute, second) = read_rtc_time();
    DateTime {
        year,
        month,
        day,
        hour,
        minute,
        second,
    }
    .unix_timestamp()
}

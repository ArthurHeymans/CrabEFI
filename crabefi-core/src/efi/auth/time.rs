//! Shared time utilities for the auth subsystem
//!
//! Provides RTC reading for certificate validation.

use crabefi_pkcs7::time::DateTime;

/// Deterministic stand-in for host unit tests: the certificate fixtures in
/// crabefi-pkcs7/testdata/ and the CRLs in auth/testdata/ are valid across
/// this date (certs 2026-09-09 +825d, CRLs +30d), so time-dependent checks
/// behave deterministically.
#[cfg(test)]
pub(crate) fn read_rtc_time() -> Result<DateTime, &'static str> {
    Ok(DateTime {
        year: 2026,
        month: 9,
        day: 10,
        hour: 0,
        minute: 0,
        second: 0,
    })
}

/// Read the current UTC date/time from the hardware RTC.
///
/// Returns the reason instead of a substitute date when no usable time is
/// available, so callers decide explicitly how to handle an unknown clock.
///
/// - **x86_64**: Reads the CMOS RTC via I/O ports 0x70/0x71
/// - **aarch64**, **riscv64**: Unavailable; no boot-time PL031/Goldfish RTC
///   reader is wired up
#[cfg(not(test))]
pub(crate) fn read_rtc_time() -> Result<DateTime, &'static str> {
    #[cfg(target_arch = "x86_64")]
    {
        read_rtc_time_x86()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        Err("no boot-time RTC on this architecture")
    }
}

/// x86 CMOS RTC implementation
#[cfg(target_arch = "x86_64")]
#[cfg_attr(test, allow(dead_code))] // Test builds use the stubbed read_rtc_time above.
fn read_rtc_time_x86() -> Result<DateTime, &'static str> {
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
            "RTC: invalid time values: {}-{:02}-{:02} {:02}:{:02}:{:02}",
            full_year,
            month,
            day,
            hour,
            minute,
            second
        );
        return Err("invalid CMOS RTC values");
    }

    Ok(DateTime {
        year: full_year,
        month,
        day,
        hour,
        minute,
        second,
    })
}

/// Read the current time as a Unix timestamp (seconds since epoch).
pub(crate) fn current_unix_timestamp() -> Result<i64, &'static str> {
    read_rtc_time().map(|time| time.unix_timestamp())
}

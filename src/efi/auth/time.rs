//! Shared time utilities for the auth subsystem
//!
//! Provides RTC reading and date-to-timestamp conversion used by
//! multiple auth submodules (crypto, revocation, dbx_update).

use super::AuthError;
use super::structures::EfiTime;

/// Convert a date/time to Unix timestamp (seconds since 1970-01-01 00:00:00 UTC)
///
/// Delegates to [`der::DateTime`] which handles leap years correctly.
pub(crate) fn datetime_to_unix_timestamp(
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
) -> i64 {
    // der::DateTime::new validates ranges; on invalid input fall back to 0
    der::DateTime::new(
        year as u16,
        month as u8,
        day as u8,
        hour as u8,
        minute as u8,
        second as u8,
    )
    .map(|dt| dt.unix_duration().as_secs() as i64)
    .unwrap_or(0)
}

/// Convert an x509 `Time` to a Unix timestamp
pub(crate) fn x509_time_to_unix(time: &x509_cert::time::Time) -> Result<i64, AuthError> {
    use x509_cert::time::Time;

    let dt = match time {
        Time::UtcTime(t) => t.to_date_time(),
        Time::GeneralTime(t) => t.to_date_time(),
    };

    Ok(dt.unix_duration().as_secs() as i64)
}

/// Read the current date/time from the CMOS RTC
///
/// Returns `(year, month, day, hour, minute, second)`.
/// Handles both BCD and binary RTC modes, and reads the century register.
pub(crate) fn read_rtc_time() -> (u16, u8, u8, u8, u8, u8) {
    use crate::arch::x86_64::io;

    // Wait for RTC update to complete
    loop {
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
    datetime_to_unix_timestamp(
        year as i64,
        month as i64,
        day as i64,
        hour as i64,
        minute as i64,
        second as i64,
    )
}

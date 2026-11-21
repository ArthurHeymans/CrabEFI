use crabefi_runtime_abi::TimeMechanism;

use crate::{arch, efi, state};

pub extern "efiapi" fn get_time(
    time: *mut efi::Time,
    capabilities: *mut efi::TimeCapabilities,
) -> efi::Status {
    efi::status(current_time(time, capabilities))
}

fn current_time(
    time: *mut efi::Time,
    capabilities: *mut efi::TimeCapabilities,
) -> Result<(), efi::Status> {
    if time.is_null() {
        return Err(efi::Status::INVALID_PARAMETER);
    }
    let lease = state::lease()?;
    // SAFETY: UEFI requires `time` to name writable EFI_TIME storage. We have
    // checked null and write exactly one value.
    arch::read_time(lease.state().time, unsafe { &mut *time })?;
    if !capabilities.is_null() {
        // SAFETY: optional output is written only when non-null.
        unsafe {
            capabilities.write(efi::TimeCapabilities {
                resolution: 1,
                accuracy: 50_000_000,
                sets_to_zero: efi::Boolean::FALSE,
            })
        };
    }
    Ok(())
}

pub extern "efiapi" fn set_time(_time: *mut efi::Time) -> efi::Status {
    efi::Status::UNSUPPORTED
}

pub extern "efiapi" fn get_wakeup_time(
    _enabled: *mut efi::Boolean,
    _pending: *mut efi::Boolean,
    _time: *mut efi::Time,
) -> efi::Status {
    efi::Status::UNSUPPORTED
}

pub extern "efiapi" fn set_wakeup_time(
    _enable: efi::Boolean,
    _time: *mut efi::Time,
) -> efi::Status {
    efi::Status::UNSUPPORTED
}

pub extern "efiapi" fn get_next_high_mono_count(_high_count: *mut u32) -> efi::Status {
    efi::Status::UNSUPPORTED
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
pub fn time_from_unix(seconds: u64, out: &mut efi::Time) -> Result<(), efi::Status> {
    let days = i64::try_from(seconds / 86_400).map_err(|_| efi::Status::DEVICE_ERROR)?;
    let day_seconds = seconds % 86_400;
    let z = days.checked_add(719_468).ok_or(efi::Status::DEVICE_ERROR)?;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += (month <= 2) as i64;
    if !(1900..=9999).contains(&year) {
        return Err(efi::Status::DEVICE_ERROR);
    }
    out.year = year as u16;
    out.month = month as u8;
    out.day = day as u8;
    out.hour = (day_seconds / 3_600) as u8;
    out.minute = ((day_seconds % 3_600) / 60) as u8;
    out.second = (day_seconds % 60) as u8;
    out.pad1 = 0;
    out.nanosecond = 0;
    out.timezone = 0x07ff;
    out.daylight = 0;
    out.pad2 = 0;
    Ok(())
}

pub fn time_is_supported(mechanism: TimeMechanism) -> bool {
    #[cfg(target_arch = "x86_64")]
    return mechanism == TimeMechanism::X86Cmos;
    #[cfg(target_arch = "aarch64")]
    return mechanism == TimeMechanism::Pl031;
    #[cfg(target_arch = "riscv64")]
    return mechanism == TimeMechanism::GoldfishRtc;
}

//! x86-64 CMOS time and legacy reset mechanisms.

use crabefi_runtime_abi::{RuntimeResetConfig, RuntimeTimeConfig, reset_mechanism, time_mechanism};

use crate::efi;

#[inline]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: the caller supplies a validated, architecture-defined I/O port.
    unsafe {
        core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack))
    };
    value
}

#[inline]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the caller supplies a validated, architecture-defined I/O port.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack))
    };
}

fn rtc_register(index: u8) -> u8 {
    // SAFETY: ports 0x70/0x71 are the architectural CMOS index/data pair.
    unsafe {
        outb(0x70, index);
        inb(0x71)
    }
}

fn from_bcd(value: u8) -> Option<u8> {
    let low = value & 0x0f;
    let high = value >> 4;
    (low < 10 && high < 10).then_some(high * 10 + low)
}

fn wait_for_rtc_update() -> Result<(), efi::Status> {
    for _ in 0..1_000_000 {
        if rtc_register(0x0a) & 0x80 == 0 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(efi::Status::DEVICE_ERROR)
}

pub fn read_time(config: RuntimeTimeConfig, out: &mut efi::Time) -> Result<(), efi::Status> {
    if config.mechanism != time_mechanism::X86_CMOS {
        return Err(efi::Status::UNSUPPORTED);
    }
    for _ in 0..3 {
        wait_for_rtc_update()?;
        let status_b = rtc_register(0x0b);
        let binary = status_b & 0x04 != 0;
        let decode = |value| {
            if binary { Some(value) } else { from_bcd(value) }
        };
        let second_before = rtc_register(0x00);
        let minute = rtc_register(0x02);
        let hour = rtc_register(0x04);
        let pm = hour & 0x80 != 0;
        let day = rtc_register(0x07);
        let month = rtc_register(0x08);
        let year = rtc_register(0x09);
        let second_after = rtc_register(0x00);
        if second_before != second_after || rtc_register(0x0a) & 0x80 != 0 {
            continue;
        }
        let mut hour = decode(hour & 0x7f).ok_or(efi::Status::DEVICE_ERROR)?;
        if status_b & 0x02 == 0 {
            if hour == 0 || hour > 12 {
                return Err(efi::Status::DEVICE_ERROR);
            }
            hour %= 12;
            if pm {
                hour += 12;
            }
        }
        let (second, minute, day, month, year) = (
            decode(second_after).ok_or(efi::Status::DEVICE_ERROR)?,
            decode(minute).ok_or(efi::Status::DEVICE_ERROR)?,
            decode(day).ok_or(efi::Status::DEVICE_ERROR)?,
            decode(month).ok_or(efi::Status::DEVICE_ERROR)?,
            decode(year).ok_or(efi::Status::DEVICE_ERROR)?,
        );
        if second > 59
            || minute > 59
            || hour > 23
            || !(1..=31).contains(&day)
            || !(1..=12).contains(&month)
        {
            return Err(efi::Status::DEVICE_ERROR);
        }
        // CMOS century register assignments are platform-specific. CrabEFI
        // uses the conventional 2000..=2099 window rather than trusting 0x32.
        out.year = 2000 + u16::from(year);
        out.month = month;
        out.day = day;
        out.hour = hour;
        out.minute = minute;
        out.second = second;
        out.pad1 = 0;
        out.nanosecond = 0;
        out.timezone = 0x07ff;
        out.daylight = 0;
        out.pad2 = 0;
        return Ok(());
    }
    Err(efi::Status::DEVICE_ERROR)
}

fn reset_port(configured: u64) -> u16 {
    match u16::try_from(configured) {
        Ok(0) | Err(_) => 0xcf9,
        Ok(port) => port,
    }
}

pub fn reset(config: RuntimeResetConfig, reset_type: efi::ResetType) -> ! {
    if config.mechanism == reset_mechanism::X86_LEGACY {
        let port = reset_port(config.io_or_mmio_base);
        // QEMU and most modern chipsets implement reset control at the
        // platform-provided CF9-compatible reset port.
        // SAFETY: initialization supplies the selected x86 reset mechanism.
        unsafe {
            outb(
                port,
                if reset_type == efi::RESET_SHUTDOWN {
                    0x04
                } else {
                    0x06
                },
            )
        };
        for _ in 0..100_000 {
            core::hint::spin_loop();
        }
        // Fall back to the keyboard-controller pulse.
        // SAFETY: 0x64 is the architectural i8042 command port.
        unsafe { outb(0x64, 0xfe) };
    }
    loop {
        // SAFETY: halting is the terminal fallback after ResetSystem.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

#[cfg(test)]
mod tests {
    use super::reset_port;

    #[test]
    fn reset_port_uses_cf9_for_missing_or_invalid_configuration() {
        assert_eq!(reset_port(0), 0xcf9);
        assert_eq!(reset_port(0xcf9), 0xcf9);
        assert_eq!(reset_port(0x1234), 0x1234);
        assert_eq!(reset_port(u64::from(u16::MAX) + 1), 0xcf9);
    }
}

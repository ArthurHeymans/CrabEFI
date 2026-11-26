//! x86-64 CMOS time and legacy reset mechanisms.

use crabefi_runtime_abi::{ResetMechanism, TimeMechanism};

use crate::{
    efi,
    state::{ResetConfig, TimeConfig},
};

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
unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    // SAFETY: the caller supplies a validated, architecture-defined I/O port.
    unsafe {
        core::arch::asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack))
    };
    value
}

#[inline]
unsafe fn outw(port: u16, value: u16) {
    // SAFETY: the caller supplies a validated, architecture-defined I/O port.
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack))
    };
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

pub fn read_time(config: TimeConfig, out: &mut efi::Time) -> Result<(), efi::Status> {
    if config.mechanism != TimeMechanism::X86Cmos {
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

/// The AMD FCH's power-management registers, from its ACPI-MMIO block.
/// The recipes are fstart's (`fstart_driver_amd::fch::qilian::reset`,
/// `prepare` and `ResetKind`; its S5 path `fch::sx`/`qilian::sx`): keep
/// the two in step.
mod amd_fch {
    /// PMx10 ResetControl0: bit 1 ToggleAllPwrGood (the next CF9h reset
    /// is a cold one).
    pub const PM_RESET_CONTROL0: usize = 0x310;
    pub const TOGGLE_ALL_PWR_GOOD: u8 = 1 << 1;
    /// PMxC2, byte 2 of the reset status PMxC0 (write 1 to clear): bit 4
    /// is the last full reset.
    pub const PM_RESET_STATUS2: usize = 0x3c2;
    pub const FULL_RESET_STATUS: u8 = 1 << 4;
    /// PMxD2: bit 6 Cf9RstDisable.
    pub const PM_D2: usize = 0x3d2;
    pub const CF9_RESET_DISABLE: u8 = 1 << 6;
    /// PMx62 (16-bit): the I/O port of PM1_CNT the FCH decodes, the one
    /// the FADT names and the OS's sleep writes go to.
    pub const PM_ACPI_PM1_CNT: usize = 0x362;
    /// PM1_CNT through the ACPI MMIO, whatever PMx62 decodes.
    pub const ACPI_PM1_CNT: usize = 0x804;
    /// PM1_CNT SLP_TYP (bits 12:10) and SLP_EN (bit 13).
    pub const SLP_TYP_MASK: u16 = 7 << 10;
    pub const SLP_TYP_S5: u16 = 5 << 10;
    pub const SLP_EN: u16 = 1 << 13;
    /// CF9h FullRst | RstCpu | SysRst.
    pub const FULL_RESET: u8 = 0x0e;

    /// The byte writes ahead of CF9h for `cold`, as `(offset, and, or)`:
    /// both clear Cf9RstDisable; cold sets ToggleAllPwrGood and leaves the
    /// reset status alone (fstart's `ResetKind::Full`, AMD's DXE cold
    /// ResetSystem); warm clears ToggleAllPwrGood and writes PMxC2 back
    /// with the full-reset status (`ResetKind::Warm`: a write-1-to-clear
    /// of PMxC0[23:16]). The CF9h value follows: a cold reset is the full
    /// one, 0Eh, as both of AMD's Venice ResetSystem builds write it; a
    /// warm one 06h.
    pub const fn writes(cold: bool) -> &'static [(usize, u8, u8)] {
        if cold {
            &[
                (PM_D2, !CF9_RESET_DISABLE, 0),
                (PM_RESET_CONTROL0, 0xff, TOGGLE_ALL_PWR_GOOD),
            ]
        } else {
            &[
                (PM_D2, !CF9_RESET_DISABLE, 0),
                (PM_RESET_CONTROL0, !TOGGLE_ALL_PWR_GOOD, 0),
                (PM_RESET_STATUS2, 0xff, FULL_RESET_STATUS),
            ]
        }
    }

    /// PM1_CNT's two writes of an S5 entry from its value `pm1_cnt`: SLP_TYP
    /// 5 with SLP_EN clear, then SLP_EN set (fstart's `sx::arm` and
    /// `Armed::enter`; an SMM that traps SLP_TYP finishes the AMD way,
    /// with the SMU's sleep entry).
    pub const fn s5(pm1_cnt: u16) -> [u16; 2] {
        let typ = (pm1_cnt & !(SLP_TYP_MASK | SLP_EN)) | SLP_TYP_S5;
        [typ, typ | SLP_EN]
    }
}

/// The AMD FCH's byte writes ahead of CF9h ([`amd_fch::writes`]).
fn amd_fch_prepare(block: *mut u8, cold: bool) {
    for &(offset, and, or) in amd_fch::writes(cold) {
        // SAFETY: initialization validated that a retained external range
        // covers the ACPI-MMIO page at `block` (virtual after
        // SetVirtualAddressMap); the registers are bytes of its PM block.
        unsafe {
            let register = block.add(offset);
            let value = core::ptr::read_volatile(register);
            core::ptr::write_volatile(register, (value & and) | or);
        }
    }
}

/// S5 through PM1_CNT, at the port the FCH decodes (PMx62), else through
/// the ACPI MMIO; if the system still runs a while later, the cold reset,
/// as fstart's S5 path falls back to Qilian's full reset.
fn amd_fch_shutdown(block: *mut u8) {
    // SAFETY: as in `amd_fch_prepare`: PMx62 and PM1_CNT are 16-bit
    // registers of the retained ACPI-MMIO page.
    let port =
        unsafe { core::ptr::read_volatile(block.add(amd_fch::PM_ACPI_PM1_CNT).cast::<u16>()) };
    // SAFETY: an offset inside the same ACPI-MMIO page.
    let mmio = unsafe { block.add(amd_fch::ACPI_PM1_CNT).cast::<u16>() };
    let io = port != 0 && port != u16::MAX;
    // SAFETY: the PM1_CNT the FCH decodes, as the FADT names it, or its
    // ACPI-MMIO alias.
    let value = unsafe {
        if io {
            inw(port)
        } else {
            core::ptr::read_volatile(mmio)
        }
    };
    for write in amd_fch::s5(value) {
        // SAFETY: as above.
        unsafe {
            if io {
                outw(port, write)
            } else {
                core::ptr::write_volatile(mmio, write)
            }
        }
    }
    for _ in 0..10_000_000 {
        core::hint::spin_loop();
    }
}

pub fn reset(config: Option<ResetConfig>, reset_type: efi::ResetType) -> ! {
    match config {
        Some(ResetConfig {
            mechanism: ResetMechanism::X86Legacy,
            base,
        }) => cf9(reset_port(base), reset_type),
        Some(ResetConfig {
            mechanism: ResetMechanism::X86AmdFch,
            base,
        }) => {
            let block = base as usize as *mut u8;
            if reset_type == efi::RESET_SHUTDOWN {
                amd_fch_shutdown(block);
            }
            if reset_type == efi::RESET_WARM {
                amd_fch_prepare(block, false);
                cf9(0xcf9, reset_type)
            } else {
                amd_fch_prepare(block, true);
                // SAFETY: the FCH's CF9h reset port; FullRst with the power
                // goods toggled (PMx10[1], set above).
                unsafe { outb(0xcf9, amd_fch::FULL_RESET) };
                kbc_fallback();
            }
        }
        _ => {}
    }
    loop {
        // SAFETY: halting is the terminal fallback after ResetSystem.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

/// The CF9h-compatible reset at `port`, then the keyboard controller's.
fn cf9(port: u16, reset_type: efi::ResetType) {
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
    kbc_fallback();
}

/// A while for the reset to land, then the keyboard controller's pulse.
fn kbc_fallback() {
    for _ in 0..100_000 {
        core::hint::spin_loop();
    }
    // Fall back to the keyboard-controller pulse.
    // SAFETY: 0x64 is the architectural i8042 command port.
    unsafe { outb(0x64, 0xfe) };
}

#[cfg(test)]
mod tests {
    use super::{amd_fch, reset_port};

    #[test]
    fn amd_fch_cold_sets_and_warm_clears_toggle_all_power_good() {
        // fstart's qilian::reset::prepare: Full sets PMx10[1] and leaves
        // PMxC2 alone; Warm clears PMx10[1] and writes PMxC2 | 10h.
        let cold = amd_fch::writes(true);
        assert_eq!(cold, [(0x3d2, !0x40, 0), (0x310, 0xff, 0x02)]);
        assert!(cold.iter().all(|w| w.0 != 0x3c2));
        let warm = amd_fch::writes(false);
        assert_eq!(
            warm,
            [(0x3d2, !0x40, 0), (0x310, !0x02, 0), (0x3c2, 0xff, 0x10)]
        );
    }

    #[test]
    fn amd_fch_shutdown_is_slp_typ_5_then_slp_en() {
        // SCI_EN and SLP_TYP 0 before: SLP_TYP 5 kept with SCI_EN, then
        // SLP_EN; a stale SLP_EN or SLP_TYP is replaced.
        assert_eq!(amd_fch::s5(0x0001), [0x1401, 0x3401]);
        assert_eq!(amd_fch::s5(0x2c01), [0x1401, 0x3401]);
    }

    #[test]
    fn reset_port_uses_cf9_for_missing_or_invalid_configuration() {
        assert_eq!(reset_port(0), 0xcf9);
        assert_eq!(reset_port(0xcf9), 0xcf9);
        assert_eq!(reset_port(0x1234), 0x1234);
        assert_eq!(reset_port(u64::from(u16::MAX) + 1), 0xcf9);
    }
}

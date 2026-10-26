use super::designware::{DesignWare, Error};
use core::cell::UnsafeCell;
use embedded_hal::delay::DelayNs;
use std::boxed::Box;

struct Delay;
impl DelayNs for Delay {
    fn delay_ns(&mut self, _: u32) {
        panic!("idle controller must not wait");
    }
}
fn registers() -> &'static UnsafeCell<[u32; 64]> {
    let mut words = [0; 64];
    words[0] = 1 | (2 << 1) | (1 << 5) | (1 << 6);
    words[0x1c / 4] = 117;
    words[0x20 / 4] = 245;
    words[0x30 / 4] = 0x242;
    words[0x7c / 4] = 45;
    words[0xa0 / 4] = 2;
    words[0xfc / 4] = 0x4457_0140;
    Box::leak(Box::new(UnsafeCell::new(words)))
}
#[test]
fn adoption_preserves_firmware_clock_and_pad_timings() {
    let regs = registers();
    // SAFETY: single-threaded, RAM-backed fake register storage.
    let mut expected = unsafe { *regs.get() };
    expected[0x30 / 4] = 0; // Polling must not enable hardware interrupts.
    let base = regs.get() as usize;
    // SAFETY: aligned, complete fake register block, exclusively owned.
    let _bus = unsafe { DesignWare::attach(base, 256, 400_000, Delay) }.unwrap();
    assert_eq!(unsafe { *regs.get() }, expected);
}
#[test]
fn invalid_regions_and_uninitialized_modes_are_rejected() {
    assert!(matches!(
        unsafe { DesignWare::attach(0, 256, 400_000, Delay) },
        Err(Error::InvalidRegion)
    ));
    let regs = registers();
    let base = regs.get() as usize;
    assert!(matches!(
        unsafe { DesignWare::attach(base, 252, 400_000, Delay) },
        Err(Error::InvalidRegion)
    ));
    assert!(matches!(
        unsafe { DesignWare::attach(base, 256, 100_000, Delay) },
        Err(Error::NotConfigured)
    ));
    assert!(matches!(
        unsafe { DesignWare::attach(base, 256, 1_000_000, Delay) },
        Err(Error::UnsupportedSpeed)
    ));
    unsafe {
        (*regs.get())[0] = 0;
    }
    assert!(matches!(
        unsafe { DesignWare::attach(base, 256, 400_000, Delay) },
        Err(Error::NotConfigured)
    ));
}

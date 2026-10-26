use super::{DesignWare, Error};
use core::cell::UnsafeCell;
use embedded_hal::delay::DelayNs;
use embedded_hal::i2c::{NoAcknowledgeSource, Operation};
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
fn write_abort_is_reported_without_waiting_for_stop() {
    let regs = registers();
    let base = regs.get() as usize;
    // SAFETY: aligned, complete fake register block, exclusively owned.
    let mut bus = unsafe { DesignWare::attach(base, 256, 400_000, Delay) }.unwrap();
    unsafe {
        (*regs.get())[0x34 / 4] = 1 << 6; // TX_ABRT, without STOP_DET
        (*regs.get())[0x80 / 4] = 1; // address NACK
    }
    assert_eq!(
        bus.finish(),
        Err(Error::NoAcknowledge(NoAcknowledgeSource::Address))
    );
}

#[test]
fn empty_operations_do_not_transmit_a_dummy_byte() {
    let regs = registers();
    let base = regs.get() as usize;
    // SAFETY: aligned, complete fake register block, exclusively owned.
    let mut bus = unsafe { DesignWare::attach(base, 256, 400_000, Delay) }.unwrap();
    assert_eq!(bus.run(&mut [Operation::Write(&[])]), Ok(()));
    assert_eq!(unsafe { (*regs.get())[0x10 / 4] }, 0);
}

#[test]
fn read_commands_wait_for_room_in_the_transmit_fifo() {
    struct FifoDelay {
        regs: &'static UnsafeCell<[u32; 64]>,
        waits: usize,
    }
    impl DelayNs for FifoDelay {
        fn delay_ns(&mut self, _: u32) {
            self.waits += 1;
            // SAFETY: this test exclusively owns the fake register block.
            unsafe {
                match self.waits {
                    1 => {
                        assert_eq!((*self.regs.get())[0x10 / 4], 0);
                        (*self.regs.get())[0x70 / 4] |= 1 << 1;
                    }
                    2 => (*self.regs.get())[0x70 / 4] &= !(1 << 3),
                    _ => panic!("unexpected FIFO wait"),
                }
            }
        }
    }
    let regs = registers();
    let delay = FifoDelay { regs, waits: 0 };
    // SAFETY: aligned, complete fake register block, exclusively owned.
    let mut bus = unsafe { DesignWare::attach(regs.get() as usize, 256, 400_000, delay) }.unwrap();
    unsafe {
        (*regs.get())[0x70 / 4] = (1 << 2) | (1 << 3); // TX empty, RX ready, TX full
        (*regs.get())[0x34 / 4] = 1 << 9; // STOP_DET
    }
    let mut byte = [0];
    assert_eq!(bus.run(&mut [Operation::Read(&mut byte)]), Ok(()));
    assert_eq!(bus.delay.waits, 2);
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

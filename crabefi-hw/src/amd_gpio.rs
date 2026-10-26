// SPDX-License-Identifier: MIT OR Apache-2.0
//! AMD FCH GPIO pin level and latched interrupt status (ACPI `AMD0030`).
//! Pad configuration stays with the firmware that owns the pin mux.

use core::convert::Infallible;
use embedded_hal::digital::{ErrorType, InputPin};
use tock_registers::{
    interfaces::{Readable, Writeable},
    register_bitfields,
    registers::ReadWrite,
};

register_bitfields![u32, Control [
    PIN OFFSET(16) NUMBITS(1) [],
    INTERRUPT_STATUS OFFSET(28) NUMBITS(1) [],
    WAKE_STATUS OFFSET(29) NUMBITS(1) []
]];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidRegion,
    PinOutOfRange,
}

/// One pin of an AMD GPIO bank, with one 32-bit control register per pin.
pub struct GpioPin {
    control: &'static ReadWrite<u32, Control::Register>,
}

impl GpioPin {
    /// # Safety
    /// `base`/`size` describe the GPIO bank's decoded, UC-mapped MMIO.
    /// Reading a pin's control register has no side effects; only
    /// [`Self::take_interrupt_status`] writes it.
    pub unsafe fn new(base: usize, size: usize, pin: u16) -> Result<Self, Error> {
        if base == 0 || base & 3 != 0 || base.checked_add(size).is_none() {
            return Err(Error::InvalidRegion);
        }
        let offset = usize::from(pin) * 4;
        if offset + 4 > size {
            return Err(Error::PinOutOfRange);
        }
        // SAFETY: an aligned register inside the caller's validated bank.
        let control = unsafe { &*((base + offset) as *const ReadWrite<u32, Control::Register>) };
        Ok(Self { control })
    }

    /// Whether the pad latched an interrupt, clearing the latch. The pad
    /// must be configured to set its interrupt status.
    pub fn take_interrupt_status(&mut self) -> bool {
        let control = self.control.extract();
        if !control.is_set(Control::INTERRUPT_STATUS) {
            return false;
        }
        // Status bits are write-1-to-clear; keep a pending wake status.
        self.control
            .set(control.get() & !Control::WAKE_STATUS::SET.value);
        true
    }
}

impl ErrorType for GpioPin {
    type Error = Infallible;
}

impl InputPin for GpioPin {
    fn is_high(&mut self) -> Result<bool, Infallible> {
        Ok(self.control.is_set(Control::PIN))
    }

    fn is_low(&mut self) -> Result<bool, Infallible> {
        self.is_high().map(|high| !high)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;

    #[test]
    fn reads_the_pin_level_and_rejects_pins_outside_the_bank() {
        let bank = Box::leak(Box::new([0u32; 16]));
        bank[9] = 1 << 16;
        let base = bank.as_ptr() as usize;
        // SAFETY: RAM-backed fake bank.
        let mut pin = unsafe { GpioPin::new(base, 64, 9) }.unwrap();
        assert_eq!(pin.is_high(), Ok(true));
        let mut pin = unsafe { GpioPin::new(base, 64, 8) }.unwrap();
        assert_eq!(pin.is_low(), Ok(true));
        assert_eq!(
            unsafe { GpioPin::new(base, 64, 16) }.err(),
            Some(Error::PinOutOfRange)
        );
    }

    #[test]
    fn interrupt_status_is_taken_once_without_clearing_wake_status() {
        let bank = Box::leak(Box::new([0u32; 4]));
        let base = bank.as_ptr() as usize;
        // SAFETY: RAM-backed fake bank.
        let mut pin = unsafe { GpioPin::new(base, 16, 3) }.unwrap();
        assert!(!pin.take_interrupt_status());
        bank[3] = (1 << 28) | (1 << 29) | 0x1000;
        assert!(pin.take_interrupt_status());
        // The write sets the interrupt status bit (to clear it) and leaves
        // wake status and configuration alone.
        assert_eq!(bank[3], (1 << 28) | 0x1000);
    }
}

//! Bind ACPI-described native ELAN devices to the shared polled transports.
//! No board addresses, pin mux programming or guessed bus clocks belong here.
use alloc::boxed::Box;
use crabefi::{
    PointerInput,
    drivers::{elan::ElanTouchpad, mmio::MmioRegion},
};
use crabefi_i2c::designware::DesignWare;
use embedded_hal::delay::DelayNs;
use tock_registers::{LocalRegisterCopy, register_bitfields};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Touchpad {
    pub i2c_base: u64,
    pub i2c_size: u64,
    pub address: u8,
    pub speed_hz: u32,
    pub gpio_base: u64,
    pub gpio_size: u64,
    pub pin: u16,
    pub active_low: bool,
}
struct Delay;
impl DelayNs for Delay {
    fn delay_ns(&mut self, ns: u32) {
        crabefi::time::delay_us(u64::from(ns).div_ceil(1000));
    }
}
register_bitfields![u32, Pin [INPUT OFFSET(16) NUMBITS(1) []]];

/// # Safety
/// Called only for present, enabled ACPI devices of the recognized controller
/// types. The supplied MMIO is identity/UC mapped and firmware has initialized
/// power, clocks and pads. No other CrabEFI driver owns these resources.
pub(crate) unsafe fn bind(device: Touchpad) -> Option<Box<dyn PointerInput>> {
    let bus_base = usize::try_from(device.i2c_base).ok()?;
    let bus_size = usize::try_from(device.i2c_size).ok()?;
    let gpio_size = usize::try_from(device.gpio_size).ok()?;
    if device.gpio_base & 3 != 0 {
        return None;
    }
    // Validate both spans and narrow GPIO access to exactly the declared pin
    // before any controller register is accessed.
    let gpio = unsafe { MmioRegion::try_new(device.gpio_base, gpio_size) }.ok()?;
    let pin = gpio.try_subregion(u64::from(device.pin) * 4, 4).ok()?;
    // SAFETY: validated ACPI controller resource, with exclusive ownership.
    let bus = match unsafe { DesignWare::attach(bus_base, bus_size, device.speed_hz, Delay) } {
        Ok(bus) => bus,
        Err(error) => {
            log::warn!("ACPI touchpad controller unavailable: {:?}", error);
            return None;
        }
    };
    let ready = move || {
        let high = LocalRegisterCopy::<u32, Pin::Register>::new(pin.read32(0)).is_set(Pin::INPUT);
        high != device.active_low
    };
    match ElanTouchpad::new(bus, Delay, ready, device.address) {
        Ok(input) => {
            log::info!(
                "ACPI ELAN touchpad: I2C {:#x} address {:#x}, GPIO {:#x} pin {}",
                device.i2c_base,
                device.address,
                device.gpio_base,
                device.pin
            );
            Some(Box::new(input))
        }
        Err(error) => {
            log::warn!("ACPI ELAN touchpad initialization failed: {:?}", error);
            None
        }
    }
}

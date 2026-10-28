//! Platform-described peripherals
//!
//! The platform owns the hardware it initializes: bus controllers, clocks,
//! pads and power. It describes each device on those buses, and each
//! memory-mapped SoC device, as a [`Peripheral`], handing over working
//! embedded-hal handles. CrabEFI owns the device drivers and picks one by the
//! device's identifiers.

use alloc::{boxed::Box, string::String, vec::Vec};
use embedded_hal::{
    digital::{self, InputPin},
    i2c::{self, I2c, Operation},
};

/// An I2C bus whose errors are reduced to embedded-hal's error kinds.
pub struct I2cBus(Box<dyn I2c<Error = i2c::ErrorKind>>);

struct ErasedI2c<B>(B);

impl<B: I2c> i2c::ErrorType for ErasedI2c<B> {
    type Error = i2c::ErrorKind;
}

impl<B: I2c> I2c for ErasedI2c<B> {
    fn transaction(
        &mut self,
        address: u8,
        operations: &mut [Operation<'_>],
    ) -> Result<(), i2c::ErrorKind> {
        self.0
            .transaction(address, operations)
            .map_err(|error| i2c::Error::kind(&error))
    }
}

impl I2cBus {
    pub fn new<B: I2c + 'static>(bus: B) -> Self {
        Self(Box::new(ErasedI2c(bus)))
    }
}

impl i2c::ErrorType for I2cBus {
    type Error = i2c::ErrorKind;
}

impl I2c for I2cBus {
    fn transaction(
        &mut self,
        address: u8,
        operations: &mut [Operation<'_>],
    ) -> Result<(), i2c::ErrorKind> {
        self.0.transaction(address, operations)
    }
}

/// A GPIO input whose errors are reduced to embedded-hal's error kinds.
pub struct InputLine(Box<dyn InputPin<Error = digital::ErrorKind>>);

struct ErasedPin<P>(P);

impl<P: InputPin> digital::ErrorType for ErasedPin<P> {
    type Error = digital::ErrorKind;
}

impl<P: InputPin> InputPin for ErasedPin<P> {
    fn is_high(&mut self) -> Result<bool, digital::ErrorKind> {
        self.0
            .is_high()
            .map_err(|error| digital::Error::kind(&error))
    }

    fn is_low(&mut self) -> Result<bool, digital::ErrorKind> {
        self.0
            .is_low()
            .map_err(|error| digital::Error::kind(&error))
    }
}

impl InputLine {
    pub fn new<P: InputPin + 'static>(pin: P) -> Self {
        Self(Box::new(ErasedPin(pin)))
    }
}

/// An edge that the GPIO controller latched.
pub trait InterruptLatch {
    /// Whether an edge was latched since the previous call. Clears the latch.
    fn take(&mut self) -> bool;
}

/// How a device signals data or a finished transaction, polled.
pub enum Interrupt {
    /// A level-triggered line read through a GPIO input.
    Level { line: InputLine, active_low: bool },
    /// An edge-triggered line whose GPIO controller latches the edge.
    Latched(Box<dyn InterruptLatch>),
}

impl Interrupt {
    /// Whether the device signals now. A latched edge is consumed; an
    /// unreadable line reads as idle.
    pub fn is_pending(&mut self) -> bool {
        match self {
            Self::Level { line, active_low } => {
                line.0.is_high().is_ok_and(|high| high != *active_low)
            }
            Self::Latched(latch) => latch.take(),
        }
    }
}

/// A device on a platform-owned I2C bus.
pub struct I2cPeripheral {
    /// Identifiers in order of preference, such as an ACPI `_HID` followed by
    /// its `_CID`s.
    pub ids: Vec<String>,
    pub bus: I2cBus,
    /// Seven-bit target address.
    pub address: u8,
    /// Data-ready interrupt, if wired.
    pub interrupt: Option<Interrupt>,
    /// HID descriptor register of a HID-over-I2C device, from ACPI `_DSM`
    /// or board data.
    pub hid_descriptor_register: Option<u16>,
}

/// A memory-mapped device, such as an ACPI-enumerated SoC controller.
pub struct MmioPeripheral {
    /// Identifiers in order of preference, such as an ACPI `_HID` followed by
    /// its `_CID`s.
    pub ids: Vec<String>,
    /// Register window, identity mapped and owned by no other driver.
    pub base: u64,
    pub size: u64,
}

/// A platform-described device that CrabEFI drives.
pub enum Peripheral {
    I2c(I2cPeripheral),
    Mmio(MmioPeripheral),
}

struct I2cDriver {
    ids: &'static [&'static str],
    /// Takes ownership of the device; logs its own failures.
    bind: fn(I2cPeripheral),
}

const I2C_DRIVERS: &[I2cDriver] = &[
    #[cfg(feature = "elan-i2c")]
    I2cDriver {
        ids: crate::drivers::elan::IDS,
        bind: crate::drivers::elan::bind,
    },
    #[cfg(feature = "hid-i2c")]
    I2cDriver {
        ids: crate::drivers::hid_i2c::IDS,
        bind: crate::drivers::hid_i2c::bind,
    },
    #[cfg(feature = "tpm")]
    I2cDriver {
        ids: crate::efi::tcg::gsc_i2c::IDS,
        bind: crate::efi::tcg::gsc_i2c::bind,
    },
];

struct MmioDriver {
    ids: &'static [&'static str],
    /// Takes ownership of the device; logs its own failures.
    bind: fn(MmioPeripheral),
}

const MMIO_DRIVERS: &[MmioDriver] = &[MmioDriver {
    ids: crate::drivers::sdhci::EMMC_IDS,
    bind: crate::drivers::sdhci::bind_emmc,
}];

/// A driver table entry, by the identifiers it handles.
trait Driver {
    fn ids(&self) -> &'static [&'static str];
}

impl Driver for I2cDriver {
    fn ids(&self) -> &'static [&'static str] {
        self.ids
    }
}

impl Driver for MmioDriver {
    fn ids(&self) -> &'static [&'static str] {
        self.ids
    }
}

/// The first driver handling one of `ids`, in the order of `ids`.
fn find<'a, D: Driver>(
    drivers: &'static [D],
    ids: impl IntoIterator<Item = &'a str>,
) -> Option<&'static D> {
    ids.into_iter()
        .find_map(|id| drivers.iter().find(|driver| driver.ids().contains(&id)))
}

fn i2c_driver<'a>(ids: impl IntoIterator<Item = &'a str>) -> Option<&'static I2cDriver> {
    find(I2C_DRIVERS, ids)
}

/// Whether this build has a driver for an I2C device with these identifiers.
///
/// Lets a platform skip taking over a bus controller nothing will use.
pub fn i2c_supported<'a>(ids: impl IntoIterator<Item = &'a str>) -> bool {
    i2c_driver(ids).is_some()
}

#[cfg(feature = "tpm")]
static TPM: crate::cell::Local<Option<Box<dyn crate::platform::Tpm2Device>>> =
    crate::cell::Local::new(None);

/// Offer a bound TPM for measured boot. The first one wins.
#[cfg(feature = "tpm")]
pub(crate) fn provide_tpm(tpm: Box<dyn crate::platform::Tpm2Device>) {
    let mut slot = TPM.borrow_mut();
    if slot.is_some() {
        log::warn!("Ignoring a second TPM peripheral");
        return;
    }
    *slot = Some(tpm);
}

/// The TPM a peripheral driver bound, for the rest of boot services.
#[cfg(feature = "tpm")]
pub(crate) fn take_tpm() -> Option<&'static mut dyn crate::platform::Tpm2Device> {
    TPM.borrow_mut().take().map(Box::leak)
}

/// Whether this build has a driver for an MMIO device with these identifiers.
pub fn mmio_supported<'a>(ids: impl IntoIterator<Item = &'a str>) -> bool {
    find(MMIO_DRIVERS, ids).is_some()
}

/// Hand every peripheral to the first driver that matches its identifiers.
pub(crate) fn bind(peripherals: Vec<Peripheral>) {
    for peripheral in peripherals {
        match peripheral {
            Peripheral::I2c(device) => match i2c_driver(device.ids.iter().map(String::as_str)) {
                Some(driver) => (driver.bind)(device),
                None => log::info!(
                    "No driver for I2C device {:?} at {:#x}",
                    device.ids,
                    device.address
                ),
            },
            Peripheral::Mmio(device) => {
                match find(MMIO_DRIVERS, device.ids.iter().map(String::as_str)) {
                    Some(driver) => (driver.bind)(device),
                    None => log::info!(
                        "No driver for MMIO device {:?} at {:#x}",
                        device.ids,
                        device.base
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "elan-i2c")]
    #[test]
    fn any_identifier_selects_a_driver() {
        assert!(super::i2c_supported(["VEND0001", "ELAN0000"]));
        assert!(!super::i2c_supported(["VEND9999"]));
    }

    #[test]
    fn mmio_and_i2c_drivers_are_matched_separately() {
        assert!(super::mmio_supported(["AMDI0041"]));
        assert!(!super::i2c_supported(["AMDI0041"]));
    }
}

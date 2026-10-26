//! Native ELAN I2C touchpads (34-byte and high-precision 39-byte reports).
//!
//! The platform supplies an exclusive embedded-hal I2C bus, a reset delay,
//! the seven-bit address and a data-ready callback (normally active-low GPIO).
//! No controller addresses, GPIO numbers or ACPI discovery belong here.
//! Only relative motion and physical buttons are supported, not gestures.
use crate::platform::{PointerInput, PointerState};
use embedded_hal::{delay::DelayNs, i2c::I2c};
use tock_registers::register_bitfields;
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    byteorder::{BigEndian, LittleEndian, U16},
};

type Le16 = U16<LittleEndian>;
type Be16 = U16<BigEndian>;
const DESCRIPTOR: u16 = 0x0001;
const COMMAND: u16 = 0x0005;
const RESET: u16 = 0x0100;
const WAKE: u16 = 0x0800;
const SLEEP: u16 = 0x0801;
const PATTERN: u16 = 0x0100;
const MAX_X: u16 = 0x0106;
const MAX_Y: u16 = 0x0107;
const SET_MODE: u16 = 0x0300;
const MAX_REPORT: usize = 39;
register_bitfields![u16, Mode [ABSOLUTE OFFSET(0) NUMBITS(1) []]];

#[derive(Debug)]
pub enum Error<E> {
    Bus(E),
    InvalidAddress,
    ResetAcknowledgement,
    UnsupportedDescriptor,
    InvalidGeometry,
    InvalidReport,
}

#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
struct Command {
    register: Le16,
    value: Le16,
}
#[repr(C)]
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
struct Descriptor {
    length: Le16,
    version: Le16,
    report_length: Le16,
    report_register: Le16,
    input_register: Le16,
    max_input_length: Le16,
    output_register: Le16,
    max_output_length: Le16,
    command_register: Le16,
    data_register: Le16,
    vendor: Le16,
    product: Le16,
    firmware: Le16,
    reserved: [u8; 4],
}
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable)]
struct Header {
    length: Le16,
    id: u8,
    touch: u8,
}
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable)]
struct StandardContact {
    high: u8,
    x: u8,
    y: u8,
    area: u8,
    pressure: u8,
}
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable)]
struct PreciseContact {
    x: Be16,
    y: Be16,
    pressure: u8,
}

fn write<I: I2c>(
    bus: &mut I,
    address: u8,
    register: u16,
    value: u16,
) -> Result<(), Error<I::Error>> {
    bus.write(
        address,
        Command {
            register: register.into(),
            value: value.into(),
        }
        .as_bytes(),
    )
    .map_err(Error::Bus)
}
fn word<I: I2c>(bus: &mut I, address: u8, register: u16) -> Result<u16, Error<I::Error>> {
    let mut value = [0; 2];
    bus.write_read(address, Le16::new(register).as_bytes(), &mut value)
        .map_err(Error::Bus)?;
    Ok(Le16::read_from_bytes(&value)
        .expect("two-byte ELAN word")
        .get())
}

#[derive(Debug, Clone, Copy)]
struct Contact {
    slot: u8,
    x: u16,
    y: u16,
}
#[derive(Default)]
struct Tracking {
    previous: Option<Contact>,
}
impl Tracking {
    fn sample(&mut self, contact: Option<Contact>, buttons: u8) -> PointerState {
        let (dx, dy) = self
            .previous
            .zip(contact)
            .filter(|(old, new)| old.slot == new.slot)
            .map_or((0, 0), |(old, new)| {
                (
                    i32::from(new.x) - i32::from(old.x),
                    i32::from(old.y) - i32::from(new.y),
                )
            });
        self.previous = contact;
        PointerState {
            dx,
            dy,
            dz: 0,
            buttons: u32::from(buttons & 7),
        }
    }
}

fn report(bytes: &[u8], maximum: (u16, u16)) -> Result<Option<(Option<Contact>, u8)>, ()> {
    let (header, data) = Header::ref_from_prefix(bytes).map_err(|_| ())?;
    // A device reset notification has no contact state.
    if header.length.get() == 0 {
        return Ok(Some((None, 0)));
    }
    if usize::from(header.length.get()) != bytes.len() {
        return Err(());
    }
    if header.id == 0x5e {
        return Ok(None);
    } // separate TrackPoint reports
    let expected = match header.id {
        0x5d => 34,
        0x60 => 39,
        _ => return Err(()),
    };
    if bytes.len() != expected {
        return Err(());
    }
    let fingers = header.touch >> 3;
    let buttons = header.touch & 7;
    if fingers == 0 || bytes[30] & (1 << 6) != 0 {
        return Ok(Some((None, buttons)));
    }
    let (x, y) = if header.id == 0x60 {
        let (contact, _) = PreciseContact::ref_from_prefix(data).map_err(|_| ())?;
        (contact.x.get(), contact.y.get())
    } else {
        let (contact, _) = StandardContact::ref_from_prefix(data).map_err(|_| ())?;
        (
            (u16::from(contact.high & 0xf0) << 4) | u16::from(contact.x),
            (u16::from(contact.high & 0x0f) << 8) | u16::from(contact.y),
        )
    };
    if x > maximum.0 || y > maximum.1 {
        return Err(());
    }
    // Contacts are packed in active-slot order. Follow the first active slot;
    // a slot change or finger lift resets the relative-motion origin.
    Ok(Some((
        Some(Contact {
            slot: fingers.trailing_zeros() as u8,
            x,
            y,
        }),
        buttons,
    )))
}

pub struct ElanTouchpad<I, R> {
    bus: I,
    ready: R,
    address: u8,
    length: usize,
    maximum: (u16, u16),
    tracking: Tracking,
    enabled: bool,
}
impl<I: I2c, R: FnMut() -> bool> ElanTouchpad<I, R> {
    /// Initialize a platform-identified native ELAN touchpad. `ready` must
    /// return true only when an input report can be read without waiting.
    pub fn new(
        mut bus: I,
        mut delay: impl DelayNs,
        ready: R,
        address: u8,
    ) -> Result<Self, Error<I::Error>> {
        if !(0x08..0x78).contains(&address) {
            return Err(Error::InvalidAddress);
        }
        write(&mut bus, address, COMMAND, RESET)?;
        delay.delay_ms(100);
        let mut acknowledgement = [0; 2];
        bus.read(address, &mut acknowledgement)
            .map_err(Error::Bus)?;
        if acknowledgement != [0; 2] {
            return Err(Error::ResetAcknowledgement);
        }
        let mut raw = [0; size_of::<Descriptor>()];
        bus.write_read(address, Le16::new(DESCRIPTOR).as_bytes(), &mut raw)
            .map_err(Error::Bus)?;
        let descriptor =
            Descriptor::read_from_bytes(&raw).map_err(|_| Error::UnsupportedDescriptor)?;
        let descriptor_length = usize::from(descriptor.report_length.get());
        if descriptor.length.get() != 30
            || descriptor.vendor.get() != 0x04f3
            || descriptor.version.get() != 0x0100
            || descriptor_length == 0
            || descriptor_length > 512
        {
            return Err(Error::UnsupportedDescriptor);
        }
        // Fetch the descriptor as required by the device's initialization
        // handshake; native reports below have fixed, bounded formats.
        let mut report_descriptor = [0; 512];
        bus.write_read(
            address,
            descriptor.report_register.as_bytes(),
            &mut report_descriptor[..descriptor_length],
        )
        .map_err(Error::Bus)?;
        let pattern = word(&mut bus, address, PATTERN)?;
        let pattern = if pattern == 0xffff { 0 } else { pattern >> 8 };
        let length = if pattern <= 1 { 34 } else { 39 };
        let maximum = (
            word(&mut bus, address, MAX_X)?,
            word(&mut bus, address, MAX_Y)?,
        );
        if maximum.0 == 0 || maximum.1 == 0 {
            return Err(Error::InvalidGeometry);
        }
        write(&mut bus, address, SET_MODE, Mode::ABSOLUTE::SET.value)?;
        write(&mut bus, address, COMMAND, WAKE)?;
        log::info!(
            "ELAN I2C touchpad: product {:#06x}, {}x{}, {}-byte reports",
            descriptor.product.get(),
            maximum.0,
            maximum.1,
            length
        );
        Ok(Self {
            bus,
            ready,
            address,
            length,
            maximum,
            tracking: Tracking::default(),
            enabled: true,
        })
    }
    /// Maximum sensor coordinates, independent of screen resolution.
    pub fn geometry(&self) -> (u16, u16) {
        self.maximum
    }
    /// Read at most one report. Malformed data or transfer errors disable the source so
    /// an absent/broken device cannot stall every UI or EFI input poll.
    pub fn poll(&mut self) -> Result<Option<PointerState>, Error<I::Error>> {
        if !self.enabled || !(self.ready)() {
            return Ok(None);
        }
        let mut bytes = [0; MAX_REPORT];
        if let Err(error) = self.bus.read(self.address, &mut bytes[..self.length]) {
            self.enabled = false;
            self.tracking.previous = None;
            return Err(Error::Bus(error));
        }
        let sample = report(&bytes[..self.length], self.maximum).map_err(|_| {
            self.enabled = false;
            self.tracking.previous = None;
            Error::InvalidReport
        })?;
        Ok(sample.map(|(contact, buttons)| self.tracking.sample(contact, buttons)))
    }
}
impl<I: I2c, R: FnMut() -> bool> PointerInput for ElanTouchpad<I, R> {
    fn read_state(&mut self) -> Option<PointerState> {
        match self.poll() {
            Ok(state) => state,
            Err(error) => {
                self.tracking.previous = None;
                log::warn!("ELAN I2C touchpad input error: {:?}", error);
                Some(PointerState::default()) // release any previously held buttons
            }
        }
    }
    fn stop(&mut self) {
        self.enabled = false;
        self.tracking.previous = None;
        if let Err(error) = write(&mut self.bus, self.address, COMMAND, SLEEP) {
            log::warn!("ELAN I2C touchpad sleep failed: {:?}", error);
        }
    }
}

#[cfg(test)]
#[path = "elan_tests.rs"]
mod tests;

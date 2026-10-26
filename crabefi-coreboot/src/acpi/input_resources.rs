//! Decode only the connection descriptors not yet exposed by the AML crate.
//! AML evaluation, namespace lookup and ordinary MMIO resources still use acpi.
use zerocopy::{
    FromBytes, Immutable, KnownLayout,
    little_endian::{U16, U32},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct I2c<'a> {
    pub source: &'a str,
    pub address: u8,
    pub speed_hz: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Interrupt<'a> {
    pub source: &'a str,
    pub pin: u16,
    pub active_low: bool,
}
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Connections<'a> {
    pub i2c: Option<I2c<'a>>,
    pub interrupt: Option<Interrupt<'a>>,
}
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable)]
struct Large {
    tag: u8,
    length: U16,
}
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable)]
struct Serial {
    header: Large,
    revision: u8,
    source_index: u8,
    kind: u8,
    flags: u8,
    type_flags: U16,
    type_revision: u8,
    data_length: U16,
    speed: U32,
    address: U16,
}
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable)]
struct Gpio {
    header: Large,
    revision: u8,
    kind: u8,
    flags: U16,
    interrupt_flags: U16,
    pin_config: u8,
    drive: U16,
    debounce: U16,
    pins_offset: U16,
    source_index: u8,
    source_offset: U16,
    vendor_offset: U16,
    vendor_length: U16,
}
fn name(bytes: &[u8]) -> Result<&str, &'static str> {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .ok_or("unterminated resource source")?;
    if end == 0 || end > 255 || bytes[end..].iter().any(|&byte| byte != 0) {
        return Err("invalid resource source");
    }
    core::str::from_utf8(&bytes[..end]).map_err(|_| "resource source is not UTF-8")
}

/// Validate the framing before handing a resource template to the AML crate,
/// whose descriptor parser currently assumes complete descriptor headers.
pub(super) fn records(mut bytes: &[u8]) -> Result<alloc::vec::Vec<&[u8]>, &'static str> {
    if bytes.len() > 4096 {
        return Err("resource template exceeds input discovery limit");
    }
    let mut records = alloc::vec::Vec::new();
    while let Some(&tag) = bytes.first() {
        let length = if tag & 0x80 != 0 {
            let (header, _) =
                Large::ref_from_prefix(bytes).map_err(|_| "short large resource header")?;
            3 + usize::from(header.length.get())
        } else {
            1 + usize::from(tag & 7)
        };
        let record = bytes.get(..length).ok_or("truncated ACPI resource")?;
        bytes = &bytes[length..];
        if tag >> 3 == 0x0f {
            if tag != 0x79 || !bytes.is_empty() {
                return Err("invalid resource end tag");
            }
            return Ok(records);
        }
        records.push(record);
    }
    Err("missing resource end tag")
}

pub(super) fn parse(bytes: &[u8]) -> Result<Connections<'_>, &'static str> {
    let mut result = Connections::default();
    for record in records(bytes)? {
        match record[0] {
            0x8e => {
                // Other serial bus types are not touchpad I2C connections.
                if record.get(5).copied() != Some(1) {
                    continue;
                }
                let (serial, _) =
                    Serial::ref_from_prefix(record).map_err(|_| "short I2C connection")?;
                if !matches!(serial.revision, 1 | 2)
                    || serial.type_revision != 1
                    || serial.source_index != 0
                    || serial.flags & 3 != 2
                    || serial.type_flags.get() != 0
                    || serial.data_length.get() < 6
                {
                    return Err("unsupported I2C connection mode");
                }
                let address = serial.address.get();
                if !(0x08..0x78).contains(&address) {
                    return Err("reserved I2C address");
                }
                let source_offset = 12 + usize::from(serial.data_length.get());
                let source = name(record.get(source_offset..).ok_or("I2C type data bounds")?)?;
                let connection = I2c {
                    source,
                    address: address as u8,
                    speed_hz: serial.speed.get(),
                };
                if result.i2c.replace(connection).is_some() {
                    return Err("multiple I2C connections");
                }
            }
            0x8c => {
                let (gpio, _) =
                    Gpio::ref_from_prefix(record).map_err(|_| "short GPIO connection")?;
                if gpio.kind != 0 {
                    continue;
                } // GPIO I/O is not a report-ready interrupt.
                let flags = gpio.interrupt_flags.get();
                let polarity = (flags >> 1) & 3;
                if gpio.revision != 1
                    || gpio.flags.get() & 1 == 0
                    || gpio.source_index != 0
                    || flags & 1 != 0
                    || polarity > 1
                {
                    return Err("report-ready GPIO must be a level interrupt");
                }
                let pins = usize::from(gpio.pins_offset.get());
                let source = usize::from(gpio.source_offset.get());
                let vendor = if gpio.vendor_length.get() == 0 && gpio.vendor_offset.get() == 0 {
                    record.len()
                } else {
                    usize::from(gpio.vendor_offset.get())
                };
                if pins < size_of::<Gpio>()
                    || source != pins + 2
                    || vendor < source
                    || vendor.checked_add(usize::from(gpio.vendor_length.get()))
                        != Some(record.len())
                {
                    return Err("invalid GPIO pin/source/vendor spans");
                }
                let pin = U16::read_from_bytes(record.get(pins..source).ok_or("GPIO pin bounds")?)
                    .map_err(|_| "GPIO requires exactly one pin")?
                    .get();
                let source = name(record.get(source..vendor).ok_or("GPIO source bounds")?)?;
                let interrupt = Interrupt {
                    source,
                    pin,
                    active_low: polarity == 1,
                };
                if result.interrupt.replace(interrupt).is_some() {
                    return Err("multiple GPIO interrupts");
                }
            }
            _ => {}
        }
    }
    Ok(result)
}

//! HID over I2C (ACPI `PNP0C50`): touchpads, mice and keyboards.
//!
//! The device's report descriptor decides what it is. Mouse collections
//! drive the pointer, which also covers precision touchpads in their power-on
//! mouse mode, and keyboard collections drive the keyboard through the same
//! key handling as USB boot keyboards. Touchscreens and multi-touch
//! digitizer reports are not interpreted.

use super::keyboard_common::KeyboardDevice;
use super::pointer::{PointerDevice, PointerReport};
use super::usb::hid_keyboard::{BootKeys, KeyboardReport};
use crate::peripheral::{I2cBus, I2cPeripheral, Interrupt};
use crate::platform::{Key, KeyState};
use crate::time::{Timeout, delay_ms};
use alloc::{boxed::Box, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;
use embedded_hal::i2c::I2c;
use hidreport::{Field, FieldAttributes, Report, ReportDescriptor, Usage, VariableField};
use zerocopy::{FromBytes, Immutable, KnownLayout, little_endian::U16};

/// ACPI identifiers of HID-over-I2C devices.
pub(crate) const IDS: &[&str] = &["PNP0C50", "ACPI0C50"];

const OPCODE_RESET: u8 = 0x01;
const OPCODE_SET_POWER: u8 = 0x08;
const POWER_ON: u8 = 0x00;
const POWER_SLEEP: u8 = 0x01;
/// Bound the work of one poll.
const REPORTS_PER_POLL: usize = 8;
const MAX_REPORT_DESCRIPTOR: usize = 4096;
const MAX_INPUT: usize = 512;

const GENERIC_DESKTOP: u16 = 0x01;
const MOUSE: u16 = 0x02;
const KEYBOARD: u16 = 0x06;
const X: u16 = 0x30;
const Y: u16 = 0x31;
const WHEEL: u16 = 0x38;
const KEY_CODES: u16 = 0x07;
const BUTTONS: u16 = 0x09;

/// HID descriptor, HID over I2C specification section 5.1.
#[repr(C)]
#[derive(FromBytes, KnownLayout, Immutable)]
struct Descriptor {
    length: U16,
    version: U16,
    report_descriptor_length: U16,
    report_descriptor_register: U16,
    input_register: U16,
    max_input_length: U16,
    output_register: U16,
    max_output_length: U16,
    command_register: U16,
    data_register: U16,
    vendor: U16,
    product: U16,
    firmware: U16,
    reserved: [u8; 4],
}

#[derive(Debug)]
pub enum Error<E> {
    Bus(E),
    NoInterrupt,
    NoDescriptorRegister,
    UnsupportedDescriptor,
    ResetAcknowledgement,
    ReportDescriptor,
    NoUsableCollection,
    InvalidReport,
}

fn usage(page: u16, id: u16) -> u32 {
    (u32::from(page) << 16) | u32::from(id)
}

fn in_collection(field: &VariableField, collection: u32) -> bool {
    field
        .collections
        .iter()
        .any(|c| c.usages().iter().any(|u| u32::from(u) == collection))
}

fn variables(report: &impl Report, collection: u32) -> impl Iterator<Item = &VariableField> + '_ {
    report.fields().iter().filter_map(move |field| match field {
        Field::Variable(field) if in_collection(field, collection) => Some(field),
        _ => None,
    })
}

fn variable(report: &impl Report, collection: u32, usage: u32) -> Option<VariableField> {
    variables(report, collection)
        .find(|field| u32::from(&field.usage) == usage)
        .cloned()
}

/// Relative mouse fields of one input report.
struct Mouse {
    report_id: Option<u8>,
    size: usize,
    x: VariableField,
    y: VariableField,
    wheel: Option<VariableField>,
    buttons: Vec<(u32, VariableField)>,
}

impl Mouse {
    fn find(descriptor: &ReportDescriptor) -> Option<Self> {
        let collection = usage(GENERIC_DESKTOP, MOUSE);
        descriptor.input_reports().iter().find_map(|report| {
            let x = variable(report, collection, usage(GENERIC_DESKTOP, X))?;
            let y = variable(report, collection, usage(GENERIC_DESKTOP, Y))?;
            if !x.is_relative() || !y.is_relative() {
                return None;
            }
            let buttons = variables(report, collection)
                .filter_map(|field| {
                    let Usage {
                        usage_page,
                        usage_id,
                    } = field.usage;
                    let index = u16::from(usage_id);
                    (u16::from(usage_page) == BUTTONS && (1..=3).contains(&index))
                        .then(|| (1 << (index - 1), field.clone()))
                })
                .collect();
            Some(Self {
                report_id: (*report.report_id()).map(u8::from),
                size: report.size_in_bytes(),
                x,
                y,
                wheel: variable(report, collection, usage(GENERIC_DESKTOP, WHEEL)),
                buttons,
            })
        })
    }

    fn read(&self, report: &[u8]) -> Option<PointerReport> {
        let value = |field: &VariableField| field.extract(report).ok().map(i32::from);
        Some(PointerReport {
            dx: value(&self.x)?,
            dy: value(&self.y)?,
            // HID wheel up is positive; EFI and the UI scroll down positive.
            dz: self.wheel.as_ref().and_then(value).map_or(0, |dz| -dz),
            buttons: self
                .buttons
                .iter()
                .filter(|(_, field)| value(field).is_some_and(|pressed| pressed != 0))
                .fold(0, |buttons, (bit, _)| buttons | bit),
        })
    }
}

/// Boot-keyboard-like fields of one input report.
struct Keyboard {
    report_id: Option<u8>,
    size: usize,
    modifiers: Vec<(u8, VariableField)>,
    keys: hidreport::ArrayField,
}

impl Keyboard {
    fn find(descriptor: &ReportDescriptor) -> Option<Self> {
        let collection = usage(GENERIC_DESKTOP, KEYBOARD);
        descriptor.input_reports().iter().find_map(|report| {
            let keys = report.fields().iter().find_map(|field| match field {
                Field::Array(field)
                    if field
                        .collections
                        .iter()
                        .any(|c| c.usages().iter().any(|u| u32::from(u) == collection))
                        && field
                            .usages()
                            .first()
                            .is_some_and(|u| u16::from(u.usage_page) == KEY_CODES) =>
                {
                    Some(field.clone())
                }
                _ => None,
            })?;
            let modifiers = variables(report, collection)
                .filter_map(|field| {
                    let id = u16::from(field.usage.usage_id);
                    (u16::from(field.usage.usage_page) == KEY_CODES && (0xe0..=0xe7).contains(&id))
                        .then(|| (1 << (id - 0xe0), field.clone()))
                })
                .collect();
            Some(Self {
                report_id: (*report.report_id()).map(u8::from),
                size: report.size_in_bytes(),
                modifiers,
                keys,
            })
        })
    }

    fn read(&self, report: &[u8]) -> Option<KeyboardReport> {
        let modifiers = self
            .modifiers
            .iter()
            .filter(|(_, field)| field.extract(report).is_ok_and(|v| u32::from(v) != 0))
            .fold(0, |modifiers, (bit, _)| modifiers | bit);
        let mut keys = [0; 6];
        self.keys
            .extract(report)
            .ok()?
            .iter()
            .map(|key| u8::try_from(u32::from(key)).unwrap_or(0))
            .filter(|&key| key > 3)
            .take(keys.len())
            .enumerate()
            .for_each(|(slot, key)| keys[slot] = key);
        Some(KeyboardReport {
            modifiers,
            reserved: 0,
            keys,
        })
    }
}

/// Whether `report` is the input report with `id` and at least `size` bytes.
fn matches(report: &[u8], id: Option<u8>, size: usize) -> bool {
    report.len() >= size.max(1) && id.is_none_or(|id| report[0] == id)
}

/// One HID-over-I2C device, shared by its pointer and keyboard functions.
pub struct HidI2c<I> {
    bus: I,
    address: u8,
    interrupt: Interrupt,
    command_register: u16,
    max_input: usize,
    mouse: Option<Mouse>,
    keyboard: Option<Keyboard>,
    /// Coalesce motion only within one button level, never across a click.
    reports: heapless::Deque<PointerReport, 16>,
    buttons: u32,
    keys: BootKeys,
    enabled: bool,
}

impl<I: I2c> HidI2c<I> {
    /// Fetch the HID descriptor at `register`, reset and power on the device
    /// and parse its report descriptor.
    pub fn open(
        mut bus: I,
        address: u8,
        interrupt: Interrupt,
        register: u16,
    ) -> Result<Self, Error<I::Error>> {
        let mut raw = [0; size_of::<Descriptor>()];
        bus.write_read(address, &register.to_le_bytes(), &mut raw)
            .map_err(Error::Bus)?;
        let descriptor =
            Descriptor::read_from_bytes(&raw).map_err(|_| Error::UnsupportedDescriptor)?;
        let report_length = usize::from(descriptor.report_descriptor_length.get());
        let max_input = usize::from(descriptor.max_input_length.get());
        if descriptor.length.get() != 30
            || descriptor.version.get() != 0x0100
            || !(1..=MAX_REPORT_DESCRIPTOR).contains(&report_length)
            || !(3..=MAX_INPUT).contains(&max_input)
        {
            return Err(Error::UnsupportedDescriptor);
        }
        let mut device = Self {
            bus,
            address,
            interrupt,
            command_register: descriptor.command_register.get(),
            max_input,
            mouse: None,
            keyboard: None,
            reports: heapless::Deque::new(),
            buttons: 0,
            keys: BootKeys::default(),
            enabled: true,
        };

        device.command(OPCODE_SET_POWER, POWER_ON)?;
        // Match Linux's settling time for devices that do not clock-stretch
        // while waking; an immediate RESET fails on several HID controllers.
        delay_ms(60);
        device.command(OPCODE_RESET, 0)?;
        // The device signals the end of a reset with a zero-length report.
        let reset = Timeout::from_ms(1_000);
        while !device.interrupt.is_pending() {
            if reset.is_expired() {
                return Err(Error::ResetAcknowledgement);
            }
            delay_ms(1);
        }
        let mut input = vec![0; max_input];
        device.bus.read(address, &mut input).map_err(Error::Bus)?;
        if input[..2] != [0, 0] {
            return Err(Error::ResetAcknowledgement);
        }

        let mut report_descriptor = vec![0; report_length];
        device
            .bus
            .write_read(
                address,
                &descriptor.report_descriptor_register.get().to_le_bytes(),
                &mut report_descriptor,
            )
            .map_err(Error::Bus)?;
        let report_descriptor = ReportDescriptor::try_from(report_descriptor.as_slice())
            .map_err(|_| Error::ReportDescriptor)?;
        device.mouse = Mouse::find(&report_descriptor);
        device.keyboard = Keyboard::find(&report_descriptor);
        if device.mouse.is_none() && device.keyboard.is_none() {
            return Err(Error::NoUsableCollection);
        }
        log::info!(
            "HID I2C device {:04x}:{:04x} at {:#x}: mouse {}, keyboard {}",
            descriptor.vendor.get(),
            descriptor.product.get(),
            address,
            device.mouse.is_some(),
            device.keyboard.is_some()
        );
        Ok(device)
    }

    fn command(&mut self, opcode: u8, argument: u8) -> Result<(), Error<I::Error>> {
        let [low, high] = self.command_register.to_le_bytes();
        self.bus
            .write(self.address, &[low, high, argument, opcode])
            .map_err(Error::Bus)
    }

    /// Read the pending input reports into the pointer motion and key buffer.
    fn poll(&mut self) {
        let mut input = [0; MAX_INPUT];
        let input = &mut input[..self.max_input];
        for _ in 0..REPORTS_PER_POLL {
            // Bounded backpressure rather than dropping button transitions.
            if !self.enabled || self.reports.is_full() || !self.interrupt.is_pending() {
                break;
            }
            if let Err(error) = self.read_report(input) {
                // A broken device must not stall every input poll.
                log::warn!(
                    "HID I2C device at {:#x} disabled: {:?}",
                    self.address,
                    error
                );
                self.enabled = false;
                self.reports.clear();
                let _ = self.reports.push_back(PointerReport::default());
                self.keys.process_report(&KeyboardReport::default());
            }
        }
        self.keys.handle_repeat();
    }

    fn read_report(&mut self, input: &mut [u8]) -> Result<(), Error<I::Error>> {
        self.bus.read(self.address, input).map_err(Error::Bus)?;
        let length = usize::from(u16::from_le_bytes([input[0], input[1]]));
        // A zero length announces a reset and carries no report.
        if length == 0 {
            return Ok(());
        }
        if !(3..=input.len()).contains(&length) {
            return Err(Error::InvalidReport);
        }
        let report = &input[2..length];
        if let Some(mouse) = &self.mouse
            && matches(report, mouse.report_id, mouse.size)
            && let Some(motion) = mouse.read(report)
        {
            if let Some(pending) = self.reports.back_mut()
                && pending.buttons == motion.buttons
            {
                pending.dx = pending.dx.saturating_add(motion.dx);
                pending.dy = pending.dy.saturating_add(motion.dy);
                pending.dz = pending.dz.saturating_add(motion.dz);
            } else {
                self.reports
                    .push_back(motion)
                    .map_err(|_| Error::InvalidReport)?;
            }
        }
        if let Some(keyboard) = &self.keyboard
            && matches(report, keyboard.report_id, keyboard.size)
            && let Some(keys) = keyboard.read(report)
        {
            self.keys.process_report(&keys);
        }
        Ok(())
    }

    fn stop(&mut self) {
        if core::mem::replace(&mut self.enabled, false)
            && let Err(error) = self.command(OPCODE_SET_POWER, POWER_SLEEP)
        {
            log::warn!(
                "HID I2C device at {:#x}: sleep failed: {:?}",
                self.address,
                error
            );
        }
    }
}

/// The pointer function of a shared HID device.
struct HidPointer<I>(Rc<RefCell<HidI2c<I>>>);

impl<I: I2c> PointerDevice for HidPointer<I> {
    fn poll(&mut self) -> Option<PointerReport> {
        let mut device = self.0.borrow_mut();
        device.poll();
        let report = device.reports.pop_front().unwrap_or(PointerReport {
            buttons: device.buttons,
            ..PointerReport::default()
        });
        device.buttons = report.buttons;
        Some(report)
    }

    fn stop(&mut self) {
        self.0.borrow_mut().stop();
    }
}

/// The keyboard function of a shared HID device.
struct HidKeyboard<I>(Rc<RefCell<HidI2c<I>>>);

impl<I: I2c> KeyboardDevice for HidKeyboard<I> {
    fn read_key(&mut self) -> Option<Key> {
        let mut device = self.0.borrow_mut();
        device.poll();
        device.keys.read_key()
    }

    fn key_state(&mut self) -> KeyState {
        self.0.borrow().keys.efi_state()
    }

    fn stop(&mut self) {
        self.0.borrow_mut().stop();
    }
}

/// Bind a described HID-over-I2C device as pointer and/or keyboard.
pub(crate) fn bind(device: I2cPeripheral) {
    let opened = match (device.interrupt, device.hid_descriptor_register) {
        (None, _) => Err(Error::NoInterrupt),
        (_, None) => Err(Error::NoDescriptorRegister),
        (Some(interrupt), Some(register)) => {
            HidI2c::<I2cBus>::open(device.bus, device.address, interrupt, register)
        }
    };
    let hid = match opened {
        Ok(hid) => hid,
        Err(error) => {
            log::warn!("HID I2C device at {:#x}: {:?}", device.address, error);
            return;
        }
    };
    let (mouse, keyboard) = (hid.mouse.is_some(), hid.keyboard.is_some());
    let hid = Rc::new(RefCell::new(hid));
    if mouse {
        super::pointer::register(Box::new(HidPointer(hid.clone())));
    }
    if keyboard {
        super::keyboard_common::register(Box::new(HidKeyboard(hid)));
    }
}

#[cfg(test)]
#[path = "hid_i2c_tests.rs"]
mod tests;

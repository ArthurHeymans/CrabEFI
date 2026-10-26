use super::*;
use crate::peripheral::InputLine;
use alloc::collections::VecDeque;
use core::convert::Infallible;
use embedded_hal::{
    digital::{self, InputPin},
    i2c::{ErrorKind, ErrorType, Operation},
};
use std::sync::{Arc, Mutex};

/// A three-button wheel mouse (report 1) and a boot keyboard (report 2).
const REPORT_DESCRIPTOR: &[u8] = &[
    0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x85, 0x01, 0x09, 0x01, 0xa1, 0x00, 0x05, 0x09, 0x19, 0x01,
    0x29, 0x03, 0x15, 0x00, 0x25, 0x01, 0x95, 0x03, 0x75, 0x01, 0x81, 0x02, 0x95, 0x01, 0x75, 0x05,
    0x81, 0x03, 0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x38, 0x15, 0x81, 0x25, 0x7f, 0x75, 0x08,
    0x95, 0x03, 0x81, 0x06, 0xc0, 0xc0, //
    0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x85, 0x02, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00,
    0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x03, 0x95, 0x06,
    0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xc0,
];

#[derive(Default)]
struct Device {
    inputs: VecDeque<Vec<u8>>,
    commands: Vec<Vec<u8>>,
    failed: bool,
}

#[derive(Clone, Default)]
struct Bus(Arc<Mutex<Device>>);

impl ErrorType for Bus {
    type Error = ErrorKind;
}

fn descriptor() -> Vec<u8> {
    [
        30u16,
        0x0100,
        REPORT_DESCRIPTOR.len() as u16,
        2,
        3,
        16,
        4,
        0,
        5,
        6,
        0x04f3,
        0x1234,
        1,
    ]
    .iter()
    .flat_map(|word| word.to_le_bytes())
    .chain([0; 4])
    .collect()
}

impl I2c for Bus {
    fn transaction(
        &mut self,
        address: u8,
        operations: &mut [Operation<'_>],
    ) -> Result<(), ErrorKind> {
        assert_eq!(address, 0x2c);
        let mut device = self.0.lock().unwrap();
        if device.failed {
            return Err(ErrorKind::Other);
        }
        match operations {
            [Operation::Write([low, high]), Operation::Read(buffer)] => {
                let data = match u16::from_le_bytes([*low, *high]) {
                    0x20 => descriptor(),
                    2 => REPORT_DESCRIPTOR.to_vec(),
                    register => panic!("read of register {register:#x}"),
                };
                buffer.copy_from_slice(&data[..buffer.len()]);
            }
            [Operation::Write(command)] => device.commands.push(command.to_vec()),
            [Operation::Read(buffer)] => {
                buffer.fill(0);
                // An empty entry stands for the reset announcement.
                if let Some(report) = device.inputs.pop_front().filter(|r| !r.is_empty()) {
                    let length = (report.len() + 2) as u16;
                    buffer[..2].copy_from_slice(&length.to_le_bytes());
                    buffer[2..2 + report.len()].copy_from_slice(&report);
                }
            }
            _ => panic!("unexpected transfer"),
        }
        Ok(())
    }
}

/// Active-low data-ready line asserted while input is queued.
struct Ready(Bus);

impl digital::ErrorType for Ready {
    type Error = Infallible;
}

impl InputPin for Ready {
    fn is_high(&mut self) -> Result<bool, Infallible> {
        Ok(self.0.0.lock().unwrap().inputs.is_empty())
    }

    fn is_low(&mut self) -> Result<bool, Infallible> {
        self.is_high().map(|high| !high)
    }
}

fn open() -> (Bus, HidI2c<Bus>) {
    let bus = Bus::default();
    bus.0.lock().unwrap().inputs.push_back(Vec::new());
    let interrupt = Interrupt::Level {
        line: InputLine::new(Ready(bus.clone())),
        active_low: true,
    };
    let hid = HidI2c::open(bus.clone(), 0x2c, interrupt, 0x20).unwrap();
    (bus, hid)
}

#[test]
fn powers_on_resets_and_finds_mouse_and_keyboard_collections() {
    let (bus, hid) = open();
    assert!(hid.mouse.is_some() && hid.keyboard.is_some());
    assert_eq!(
        bus.0.lock().unwrap().commands,
        vec![
            vec![5, 0, POWER_ON, OPCODE_SET_POWER],
            vec![5, 0, 0, OPCODE_RESET]
        ]
    );
}

#[test]
fn absolute_mouse_axes_are_not_treated_as_relative_motion() {
    let mut descriptor = REPORT_DESCRIPTOR.to_vec();
    let axes = descriptor
        .windows(2)
        .position(|bytes| bytes == [0x81, 0x06])
        .unwrap();
    descriptor[axes + 1] = 0x02; // Data, Variable, Absolute
    let descriptor = ReportDescriptor::try_from(descriptor.as_slice()).unwrap();
    assert!(Mouse::find(&descriptor).is_none());
    assert!(Keyboard::find(&descriptor).is_some());
}

#[test]
fn reset_requires_a_zero_length_acknowledgement() {
    let bus = Bus::default();
    bus.0.lock().unwrap().inputs.push_back(vec![1, 0, 0, 0, 0]);
    let interrupt = Interrupt::Level {
        line: InputLine::new(Ready(bus.clone())),
        active_low: true,
    };
    assert!(matches!(
        HidI2c::open(bus, 0x2c, interrupt, 0x20),
        Err(Error::ResetAcknowledgement)
    ));
}

#[test]
fn keyboard_polling_does_not_erase_pointer_button_transitions() {
    let (bus, hid) = open();
    {
        let mut device = bus.0.lock().unwrap();
        device.inputs.push_back(vec![1, 1, 0, 0, 0]);
        device.inputs.push_back(vec![1, 0, 0, 0, 0]);
    }
    let hid = Rc::new(RefCell::new(hid));
    let mut pointer = HidPointer(hid.clone());
    let mut keyboard = HidKeyboard(hid);
    assert!(keyboard.read_key().is_none());
    assert_eq!(pointer.poll().unwrap().buttons, 1);
    assert_eq!(pointer.poll().unwrap().buttons, 0);
}

#[test]
fn transport_failure_releases_modifiers_and_stops_key_repeat() {
    let (bus, hid) = open();
    bus.0
        .lock()
        .unwrap()
        .inputs
        .push_back(vec![2, 2, 0, 4, 0, 0, 0, 0, 0]);
    let mut keyboard = HidKeyboard(Rc::new(RefCell::new(hid)));
    assert!(keyboard.read_key().is_some());
    assert_ne!(keyboard.key_state().shift_state, 0);
    {
        let mut device = bus.0.lock().unwrap();
        device.inputs.push_back(vec![2, 0, 0, 0, 0, 0, 0, 0, 0]);
        device.failed = true;
    }
    assert!(keyboard.read_key().is_none());
    assert_eq!(keyboard.key_state().shift_state, 0);
    assert_eq!(
        keyboard.0.borrow().keys.prev_report,
        KeyboardReport::default()
    );
}

#[test]
fn mouse_and_keyboard_fields_can_share_one_report() {
    let (bus, mut hid) = open();
    let mut descriptor = REPORT_DESCRIPTOR.to_vec();
    let keyboard_id = descriptor
        .windows(2)
        .position(|bytes| bytes == [0x85, 2])
        .unwrap();
    descriptor[keyboard_id + 1] = 1;
    let descriptor = ReportDescriptor::try_from(descriptor.as_slice()).unwrap();
    hid.mouse = Mouse::find(&descriptor);
    hid.keyboard = Keyboard::find(&descriptor);
    bus.0
        .lock()
        .unwrap()
        .inputs
        .push_back(vec![1, 1, 5, 0, 0, 2, 0, 4, 0, 0, 0, 0, 0]);
    let hid = Rc::new(RefCell::new(hid));
    let mut pointer = HidPointer(hid.clone());
    let mut keyboard = HidKeyboard(hid);
    assert_eq!(pointer.poll().unwrap().dx, 5);
    assert_eq!(keyboard.read_key().unwrap().unicode_char, u16::from(b'A'));
}

#[test]
fn mouse_reports_accumulate_and_keyboard_reports_produce_keys() {
    let (bus, hid) = open();
    {
        let mut device = bus.0.lock().unwrap();
        // Left button, dx 5, dy -3, one wheel notch up.
        device.inputs.push_back(vec![1, 1, 5, 0xfd, 1]);
        device.inputs.push_back(vec![1, 1, 2, 0, 0]);
        // Left shift + 'a'.
        device.inputs.push_back(vec![2, 0x02, 0, 4, 0, 0, 0, 0, 0]);
    }
    let hid = Rc::new(RefCell::new(hid));
    let mut pointer = HidPointer(hid.clone());
    let mut keyboard = HidKeyboard(hid);
    assert_eq!(
        pointer.poll(),
        Some(PointerReport {
            dx: 7,
            dy: -3,
            dz: -1,
            buttons: 1
        })
    );
    assert_eq!(
        keyboard.read_key().map(|key| key.unicode_char),
        Some(u16::from(b'A'))
    );
    assert_eq!(
        pointer.poll(),
        Some(PointerReport {
            buttons: 1,
            ..PointerReport::default()
        })
    );
    pointer.stop();
    assert_eq!(
        bus.0.lock().unwrap().commands.last(),
        Some(&vec![5, 0, POWER_SLEEP, OPCODE_SET_POWER])
    );
}

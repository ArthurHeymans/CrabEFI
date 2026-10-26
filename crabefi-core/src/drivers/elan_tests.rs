use super::*;
use embedded_hal::i2c::{ErrorKind, ErrorType, Operation};
use std::{collections::VecDeque, vec, vec::Vec};

enum Step {
    Write(Vec<u8>),
    Read(Vec<u8>),
    Register(u16, Vec<u8>),
    Failure,
}
struct Bus(VecDeque<Step>);
impl ErrorType for Bus {
    type Error = ErrorKind;
}
impl I2c for Bus {
    fn transaction(
        &mut self,
        address: u8,
        operations: &mut [Operation<'_>],
    ) -> Result<(), ErrorKind> {
        assert_eq!(address, 0x15);
        match (
            self.0.pop_front().expect("unexpected I2C transfer"),
            operations,
        ) {
            (Step::Write(expected), [Operation::Write(actual)]) => assert_eq!(expected, *actual),
            (Step::Read(data), [Operation::Read(actual)]) => actual.copy_from_slice(&data),
            (
                Step::Register(register, data),
                [Operation::Write(actual), Operation::Read(output)],
            ) => {
                assert_eq!(*actual, Le16::new(register).as_bytes());
                output.copy_from_slice(&data);
            }
            (Step::Failure, _) => return Err(ErrorKind::Bus),
            _ => panic!("wrong I2C transaction shape"),
        }
        Ok(())
    }
}
struct Delay;
impl DelayNs for Delay {
    fn delay_ns(&mut self, ns: u32) {
        assert_eq!(ns, 100_000_000);
    }
}
fn command(register: u16, value: u16) -> Step {
    Step::Write(
        Command {
            register: register.into(),
            value: value.into(),
        }
        .as_bytes()
        .to_vec(),
    )
}
fn register(register: u16, value: u16) -> Step {
    Step::Register(register, Le16::new(value).as_bytes().to_vec())
}
fn initialization(pattern: u16) -> VecDeque<Step> {
    let descriptor = Descriptor {
        length: Le16::new(30),
        version: Le16::new(0x100),
        report_length: Le16::new(158),
        report_register: Le16::new(2),
        input_register: Le16::new(3),
        max_input_length: Le16::new(34),
        output_register: Le16::new(4),
        max_output_length: Le16::new(0),
        command_register: Le16::new(5),
        data_register: Le16::new(6),
        vendor: Le16::new(0x04f3),
        product: Le16::new(1),
        firmware: Le16::new(1),
        reserved: [0; 4],
    };
    VecDeque::from(vec![
        command(COMMAND, RESET),
        Step::Read(vec![0, 0]),
        Step::Register(DESCRIPTOR, descriptor.as_bytes().to_vec()),
        Step::Register(2, vec![0; 158]),
        register(PATTERN, pattern),
        register(MAX_X, 4095),
        register(MAX_Y, 4095),
        command(SET_MODE, 1),
        command(COMMAND, WAKE),
    ])
}
fn packet(precise: bool, slot: Option<u8>, x: u16, y: u16, buttons: u8) -> Vec<u8> {
    let len = if precise { 39 } else { 34 };
    let mut data = vec![0; len];
    data[..2].copy_from_slice(Le16::new(len as u16).as_bytes());
    data[2] = if precise { 0x60 } else { 0x5d };
    data[3] = buttons | slot.map_or(0, |slot| 1 << (3 + slot));
    if precise {
        data[4..6].copy_from_slice(Be16::new(x).as_bytes());
        data[6..8].copy_from_slice(Be16::new(y).as_bytes());
        data[8] = 30;
    } else {
        data[4] = ((x >> 4) & 0xf0) as u8 | ((y >> 8) & 0xf) as u8;
        data[5] = x as u8;
        data[6] = y as u8;
        data[8] = 30;
    }
    data
}
#[test]
fn initializes_native_mode_polls_only_when_ready_and_sleeps_at_handoff() {
    let mut steps = initialization(0xffff);
    steps.push_back(command(COMMAND, SLEEP));
    let mut device = ElanTouchpad::new(Bus(steps), Delay, || false, 0x15).unwrap();
    assert_eq!(device.geometry(), (4095, 4095));
    assert!(device.poll().unwrap().is_none());
    device.stop();
    assert!(device.bus.0.is_empty());
}
#[test]
fn reports_motion_click_release_and_resets_origin_after_lift_or_slot_change() {
    for precise in [false, true] {
        let mut steps = initialization(if precise { 0x0200 } else { 0x0100 });
        for data in [
            packet(precise, Some(0), 100, 200, 0),
            packet(precise, Some(0), 110, 180, 1),
            packet(precise, None, 0, 0, 0),
            packet(precise, Some(2), 800, 800, 0),
            packet(precise, Some(3), 900, 900, 0),
        ] {
            steps.push_back(Step::Read(data));
        }
        let mut device = ElanTouchpad::new(Bus(steps), Delay, || true, 0x15).unwrap();
        assert_eq!(device.read_state(), Some(PointerState::default()));
        assert_eq!(
            device.read_state(),
            Some(PointerState {
                dx: 10,
                dy: 20,
                dz: 0,
                buttons: 1
            })
        );
        for _ in 0..3 {
            assert_eq!(device.read_state(), Some(PointerState::default()));
        }
        assert!(device.bus.0.is_empty());
    }
}
#[test]
fn rejects_invalid_reports_and_ignores_hover_coordinates() {
    let mut data = packet(false, Some(0), 100, 200, 0);
    data[30] = 1 << 6;
    assert!(matches!(report(&data, (4095, 4095)), Ok(Some((None, 0)))));
    assert!(report(&data[..10], (4095, 4095)).is_err());
    data[30] = 0;
    assert!(report(&data, (99, 4095)).is_err());
    data[2] = 0x60;
    assert!(report(&data, (4095, 4095)).is_err());
}
#[test]
fn bus_failure_releases_buttons_and_does_not_retry_on_every_ui_poll() {
    let mut steps = initialization(0);
    steps.push_back(Step::Read(packet(false, None, 0, 0, 1)));
    steps.push_back(Step::Failure);
    let mut device = ElanTouchpad::new(Bus(steps), Delay, || true, 0x15).unwrap();
    assert_eq!(device.read_state().unwrap().buttons, 1);
    assert_eq!(device.read_state(), Some(PointerState::default()));
    assert!(device.read_state().is_none());
    assert!(device.bus.0.is_empty());
}

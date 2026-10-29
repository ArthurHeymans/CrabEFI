use super::*;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};

struct FakeController {
    now: Cell<u64>,
    busy_until: Cell<u64>,
    config: Cell<u8>,
    writing_config: Cell<bool>,
    reply_to_config: bool,
    // (arrival time, AUX tag, byte)
    output: RefCell<VecDeque<(u64, bool, u8)>>,
    commands: RefCell<Vec<u8>>,
    data: RefCell<Vec<u8>>,
}

impl FakeController {
    fn new() -> Self {
        Self {
            now: Cell::new(0),
            busy_until: Cell::new(0),
            config: Cell::new(0x45),
            writing_config: Cell::new(false),
            reply_to_config: true,
            output: RefCell::new(VecDeque::new()),
            commands: RefCell::new(Vec::new()),
            data: RefCell::new(Vec::new()),
        }
    }

    fn reply(&self, at: u64, aux: bool, byte: u8) {
        self.output.borrow_mut().push_back((at, aux, byte));
    }
}

impl Controller for FakeController {
    fn status(&self) -> u8 {
        let busy = if self.now.get() < self.busy_until.get() {
            INPUT_FULL
        } else {
            0
        };
        let output = self.output.borrow();
        match output.front() {
            Some(&(at, aux, _)) if at <= self.now.get() => {
                busy | OUTPUT_FULL | if aux { AUX_DATA } else { 0 }
            }
            _ => busy,
        }
    }

    fn read_data(&self) -> u8 {
        self.output.borrow_mut().pop_front().unwrap().2
    }

    fn write_data(&self, byte: u8) {
        self.data.borrow_mut().push(byte);
        if self.writing_config.replace(false) {
            self.config.set(byte);
        }
    }

    fn write_command(&self, byte: u8) {
        self.commands.borrow_mut().push(byte);
        match byte {
            0xAD => self.config.set(self.config.get() | KB_DISABLE),
            0xAE => self.config.set(self.config.get() & !KB_DISABLE),
            0xA7 => self.config.set(self.config.get() | AUX_DISABLE),
            0x20 if self.reply_to_config => self.reply(self.now.get(), false, self.config.get()),
            0x60 => self.writing_config.set(true),
            _ => {}
        }
    }

    fn now_us(&self) -> u64 {
        self.now.get()
    }

    fn delay(&self) {
        self.now.set(self.now.get() + POLL_US);
    }
}

#[test]
fn stale_keyboard_ack_and_bat_cannot_be_written_as_controller_config() {
    let mut io = FakeController::new();
    io.reply(0, false, 0xFA);
    io.reply(0, false, 0xAA);
    assert!(init_aux(&mut io, |io| {
        assert_eq!(io.config.get(), 0x54); // translated, keyboard off, AUX on, no IRQs
        true
    }));
    assert_eq!(*io.data.borrow(), vec![0x54]); // not 0xDA from interpreting ACK as config
    assert_eq!(io.config.get(), 0x44); // keyboard clock restored
    assert_eq!(*io.commands.borrow(), vec![0xAD, 0xA7, 0x20, 0x60, 0xAE]);
    assert!(io.output.borrow().is_empty());
}

#[test]
fn failed_aux_probe_still_restores_keyboard_clock() {
    let mut io = FakeController::new();
    assert!(!init_aux(&mut io, |io| {
        assert_ne!(io.config.get() & KB_DISABLE, 0);
        false
    }));
    assert_eq!(io.config.get() & KB_DISABLE, 0);
    assert_eq!(io.commands.borrow().last(), Some(&0xAE));
}

#[test]
fn config_timeout_restores_keyboard_without_running_aux_probe() {
    let mut io = FakeController::new();
    io.reply_to_config = false;
    assert!(!init_aux(&mut io, |_| panic!("configuration read failed")));
    assert_eq!(io.config.get() & KB_DISABLE, 0);
    assert!(io.data.borrow().is_empty());
    assert!(io.now.get() >= CONTROLLER_TIMEOUT_US);
}

#[test]
fn controller_waits_for_a_slow_response_using_elapsed_time() {
    let io = FakeController::new();
    io.reply(80_000, false, 0x55);
    assert!(io.wait_output_ready());
    assert_eq!(io.now.get(), 80_000);
}

#[test]
fn busy_controller_times_out_without_writing_a_command() {
    let io = FakeController::new();
    io.busy_until.set(u64::MAX);
    assert!(!io.send_controller_cmd(0xAA));
    assert_eq!(io.now.get(), CONTROLLER_TIMEOUT_US);
    assert!(io.commands.borrow().is_empty());
}

#[test]
fn keyboard_command_skips_aux_ack_and_late_bat_before_its_own_ack() {
    let io = FakeController::new();
    io.reply(0, true, 0xFA);
    io.reply(50, false, 0xAA);
    io.reply(80_000, false, 0xFA);
    assert!(io.send_device_byte(false, 0xF4));
    assert_eq!(*io.data.borrow(), vec![0xF4]);
    assert_eq!(io.now.get(), 80_000);
    assert!(io.output.borrow().is_empty());
}

#[test]
fn ack_from_wrong_interface_does_not_complete_a_command() {
    let io = FakeController::new();
    io.reply(0, true, 0xFA);
    assert!(!io.send_device_byte(false, 0xF4));
    assert_eq!(io.now.get(), ACK_TIMEOUT_US);
}

#[test]
fn aux_resend_repeats_the_routing_command_and_data() {
    let io = FakeController::new();
    io.reply(0, true, 0xFE);
    io.reply(50, true, 0xFA);
    assert!(io.send_device_byte(true, 0xF5));
    assert_eq!(*io.commands.borrow(), vec![0xD4, 0xD4]);
    assert_eq!(*io.data.borrow(), vec![0xF5, 0xF5]);
}

#[test]
fn repeated_resend_is_bounded() {
    let io = FakeController::new();
    for _ in 0..3 {
        io.reply(0, false, 0xFE);
    }
    assert!(!io.send_device_byte(false, 0xF4));
    assert_eq!(*io.data.borrow(), vec![0xF4; 3]);
}

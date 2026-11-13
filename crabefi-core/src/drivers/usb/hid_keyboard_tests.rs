use super::*;
use crate::drivers::usb::controller::{desc_type, request};

#[test]
fn queued_tab_keeps_shift_after_a_release_report() {
    let mut keys = BootKeys::default();
    keys.process_report(&KeyboardReport {
        modifiers: KeyboardReport::MOD_LEFT_SHIFT,
        keys: [0x2b, 0, 0, 0, 0, 0],
        ..KeyboardReport::default()
    });
    keys.process_report(&KeyboardReport::default());
    assert_eq!(keys.efi_state().shift_state, 0);
    let (key, state) = keys.read_key_with_state().unwrap();
    assert_eq!(key.unicode_char, b'\t' as u16);
    assert_ne!(
        state.shift_state & crate::drivers::keyboard_common::efi_shift_state::LEFT_SHIFT_PRESSED,
        0
    );
}

struct Controller {
    report: [u8; 8],
    length: usize,
    supported: bool,
    get_reports: usize,
    class_indices: alloc::vec::Vec<u16>,
    descriptor: Option<alloc::vec::Vec<u8>>,
    boot_protocol_stalls: bool,
}

impl Controller {
    fn new() -> Self {
        Self {
            report: [0, 0, 4, 0, 0, 0, 0, 0],
            length: 8,
            supported: true,
            get_reports: 0,
            class_indices: alloc::vec::Vec::new(),
            descriptor: None,
            boot_protocol_stalls: false,
        }
    }
}

impl UsbController for Controller {
    fn controller_type(&self) -> &'static str {
        "test"
    }
    fn hid_report_descriptor(
        &mut self,
        _: u8,
        interface: u8,
    ) -> Result<alloc::vec::Vec<u8>, UsbError> {
        assert_eq!(interface, 3);
        self.descriptor.clone().ok_or(UsbError::NotSupported)
    }
    fn control_transfer(
        &mut self,
        _device: u8,
        request_type: u8,
        req: u8,
        value: u16,
        index: u16,
        data: Option<&mut [u8]>,
    ) -> Result<usize, UsbError> {
        if request_type & req_type::TYPE_CLASS == 0 {
            assert_eq!(req, request::GET_DESCRIPTOR);
            assert_eq!(value, (desc_type::CONFIGURATION as u16) << 8);
            let config = [
                9, 2, 25, 0, 1, 1, 0, 0x80, 50, 9, 4, 3, 0, 1, 3, 1, 1, 0, 7, 5, 0x81, 3, 8, 0, 10,
            ];
            let data = data.unwrap();
            let length = data.len().min(config.len());
            data[..length].copy_from_slice(&config[..length]);
            return Ok(length);
        }
        self.class_indices.push(index);
        if req == hid_request::SET_PROTOCOL && self.boot_protocol_stalls {
            return Err(UsbError::Stall);
        }
        if req == hid_request::GET_REPORT {
            self.get_reports += 1;
            data.unwrap()[..8].copy_from_slice(&self.report);
            return Ok(8);
        }
        Ok(0)
    }
    fn interrupt_transfer(
        &mut self,
        _device: u8,
        endpoint: u8,
        data: &mut [u8],
    ) -> Result<usize, UsbError> {
        assert_eq!(endpoint, 1);
        if !self.supported {
            return Err(UsbError::NotSupported);
        }
        data[..self.length].copy_from_slice(&self.report[..self.length]);
        Ok(self.length)
    }
    fn bulk_transfer(&mut self, _: u8, _: u8, _: bool, _: &mut [u8]) -> Result<usize, UsbError> {
        unreachable!()
    }
    fn create_interrupt_queue(
        &mut self,
        _: u8,
        _: u8,
        _: bool,
        _: u16,
        _: u8,
    ) -> Result<u32, UsbError> {
        unreachable!()
    }
    fn poll_interrupt_queue(&mut self, _: u32, _: &mut [u8]) -> Option<usize> {
        unreachable!()
    }
    fn destroy_interrupt_queue(&mut self, _: u32) {
        unreachable!()
    }
}

#[cfg(feature = "ui")]
#[test]
fn stalled_boot_protocol_uses_the_keyboard_report_descriptor_and_report_id() {
    // Standard keyboard fields, with report ID 42 rather than boot layout.
    let mut descriptor = alloc::vec![
        0x05, 1, 0x09, 6, 0xa1, 1, 0x85, 42, 0x05, 7, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0, 0x25, 1,
        0x75, 1, 0x95, 8, 0x81, 2, 0x95, 1, 0x75, 8, 0x81, 3, 0x95, 6, 0x75, 8, 0x15, 0, 0x25,
        0x65, 0x05, 7, 0x19, 0, 0x29, 0x65, 0x81, 0, 0xc0,
    ];
    let mut controller = Controller::new();
    controller.descriptor = Some(descriptor.clone());
    controller.boot_protocol_stalls = true;
    let mut keyboard = UsbHidKeyboard::new(0, 1, 1, 8, 10);
    assert!(matches!(
        keyboard.set_boot_protocol(&mut controller),
        Err(UsbError::Stall)
    ));
    assert_eq!(keyboard.report_buffer.len(), 9);
    keyboard
        .report_buffer
        .copy_from_slice(&[42, 0, 0, 0x52, 0, 0, 0, 0, 0]);
    let report = keyboard.decode_report(9).unwrap();
    assert_eq!(report.modifiers, 0);
    assert_eq!(report.keys[0], 0x52);
    assert!(keyboard.decode_report(8).is_none());
    // Without an ID, the same stalled device uses an eight-byte report.
    descriptor.drain(6..8);
    controller.descriptor = Some(descriptor);
    let mut keyboard = UsbHidKeyboard::new(0, 1, 1, 8, 10);
    assert!(matches!(
        keyboard.set_boot_protocol(&mut controller),
        Err(UsbError::Stall)
    ));
    controller.report = [0, 0, 0x52, 0, 0, 0, 0, 0];
    keyboard.poll_report(&mut controller);
    assert_eq!(keyboard.keys.get_key(), Some(0x0100));
}

#[test]
fn interrupt_reports_preserve_keys_when_pending_or_short() {
    let mut controller = Controller::new();
    let mut keyboard = UsbHidKeyboard::new(0, 1, 1, 8, 10);
    keyboard.poll_report(&mut controller);
    assert_eq!(keyboard.keys.get_key(), Some(b'a' as u16));
    assert_eq!(keyboard.keys.prev_report.keys[0], 4);
    controller.report.fill(0);
    for length in [0, 2, 7] {
        controller.length = length;
        keyboard.poll_report(&mut controller);
        assert_eq!(keyboard.keys.prev_report.keys[0], 4);
    }
    controller.length = 8;
    keyboard.poll_report(&mut controller);
    assert_eq!(keyboard.keys.prev_report.keys[0], 0);
    assert_eq!(controller.get_reports, 0);
}

#[test]
fn composite_interface_is_used_for_all_class_requests() {
    let mut controller = Controller::new();
    let mut keyboard = UsbHidKeyboard::new(0, 1, 1, 8, 10);
    keyboard.set_boot_protocol(&mut controller).unwrap();
    keyboard.set_idle(&mut controller, 0).unwrap();
    keyboard.set_leds(&mut controller).unwrap();
    controller.supported = false;
    keyboard.poll_report(&mut controller);
    assert_eq!(controller.class_indices, [3, 3, 3, 3]);
    assert_eq!(controller.get_reports, 1);
}

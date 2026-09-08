use super::*;
use crate::drivers::usb::controller::{desc_type, request};

struct Controller {
    report: [u8; 8],
    length: usize,
    supported: bool,
    get_reports: usize,
    class_indices: alloc::vec::Vec<u16>,
}

impl Controller {
    fn new() -> Self {
        Self {
            report: [0, 0, 4, 0, 0, 0, 0, 0],
            length: 8,
            supported: true,
            get_reports: 0,
            class_indices: alloc::vec::Vec::new(),
        }
    }
}

impl UsbController for Controller {
    fn controller_type(&self) -> &'static str {
        "test"
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

#[test]
fn interrupt_reports_preserve_keys_when_pending_or_short() {
    let mut controller = Controller::new();
    let mut keyboard = UsbHidKeyboard::new(0, 1, 1, 8, 10);
    poll_report(&mut keyboard, &mut controller);
    assert_eq!(keyboard.get_key(), Some(b'a' as u16));
    assert_eq!(keyboard.prev_report.keys[0], 4);
    controller.report.fill(0);
    for length in [0, 2, 7] {
        controller.length = length;
        poll_report(&mut keyboard, &mut controller);
        assert_eq!(keyboard.prev_report.keys[0], 4);
    }
    controller.length = 8;
    poll_report(&mut keyboard, &mut controller);
    assert_eq!(keyboard.prev_report.keys[0], 0);
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
    poll_report(&mut keyboard, &mut controller);
    assert_eq!(controller.class_indices, [3, 3, 3, 3]);
    assert_eq!(controller.get_reports, 1);
}

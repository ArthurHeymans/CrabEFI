use super::super::controller::{Direction, EndpointInfo, EndpointType};
use super::*;
use crate::drivers::hid_report::tests::ABSOLUTE_MOUSE;

struct Controller {
    report: Option<[u8; 6]>,
    requests: Vec<(u8, u16, u16)>,
}

impl UsbController for Controller {
    fn controller_type(&self) -> &'static str {
        "test"
    }
    fn get_mouse_interrupt_endpoint(&self, device: u8) -> Option<EndpointInfo> {
        assert_eq!(device, 2);
        Some(EndpointInfo {
            number: 3,
            direction: Direction::In,
            transfer_type: EndpointType::Interrupt,
            max_packet_size: 6,
            interval: 100,
            toggle: false,
        })
    }
    fn hid_interface_number(&mut self, device: u8, endpoint: u8) -> Result<u8, UsbError> {
        assert_eq!((device, endpoint), (2, 3));
        Ok(1)
    }
    fn hid_report_descriptor(&mut self, device: u8, interface: u8) -> Result<Vec<u8>, UsbError> {
        assert_eq!((device, interface), (2, 1));
        Ok(ABSOLUTE_MOUSE.to_vec())
    }
    fn control_transfer(
        &mut self,
        device: u8,
        kind: u8,
        request: u8,
        value: u16,
        interface: u16,
        data: Option<&mut [u8]>,
    ) -> Result<usize, UsbError> {
        assert_eq!(device, 2);
        assert_eq!(
            kind,
            req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE
        );
        assert!(data.is_none());
        self.requests.push((request, value, interface));
        // Match the Insyde gadget: descriptor-defined reports remain usable
        // even though its class protocol/idle requests stall.
        Err(UsbError::Stall)
    }
    fn interrupt_transfer(
        &mut self,
        device: u8,
        endpoint: u8,
        data: &mut [u8],
    ) -> Result<usize, UsbError> {
        assert_eq!((device, endpoint), (2, 3));
        assert_eq!(
            data.len(),
            6,
            "an eight-byte TD babbles on the next six-byte report"
        );
        if let Some(report) = self.report.take() {
            data.copy_from_slice(&report);
            Ok(report.len())
        } else {
            Ok(0)
        }
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
fn absolute_bmc_mouse_polls_six_bytes_despite_class_stalls() {
    let mut controller = Controller {
        report: Some([1, 0xff, 0x7f, 0, 0, 0]),
        requests: Vec::new(),
    };
    let mut mouse = init_mouse(&mut controller, 1, 2).unwrap();
    assert_eq!(
        controller.requests,
        [
            (hid_request::SET_PROTOCOL, 1, 1),
            (hid_request::SET_IDLE, 0, 1)
        ]
    );
    mouse.poll_controller(&mut controller);
    let report = mouse.pending.take().unwrap();
    assert_eq!(report.absolute, Some((u16::MAX, 0)));
    assert_eq!(report.buttons, 1);
    assert_eq!((report.dx, report.dy), (0, 0));
    mouse.next_poll = None;
    mouse.poll_controller(&mut controller);
    assert!(
        mouse.pending.is_none(),
        "no completion must not fabricate a release"
    );
}

#[test]
fn interrupt_capacity_never_leaves_a_partial_packet() {
    assert_eq!(input_capacity(6, 6).unwrap(), 6);
    assert_eq!(input_capacity(8, 3).unwrap(), 8);
    assert_eq!(input_capacity(64, 65).unwrap(), 128);
    assert!(input_capacity(0, 6).is_err());
    assert!(input_capacity(8, 4097).is_err());
}

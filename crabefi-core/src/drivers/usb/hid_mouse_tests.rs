use super::super::controller::{Direction, EndpointInfo, EndpointType};
use super::*;
use crate::drivers::hid_report::tests::{ABSOLUTE_MOUSE, RELATIVE_MOUSE};

struct Controller {
    report: Option<Vec<u8>>,
    descriptor: Option<Vec<u8>>,
    requests: Vec<(u8, u16, u16)>,
    packet: u16,
    expected_capacity: usize,
    interface: u8,
    endpoint: u8,
    class_stalls: bool,
    interrupts_supported: bool,
}

impl Controller {
    fn new(descriptor: &[u8], report: &[u8], packet: u16, capacity: usize) -> Self {
        Self {
            report: Some(report.to_vec()),
            descriptor: Some(descriptor.to_vec()),
            requests: Vec::new(),
            packet,
            expected_capacity: capacity,
            interface: 1,
            endpoint: 3,
            class_stalls: true,
            interrupts_supported: true,
        }
    }
}

impl UsbController for Controller {
    fn controller_type(&self) -> &'static str {
        "test"
    }
    fn get_mouse_interrupt_endpoint(&self, device: u8) -> Option<EndpointInfo> {
        assert_eq!(device, 2);
        Some(EndpointInfo {
            number: self.endpoint,
            direction: Direction::In,
            transfer_type: EndpointType::Interrupt,
            max_packet_size: self.packet,
            interval: 100,
            toggle: false,
        })
    }
    fn hid_interface_number(&mut self, device: u8, endpoint: u8) -> Result<u8, UsbError> {
        assert_eq!((device, endpoint), (2, self.endpoint));
        Ok(self.interface)
    }
    fn hid_report_descriptor(&mut self, device: u8, interface: u8) -> Result<Vec<u8>, UsbError> {
        assert_eq!((device, interface), (2, self.interface));
        self.descriptor.clone().ok_or(UsbError::NotSupported)
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
        assert_eq!(interface, u16::from(self.interface));
        self.requests.push((request, value, interface));
        if request == hid_request::GET_REPORT {
            assert_eq!(
                kind,
                req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE
            );
            let report = self.report.take().ok_or(UsbError::Nak)?;
            data.unwrap()[..report.len()].copy_from_slice(&report);
            return Ok(report.len());
        }
        assert_eq!(
            kind,
            req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE
        );
        assert!(data.is_none());
        if self.class_stalls {
            Err(UsbError::Stall)
        } else {
            Ok(0)
        }
    }
    fn interrupt_transfer(
        &mut self,
        device: u8,
        endpoint: u8,
        data: &mut [u8],
    ) -> Result<usize, UsbError> {
        assert_eq!((device, endpoint), (2, self.endpoint));
        assert_eq!(data.len(), self.expected_capacity);
        if !self.interrupts_supported {
            return Err(UsbError::NotSupported);
        }
        if let Some(report) = self.report.take() {
            data[..report.len()].copy_from_slice(&report);
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
    let mut controller = Controller::new(ABSOLUTE_MOUSE, &[1, 0xff, 0x7f, 0, 0, 0], 6, 6);
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
    assert_eq!(
        controller.requests.len(),
        2,
        "pending interrupts must not trigger GET_REPORT"
    );
}

#[test]
fn relative_wheel_mice_work_with_different_endpoint_packets() {
    for packet in [4, 8, 16, 64] {
        let mut controller = Controller::new(
            RELATIVE_MOUSE,
            &[5, 0xfe, 7, 1],
            packet,
            usize::from(packet),
        );
        controller.class_stalls = false;
        let mut mouse = init_mouse(&mut controller, 0, 2).unwrap();
        mouse.poll_controller(&mut controller);
        let report = mouse.pending.take().unwrap();
        assert_eq!(
            (report.dx, report.dy, report.dz, report.buttons),
            (-2, 7, -1, 5)
        );
        assert_eq!(report.absolute, None);
    }
}

#[test]
fn bmc_mouse_interface_endpoint_and_packet_are_not_hardcoded() {
    let mut controller = Controller::new(ABSOLUTE_MOUSE, &[0, 0, 0, 0xff, 0x7f, 0], 8, 8);
    controller.interface = 5;
    controller.endpoint = 7;
    let mut mouse = init_mouse(&mut controller, 3, 2).unwrap();
    mouse.poll_controller(&mut controller);
    assert_eq!(mouse.pending.take().unwrap().absolute, Some((0, u16::MAX)));
    assert_eq!(
        controller.requests,
        [
            (hid_request::SET_PROTOCOL, 1, 5),
            (hid_request::SET_IDLE, 0, 5)
        ]
    );
}

#[test]
fn absolute_report_ids_work_without_a_vendor_specific_layout() {
    let mut descriptor = ABSOLUTE_MOUSE.to_vec();
    descriptor.splice(6..6, [0x85, 7]);
    let mut controller = Controller::new(&descriptor, &[7, 2, 0, 0, 0xff, 0x7f, 0], 8, 8);
    let mut mouse = init_mouse(&mut controller, 0, 2).unwrap();
    mouse.poll_controller(&mut controller);
    let report = mouse.pending.take().unwrap();
    assert_eq!(report.absolute, Some((0, u16::MAX)));
    assert_eq!(report.buttons, 2);
}

#[test]
fn boot_fallback_requires_a_successful_protocol_switch() {
    for packet in [3, 4, 8] {
        let mut controller = Controller::new(&[], &[1, 0xfe, 7], packet, usize::from(packet));
        controller.descriptor = None;
        controller.class_stalls = false;
        let mut mouse = init_mouse(&mut controller, 0, 2).unwrap();
        assert_eq!(controller.requests[0], (hid_request::SET_PROTOCOL, 0, 1));
        mouse.poll_controller(&mut controller);
        let report = mouse.pending.take().unwrap();
        assert_eq!(
            (report.dx, report.dy, report.buttons, report.absolute),
            (-2, 7, 1, None)
        );
    }
    let mut controller = Controller::new(&[], &[0; 3], 8, 8);
    controller.descriptor = None;
    assert!(matches!(
        init_mouse(&mut controller, 0, 2),
        Err(UsbError::Stall)
    ));
}

#[test]
fn legacy_controller_get_report_uses_the_interface_and_report_id() {
    let mut descriptor = ABSOLUTE_MOUSE.to_vec();
    descriptor.splice(6..6, [0x85, 7]);
    let mut controller = Controller::new(&descriptor, &[7, 1, 0xff, 0x7f, 0, 0, 0], 8, 8);
    controller.interrupts_supported = false;
    controller.class_stalls = false;
    controller.interface = 4;
    let mut mouse = init_mouse(&mut controller, 0, 2).unwrap();
    mouse.poll_controller(&mut controller);
    assert_eq!(
        controller.requests.last(),
        Some(&(hid_request::GET_REPORT, 0x0107, 4))
    );
    assert_eq!(mouse.pending.take().unwrap().absolute, Some((u16::MAX, 0)));
}

#[test]
fn interrupt_capacity_never_leaves_a_partial_packet() {
    assert_eq!(input_capacity(6, 6).unwrap(), 6);
    assert_eq!(input_capacity(6, 8).unwrap(), 12);
    assert_eq!(input_capacity(8, 3).unwrap(), 8);
    assert_eq!(input_capacity(64, 65).unwrap(), 128);
    assert!(input_capacity(0, 6).is_err());
    assert!(input_capacity(8, 4097).is_err());
}

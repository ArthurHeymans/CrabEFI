//! USB HID mouse input, using descriptor-defined relative or absolute reports.
//!
//! Interrupt IN requests span whole endpoint packets. Requesting e.g. eight
//! bytes from a six-byte endpoint waits for the next report after a full first
//! packet, then babbles because that next packet cannot fit the remaining TD.

use super::controller::{UsbController, UsbError, hid_request, req_type};
use crate::drivers::hid_descriptor::{input_capacity, input_size, parse};
use crate::drivers::hid_report::Mouse;
use crate::drivers::pointer::{PointerDevice, PointerReport};
use crate::time::Timeout;
use alloc::vec::Vec;

/// USB HID mouse, owned by the common pointer registry.
pub struct UsbHidMouse {
    controller_idx: usize,
    device_address: u8,
    interface_number: u8,
    endpoint: u8,
    report: Option<Mouse>,
    buffer: Vec<u8>,
    pending: Option<PointerReport>,
    next_poll: Option<Timeout>,
    stall_count: u8,
    get_report_disabled: bool,
    transfer_failed: bool,
    seen_report: bool,
}

impl UsbHidMouse {
    pub fn device_address(&self) -> u8 {
        self.device_address
    }
    pub fn controller_idx(&self) -> usize {
        self.controller_idx
    }
    pub fn endpoint(&self) -> u8 {
        self.endpoint
    }

    fn decode(&mut self, length: usize) {
        let bytes = &self.buffer[..length];
        self.pending = if let Some(report) = &self.report {
            report.read(bytes)
        } else if bytes.len() >= 3 {
            Some(PointerReport {
                dx: i32::from(bytes[1] as i8),
                dy: i32::from(bytes[2] as i8),
                buttons: u32::from(bytes[0] & 7),
                ..Default::default()
            })
        } else {
            None
        };
        if let Some(report) = self.pending
            && !self.seen_report
        {
            log::debug!(
                "USB mouse {} first report: {:?}",
                self.device_address,
                report
            );
            self.seen_report = true;
        }
    }

    fn poll_controller<C: UsbController + ?Sized>(&mut self, controller: &mut C) {
        if self
            .next_poll
            .as_ref()
            .is_some_and(|next| !next.is_expired())
        {
            return;
        }
        self.next_poll = Some(Timeout::from_ms(8));
        if self.get_report_disabled {
            return;
        }
        match controller.interrupt_transfer(self.device_address, self.endpoint, &mut self.buffer) {
            Ok(0) | Err(UsbError::Nak) => return,
            Ok(length) => {
                self.transfer_failed = false;
                self.decode(length);
                return;
            }
            Err(UsbError::NotSupported) => {}
            Err(error) => {
                if !self.transfer_failed {
                    log::warn!(
                        "USB mouse {} EP {} interrupt failed: {:?}",
                        self.device_address,
                        self.endpoint,
                        error
                    );
                    self.transfer_failed = true;
                }
                return;
            }
        }
        // Legacy controllers without an interrupt implementation only.
        let id = self
            .report
            .as_ref()
            .and_then(|report| report.report_id)
            .unwrap_or(0);
        match controller.control_transfer(
            self.device_address,
            req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE,
            hid_request::GET_REPORT,
            0x0100 | u16::from(id),
            u16::from(self.interface_number),
            Some(&mut self.buffer),
        ) {
            Ok(length) => {
                self.stall_count = 0;
                self.decode(length);
            }
            Err(_) => {
                self.stall_count += 1;
                if self.stall_count >= 3 {
                    log::warn!(
                        "USB mouse {}: GET_REPORT repeatedly failed; disabling fallback",
                        self.device_address
                    );
                    self.get_report_disabled = true;
                }
            }
        }
    }
}

/// Register a mouse in report protocol when its descriptor can be decoded,
/// otherwise require a successful switch to the fixed boot mouse protocol.
pub fn init_mouse<C: UsbController + ?Sized>(
    controller: &mut C,
    controller_idx: usize,
    device_addr: u8,
) -> Result<UsbHidMouse, UsbError> {
    let ep = controller
        .get_mouse_interrupt_endpoint(device_addr)
        .ok_or(UsbError::DeviceNotFound)?;
    let interface = controller.hid_interface_number(device_addr, ep.number)?;
    let descriptor = controller
        .hid_report_descriptor(device_addr, interface)
        .ok()
        .and_then(|bytes| parse(&bytes));
    let report = descriptor.as_ref().and_then(Mouse::find);
    let size = if report.is_some() {
        input_size(descriptor.as_ref().unwrap())
    } else {
        3
    };
    let capacity = input_capacity(ep.max_packet_size, size).ok_or(UsbError::NotSupported)?;
    let protocol = u16::from(report.is_some()); // 1 = descriptor-defined report protocol
    if let Err(error) = controller.control_transfer(
        device_addr,
        req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE,
        hid_request::SET_PROTOCOL,
        protocol,
        u16::from(interface),
        None,
    ) {
        if report.is_none() {
            return Err(error);
        }
        // Some BMC gadgets reject this optional request but remain in their
        // power-on report protocol. We have their descriptor, not a boot guess.
        log::debug!(
            "USB mouse {} SET_PROTOCOL rejected: {:?}; using report descriptor",
            device_addr,
            error
        );
    }
    let _ = controller.control_transfer(
        device_addr,
        req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE,
        hid_request::SET_IDLE,
        0,
        u16::from(interface),
        None,
    );
    log::info!(
        "USB HID mouse: device {}, interface {}, EP {}, packet {}, input {}, report protocol {}",
        device_addr,
        interface,
        ep.number,
        ep.max_packet_size,
        capacity,
        report.is_some()
    );
    Ok(UsbHidMouse {
        controller_idx,
        device_address: device_addr,
        interface_number: interface,
        endpoint: ep.number,
        report,
        buffer: alloc::vec![0; capacity],
        pending: None,
        next_poll: None,
        stall_count: 0,
        get_report_disabled: false,
        transfer_failed: false,
        seen_report: false,
    })
}

impl PointerDevice for UsbHidMouse {
    fn poll(&mut self) -> Option<PointerReport> {
        super::with_controller(self.controller_idx, |controller| {
            self.poll_controller(controller)
        })?;
        self.pending.take()
    }
}

#[cfg(test)]
#[path = "hid_mouse_tests.rs"]
mod tests;

//! USB HID Mouse Driver
//!
//! This module implements USB HID mouse support using the boot protocol.
//! Boot protocol mice send 3-byte reports: buttons, X delta, Y delta.
//!
//! # Polling Strategy
//!
//! Many USB mice do NOT implement the HID class GET_REPORT request (they
//! stall the control pipe).  The only reliable way to read mouse data is
//! via interrupt IN transfers on the device's interrupt endpoint.
//!
//! We use interrupt IN transfers exclusively.  If the xHCI controller does
//! not have interrupt transfer support configured for the endpoint, we fall
//! back to GET_REPORT but give up after a few stalls to avoid chewing
//! through the command ring endlessly.
//!
//! # References
//! - USB HID Specification 1.11, Appendix B.2 (Boot Interface — Mouse)
//! - libpayload: `payloads/libpayload/drivers/usb/usbhid.c`

use super::controller::{UsbController, UsbError, hid_request, req_type};
use crate::time::Timeout;

// ============================================================================
// HID Boot Protocol Mouse
// ============================================================================

/// Boot protocol mouse report (3+ bytes)
///
/// The boot protocol defines a fixed 3-byte report:
/// - Byte 0: Button state (bit 0=left, 1=right, 2=middle)
/// - Byte 1: X displacement (signed 8-bit)
/// - Byte 2: Y displacement (signed 8-bit)
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct MouseReport {
    /// Button state (bit 0=left, 1=right, 2=middle)
    pub buttons: u8,
    /// X displacement (signed)
    pub x: i8,
    /// Y displacement (signed)
    pub y: i8,
}

// ============================================================================
// USB HID Mouse State
// ============================================================================

/// USB HID mouse state
pub struct UsbHidMouse {
    /// Controller index
    controller_idx: usize,
    /// Device address
    device_address: u8,
    /// Interface owning the boot-protocol interrupt endpoint.
    interface_number: u8,
    /// Interrupt endpoint number
    endpoint: u8,
    /// Max packet size
    #[allow(dead_code)] // Endpoint descriptor shadow; completeness for re-enumeration.
    max_packet: u16,
    /// Polling interval in ms
    #[allow(dead_code)] // Endpoint descriptor shadow; completeness for re-enumeration.
    interval: u8,
    /// Accumulated X relative motion
    rel_x: i32,
    /// Accumulated Y relative motion
    rel_y: i32,
    /// Current button state
    buttons: u32,
    /// Consecutive GET_REPORT stall count (if using fallback)
    stall_count: u32,
    /// Whether GET_REPORT has been disabled due to persistent stalls
    get_report_disabled: bool,
    /// Earliest time of the next poll
    next_poll: Option<Timeout>,
}

impl UsbHidMouse {
    /// Create a new USB HID mouse
    fn new(
        controller_idx: usize,
        device_address: u8,
        endpoint: u8,
        max_packet: u16,
        interval: u8,
    ) -> Self {
        Self {
            controller_idx,
            device_address,
            interface_number: 0,
            endpoint,
            max_packet,
            interval,
            rel_x: 0,
            rel_y: 0,
            buttons: 0,
            stall_count: 0,
            get_report_disabled: false,
            next_poll: None,
        }
    }

    /// Set boot protocol mode
    fn set_boot_protocol<C: UsbController + ?Sized>(
        &mut self,
        controller: &mut C,
    ) -> Result<(), UsbError> {
        self.interface_number =
            controller.hid_interface_number(self.device_address, self.endpoint)?;
        controller.control_transfer(
            self.device_address,
            req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE,
            hid_request::SET_PROTOCOL,
            0, // Boot protocol
            self.interface_number as u16,
            None,
        )?;
        Ok(())
    }

    /// Set idle rate
    fn set_idle<C: UsbController + ?Sized>(
        &self,
        controller: &mut C,
        rate_ms: u8,
    ) -> Result<(), UsbError> {
        let duration = rate_ms / 4;
        controller.control_transfer(
            self.device_address,
            req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE,
            hid_request::SET_IDLE,
            (duration as u16) << 8,
            self.interface_number as u16,
            None,
        )?;
        Ok(())
    }

    /// Process a mouse report
    fn process_report(&mut self, report: &MouseReport) {
        self.rel_x += report.x as i32;
        self.rel_y += report.y as i32;
        self.buttons = (report.buttons & 0x07) as u32;
    }

    /// Get device address
    pub fn device_address(&self) -> u8 {
        self.device_address
    }

    /// Get controller index
    pub fn controller_idx(&self) -> usize {
        self.controller_idx
    }

    /// Get interrupt endpoint number
    pub fn endpoint(&self) -> u8 {
        self.endpoint
    }
}

// ============================================================================
// Mouse lifecycle
// ============================================================================

/// Minimum poll interval in milliseconds
const MIN_POLL_INTERVAL_MS: u64 = 8;

/// Number of consecutive GET_REPORT stalls before giving up.
const MAX_CONSECUTIVE_STALLS: u32 = 3;

/// Set up the boot-protocol mouse at `device_addr`.
pub fn init_mouse<C: UsbController + ?Sized>(
    controller: &mut C,
    controller_idx: usize,
    device_addr: u8,
) -> Result<UsbHidMouse, UsbError> {
    let ep_info = controller
        .get_mouse_interrupt_endpoint(device_addr)
        .ok_or(UsbError::DeviceNotFound)?;

    log::info!(
        "USB HID mouse found: device {}, endpoint {}, max_pkt {}, interval {}ms",
        device_addr,
        ep_info.number,
        ep_info.max_packet_size,
        ep_info.interval
    );

    let mut mouse = UsbHidMouse::new(
        controller_idx,
        device_addr,
        ep_info.number,
        ep_info.max_packet_size,
        ep_info.interval,
    );

    if let Err(e) = mouse.set_boot_protocol(controller) {
        log::warn!("Failed to set mouse boot protocol: {:?}", e);
    }

    // Set idle rate to 0 (infinite — only report on change)
    if let Err(e) = mouse.set_idle(controller, 0) {
        log::debug!("Failed to set mouse idle rate: {:?}", e);
    }

    Ok(mouse)
}

impl UsbHidMouse {
    /// Poll for a new report.
    ///
    /// Tries interrupt IN transfer first (the correct HID approach).
    /// Falls back to GET_REPORT only if interrupt transfers are not available,
    /// and gives up after [`MAX_CONSECUTIVE_STALLS`] to avoid hammering the
    /// xHCI command ring.
    fn poll<C: UsbController + ?Sized>(&mut self, controller: &mut C) {
        if self
            .next_poll
            .as_ref()
            .is_some_and(|next| !next.is_expired())
        {
            return;
        }
        self.next_poll = Some(Timeout::from_ms(MIN_POLL_INTERVAL_MS));

        // Nothing to do once GET_REPORT is disabled after persistent stalls.
        if self.get_report_disabled {
            return;
        }

        let mut report_buf = [0u8; 8];
        match controller.interrupt_transfer(self.device_address, self.endpoint, &mut report_buf) {
            Ok(bytes_read) if bytes_read >= 3 => {
                self.stall_count = 0;
                self.process_report(&MouseReport {
                    buttons: report_buf[0],
                    x: report_buf[1] as i8,
                    y: report_buf[2] as i8,
                });
                return;
            }
            // Short read (NAK) or a transfer error: not fatal for interrupt
            // endpoints.
            Ok(_) => return,
            Err(UsbError::NotSupported) => {}
            Err(_) => return,
        }

        // ── Fallback: GET_REPORT via control transfer ──
        let mut ctrl_buf = [0u8; 4];
        let result = controller.control_transfer(
            self.device_address,
            req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_INTERFACE,
            hid_request::GET_REPORT,
            0x0100, // Report type = Input (1), Report ID = 0
            self.interface_number as u16,
            Some(&mut ctrl_buf),
        );

        match result {
            Ok(_) => {
                self.stall_count = 0;
                self.process_report(&MouseReport {
                    buttons: ctrl_buf[0],
                    x: ctrl_buf[1] as i8,
                    y: ctrl_buf[2] as i8,
                });
            }
            Err(_) => {
                self.stall_count += 1;
                if self.stall_count >= MAX_CONSECUTIVE_STALLS {
                    log::warn!(
                        "USB mouse: GET_REPORT stalled {} times, disabling \
                         (device does not support HID class GET_REPORT)",
                        self.stall_count
                    );
                    self.get_report_disabled = true;
                }
            }
        }
    }
}

#[cfg(feature = "ui")]
impl crate::drivers::pointer::PointerDevice for UsbHidMouse {
    fn poll(&mut self) -> Option<crate::drivers::pointer::PointerReport> {
        super::with_controller(self.controller_idx, |controller| {
            UsbHidMouse::poll(self, controller)
        })?;
        Some(crate::drivers::pointer::PointerReport {
            dx: core::mem::take(&mut self.rel_x),
            dy: core::mem::take(&mut self.rel_y),
            dz: 0,
            buttons: self.buttons,
        })
    }
}

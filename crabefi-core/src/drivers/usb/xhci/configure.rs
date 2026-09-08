//! xHCI endpoint configuration by device class.

use super::super::controller::{ConfigurationInfo, UsbController};
use super::{TrbRing, XhciError};
use crate::barrier;
use crate::efi;
use xhci::context::EndpointType;
use xhci::ring::trb::command;

/// xHCI schedules in powers of two microframes. Never poll less frequently
/// than the LS/FS descriptor requests; HS/SS bInterval is already exponent + 1.
fn hid_interval(speed: u8, interval: u8) -> u8 {
    if speed >= 3 {
        interval.clamp(1, 16) - 1
    } else {
        ((interval.max(1) as u32 * 8).ilog2() as u8).max(3)
    }
}

#[cfg(test)]
mod tests {
    use super::hid_interval;

    #[test]
    fn interrupt_intervals_respect_usb_periods() {
        assert_eq!(hid_interval(1, 1), 3);
        assert_eq!(hid_interval(2, 10), 6); // 8 ms, not 16 ms
        assert_eq!(hid_interval(1, 255), 10);
        assert_eq!(hid_interval(3, 1), 0);
        assert_eq!(hid_interval(3, 4), 3);
        assert_eq!(hid_interval(4, 16), 15);
    }
}

impl super::XhciController {
    /// Fetch and parse the full configuration descriptor for a device
    pub(super) fn get_config_descriptor(
        &mut self,
        slot_id: u8,
    ) -> Result<ConfigurationInfo, XhciError> {
        self.read_configuration(slot_id).map_err(|error| {
            log::warn!(
                "xHCI: configuration descriptor for slot {}: {:?}",
                slot_id,
                error
            );
            XhciError::UsbError
        })
    }

    /// Configure a mass storage device
    ///
    /// Uses the shared parse_configuration() infrastructure from controller.rs
    pub(super) fn configure_mass_storage(&mut self, slot_id: u8) -> Result<(), XhciError> {
        let config_info = self.get_config_descriptor(slot_id)?;

        // Find mass storage interface
        let mut bulk_in = 0u8;
        let mut bulk_out = 0u8;
        let mut bulk_in_max_packet = 0u16;
        let mut bulk_out_max_packet = 0u16;
        let mut ms_interface_number = 0u8;
        let mut found = false;

        for iface in &config_info.interfaces[..config_info.num_interfaces] {
            if iface.is_mass_storage() {
                log::info!(
                    "  Found USB Mass Storage interface {}",
                    iface.interface_number
                );
                ms_interface_number = iface.interface_number;

                if let Some(ep) = iface.find_bulk_in() {
                    bulk_in = ep.number;
                    bulk_in_max_packet = ep.max_packet_size;
                    log::debug!(
                        "    Bulk IN EP: {} max_packet: {}",
                        bulk_in,
                        bulk_in_max_packet
                    );
                }
                if let Some(ep) = iface.find_bulk_out() {
                    bulk_out = ep.number;
                    bulk_out_max_packet = ep.max_packet_size;
                    log::debug!(
                        "    Bulk OUT EP: {} max_packet: {}",
                        bulk_out,
                        ep.max_packet_size
                    );
                }
                found = true;
                break;
            }
        }

        if !found || bulk_in == 0 || bulk_out == 0 {
            return Err(XhciError::DeviceNotFound);
        }

        // Set configuration
        self.set_configuration(slot_id, config_info.configuration_value)?;

        // Configure endpoints
        self.configure_bulk_endpoints(
            slot_id,
            bulk_in,
            bulk_out,
            bulk_in_max_packet,
            bulk_out_max_packet,
        )?;

        // Update slot info
        if let Some(slot) = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
        {
            slot.is_mass_storage = true;
            slot.mass_storage_interface = ms_interface_number;
            slot.bulk_in_ep = bulk_in;
            slot.bulk_out_ep = bulk_out;
            slot.bulk_in_max_packet = bulk_in_max_packet;
            slot.bulk_out_max_packet = bulk_out_max_packet;
        }

        log::info!("USB Mass Storage device configured on slot {}", slot_id);
        Ok(())
    }

    /// Configure a HID keyboard device
    ///
    /// Uses the shared parse_configuration() infrastructure from controller.rs
    pub(super) fn configure_hid_keyboard(&mut self, slot_id: u8) -> Result<(), XhciError> {
        let config_info = self.get_config_descriptor(slot_id)?;

        // Find HID keyboard interface
        let mut interrupt_in = 0u8;
        let mut interrupt_max_packet = 0u16;
        let mut interrupt_interval = 0u8;
        let mut found = false;

        for iface in &config_info.interfaces[..config_info.num_interfaces] {
            if iface.is_hid_keyboard() {
                log::info!(
                    "  Found USB HID Keyboard interface {}",
                    iface.interface_number
                );

                if let Some(ep) = iface.find_interrupt_in() {
                    interrupt_in = ep.number;
                    interrupt_max_packet = ep.max_packet_size;
                    interrupt_interval = ep.interval;
                    log::debug!(
                        "    Interrupt IN EP: {} max_packet: {} interval: {}",
                        interrupt_in,
                        interrupt_max_packet,
                        interrupt_interval
                    );
                }
                found = true;
                break;
            }
        }

        if !found || interrupt_in == 0 {
            return Err(XhciError::DeviceNotFound);
        }

        // Do not reset another function's already-configured endpoints.
        let already_configured = self
            .slots
            .get(slot_id as usize)
            .and_then(Option::as_ref)
            .is_some_and(|slot| slot.is_mass_storage || slot.is_hid_mouse);
        if !already_configured {
            self.set_configuration(slot_id, config_info.configuration_value)?;
        }

        self.configure_hid_interrupt_endpoint(
            slot_id,
            interrupt_in,
            interrupt_max_packet,
            interrupt_interval,
        )?;

        // Update slot info after configuring the interrupt pipe.
        if let Some(slot) = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
        {
            slot.is_hid_keyboard = true;
            slot.interrupt_in_ep = interrupt_in;
            slot.interrupt_max_packet = interrupt_max_packet;
            slot.interrupt_interval = interrupt_interval;
        }

        log::info!("USB HID Keyboard configured on slot {}", slot_id);
        Ok(())
    }

    /// Configure a HID mouse device.
    ///
    /// Configure the interrupt pipe, shared with HID keyboards.
    pub(super) fn configure_hid_mouse(&mut self, slot_id: u8) -> Result<(), XhciError> {
        let config_info = self.get_config_descriptor(slot_id)?;

        let mut interrupt_in = 0u8;
        let mut interrupt_max_packet = 0u16;
        let mut interrupt_interval = 0u8;
        let mut found = false;

        for iface in &config_info.interfaces[..config_info.num_interfaces] {
            if iface.is_hid_mouse() {
                log::info!("  Found USB HID Mouse interface {}", iface.interface_number);

                if let Some(ep) = iface.find_interrupt_in() {
                    interrupt_in = ep.number;
                    interrupt_max_packet = ep.max_packet_size;
                    interrupt_interval = ep.interval;
                }
                found = true;
                break;
            }
        }

        if !found || interrupt_in == 0 {
            return Err(XhciError::DeviceNotFound);
        }

        // Set configuration (only if not already set by keyboard config)
        let already_configured = self
            .slots
            .get(slot_id as usize)
            .and_then(|s| s.as_ref())
            .map(|s| s.is_hid_keyboard || s.is_mass_storage)
            .unwrap_or(false);

        if !already_configured {
            self.set_configuration(slot_id, config_info.configuration_value)?;
        }

        self.configure_hid_interrupt_endpoint(
            slot_id,
            interrupt_in,
            interrupt_max_packet,
            interrupt_interval,
        )?;
        if let Some(slot) = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(Option::as_mut)
        {
            slot.is_hid_mouse = true;
            slot.mouse_interrupt_in_ep = interrupt_in;
            slot.mouse_interrupt_max_packet = interrupt_max_packet;
            slot.mouse_interrupt_interval = interrupt_interval;
        }
        Ok(())
    }

    fn configure_hid_interrupt_endpoint(
        &mut self,
        slot_id: u8,
        interrupt_in: u8,
        interrupt_max_packet: u16,
        interrupt_interval: u8,
    ) -> Result<(), XhciError> {
        if interrupt_in == 0 || interrupt_in > 15 || interrupt_max_packet == 0 {
            return Err(XhciError::InvalidParameter);
        }
        // ── Configure the interrupt IN endpoint on the xHC ──
        //
        // Allocate a transfer ring and tell the controller about the endpoint
        // via Configure Endpoint.  This is required for interrupt IN transfers
        // (many mice stall GET_REPORT so we must use the interrupt pipe).
        let in_dci = (interrupt_in as usize * 2) + 1; // Interrupt IN → odd DCI

        let ring_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        let ring_addr = ring_mem.as_ptr() as u64;
        let ring = TrbRing::new(ring_addr, 256);
        let context_size = self.context_size;

        {
            let slot = self
                .slots
                .get_mut(slot_id as usize)
                .and_then(|s| s.as_mut())
                .ok_or(XhciError::DeviceNotFound)?;

            slot.transfer_rings[in_dci - 1] = Some(ring);

            // Set up input context for Configure Endpoint
            let input = slot.input_context;
            unsafe {
                core::ptr::write_bytes(input, 0, Self::input_context_len(context_size));
            }
            Self::copy_device_slot_context(input, slot.device_context, context_size);
            let slot_ctx = Self::input_slot_context(input, context_size);
            // Adding a second HID function must not hide a higher existing DCI.
            slot_ctx.set_context_entries(slot_ctx.context_entries().max(in_dci as u8));
            let control = Self::input_control_context(input, context_size);
            control.set_add_context_flag(0);
            control.set_add_context_flag(in_dci);

            // Interrupt IN endpoint context (EP Type 7)
            // Convert bInterval to xHCI interval exponent:
            //   For LS/FS: period = 2^(Interval) * 125µs, bInterval is in ms
            //   Use Interval such that 2^Interval ≈ bInterval * 8
            //   For HS: bInterval already is exponent+1
            let xhci_interval = hid_interval(slot.speed, interrupt_interval);
            let max_packet = interrupt_max_packet & 0x7ff;
            let max_burst = if slot.speed == 3 {
                ((interrupt_max_packet >> 11) & 3) as u8
            } else {
                0
            };
            if max_packet == 0 || max_burst == 3 {
                return Err(XhciError::InvalidParameter);
            }
            let payload = max_packet * (max_burst as u16 + 1);

            let ep_ctx = Self::input_ep_context(input, context_size, in_dci - 1);
            ep_ctx.set_endpoint_type(EndpointType::InterruptIn);
            ep_ctx.set_max_packet_size(max_packet);
            ep_ctx.set_max_burst_size(max_burst);
            ep_ctx.set_error_count(3);
            ep_ctx.set_tr_dequeue_pointer(ring_addr);
            ep_ctx.set_dequeue_cycle_state();
            ep_ctx.set_average_trb_length(max_packet);
            ep_ctx.set_max_endpoint_service_time_interval_payload_low(payload);
            ep_ctx.set_interval(xhci_interval);
        }

        // Issue Configure Endpoint command
        let input_ctx_ptr = self
            .slots
            .get(slot_id as usize)
            .and_then(|s| s.as_ref())
            .ok_or(XhciError::DeviceNotFound)?
            .input_context as u64;

        let mut command = command::ConfigureEndpoint::new();
        command
            .set_input_context_pointer(input_ctx_ptr)
            .set_slot_id(slot_id);

        self.cmd_ring.enqueue(command, false);
        barrier::mmio_write();
        self.ring_doorbell(0, 0);
        self.wait_command_completion()?;

        log::info!(
            "USB HID interrupt pipe configured on slot {}, EP {} (DCI {})",
            slot_id,
            interrupt_in,
            in_dci
        );
        Ok(())
    }
}

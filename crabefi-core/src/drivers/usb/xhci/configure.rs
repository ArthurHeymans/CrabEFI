//! xHCI endpoint configuration by device class.

use super::super::controller::{
    ConfigurationInfo, desc_type, parse_configuration, req_type, request,
};
use super::{TrbRing, XhciError};
use crate::barrier;
use crate::efi;
use xhci::context::EndpointType;
use xhci::ring::trb::command;

impl super::XhciController {
    /// Fetch and parse the full configuration descriptor for a device
    pub(super) fn get_config_descriptor(
        &mut self,
        slot_id: u8,
    ) -> Result<ConfigurationInfo, XhciError> {
        let mut config_buf = [0u8; 256];

        // First get just the header to learn total length
        let mut header = [0u8; 9];
        self.control_transfer(
            slot_id,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::CONFIGURATION as u16) << 8,
            0,
            Some(&mut header),
        )?;

        let total_len = u16::from_le_bytes([header[2], header[3]]) as usize;
        let total_len = total_len.min(config_buf.len());

        // Get full configuration
        self.control_transfer(
            slot_id,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::CONFIGURATION as u16) << 8,
            0,
            Some(&mut config_buf[..total_len]),
        )?;

        Ok(parse_configuration(&config_buf[..total_len]))
    }

    /// Configure a mass storage device
    ///
    /// Uses the shared parse_configuration() infrastructure from controller.rs
    pub(super) fn configure_mass_storage(&mut self, slot_id: u8) -> Result<(), XhciError> {
        let config_info = self.get_config_descriptor(slot_id)?;

        // Find mass storage interface
        let mut bulk_in = 0u8;
        let mut bulk_out = 0u8;
        let mut bulk_max_packet = 0u16;
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
                    bulk_max_packet = ep.max_packet_size;
                    log::debug!(
                        "    Bulk IN EP: {} max_packet: {}",
                        bulk_in,
                        bulk_max_packet
                    );
                }
                if let Some(ep) = iface.find_bulk_out() {
                    bulk_out = ep.number;
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
        self.configure_bulk_endpoints(slot_id, bulk_in, bulk_out, bulk_max_packet)?;

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
            slot.bulk_max_packet = bulk_max_packet;
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

        // Set configuration
        self.set_configuration(slot_id, config_info.configuration_value)?;

        // Update slot info (but don't configure endpoint - we use control transfers for HID)
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
    /// Unlike the keyboard (which may get away with GET_REPORT on some
    /// hardware), USB mice almost universally require interrupt IN transfers.
    /// We configure the interrupt endpoint with a transfer ring here so that
    /// `interrupt_transfer()` can queue Normal TRBs on it later.
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

            slot.is_hid_mouse = true;
            slot.mouse_interrupt_in_ep = interrupt_in;
            slot.mouse_interrupt_max_packet = interrupt_max_packet;
            slot.mouse_interrupt_interval = interrupt_interval;
            slot.transfer_rings[in_dci - 1] = Some(ring);

            // Set up input context for Configure Endpoint
            let input = slot.input_context;
            unsafe {
                core::ptr::write_bytes(input, 0, Self::input_context_len(context_size));
            }
            Self::copy_device_slot_context(input, slot.device_context, context_size);
            let slot_ctx = Self::input_slot_context(input, context_size);
            slot_ctx.set_context_entries(in_dci as u8);
            let control = Self::input_control_context(input, context_size);
            control.set_add_context_flag(0);
            control.set_add_context_flag(in_dci);

            // Interrupt IN endpoint context (EP Type 7)
            // Convert bInterval to xHCI interval exponent:
            //   For LS/FS: period = 2^(Interval) * 125µs, bInterval is in ms
            //   Use Interval such that 2^Interval ≈ bInterval * 8
            //   For HS: bInterval already is exponent+1
            let speed = slot.speed;
            let xhci_interval = if speed >= 3 {
                // High/Super speed: bInterval is already exponent form
                interrupt_interval.max(1)
            } else {
                // Low/Full speed: bInterval in ms, convert to 125µs exponent
                // 2^N * 125µs ≈ bInterval * 1000µs → N ≈ log2(bInterval*8)
                let frames = (interrupt_interval as u32).max(1) * 8;
                let mut n = 0u8;
                let mut v = 1u32;
                while v < frames && n < 15 {
                    n += 1;
                    v <<= 1;
                }
                n.max(3) // At least 1ms (2^3 * 125µs)
            };

            let ep_ctx = Self::input_ep_context(input, context_size, in_dci - 1);
            ep_ctx.set_endpoint_type(EndpointType::InterruptIn);
            ep_ctx.set_max_packet_size(interrupt_max_packet);
            ep_ctx.set_max_burst_size(0);
            ep_ctx.set_error_count(3);
            ep_ctx.set_tr_dequeue_pointer(ring_addr);
            ep_ctx.set_dequeue_cycle_state();
            ep_ctx.set_average_trb_length(interrupt_max_packet);
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
            "USB HID Mouse configured on slot {}, interrupt EP {} (DCI {})",
            slot_id,
            interrupt_in,
            in_dci
        );
        Ok(())
    }
}

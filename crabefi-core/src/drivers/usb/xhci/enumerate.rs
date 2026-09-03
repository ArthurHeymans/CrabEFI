//! xHCI port enumeration and hubs.

use super::super::controller::{
    DeviceDescriptor, HUB_DESCRIPTOR_TYPE, hub_feature, hub_port_status, req_type, request,
};
use super::{TrbRing, UsbSlot, XhciError};
use crate::barrier;
use crate::efi;
use crate::time::Timeout;
use xhci::context::EndpointType;
use xhci::ring::trb::command;

impl super::XhciController {
    /// Configure a hub device and enumerate its downstream ports.
    ///
    /// This mirrors the EHCI `enumerate_hub()` logic adapted for xHCI's
    /// route-string-based addressing model.
    pub(super) fn configure_and_enumerate_hub(
        &mut self,
        hub_slot_id: u8,
        root_port: u8,
    ) -> Result<(), XhciError> {
        // Get config descriptor to find hub interface and SET_CONFIGURATION
        let config_info = self.get_config_descriptor(hub_slot_id)?;

        // Verify this is actually a hub
        let has_hub_iface = config_info.interfaces[..config_info.num_interfaces]
            .iter()
            .any(|i| i.interface_class == 0x09);
        let is_hub_class = self
            .slots
            .get(hub_slot_id as usize)
            .and_then(|s| s.as_ref())
            .map(|s| s.device_desc.device_class == 0x09)
            .unwrap_or(false);

        if !is_hub_class && !has_hub_iface {
            return Err(XhciError::DeviceNotFound);
        }

        // Set configuration (activates hub endpoints)
        if config_info.configuration_value > 0 {
            self.set_configuration(hub_slot_id, config_info.configuration_value)?;
        }

        // Get hub descriptor
        let mut hub_desc_buf = [0u8; 12];
        self.control_transfer(
            hub_slot_id,
            req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (HUB_DESCRIPTOR_TYPE as u16) << 8,
            0,
            Some(&mut hub_desc_buf),
        )?;

        let num_ports = hub_desc_buf[2];
        let power_delay = (hub_desc_buf[5] as u64) * 2; // PwrOn2PwrGood in 2ms units

        if num_ports == 0 || num_ports > 15 {
            log::debug!("Hub has {} ports, skipping", num_ports);
            return Ok(());
        }

        log::info!(
            "xHCI: Hub slot {} has {} ports, power delay {}ms",
            hub_slot_id,
            num_ports,
            power_delay
        );

        // Mark slot as hub and store route info
        if let Some(slot) = self
            .slots
            .get_mut(hub_slot_id as usize)
            .and_then(|s| s.as_mut())
        {
            slot.is_hub = true;
            slot.hub_ports = num_ports;
        }

        // Update the hub's slot context via Evaluate Context so xHC knows
        // this device is a hub (required for proper downstream routing).
        self.evaluate_hub_context(hub_slot_id, num_ports)?;

        // Power on all hub ports
        for p in 1..=num_ports {
            let _ = self.control_transfer(
                hub_slot_id,
                req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                request::SET_FEATURE,
                hub_feature::PORT_POWER,
                p as u16,
                None,
            );
        }

        crate::time::delay_ms(power_delay.max(100));

        // Check each port for connected devices
        for p in 1..=num_ports {
            let mut status_buf = [0u8; 4];
            if self
                .control_transfer(
                    hub_slot_id,
                    req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                    request::GET_STATUS,
                    0,
                    p as u16,
                    Some(&mut status_buf),
                )
                .is_err()
            {
                continue;
            }

            let port_status = u16::from_le_bytes([status_buf[0], status_buf[1]]);
            if (port_status & hub_port_status::CONNECTION) == 0 {
                continue;
            }

            log::info!("xHCI: Device on hub slot {} port {}", hub_slot_id, p);

            // Clear connection change
            let _ = self.control_transfer(
                hub_slot_id,
                req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                request::CLEAR_FEATURE,
                hub_feature::C_PORT_CONNECTION,
                p as u16,
                None,
            );

            // Reset the port
            let _ = self.control_transfer(
                hub_slot_id,
                req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                request::SET_FEATURE,
                hub_feature::PORT_RESET,
                p as u16,
                None,
            );

            crate::time::delay_ms(60);

            // Poll for reset completion
            let timeout = crate::time::Timeout::from_ms(500);
            let mut speed = 0u8;
            let mut reset_ok = false;
            while !timeout.is_expired() {
                let mut sb = [0u8; 4];
                if self
                    .control_transfer(
                        hub_slot_id,
                        req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                        request::GET_STATUS,
                        0,
                        p as u16,
                        Some(&mut sb),
                    )
                    .is_err()
                {
                    break;
                }
                let ps = u16::from_le_bytes([sb[0], sb[1]]);
                let pc = u16::from_le_bytes([sb[2], sb[3]]);

                if pc & 0x10 != 0 {
                    // C_PORT_RESET
                    let _ = self.control_transfer(
                        hub_slot_id,
                        req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                        request::CLEAR_FEATURE,
                        hub_feature::C_PORT_RESET,
                        p as u16,
                        None,
                    );
                    if ps & hub_port_status::ENABLE != 0 {
                        speed = if ps & hub_port_status::HIGH_SPEED != 0 {
                            3
                        } else if ps & hub_port_status::LOW_SPEED != 0 {
                            2
                        } else {
                            1
                        };
                        reset_ok = true;
                    }
                    break;
                }
                crate::time::delay_ms(10);
            }

            if !reset_ok {
                log::debug!("Hub port {} reset failed", p);
                continue;
            }

            crate::time::delay_ms(10);

            // Build route string: parent's route | (port << (4 * tier))
            let parent_route = self
                .slots
                .get(hub_slot_id as usize)
                .and_then(|s| s.as_ref())
                .map(|s| s.route_string)
                .unwrap_or(0);
            // Find which nibble is the first zero (that's our tier)
            let mut route = parent_route;
            for tier in 0..5u32 {
                if (route >> (tier * 4)) & 0xF == 0 {
                    route |= (p as u32 & 0xF) << (tier * 4);
                    break;
                }
            }

            // Enable slot and address the downstream device
            if let Err(e) = self.attach_device_on_hub(hub_slot_id, p, speed, route, root_port) {
                log::warn!("Failed to attach device on hub port {}: {:?}", p, e);
            }
        }

        Ok(())
    }

    /// Issue an Evaluate Context command to inform the xHC that a device
    /// is a hub (sets Hub flag and NumberOfPorts in the slot context).
    pub(super) fn evaluate_hub_context(
        &mut self,
        slot_id: u8,
        num_ports: u8,
    ) -> Result<(), XhciError> {
        let slot = self
            .slots
            .get(slot_id as usize)
            .and_then(|s| s.as_ref())
            .ok_or(XhciError::DeviceNotFound)?;

        let input_ctx = slot.input_context;
        unsafe {
            core::ptr::write_bytes(input_ctx, 0, Self::input_context_len(self.context_size));
        }
        let control_ctx = Self::input_control_context(input_ctx, self.context_size);
        control_ctx.set_add_context_flag(0);
        Self::copy_device_slot_context(input_ctx, slot.device_context, self.context_size);
        let slot_ctx = Self::input_slot_context(input_ctx, self.context_size);
        slot_ctx.set_hub();
        slot_ctx.set_number_of_ports(num_ports);
        // Context entries must cover at least slot + EP0
        slot_ctx.set_context_entries(1);

        let mut command = command::EvaluateContext::new();
        command
            .set_input_context_pointer(slot.input_context as u64)
            .set_slot_id(slot_id);

        self.cmd_ring.enqueue(command, false);
        barrier::mmio_write();
        self.ring_doorbell(0, 0);

        self.wait_command_completion()?;
        Ok(())
    }

    /// Attach a device that is behind a USB hub.
    pub(super) fn attach_device_on_hub(
        &mut self,
        hub_slot_id: u8,
        hub_port: u8,
        speed: u8,
        route_string: u32,
        root_port: u8,
    ) -> Result<(), XhciError> {
        let slot_id = self.enable_slot()?;

        // Allocate device context
        let device_context_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        device_context_mem.fill(0);
        let device_context = device_context_mem.as_ptr() as u64;

        // Allocate input context
        let input_context_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        input_context_mem.fill(0);
        let input_context = input_context_mem.as_ptr() as u64;

        // Allocate transfer ring for control endpoint
        let transfer_ring_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        let transfer_ring = transfer_ring_mem.as_ptr() as u64;

        let input_ptr = input_context as *mut u8;
        let control = Self::input_control_context(input_ptr, self.context_size);
        control.set_add_context_flag(0);
        control.set_add_context_flag(1);

        // Slot context with hub topology info
        let slot_ctx = Self::input_slot_context(input_ptr, self.context_size);
        slot_ctx.set_context_entries(1);
        slot_ctx.set_speed(speed);
        slot_ctx.set_root_hub_port_number(root_port + 1);
        slot_ctx.set_route_string(route_string);
        slot_ctx.set_parent_hub_slot_id(hub_slot_id);
        slot_ctx.set_parent_port_number(hub_port);

        // Control endpoint
        let max_packet = match speed {
            1 => 64, // Full speed: updated from bMaxPacketSize0 before longer transfers
            2 => 8,
            3 => 64,
            4 => 512,
            _ => 8,
        };

        let ep0_ctx = Self::input_ep_context(input_ptr, self.context_size, 0);
        ep0_ctx.set_endpoint_type(EndpointType::Control);
        ep0_ctx.set_max_packet_size(max_packet);
        ep0_ctx.set_max_burst_size(0);
        ep0_ctx.set_error_count(3);
        ep0_ctx.set_tr_dequeue_pointer(transfer_ring);
        ep0_ctx.set_dequeue_cycle_state();
        ep0_ctx.set_average_trb_length(8);

        let ring = TrbRing::new(transfer_ring, 256);

        // DCBAA
        let dcbaa_entry = unsafe { &mut *((self.dcbaa + (slot_id as u64 * 8)) as *mut u64) };
        *dcbaa_entry = device_context;

        // Address Device command
        let mut command = command::AddressDevice::new();
        command
            .set_input_context_pointer(input_context)
            .set_slot_id(slot_id);

        self.cmd_ring.enqueue(command, false);
        barrier::mmio_write();
        self.ring_doorbell(0, 0);
        self.wait_command_completion()?;
        crate::time::delay_ms(2);

        // Store slot info
        let mut transfer_rings: [Option<TrbRing>; 31] = core::array::from_fn(|_| None);
        transfer_rings[0] = Some(ring);

        let slot_entry = self
            .slots
            .get_mut(slot_id as usize)
            .ok_or(XhciError::NoFreeSlots)?;
        *slot_entry = Some(UsbSlot {
            slot_id,
            device_context: device_context as *mut u8,
            input_context: input_context as *mut u8,
            transfer_rings,
            device_desc: DeviceDescriptor::default(),
            port: hub_port,
            speed,
            is_mass_storage: false,
            mass_storage_interface: 0,
            bulk_in_ep: 0,
            bulk_out_ep: 0,
            bulk_max_packet: 0,
            is_hid_keyboard: false,
            is_hid_mouse: false,
            interrupt_in_ep: 0,
            mouse_interrupt_in_ep: 0,
            mouse_interrupt_max_packet: 0,
            mouse_interrupt_interval: 0,
            interrupt_max_packet: 0,
            interrupt_interval: 0,
            is_hub: false,
            hub_ports: 0,
            route_string,
            root_port,
        });

        // Now enumerate the device (get descriptor, configure, etc.)
        match self.get_device_descriptor(slot_id) {
            Ok(desc) => {
                let vid = desc.vendor_id;
                let pid = desc.product_id;
                let class = desc.device_class;
                let num_configs = desc.num_configurations;
                log::info!(
                    "  Hub port device: VID={:04x} PID={:04x} Class={:02x}",
                    vid,
                    pid,
                    class
                );

                if let Some(slot) = self
                    .slots
                    .get_mut(slot_id as usize)
                    .and_then(|s| s.as_mut())
                {
                    slot.device_desc = desc;
                }

                // Configure as storage / keyboard / mouse
                if class == 0x08 || (class == 0x00 && num_configs > 0) {
                    let _ = self.configure_mass_storage(slot_id);
                }
                if class == 0x03 || (class == 0x00 && num_configs > 0) {
                    let _ = self.configure_hid_keyboard(slot_id);
                    let _ = self.configure_hid_mouse(slot_id);
                }

                // Nested hub support (one level deep to keep it simple)
                if class == 0x09
                    && let Err(e) = self.configure_and_enumerate_hub(slot_id, root_port)
                {
                    log::debug!("Nested hub enum failed: {:?}", e);
                }
            }
            Err(e) => {
                log::warn!("Failed to get descriptor for hub device: {:?}", e);
            }
        }

        Ok(())
    }

    /// Enumerate ports and attach devices
    pub(super) fn enumerate_ports(&mut self) -> Result<(), XhciError> {
        for port in 0..self.num_ports {
            if !self.portsc(port).current_connect_status() {
                continue;
            }

            let mut stable_count = 0;
            for _ in 0..5 {
                if self.portsc(port).current_connect_status() {
                    stable_count += 1;
                } else {
                    stable_count = 0;
                }
                crate::time::delay_ms(10);
            }
            if stable_count < 3 {
                continue;
            }

            let status = self.portsc(port);
            let speed = status.port_speed();
            let link_state = status.port_link_state();
            let speed_name = match speed {
                1 => "Full",
                2 => "Low",
                3 => "High",
                4 => "Super",
                _ => "Unknown",
            };
            let link_name = match link_state {
                0 => "U0",
                5 => "RxDetect",
                7 => "Polling",
                _ => "Other",
            };
            log::info!(
                "USB device on port {}: {} speed, PLS={}",
                port,
                speed_name,
                link_name
            );

            if link_state == 5 {
                log::debug!("Port {}: RxDetect state (phantom device), skipping", port);
                continue;
            }

            self.clear_port_changes(port);

            let status = self.portsc(port);
            let is_usb3 = speed == 4;
            if is_usb3 && status.port_enabled_disabled() && status.port_link_state() == 0 {
                log::debug!("Port {}: USB3 device already in U0, skipping reset", port);
            } else if is_usb3 && status.port_link_state() == 7 {
                log::debug!("Port {}: USB3 device in Polling, waiting for link", port);
                let timeout = Timeout::from_ms(200);
                let mut link_up = false;
                while !timeout.is_expired() {
                    let status = self.portsc(port);
                    if status.port_link_state() == 0 && status.port_enabled_disabled() {
                        link_up = true;
                        break;
                    }
                    crate::time::delay_ms(1);
                }
                if !link_up {
                    log::debug!(
                        "Port {}: USB3 link training failed (PLS={}), skipping",
                        port,
                        self.portsc(port).port_link_state()
                    );
                    continue;
                }
            } else if !status.port_enabled_disabled() {
                self.update_portsc(port, |portsc| {
                    portsc.set_port_reset();
                });

                let timeout = Timeout::from_ms(150);
                while !timeout.is_expired() {
                    if self.portsc(port).port_reset_change() {
                        self.update_portsc(port, |portsc| {
                            portsc.clear_port_reset_change();
                        });
                        break;
                    }
                    crate::time::delay_ms(1);
                }

                if self.portsc(port).port_link_state() != 0 {
                    if is_usb3 {
                        log::debug!(
                            "Port {}: USB3 normal reset failed (PLS={}), trying warm reset",
                            port,
                            self.portsc(port).port_link_state()
                        );
                        self.update_portsc(port, |portsc| {
                            portsc.set_warm_port_reset();
                        });

                        let timeout = Timeout::from_ms(200);
                        while !timeout.is_expired() {
                            if self.portsc(port).warm_port_reset_change() {
                                self.update_portsc(port, |portsc| {
                                    portsc.clear_warm_port_reset_change();
                                });
                                break;
                            }
                            crate::time::delay_ms(1);
                        }

                        if self.portsc(port).port_link_state() != 0 {
                            log::debug!(
                                "Port {}: link not up after warm reset (PLS={}), skipping",
                                port,
                                self.portsc(port).port_link_state()
                            );
                            continue;
                        }
                        log::debug!("Port {}: warm reset successful", port);
                    } else {
                        log::debug!(
                            "Port {}: link not up after reset (PLS={}), skipping",
                            port,
                            self.portsc(port).port_link_state()
                        );
                        continue;
                    }
                }
            }

            // Enable slot and address device
            match self.enable_slot() {
                Ok(slot_id) => {
                    log::debug!("Enabled slot {}", slot_id);

                    if let Err(e) = self.address_device(slot_id, port, speed) {
                        log::error!("Failed to address device on port {}: {:?}", port, e);
                        continue;
                    }

                    // Get device descriptor
                    match self.get_device_descriptor(slot_id) {
                        Ok(desc) => {
                            // Copy fields to avoid alignment issues
                            let vid = desc.vendor_id;
                            let pid = desc.product_id;
                            let class = desc.device_class;
                            let num_configs = desc.num_configurations;

                            log::info!("  VID={:04x} PID={:04x} Class={:02x}", vid, pid, class);

                            if let Some(slot) = self
                                .slots
                                .get_mut(slot_id as usize)
                                .and_then(|s| s.as_mut())
                            {
                                slot.device_desc = desc;
                            }

                            // Try to configure as mass storage (class 0x08)
                            if (class == 0x08 || (class == 0x00 && num_configs > 0))
                                && let Err(e) = self.configure_mass_storage(slot_id)
                            {
                                log::debug!("Not a mass storage device: {:?}", e);
                            }

                            // Try to configure as HID keyboard (class 0x03 or class 0x00)
                            if (class == 0x03 || (class == 0x00 && num_configs > 0))
                                && let Err(e) = self.configure_hid_keyboard(slot_id)
                            {
                                log::debug!("Not a HID keyboard: {:?}", e);
                            }

                            // Try to configure as HID mouse (class 0x03 or class 0x00)
                            if (class == 0x03 || (class == 0x00 && num_configs > 0))
                                && let Err(e) = self.configure_hid_mouse(slot_id)
                            {
                                log::debug!("Not a HID mouse: {:?}", e);
                            }

                            // If it's a hub, enumerate its downstream ports
                            if (class == 0x09 || (class == 0x00 && num_configs > 0))
                                && let Err(e) = self.configure_and_enumerate_hub(slot_id, port)
                            {
                                log::debug!("Not a hub or hub enum failed: {:?}", e);
                            }
                        }
                        Err(e) => {
                            log::error!("Failed to get device descriptor: {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    log::error!("Failed to enable slot for port {}: {:?}", port, e);
                }
            }
        }

        Ok(())
    }
}

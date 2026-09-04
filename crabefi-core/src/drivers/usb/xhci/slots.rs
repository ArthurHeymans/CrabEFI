//! xHCI device slots and addressing.

use super::super::controller::DeviceDescriptor;
use super::{TrbRing, XhciError};
use crate::barrier;
use crate::efi;
use xhci::context::EndpointType;
use xhci::ring::trb::command;

/// USB device slot
pub struct UsbSlot {
    /// Slot ID
    pub slot_id: u8,
    /// Device context
    pub device_context: *mut u8,
    /// Input context
    pub input_context: *mut u8,
    /// Transfer rings for each endpoint (0 = control, 1-30 = other)
    pub transfer_rings: [Option<TrbRing>; 31],
    /// Device descriptor
    pub device_desc: DeviceDescriptor,
    /// Port number
    pub port: u8,
    /// Speed
    pub speed: u8,
    /// Is this a mass storage device?
    pub is_mass_storage: bool,
    /// Mass storage interface number (for BOT reset recovery)
    pub mass_storage_interface: u8,
    /// Bulk IN endpoint
    pub bulk_in_ep: u8,
    /// Bulk OUT endpoint
    pub bulk_out_ep: u8,
    /// Max packet size for bulk endpoints
    pub bulk_max_packet: u16,
    /// Is this a HID keyboard device?
    pub is_hid_keyboard: bool,
    /// Is this a HID mouse device?
    pub is_hid_mouse: bool,
    /// Interrupt IN endpoint for HID keyboard
    pub interrupt_in_ep: u8,
    /// Mouse interrupt IN endpoint
    pub mouse_interrupt_in_ep: u8,
    /// Max packet size for mouse interrupt endpoint
    pub mouse_interrupt_max_packet: u16,
    /// Polling interval for mouse interrupt endpoint (in ms)
    pub mouse_interrupt_interval: u8,
    /// Max packet size for interrupt endpoint
    pub interrupt_max_packet: u16,
    /// Polling interval for interrupt endpoint (in ms)
    pub interrupt_interval: u8,
    /// Is this a hub?
    pub is_hub: bool,
    /// Number of downstream ports (if hub)
    pub hub_ports: u8,
    /// Route string for this device (xHCI hub topology)
    pub route_string: u32,
    /// Root hub port this device chain starts from
    pub root_port: u8,
}

impl super::XhciController {
    /// Reset an endpoint after a stall or other error
    ///
    /// This sends a Reset Endpoint command followed by a Set TR Dequeue Pointer
    /// command to recover the endpoint and allow new transfers.
    ///
    /// Based on U-Boot's reset_ep() in xhci-ring.c and xHCI spec section 4.6.8.
    ///
    /// # Arguments
    /// * `slot_id` - The device slot ID
    /// * `dci` - The Device Context Index (endpoint index in xHCI terms)
    ///
    /// # Returns
    /// Ok(()) on success, Err on failure
    pub(super) fn reset_endpoint(&mut self, slot_id: u8, dci: u8) -> Result<(), XhciError> {
        log::debug!("xHCI: Resetting endpoint slot={} dci={}", slot_id, dci);

        // Step 1: Send Reset Endpoint command.
        let mut command = command::ResetEndpoint::new();
        command.set_slot_id(slot_id).set_endpoint_id(dci);

        self.cmd_ring.enqueue(command, false);
        barrier::mmio_write();
        self.ring_doorbell(0, 0);

        // Wait for Reset Endpoint completion
        match self.wait_command_completion() {
            Ok(_) => {
                log::debug!("xHCI: Reset Endpoint command completed");
            }
            Err(e) => {
                log::warn!("xHCI: Reset Endpoint command failed: {:?}", e);
                return Err(e);
            }
        }

        // Step 2: Send Set TR Dequeue Pointer command
        // This updates the endpoint's transfer ring dequeue pointer to match our enqueue pointer,
        // effectively discarding any pending TRBs and allowing new transfers.

        // Get the transfer ring for this endpoint
        let slot = self
            .slots
            .get(slot_id as usize)
            .and_then(|s| s.as_ref())
            .ok_or(XhciError::DeviceNotFound)?;

        let ring = slot.transfer_rings[dci as usize - 1]
            .as_ref()
            .ok_or(XhciError::DeviceNotFound)?;

        // The dequeue pointer should point to the current enqueue position
        // with the cycle bit set appropriately (bit 0 of the pointer)
        let dequeue_ptr = ring.base + (ring.enqueue_idx * 16) as u64;
        let dequeue_ptr_with_dcs = dequeue_ptr | if ring.cycle { 1 } else { 0 };

        let mut command = command::SetTrDequeuePointer::new();
        command
            .set_new_tr_dequeue_pointer(dequeue_ptr)
            .set_slot_id(slot_id)
            .set_endpoint_id(dci);
        if ring.cycle {
            command.set_dequeue_cycle_state();
        }

        self.cmd_ring.enqueue(command, false);
        barrier::mmio_write();
        self.ring_doorbell(0, 0);

        // Wait for Set TR Dequeue Pointer completion
        match self.wait_command_completion() {
            Ok(_) => {
                log::debug!(
                    "xHCI: Set TR Dequeue Pointer completed, new dequeue={:#x}",
                    dequeue_ptr_with_dcs
                );
            }
            Err(e) => {
                log::warn!("xHCI: Set TR Dequeue Pointer command failed: {:?}", e);
                return Err(e);
            }
        }

        Ok(())
    }

    /// Enable a slot
    pub(super) fn enable_slot(&mut self) -> Result<u8, XhciError> {
        let cmd_addr = self.cmd_ring.enqueue(command::EnableSlot::new(), false);
        log::debug!(
            "xHCI: Enable Slot TRB at {:#x}, cycle={}, CRCR={:?}",
            cmd_addr,
            self.cmd_ring.cycle,
            self.registers.operational.crcr.read_volatile()
        );

        barrier::mmio_write();
        self.ring_doorbell(0, 0); // Ring host controller doorbell

        // Check USBSTS after ringing doorbell
        let usbsts = self.registers.operational.usbsts.read_volatile();
        log::debug!("xHCI: USBSTS after doorbell: {:?}", usbsts);

        let completion = self.wait_command_completion()?;
        Ok(completion.slot_id())
    }

    /// Address a device
    pub(super) fn address_device(
        &mut self,
        slot_id: u8,
        port: u8,
        speed: u8,
    ) -> Result<(), XhciError> {
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

        // Set up input control context: add slot and EP0.
        let control = Self::input_control_context(input_ptr, self.context_size);
        control.set_add_context_flag(0);
        control.set_add_context_flag(1);

        // Set up slot context
        let slot_ctx = Self::input_slot_context(input_ptr, self.context_size);
        slot_ctx.set_context_entries(1);
        slot_ctx.set_speed(speed);
        slot_ctx.set_root_hub_port_number(port + 1);

        // Set up control endpoint context
        let max_packet = match speed {
            1 => 64,  // Full speed: updated from bMaxPacketSize0 before longer transfers
            2 => 8,   // Low speed
            3 => 64,  // High speed
            4 => 512, // Super speed
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

        // Set up transfer ring
        let ring = TrbRing::new(transfer_ring, 256);

        // Store in DCBAA
        let dcbaa_entry = unsafe { &mut *((self.dcbaa + (slot_id as u64 * 8)) as *mut u64) };
        *dcbaa_entry = device_context;

        // Build Address Device command
        let mut command = command::AddressDevice::new();
        command
            .set_input_context_pointer(input_context)
            .set_slot_id(slot_id);

        self.cmd_ring.enqueue(command, false);
        barrier::mmio_write();
        self.ring_doorbell(0, 0);

        self.wait_command_completion()?;

        // USB spec requires delay after SET_ADDRESS (xHCI's Address Device is equivalent)
        // U-Boot uses 10ms, libpayload uses 2ms. We use 2ms for speed.
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
            port,
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
            route_string: 0,
            root_port: port,
        });

        Ok(())
    }
}

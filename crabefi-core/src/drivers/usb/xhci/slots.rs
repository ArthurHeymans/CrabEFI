//! xHCI device slots and addressing.

use super::super::controller::DeviceDescriptor;
use super::{TrbRing, XhciError};
use crate::barrier;
use crate::efi;
use xhci::context::EndpointType;
use xhci::ring::trb::command;

/// Addressing information shared by root and downstream ports.
pub(super) struct SlotRoute {
    pub port: u8,
    pub root_port: u8,
    pub route_string: u32,
    pub parent_hub: Option<(u8, u8)>,
}

/// Unpublished slot pages. Partial allocations are safe to release until the
/// DCBAA/Address Device command exposes them to hardware.
#[derive(Default)]
struct SlotPages([u64; 3]);

impl Drop for SlotPages {
    fn drop(&mut self) {
        for address in self.0.into_iter().filter(|address| *address != 0) {
            let _ = efi::allocator::free_pages(address, 1);
        }
    }
}

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
    /// Descriptor max packet size for bulk IN.
    pub bulk_in_max_packet: u16,
    /// Descriptor max packet size for bulk OUT.
    pub bulk_out_max_packet: u16,
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

        self.discard_endpoint_transfers(slot_id, dci)
    }

    /// Skip pending TDs while the endpoint is stopped or halted.
    fn discard_endpoint_transfers(&mut self, slot_id: u8, dci: u8) -> Result<(), XhciError> {
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
        self.address_slot(
            slot_id,
            speed,
            SlotRoute {
                port,
                root_port: port,
                route_string: 0,
                parent_hub: None,
            },
        )
    }

    /// Address either a root or hub device, rolling back an enabled slot on error.
    pub(super) fn address_slot(
        &mut self,
        slot_id: u8,
        speed: u8,
        route: SlotRoute,
    ) -> Result<(), XhciError> {
        let result = self.prepare_address_slot(slot_id, speed, route);
        if result.is_err() && slot_id != 0 {
            let mut command = command::DisableSlot::new();
            command.set_slot_id(slot_id);
            self.cmd_ring.enqueue(command, false);
            barrier::mmio_write();
            self.ring_doorbell(0, 0);
            if self.wait_command_completion().is_ok() {
                // Only Disable Slot completion proves that a timed-out Address
                // Device can no longer access its input/device context or ring.
                if let Some(entry) = self.slots.get_mut(slot_id as usize)
                    && let Some(slot) = entry.take()
                {
                    // SAFETY: the slot index was checked before publication.
                    unsafe {
                        core::ptr::write_volatile((self.dcbaa as *mut u64).add(slot_id as usize), 0)
                    };
                    let _pages = SlotPages([
                        slot.device_context as u64,
                        slot.input_context as u64,
                        slot.transfer_rings[0].as_ref().map_or(0, |ring| ring.base),
                    ]);
                }
            } else {
                log::warn!("xHCI: retaining slot {} DMA after failed rollback", slot_id);
            }
        }
        result
    }

    fn prepare_address_slot(
        &mut self,
        slot_id: u8,
        speed: u8,
        route: SlotRoute,
    ) -> Result<(), XhciError> {
        // Slot IDs are 1-based indices into `slots` (index 0 is never
        // assigned). Reject anything outside the populated range before
        // allocating contexts or touching the DCBAA.
        if slot_id == 0 || slot_id as usize >= self.slots.len() {
            log::error!("xHCI: slot ID {} outside tracked range", slot_id);
            return Err(XhciError::InvalidParameter);
        }
        let mut pages = SlotPages::default();
        for address in &mut pages.0 {
            let memory = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
            memory.fill(0);
            *address = memory.as_ptr() as u64;
        }
        let [device_context, input_context, transfer_ring] = pages.0;

        let input_ptr = input_context as *mut u8;

        // Set up input control context: add slot and EP0.
        let control = Self::input_control_context(input_ptr, self.context_size);
        control.set_add_context_flag(0);
        control.set_add_context_flag(1);

        // Set up slot context
        let slot_ctx = Self::input_slot_context(input_ptr, self.context_size);
        slot_ctx.set_context_entries(1);
        slot_ctx.set_speed(speed);
        slot_ctx.set_root_hub_port_number(route.root_port + 1);
        slot_ctx.set_route_string(route.route_string);
        if let Some((hub_slot, hub_port)) = route.parent_hub {
            slot_ctx.set_parent_hub_slot_id(hub_slot);
            slot_ctx.set_parent_port_number(hub_port);
        }

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

        // Track ownership before exposing any pages to the controller.
        // Failed Address Device commands are rolled back by address_slot.
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
            port: route.port,
            speed,
            is_mass_storage: false,
            mass_storage_interface: 0,
            bulk_in_ep: 0,
            bulk_out_ep: 0,
            bulk_in_max_packet: 0,
            bulk_out_max_packet: 0,
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
            route_string: route.route_string,
            root_port: route.root_port,
        });
        core::mem::forget(pages);

        // SAFETY: the slot index is checked above and DCBAA is controller-owned.
        unsafe {
            core::ptr::write_volatile(
                (self.dcbaa as *mut u64).add(slot_id as usize),
                device_context,
            )
        };
        let mut command = command::AddressDevice::new();
        command
            .set_input_context_pointer(input_context)
            .set_slot_id(slot_id);
        self.cmd_ring.enqueue(command, false);
        barrier::mmio_write();
        self.ring_doorbell(0, 0);
        self.wait_command_completion()?;
        // SET_ADDRESS recovery interval (xHCI issues the USB request).
        crate::time::delay_ms(2);
        Ok(())
    }
}

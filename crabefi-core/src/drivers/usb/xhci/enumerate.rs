//! xHCI port enumeration and hubs.

use super::super::controller::{
    HUB_DESCRIPTOR_TYPE, hub_feature, hub_port_status, req_type, request,
};
use super::XhciError;
use super::speed::{BOS_DESCRIPTOR_TYPE, BosHeader, LinkSpeed, SublinkSpeeds};
use crate::barrier;
use crate::exec::{self, BoxFuture};
use crate::time::Timeout;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::RefCell;
use xhci::ring::trb::command;
use zerocopy::FromBytes;
use zerocopy::byteorder::{LittleEndian, U32};

const SUPER_SPEED_HUB_DESCRIPTOR_TYPE: u8 = 0x2a;
const SET_HUB_DEPTH: u8 = 0x0c;

fn hub_descriptor_type(is_superspeed: bool) -> u8 {
    if is_superspeed {
        SUPER_SPEED_HUB_DESCRIPTOR_TYPE
    } else {
        HUB_DESCRIPTOR_TYPE
    }
}

fn hub_depth(route: u32) -> u16 {
    (0..5)
        .take_while(|tier| (route >> (tier * 4)) & 0xf != 0)
        .count() as u16
}

fn usb2_downstream_speed(status: u16) -> u8 {
    if status & hub_port_status::HIGH_SPEED != 0 {
        3
    } else if status & hub_port_status::LOW_SPEED != 0 {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod hub_protocol_tests {
    use super::*;

    #[test]
    fn hub_protocol_and_depth_follow_the_xhci_slot() {
        assert_eq!(hub_descriptor_type(false), 0x29);
        assert_eq!(hub_descriptor_type(true), 0x2a);
        assert_eq!(hub_depth(0), 0);
        assert_eq!(hub_depth(2), 1);
        assert_eq!(hub_depth(0x321), 3);
    }

    #[test]
    fn usb2_port_speed_decodes_status_bits() {
        assert_eq!(usb2_downstream_speed(hub_port_status::HIGH_SPEED), 3);
        assert_eq!(usb2_downstream_speed(hub_port_status::LOW_SPEED), 2);
        assert_eq!(usb2_downstream_speed(0), 1);
    }
}

/// How long enumeration waits for a device that left its root port during
/// bring-up to show up on another one. A USB3 device first appears on its
/// USB2 port and drops that connection once its SuperSpeed link trains.
const MOVED_DEVICE_TIMEOUT_MS: u64 = 500;

/// Root ports already brought up during enumeration.
struct RootPortScan {
    tried: Vec<bool>,
    /// A device left its root port; new connections cannot be matched to it.
    migration_seen: bool,
}

impl RootPortScan {
    fn new(num_ports: u8) -> Self {
        Self {
            tried: alloc::vec![false; usize::from(num_ports)],
            migration_seen: false,
        }
    }

    /// A device left its root port during bring-up.
    fn record_move(&mut self) {
        self.migration_seen = true;
    }

    fn untried(&self) -> impl Iterator<Item = u8> + '_ {
        (0..self.tried.len())
            .filter(|&port| !self.tried[port])
            .map(|port| port as u8)
    }

    /// Connected ports that were not brought up yet; marks them as tried.
    fn take_new_connections(&mut self, connected: impl Fn(u8) -> bool) -> Vec<u8> {
        let ports: Vec<u8> = self.untried().filter(|&port| connected(port)).collect();
        for &port in &ports {
            self.tried[usize::from(port)] = true;
        }
        ports
    }

    fn has_new_connection(&self, connected: impl Fn(u8) -> bool) -> bool {
        self.untried().any(connected)
    }

    /// Rescan immediately, then allow a fresh quiet window after any migration.
    async fn wait_for_next_pass(&self, connected: impl Fn(u8) -> bool) -> bool {
        // Without port-pair information, even a new SuperSpeed connection
        // could be unrelated. Keep waiting until a whole window is quiet.
        let wait_ms = if self.migration_seen {
            MOVED_DEVICE_TIMEOUT_MS
        } else {
            0
        };
        self.wait_for_new_connection(Timeout::from_ms(wait_ms), connected)
            .await
    }

    async fn wait_for_new_connection(
        &self,
        timeout: Timeout,
        connected: impl Fn(u8) -> bool,
    ) -> bool {
        loop {
            if self.has_new_connection(&connected) {
                return true;
            }
            if timeout.is_expired() {
                return self.has_new_connection(connected);
            }
            exec::yield_now().await;
        }
    }
}

/// A port whose device neither attached nor stayed connected lost it to
/// another root port, e.g. a USB3 device moving to its SuperSpeed port.
fn device_moved(attached: bool, still_connected: bool) -> bool {
    !attached && !still_connected
}

#[cfg(test)]
mod root_port_scan_tests {
    use super::*;

    #[test]
    fn usb3_device_moving_from_usb2_port_is_picked_up_in_a_second_pass() {
        let mut scan = RootPortScan::new(26);

        // A keyboard on port 3, a USB3 stick seen on its USB2 port 2.
        let first = scan.take_new_connections(|port| port == 2 || port == 3);
        assert_eq!(first, [2, 3]);

        // Resetting port 2 makes the stick train on SuperSpeed port 18.
        assert!(device_moved(false, false));
        assert!(!device_moved(true, true));
        assert!(scan.has_new_connection(|port| port == 18));

        // Only the new connection is brought up, not the attached keyboard.
        let second = scan.take_new_connections(|port| port == 3 || port == 18);
        assert_eq!(second, [18]);
        assert!(!scan.has_new_connection(|port| port == 3 || port == 18));
    }

    #[test]
    fn staggered_migrations_get_fresh_wait_windows() {
        use core::cell::Cell;

        let mut scan = RootPortScan::new(26);
        assert_eq!(
            scan.take_new_connections(|port| port == 2 || port == 3),
            [2, 3]
        );
        scan.record_move();
        scan.record_move();

        // Each SuperSpeed connection appears only after waiting. Attaching
        // the first device must not end the wait for the second migration.
        for port in [18, 19] {
            let polls = Cell::new(0);
            assert!(exec::block_on(scan.wait_for_next_pass(|p| {
                if p != port {
                    return false;
                }
                polls.set(polls.get() + 1);
                polls.get() > 1
            })));
            assert_eq!(scan.take_new_connections(|p| p == port), [port]);
        }

        // Once a quiet window expires, an absent device cannot keep
        // enumeration waiting, but an already-connected port is still found.
        let expired = Timeout::from_raw(crate::time::read_counter());
        assert!(!exec::block_on(
            scan.wait_for_new_connection(expired, |_| false)
        ));
        assert!(exec::block_on(
            scan.wait_for_new_connection(expired, |port| port == 20)
        ));
    }

    #[test]
    fn unrelated_connection_does_not_end_migration_wait() {
        use core::cell::Cell;

        let mut scan = RootPortScan::new(26);
        assert_eq!(scan.take_new_connections(|port| port == 1), [1]);
        scan.record_move();

        // An unrelated device connects before the moved USB3 device.
        assert_eq!(scan.take_new_connections(|port| port == 3), [3]);
        assert!(scan.migration_seen);
        let polls = Cell::new(0);
        assert!(exec::block_on(scan.wait_for_next_pass(|port| {
            if port != 18 {
                return false;
            }
            polls.set(polls.get() + 1);
            polls.get() > 1
        })));
        assert_eq!(scan.take_new_connections(|port| port == 18), [18]);
    }

    #[test]
    fn connection_during_final_attachment_is_rescanned() {
        let mut scan = RootPortScan::new(26);
        assert_eq!(scan.take_new_connections(|port| port == 1), [1]);
        scan.record_move();
        assert_eq!(scan.take_new_connections(|port| port == 18), [18]);

        // Another port connects while the last moved device is attached.
        assert!(exec::block_on(scan.wait_for_next_pass(|port| port == 19)));
        assert_eq!(scan.take_new_connections(|port| port == 19), [19]);
    }

    #[test]
    fn no_migration_rescans_without_waiting() {
        let mut scan = RootPortScan::new(4);
        assert_eq!(scan.take_new_connections(|port| port == 1), [1]);
        assert!(!scan.migration_seen);
        assert!(exec::block_on(scan.wait_for_next_pass(|port| port == 2)));
        assert_eq!(scan.take_new_connections(|port| port == 2), [2]);
        assert!(!exec::block_on(scan.wait_for_next_pass(|_| false)));
    }

    #[test]
    fn failed_device_that_stays_connected_is_not_retried() {
        let mut scan = RootPortScan::new(4);

        assert_eq!(scan.take_new_connections(|port| port == 1), [1]);
        assert!(!device_moved(false, true));
        assert!(scan.take_new_connections(|port| port == 1).is_empty());
    }
}

impl super::XhciController {
    fn hub_sublink_speeds(&mut self, slot_id: u8) -> Result<Option<SublinkSpeeds>, XhciError> {
        let mut header = [0u8; 5];
        let length = self.control_transfer(
            slot_id,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            u16::from(BOS_DESCRIPTOR_TYPE) << 8,
            0,
            Some(&mut header),
        )?;
        if length != header.len() {
            return Err(XhciError::InvalidParameter);
        }
        let length = BosHeader::total_length(&header)?;
        if length > 4096 {
            return Err(XhciError::InvalidParameter);
        }
        let mut bos = alloc::vec![0u8; length];
        let received = self.control_transfer(
            slot_id,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            u16::from(BOS_DESCRIPTOR_TYPE) << 8,
            0,
            Some(&mut bos),
        )?;
        SublinkSpeeds::from_bos(&bos[..received])
    }

    fn superspeed_hub_port_speed(
        &mut self,
        hub_slot: u8,
        port: u8,
        root_port: u8,
        sublinks: Option<&SublinkSpeeds>,
    ) -> Result<u8, XhciError> {
        let link = if let Some(sublinks) = sublinks {
            // USB 3.1+ ordinary port status always reports the legacy 5-Gbit/s
            // encoding. Extended status supplies hub-local IDs and lane counts.
            let mut status = [0u8; 8];
            let length = self.control_transfer(
                hub_slot,
                req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                request::GET_STATUS,
                2,
                u16::from(port),
                Some(&mut status),
            )?;
            if length != status.len() {
                return Err(XhciError::InvalidParameter);
            }
            let extended = U32::<LittleEndian>::read_from_bytes(&status[4..])
                .unwrap()
                .get();
            sublinks
                .port_speed(extended)
                .ok_or(XhciError::InvalidParameter)?
        } else {
            LinkSpeed::SUPER
        };
        self.usb3_speed_id(root_port, link)
            .ok_or(XhciError::InvalidParameter)
    }

    /// Configure a hub device and enumerate its downstream ports.
    ///
    /// This mirrors the EHCI `enumerate_hub()` logic adapted for xHCI's
    /// route-string-based addressing model.
    ///
    /// Boxed because hubs nest: attaching a hub port device may recurse here.
    pub(super) fn configure_and_enumerate_hub(
        &mut self,
        hub_slot_id: u8,
        root_port: u8,
    ) -> BoxFuture<'_, Result<(), XhciError>> {
        Box::pin(self.configure_and_enumerate_hub_inner(hub_slot_id, root_port))
    }

    async fn configure_and_enumerate_hub_inner(
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

        let (hub_is_superspeed, bcd_usb, parent_route) = self
            .slots
            .get(hub_slot_id as usize)
            .and_then(|slot| slot.as_ref())
            .map(|slot| {
                (
                    slot.is_superspeed,
                    slot.device_desc.bcd_usb,
                    slot.route_string,
                )
            })
            .ok_or(XhciError::DeviceNotFound)?;
        // Get the descriptor belonging to this hub's bus protocol.
        let mut hub_desc_buf = [0u8; 12];
        self.control_transfer(
            hub_slot_id,
            req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            u16::from(hub_descriptor_type(hub_is_superspeed)) << 8,
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

        let sublinks = if hub_is_superspeed && bcd_usb >= 0x0310 {
            self.hub_sublink_speeds(hub_slot_id)?
        } else {
            None
        };

        if hub_is_superspeed {
            self.control_transfer(
                hub_slot_id,
                req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_DEVICE,
                SET_HUB_DEPTH,
                hub_depth(parent_route),
                0,
                None,
            )?;
        }

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

        exec::sleep_ms(power_delay.max(100)).await;

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

            exec::sleep_ms(60).await;

            // Poll for reset completion
            let timeout = crate::time::Timeout::from_ms(500);
            let mut speed = 0u8;
            let mut reset_ok = false;
            // Check status after the deadline too: other controllers may
            // delay this task past it.
            loop {
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
                        if hub_is_superspeed {
                            match self.superspeed_hub_port_speed(
                                hub_slot_id,
                                p,
                                root_port,
                                sublinks.as_ref(),
                            ) {
                                Ok(port_speed) => {
                                    speed = port_speed;
                                    reset_ok = true;
                                }
                                Err(error) => {
                                    log::warn!("Hub port {} speed unavailable: {:?}", p, error)
                                }
                            }
                        } else {
                            speed = usb2_downstream_speed(ps);
                            reset_ok = true;
                        }
                    }
                    break;
                }
                if timeout.is_expired() {
                    break;
                }
                exec::sleep_ms(10).await;
            }

            if !reset_ok {
                log::debug!("Hub port {} reset failed", p);
                continue;
            }

            exec::sleep_ms(10).await;

            // Build route string: parent's route | (port << (4 * tier))
            // Find which nibble is the first zero (that's our tier)
            let mut route = parent_route;
            for tier in 0..5u32 {
                if (route >> (tier * 4)) & 0xF == 0 {
                    route |= (p as u32 & 0xF) << (tier * 4);
                    break;
                }
            }

            // Enable slot and address the downstream device
            if let Err(e) = self
                .attach_device_on_hub(hub_slot_id, p, speed, route, root_port)
                .await
            {
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
    pub(super) async fn attach_device_on_hub(
        &mut self,
        hub_slot_id: u8,
        hub_port: u8,
        speed: u8,
        route_string: u32,
        root_port: u8,
    ) -> Result<(), XhciError> {
        let slot_id = self.enable_slot()?;
        self.address_slot(
            slot_id,
            speed,
            super::slots::SlotRoute {
                port: hub_port,
                root_port,
                route_string,
                parent_hub: Some((hub_slot_id, hub_port)),
            },
        )?;

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
                    && let Err(e) = self.configure_and_enumerate_hub(slot_id, root_port).await
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
    pub(super) async fn enumerate_ports(&mut self) -> Result<(), XhciError> {
        let mut scan = RootPortScan::new(self.num_ports);

        loop {
            let ports =
                scan.take_new_connections(|port| self.portsc(port).current_connect_status());
            if ports.is_empty() {
                break;
            }

            // Link bring-up (debounce, resets) only touches each port's own
            // PORTSC, so run it for all root ports at once. Device attachment
            // goes through the shared command ring and stays sequential.
            let link_up = {
                let this = RefCell::new(&mut *self);
                exec::join_all(
                    ports
                        .iter()
                        .map(|&port| {
                            Box::pin(Self::bring_up_root_port(&this, port)) as BoxFuture<'_, bool>
                        })
                        .collect(),
                )
                .await
            };

            for (port, up) in ports.into_iter().zip(link_up) {
                let attached = up && self.attach_root_port_device(port).await;
                if device_moved(attached, self.portsc(port).current_connect_status()) {
                    log::debug!("Port {}: device disconnected during bring-up", port);
                    scan.record_move();
                }
            }

            // Rescan ports that connected during attachment. After a move,
            // wait from the end of each pass: attaching the other devices
            // can take longer than the wait, and new connections may be
            // unrelated to the devices whose links are still training.
            if !scan
                .wait_for_next_pass(|port| self.portsc(port).current_connect_status())
                .await
            {
                break;
            }
        }

        Ok(())
    }

    /// Debounce a root port connection and bring its link to U0/enabled.
    ///
    /// `this` is only borrowed between awaits so all ports can share it.
    async fn bring_up_root_port(this: &RefCell<&mut Self>, port: u8) -> bool {
        let portsc = || this.borrow().portsc(port);
        let update_portsc =
            |update: fn(&mut xhci::registers::operational::PortStatusAndControlRegister)| {
                this.borrow_mut().update_portsc(port, update)
            };

        if !portsc().current_connect_status() {
            return false;
        }

        let mut stable_count = 0;
        for _ in 0..5 {
            if portsc().current_connect_status() {
                stable_count += 1;
            } else {
                stable_count = 0;
            }
            exec::sleep_ms(10).await;
        }
        if stable_count < 3 {
            return false;
        }

        let status = portsc();
        let speed = status.port_speed();
        let link_state = status.port_link_state();
        let is_usb3 = this.borrow().is_superspeed_port(port, speed);
        let speed_name = if is_usb3 {
            "SuperSpeed"
        } else {
            match speed {
                1 => "Full",
                2 => "Low",
                3 => "High",
                _ => "Unknown",
            }
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
            return false;
        }

        this.borrow_mut().clear_port_changes(port);

        let status = portsc();
        if is_usb3 && status.port_enabled_disabled() && status.port_link_state() == 0 {
            log::debug!("Port {}: USB3 device already in U0, skipping reset", port);
        } else if is_usb3 && status.port_link_state() == 7 {
            log::debug!("Port {}: USB3 device in Polling, waiting for link", port);
            let link_up = exec::wait_for(200, || {
                let status = portsc();
                status.port_link_state() == 0 && status.port_enabled_disabled()
            })
            .await;
            if !link_up {
                log::debug!(
                    "Port {}: USB3 link training failed (PLS={}), skipping",
                    port,
                    portsc().port_link_state()
                );
                return false;
            }
        } else if !status.port_enabled_disabled() {
            update_portsc(|portsc| {
                portsc.set_port_reset();
            });

            if exec::wait_for(150, || portsc().port_reset_change()).await {
                update_portsc(|portsc| {
                    portsc.clear_port_reset_change();
                });
            }

            if portsc().port_link_state() != 0 {
                if !is_usb3 {
                    log::debug!(
                        "Port {}: link not up after reset (PLS={}), skipping",
                        port,
                        portsc().port_link_state()
                    );
                    return false;
                }
                log::debug!(
                    "Port {}: USB3 normal reset failed (PLS={}), trying warm reset",
                    port,
                    portsc().port_link_state()
                );
                update_portsc(|portsc| {
                    portsc.set_warm_port_reset();
                });

                if exec::wait_for(200, || portsc().warm_port_reset_change()).await {
                    update_portsc(|portsc| {
                        portsc.clear_warm_port_reset_change();
                    });
                }

                if portsc().port_link_state() != 0 {
                    log::debug!(
                        "Port {}: link not up after warm reset (PLS={}), skipping",
                        port,
                        portsc().port_link_state()
                    );
                    return false;
                }
                log::debug!("Port {}: warm reset successful", port);
            }
        }

        true
    }

    /// Address and configure the device behind an enabled root port.
    ///
    /// Returns `false` when the port no longer has an enabled device.
    async fn attach_root_port_device(&mut self, port: u8) -> bool {
        // USB2 speed is not reliable until reset has enabled the port.
        let status = self.portsc(port);
        if !status.current_connect_status() || !status.port_enabled_disabled() {
            log::debug!("Port {}: no enabled device after bring-up", port);
            return false;
        }
        let speed = status.port_speed();

        // Enable slot and address device
        match self.enable_slot() {
            Ok(slot_id) => {
                log::debug!("Enabled slot {}", slot_id);

                if let Err(e) = self.address_device(slot_id, port, speed) {
                    log::error!("Failed to address device on port {}: {:?}", port, e);
                    let status = self.portsc(port);
                    return status.current_connect_status() && status.port_enabled_disabled();
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
                            && let Err(e) = self.configure_and_enumerate_hub(slot_id, port).await
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
        let status = self.portsc(port);
        status.current_connect_status() && status.port_enabled_disabled()
    }
}

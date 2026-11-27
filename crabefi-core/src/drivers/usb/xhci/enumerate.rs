//! xHCI port registers, slot attachment, and hub routing.

use super::super::controller::{DeviceDescriptor, UsbError, class, desc_type, req_type, request};
use super::super::port::{self, Control, Pipe, PortController, RootCommand, RootKind, RootStatus};
use super::super::{unbind_device, with_xhci};
use super::slots::SlotRoute;
use super::speed::{BOS_DESCRIPTOR_TYPE, BosHeader, LinkSpeed, SublinkSpeeds};
use super::{XhciController, XhciError};
use crate::{barrier, exec};
use xhci::ring::trb::command;
use zerocopy::FromBytes;

impl PortController for XhciController {
    fn root_ports(&self) -> (RootKind, u8) {
        (RootKind::Xhci, self.num_ports)
    }

    fn root_status(&self, port: u8) -> RootStatus {
        let status = self.portsc(port);
        let speed_id = status.port_speed();
        RootStatus {
            connected: status.current_connect_status(),
            changed: status.connect_status_change(),
            enabled: status.port_enabled_disabled(),
            link_state: status.port_link_state(),
            speed_id,
            superspeed: self.is_superspeed_port(port, speed_id),
            reset_done: status.port_reset_change(),
            warm_reset_done: status.warm_port_reset_change(),
            ..RootStatus::default()
        }
    }

    fn root_command(&mut self, port: u8, command: RootCommand) {
        if matches!(command, RootCommand::ClearChanges) {
            self.clear_port_changes(port);
            return;
        }
        self.update_portsc(port, |reg| {
            match command {
                RootCommand::Reset => reg.set_port_reset(),
                RootCommand::WarmReset => reg.set_warm_port_reset(),
                RootCommand::AckReset => reg.clear_port_reset_change(),
                RootCommand::AckWarmReset => reg.clear_warm_port_reset_change(),
                _ => unreachable!(),
            };
        });
    }

    fn poll_bus(&mut self) {
        // Consume Port Status Change events even with no active transfers.
        // Root-port tasks observe their latched PORTSC bits directly.
        let _ = self.poll_interrupt_events();
    }
}

fn controller<T>(
    index: usize,
    operation: impl FnOnce(&mut XhciController) -> Result<T, XhciError>,
) -> Result<T, UsbError> {
    with_xhci(index, operation)
        .ok_or(UsbError::Disconnected)?
        .map_err(|error| match error {
            XhciError::Timeout => UsbError::Timeout,
            XhciError::DeviceNotFound => UsbError::DeviceNotFound,
            XhciError::NoFreeSlots => UsbError::NoFreeSlots,
            XhciError::InvalidParameter => UsbError::InvalidParameter,
            XhciError::AllocationFailed => UsbError::AllocationFailed,
            _ => {
                log::debug!("xHCI enumeration: {error:?}");
                UsbError::TransactionError
            }
        })
}

fn route(controller: &XhciController, hub: Option<u8>, port: u8) -> Result<SlotRoute, XhciError> {
    if let Some(address) = hub {
        let hub = controller
            .get_slot(address)
            .ok_or(XhciError::DeviceNotFound)?;
        let depth = hub_depth(hub.route_string);
        if depth >= 5 || !(1..=15).contains(&port) {
            return Err(XhciError::InvalidParameter);
        }
        Ok(SlotRoute {
            port,
            root_port: hub.root_port,
            route_string: hub.route_string | (u32::from(port) << (depth * 4)),
            parent_hub: Some((address, port)),
        })
    } else {
        Ok(SlotRoute {
            port,
            root_port: port,
            route_string: 0,
            parent_hub: None,
        })
    }
}

pub(in crate::drivers::usb) async fn attach(
    index: usize,
    hub: Option<u8>,
    number: u8,
    speed: u8,
) -> Result<u8, UsbError> {
    port::transfer().await;
    // Enable and address consecutively. The enabled slot is tracked even
    // if allocating the address context fails before the command is issued.
    let (address, addressed) = controller(index, |host| {
        let route = route(host, hub, number)?;
        let address = host.enable_slot()?;
        Ok((address, host.address_slot(address, speed, route)))
    })?;
    if let Err(error) = addressed {
        port::transfer().await;
        with_xhci(index, |host| host.detach_slot(address));
        log::debug!("xHCI: addressing slot {address} failed: {error:?}");
        return Err(if matches!(error, XhciError::Timeout) {
            UsbError::Timeout
        } else {
            UsbError::TransactionError
        });
    }
    exec::sleep_ms(2).await; // SET_ADDRESS recovery
    let pipe = Pipe {
        controller: index,
        address,
    };
    if let Err(error) = configure_device(pipe).await {
        detach(index, address).await;
        return Err(error);
    }
    Ok(address)
}

async fn configure_device(pipe: Pipe) -> Result<(), UsbError> {
    let get_device = Control::descriptor(req_type::RCPT_DEVICE, desc_type::DEVICE, 0);
    let full_speed = controller(pipe.controller, |host| {
        let slot = host
            .get_slot(pipe.address)
            .ok_or(XhciError::DeviceNotFound)?;
        Ok(!slot.is_superspeed && slot.speed == 1)
    })?;
    if full_speed {
        let mut short = [0; 8];
        if pipe.control(get_device, Some(&mut short)).await? != short.len() {
            return Err(UsbError::InvalidParameter);
        }
        port::transfer().await;
        controller(pipe.controller, |host| {
            host.update_full_speed_ep0_max_packet(pipe.address, u16::from(short[7]))
        })?;
    }
    let mut descriptor = [0; 18];
    if pipe.control(get_device, Some(&mut descriptor)).await? != descriptor.len() {
        return Err(UsbError::InvalidParameter);
    }
    let descriptor =
        DeviceDescriptor::read_from_bytes(&descriptor).map_err(|_| UsbError::InvalidParameter)?;
    let vid = descriptor.vendor_id;
    let pid = descriptor.product_id;
    log::info!(
        "  VID={vid:04x} PID={pid:04x} Class={:02x}",
        descriptor.device_class
    );
    let config = pipe.configuration().await?;
    let interfaces = &config.interfaces[..config.num_interfaces];
    if config.configuration_value != 0 {
        pipe.control(
            Control::new(
                req_type::RCPT_DEVICE,
                request::SET_CONFIGURATION,
                u16::from(config.configuration_value),
                0,
            ),
            None,
        )
        .await?;
    }
    controller(pipe.controller, |host| {
        let slot = host
            .get_slot_mut(pipe.address)
            .ok_or(XhciError::DeviceNotFound)?;
        slot.device_desc = descriptor;
        slot.is_hub = descriptor.device_class == class::HUB
            || interfaces
                .iter()
                .any(|iface| iface.interface_class == class::HUB);
        Ok(())
    })?;
    if interfaces.iter().any(|iface| iface.is_mass_storage()) {
        port::transfer().await;
        controller(pipe.controller, |host| {
            optional_class(
                pipe.address,
                "mass storage",
                host.configure_mass_storage(pipe.address, &config),
            )
        })?;
    }
    if interfaces.iter().any(|iface| iface.is_hid_keyboard()) {
        port::transfer().await;
        controller(pipe.controller, |host| {
            optional_class(
                pipe.address,
                "keyboard",
                host.configure_hid_keyboard(pipe.address, &config),
            )
        })?;
    }
    if interfaces.iter().any(|iface| iface.is_hid_mouse()) {
        port::transfer().await;
        controller(pipe.controller, |host| {
            optional_class(
                pipe.address,
                "mouse",
                host.configure_hid_mouse(pipe.address, &config),
            )
        })?;
    }
    Ok(())
}

fn optional_class(
    address: u8,
    class: &str,
    result: Result<(), XhciError>,
) -> Result<(), XhciError> {
    if let Err(error) = &result
        && error.class_rejected()
    {
        log::warn!("xHCI slot {address}: skipping unusable {class} interface: {error:?}");
        return Ok(());
    }
    result
}

#[cfg(test)]
#[test]
fn rejecting_a_secondary_function_does_not_abort_the_configured_device() {
    use xhci::ring::trb::event::CompletionCode;
    assert!(optional_class(1, "mass storage", Ok(())).is_ok());
    assert!(optional_class(1, "keyboard", Err(XhciError::InvalidParameter)).is_ok());
    assert!(
        optional_class(
            1,
            "mouse",
            Err(XhciError::CommandFailed(Ok(CompletionCode::BandwidthError)))
        )
        .is_ok()
    );
    assert!(matches!(
        optional_class(1, "mouse", Err(XhciError::Timeout)),
        Err(XhciError::Timeout)
    ));
}

pub(in crate::drivers::usb) async fn detach(index: usize, address: u8) {
    loop {
        let next = with_xhci(index, |host| {
            if host.get_slot(address).is_none()
                && host.pending_parents.get(address as usize)?.is_none()
            {
                return None;
            }
            Some(teardown_leaf(address, |parent| {
                host.find_slot(|slot| slot.parent_hub.is_some_and(|(hub, _)| hub == parent))
                    .or_else(|| pending_child(&host.pending_parents, parent))
            }))
        })
        .flatten();
        let Some(next) = next else {
            break;
        };
        port::transfer().await;
        with_xhci(index, |host| host.detach_slot(next));
        unbind_device(index, next);
        if next == address {
            break;
        }
    }
}

fn pending_child(parents: &[Option<u8>], parent: u8) -> Option<u8> {
    parents
        .iter()
        .position(|child| *child == Some(parent))
        .and_then(|id| u8::try_from(id).ok())
}

fn teardown_leaf(mut slot: u8, mut child: impl FnMut(u8) -> Option<u8>) -> u8 {
    while let Some(next) = child(slot) {
        slot = next;
    }
    slot
}

#[cfg(test)]
#[test]
fn teardown_finds_unaddressed_child_after_its_attach_is_cancelled() {
    // Addressed hub 2 has addressed child hub 3. Slot 5 was enabled
    // beneath hub 3 but allocating its contexts failed before publication.
    let mut pending = [None; 6];
    pending[5] = Some(3);
    let leaf = |pending: &[Option<u8>]| {
        teardown_leaf(2, |parent| {
            if parent == 2 {
                Some(3)
            } else {
                pending_child(pending, parent)
            }
        })
    };
    assert_eq!(leaf(&pending), 5);
    pending[5] = None;
    assert_eq!(leaf(&pending), 3);
}

const SET_HUB_DEPTH: u8 = 0x0c;

fn hub_depth(route: u32) -> u16 {
    ((u32::BITS - route.leading_zeros()).div_ceil(4)) as u16
}

#[derive(Clone, Copy)]
pub(in crate::drivers::usb) struct HubGeometry {
    pub superspeed: bool,
    depth: u16,
    bcd_usb: u16,
}

pub(in crate::drivers::usb) fn hub_geometry(pipe: Pipe) -> Result<HubGeometry, UsbError> {
    controller(pipe.controller, |host| {
        let hub = host
            .get_slot(pipe.address)
            .ok_or(XhciError::DeviceNotFound)?;
        Ok(HubGeometry {
            superspeed: hub.is_superspeed,
            depth: hub_depth(hub.route_string),
            bcd_usb: hub.device_desc.bcd_usb,
        })
    })
}

pub(in crate::drivers::usb) async fn configure_hub(
    pipe: Pipe,
    hub: HubGeometry,
    count: u8,
) -> Result<(), UsbError> {
    let sublinks = if hub.superspeed && hub.bcd_usb >= 0x0310 {
        hub_sublink_speeds(pipe).await?
    } else {
        None
    };
    if hub.superspeed {
        pipe.control(
            Control::new(
                req_type::DIR_OUT | req_type::TYPE_CLASS | req_type::RCPT_DEVICE,
                SET_HUB_DEPTH,
                hub.depth,
                0,
            ),
            None,
        )
        .await?;
    }
    port::transfer().await;
    controller(pipe.controller, |host| {
        host.evaluate_hub_context(pipe.address, count)?;
        host.get_slot_mut(pipe.address)
            .ok_or(XhciError::DeviceNotFound)?
            .sublinks = sublinks;
        Ok(())
    })
}

async fn hub_sublink_speeds(pipe: Pipe) -> Result<Option<SublinkSpeeds>, UsbError> {
    let request = Control::descriptor(req_type::RCPT_DEVICE, BOS_DESCRIPTOR_TYPE, 0);
    let mut header = [0; 5];
    if pipe.control(request, Some(&mut header)).await? != header.len() {
        return Err(UsbError::InvalidParameter);
    }
    let length = BosHeader::total_length(&header).map_err(|_| UsbError::InvalidParameter)?;
    if length > 4096 {
        return Err(UsbError::InvalidParameter);
    }
    let mut bos = alloc::vec![0; length];
    let received = pipe.control(request, Some(&mut bos)).await?;
    SublinkSpeeds::from_bos(&bos[..received]).map_err(|_| UsbError::InvalidParameter)
}

pub(in crate::drivers::usb) async fn superspeed_hub_port_speed(
    pipe: Pipe,
    port: u8,
) -> Result<u8, UsbError> {
    let needs_extended = controller(pipe.controller, |host| {
        Ok(host
            .get_slot(pipe.address)
            .ok_or(XhciError::DeviceNotFound)?
            .sublinks
            .is_some())
    })?;
    let mut status = [0; 8];
    if needs_extended
        && pipe
            .control(
                Control::new(
                    req_type::DIR_IN | req_type::TYPE_CLASS | req_type::RCPT_OTHER,
                    request::GET_STATUS,
                    2,
                    u16::from(port),
                ),
                Some(&mut status),
            )
            .await?
            != status.len()
    {
        return Err(UsbError::InvalidParameter);
    }
    controller(pipe.controller, |host| {
        let slot = host
            .get_slot(pipe.address)
            .ok_or(XhciError::DeviceNotFound)?;
        let link = if let Some(sublinks) = &slot.sublinks {
            sublinks
                .port_speed(u32::from_le_bytes(status[4..].try_into().unwrap()))
                .ok_or(XhciError::InvalidParameter)?
        } else {
            LinkSpeed::SUPER
        };
        host.usb3_speed_id(slot.root_port, link)
            .ok_or(XhciError::InvalidParameter)
    })
}

impl XhciController {
    /// Inform the controller of the hub flag and downstream routing limits.
    fn evaluate_hub_context(&mut self, address: u8, count: u8) -> Result<(), XhciError> {
        let slot = self.get_slot(address).ok_or(XhciError::DeviceNotFound)?;
        let input = slot.input_context;
        unsafe { core::ptr::write_bytes(input, 0, Self::input_context_len(self.context_size)) };
        Self::input_control_context(input, self.context_size).set_add_context_flag(0);
        Self::copy_device_slot_context(input, slot.device_context, self.context_size);
        let slot_ctx = Self::input_slot_context(input, self.context_size);
        slot_ctx.set_hub();
        slot_ctx.set_number_of_ports(count);
        let mut command = command::EvaluateContext::new();
        command
            .set_input_context_pointer(input as u64)
            .set_slot_id(address);
        self.cmd_ring.enqueue(command, false);
        barrier::mmio_write();
        self.ring_doorbell(0, 0);
        self.wait_command_completion()?;
        Ok(())
    }
}

#[cfg(test)]
#[test]
fn hub_depth_matches_route_tiers() {
    assert_eq!(hub_depth(0), 0);
    assert_eq!(hub_depth(1), 1);
    assert_eq!(hub_depth(0x31), 2);
    assert_eq!(hub_depth(0xf4321), 5);
}

//! xHCI (USB 3.0) Host Controller Interface driver
//!
//! This module provides a minimal xHCI driver for USB mass storage devices.

use crate::barrier;
use crate::drivers::mmio::MmioRegion;
use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi;
use crate::time::{Timeout, wait_for};
use core::ptr;
use zerocopy::FromBytes;

use super::controller::{
    ConfigurationInfo, DeviceDescriptor, HUB_DESCRIPTOR_TYPE, desc_type, hub_feature,
    hub_port_status, parse_configuration, req_type, request,
};

use xhci::accessor::Mapper;
use xhci::context::{
    self, EndpointHandler, EndpointType, InputControlHandler, InputHandler, SlotHandler,
};
use xhci::extended_capabilities::{self, ExtendedCapability};
use xhci::registers::capability::CapabilityParameters1;
use xhci::registers::operational::PortStatusAndControlRegister;
use xhci::registers::{Access64, Doorbell, Registers};
use xhci::ring::trb::{self, Link, command, event, transfer};

/// Identity mapper for firmware environments where PCI MMIO is already mapped.
#[derive(Clone, Copy, Debug)]
struct IdentityMapper;

impl Mapper for IdentityMapper {
    #[allow(unused_unsafe)]
    unsafe fn map(&mut self, phys_start: usize, _bytes: usize) -> core::num::NonZeroUsize {
        unsafe {
            core::num::NonZeroUsize::new(phys_start).expect("xHCI MMIO address must be non-zero")
        }
    }

    fn unmap(&mut self, _virt_start: usize, _bytes: usize) {}
}

type RawTrb = [u32; 4];

#[inline]
fn raw_trb_type(raw: &RawTrb) -> u32 {
    (raw[3] >> 10) & 0x3f
}

#[inline]
fn raw_completion_code(raw: &RawTrb) -> u32 {
    (raw[2] >> 24) & 0xff
}

#[inline]
fn read_event_trb(addr: u64, expected_cycle: bool) -> Option<RawTrb> {
    let p = addr as *const u32;
    // The controller publishes event ownership through control dword 3. Do not
    // read the payload until that publication has been observed and ordered.
    // SAFETY: callers pass an address within a page-backed xHCI event ring.
    let control = unsafe { ptr::read_volatile(p.add(3)) };
    if (control & 1 != 0) != expected_cycle {
        return None;
    }

    barrier::dma_read();
    // SAFETY: the matching cycle bit makes the complete event TRB available.
    Some(unsafe {
        [
            ptr::read_volatile(p),
            ptr::read_volatile(p.add(1)),
            ptr::read_volatile(p.add(2)),
            control,
        ]
    })
}

#[inline]
fn read_event_control(addr: u64) -> u32 {
    // SAFETY: callers pass an address within a page-backed xHCI event ring.
    unsafe { ptr::read_volatile((addr + 12) as *const u32) }
}

/// Ring buffer for TRBs
pub struct TrbRing {
    /// Base address of the ring
    base: u64,
    /// Current enqueue pointer index
    enqueue_idx: usize,
    /// Current dequeue pointer index
    dequeue_idx: usize,
    /// Number of TRBs in the ring
    size: usize,
    /// Current cycle bit
    cycle: bool,
}

impl TrbRing {
    /// Create an empty/uninitialized TrbRing (for placeholder use)
    const fn empty() -> Self {
        Self {
            base: 0,
            enqueue_idx: 0,
            dequeue_idx: 0,
            size: 0,
            cycle: true,
        }
    }

    /// Create a new command/transfer ring with a link TRB at the end
    fn new(base: u64, size: usize) -> Self {
        if size == 0 {
            return Self::empty();
        }

        // Initialize all TRBs to 0
        unsafe { core::slice::from_raw_parts_mut(base as *mut u8, size * 16).fill(0) };

        // Set up the upstream Link TRB at the end to wrap around.
        let mut link = Link::new();
        link.set_ring_segment_pointer(base).set_toggle_cycle();
        let link_addr = (base + ((size - 1) * trb::BYTES) as u64) as *mut RawTrb;
        // SAFETY: the ring allocation contains `size` TRBs.
        unsafe { ptr::write(link_addr, link.into_raw()) };

        Self {
            base,
            enqueue_idx: 0,
            dequeue_idx: 0,
            size,
            cycle: true,
        }
    }

    /// Create a new event ring (no link TRB, consumer-side cycle tracking)
    fn new_event_ring(base: u64, size: usize) -> Self {
        if size == 0 {
            return Self::empty();
        }

        // Initialize all TRBs to 0 (cycle bits = 0)
        // Hardware will write with cycle = 1 initially
        unsafe { core::slice::from_raw_parts_mut(base as *mut u8, size * 16).fill(0) };

        Self {
            base,
            enqueue_idx: 0,
            dequeue_idx: 0,
            size,
            cycle: true, // Expect cycle = 1 from hardware initially
        }
    }

    /// Enqueue a TRB onto the ring.
    ///
    /// Writes are ordered per the xHCI spec: param and status are written first,
    /// then a write barrier, then control (which contains the cycle bit). This
    /// ensures the HC sees complete TRB data when it checks the cycle bit.
    ///
    /// If `defer_cycle` is true, the TRB is written with an **inverted** cycle bit.
    /// The caller must later call `commit_deferred_trb()` to flip it live. This
    /// implements the "deferred first TRB" technique to prevent the HC from
    /// processing a partially-built multi-TRB TD.
    fn enqueue<T: Into<RawTrb>>(&mut self, trb: T, defer_cycle: bool) -> u64 {
        let raw = trb.into();
        let addr = self.base + (self.enqueue_idx * trb::BYTES) as u64;
        let entry = addr as *mut u32;

        let cycle_bit = u32::from(if defer_cycle { !self.cycle } else { self.cycle });

        // Preserve CrabEFI's publication policy: parameter and status first.
        unsafe {
            ptr::write_volatile(
                entry as *mut u64,
                u64::from(raw[0]) | (u64::from(raw[1]) << 32),
            );
            ptr::write_volatile(entry.add(2), raw[2]);
        }
        barrier::dma_write();
        // Publish ownership through the cycle-bearing control dword last.
        unsafe { ptr::write_volatile(entry.add(3), (raw[3] & !1) | cycle_bit) };

        self.enqueue_idx += 1;

        if self.enqueue_idx >= self.size - 1 {
            let link_control = (self.base + ((self.size - 1) * trb::BYTES + 12) as u64) as *mut u32;
            barrier::dma_write();
            let control = unsafe { ptr::read_volatile(link_control) };
            unsafe {
                ptr::write_volatile(
                    link_control,
                    if self.cycle {
                        control | 1
                    } else {
                        control & !1
                    },
                )
            };
            barrier::dma_write();

            self.enqueue_idx = 0;
            self.cycle = !self.cycle;
        }

        addr
    }

    /// Commit a deferred TRB by flipping its cycle bit to the correct value.
    ///
    /// This is the second half of the "deferred first TRB" technique. After all
    /// TRBs in a TD have been enqueued, call this on the first TRB's address
    /// (returned by `enqueue(..., defer_cycle=true)`) to atomically make the
    /// entire TD visible to the HC.
    ///
    /// The `cycle_at_enqueue` parameter is the ring's cycle state at the time
    /// the deferred TRB was enqueued.
    fn commit_deferred_trb(trb_addr: u64, cycle_at_enqueue: bool) {
        let control_ptr = (trb_addr + 12) as *mut u32;

        // Ensure the whole TD is visible before publishing its first TRB.
        barrier::dma_write();

        let control = unsafe { ptr::read_volatile(control_ptr) };
        let new_control = if cycle_at_enqueue {
            control | 1
        } else {
            control & !1
        };
        unsafe { ptr::write_volatile(control_ptr, new_control) };
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

/// xHCI MMIO region size (64KB should cover all controllers)
const XHCI_MMIO_SIZE: usize = 0x10000;

/// Maximum number of device slots supported.
///
/// The xHCI spec allows up to 255 slots. We use a heapless Vec with this
/// capacity and tell the controller to limit itself accordingly via the
/// CONFIG register. This avoids a separate `max_slots` bookkeeping field
/// and ensures all slot accesses go through bounds-checked `.get()`.
pub const MAX_SLOTS: usize = 16;

/// xHCI Controller
pub struct XhciController {
    /// PCI address (bus:device.function)
    pci_address: PciAddress,
    /// MMIO region (kept alive so the mapping is not dropped)
    #[allow(dead_code)]
    // Retained for the mapping lifetime; register I/O goes through `registers`.
    mmio: MmioRegion,
    /// xHCI register accessors.
    registers: Registers<IdentityMapper>,
    /// Number of ports
    num_ports: u8,
    /// Page size used by controller
    page_size: u32,
    /// Context stride (32 or 64 bytes based on HCCPARAMS1.CSZ)
    context_size: u8,
    /// Device Context Base Address Array
    dcbaa: u64,
    /// Scratchpad buffer array pointer (stored in DCBAA[0])
    scratchpad_array: u64,
    /// Number of scratchpad buffers
    num_scratchpad_bufs: u16,
    /// Command ring
    cmd_ring: TrbRing,
    /// Event ring segment table
    erst: u64,
    /// Event ring
    event_ring: TrbRing,
    /// Active device slots, indexed by slot ID.
    ///
    /// Slot IDs are assigned by the controller (1-based). We pre-fill the Vec
    /// to `MAX_SLOTS` entries (all `None`) so slot IDs map directly to indices.
    /// All accesses use `.get()` / `.get_mut()` to safely handle out-of-range
    /// slot IDs without panicking.
    slots: heapless::Vec<Option<UsbSlot>, MAX_SLOTS>,
}

/// xHCI error type
#[derive(Debug)]
pub enum XhciError {
    /// Controller not ready
    NotReady,
    /// Timeout
    Timeout,
    /// No free slots
    NoFreeSlots,
    /// Command failed
    CommandFailed(Result<event::CompletionCode, u8>),
    /// Allocation failed
    AllocationFailed,
    /// Device not found
    DeviceNotFound,
    /// Transfer failed
    TransferFailed(Result<event::CompletionCode, u8>),
    /// Invalid parameter
    InvalidParameter,
    /// USB transaction error
    UsbError,
    /// Stall error
    StallError,
}

impl XhciController {
    #[inline]
    fn input_context_len(context_size: u8) -> usize {
        context_size as usize * 33 // input control + slot + 31 endpoint contexts
    }

    #[inline]
    fn input_control_context<'a>(
        input: *mut u8,
        context_size: u8,
    ) -> &'a mut dyn InputControlHandler {
        // SAFETY: input points to a page-aligned, zeroed context allocation of
        // the controller-selected upstream 32- or 64-byte Input layout.
        unsafe {
            if context_size == 64 {
                (&mut *(input as *mut context::Input64Byte)).control_mut()
            } else {
                (&mut *(input as *mut context::Input32Byte)).control_mut()
            }
        }
    }

    #[inline]
    fn input_slot_context<'a>(input: *mut u8, context_size: u8) -> &'a mut dyn SlotHandler {
        // SAFETY: same allocation and layout invariant as input_control_context.
        unsafe {
            if context_size == 64 {
                (&mut *(input as *mut context::Input64Byte))
                    .device_mut()
                    .slot_mut()
            } else {
                (&mut *(input as *mut context::Input32Byte))
                    .device_mut()
                    .slot_mut()
            }
        }
    }

    #[inline]
    fn input_ep_context<'a>(
        input: *mut u8,
        context_size: u8,
        ep_index: usize,
    ) -> &'a mut dyn EndpointHandler {
        let dci = ep_index + 1;
        // SAFETY: callers use endpoint indices in 0..31 and the allocation is
        // an upstream Input32Byte or Input64Byte selected by HCCPARAMS1.CSZ.
        unsafe {
            if context_size == 64 {
                (&mut *(input as *mut context::Input64Byte))
                    .device_mut()
                    .endpoint_mut(dci)
            } else {
                (&mut *(input as *mut context::Input32Byte))
                    .device_mut()
                    .endpoint_mut(dci)
            }
        }
    }

    #[inline]
    fn copy_context_payload(dst: *mut u8, src: *const u8) {
        // Only the architected first 32 bytes contain fields. The destination
        // was zeroed, so the reserved upper half of a 64-byte context stays 0.
        unsafe { ptr::copy_nonoverlapping(src, dst, 32) };
    }

    #[inline]
    fn copy_device_slot_context(input: *mut u8, device: *const u8, context_size: u8) {
        let dst = unsafe { input.add(context_size as usize) };
        Self::copy_context_payload(dst, device);
    }

    #[inline]
    fn copy_device_ep_context(
        input: *mut u8,
        device: *const u8,
        context_size: u8,
        ep_index: usize,
    ) {
        let dst = unsafe { input.add((ep_index + 2) * context_size as usize) };
        let src = unsafe { device.add((ep_index + 1) * context_size as usize) };
        Self::copy_context_payload(dst, src);
    }

    /// Take ownership of the controller from BIOS/SMM
    ///
    /// xHCI has an optional extended capability for BIOS ownership handoff.
    /// Unlike EHCI, xHCI extended capabilities are memory-mapped, not in PCI config space.
    /// The xECP (Extended Capabilities Pointer) is in HCCPARAMS1 bits 31:16.
    fn take_bios_ownership(mmio_base: u64, hccparams1: CapabilityParameters1) {
        let Some(mut capabilities) = (unsafe {
            extended_capabilities::List::new(mmio_base as usize, hccparams1, IdentityMapper)
        }) else {
            return;
        };

        for capability in &mut capabilities {
            let Ok(ExtendedCapability::UsbLegacySupport(mut legacy)) = capability else {
                continue;
            };

            if legacy.usblegsup.read_volatile().hc_bios_owned_semaphore() {
                log::debug!("xHCI: Taking ownership from BIOS");
                legacy.usblegsup.update_volatile(|register| {
                    register.set_hc_os_owned_semaphore();
                });

                let timeout = Timeout::from_ms(1000);
                while !timeout.is_expired() {
                    if !legacy.usblegsup.read_volatile().hc_bios_owned_semaphore() {
                        log::debug!("xHCI: BIOS released ownership");
                        break;
                    }
                    crate::time::delay_ms(10);
                }
            }

            legacy.usblegctlsts.update_volatile(|register| {
                register
                    .clear_usb_smi_enable()
                    .clear_smi_on_host_system_error_enable()
                    .clear_smi_on_os_ownership_enable()
                    .clear_smi_on_pci_command_enable()
                    .clear_smi_on_bar_enable()
                    .clear_smi_on_os_ownership_change()
                    .clear_smi_on_pci_command()
                    .clear_smi_on_bar();
            });
            break;
        }
    }

    /// Create a new xHCI controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, XhciError> {
        let mmio_base = pci_dev.mmio_base().ok_or(XhciError::NotReady)?;
        // SAFETY: mmio_base is a PCI BAR address for this xHCI controller,
        // mapped by the platform and valid for the device's lifetime.
        let mmio = unsafe {
            MmioRegion::try_new(mmio_base, XHCI_MMIO_SIZE).map_err(|e| {
                log::error!("xHCI MMIO region invalid at {mmio_base:#x}: {e}");
                XhciError::InvalidParameter
            })?
        };

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        let registers = unsafe {
            Registers::new_with_64bit_access(mmio_base as usize, IdentityMapper, Access64::LowHigh)
        };
        let hciversion = registers.capability.hciversion.read_volatile().get();
        let hccparams1 = registers.capability.hccparams1.read_volatile();
        let hcsparams1 = registers.capability.hcsparams1.read_volatile();
        let hcsparams2 = registers.capability.hcsparams2.read_volatile();

        let context_size = if hccparams1.context_size() { 64 } else { 32 };
        let num_scratchpad_bufs = hcsparams2.max_scratchpad_buffers() as u16;
        Self::take_bios_ownership(mmio_base, hccparams1);

        let num_ports = hcsparams1.number_of_ports();
        let hw_max_slots = hcsparams1.number_of_device_slots();
        // Cap to our Vec capacity
        let max_slots = (hw_max_slots as usize).min(MAX_SLOTS);

        log::info!(
            "xHCI version: {}.{}.{}, ports: {}, slots: {} (hw: {})",
            (hciversion >> 8) & 0xFF,
            (hciversion >> 4) & 0xF,
            hciversion & 0xF,
            num_ports,
            max_slots,
            hw_max_slots,
        );

        let page_size = u32::from(registers.operational.pagesize.read_volatile().get()) << 12;

        log::debug!(
            "xHCI: context_size={}, scratchpad_bufs={}",
            context_size,
            num_scratchpad_bufs
        );

        // Pre-fill slot Vec to max_slots entries (all None) so slot IDs
        // from the controller map directly to Vec indices.
        let mut slots = heapless::Vec::new();
        for _ in 0..max_slots {
            let _ = slots.push(None);
        }

        let mut controller = Self {
            pci_address: pci_dev.address,
            mmio,
            registers,
            num_ports,
            page_size,
            context_size,
            dcbaa: 0,
            scratchpad_array: 0,
            num_scratchpad_bufs,
            cmd_ring: TrbRing::empty(), // Will be initialized in init()
            erst: 0,
            event_ring: TrbRing::empty(), // Will be initialized in init()
            slots,
        };

        controller.init()?;

        // Give USB devices time to connect and be detected
        crate::time::delay_ms(50);

        controller.enumerate_ports()?;

        Ok(controller)
    }

    #[inline]
    fn portsc(&self, port: u8) -> PortStatusAndControlRegister {
        self.registers
            .port_register_set
            .port(port as usize)
            .portsc
            .read_volatile()
    }

    fn prepare_portsc_write(register: &mut PortStatusAndControlRegister) {
        register
            .set_0_port_enabled_disabled()
            .set_0_port_reset()
            .clear_port_link_state_write_strobe()
            .set_0_connect_status_change()
            .set_0_port_enabled_disabled_change()
            .set_0_warm_port_reset_change()
            .set_0_over_current_change()
            .set_0_port_reset_change()
            .set_0_port_link_state_change()
            .set_0_port_config_error_change()
            .set_0_warm_port_reset();
    }

    fn update_portsc<F>(&mut self, port: u8, update: F)
    where
        F: FnOnce(&mut PortStatusAndControlRegister),
    {
        self.registers
            .port_register_set
            .port_mut(port as usize)
            .portsc
            .update_volatile(|register| {
                Self::prepare_portsc_write(register);
                update(register);
            });
    }

    fn clear_port_changes(&mut self, port: u8) {
        self.update_portsc(port, |register| {
            register
                .clear_connect_status_change()
                .clear_port_enabled_disabled_change()
                .clear_warm_port_reset_change()
                .clear_over_current_change()
                .clear_port_reset_change()
                .clear_port_link_state_change()
                .clear_port_config_error_change();
        });
    }

    /// Ring a doorbell
    ///
    /// IMPORTANT: Caller must ensure memory barrier (fence) is executed
    /// before calling this to ensure all TRBs are visible to hardware.
    ///
    /// After writing the doorbell, a readback is performed to flush the PCI
    /// posted write buffer. Without this, the write may sit in a PCIe buffer
    /// and not reach the controller immediately (causing timeouts on some HW).
    /// This follows the Linux kernel's pattern in xhci-ring.c.
    #[inline]
    fn ring_doorbell(&mut self, slot: u8, target: u8) {
        let mut doorbell = Doorbell::default();
        doorbell.set_doorbell_target(target);
        self.registers
            .doorbell
            .write_volatile_at(slot as usize, doorbell);
        let _ = self.registers.doorbell.read_volatile_at(slot as usize);
    }

    /// Initialize the controller
    fn init(&mut self) -> Result<(), XhciError> {
        wait_for(100, || {
            !self
                .registers
                .operational
                .usbsts
                .read_volatile()
                .controller_not_ready()
        });

        self.registers
            .operational
            .usbcmd
            .update_volatile(|command| {
                command.clear_run_stop();
            });
        wait_for(100, || {
            self.registers
                .operational
                .usbsts
                .read_volatile()
                .hc_halted()
        });

        self.registers
            .operational
            .usbcmd
            .update_volatile(|command| {
                command.set_host_controller_reset();
            });
        crate::time::delay_ms(1);
        wait_for(500, || {
            !self
                .registers
                .operational
                .usbcmd
                .read_volatile()
                .host_controller_reset()
                && !self
                    .registers
                    .operational
                    .usbsts
                    .read_volatile()
                    .controller_not_ready()
        });

        self.registers
            .operational
            .usbcmd
            .update_volatile(|command| {
                command.clear_interrupter_enable();
            });
        self.registers.operational.config.update_volatile(|config| {
            config.set_max_device_slots_enabled(self.slots.capacity() as u8);
        });

        // Allocate and set up DCBAA (Device Context Base Address Array)
        // DCBAA[0] is reserved for scratchpad buffer array pointer
        // DCBAA[1..max_slots] are for device context pointers
        let dcbaa_pages = ((self.slots.capacity() as u64 + 1) * 8).div_ceil(4096);
        let dcbaa_mem = efi::allocate_pages(dcbaa_pages).ok_or(XhciError::AllocationFailed)?;
        dcbaa_mem.fill(0);
        self.dcbaa = dcbaa_mem.as_ptr() as u64;

        // Allocate scratchpad buffers if needed
        // This is CRITICAL - many controllers (especially Intel) will fail with HSE
        // (Host System Error) if scratchpad buffers aren't allocated when required.
        if self.num_scratchpad_bufs > 0 {
            log::debug!(
                "xHCI: Allocating {} scratchpad buffers (page_size={})",
                self.num_scratchpad_bufs,
                self.page_size
            );

            // Allocate the scratchpad buffer array (array of u64 pointers)
            let sp_array_size = (self.num_scratchpad_bufs as u64) * 8;
            let sp_array_pages = sp_array_size.div_ceil(4096);
            let sp_array_mem =
                efi::allocate_pages(sp_array_pages).ok_or(XhciError::AllocationFailed)?;
            sp_array_mem.fill(0);
            self.scratchpad_array = sp_array_mem.as_ptr() as u64;

            // Allocate the actual scratchpad buffers (page-aligned, page-sized)
            // Each buffer must be page-aligned according to the controller's page size
            let page_size = self.page_size.max(4096) as usize;
            for i in 0..self.num_scratchpad_bufs as usize {
                // Allocate one page per scratchpad buffer
                let buf_pages = (page_size as u64).div_ceil(4096);
                let buf_mem = efi::allocate_pages(buf_pages).ok_or(XhciError::AllocationFailed)?;
                buf_mem.fill(0);
                let buf_addr = buf_mem.as_ptr() as u64;

                // Store pointer in scratchpad array
                let sp_array_entry = (self.scratchpad_array + (i as u64 * 8)) as *mut u64;
                unsafe {
                    ptr::write_volatile(sp_array_entry, buf_addr);
                }
            }

            // Store scratchpad array pointer in DCBAA[0]
            let dcbaa_entry0 = self.dcbaa as *mut u64;
            unsafe {
                ptr::write_volatile(dcbaa_entry0, self.scratchpad_array);
            }

            log::debug!(
                "xHCI: Scratchpad array at {:#x}, stored in DCBAA[0]",
                self.scratchpad_array
            );
        }

        // Publish DMA structures before programming their MMIO base address.
        barrier::mmio_write();

        let mut dcbaap =
            xhci::registers::operational::DeviceContextBaseAddressArrayPointerRegister::default();
        dcbaap.set(self.dcbaa);
        self.registers.operational.dcbaap.write_volatile(dcbaap);

        // Allocate command ring (256 TRBs)
        let cmd_ring_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        let cmd_ring_base = cmd_ring_mem.as_ptr() as u64;
        self.cmd_ring = TrbRing::new(cmd_ring_base, 256);

        // Set command ring pointer
        self.registers.operational.crcr.update_volatile(|crcr| {
            crcr.set_0_command_stop().set_0_command_abort();
            crcr.set_command_ring_pointer(self.cmd_ring.base);
            if self.cmd_ring.cycle {
                crcr.set_ring_cycle_state();
            } else {
                crcr.clear_ring_cycle_state();
            }
        });

        // Allocate event ring (256 TRBs) - no link TRB for event rings
        let event_ring_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        let event_ring_base = event_ring_mem.as_ptr() as u64;
        self.event_ring = TrbRing::new_event_ring(event_ring_base, 256);

        // Allocate Event Ring Segment Table (ERST)
        let erst_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        erst_mem.fill(0);
        self.erst = erst_mem.as_ptr() as u64;

        // Set up ERST entry (xHCI spec 6.5)
        // Structure: u64 base address, u32 size, u32 reserved
        unsafe {
            let erst_base = self.erst as *mut u64;
            let erst_size = (self.erst + 8) as *mut u32;
            ptr::write_volatile(erst_base, event_ring_base); // Ring Segment Base Address (64-bit)
            ptr::write_volatile(erst_size, 256); // Ring Segment Size (32-bit, number of TRBs)
        }

        {
            let mut interrupter = self.registers.interrupter_register_set.interrupter_mut(0);
            interrupter.erstsz.update_volatile(|erstsz| {
                erstsz.set(1);
            });
            interrupter.erdp.update_volatile(|erdp| {
                erdp.set_event_ring_dequeue_pointer(event_ring_base);
                erdp.clear_event_handler_busy();
            });
            interrupter.erstba.update_volatile(|erstba| {
                erstba.set(self.erst);
            });
            interrupter.iman.update_volatile(|iman| {
                iman.set_0_interrupt_pending().set_interrupt_enable();
            });
        }

        self.registers
            .operational
            .usbcmd
            .update_volatile(|command| {
                command.set_run_stop().set_interrupter_enable();
            });
        wait_for(100, || {
            !self
                .registers
                .operational
                .usbsts
                .read_volatile()
                .hc_halted()
        });

        // Power on all ports - many real hardware controllers require explicit port power
        self.power_on_ports();

        log::info!("xHCI controller initialized");
        Ok(())
    }

    /// Power on all ports
    ///
    /// Many xHCI controllers (especially on real hardware) require explicit
    /// port power enable. Without this, devices won't be detected.
    fn power_on_ports(&mut self) {
        for port in 0..self.num_ports {
            if self.portsc(port).port_power() {
                continue;
            }
            self.update_portsc(port, |portsc| {
                portsc.set_port_power();
            });
            log::debug!("xHCI: Powered on port {}", port);
        }
        crate::time::delay_ms(20);
    }

    /// Wait for and process a command completion event
    fn wait_command_completion(&mut self) -> Result<event::CommandCompletion, XhciError> {
        let timeout = Timeout::from_ms(5000);

        log::debug!(
            "xHCI: Waiting for command, dequeue_idx={}, expect_cycle={}",
            self.event_ring.dequeue_idx,
            self.event_ring.cycle,
        );

        while !timeout.is_expired() {
            let erdp = self.event_ring.base + (self.event_ring.dequeue_idx * trb::BYTES) as u64;
            let raw = read_event_trb(erdp, self.event_ring.cycle);

            if let Some(raw) = raw {
                log::debug!(
                    "xHCI: Got event type={}, cc={}, param={:#x}",
                    raw_trb_type(&raw),
                    raw_completion_code(&raw),
                    u64::from(raw[0]) | (u64::from(raw[1]) << 32)
                );

                self.event_ring.dequeue_idx += 1;
                if self.event_ring.dequeue_idx >= self.event_ring.size {
                    self.event_ring.dequeue_idx = 0;
                    self.event_ring.cycle = !self.event_ring.cycle;
                }
                self.update_erdp();

                match event::Allowed::try_from(raw) {
                    Ok(event::Allowed::CommandCompletion(completion)) => {
                        let completion_code = completion.completion_code();
                        if completion_code == Ok(event::CompletionCode::Success) {
                            return Ok(completion);
                        }
                        return Err(XhciError::CommandFailed(completion_code));
                    }
                    Ok(event::Allowed::PortStatusChange(_)) => continue,
                    Ok(event::Allowed::HostController(host)) => {
                        log::error!(
                            "xHCI: Host Controller Event (fatal HSE), cc={:?}",
                            host.completion_code()
                        );
                        return Err(XhciError::CommandFailed(host.completion_code()));
                    }
                    _ => {}
                }
            }
            core::hint::spin_loop();
        }

        self.update_erdp();
        let usbsts = self.registers.operational.usbsts.read_volatile();
        log::warn!(
            "xHCI: Command timeout, USBSTS={:?}, event_ring[0].control={:#x}",
            usbsts,
            read_event_control(self.event_ring.base)
        );

        Err(XhciError::Timeout)
    }

    /// Wait for transfer completion events
    ///
    /// Each TRB is its own independent TD with IOC=1. CrabEFI keeps its
    /// polling, timeout, and ERDP policy while decoding events upstream.
    fn wait_transfer_completion(
        &mut self,
        _slot: u8,
        _ep: u8,
        expected_trbs: usize,
    ) -> Result<u32, XhciError> {
        let timeout = Timeout::from_ms(5000);
        let mut completed = 0usize;
        let mut total_residual = 0u32;

        while !timeout.is_expired() {
            let erdp = self.event_ring.base + (self.event_ring.dequeue_idx * trb::BYTES) as u64;
            let raw = read_event_trb(erdp, self.event_ring.cycle);

            if let Some(raw) = raw {
                self.event_ring.dequeue_idx += 1;
                if self.event_ring.dequeue_idx >= self.event_ring.size {
                    self.event_ring.dequeue_idx = 0;
                    self.event_ring.cycle = !self.event_ring.cycle;
                }
                self.update_erdp();

                match event::Allowed::try_from(raw) {
                    Ok(event::Allowed::TransferEvent(transfer_event)) => {
                        let residual = transfer_event.trb_transfer_length();
                        let completion_code = transfer_event.completion_code();
                        log::trace!(
                            "xHCI: Transfer event cc={:?} residue={} [{}/{}]",
                            completion_code,
                            residual,
                            completed + 1,
                            expected_trbs
                        );

                        if matches!(
                            completion_code,
                            Ok(event::CompletionCode::Success | event::CompletionCode::ShortPacket)
                        ) {
                            completed += 1;
                            total_residual += residual;
                            if completed >= expected_trbs {
                                return Ok(total_residual);
                            }
                        } else if completion_code == Ok(event::CompletionCode::StallError) {
                            log::debug!(
                                "xHCI: Transfer stalled [{}/{}]",
                                completed + 1,
                                expected_trbs
                            );
                            self.drain_remaining_transfer_events(expected_trbs - completed - 1);
                            return Err(XhciError::StallError);
                        } else {
                            log::debug!(
                                "xHCI: Transfer failed with cc={:?} [{}/{}]",
                                completion_code,
                                completed + 1,
                                expected_trbs
                            );
                            self.drain_remaining_transfer_events(expected_trbs - completed - 1);
                            return Err(XhciError::TransferFailed(completion_code));
                        }
                    }
                    Ok(event::Allowed::HostController(host)) => {
                        log::error!(
                            "xHCI: Host Controller Event (fatal HSE) during transfer, cc={:?}",
                            host.completion_code()
                        );
                        return Err(XhciError::TransferFailed(host.completion_code()));
                    }
                    _ => log::trace!(
                        "xHCI: Got event type {} while waiting for transfer",
                        raw_trb_type(&raw)
                    ),
                }
            }
            core::hint::spin_loop();
        }

        log::warn!(
            "xHCI: Transfer timeout, completed={}/{}, event ring dequeue_idx={}, cycle={}",
            completed,
            expected_trbs,
            self.event_ring.dequeue_idx,
            self.event_ring.cycle
        );
        Err(XhciError::Timeout)
    }

    /// Drain remaining transfer events after an error
    ///
    /// When a multi-TRB transfer fails on one TRB, the controller may have
    /// already queued completion events for subsequent TRBs. These must be
    /// consumed to prevent them from confusing later transfers.
    fn drain_remaining_transfer_events(&mut self, max_events: usize) {
        let timeout = Timeout::from_ms(100); // Short timeout — events should already be there
        let mut drained = 0usize;
        let mut consumed = 0usize;

        while drained < max_events && !timeout.is_expired() {
            let erdp = self.event_ring.base + (self.event_ring.dequeue_idx * trb::BYTES) as u64;
            let raw = read_event_trb(erdp, self.event_ring.cycle);

            if let Some(raw) = raw {
                self.event_ring.dequeue_idx += 1;
                if self.event_ring.dequeue_idx >= self.event_ring.size {
                    self.event_ring.dequeue_idx = 0;
                    self.event_ring.cycle = !self.event_ring.cycle;
                }
                consumed += 1;

                if event::TransferEvent::try_from(raw).is_ok() {
                    drained += 1;
                }
            } else {
                break; // No more events ready
            }
            core::hint::spin_loop();
        }

        if consumed > 0 {
            self.update_erdp();
            log::trace!(
                "xHCI: drained {} orphaned transfer events ({} total consumed)",
                drained,
                consumed
            );
        }
    }

    /// Update the Event Ring Dequeue Pointer (ERDP) in hardware
    ///
    /// This writes the current software dequeue pointer to the interrupter's
    /// ERDP register with the EHB (Event Handler Busy) bit set to clear it.
    /// This is a 64-bit split write (two PCIe MMIO writes), so it should be
    /// called as infrequently as possible.
    #[inline]
    fn update_erdp(&mut self) {
        let new_erdp = self.event_ring.base + (self.event_ring.dequeue_idx * 16) as u64;
        self.registers
            .interrupter_register_set
            .interrupter_mut(0)
            .erdp
            .update_volatile(|erdp| {
                erdp.set_event_ring_dequeue_pointer(new_erdp);
                erdp.clear_event_handler_busy();
            });
    }

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
    fn reset_endpoint(&mut self, slot_id: u8, dci: u8) -> Result<(), XhciError> {
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
    fn enable_slot(&mut self) -> Result<u8, XhciError> {
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
    fn address_device(&mut self, slot_id: u8, port: u8, speed: u8) -> Result<(), XhciError> {
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

    /// Control transfer
    ///
    /// Performs a USB control transfer (Setup -> Data -> Status stages).
    /// Uses the "deferred first TRB" technique: the Setup TRB is initially
    /// written with an inverted cycle bit so the HC won't start processing
    /// until the entire TD (Setup + optional Data + Status) is built.
    /// Automatically recovers from stall errors by resetting the endpoint.
    fn control_transfer(
        &mut self,
        slot_id: u8,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: Option<&mut [u8]>,
    ) -> Result<usize, XhciError> {
        const DCI_EP0: u8 = 1; // Control endpoint is always DCI 1

        let slot = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::DeviceNotFound)?;

        let ring = slot.transfer_rings[0]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        let is_in = (request_type & 0x80) != 0;
        let data_len = data.as_ref().map(|h| h.len()).unwrap_or(0);

        // Save cycle state before enqueuing the first (deferred) TRB
        let first_trb_cycle = ring.cycle;

        // Setup Stage TRB — enqueued with DEFERRED cycle bit
        let mut setup = transfer::SetupStage::new();
        setup
            .set_request_type(request_type)
            .set_request(request)
            .set_value(value)
            .set_index(index)
            .set_length(data_len as u16)
            .set_transfer_type(if data_len == 0 {
                transfer::TransferType::No
            } else if is_in {
                transfer::TransferType::In
            } else {
                transfer::TransferType::Out
            });

        let first_trb_addr = ring.enqueue(setup, true); // defer_cycle = true

        // Data Stage TRB (if needed)
        // Note: We intentionally do NOT set ISP (Interrupt on Short Packet) on the
        // Data Stage TRB. With ISP, a short packet would generate an extra event
        // before the Status Stage's IOC event, but wait_transfer_completion only
        // expects 1 event. The orphaned Status event would corrupt later transfers.
        // EDK2 also relies solely on IOC on the Status Stage TRB.
        if let Some(data_buf) = data {
            let mut data_trb = transfer::DataStage::new();
            data_trb
                .set_data_buffer_pointer(data_buf.as_ptr() as u64)
                .set_trb_transfer_length(data_buf.len() as u32)
                .set_direction(if is_in {
                    transfer::Direction::In
                } else {
                    transfer::Direction::Out
                });

            ring.enqueue(data_trb, false);
        }

        // Status Stage TRB
        let mut status = transfer::StatusStage::new();
        if data_len == 0 || !is_in {
            status.set_direction();
        }
        status.set_interrupt_on_completion();

        ring.enqueue(status, false);

        // Commit the deferred first TRB — atomically makes the entire TD live
        TrbRing::commit_deferred_trb(first_trb_addr, first_trb_cycle);

        // Publish the DMA transfer ring before its MMIO doorbell.
        barrier::mmio_write();
        self.ring_doorbell(slot_id, DCI_EP0);

        // Wait for completion
        match self.wait_transfer_completion(slot_id, 0, 1) {
            Ok(total_residual) => {
                // Return transfer length
                Ok(data_len.saturating_sub(total_residual as usize))
            }
            Err(XhciError::StallError) => {
                // Control endpoint stalled - reset it
                log::debug!(
                    "xHCI: Control transfer stalled on slot={}, resetting endpoint",
                    slot_id
                );
                if let Err(e) = self.reset_endpoint(slot_id, DCI_EP0) {
                    log::warn!(
                        "xHCI: Failed to reset control endpoint after stall: {:?}",
                        e
                    );
                }
                Err(XhciError::StallError)
            }
            Err(e) => Err(e),
        }
    }

    /// Update a full-speed device's EP0 max packet size.
    fn update_full_speed_ep0_max_packet(
        &mut self,
        slot_id: u8,
        max_packet: u16,
    ) -> Result<(), XhciError> {
        if !matches!(max_packet, 8 | 16 | 32 | 64) {
            log::error!("xHCI: invalid full-speed EP0 max packet size {max_packet}");
            return Err(XhciError::InvalidParameter);
        }

        let context_size = self.context_size;
        let input_context = {
            let slot = self
                .slots
                .get_mut(slot_id as usize)
                .and_then(|slot| slot.as_mut())
                .ok_or(XhciError::DeviceNotFound)?;
            let input = slot.input_context;
            unsafe {
                core::ptr::write_bytes(input, 0, Self::input_context_len(context_size));
            }
            Self::copy_device_ep_context(input, slot.device_context, context_size, 0);
            let ep0 = Self::input_ep_context(input, context_size, 0);
            ep0.set_max_packet_size(max_packet);
            Self::input_control_context(input, context_size).set_add_context_flag(1);
            input as u64
        };

        let mut command = command::EvaluateContext::new();
        command
            .set_input_context_pointer(input_context)
            .set_slot_id(slot_id);

        self.cmd_ring.enqueue(command, false);
        barrier::mmio_write();
        self.ring_doorbell(0, 0);
        self.wait_command_completion()?;
        Ok(())
    }

    /// Get the device descriptor.
    fn get_device_descriptor(&mut self, slot_id: u8) -> Result<DeviceDescriptor, XhciError> {
        let mut desc = [0u8; 18];

        // First, get just 8 bytes to determine max packet size.
        let mut short_desc = [0u8; 8];
        self.control_transfer(
            slot_id,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::DEVICE as u16) << 8,
            0,
            Some(&mut short_desc),
        )?;

        let full_speed = self
            .slots
            .get(slot_id as usize)
            .and_then(|slot| slot.as_ref())
            .is_some_and(|slot| slot.speed == 1);
        if full_speed {
            self.update_full_speed_ep0_max_packet(slot_id, short_desc[7] as u16)?;
        }

        // Now get full descriptor
        self.control_transfer(
            slot_id,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::DEVICE as u16) << 8,
            0,
            Some(&mut desc),
        )?;

        // Parse device descriptor using zerocopy
        DeviceDescriptor::read_from_prefix(&desc)
            .map(|(d, _)| d)
            .map_err(|_| XhciError::InvalidParameter)
    }

    /// Set configuration
    fn set_configuration(&mut self, slot_id: u8, config: u8) -> Result<(), XhciError> {
        self.control_transfer(
            slot_id,
            req_type::DIR_OUT | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::SET_CONFIGURATION,
            config as u16,
            0,
            None,
        )?;
        Ok(())
    }

    /// Configure a hub device and enumerate its downstream ports.
    ///
    /// This mirrors the EHCI `enumerate_hub()` logic adapted for xHCI's
    /// route-string-based addressing model.
    fn configure_and_enumerate_hub(
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
    fn evaluate_hub_context(&mut self, slot_id: u8, num_ports: u8) -> Result<(), XhciError> {
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
    fn attach_device_on_hub(
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
    fn enumerate_ports(&mut self) -> Result<(), XhciError> {
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

    /// Fetch and parse the full configuration descriptor for a device
    fn get_config_descriptor(&mut self, slot_id: u8) -> Result<ConfigurationInfo, XhciError> {
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
    fn configure_mass_storage(&mut self, slot_id: u8) -> Result<(), XhciError> {
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
    fn configure_hid_keyboard(&mut self, slot_id: u8) -> Result<(), XhciError> {
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
    fn configure_hid_mouse(&mut self, slot_id: u8) -> Result<(), XhciError> {
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

    /// Perform a single synchronous interrupt IN transfer.
    ///
    /// Queues one Normal TRB on the interrupt endpoint's transfer ring,
    /// rings the doorbell, and waits for the completion event.  Reuses the
    /// existing `wait_transfer_completion` path.
    fn interrupt_transfer_impl(
        &mut self,
        slot_id: u8,
        endpoint: u8,
        data: &mut [u8],
    ) -> Result<usize, XhciError> {
        let in_dci = (endpoint as usize * 2) + 1;

        let slot = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::DeviceNotFound)?;

        let ring = slot.transfer_rings[in_dci - 1]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        // Queue a Normal TRB for the interrupt IN transfer
        let mut trb = transfer::Normal::new();
        trb.set_data_buffer_pointer(data.as_ptr() as u64)
            .set_trb_transfer_length((data.len() as u32) & 0x1ffff)
            .set_interrupt_on_completion()
            .set_interrupt_on_short_packet();

        ring.enqueue(trb, false);
        barrier::mmio_write();
        self.ring_doorbell(slot_id, in_dci as u8);

        // Reuse the existing transfer completion path (expects 1 TRB event).
        let residual = self.wait_transfer_completion(slot_id, endpoint, 1)?;
        let transferred = data.len().saturating_sub(residual as usize);
        Ok(transferred)
    }

    /// Configure bulk endpoints
    fn configure_bulk_endpoints(
        &mut self,
        slot_id: u8,
        bulk_in: u8,
        bulk_out: u8,
        max_packet: u16,
    ) -> Result<(), XhciError> {
        let slot = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::DeviceNotFound)?;

        // Allocate transfer rings for bulk endpoints
        let in_ring_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        let in_ring_addr = in_ring_mem.as_ptr() as u64;
        let out_ring_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        let out_ring_addr = out_ring_mem.as_ptr() as u64;

        let in_ring = TrbRing::new(in_ring_addr, 256);
        let out_ring = TrbRing::new(out_ring_addr, 256);
        let context_size = self.context_size;

        // Calculate DCI (Device Context Index) for endpoints
        // DCI = (Endpoint Number * 2) + Direction (0=OUT, 1=IN)
        let in_dci = (bulk_in as usize * 2) + 1;
        let out_dci = bulk_out as usize * 2;

        // Set up input context
        let input = slot.input_context;
        unsafe {
            core::ptr::write_bytes(input, 0, Self::input_context_len(context_size));
        }

        // Copy slot context from device context
        Self::copy_device_slot_context(input, slot.device_context, context_size);
        let slot_ctx = Self::input_slot_context(input, context_size);
        slot_ctx.set_context_entries(in_dci.max(out_dci) as u8);

        // Set up endpoint contexts
        let control = Self::input_control_context(input, context_size);
        control.set_add_context_flag(0);
        control.set_add_context_flag(in_dci);
        control.set_add_context_flag(out_dci);

        // Bulk IN endpoint
        let in_ep_ctx = Self::input_ep_context(input, context_size, in_dci - 1);
        in_ep_ctx.set_endpoint_type(EndpointType::BulkIn);
        in_ep_ctx.set_max_packet_size(max_packet);
        in_ep_ctx.set_max_burst_size(0);
        in_ep_ctx.set_error_count(3);
        in_ep_ctx.set_tr_dequeue_pointer(in_ring_addr);
        in_ep_ctx.set_dequeue_cycle_state();
        in_ep_ctx.set_average_trb_length(max_packet);

        // Bulk OUT endpoint
        let out_ep_ctx = Self::input_ep_context(input, context_size, out_dci - 1);
        out_ep_ctx.set_endpoint_type(EndpointType::BulkOut);
        out_ep_ctx.set_max_packet_size(max_packet);
        out_ep_ctx.set_max_burst_size(0);
        out_ep_ctx.set_error_count(3);
        out_ep_ctx.set_tr_dequeue_pointer(out_ring_addr);
        out_ep_ctx.set_dequeue_cycle_state();
        out_ep_ctx.set_average_trb_length(max_packet);

        // Store rings
        slot.transfer_rings[in_dci - 1] = Some(in_ring);
        slot.transfer_rings[out_dci - 1] = Some(out_ring);

        // Send Configure Endpoint command
        let mut command = command::ConfigureEndpoint::new();
        command
            .set_input_context_pointer(slot.input_context as u64)
            .set_slot_id(slot_id);

        self.cmd_ring.enqueue(command, false);
        barrier::mmio_write();
        self.ring_doorbell(0, 0);

        self.wait_command_completion()?;

        Ok(())
    }

    /// Bulk transfer
    ///
    /// Large requests are submitted as a sequence of independent 64 KiB TDs.
    /// Only one TD is visible to the controller at a time, so a short packet
    /// ends the request before a later TD can consume the following BOT CSW.
    /// This retains large SCSI commands without relying on chained xHCI TRBs.
    pub fn bulk_transfer(
        &mut self,
        slot_id: u8,
        ep: u8,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<usize, XhciError> {
        const TD_MAX_TRANSFER_SIZE: usize = 0x10000;

        let dci = if is_in {
            (ep as usize * 2) + 1
        } else {
            ep as usize * 2
        };

        log::trace!(
            "xHCI: bulk_transfer slot={} ep={} dci={} dir={} len={} addr={:#x}",
            slot_id,
            ep,
            dci,
            if is_in { "IN" } else { "OUT" },
            data.len(),
            data.as_ptr() as u64
        );

        let mut transferred_total = 0usize;
        while transferred_total < data.len() {
            let chunk_end = (transferred_total + TD_MAX_TRANSFER_SIZE).min(data.len());
            let chunk = &mut data[transferred_total..chunk_end];
            self.queue_bulk_trb(slot_id, dci, is_in, chunk)?;

            barrier::mmio_write();
            self.ring_doorbell(slot_id, dci as u8);

            match self.wait_transfer_completion(slot_id, ep, 1) {
                Ok(residual) => {
                    let transferred = chunk.len().saturating_sub(residual as usize);
                    transferred_total += transferred;
                    if transferred < chunk.len() {
                        log::trace!(
                            "xHCI: bulk transfer ended on short packet, transferred={}/{}",
                            transferred_total,
                            data.len()
                        );
                        return Ok(transferred_total);
                    }
                }
                Err(XhciError::StallError) => {
                    log::debug!(
                        "xHCI: Bulk transfer stalled on slot={} dci={}, resetting endpoint",
                        slot_id,
                        dci
                    );
                    if let Err(e) = self.reset_endpoint(slot_id, dci as u8) {
                        log::warn!("xHCI: Failed to reset endpoint after stall: {:?}", e);
                    }
                    return Err(XhciError::StallError);
                }
                Err(XhciError::TransferFailed(Ok(
                    cc @ (event::CompletionCode::BabbleDetectedError
                    | event::CompletionCode::UsbTransactionError),
                ))) => {
                    log::debug!(
                        "xHCI: Bulk transfer failed with {:?} on slot={} dci={}, resetting endpoint",
                        cc,
                        slot_id,
                        dci
                    );
                    if let Err(e) = self.reset_endpoint(slot_id, dci as u8) {
                        log::warn!(
                            "xHCI: Failed to reset endpoint after completion code {:?}: {:?}",
                            cc,
                            e
                        );
                    }
                    return Err(XhciError::TransferFailed(Ok(cc)));
                }
                Err(e) => return Err(e),
            }
        }

        log::trace!(
            "xHCI: bulk transfer complete, transferred={}",
            transferred_total
        );
        Ok(transferred_total)
    }

    /// Queue one independent bulk TD.
    ///
    /// Keeping the TD to one 64 KiB TRB avoids the chained-TRB interactions
    /// that cause BABBLE on some Intel xHCI controllers.
    fn queue_bulk_trb(
        &mut self,
        slot_id: u8,
        dci: usize,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<(), XhciError> {
        debug_assert!(data.len() <= 0x10000);

        let slot = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::DeviceNotFound)?;

        let ring = slot.transfer_rings[dci - 1]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        let mut trb = transfer::Normal::new();
        trb.set_data_buffer_pointer(data.as_ptr() as u64)
            .set_trb_transfer_length(data.len() as u32)
            .set_interrupt_on_completion();
        if is_in {
            trb.set_interrupt_on_short_packet();
        }

        ring.enqueue(trb, false);
        log::trace!("xHCI: queued {}B bulk TD", data.len());
        Ok(())
    }

    /// Find a mass storage device
    pub fn find_mass_storage(&self) -> Option<u8> {
        self.slots.iter().enumerate().find_map(|(slot_id, slot)| {
            slot.as_ref()
                .filter(|s| s.is_mass_storage)
                .map(|_| slot_id as u8)
        })
    }

    /// Get slot info
    pub fn get_slot(&self, slot_id: u8) -> Option<&UsbSlot> {
        self.slots.get(slot_id as usize).and_then(|s| s.as_ref())
    }

    /// Get mutable slot info
    pub fn get_slot_mut(&mut self, slot_id: u8) -> Option<&mut UsbSlot> {
        self.slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
    }

    /// Get the PCI address of this controller
    pub fn pci_address(&self) -> PciAddress {
        self.pci_address
    }

    /// Clean up the controller before handing off to the OS
    ///
    /// This must be called before ExitBootServices to ensure Linux's xHCI
    /// driver can properly initialize the controller.
    pub fn cleanup(&mut self) {
        log::debug!("xHCI cleanup: stopping controller");

        self.registers
            .operational
            .usbcmd
            .update_volatile(|command| {
                command.clear_run_stop();
            });
        wait_for(100, || {
            self.registers
                .operational
                .usbsts
                .read_volatile()
                .hc_halted()
        });

        self.registers
            .operational
            .usbcmd
            .update_volatile(|command| {
                command.set_host_controller_reset();
            });
        wait_for(500, || {
            !self
                .registers
                .operational
                .usbcmd
                .read_volatile()
                .host_controller_reset()
                && !self
                    .registers
                    .operational
                    .usbsts
                    .read_volatile()
                    .controller_not_ready()
        });

        log::debug!("xHCI cleanup complete");
    }
}

// SAFETY: XhciController contains DMA buffer pointers managed by the EFI page allocator.
// The MMIO accessors and DMA buffers are:
// 1. Backed by addresses that remain valid for the controller's lifetime
// 2. Properly aligned and DMA-accessible
// 3. Accessed only through the UsbControllerHandle abstraction which serializes access
// The firmware is single-threaded and interrupts are disabled during USB operations.
unsafe impl Send for XhciController {}

// SAFETY: UsbSlot contains raw pointers to device/input contexts allocated via EFI.
// These DMA buffers remain valid for the slot's lifetime and are only accessed
// through the parent XhciController. Single-threaded firmware ensures no races.
unsafe impl Send for UsbSlot {}

// ============================================================================
// Helper functions for trait implementation (avoid name collision)
// ============================================================================

/// Perform a control transfer on an xHCI controller
///
/// This is a helper function to allow calling from the UsbController trait implementation
/// without method name collision.
pub fn do_control_transfer(
    controller: &mut XhciController,
    slot_id: u8,
    request_type: u8,
    request: u8,
    value: u16,
    index: u16,
    data: Option<&mut [u8]>,
) -> Result<usize, XhciError> {
    controller.control_transfer(slot_id, request_type, request, value, index, data)
}

/// Perform a bulk transfer on an xHCI controller
///
/// This is a helper function to allow calling from the UsbController trait implementation
/// without method name collision.
pub fn do_bulk_transfer(
    controller: &mut XhciController,
    slot_id: u8,
    endpoint: u8,
    is_in: bool,
    data: &mut [u8],
) -> Result<usize, XhciError> {
    controller.bulk_transfer(slot_id, endpoint, is_in, data)
}

/// Perform an interrupt IN transfer on an xHCI controller
pub fn do_interrupt_transfer(
    controller: &mut XhciController,
    slot_id: u8,
    endpoint: u8,
    data: &mut [u8],
) -> Result<usize, XhciError> {
    controller.interrupt_transfer_impl(slot_id, endpoint, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn event_trb_read_requires_expected_cycle_and_returns_coherent_raw() {
        let expected = [
            0x11,
            0x22,
            0x33,
            (trb::Type::TransferEvent as u32) << 10 | 1,
        ];

        assert_eq!(
            read_event_trb(expected.as_ptr() as u64, true),
            Some(expected)
        );
        assert_eq!(read_event_trb(expected.as_ptr() as u64, false), None);
    }

    #[test]
    fn upstream_context_and_trb_layouts_match_xhci_dma_layouts() {
        assert_eq!(size_of::<context::Slot32Byte>(), 32);
        assert_eq!(size_of::<context::Slot64Byte>(), 64);
        assert_eq!(size_of::<context::Endpoint32Byte>(), 32);
        assert_eq!(size_of::<context::Endpoint64Byte>(), 64);
        assert_eq!(size_of::<context::Device32Byte>(), 32 * 32);
        assert_eq!(size_of::<context::Device64Byte>(), 64 * 32);
        assert_eq!(size_of::<context::Input32Byte>(), 32 * 33);
        assert_eq!(size_of::<context::Input64Byte>(), 64 * 33);
        assert_eq!(size_of::<command::AddressDevice>(), trb::BYTES);
        assert_eq!(size_of::<transfer::Normal>(), trb::BYTES);
        assert_eq!(size_of::<event::TransferEvent>(), trb::BYTES);
    }

    #[test]
    fn upstream_builders_encode_command_transfer_and_context_fields() {
        let mut address = command::AddressDevice::new();
        address.set_input_context_pointer(0x4000).set_slot_id(7);
        let raw = address.into_raw();
        assert_eq!(raw_trb_type(&raw), trb::Type::AddressDevice as u32);
        assert_eq!(u64::from(raw[0]) | (u64::from(raw[1]) << 32), 0x4000);
        assert_eq!(raw[3] >> 24, 7);

        let mut normal = transfer::Normal::new();
        normal
            .set_data_buffer_pointer(0x1234_5678)
            .set_trb_transfer_length(4096)
            .set_interrupt_on_completion();
        let raw = normal.into_raw();
        assert_eq!(raw_trb_type(&raw), trb::Type::Normal as u32);
        assert_eq!(raw[2] & 0x1ffff, 4096);
        assert_ne!(raw[3] & (1 << 5), 0);

        let mut input = context::Input64Byte::new_64byte();
        input.control_mut().set_add_context_flag(1);
        let slot = input.device_mut().slot_mut();
        slot.set_speed(4);
        slot.set_root_hub_port_number(2);
        assert!(input.control().add_context_flag(1));
        assert_eq!(input.device().slot().speed(), 4);
        assert_eq!(input.device().slot().root_hub_port_number(), 2);
    }
}

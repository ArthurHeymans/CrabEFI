//! xHCI (USB 3.0) Host Controller Interface driver
//!
//! This module provides a minimal xHCI driver for USB mass storage devices.

use crate::drivers::mmio::MmioRegion;
use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi;
use crate::time::{Timeout, wait_for};
use core::ptr;
use core::sync::atomic::{Ordering, fence};
use zerocopy::FromBytes;

use super::controller::{DeviceDescriptor, desc_type, parse_configuration, req_type, request};

// Import all constants from xhci_regs
use super::xhci_regs::{
    // Capability register offsets
    CAP_CAPLENGTH,
    CAP_DBOFF,
    CAP_HCCPARAMS1,
    CAP_HCSPARAMS1,
    CAP_HCSPARAMS2,
    CAP_RTSOFF,
    // Operational register offsets
    OP_CONFIG,
    OP_CRCR,
    OP_DCBAAP,
    OP_PAGESIZE,
    OP_USBCMD,
    OP_USBSTS,
    // Port register offsets
    PORT_PORTSC,
    // PORTSC register bits
    PORTSC_CCS,
    PORTSC_CHANGE_MASK,
    PORTSC_PED,
    PORTSC_PLS_MASK,
    PORTSC_PLS_POLLING,
    PORTSC_PLS_RXDETECT,
    PORTSC_PLS_U0,
    PORTSC_PP,
    PORTSC_PR,
    PORTSC_PRC,
    PORTSC_RW_MASK,
    PORTSC_SPEED_MASK,
    PORTSC_WPR,
    PORTSC_WRC,
    TRB_CC_BABBLE_DETECTED,
    TRB_CC_SHORT_PACKET,
    TRB_CC_STALL_ERROR,
    TRB_CC_SUCCESS,
    TRB_CC_USB_TRANSACTION_ERROR,
    // TRB types
    TRB_TYPE_ADDRESS_DEVICE,
    TRB_TYPE_COMMAND_COMPLETION,
    TRB_TYPE_CONFIGURE_ENDPOINT,
    TRB_TYPE_DATA,
    TRB_TYPE_ENABLE_SLOT,
    TRB_TYPE_HOST_CONTROLLER,
    TRB_TYPE_LINK,
    TRB_TYPE_NORMAL,
    TRB_TYPE_PORT_STATUS_CHANGE,
    TRB_TYPE_RESET_ENDPOINT,
    TRB_TYPE_SET_TR_DEQUEUE,
    TRB_TYPE_SETUP,
    TRB_TYPE_STATUS,
    TRB_TYPE_TRANSFER_EVENT,
    // USBCMD register bits
    USBCMD_HCRST,
    USBCMD_INTE,
    USBCMD_RS,
    // USBSTS register bits
    USBSTS_CNR,
    USBSTS_HCH,
    // TRB completion codes
    trb_cc_name,
};

// NOTE: USB descriptor types (DeviceDescriptor, ConfigurationDescriptor, etc.)
// and USB constants (req_type, request, desc_type) are imported from
// super::controller to avoid duplication with EHCI/OHCI/UHCI drivers.

/// Transfer Request Block (16 bytes)
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
pub struct Trb {
    pub param: u64,
    pub status: u32,
    pub control: u32,
}

impl Trb {
    fn set_type(&mut self, trb_type: u32) {
        self.control = (self.control & !0xFC00) | ((trb_type & 0x3F) << 10);
    }

    fn get_type(&self) -> u32 {
        (self.control >> 10) & 0x3F
    }

    fn get_cycle(&self) -> bool {
        self.control & 1 != 0
    }

    fn completion_code(&self) -> u32 {
        (self.status >> 24) & 0xFF
    }

    fn slot_id(&self) -> u8 {
        ((self.control >> 24) & 0xFF) as u8
    }
}

/// Slot Context (32 bytes)
///
/// Note: Some xHCI controllers use 64-byte contexts (HCCPARAMS1.CSZ=1).
/// This structure assumes 32-byte contexts. Controllers with CSZ=1 may not work.
#[repr(C, align(32))]
#[derive(Clone, Copy, Default)]
pub struct SlotContext {
    pub dw0: u32, // Route String, Speed, MTT, Hub, Context Entries
    pub dw1: u32, // Max Exit Latency, Root Hub Port Number, Number of Ports
    pub dw2: u32, // Parent Hub Slot ID, Parent Port Number, TT Think Time, Interrupter Target
    pub dw3: u32, // USB Device Address, Slot State
    pub reserved: [u32; 4],
}

impl SlotContext {
    fn set_context_entries(&mut self, entries: u8) {
        self.dw0 = (self.dw0 & !0xF8000000) | ((entries as u32) << 27);
    }

    fn set_speed(&mut self, speed: u8) {
        self.dw0 = (self.dw0 & !0x00F00000) | ((speed as u32) << 20);
    }

    fn set_root_hub_port(&mut self, port: u8) {
        self.dw1 = (self.dw1 & !0x00FF0000) | ((port as u32) << 16);
    }
}

/// Endpoint Context (32 bytes)
#[repr(C, align(32))]
#[derive(Clone, Copy, Default)]
pub struct EndpointContext {
    pub dw0: u32,            // EP State, Mult, MaxPStreams, LSA, Interval, MaxESITPayloadHi
    pub dw1: u32,            // CErr, EP Type, HID, MaxBurstSize, MaxPacketSize
    pub tr_dequeue_ptr: u64, // TR Dequeue Pointer
    pub dw4: u32,            // Average TRB Length, MaxESITPayloadLo
    pub reserved: [u32; 3],
}

impl EndpointContext {
    fn set_ep_type(&mut self, ep_type: u8) {
        self.dw1 = (self.dw1 & !0x00000038) | ((ep_type as u32) << 3);
    }

    fn set_max_packet_size(&mut self, size: u16) {
        self.dw1 = (self.dw1 & !0xFFFF0000) | ((size as u32) << 16);
    }

    fn set_max_burst_size(&mut self, size: u8) {
        self.dw1 = (self.dw1 & !0x0000FF00) | ((size as u32) << 8);
    }

    fn set_cerr(&mut self, cerr: u8) {
        self.dw1 = (self.dw1 & !0x00000006) | ((cerr as u32) << 1);
    }

    fn set_tr_dequeue_ptr(&mut self, ptr: u64, dcs: bool) {
        self.tr_dequeue_ptr = (ptr & !0xF) | if dcs { 1 } else { 0 };
    }

    fn set_avg_trb_length(&mut self, len: u16) {
        self.dw4 = (self.dw4 & !0x0000FFFF) | (len as u32);
    }
}

/// Input Control Context (32 bytes)
#[repr(C, align(32))]
#[derive(Clone, Copy, Default)]
pub struct InputControlContext {
    pub drop_flags: u32,
    pub add_flags: u32,
    pub reserved: [u32; 5],
    pub configuration_value: u8,
    pub interface_number: u8,
    pub alternate_setting: u8,
    pub reserved2: u8,
}

/// Device Context (consists of Slot + 31 Endpoint Contexts)
#[repr(C, align(64))]
#[derive(Default)]
pub struct DeviceContext {
    pub slot: SlotContext,
    pub endpoints: [EndpointContext; 31],
}

/// Input Context (Input Control + Device Context)
#[repr(C, align(64))]
#[derive(Default)]
pub struct InputContext {
    pub control: InputControlContext,
    pub slot: SlotContext,
    pub endpoints: [EndpointContext; 31],
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

        // Set up link TRB at the end to wrap around
        let link_trb = unsafe { &mut *((base + ((size - 1) * 16) as u64) as *mut Trb) };
        link_trb.param = base;
        link_trb.set_type(TRB_TYPE_LINK);
        link_trb.control |= 1 << 1; // Toggle Cycle bit

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
    fn enqueue(&mut self, trb: &Trb, defer_cycle: bool) -> u64 {
        let addr = self.base + (self.enqueue_idx * 16) as u64;
        let entry = unsafe { &mut *(addr as *mut Trb) };

        // Determine the cycle bit for this TRB
        let cycle_bit = if defer_cycle {
            // Inverted cycle: HC will NOT process this TRB yet
            if self.cycle { 0 } else { 1 }
        } else {
            if self.cycle { 1 } else { 0 }
        };

        // Write param and status FIRST (these don't contain the ownership bit)
        unsafe {
            core::ptr::write_volatile(&mut entry.param as *mut u64, trb.param);
            core::ptr::write_volatile(&mut entry.status as *mut u32, trb.status);
        }

        // Write barrier: ensure param/status are visible before the cycle bit
        fence(Ordering::Release);

        // Write control LAST (contains the cycle bit that signals HC ownership)
        unsafe {
            core::ptr::write_volatile(
                &mut entry.control as *mut u32,
                (trb.control & !1) | cycle_bit,
            );
        }

        self.enqueue_idx += 1;

        // Check if we need to wrap around via link TRB
        if self.enqueue_idx >= self.size - 1 {
            // Activate the link TRB's cycle bit to hand it to the HC
            let link = unsafe { &mut *((self.base + ((self.size - 1) * 16) as u64) as *mut Trb) };
            fence(Ordering::Release);
            if self.cycle {
                unsafe {
                    core::ptr::write_volatile(&mut link.control as *mut u32, link.control | 1)
                };
            } else {
                unsafe {
                    core::ptr::write_volatile(&mut link.control as *mut u32, link.control & !1)
                };
            }
            fence(Ordering::Release);

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
        let entry = unsafe { &mut *(trb_addr as *mut Trb) };

        // Write barrier: ensure all subsequent TRBs are visible first
        fence(Ordering::Release);

        // Flip the cycle bit to the correct value
        let control = unsafe { core::ptr::read_volatile(&entry.control as *const u32) };
        let new_control = if cycle_at_enqueue {
            control | 1
        } else {
            control & !1
        };
        unsafe {
            core::ptr::write_volatile(&mut entry.control as *mut u32, new_control);
        }
    }

    fn physical_addr(&self) -> u64 {
        self.base | if self.cycle { 1 } else { 0 }
    }
}

/// USB device slot
pub struct UsbSlot {
    /// Slot ID
    pub slot_id: u8,
    /// Device context
    pub device_context: *mut DeviceContext,
    /// Input context
    pub input_context: *mut InputContext,
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
    /// Interrupt IN endpoint for HID
    pub interrupt_in_ep: u8,
    /// Max packet size for interrupt endpoint
    pub interrupt_max_packet: u16,
    /// Polling interval for interrupt endpoint (in ms)
    pub interrupt_interval: u8,
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
    /// Capability registers MMIO region (kept for potential future use)
    #[allow(dead_code)]
    cap_regs: MmioRegion,
    /// Operational registers MMIO region
    op_regs: MmioRegion,
    /// Runtime registers MMIO region
    rt_regs: MmioRegion,
    /// Doorbell registers MMIO region
    db_regs: MmioRegion,
    /// Port registers MMIO region
    port_regs: MmioRegion,
    /// Number of ports
    num_ports: u8,
    /// Page size used by controller
    page_size: u32,
    /// Context size (32 or 64 bytes based on HCCPARAMS1.CSZ)
    /// Currently only 32-byte contexts are fully supported.
    #[allow(dead_code)]
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
    CommandFailed(u32),
    /// Allocation failed
    AllocationFailed,
    /// Device not found
    DeviceNotFound,
    /// Transfer failed
    TransferFailed(u32),
    /// Invalid parameter
    InvalidParameter,
    /// USB transaction error
    UsbError,
    /// Stall error
    StallError,
}

impl XhciController {
    /// xHCI Extended Capability: USB Legacy Support
    const XHCI_CAP_LEGACY: u8 = 0x01;

    /// USBLEGSUP register offsets (within the extended capability)
    const USBLEGSUP_BIOS_OWNED: u32 = 1 << 16;
    const USBLEGSUP_OS_OWNED: u32 = 1 << 24;

    /// Take ownership of the controller from BIOS/SMM
    ///
    /// xHCI has an optional extended capability for BIOS ownership handoff.
    /// Unlike EHCI, xHCI extended capabilities are memory-mapped, not in PCI config space.
    /// The xECP (Extended Capabilities Pointer) is in HCCPARAMS1 bits 31:16.
    fn take_bios_ownership(mmio_base: u64, hccparams1: u32) {
        // xECP is in bits 31:16, gives offset in DWORDs from mmio_base
        let xecp = ((hccparams1 >> 16) & 0xFFFF) as u64;

        if xecp == 0 {
            // No extended capabilities
            return;
        }

        let mut cap_addr = mmio_base + (xecp * 4);

        // Walk the capability chain looking for USBLEGSUP (cap ID 0x01)
        loop {
            let cap = unsafe { ptr::read_volatile(cap_addr as *const u32) };
            let cap_id = (cap & 0xFF) as u8;
            let next_ptr = ((cap >> 8) & 0xFF) as u8;

            if cap_id == Self::XHCI_CAP_LEGACY {
                // Found USBLEGSUP - check if BIOS owns it
                if (cap & Self::USBLEGSUP_BIOS_OWNED) != 0 {
                    log::debug!("xHCI: Taking ownership from BIOS (USBLEGSUP={:#010x})", cap);

                    // Set OS owned semaphore
                    unsafe {
                        ptr::write_volatile(cap_addr as *mut u32, cap | Self::USBLEGSUP_OS_OWNED);
                    }

                    // Wait for BIOS to release (up to 1 second)
                    let timeout = Timeout::from_ms(1000);
                    while !timeout.is_expired() {
                        let new_cap = unsafe { ptr::read_volatile(cap_addr as *const u32) };
                        if (new_cap & Self::USBLEGSUP_BIOS_OWNED) == 0 {
                            log::debug!("xHCI: BIOS released ownership");
                            break;
                        }
                        crate::time::delay_ms(10);
                    }

                    // Clear any SMI enables and pending SMI status in USBLEGCTLSTS (offset +4)
                    // Following Linux kernel's usb_disable_xhci_ports() pattern:
                    //
                    // USBLEGCTLSTS layout:
                    //   Bits 0-4: SMI Enable bits (clear these to 0 to disable SMIs)
                    //   Bits 13-15: Reserved/preserved bits
                    //   Bits 16-20: SMI Event bits (preserved by read)
                    //   Bits 29-31: SMI on OS/BIOS ownership change status (W1C, write 1 to clear)
                    //
                    // We disable all SMI enables (clear bits 0-4) AND clear any pending
                    // SMI event status (write 1 to bits 29-31). The old code only cleared
                    // enables but left stale status bits set.
                    let ctlsts_addr = cap_addr + 4;
                    let ctlsts = unsafe { ptr::read_volatile(ctlsts_addr as *const u32) };
                    // Preserve reserved bits (13:15, 17:19), clear SMI enables (0:4),
                    // clear SMI event status bits 29:31 by writing 1
                    let new_ctlsts = (ctlsts & 0x0000_E000) | 0xE000_0000;
                    unsafe {
                        ptr::write_volatile(ctlsts_addr as *mut u32, new_ctlsts);
                    }
                }
                break;
            }

            if next_ptr == 0 {
                break;
            }
            // next_ptr is a RELATIVE offset from the current capability (in DWORDs)
            cap_addr += next_ptr as u64 * 4;
        }
    }

    /// Create a new xHCI controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, XhciError> {
        let mmio_base = pci_dev.mmio_base().ok_or(XhciError::NotReady)?;
        let mmio = MmioRegion::new(mmio_base, XHCI_MMIO_SIZE);

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        // Read capability registers using MmioRegion
        // First DWORD contains CAPLENGTH and HCIVERSION
        let cap_dword0 = mmio.read32(CAP_CAPLENGTH as u64);
        let caplength = (cap_dword0 & 0xFF) as u8;
        let hciversion = ((cap_dword0 >> 16) & 0xFFFF) as u16;

        let hcsparams1 = mmio.read32(CAP_HCSPARAMS1 as u64);
        let hcsparams2 = mmio.read32(CAP_HCSPARAMS2 as u64);
        let hccparams1 = mmio.read32(CAP_HCCPARAMS1 as u64);
        let dboff = mmio.read32(CAP_DBOFF as u64);
        let rtsoff = mmio.read32(CAP_RTSOFF as u64);

        // Determine context size from HCCPARAMS1.CSZ (bit 2)
        // 0 = 32 bytes, 1 = 64 bytes
        let context_size: u8 = if (hccparams1 & (1 << 2)) != 0 { 64 } else { 32 };

        // Reject controllers that require 64-byte contexts.
        // Our SlotContext, EndpointContext, InputContext, and DeviceContext structs
        // are all defined with 32-byte contexts. Using them on a CSZ=1 controller
        // would cause every offset calculation to be wrong, leading to silent
        // corruption and controller misbehavior.
        if context_size == 64 {
            log::error!(
                "xHCI: Controller requires 64-byte contexts (CSZ=1), which is not yet supported"
            );
            return Err(XhciError::NotReady);
        }

        // Get max scratchpad buffers from HCSPARAMS2
        // Bits 21-25: Max Scratchpad Buffers Hi
        // Bits 27-31: Max Scratchpad Buffers Lo
        let max_sp_hi = ((hcsparams2 >> 21) & 0x1F) as u16;
        let max_sp_lo = ((hcsparams2 >> 27) & 0x1F) as u16;
        let num_scratchpad_bufs = (max_sp_hi << 5) | max_sp_lo;

        // Take ownership from BIOS/SMM before doing anything else
        Self::take_bios_ownership(mmio_base, hccparams1);

        // Calculate register region offsets
        let op_offset = caplength as u64;
        let rt_offset = (rtsoff & !0x1F) as u64;
        let db_offset = (dboff & !0x3) as u64;
        let port_offset = op_offset + 0x400;

        let num_ports = ((hcsparams1 >> 24) & 0xFF) as u8;
        let hw_max_slots = (hcsparams1 & 0xFF) as u8;
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

        // Create MMIO subregions for each register area
        let cap_regs_region = mmio;
        let op_regs_region =
            MmioRegion::new(mmio_base + op_offset, XHCI_MMIO_SIZE - op_offset as usize);
        let rt_regs_region = MmioRegion::new(mmio_base + rt_offset, 0x1000);
        let db_regs_region = MmioRegion::new(mmio_base + db_offset, 0x1000);
        let port_regs_region =
            MmioRegion::new(mmio_base + port_offset, (num_ports as usize) * 0x10);

        // Read page size from operational registers
        let page_size_reg = op_regs_region.read32(OP_PAGESIZE as u64);
        let page_size = (page_size_reg & 0xFFFF) << 12;

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
            cap_regs: cap_regs_region,
            op_regs: op_regs_region,
            rt_regs: rt_regs_region,
            db_regs: db_regs_region,
            port_regs: port_regs_region,
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

    /// Read operational register
    #[inline]
    fn read_op_reg(&self, offset: u32) -> u32 {
        self.op_regs.read32(offset as u64)
    }

    /// Write operational register
    #[inline]
    fn write_op_reg(&self, offset: u32, value: u32) {
        self.op_regs.write32(offset as u64, value)
    }

    /// Read 64-bit operational register
    #[inline]
    fn read_op_reg64(&self, offset: u32) -> u64 {
        self.op_regs.read64(offset as u64)
    }

    /// Write 64-bit operational register (split into two 32-bit writes, lo first)
    ///
    /// The xHCI spec mandates that 64-bit registers (CRCR, DCBAAP) be written
    /// as two 32-bit writes. Many controllers don't support atomic 64-bit MMIO
    /// writes across the PCIe bus.
    #[inline]
    fn write_op_reg64(&self, offset: u32, value: u64) {
        self.op_regs.write64_lo_hi(offset as u64, value)
    }

    /// Read port register
    #[inline]
    fn read_port_reg(&self, port: u8, offset: u32) -> u32 {
        self.port_regs.read32((port as u64 * 0x10) + offset as u64)
    }

    /// Write port register
    #[inline]
    fn write_port_reg(&self, port: u8, offset: u32, value: u32) {
        self.port_regs
            .write32((port as u64 * 0x10) + offset as u64, value)
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
    fn ring_doorbell(&self, slot: u8, target: u8) {
        // The memory barrier should be done by caller before this point
        // to ensure TRBs are written to memory before the doorbell signals
        // the controller to read them.
        let offset = slot as u64 * 4;
        self.db_regs.write32(offset, target as u32);
        // Readback to flush PCI posted write
        let _ = self.db_regs.read32(offset);
    }

    /// Read interrupter register
    #[inline]
    fn read_interrupter_reg(&self, offset: u32) -> u32 {
        // Interrupter 0 is at offset 0x20 within runtime registers
        self.rt_regs.read32(0x20 + offset as u64)
    }

    /// Write interrupter register
    #[inline]
    fn write_interrupter_reg(&self, offset: u32, value: u32) {
        // Interrupter 0 is at offset 0x20 within runtime registers
        self.rt_regs.write32(0x20 + offset as u64, value)
    }

    /// Write 64-bit interrupter register (split into two 32-bit writes, lo first)
    ///
    /// The xHCI spec mandates that 64-bit registers (ERSTBA, ERDP) be written
    /// as two 32-bit writes. Many controllers don't support atomic 64-bit MMIO
    /// writes across the PCIe bus.
    #[inline]
    fn write_interrupter_reg64(&self, offset: u32, value: u64) {
        self.rt_regs.write64_lo_hi(0x20 + offset as u64, value)
    }

    /// Initialize the controller
    fn init(&mut self) -> Result<(), XhciError> {
        // Wait for controller to be ready (up to 100ms)
        wait_for(100, || self.read_op_reg(OP_USBSTS) & USBSTS_CNR == 0);

        // Stop the controller
        let cmd = self.read_op_reg(OP_USBCMD);
        self.write_op_reg(OP_USBCMD, cmd & !USBCMD_RS);

        // Wait for halt (up to 100ms)
        wait_for(100, || self.read_op_reg(OP_USBSTS) & USBSTS_HCH != 0);

        // Reset the controller
        self.write_op_reg(OP_USBCMD, USBCMD_HCRST);

        // Intel xHCI controllers require a 1ms delay after setting HCRST
        // before accessing any HC registers (prevents rare system hangs)
        crate::time::delay_ms(1);

        // Wait for reset to complete (up to 500ms per USB spec)
        wait_for(500, || {
            let cmd = self.read_op_reg(OP_USBCMD);
            let sts = self.read_op_reg(OP_USBSTS);
            cmd & USBCMD_HCRST == 0 && sts & USBSTS_CNR == 0
        });

        // Make sure interrupts are disabled
        let cmd = self.read_op_reg(OP_USBCMD);
        self.write_op_reg(OP_USBCMD, cmd & !USBCMD_INTE);

        // Set max device slots to our Vec capacity
        self.write_op_reg(OP_CONFIG, self.slots.capacity() as u32);

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

        // Memory barrier to ensure all DCBAA/scratchpad writes are visible
        fence(Ordering::SeqCst);

        self.write_op_reg64(OP_DCBAAP, self.dcbaa);

        // Allocate command ring (256 TRBs)
        let cmd_ring_mem = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        let cmd_ring_base = cmd_ring_mem.as_ptr() as u64;
        self.cmd_ring = TrbRing::new(cmd_ring_base, 256);

        // Set command ring pointer
        self.write_op_reg64(OP_CRCR, self.cmd_ring.physical_addr());

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

        // Set ERSTSZ (Event Ring Segment Table Size)
        self.write_interrupter_reg(0x08, 1);

        // Set ERDP (Event Ring Dequeue Pointer)
        self.write_interrupter_reg64(0x18, event_ring_base);

        // Set ERSTBA (Event Ring Segment Table Base Address)
        self.write_interrupter_reg64(0x10, self.erst);

        // Enable interrupter 0 (IMAN.IE = 1)
        // Some controllers won't generate events at all unless the interrupter
        // is enabled, even when using polling mode. Clear any pending interrupt
        // (IP bit is W1C at bit 0) and set IE (bit 1).
        // This follows Linux's xhci_run_finished() pattern.
        let iman = self.read_interrupter_reg(0x00);
        self.write_interrupter_reg(0x00, (iman & !0x1) | 0x2);

        // Start the controller with event interrupt enable
        let cmd = self.read_op_reg(OP_USBCMD);
        self.write_op_reg(OP_USBCMD, cmd | USBCMD_RS | USBCMD_INTE);

        // Wait for running (up to 100ms)
        wait_for(100, || self.read_op_reg(OP_USBSTS) & USBSTS_HCH == 0);

        // Power on all ports - many real hardware controllers require explicit port power
        self.power_on_ports();

        log::info!("xHCI controller initialized");
        Ok(())
    }

    /// Power on all ports
    ///
    /// Many xHCI controllers (especially on real hardware) require explicit
    /// port power enable. Without this, devices won't be detected.
    fn power_on_ports(&self) {
        for port in 0..self.num_ports {
            let portsc = self.read_port_reg(port, PORT_PORTSC);

            // Check if port power is already on
            if portsc & PORTSC_PP != 0 {
                continue;
            }

            // Enable port power, preserving RW bits
            let new_portsc = (portsc & PORTSC_RW_MASK) | PORTSC_PP;
            self.write_port_reg(port, PORT_PORTSC, new_portsc);

            log::debug!("xHCI: Powered on port {}", port);
        }

        // Wait for power to stabilize (2ms per USB spec, but give more time for real hardware)
        crate::time::delay_ms(20);
    }

    /// Wait for and process a command completion event
    fn wait_command_completion(&mut self) -> Result<Trb, XhciError> {
        let timeout = Timeout::from_ms(5000); // 5 second timeout for commands

        log::debug!(
            "xHCI: Waiting for command, dequeue_idx={}, expect_cycle={}",
            self.event_ring.dequeue_idx,
            self.event_ring.cycle,
        );

        while !timeout.is_expired() {
            let erdp = self.event_ring.base + (self.event_ring.dequeue_idx * 16) as u64;
            let event = unsafe { &*(erdp as *const Trb) };

            if event.get_cycle() == self.event_ring.cycle {
                let trb = *event;

                log::debug!(
                    "xHCI: Got event type={}, cc={}, param={:#x}",
                    trb.get_type(),
                    trb.completion_code(),
                    trb.param
                );

                // Advance dequeue pointer (software only — defer MMIO write)
                self.event_ring.dequeue_idx += 1;
                if self.event_ring.dequeue_idx >= self.event_ring.size {
                    self.event_ring.dequeue_idx = 0;
                    self.event_ring.cycle = !self.event_ring.cycle;
                }

                if trb.get_type() == TRB_TYPE_COMMAND_COMPLETION {
                    self.update_erdp();
                    let cc = trb.completion_code();
                    if cc == TRB_CC_SUCCESS {
                        return Ok(trb);
                    } else {
                        return Err(XhciError::CommandFailed(cc));
                    }
                } else if trb.get_type() == TRB_TYPE_PORT_STATUS_CHANGE {
                    // Ignore port status change events during command wait,
                    // but update ERDP so the controller knows we consumed the slot
                    self.update_erdp();
                    continue;
                } else if trb.get_type() == TRB_TYPE_HOST_CONTROLLER {
                    self.update_erdp();
                    // Host Controller Event indicates a fatal error (HSE)
                    log::error!(
                        "xHCI: Host Controller Event (fatal HSE), cc={}",
                        trb.completion_code()
                    );
                    return Err(XhciError::CommandFailed(trb.completion_code()));
                }
            }
            core::hint::spin_loop();
        }

        // Timeout — still update ERDP for any events we consumed
        self.update_erdp();
        let usbsts = self.read_op_reg(OP_USBSTS);
        log::warn!(
            "xHCI: Command timeout, USBSTS={:#x}, event_ring[0].control={:#x}",
            usbsts,
            unsafe { (*(self.event_ring.base as *const Trb)).control }
        );

        Err(XhciError::Timeout)
    }

    /// Wait for transfer completion events
    ///
    /// Each TRB is its own independent TD with IOC=1, so the controller
    /// generates one Transfer Event per TRB. We collect `expected_trbs`
    /// successful events before returning. ERDP is updated after each event
    /// to keep the event ring flowing (required since each TRB generates its
    /// own event).
    fn wait_transfer_completion(
        &mut self,
        _slot: u8,
        _ep: u8,
        expected_trbs: usize,
    ) -> Result<Trb, XhciError> {
        let timeout = Timeout::from_ms(5000); // 5 second timeout for transfers
        let mut completed = 0usize;
        #[allow(unused_assignments)]
        let mut last_trb = Trb::default();

        while !timeout.is_expired() {
            let erdp = self.event_ring.base + (self.event_ring.dequeue_idx * 16) as u64;
            let event = unsafe { &*(erdp as *const Trb) };

            if event.get_cycle() == self.event_ring.cycle {
                let trb = *event;

                // Advance dequeue pointer
                self.event_ring.dequeue_idx += 1;
                if self.event_ring.dequeue_idx >= self.event_ring.size {
                    self.event_ring.dequeue_idx = 0;
                    self.event_ring.cycle = !self.event_ring.cycle;
                }

                // Update ERDP after each event — required since every TRB
                // generates its own completion event
                self.update_erdp();

                if trb.get_type() == TRB_TYPE_TRANSFER_EVENT {
                    let cc = trb.completion_code();
                    log::trace!(
                        "xHCI: Transfer event cc={} ({}) residue={} [{}/{}]",
                        cc,
                        trb_cc_name(cc),
                        trb.status & 0xFFFFFF,
                        completed + 1,
                        expected_trbs
                    );

                    if cc == TRB_CC_SUCCESS || cc == TRB_CC_SHORT_PACKET {
                        completed += 1;
                        last_trb = trb;
                        if completed >= expected_trbs {
                            return Ok(last_trb);
                        }
                        // More TRBs to collect — continue
                    } else if cc == TRB_CC_STALL_ERROR {
                        log::debug!(
                            "xHCI: Transfer stalled [{}/{}]",
                            completed + 1,
                            expected_trbs
                        );
                        self.drain_remaining_transfer_events(expected_trbs - completed - 1);
                        return Err(XhciError::StallError);
                    } else {
                        log::debug!(
                            "xHCI: Transfer failed with cc={} ({}) [{}/{}]",
                            cc,
                            trb_cc_name(cc),
                            completed + 1,
                            expected_trbs
                        );
                        self.drain_remaining_transfer_events(expected_trbs - completed - 1);
                        return Err(XhciError::TransferFailed(cc));
                    }
                } else if trb.get_type() == TRB_TYPE_HOST_CONTROLLER {
                    // Host Controller Event indicates a fatal error (HSE)
                    log::error!(
                        "xHCI: Host Controller Event (fatal HSE) during transfer, cc={}",
                        trb.completion_code()
                    );
                    return Err(XhciError::TransferFailed(trb.completion_code()));
                } else {
                    log::trace!(
                        "xHCI: Got event type {} while waiting for transfer",
                        trb.get_type()
                    );
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

        while drained < max_events && !timeout.is_expired() {
            let erdp = self.event_ring.base + (self.event_ring.dequeue_idx * 16) as u64;
            let event = unsafe { &*(erdp as *const Trb) };

            if event.get_cycle() == self.event_ring.cycle {
                self.event_ring.dequeue_idx += 1;
                if self.event_ring.dequeue_idx >= self.event_ring.size {
                    self.event_ring.dequeue_idx = 0;
                    self.event_ring.cycle = !self.event_ring.cycle;
                }

                if event.get_type() == TRB_TYPE_TRANSFER_EVENT {
                    drained += 1;
                }
            } else {
                break; // No more events ready
            }
            core::hint::spin_loop();
        }

        if drained > 0 {
            self.update_erdp();
            log::trace!("xHCI: drained {} orphaned transfer events", drained);
        }
    }

    /// Update the Event Ring Dequeue Pointer (ERDP) in hardware
    ///
    /// This writes the current software dequeue pointer to the interrupter's
    /// ERDP register with the EHB (Event Handler Busy) bit set to clear it.
    /// This is a 64-bit split write (two PCIe MMIO writes), so it should be
    /// called as infrequently as possible.
    #[inline]
    fn update_erdp(&self) {
        let new_erdp = self.event_ring.base + (self.event_ring.dequeue_idx * 16) as u64;
        let erdp_with_ehb = (new_erdp & !0xF) | (1 << 3);
        self.write_interrupter_reg64(0x18, erdp_with_ehb);
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

        // Step 1: Send Reset Endpoint command
        // The Reset Endpoint command transitions the endpoint from Halted to Stopped state
        let mut trb = Trb::default();
        trb.set_type(TRB_TYPE_RESET_ENDPOINT);
        // Slot ID in bits 31:24, Endpoint ID in bits 20:16
        trb.control |= (slot_id as u32) << 24;
        trb.control |= (dci as u32) << 16;

        self.cmd_ring.enqueue(&trb, false);
        fence(Ordering::SeqCst);
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

        let mut trb = Trb::default();
        trb.param = dequeue_ptr_with_dcs;
        trb.set_type(TRB_TYPE_SET_TR_DEQUEUE);
        // Slot ID in bits 31:24, Endpoint ID in bits 20:16
        trb.control |= (slot_id as u32) << 24;
        trb.control |= (dci as u32) << 16;

        self.cmd_ring.enqueue(&trb, false);
        fence(Ordering::SeqCst);
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
        let mut trb = Trb::default();
        trb.set_type(TRB_TYPE_ENABLE_SLOT);

        let cmd_addr = self.cmd_ring.enqueue(&trb, false);
        log::debug!(
            "xHCI: Enable Slot TRB at {:#x}, cycle={}, CRCR={:#x}",
            cmd_addr,
            self.cmd_ring.cycle,
            self.read_op_reg64(OP_CRCR)
        );

        fence(Ordering::SeqCst); // Memory barrier before doorbell
        self.ring_doorbell(0, 0); // Ring host controller doorbell

        // Check USBSTS after ringing doorbell
        let usbsts = self.read_op_reg(OP_USBSTS);
        log::debug!("xHCI: USBSTS after doorbell: {:#x}", usbsts);

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

        let input = unsafe { &mut *(input_context_mem.as_mut_ptr() as *mut InputContext) };

        // Set up input control context
        input.control.add_flags = 0x3; // Add slot and EP0

        // Set up slot context
        input.slot.set_context_entries(1);
        input.slot.set_speed(speed);
        input.slot.set_root_hub_port(port + 1);

        // Set up control endpoint context
        let max_packet = match speed {
            1 => 8,   // Full speed
            2 => 8,   // Low speed
            3 => 64,  // High speed
            4 => 512, // Super speed
            _ => 8,
        };

        input.endpoints[0].set_ep_type(4); // Control endpoint
        input.endpoints[0].set_max_packet_size(max_packet);
        input.endpoints[0].set_max_burst_size(0);
        input.endpoints[0].set_cerr(3);
        input.endpoints[0].set_tr_dequeue_ptr(transfer_ring, true);
        input.endpoints[0].set_avg_trb_length(8);

        // Set up transfer ring
        let ring = TrbRing::new(transfer_ring, 256);

        // Store in DCBAA
        let dcbaa_entry = unsafe { &mut *((self.dcbaa + (slot_id as u64 * 8)) as *mut u64) };
        *dcbaa_entry = device_context;

        // Build Address Device command
        let mut trb = Trb::default();
        trb.param = input_context;
        trb.set_type(TRB_TYPE_ADDRESS_DEVICE);
        trb.control |= (slot_id as u32) << 24;

        self.cmd_ring.enqueue(&trb, false);
        fence(Ordering::SeqCst); // Memory barrier before doorbell
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
            device_context: device_context as *mut DeviceContext,
            input_context: input_context as *mut InputContext,
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
            interrupt_in_ep: 0,
            interrupt_max_packet: 0,
            interrupt_interval: 0,
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
        const TRB_ISP: u32 = 1 << 2; // Interrupt on Short Packet

        let slot = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::DeviceNotFound)?;

        let ring = slot.transfer_rings[0]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        let is_in = (request_type & 0x80) != 0;
        let data_len = data.as_ref().map(|d| d.len()).unwrap_or(0);

        // Save cycle state before enqueuing the first (deferred) TRB
        let first_trb_cycle = ring.cycle;

        // Setup Stage TRB — enqueued with DEFERRED cycle bit
        let mut setup = Trb::default();
        setup.param = (request_type as u64)
            | ((request as u64) << 8)
            | ((value as u64) << 16)
            | ((index as u64) << 32)
            | ((data_len as u64) << 48);
        setup.status = 8; // TRB transfer length = 8
        setup.set_type(TRB_TYPE_SETUP);
        setup.control |= 1 << 6; // IDT (Immediate Data)
        if data_len > 0 {
            setup.control |= if is_in { 3 << 16 } else { 2 << 16 }; // TRT
        }

        let first_trb_addr = ring.enqueue(&setup, true); // defer_cycle = true

        // Data Stage TRB (if needed)
        if let Some(data_buf) = data {
            let mut data_trb = Trb::default();
            data_trb.param = data_buf.as_ptr() as u64;
            data_trb.status = data_buf.len() as u32;
            data_trb.set_type(TRB_TYPE_DATA);
            if is_in {
                data_trb.control |= 1 << 16; // DIR = IN
                data_trb.control |= TRB_ISP; // Interrupt on Short Packet for IN
            }

            ring.enqueue(&data_trb, false);
        }

        // Status Stage TRB
        let mut status = Trb::default();
        status.set_type(TRB_TYPE_STATUS);
        if data_len == 0 || !is_in {
            status.control |= 1 << 16; // DIR = IN for status
        }
        status.control |= 1 << 5; // IOC (Interrupt on Completion)

        ring.enqueue(&status, false);

        // Commit the deferred first TRB — atomically makes the entire TD live
        TrbRing::commit_deferred_trb(first_trb_addr, first_trb_cycle);

        // Memory barrier and ring doorbell
        fence(Ordering::SeqCst);
        self.ring_doorbell(slot_id, DCI_EP0);

        // Wait for completion
        match self.wait_transfer_completion(slot_id, 0, 1) {
            Ok(completion) => {
                // Return transfer length
                let residual = completion.status & 0xFFFFFF;
                Ok(data_len.saturating_sub(residual as usize))
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

    /// Get device descriptor
    fn get_device_descriptor(&mut self, slot_id: u8) -> Result<DeviceDescriptor, XhciError> {
        let mut desc = [0u8; 18];

        // First, get just 8 bytes to determine max packet size
        let mut short_desc = [0u8; 8];
        self.control_transfer(
            slot_id,
            req_type::DIR_IN | req_type::TYPE_STANDARD | req_type::RCPT_DEVICE,
            request::GET_DESCRIPTOR,
            (desc_type::DEVICE as u16) << 8,
            0,
            Some(&mut short_desc),
        )?;

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
            .map_err(|_| XhciError::TransferFailed(0))
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

    /// Enumerate ports and attach devices
    fn enumerate_ports(&mut self) -> Result<(), XhciError> {
        for port in 0..self.num_ports {
            // Quick check — skip immediately if nothing connected.
            // This avoids the 100ms debounce cost for every empty port.
            let portsc = self.read_port_reg(port, PORT_PORTSC);
            if portsc & PORTSC_CCS == 0 {
                continue;
            }

            // Debounce: check connection is stable for 50ms
            // This prevents detecting phantom connections during cable settling
            let mut stable_count = 0;

            for _ in 0..5 {
                let portsc = self.read_port_reg(port, PORT_PORTSC);
                let connected = portsc & PORTSC_CCS != 0;

                if connected {
                    stable_count += 1;
                } else {
                    stable_count = 0;
                }
                crate::time::delay_ms(10);
            }

            // Need at least 3 stable reads to consider device connected
            if stable_count < 3 {
                continue;
            }

            let portsc = self.read_port_reg(port, PORT_PORTSC);

            // Get speed and link state
            let speed = ((portsc & PORTSC_SPEED_MASK) >> 10) as u8;
            let pls = portsc & PORTSC_PLS_MASK;
            let speed_name = match speed {
                1 => "Full",
                2 => "Low",
                3 => "High",
                4 => "Super",
                _ => "Unknown",
            };
            let pls_name = match pls >> 5 {
                0 => "U0",
                5 => "RxDetect",
                7 => "Polling",
                _ => "Other",
            };

            log::info!(
                "USB device on port {}: {} speed, PLS={}",
                port,
                speed_name,
                pls_name
            );

            // If port is in RxDetect state, it's a phantom device (e.g., Thunderbolt
            // controller internal port that reports CCS=1 but has no real device).
            // Skip these immediately - they'll never come up.
            if pls == PORTSC_PLS_RXDETECT {
                log::debug!("Port {}: RxDetect state (phantom device), skipping", port);
                continue;
            }

            // Clear status change bits using proper RW mask to avoid side effects
            // PORTSC has RW1C bits (write-1-to-clear) like PED, so we must be careful
            let portsc = self.read_port_reg(port, PORT_PORTSC);
            self.write_port_reg(
                port,
                PORT_PORTSC,
                (portsc & PORTSC_RW_MASK) | PORTSC_CHANGE_MASK,
            );

            // For USB3 SuperSpeed devices already in U0 state with port enabled,
            // skip the reset - the device is ready to use
            let is_usb3 = speed == 4; // SuperSpeed
            let is_enabled = (portsc & PORTSC_PED) != 0;
            let is_u0 = (portsc & PORTSC_PLS_MASK) == PORTSC_PLS_U0;

            if is_usb3 && is_enabled && is_u0 {
                log::debug!("Port {}: USB3 device already in U0, skipping reset", port);
            } else if is_usb3 && (portsc & PORTSC_PLS_MASK) == PORTSC_PLS_POLLING {
                // USB3 device in Polling state - wait for link training to complete
                log::debug!("Port {}: USB3 device in Polling, waiting for link", port);
                let timeout = Timeout::from_ms(200);
                let mut link_up = false;
                while !timeout.is_expired() {
                    let portsc = self.read_port_reg(port, PORT_PORTSC);
                    if (portsc & PORTSC_PLS_MASK) == PORTSC_PLS_U0 && (portsc & PORTSC_PED) != 0 {
                        link_up = true;
                        break;
                    }
                    crate::time::delay_ms(1);
                }
                if !link_up {
                    log::debug!(
                        "Port {}: USB3 link training failed (PLS={}), skipping",
                        port,
                        (self.read_port_reg(port, PORT_PORTSC) & PORTSC_PLS_MASK) >> 5
                    );
                    continue;
                }
            } else if (portsc & PORTSC_PED) == 0 {
                // USB2 device or USB3 device that needs reset
                let portsc = self.read_port_reg(port, PORT_PORTSC);
                // Trigger port reset - preserve RW bits, set PR
                self.write_port_reg(port, PORT_PORTSC, (portsc & PORTSC_RW_MASK) | PORTSC_PR);

                // Wait for reset to complete (up to 150ms per USB spec)
                let timeout = Timeout::from_ms(150);
                while !timeout.is_expired() {
                    let portsc = self.read_port_reg(port, PORT_PORTSC);
                    if portsc & PORTSC_PRC != 0 {
                        // Clear PRC by writing 1 to it (RW1C)
                        self.write_port_reg(
                            port,
                            PORT_PORTSC,
                            (portsc & PORTSC_RW_MASK) | PORTSC_PRC,
                        );
                        break;
                    }
                    crate::time::delay_ms(1);
                }

                // After reset, verify link is actually up
                let portsc = self.read_port_reg(port, PORT_PORTSC);
                if portsc & PORTSC_PLS_MASK != PORTSC_PLS_U0 {
                    // For USB3 devices, try warm reset if normal reset failed
                    if is_usb3 {
                        log::debug!(
                            "Port {}: USB3 normal reset failed (PLS={}), trying warm reset",
                            port,
                            (portsc & PORTSC_PLS_MASK) >> 5
                        );

                        // Issue warm reset
                        let portsc = self.read_port_reg(port, PORT_PORTSC);
                        self.write_port_reg(
                            port,
                            PORT_PORTSC,
                            (portsc & PORTSC_RW_MASK) | PORTSC_WPR,
                        );

                        // Wait for warm reset to complete
                        let timeout = Timeout::from_ms(200);
                        while !timeout.is_expired() {
                            let portsc = self.read_port_reg(port, PORT_PORTSC);
                            if portsc & PORTSC_WRC != 0 {
                                // Clear WRC by writing 1 to it (RW1C)
                                self.write_port_reg(
                                    port,
                                    PORT_PORTSC,
                                    (portsc & PORTSC_RW_MASK) | PORTSC_WRC,
                                );
                                break;
                            }
                            crate::time::delay_ms(1);
                        }

                        // Check if link came up after warm reset
                        let portsc = self.read_port_reg(port, PORT_PORTSC);
                        if portsc & PORTSC_PLS_MASK != PORTSC_PLS_U0 {
                            log::debug!(
                                "Port {}: link not up after warm reset (PLS={}), skipping",
                                port,
                                (portsc & PORTSC_PLS_MASK) >> 5
                            );
                            continue;
                        }
                        log::debug!("Port {}: warm reset successful", port);
                    } else {
                        log::debug!(
                            "Port {}: link not up after reset (PLS={}), skipping",
                            port,
                            (portsc & PORTSC_PLS_MASK) >> 5
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

    /// Configure a mass storage device
    ///
    /// Uses the shared parse_configuration() infrastructure from controller.rs
    fn configure_mass_storage(&mut self, slot_id: u8) -> Result<(), XhciError> {
        // Get configuration descriptor
        let mut config_buf = [0u8; 256];

        // First get just the header
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

        // Parse configuration using shared infrastructure
        let config_info = parse_configuration(&config_buf[..total_len]);

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
        // Get configuration descriptor
        let mut config_buf = [0u8; 256];

        // First get just the header
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

        // Parse configuration using shared infrastructure
        let config_info = parse_configuration(&config_buf[..total_len]);

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

        // Calculate DCI (Device Context Index) for endpoints
        // DCI = (Endpoint Number * 2) + Direction (0=OUT, 1=IN)
        let in_dci = (bulk_in as usize * 2) + 1;
        let out_dci = bulk_out as usize * 2;

        // Set up input context
        let input = unsafe { &mut *slot.input_context };
        *input = InputContext::default();

        // Copy slot context from device context
        let device = unsafe { &*slot.device_context };
        input.slot = device.slot;
        input.slot.set_context_entries(in_dci.max(out_dci) as u8);

        // Set up endpoint contexts
        input.control.add_flags = 1 | (1 << in_dci) | (1 << out_dci);

        // Bulk IN endpoint
        input.endpoints[in_dci - 1].set_ep_type(6); // Bulk IN
        input.endpoints[in_dci - 1].set_max_packet_size(max_packet);
        input.endpoints[in_dci - 1].set_max_burst_size(0);
        input.endpoints[in_dci - 1].set_cerr(3);
        input.endpoints[in_dci - 1].set_tr_dequeue_ptr(in_ring_addr, true);
        input.endpoints[in_dci - 1].set_avg_trb_length(max_packet);

        // Bulk OUT endpoint
        input.endpoints[out_dci - 1].set_ep_type(2); // Bulk OUT
        input.endpoints[out_dci - 1].set_max_packet_size(max_packet);
        input.endpoints[out_dci - 1].set_max_burst_size(0);
        input.endpoints[out_dci - 1].set_cerr(3);
        input.endpoints[out_dci - 1].set_tr_dequeue_ptr(out_ring_addr, true);
        input.endpoints[out_dci - 1].set_avg_trb_length(max_packet);

        // Store rings
        slot.transfer_rings[in_dci - 1] = Some(in_ring);
        slot.transfer_rings[out_dci - 1] = Some(out_ring);

        // Send Configure Endpoint command
        let mut trb = Trb::default();
        trb.param = slot.input_context as u64;
        trb.set_type(TRB_TYPE_CONFIGURE_ENDPOINT);
        trb.control |= (slot_id as u32) << 24;

        self.cmd_ring.enqueue(&trb, false);
        fence(Ordering::SeqCst); // Memory barrier before doorbell
        self.ring_doorbell(0, 0);

        self.wait_command_completion()?;

        Ok(())
    }

    /// Bulk transfer
    ///
    /// Splits large transfers into ≤ 64KB TRBs, each as its own independent TD
    /// with IOC (matching EDK2's approach). Collects one completion event per TRB.
    ///
    /// Features:
    /// - Splits transfers into independent 64KB TRBs (no chaining)
    /// - Sets ISP (Interrupt on Short Packet) for IN transfers to detect short packets
    /// - Automatically recovers from stall errors by resetting the endpoint
    pub fn bulk_transfer(
        &mut self,
        slot_id: u8,
        ep: u8,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<usize, XhciError> {
        // Calculate DCI (Device Context Index)
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

        // Queue all TRBs for this transfer
        let trb_count = self.queue_bulk_trbs(slot_id, dci, is_in, data)?;

        // Memory barrier and ring doorbell
        fence(Ordering::SeqCst);
        self.ring_doorbell(slot_id, dci as u8);

        // Wait for all TRB completions
        match self.wait_transfer_completion(slot_id, ep, trb_count) {
            Ok(completion) => {
                let residual = completion.status & 0xFFFFFF;
                let transferred = data.len().saturating_sub(residual as usize);
                log::trace!(
                    "xHCI: bulk transfer complete, len={} residual={} transferred={}",
                    data.len(),
                    residual,
                    transferred
                );
                Ok(transferred)
            }
            Err(XhciError::StallError) => {
                // Endpoint stalled - reset it and return the error
                // The caller may retry the transfer after handling the stall
                log::debug!(
                    "xHCI: Bulk transfer stalled on slot={} dci={}, resetting endpoint",
                    slot_id,
                    dci
                );
                if let Err(e) = self.reset_endpoint(slot_id, dci as u8) {
                    log::warn!("xHCI: Failed to reset endpoint after stall: {:?}", e);
                }
                Err(XhciError::StallError)
            }
            Err(XhciError::TransferFailed(cc))
                if cc == TRB_CC_BABBLE_DETECTED || cc == TRB_CC_USB_TRANSACTION_ERROR =>
            {
                // Babble and transaction errors halt bulk endpoints (xHCI spec 4.8.3).
                // Recovery is the same as for stalls: Reset Endpoint + Set TR Dequeue Pointer.
                // Both EDK2 (XhcRecoverHaltedEndpoint) and Linux (xhci_handle_halted_endpoint
                // with EP_HARD_RESET) perform identical recovery for these errors.
                log::debug!(
                    "xHCI: Bulk transfer failed with {} on slot={} dci={}, resetting endpoint",
                    trb_cc_name(cc),
                    slot_id,
                    dci
                );
                if let Err(e) = self.reset_endpoint(slot_id, dci as u8) {
                    log::warn!(
                        "xHCI: Failed to reset endpoint after {}: {:?}",
                        trb_cc_name(cc),
                        e
                    );
                }
                Err(XhciError::TransferFailed(cc))
            }
            Err(e) => Err(e),
        }
    }

    /// Queue TRBs for a bulk transfer
    ///
    /// Splits large transfers into ≤ 64KB (0x10000 byte) TRBs, matching EDK2's
    /// proven approach: **each TRB is its own independent TD** with IOC=1 and
    /// ISP=1. No chaining, no deferred first TRB, no TD_SIZE — just simple
    /// per-TRB completion events that the wait loop collects.
    ///
    /// This avoids complex chained-TRB interactions that cause BABBLE on some
    /// Intel xHCI controllers (e.g. ThinkPad T480).
    ///
    /// Returns the number of TRBs queued.
    fn queue_bulk_trbs(
        &mut self,
        slot_id: u8,
        dci: usize,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<usize, XhciError> {
        const TRB_MAX_TRANSFER_SIZE: usize = 0x10000; // 64KB per TRB (EDK2 convention)
        const TRB_IOC: u32 = 1 << 5; // Interrupt on Completion
        const TRB_ISP: u32 = 1 << 2; // Interrupt on Short Packet

        let slot = self
            .slots
            .get_mut(slot_id as usize)
            .and_then(|s| s.as_mut())
            .ok_or(XhciError::DeviceNotFound)?;

        let ring = slot.transfer_rings[dci - 1]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        let mut buf_addr = data.as_ptr() as u64;
        let mut remaining = data.len();
        let mut trb_count = 0usize;

        while remaining > 0 {
            let chunk_size = remaining.min(TRB_MAX_TRANSFER_SIZE);

            let mut trb = Trb::default();
            trb.param = buf_addr;
            trb.status = chunk_size as u32; // TRB Transfer Length, TD_SIZE = 0
            trb.set_type(TRB_TYPE_NORMAL);
            trb.control |= TRB_IOC; // Every TRB gets its own completion event
            if is_in {
                trb.control |= TRB_ISP;
            }

            ring.enqueue(&trb, false);
            trb_count += 1;

            buf_addr += chunk_size as u64;
            remaining -= chunk_size;
        }

        log::trace!(
            "xHCI: queued {} TRBs for bulk transfer ({}B each, {}B total)",
            trb_count,
            TRB_MAX_TRANSFER_SIZE,
            data.len()
        );

        Ok(trb_count)
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

        // 1. Stop the controller (clear RS bit)
        let cmd = self.read_op_reg(OP_USBCMD);
        self.write_op_reg(OP_USBCMD, cmd & !USBCMD_RS);

        // Wait for halt (HCH bit set)
        wait_for(100, || self.read_op_reg(OP_USBSTS) & USBSTS_HCH != 0);

        // 2. Reset the controller (optional but helps ensure clean state)
        self.write_op_reg(OP_USBCMD, USBCMD_HCRST);

        // Wait for reset to complete (HCRST clears and CNR clears)
        wait_for(500, || {
            let cmd = self.read_op_reg(OP_USBCMD);
            let sts = self.read_op_reg(OP_USBSTS);
            (cmd & USBCMD_HCRST) == 0 && (sts & USBSTS_CNR) == 0
        });

        log::debug!("xHCI cleanup complete");
    }
}

// SAFETY: XhciController contains raw pointers to MMIO registers, DCBAA, event rings,
// and command rings. These are:
// 1. MMIO addresses from PCI BAR that remain valid for the device's lifetime
// 2. DMA-accessible buffers allocated via EFI page allocator with proper alignment
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

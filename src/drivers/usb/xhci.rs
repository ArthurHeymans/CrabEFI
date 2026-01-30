//! xHCI (USB 3.0) Host Controller Interface driver
//!
//! This module provides a minimal xHCI driver for USB mass storage devices.

use crate::drivers::mmio::MmioRegion;
use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi;
use crate::time::{Timeout, wait_for};
use core::ptr;
use core::sync::atomic::{Ordering, fence};

use super::controller::{DeviceDescriptor, desc_type, parse_configuration, req_type, request};

// Import all constants from xhci_regs
use super::xhci_regs::{
    // Capability register offsets
    CAP_CAPLENGTH,
    CAP_DBOFF,
    CAP_HCCPARAMS1,
    CAP_HCSPARAMS1,
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
    PORTSC_CCS,
    // PORTSC register bits
    PORTSC_CHANGE_MASK,
    PORTSC_PED,
    PORTSC_PR,
    PORTSC_PRC,
    PORTSC_SPEED_MASK,
    // TRB completion codes
    TRB_CC_SHORT_PACKET,
    TRB_CC_STALL_ERROR,
    TRB_CC_SUCCESS,
    // TRB types
    TRB_TYPE_ADDRESS_DEVICE,
    TRB_TYPE_COMMAND_COMPLETION,
    TRB_TYPE_CONFIGURE_ENDPOINT,
    TRB_TYPE_DATA,
    TRB_TYPE_ENABLE_SLOT,
    TRB_TYPE_LINK,
    TRB_TYPE_NORMAL,
    TRB_TYPE_PORT_STATUS_CHANGE,
    TRB_TYPE_SETUP,
    TRB_TYPE_STATUS,
    TRB_TYPE_TRANSFER_EVENT,
    // USBCMD register bits
    USBCMD_HCRST,
    USBCMD_RS,
    // USBSTS register bits
    USBSTS_CNR,
    USBSTS_HCH,
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

    fn enqueue(&mut self, trb: &Trb) -> u64 {
        let addr = self.base + (self.enqueue_idx * 16) as u64;
        let entry = unsafe { &mut *(addr as *mut Trb) };

        entry.param = trb.param;
        entry.status = trb.status;
        entry.control = (trb.control & !1) | if self.cycle { 1 } else { 0 };

        fence(Ordering::SeqCst);

        self.enqueue_idx += 1;

        // Check if we need to wrap around via link TRB
        if self.enqueue_idx >= self.size - 1 {
            // Ring the link TRB's cycle bit
            let link = unsafe { &mut *((self.base + ((self.size - 1) * 16) as u64) as *mut Trb) };
            if self.cycle {
                link.control |= 1;
            } else {
                link.control &= !1;
            }
            fence(Ordering::SeqCst);

            self.enqueue_idx = 0;
            self.cycle = !self.cycle;
        }

        addr
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
    /// Number of slots
    max_slots: u8,
    /// Page size (kept for hardware completeness)
    #[allow(dead_code)]
    page_size: u32,
    /// Device Context Base Address Array
    dcbaa: u64,
    /// Command ring
    cmd_ring: TrbRing,
    /// Event ring segment table
    erst: u64,
    /// Event ring
    event_ring: TrbRing,
    /// Active slots (limited to 4 to avoid stack overflow - each UsbSlot is ~800 bytes)
    slots: [Option<UsbSlot>; 4],
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

                    // Clear any SMI enables in USBLEGCTLSTS (at offset +4)
                    let ctlsts_addr = cap_addr + 4;
                    let ctlsts = unsafe { ptr::read_volatile(ctlsts_addr as *const u32) };
                    // Clear SMI enable bits but preserve status bits
                    // Bits 0-4: SMI enables, Bits 16-20: SMI status (write-1-to-clear)
                    // Clear enables (set to 0), clear any pending status (write 1s)
                    let new_ctlsts = ctlsts & 0xFFFF0000;
                    unsafe {
                        ptr::write_volatile(ctlsts_addr as *mut u32, new_ctlsts);
                    }
                }
                break;
            }

            if next_ptr == 0 {
                break;
            }
            cap_addr = mmio_base + (next_ptr as u64 * 4);
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
        let hccparams1 = mmio.read32(CAP_HCCPARAMS1 as u64);
        let dboff = mmio.read32(CAP_DBOFF as u64);
        let rtsoff = mmio.read32(CAP_RTSOFF as u64);

        // Take ownership from BIOS/SMM before doing anything else
        Self::take_bios_ownership(mmio_base, hccparams1);

        // Calculate register region offsets
        let op_offset = caplength as u64;
        let rt_offset = (rtsoff & !0x1F) as u64;
        let db_offset = (dboff & !0x3) as u64;
        let port_offset = op_offset + 0x400;

        let num_ports = ((hcsparams1 >> 24) & 0xFF) as u8;
        let hw_max_slots = (hcsparams1 & 0xFF) as u8;
        // Cap max_slots to our array size to avoid stack overflow
        let max_slots = hw_max_slots.min(4);

        log::info!(
            "xHCI version: {}.{}.{}, ports: {}, slots: {}",
            (hciversion >> 8) & 0xFF,
            (hciversion >> 4) & 0xF,
            hciversion & 0xF,
            num_ports,
            max_slots
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

        let mut controller = Self {
            pci_address: pci_dev.address,
            cap_regs: cap_regs_region,
            op_regs: op_regs_region,
            rt_regs: rt_regs_region,
            db_regs: db_regs_region,
            port_regs: port_regs_region,
            num_ports,
            max_slots,
            page_size,
            dcbaa: 0,
            cmd_ring: TrbRing::empty(), // Will be initialized in init()
            erst: 0,
            event_ring: TrbRing::empty(), // Will be initialized in init()
            slots: core::array::from_fn(|_| None),
        };

        controller.init()?;
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

    /// Write 64-bit operational register
    #[inline]
    fn write_op_reg64(&self, offset: u32, value: u64) {
        self.op_regs.write64(offset as u64, value)
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
    #[inline]
    fn ring_doorbell(&self, slot: u8, target: u8) {
        self.db_regs.write32(slot as u64 * 4, target as u32)
    }

    /// Write interrupter register
    #[inline]
    fn write_interrupter_reg(&self, offset: u32, value: u32) {
        // Interrupter 0 is at offset 0x20 within runtime registers
        self.rt_regs.write32(0x20 + offset as u64, value)
    }

    /// Write 64-bit interrupter register
    #[inline]
    fn write_interrupter_reg64(&self, offset: u32, value: u64) {
        self.rt_regs.write64(0x20 + offset as u64, value)
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

        // Wait for reset to complete (up to 500ms per USB spec)
        wait_for(500, || {
            let cmd = self.read_op_reg(OP_USBCMD);
            let sts = self.read_op_reg(OP_USBSTS);
            cmd & USBCMD_HCRST == 0 && sts & USBSTS_CNR == 0
        });

        // Set max device slots
        self.write_op_reg(OP_CONFIG, self.max_slots as u32);

        // Allocate and set up DCBAA (Device Context Base Address Array)
        let dcbaa_pages = ((self.max_slots as u64 + 1) * 8).div_ceil(4096);
        self.dcbaa = efi::allocate_pages(dcbaa_pages).ok_or(XhciError::AllocationFailed)?;
        unsafe {
            core::slice::from_raw_parts_mut(self.dcbaa as *mut u8, (dcbaa_pages * 4096) as usize)
                .fill(0)
        };
        self.write_op_reg64(OP_DCBAAP, self.dcbaa);

        // Allocate command ring (256 TRBs)
        let cmd_ring_base = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        self.cmd_ring = TrbRing::new(cmd_ring_base, 256);

        // Set command ring pointer
        self.write_op_reg64(OP_CRCR, self.cmd_ring.physical_addr());

        // Allocate event ring (256 TRBs) - no link TRB for event rings
        let event_ring_base = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        self.event_ring = TrbRing::new_event_ring(event_ring_base, 256);

        // Allocate Event Ring Segment Table (ERST)
        self.erst = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        unsafe { core::slice::from_raw_parts_mut(self.erst as *mut u8, 4096).fill(0) };

        // Set up ERST entry
        let erst_entry = self.erst as *mut u64;
        unsafe {
            ptr::write_volatile(erst_entry, event_ring_base); // Ring Segment Base Address
            ptr::write_volatile(erst_entry.add(1), 256); // Ring Segment Size
        }

        // Set ERSTSZ (Event Ring Segment Table Size)
        self.write_interrupter_reg(0x08, 1);

        // Set ERDP (Event Ring Dequeue Pointer)
        self.write_interrupter_reg64(0x18, event_ring_base);

        // Set ERSTBA (Event Ring Segment Table Base Address)
        self.write_interrupter_reg64(0x10, self.erst);

        // Start the controller
        let cmd = self.read_op_reg(OP_USBCMD);
        self.write_op_reg(OP_USBCMD, cmd | USBCMD_RS);

        // Wait for running (up to 100ms)
        wait_for(100, || self.read_op_reg(OP_USBSTS) & USBSTS_HCH == 0);

        log::info!("xHCI controller initialized");
        Ok(())
    }

    /// Wait for and process a command completion event
    fn wait_command_completion(&mut self) -> Result<Trb, XhciError> {
        let timeout = Timeout::from_ms(5000); // 5 second timeout for commands

        while !timeout.is_expired() {
            // Read event ring dequeue pointer
            let erdp = self.event_ring.base + (self.event_ring.dequeue_idx * 16) as u64;
            let event = unsafe { &*(erdp as *const Trb) };

            // Check if event is ready
            if event.get_cycle() == self.event_ring.cycle {
                let trb = *event;

                // Advance dequeue pointer
                self.event_ring.dequeue_idx += 1;
                if self.event_ring.dequeue_idx >= self.event_ring.size {
                    self.event_ring.dequeue_idx = 0;
                    self.event_ring.cycle = !self.event_ring.cycle;
                }

                // Update ERDP (write low and high separately, no EHB bit)
                let new_erdp = self.event_ring.base + (self.event_ring.dequeue_idx * 16) as u64;
                self.write_interrupter_reg(0x18, new_erdp as u32);
                self.write_interrupter_reg(0x1C, (new_erdp >> 32) as u32);

                if trb.get_type() == TRB_TYPE_COMMAND_COMPLETION {
                    let cc = trb.completion_code();
                    if cc == TRB_CC_SUCCESS {
                        return Ok(trb);
                    } else {
                        return Err(XhciError::CommandFailed(cc));
                    }
                } else if trb.get_type() == TRB_TYPE_PORT_STATUS_CHANGE {
                    // Ignore port status change events during command wait
                    continue;
                }
            }
            core::hint::spin_loop();
        }
        Err(XhciError::Timeout)
    }

    /// Wait for transfer completion
    fn wait_transfer_completion(&mut self, _slot: u8, _ep: u8) -> Result<Trb, XhciError> {
        let timeout = Timeout::from_ms(5000); // 5 second timeout for transfers

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

                // Update ERDP (write low and high separately, no EHB bit)
                let new_erdp = self.event_ring.base + (self.event_ring.dequeue_idx * 16) as u64;
                self.write_interrupter_reg(0x18, new_erdp as u32);
                self.write_interrupter_reg(0x1C, (new_erdp >> 32) as u32);

                if trb.get_type() == TRB_TYPE_TRANSFER_EVENT {
                    let cc = trb.completion_code();
                    if cc == TRB_CC_SUCCESS || cc == TRB_CC_SHORT_PACKET {
                        return Ok(trb);
                    } else if cc == TRB_CC_STALL_ERROR {
                        return Err(XhciError::StallError);
                    } else {
                        return Err(XhciError::TransferFailed(cc));
                    }
                } else {
                    // Got a non-transfer event, log and continue waiting
                    log::trace!(
                        "xHCI: Got event type {} while waiting for transfer",
                        trb.get_type()
                    );
                }
            }
            core::hint::spin_loop();
        }
        log::warn!(
            "xHCI: Transfer timeout, event ring dequeue_idx={}, cycle={}",
            self.event_ring.dequeue_idx,
            self.event_ring.cycle
        );
        Err(XhciError::Timeout)
    }

    /// Enable a slot
    fn enable_slot(&mut self) -> Result<u8, XhciError> {
        let mut trb = Trb::default();
        trb.set_type(TRB_TYPE_ENABLE_SLOT);

        self.cmd_ring.enqueue(&trb);
        self.ring_doorbell(0, 0); // Ring host controller doorbell

        let completion = self.wait_command_completion()?;
        Ok(completion.slot_id())
    }

    /// Address a device
    fn address_device(&mut self, slot_id: u8, port: u8, speed: u8) -> Result<(), XhciError> {
        // Allocate device context
        let device_context = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        unsafe { core::slice::from_raw_parts_mut(device_context as *mut u8, 4096).fill(0) };

        // Allocate input context
        let input_context = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        unsafe { core::slice::from_raw_parts_mut(input_context as *mut u8, 4096).fill(0) };

        // Allocate transfer ring for control endpoint
        let transfer_ring = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;

        let input = unsafe { &mut *(input_context as *mut InputContext) };

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

        self.cmd_ring.enqueue(&trb);
        self.ring_doorbell(0, 0);

        self.wait_command_completion()?;

        // Store slot info
        let mut transfer_rings: [Option<TrbRing>; 31] = core::array::from_fn(|_| None);
        transfer_rings[0] = Some(ring);

        self.slots[slot_id as usize] = Some(UsbSlot {
            slot_id,
            device_context: device_context as *mut DeviceContext,
            input_context: input_context as *mut InputContext,
            transfer_rings,
            device_desc: DeviceDescriptor::default(),
            port,
            speed,
            is_mass_storage: false,
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
    fn control_transfer(
        &mut self,
        slot_id: u8,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
        data: Option<&mut [u8]>,
    ) -> Result<usize, XhciError> {
        let slot = self.slots[slot_id as usize]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        let ring = slot.transfer_rings[0]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        let is_in = (request_type & 0x80) != 0;
        let data_len = data.as_ref().map(|d| d.len()).unwrap_or(0);

        // Setup Stage TRB
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

        ring.enqueue(&setup);

        // Data Stage TRB (if needed)
        if let Some(data_buf) = data {
            let mut data_trb = Trb::default();
            data_trb.param = data_buf.as_ptr() as u64;
            data_trb.status = data_buf.len() as u32;
            data_trb.set_type(TRB_TYPE_DATA);
            if is_in {
                data_trb.control |= 1 << 16; // DIR = IN
            }

            ring.enqueue(&data_trb);
        }

        // Status Stage TRB
        let mut status = Trb::default();
        status.set_type(TRB_TYPE_STATUS);
        if data_len == 0 || !is_in {
            status.control |= 1 << 16; // DIR = IN for status
        }
        status.control |= 1 << 5; // IOC (Interrupt on Completion)

        ring.enqueue(&status);

        // Ring doorbell
        self.ring_doorbell(slot_id, 1); // EP0 = DCI 1

        // Wait for completion
        let completion = self.wait_transfer_completion(slot_id, 0)?;

        // Return transfer length
        let residual = completion.status & 0xFFFFFF;
        Ok(data_len.saturating_sub(residual as usize))
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

        Ok(unsafe { ptr::read_unaligned(desc.as_ptr() as *const DeviceDescriptor) })
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
            let portsc = self.read_port_reg(port, PORT_PORTSC);

            // Check if device is connected
            if portsc & PORTSC_CCS == 0 {
                continue;
            }

            // Get speed
            let speed = ((portsc & PORTSC_SPEED_MASK) >> 10) as u8;
            let speed_name = match speed {
                1 => "Full",
                2 => "Low",
                3 => "High",
                4 => "Super",
                _ => "Unknown",
            };

            log::info!("USB device on port {}: {} speed", port, speed_name);

            // Clear status change bits
            self.write_port_reg(port, PORT_PORTSC, portsc | PORTSC_CHANGE_MASK);

            // Reset the port if needed
            if portsc & PORTSC_PED == 0 {
                let portsc = self.read_port_reg(port, PORT_PORTSC);
                self.write_port_reg(port, PORT_PORTSC, portsc | PORTSC_PR);

                // Wait for reset to complete (up to 100ms per USB spec)
                let timeout = Timeout::from_ms(100);
                while !timeout.is_expired() {
                    let portsc = self.read_port_reg(port, PORT_PORTSC);
                    if portsc & PORTSC_PRC != 0 {
                        self.write_port_reg(port, PORT_PORTSC, portsc | PORTSC_PRC);
                        break;
                    }
                    core::hint::spin_loop();
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

                            if let Some(slot) = &mut self.slots[slot_id as usize] {
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
        let mut found = false;

        for iface in &config_info.interfaces[..config_info.num_interfaces] {
            if iface.is_mass_storage() {
                log::info!(
                    "  Found USB Mass Storage interface {}",
                    iface.interface_number
                );

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
        if let Some(slot) = &mut self.slots[slot_id as usize] {
            slot.is_mass_storage = true;
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
        if let Some(slot) = &mut self.slots[slot_id as usize] {
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
        let slot = self.slots[slot_id as usize]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        // Allocate transfer rings for bulk endpoints
        let in_ring_addr = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;
        let out_ring_addr = efi::allocate_pages(1).ok_or(XhciError::AllocationFailed)?;

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

        self.cmd_ring.enqueue(&trb);
        self.ring_doorbell(0, 0);

        self.wait_command_completion()?;

        Ok(())
    }

    /// Bulk transfer
    pub fn bulk_transfer(
        &mut self,
        slot_id: u8,
        ep: u8,
        is_in: bool,
        data: &mut [u8],
    ) -> Result<usize, XhciError> {
        let slot = self.slots[slot_id as usize]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        // Calculate DCI
        let dci = if is_in {
            (ep as usize * 2) + 1
        } else {
            ep as usize * 2
        };

        let ring = slot.transfer_rings[dci - 1]
            .as_mut()
            .ok_or(XhciError::DeviceNotFound)?;

        // Create Normal TRB
        let mut trb = Trb::default();
        trb.param = data.as_ptr() as u64;
        trb.status = data.len() as u32;
        trb.set_type(TRB_TYPE_NORMAL);
        trb.control |= 1 << 5; // IOC

        log::trace!(
            "xHCI: bulk_transfer slot={} ep={} dci={} dir={} len={} addr={:#x}",
            slot_id,
            ep,
            dci,
            if is_in { "IN" } else { "OUT" },
            data.len(),
            data.as_ptr() as u64
        );

        ring.enqueue(&trb);

        // Ring doorbell
        self.ring_doorbell(slot_id, dci as u8);

        // Wait for completion
        let completion = self.wait_transfer_completion(slot_id, ep)?;

        let residual = completion.status & 0xFFFFFF;
        Ok(data.len().saturating_sub(residual as usize))
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
        self.slots[slot_id as usize].as_ref()
    }

    /// Get mutable slot info
    pub fn get_slot_mut(&mut self, slot_id: u8) -> Option<&mut UsbSlot> {
        self.slots[slot_id as usize].as_mut()
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

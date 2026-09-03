//! xHCI (USB 3.0) Host Controller Interface driver.
//!
//! Minimal xHCI driver for USB mass storage devices. Controller logic is
//! split by concern: init, commands, slots, transfers, enumerate,
//! configure, bulk, context builders, and the TrbRing in ring.rs.

pub mod bulk;
pub mod commands;
pub mod configure;
pub mod context;
pub mod enumerate;
pub mod init;
pub mod ring;
pub mod slots;
pub mod transfers;

pub use ring::TrbRing;
pub use slots::UsbSlot;

use crate::barrier;
use crate::drivers::mmio::MmioRegion;
use crate::drivers::pci::PciAddress;
use crate::time::wait_for;
use core::ptr;
use xhci::accessor::Mapper;
use xhci::registers::Registers;
use xhci::ring::trb::event;

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

pub(super) type RawTrb = [u32; 4];

#[inline]
pub(super) fn raw_trb_type(raw: &RawTrb) -> u32 {
    (raw[3] >> 10) & 0x3f
}

#[inline]
pub(super) fn raw_completion_code(raw: &RawTrb) -> u32 {
    (raw[2] >> 24) & 0xff
}

#[inline]
pub(super) fn read_event_trb(addr: u64, expected_cycle: bool) -> Option<RawTrb> {
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
pub(super) fn read_event_control(addr: u64) -> u32 {
    // SAFETY: callers pass an address within a page-backed xHCI event ring.
    unsafe { ptr::read_volatile((addr + 12) as *const u32) }
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

impl XhciController {
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
    use xhci::context::{self, InputControlHandler, InputHandler, SlotHandler};
    use xhci::ring::trb::{self, command, event, transfer};

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

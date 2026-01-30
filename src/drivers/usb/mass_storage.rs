//! USB Mass Storage Class driver (Bulk-Only Transport)
//!
//! This module implements the USB Mass Storage Class Bulk-Only Transport (BBB)
//! protocol with SCSI command set for reading from USB drives.
//!
//! This driver works with any USB host controller that implements the
//! `UsbController` trait (xHCI, EHCI, OHCI, UHCI).

use super::controller::{UsbController, UsbError};
use crate::time;
use core::ptr;

/// SCSI Commands
#[allow(dead_code)]
mod scsi_cmd {
    pub const TEST_UNIT_READY: u8 = 0x00;
    pub const REQUEST_SENSE: u8 = 0x03;
    pub const INQUIRY: u8 = 0x12;
    pub const READ_CAPACITY_10: u8 = 0x25;
    pub const READ_10: u8 = 0x28;
    pub const WRITE_10: u8 = 0x2A;
    pub const READ_CAPACITY_16: u8 = 0x9E;
}

/// Command Block Wrapper (CBW) - 31 bytes
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct CommandBlockWrapper {
    /// Signature (0x43425355 = "USBC")
    pub signature: u32,
    /// Tag (echoed in CSW)
    pub tag: u32,
    /// Data Transfer Length
    pub data_transfer_length: u32,
    /// Flags (bit 7: direction - 0=OUT, 1=IN)
    pub flags: u8,
    /// LUN (bits 0-3)
    pub lun: u8,
    /// Command Block Length (1-16)
    pub cb_length: u8,
    /// Command Block (SCSI CDB)
    pub cb: [u8; 16],
}

/// Command Status Wrapper (CSW) - 13 bytes
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct CommandStatusWrapper {
    /// Signature (0x53425355 = "USBS")
    pub signature: u32,
    /// Tag (same as CBW)
    pub tag: u32,
    /// Data Residue
    pub data_residue: u32,
    /// Status (0=passed, 1=failed, 2=phase error)
    pub status: u8,
}

/// CBW Signature
const CBW_SIGNATURE: u32 = 0x43425355;
/// CSW Signature
const CSW_SIGNATURE: u32 = 0x53425355;

/// CSW Status values
mod csw_status {
    pub const PASSED: u8 = 0;
    pub const FAILED: u8 = 1;
    pub const PHASE_ERROR: u8 = 2;
}

/// SCSI Inquiry Response
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct InquiryResponse {
    /// Peripheral device type (bits 0-4), qualifier (bits 5-7)
    pub peripheral: u8,
    /// RMB (bit 7)
    pub rmb: u8,
    /// Version
    pub version: u8,
    /// Response data format (bits 0-3), HiSup (bit 4), NormACA (bit 5)
    pub format: u8,
    /// Additional length
    pub additional_length: u8,
    /// SCCS, ACC, TPGS, 3PC, Reserved, Protect
    pub flags1: u8,
    /// Reserved, EncServ, VS, MultiP, MChngr, Reserved, Addr16
    pub flags2: u8,
    /// Reserved, WBus16, Sync, Linked, Reserved, CmdQue, VS
    pub flags3: u8,
    /// Vendor ID (8 bytes)
    pub vendor: [u8; 8],
    /// Product ID (16 bytes)
    pub product: [u8; 16],
    /// Product Revision (4 bytes)
    pub revision: [u8; 4],
}

/// Read Capacity 10 Response
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
pub struct ReadCapacity10Response {
    /// Last Logical Block Address (big-endian)
    pub last_lba: u32,
    /// Block Length (big-endian)
    pub block_length: u32,
}

/// USB Mass Storage Device
pub struct UsbMassStorage {
    /// Device address (slot ID for xHCI, device address for EHCI/OHCI/UHCI)
    device_addr: u8,
    /// Bulk IN endpoint number
    bulk_in: u8,
    /// Bulk OUT endpoint number
    bulk_out: u8,
    /// Maximum packet size (kept for hardware completeness)
    #[allow(dead_code)]
    max_packet: u16,
    /// LUN
    lun: u8,
    /// Command tag counter
    tag: u32,
    /// Number of blocks
    pub num_blocks: u64,
    /// Block size
    pub block_size: u32,
    /// Vendor string
    pub vendor: [u8; 8],
    /// Product string
    pub product: [u8; 16],
}

/// Mass Storage Error
#[derive(Debug)]
pub enum MassStorageError {
    /// USB transfer error
    Usb(UsbError),
    /// Invalid CSW
    InvalidCsw,
    /// Command failed
    CommandFailed,
    /// Phase error
    PhaseError,
    /// Device not ready
    NotReady,
    /// Invalid parameter
    InvalidParameter,
}

impl From<UsbError> for MassStorageError {
    fn from(e: UsbError) -> Self {
        MassStorageError::Usb(e)
    }
}

impl UsbMassStorage {
    /// Create a new USB mass storage device from any USB controller
    ///
    /// # Arguments
    /// * `controller` - Any USB controller implementing the UsbController trait
    /// * `device_addr` - Device address (slot ID for xHCI, device address for others)
    pub fn new(
        controller: &mut dyn UsbController,
        device_addr: u8,
    ) -> Result<Self, MassStorageError> {
        // Get device info to verify it's a mass storage device
        let device_info = controller
            .get_device_info(device_addr)
            .ok_or(MassStorageError::NotReady)?;

        if !device_info.is_mass_storage {
            return Err(MassStorageError::NotReady);
        }

        // Get bulk endpoint info
        let (bulk_in_ep, bulk_out_ep) = controller
            .get_bulk_endpoints(device_addr)
            .ok_or(MassStorageError::NotReady)?;

        let mut device = Self {
            device_addr,
            bulk_in: bulk_in_ep.number,
            bulk_out: bulk_out_ep.number,
            max_packet: bulk_in_ep.max_packet_size,
            lun: 0,
            tag: 1,
            num_blocks: 0,
            block_size: 512,
            vendor: [0; 8],
            product: [0; 16],
        };

        // Initialize the device
        device.init(controller)?;

        Ok(device)
    }

    /// Initialize the device
    fn init(&mut self, controller: &mut dyn UsbController) -> Result<(), MassStorageError> {
        // Test Unit Ready (may need multiple attempts as device spins up)
        for _ in 0..5 {
            if self.test_unit_ready(controller).is_ok() {
                break;
            }
            // Delay 100ms between retries
            time::delay_ms(100);
        }

        // Inquiry
        self.inquiry(controller)?;

        // Read Capacity
        self.read_capacity(controller)?;

        log::info!(
            "USB Mass Storage: {} {} - {} blocks x {} bytes = {} MB",
            core::str::from_utf8(&self.vendor).unwrap_or("?").trim(),
            core::str::from_utf8(&self.product).unwrap_or("?").trim(),
            self.num_blocks,
            self.block_size,
            (self.num_blocks * self.block_size as u64) / (1024 * 1024)
        );

        Ok(())
    }

    /// Get next tag
    fn next_tag(&mut self) -> u32 {
        let tag = self.tag;
        self.tag = self.tag.wrapping_add(1);
        tag
    }

    /// Send a SCSI command (generic version for any UsbController)
    fn scsi_command(
        &mut self,
        controller: &mut dyn UsbController,
        cdb: &[u8],
        data: Option<&mut [u8]>,
        is_read: bool,
    ) -> Result<usize, MassStorageError> {
        let data_len = data.as_ref().map(|d| d.len()).unwrap_or(0);

        // Build CBW
        let mut cbw = CommandBlockWrapper::default();
        cbw.signature = CBW_SIGNATURE;
        cbw.tag = self.next_tag();
        cbw.data_transfer_length = data_len as u32;
        cbw.flags = if is_read { 0x80 } else { 0x00 };
        cbw.lun = self.lun;
        cbw.cb_length = cdb.len().min(16) as u8;
        cbw.cb[..cdb.len().min(16)].copy_from_slice(&cdb[..cdb.len().min(16)]);

        // Send CBW (OUT)
        let cbw_bytes = unsafe { core::slice::from_raw_parts(&cbw as *const _ as *const u8, 31) };
        let mut cbw_buf = [0u8; 31];
        cbw_buf.copy_from_slice(cbw_bytes);

        controller.bulk_transfer(self.device_addr, self.bulk_out, false, &mut cbw_buf)?;

        // Data phase (if any)
        let transferred = if let Some(buf) = data {
            controller.bulk_transfer(
                self.device_addr,
                if is_read { self.bulk_in } else { self.bulk_out },
                is_read,
                buf,
            )?
        } else {
            0
        };

        // Receive CSW (IN)
        let mut csw_buf = [0u8; 13];
        controller.bulk_transfer(self.device_addr, self.bulk_in, true, &mut csw_buf)?;

        let csw = unsafe { ptr::read_unaligned(csw_buf.as_ptr() as *const CommandStatusWrapper) };

        // Verify CSW
        if csw.signature != CSW_SIGNATURE {
            return Err(MassStorageError::InvalidCsw);
        }

        if csw.tag != cbw.tag {
            return Err(MassStorageError::InvalidCsw);
        }

        match csw.status {
            csw_status::PASSED => Ok(transferred),
            csw_status::FAILED => Err(MassStorageError::CommandFailed),
            csw_status::PHASE_ERROR => Err(MassStorageError::PhaseError),
            _ => Err(MassStorageError::InvalidCsw),
        }
    }

    /// Test Unit Ready command
    fn test_unit_ready(
        &mut self,
        controller: &mut dyn UsbController,
    ) -> Result<(), MassStorageError> {
        let cdb = [scsi_cmd::TEST_UNIT_READY, 0, 0, 0, 0, 0];
        self.scsi_command(controller, &cdb, None, false)?;
        Ok(())
    }

    /// Inquiry command
    fn inquiry(&mut self, controller: &mut dyn UsbController) -> Result<(), MassStorageError> {
        let cdb = [scsi_cmd::INQUIRY, 0, 0, 0, 36, 0]; // Request 36 bytes
        let mut response = [0u8; 36];

        self.scsi_command(controller, &cdb, Some(&mut response), true)?;

        let inquiry = unsafe { ptr::read_unaligned(response.as_ptr() as *const InquiryResponse) };

        self.vendor = inquiry.vendor;
        self.product = inquiry.product;

        Ok(())
    }

    /// Read Capacity command
    fn read_capacity(
        &mut self,
        controller: &mut dyn UsbController,
    ) -> Result<(), MassStorageError> {
        let cdb = [scsi_cmd::READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut response = [0u8; 8];

        self.scsi_command(controller, &cdb, Some(&mut response), true)?;

        let cap =
            unsafe { ptr::read_unaligned(response.as_ptr() as *const ReadCapacity10Response) };

        // Values are big-endian
        let last_lba = u32::from_be(cap.last_lba);
        let block_len = u32::from_be(cap.block_length);

        self.num_blocks = last_lba as u64 + 1;
        self.block_size = block_len;

        // If last_lba is 0xFFFFFFFF, we need READ CAPACITY 16
        if last_lba == 0xFFFFFFFF {
            self.read_capacity_16(controller)?;
        }

        Ok(())
    }

    /// Read Capacity 16 command (for large drives)
    fn read_capacity_16(
        &mut self,
        controller: &mut dyn UsbController,
    ) -> Result<(), MassStorageError> {
        let mut cdb = [0u8; 16];
        cdb[0] = scsi_cmd::READ_CAPACITY_16;
        cdb[1] = 0x10; // Service Action = Read Capacity
        cdb[13] = 32; // Allocation length

        let mut response = [0u8; 32];
        self.scsi_command(controller, &cdb, Some(&mut response), true)?;

        // Response: bytes 0-7 = last LBA (big-endian), bytes 8-11 = block length (big-endian)
        let last_lba = u64::from_be_bytes([
            response[0],
            response[1],
            response[2],
            response[3],
            response[4],
            response[5],
            response[6],
            response[7],
        ]);
        let block_len = u32::from_be_bytes([response[8], response[9], response[10], response[11]]);

        self.num_blocks = last_lba + 1;
        self.block_size = block_len;

        Ok(())
    }

    /// Read sectors from the device (generic version)
    pub fn read_sectors_generic(
        &mut self,
        controller: &mut dyn UsbController,
        start_lba: u64,
        num_sectors: u32,
        buffer: &mut [u8],
    ) -> Result<(), MassStorageError> {
        if buffer.len() < (num_sectors as usize * self.block_size as usize) {
            return Err(MassStorageError::InvalidParameter);
        }

        // Use READ(10) for small LBAs, READ(16) for large
        if start_lba + num_sectors as u64 <= 0xFFFFFFFF {
            self.read_10(controller, start_lba as u32, num_sectors as u16, buffer)
        } else {
            self.read_16(controller, start_lba, num_sectors, buffer)
        }
    }

    // Note: read_sectors() was removed - use read_sectors_generic() instead

    /// READ(10) command
    fn read_10(
        &mut self,
        controller: &mut dyn UsbController,
        lba: u32,
        count: u16,
        buffer: &mut [u8],
    ) -> Result<(), MassStorageError> {
        let lba_bytes = lba.to_be_bytes();
        let count_bytes = count.to_be_bytes();

        let cdb = [
            scsi_cmd::READ_10,
            0,
            lba_bytes[0],
            lba_bytes[1],
            lba_bytes[2],
            lba_bytes[3],
            0,
            count_bytes[0],
            count_bytes[1],
            0,
        ];

        let transfer_len = count as usize * self.block_size as usize;
        self.scsi_command(controller, &cdb, Some(&mut buffer[..transfer_len]), true)?;

        Ok(())
    }

    /// READ(16) command (for large LBAs)
    fn read_16(
        &mut self,
        controller: &mut dyn UsbController,
        lba: u64,
        count: u32,
        buffer: &mut [u8],
    ) -> Result<(), MassStorageError> {
        let lba_bytes = lba.to_be_bytes();
        let count_bytes = count.to_be_bytes();

        let cdb = [
            0x88, // READ(16)
            0,
            lba_bytes[0],
            lba_bytes[1],
            lba_bytes[2],
            lba_bytes[3],
            lba_bytes[4],
            lba_bytes[5],
            lba_bytes[6],
            lba_bytes[7],
            count_bytes[0],
            count_bytes[1],
            count_bytes[2],
            count_bytes[3],
            0,
            0,
        ];

        let transfer_len = count as usize * self.block_size as usize;
        self.scsi_command(controller, &cdb, Some(&mut buffer[..transfer_len]), true)?;

        Ok(())
    }

    /// Get the device address (slot ID for xHCI, device address for others)
    pub fn device_addr(&self) -> u8 {
        self.device_addr
    }

    /// Get the slot ID (alias for device_addr, for backwards compatibility)
    pub fn slot_id(&self) -> u8 {
        self.device_addr
    }
}

// ============================================================================
// Global USB Mass Storage Device
// ============================================================================

use crate::efi;
use spin::Mutex;

/// Global state for USB mass storage
struct GlobalUsbState {
    /// Pointer to the mass storage device
    device_ptr: *mut UsbMassStorage,
    /// Pointer to the controller (as trait object)
    /// This is stored directly to avoid lock contention during reads
    controller_ptr: *mut dyn UsbController,
}

// SAFETY: GlobalUsbState contains raw pointers to UsbMassStorage and UsbController.
// These pointers are:
// 1. Allocated via EFI page allocator and remain valid for firmware lifetime
// 2. Only accessed while holding the GLOBAL_USB_STATE mutex
// 3. The UsbController pointer is a trait object stored in ALL_CONTROLLERS
// The firmware is single-threaded and USB operations are serialized.
unsafe impl Send for GlobalUsbState {}

/// Global USB mass storage device and controller
static GLOBAL_USB_STATE: Mutex<Option<GlobalUsbState>> = Mutex::new(None);

/// Store a USB mass storage device globally
///
/// This takes ownership of the device and stores it for later use by the
/// filesystem protocol. Uses the controller at the specified index.
pub fn store_global_device(device: UsbMassStorage, controller_index: usize) -> bool {
    // Get the controller pointer from ALL_CONTROLLERS
    let controller_ptr = match super::get_controller_ptr(controller_index) {
        Some(c) => c,
        None => {
            log::error!(
                "Failed to get USB controller {} for global device",
                controller_index
            );
            return false;
        }
    };

    // SAFETY: controller_ptr is obtained from get_controller_ptr which returns valid pointers
    unsafe { store_global_device_with_controller_ptr(device, controller_ptr) }
}

/// Store a USB mass storage device globally with a specific controller pointer
///
/// This version takes the controller pointer directly, avoiding the need to
/// look up the controller later (which could cause lock contention).
///
/// # Safety
///
/// The controller_ptr must point to a valid UsbController that remains valid
/// for the lifetime of the firmware.
pub unsafe fn store_global_device_with_controller_ptr(
    device: UsbMassStorage,
    controller_ptr: *mut dyn UsbController,
) -> bool {
    // Allocate memory for the device
    let size = core::mem::size_of::<UsbMassStorage>();
    let pages = size.div_ceil(4096);

    if let Some(mem) = efi::allocate_pages(pages as u64) {
        let device_ptr = mem.as_mut_ptr() as *mut UsbMassStorage;
        unsafe {
            core::ptr::write(device_ptr, device);
        }

        // Get controller type for logging before storing
        let controller_type = unsafe { (*controller_ptr).controller_type() };

        *GLOBAL_USB_STATE.lock() = Some(GlobalUsbState {
            device_ptr,
            controller_ptr,
        });
        log::info!(
            "USB mass storage device stored globally (controller: {})",
            controller_type
        );
        true
    } else {
        log::error!("Failed to allocate memory for global USB device");
        false
    }
}

/// Get a reference to the global USB mass storage device
pub fn get_global_device() -> Option<&'static mut UsbMassStorage> {
    GLOBAL_USB_STATE
        .lock()
        .as_ref()
        .map(|state| unsafe { &mut *state.device_ptr })
}

/// Read a sector from the global USB device
///
/// This function can be used as the read callback for the SimpleFileSystem protocol.
/// It uses the stored controller pointer directly to avoid lock contention.
pub fn global_read_sector(lba: u64, buffer: &mut [u8]) -> Result<(), ()> {
    log::trace!("USB mass storage: read LBA {}", lba);

    // Get the device and controller pointers (release lock immediately)
    let (device_ptr, controller_ptr) = {
        let guard = GLOBAL_USB_STATE.lock();
        match guard.as_ref() {
            Some(state) => (state.device_ptr, state.controller_ptr),
            None => {
                log::error!("USB mass storage: no device configured");
                return Err(());
            }
        }
    };

    // Safety: Pointers were set up during store_global_device and remain valid
    // for the entire boot process (memory is allocated via efi::allocate_pages)
    let device = unsafe { &mut *device_ptr };
    let controller = unsafe { &mut *controller_ptr };

    let result = device.read_sectors_generic(controller, lba, 1, buffer);
    if let Err(ref e) = result {
        log::error!(
            "USB mass storage: read failed at LBA {} via {}: {:?}",
            lba,
            controller.controller_type(),
            e
        );
    }
    result.map_err(|_| ())
}

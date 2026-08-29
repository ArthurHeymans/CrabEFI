//! NVMe driver for CrabEFI
//!
//! This module provides a minimal NVMe driver for reading from NVMe SSDs.
//! It implements the basic NVMe command set needed for booting.

pub mod logic;

use crate::barrier;
use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi;
use crate::efi::dma::{DmaBuffer, DmaCoherency, DmaDirection, DmaMask};
use crate::time::{Timeout, wait_for};
use core::ptr;
use spin::Mutex;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use tock_registers::registers::{ReadOnly, ReadWrite};

use logic::{
    QueueState, build_prps, cap_timeout_ms, decode_lba_size, effective_queue_depth,
    max_prp_transfer, ready_timeout_ms, sectors_per_chunk, supports_4k_page,
};

// NVMe Controller Register definitions using tock-registers
register_bitfields! [
    u64,
    /// Controller Capabilities (CAP)
    CAP [
        /// Maximum Queue Entries Supported (0's based)
        MQES OFFSET(0) NUMBITS(16) [],
        /// Contiguous Queues Required
        CQR OFFSET(16) NUMBITS(1) [],
        /// Arbitration Mechanism Supported
        AMS OFFSET(17) NUMBITS(2) [],
        /// Timeout (in 500ms units)
        TO OFFSET(24) NUMBITS(8) [],
        /// Doorbell Stride (2^(2+DSTRD) bytes)
        DSTRD OFFSET(32) NUMBITS(4) [],
        /// NVM Subsystem Reset Supported
        NSSRS OFFSET(36) NUMBITS(1) [],
        /// Command Sets Supported
        CSS OFFSET(37) NUMBITS(8) [],
        /// Boot Partition Support
        BPS OFFSET(45) NUMBITS(1) [],
        /// Memory Page Size Minimum (2^(12+MPSMIN) bytes)
        MPSMIN OFFSET(48) NUMBITS(4) [],
        /// Memory Page Size Maximum (2^(12+MPSMAX) bytes)
        MPSMAX OFFSET(52) NUMBITS(4) [],
        /// Controller Ready With Media mode supported
        CRMS_CRWMS OFFSET(59) NUMBITS(1) [],
        /// Controller Ready Independent of Media mode supported
        CRMS_CRIMS OFFSET(60) NUMBITS(1) []
    ]
];

register_bitfields! [
    u32,
    /// Version (VS)
    VS [
        /// Tertiary Version Number
        TER OFFSET(0) NUMBITS(8) [],
        /// Minor Version Number
        MNR OFFSET(8) NUMBITS(8) [],
        /// Major Version Number
        MJR OFFSET(16) NUMBITS(16) []
    ],
    /// Controller Configuration (CC)
    CC [
        /// Enable
        EN OFFSET(0) NUMBITS(1) [],
        /// I/O Command Set Selected
        CSS OFFSET(4) NUMBITS(3) [],
        /// Memory Page Size (2^(12+MPS) bytes)
        MPS OFFSET(7) NUMBITS(4) [],
        /// Arbitration Mechanism Selected
        AMS OFFSET(11) NUMBITS(3) [],
        /// Shutdown Notification
        SHN OFFSET(14) NUMBITS(2) [],
        /// I/O Submission Queue Entry Size (2^IOSQES bytes)
        IOSQES OFFSET(16) NUMBITS(4) [],
        /// I/O Completion Queue Entry Size (2^IOCQES bytes)
        IOCQES OFFSET(20) NUMBITS(4) []
    ],
    /// Controller Status (CSTS)
    CSTS [
        /// Ready
        RDY OFFSET(0) NUMBITS(1) [],
        /// Controller Fatal Status
        CFS OFFSET(1) NUMBITS(1) [],
        /// Shutdown Status
        SHST OFFSET(2) NUMBITS(2) [],
        /// NVM Subsystem Reset Occurred
        NSSRO OFFSET(4) NUMBITS(1) [],
        /// Processing Paused
        PP OFFSET(5) NUMBITS(1) []
    ],
    /// Admin Queue Attributes (AQA)
    AQA [
        /// Admin Submission Queue Size (0's based)
        ASQS OFFSET(0) NUMBITS(12) [],
        /// Admin Completion Queue Size (0's based)
        ACQS OFFSET(16) NUMBITS(12) []
    ],
    /// Controller Ready Timeouts (CRTO)
    CRTO [
        /// Controller Ready With Media Timeout (in 500ms units)
        CRWMT OFFSET(0) NUMBITS(16) [],
        /// Controller Ready Independent of Media Timeout (in 500ms units)
        CRIMT OFFSET(16) NUMBITS(16) []
    ]
];

/// NVMe controller registers memory map
#[repr(C)]
pub struct NvmeRegisters {
    /// Controller Capabilities
    pub cap: ReadOnly<u64, CAP::Register>,
    /// Version
    pub vs: ReadOnly<u32, VS::Register>,
    /// Interrupt Mask Set
    pub intms: ReadWrite<u32>,
    /// Interrupt Mask Clear
    pub intmc: ReadWrite<u32>,
    /// Controller Configuration
    pub cc: ReadWrite<u32, CC::Register>,
    /// Reserved
    _reserved0: u32,
    /// Controller Status
    pub csts: ReadOnly<u32, CSTS::Register>,
    /// NVM Subsystem Reset (optional)
    pub nssr: ReadWrite<u32>,
    /// Admin Queue Attributes
    pub aqa: ReadWrite<u32, AQA::Register>,
    /// Admin Submission Queue Base Address, low DWORD
    pub asq_low: ReadWrite<u32>,
    /// Admin Submission Queue Base Address, high DWORD
    pub asq_high: ReadWrite<u32>,
    /// Admin Completion Queue Base Address, low DWORD
    pub acq_low: ReadWrite<u32>,
    /// Admin Completion Queue Base Address, high DWORD
    pub acq_high: ReadWrite<u32>,
    /// Registers between ACQ (0x30) and CRTO (0x68)
    _reserved1: [u32; 12],
    /// Controller Ready Timeouts
    pub crto: ReadOnly<u32, CRTO::Register>,
}

/// NVMe admin commands
#[allow(dead_code)]
mod admin_cmd {
    pub const DELETE_SQ: u8 = 0x00;
    pub const CREATE_SQ: u8 = 0x01;
    pub const GET_LOG_PAGE: u8 = 0x02;
    pub const DELETE_CQ: u8 = 0x04;
    pub const CREATE_CQ: u8 = 0x05;
    pub const IDENTIFY: u8 = 0x06;
    pub const ABORT: u8 = 0x08;
    pub const SET_FEATURES: u8 = 0x09;
    pub const GET_FEATURES: u8 = 0x0A;
    pub const ASYNC_EVENT_REQUEST: u8 = 0x0C;
    /// Security Send (for TCG Opal, IEEE 1667, etc.)
    pub const SECURITY_SEND: u8 = 0x81;
    /// Security Receive (for TCG Opal, IEEE 1667, etc.)
    pub const SECURITY_RECEIVE: u8 = 0x82;
}

/// NVMe I/O commands
#[allow(dead_code)]
mod io_cmd {
    pub const FLUSH: u8 = 0x00;
    pub const WRITE: u8 = 0x01;
    pub const READ: u8 = 0x02;
}

const ADMIN_QUEUE_LIMIT: u16 = 16;
const IO_QUEUE_LIMIT: u16 = 64;
const CONTROLLER_PAGE_SIZE: usize = 4096;
const COMMAND_TIMEOUT_MS: u64 = 5000;
const SHUTDOWN_TIMEOUT_MS: u64 = 5000;

/// NVMe Submission Queue Entry (64 bytes)
#[repr(C, align(64))]
#[derive(Clone, Copy, Default)]
struct SubmissionQueueEntry {
    /// Command Dword 0: Opcode, Fused, reserved, PSDT, CID
    cdw0: u32,
    /// Namespace ID
    nsid: u32,
    /// Reserved
    cdw2: u32,
    /// Reserved
    cdw3: u32,
    /// Metadata Pointer
    mptr: u64,
    /// Data Pointer (PRP Entry 1)
    prp1: u64,
    /// Data Pointer (PRP Entry 2 or PRP List pointer)
    prp2: u64,
    /// Command Dwords 10-15 (command specific)
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
}

impl SubmissionQueueEntry {
    fn new() -> Self {
        Self::default()
    }

    fn set_opcode(&mut self, opcode: u8) {
        self.cdw0 = (self.cdw0 & 0xFFFFFF00) | (opcode as u32);
    }

    fn set_cid(&mut self, cid: u16) {
        self.cdw0 = (self.cdw0 & 0x0000FFFF) | ((cid as u32) << 16);
    }
}

/// NVMe Completion Queue Entry (16 bytes)
#[repr(C, align(16))]
#[derive(Clone, Copy, Default)]
struct CompletionQueueEntry {
    /// Command specific result
    dw0: u32,
    /// Reserved
    dw1: u32,
    /// Submission Queue Head Pointer & SQ Identifier
    sq_head_sqid: u32,
    /// Status Field & Command Identifier
    status_cid: u32,
}

impl CompletionQueueEntry {
    fn status_code(&self) -> u8 {
        ((self.status_cid >> 17) & 0xFF) as u8
    }

    fn status_code_type(&self) -> u8 {
        ((self.status_cid >> 25) & 0x7) as u8
    }

    fn phase(&self) -> bool {
        // Phase bit is bit 16 of the status_cid field (DW3)
        // DW3 layout: bits 0-15 = CID, bit 16 = Phase, bits 17-31 = Status
        (self.status_cid & 0x10000) != 0
    }

    fn cid(&self) -> u16 {
        // Command ID is in bits 0-15 of DW3
        (self.status_cid & 0xFFFF) as u16
    }

    fn sq_head(&self) -> u16 {
        (self.sq_head_sqid & 0xffff) as u16
    }

    fn sq_id(&self) -> u16 {
        (self.sq_head_sqid >> 16) as u16
    }

    fn is_error(&self) -> bool {
        self.status_code() != 0 || self.status_code_type() != 0
    }
}

/// NVMe Identify Controller data structure (first 256 bytes of interest)
#[repr(C)]
#[derive(Clone, Copy)]
struct IdentifyController {
    /// PCI Vendor ID
    vid: u16,
    /// PCI Subsystem Vendor ID
    ssvid: u16,
    /// Serial Number (20 bytes)
    sn: [u8; 20],
    /// Model Number (40 bytes)
    mn: [u8; 40],
    /// Firmware Revision (8 bytes)
    fr: [u8; 8],
    /// Recommended Arbitration Burst
    rab: u8,
    /// IEEE OUI Identifier
    ieee: [u8; 3],
    /// Controller Multi-Path I/O and Namespace Sharing Capabilities
    cmic: u8,
    /// Maximum Data Transfer Size
    mdts: u8,
    /// Controller ID
    cntlid: u16,
    /// Version
    ver: u32,
    /// RTD3 Resume Latency
    rtd3r: u32,
    /// RTD3 Entry Latency
    rtd3e: u32,
    /// Optional Asynchronous Events Supported
    oaes: u32,
    /// Controller Attributes
    ctratt: u32,
    /// Read Recovery Levels Supported
    rrls: u16,
    /// Reserved
    _reserved1: [u8; 9],
    /// Controller Type
    cntrltype: u8,
    /// FRU Globally Unique Identifier
    fguid: [u8; 16],
    /// Command Retry Delay Times
    crdt1: u16,
    crdt2: u16,
    crdt3: u16,
    /// Reserved
    _reserved2: [u8; 106],
    /// NVM Subsystem Report
    nvmsr: u8,
    /// VPD Write Cycle Information
    vwci: u8,
    /// Management Endpoint Capabilities
    mec: u8,
    /// Optional Admin Command Support
    oacs: u16,
    /// Abort Command Limit
    acl: u8,
    /// Asynchronous Event Request Limit
    aerl: u8,
    /// Firmware Updates
    frmw: u8,
    /// Log Page Attributes
    lpa: u8,
    /// Error Log Page Entries
    elpe: u8,
    /// Number of Power States Support
    npss: u8,
    /// Admin Vendor Specific Command Configuration
    avscc: u8,
    /// Autonomous Power State Transition Attributes
    apsta: u8,
    /// Warning Composite Temperature Threshold
    wctemp: u16,
    /// Critical Composite Temperature Threshold
    cctemp: u16,
    /// Maximum Time for Firmware Activation
    mtfa: u16,
    /// Host Memory Buffer Preferred Size
    hmpre: u32,
    /// Host Memory Buffer Minimum Size
    hmmin: u32,
    /// Total NVM Capacity (16 bytes)
    tnvmcap: [u8; 16],
    /// Unallocated NVM Capacity (16 bytes)
    unvmcap: [u8; 16],
}

/// NVMe Identify Namespace data structure (first portion of interest)
#[repr(C)]
#[derive(Clone, Copy)]
struct IdentifyNamespace {
    /// Namespace Size (in logical blocks)
    nsze: u64,
    /// Namespace Capacity (in logical blocks)
    ncap: u64,
    /// Namespace Utilization (in logical blocks)
    nuse: u64,
    /// Namespace Features
    nsfeat: u8,
    /// Number of LBA Formats
    nlbaf: u8,
    /// Formatted LBA Size
    flbas: u8,
    /// Metadata Capabilities
    mc: u8,
    /// End-to-end Data Protection Capabilities
    dpc: u8,
    /// End-to-end Data Protection Type Settings
    dps: u8,
    /// Namespace Multi-path I/O and Namespace Sharing Capabilities
    nmic: u8,
    /// Reservation Capabilities
    rescap: u8,
    /// Format Progress Indicator
    fpi: u8,
    /// Deallocate Logical Block Features
    dlfeat: u8,
    /// Namespace Atomic Write Unit Normal
    nawun: u16,
    /// Namespace Atomic Write Unit Power Fail
    nawupf: u16,
    /// Namespace Atomic Compare & Write Unit
    nacwu: u16,
    /// Namespace Atomic Boundary Size Normal
    nabsn: u16,
    /// Namespace Atomic Boundary Offset
    nabo: u16,
    /// Namespace Atomic Boundary Size Power Fail
    nabspf: u16,
    /// Namespace Optimal I/O Boundary
    noiob: u16,
    /// NVM Capacity (16 bytes)
    nvmcap: [u8; 16],
    /// Namespace Preferred Write Granularity
    npwg: u16,
    /// Namespace Preferred Write Alignment
    npwa: u16,
    /// Namespace Preferred Deallocate Granularity
    npdg: u16,
    /// Namespace Preferred Deallocate Alignment
    npda: u16,
    /// Namespace Optimal Write Size
    nows: u16,
    /// Reserved
    _reserved: [u8; 18],
    /// ANA Group Identifier
    anagrpid: u32,
    /// Reserved
    _reserved2: [u8; 3],
    /// Namespace Attributes
    nsattr: u8,
    /// NVM Set Identifier
    nvmsetid: u16,
    /// Endurance Group Identifier
    endgid: u16,
    /// Namespace Globally Unique Identifier
    nguid: [u8; 16],
    /// IEEE Extended Unique Identifier
    eui64: [u8; 8],
    /// LBA Format 0 Support
    lbaf: [u32; 16],
}

/// LBA Format descriptor
#[derive(Debug, Clone, Copy)]
pub struct LbaFormat {
    /// Logical block size (power of 2)
    pub lba_size: u32,
    /// Metadata size
    pub metadata_size: u16,
    /// Relative performance (0=best, 3=degraded)
    pub relative_perf: u8,
}

/// NVMe namespace information
#[derive(Debug)]
pub struct NvmeNamespace {
    /// Namespace ID
    pub nsid: u32,
    /// Number of logical blocks
    pub num_blocks: u64,
    /// Block size in bytes
    pub block_size: u32,
}

/// NVMe controller
pub struct NvmeController {
    /// PCI address (bus:device.function)
    pci_address: PciAddress,
    /// Pointer to memory-mapped registers (mutable — we write CC, AQA, ASQ, ACQ, etc.)
    regs: *mut NvmeRegisters,
    /// MMIO base address (for doorbell access)
    mmio_base: u64,
    /// Doorbell stride (in bytes)
    doorbell_stride: usize,
    /// Capability value captured before controller programming.
    initial_cap: u64,
    /// Admin submission queue
    admin_sq: *mut SubmissionQueueEntry,
    /// Admin completion queue
    admin_cq: *mut CompletionQueueEntry,
    /// Admin queue bookkeeping and owned DMA allocations.
    admin_queue: QueueState,
    admin_sq_dma: DmaBuffer,
    admin_cq_dma: DmaBuffer,
    /// I/O submission queue
    io_sq: *mut SubmissionQueueEntry,
    /// I/O completion queue
    io_cq: *mut CompletionQueueEntry,
    /// I/O queue bookkeeping and owned DMA allocations.
    io_queue: QueueState,
    io_sq_dma: Option<DmaBuffer>,
    io_cq_dma: Option<DmaBuffer>,
    /// Detected namespaces
    namespaces: heapless::Vec<NvmeNamespace, 8>,
    /// Permanent Identify payload, retained across command timeouts.
    identify: DmaBuffer,
    /// Controller memory page size selected in CC.MPS.
    controller_page_size: usize,
    /// Page-backed staging area sized for the largest accepted logical block.
    staging: Option<DmaBuffer>,
    /// One page containing PRP-list entries for transfers over two pages.
    prp_list: DmaBuffer,
    /// A timed-out data command still owns shared DMA memory.
    dma_quarantined: bool,
}

/// NVMe error type
#[derive(Debug)]
pub enum NvmeError {
    /// Controller not ready
    NotReady,
    /// Command failed
    CommandFailed(u8, u8),
    /// Timeout waiting for completion
    Timeout,
    /// No namespaces found
    NoNamespaces,
    /// Invalid namespace
    InvalidNamespace,
    /// Allocation failed
    AllocationFailed,
    /// Invalid parameter
    InvalidParameter,
    /// Controller capabilities cannot be safely programmed by this driver.
    UnsupportedCapability,
    /// Namespace LBA or metadata format is unsupported.
    UnsupportedLbaFormat,
    /// Queue has no safe slot or command identifier.
    QueueFull,
    /// DMA ownership synchronization failed.
    DmaError,
}

impl NvmeController {
    /// Create a new NVMe controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, NvmeError> {
        let mmio_base = pci_dev.mmio_base().ok_or(NvmeError::NotReady)?;
        let regs = mmio_base as *mut NvmeRegisters;

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        // Read capabilities using typed register access
        let regs_ref = unsafe { &*regs };
        let cap = regs_ref.cap.get();
        let doorbell_stride = 4usize << regs_ref.cap.read(CAP::DSTRD);
        let mqes = regs_ref.cap.read(CAP::MQES) as u16;
        let max_queue_entries = usize::from(mqes) + 1;
        if !supports_4k_page(
            regs_ref.cap.read(CAP::MPSMIN) as u8,
            regs_ref.cap.read(CAP::MPSMAX) as u8,
        ) {
            log::error!("NVMe: controller does not support 4 KiB memory pages");
            return Err(NvmeError::UnsupportedCapability);
        }
        let admin_depth = effective_queue_depth(ADMIN_QUEUE_LIMIT, mqes);
        let io_depth = effective_queue_depth(IO_QUEUE_LIMIT, mqes);
        if admin_depth < 2 || io_depth < 2 {
            return Err(NvmeError::UnsupportedCapability);
        }

        log::debug!("NVMe CAP: {:#018x}", cap);
        log::debug!("  Doorbell stride: {} bytes", doorbell_stride);
        log::debug!("  Max queue entries: {}", max_queue_entries);

        // Read version using typed register access
        let major = regs_ref.vs.read(VS::MJR);
        let minor = regs_ref.vs.read(VS::MNR);
        let tertiary = regs_ref.vs.read(VS::TER);
        log::info!("NVMe version: {}.{}.{}", major, minor, tertiary);

        let admin_sq_dma = DmaBuffer::allocate(
            usize::from(admin_depth) * core::mem::size_of::<SubmissionQueueEntry>(),
            DmaMask::bits64(),
            DmaCoherency::Coherent,
        )
        .map_err(|_| NvmeError::AllocationFailed)?;
        let admin_cq_dma = DmaBuffer::allocate(
            usize::from(admin_depth) * core::mem::size_of::<CompletionQueueEntry>(),
            DmaMask::bits64(),
            DmaCoherency::Coherent,
        )
        .map_err(|_| NvmeError::AllocationFailed)?;
        let admin_sq = admin_sq_dma.dma_address() as *mut SubmissionQueueEntry;
        let admin_cq = admin_cq_dma.dma_address() as *mut CompletionQueueEntry;
        let identify = DmaBuffer::allocate(
            CONTROLLER_PAGE_SIZE,
            DmaMask::bits64(),
            DmaCoherency::Coherent,
        )
        .map_err(|_| NvmeError::AllocationFailed)?;
        let prp_list = DmaBuffer::allocate(
            CONTROLLER_PAGE_SIZE,
            DmaMask::bits64(),
            DmaCoherency::Coherent,
        )
        .map_err(|_| NvmeError::AllocationFailed)?;

        let mut controller = Self {
            pci_address: pci_dev.address,
            regs,
            mmio_base,
            doorbell_stride,
            initial_cap: cap,
            admin_sq,
            admin_cq,
            admin_queue: QueueState::new(admin_depth),
            admin_sq_dma,
            admin_cq_dma,
            io_sq: ptr::null_mut(),
            io_cq: ptr::null_mut(),
            io_queue: QueueState::new(io_depth),
            io_sq_dma: None,
            io_cq_dma: None,
            namespaces: heapless::Vec::new(),
            identify,
            controller_page_size: CONTROLLER_PAGE_SIZE,
            staging: None,
            prp_list,
            dma_quarantined: false,
        };

        if let Err(error) = controller.init() {
            let regs = unsafe { &*controller.regs };
            regs.cc.modify(CC::EN::CLEAR + CC::SHN.val(0));
            let disabled = wait_for(cap_timeout_ms(regs.cap.read(CAP::TO)), || {
                regs.csts.read(CSTS::RDY) == 0
            });
            if !disabled {
                log::error!(
                    "NVMe {}: initialization failed and RDY stayed set; leaking DMA allocations",
                    controller.pci_address
                );
                core::mem::forget(controller);
            }
            return Err(error);
        }
        Ok(controller)
    }

    /// Write a doorbell register (doorbells are outside the typed register struct)
    #[inline]
    fn write_doorbell(&self, offset: u64, value: u32) {
        // Order queue-memory updates before notifying the controller through MMIO.
        barrier::mmio_write();
        unsafe {
            ptr::write_volatile((self.mmio_base + offset) as *mut u32, value);
        }
    }

    /// Write a 64-bit NVMe queue-base register as ordered low/high DWORDs.
    ///
    /// NVMe queue-base address registers must be programmed by writing the low
    /// DWORD first and the high DWORD second. This also matches Linux, EDK2 DXE,
    /// SeaBIOS, and U-Boot and avoids controllers that do not accept a native
    /// 64-bit MMIO transaction for ASQ or ACQ.
    #[inline]
    fn write_queue_base(low: &ReadWrite<u32>, high: &ReadWrite<u32>, address: u64) {
        low.set(address as u32);
        high.set((address >> 32) as u32);
    }

    /// Read a 64-bit NVMe queue-base register as low/high DWORDs.
    #[inline]
    fn read_queue_base(low: &ReadWrite<u32>, high: &ReadWrite<u32>) -> u64 {
        u64::from(low.get()) | (u64::from(high.get()) << 32)
    }

    /// Get doorbell register offset for a queue
    fn doorbell_offset(&self, queue_id: u16, is_completion: bool) -> u64 {
        let base = 0x1000u64;
        let idx = (queue_id as u64) * 2 + if is_completion { 1 } else { 0 };
        base + idx * (self.doorbell_stride as u64)
    }

    /// Ring the submission queue doorbell
    fn ring_sq_doorbell(&mut self, queue_id: u16, tail: u16) {
        let offset = self.doorbell_offset(queue_id, false);
        self.write_doorbell(offset, tail as u32);
    }

    /// Ring the completion queue doorbell
    fn ring_cq_doorbell(&mut self, queue_id: u16, head: u16) {
        let offset = self.doorbell_offset(queue_id, true);
        self.write_doorbell(offset, head as u32);
    }

    /// Initialize the controller
    fn init(&mut self) -> Result<(), NvmeError> {
        // SAFETY: `self.regs` points to MMIO registers mapped by PCI BAR.
        // The pointer is valid for the lifetime of the NvmeController.
        let regs = unsafe { &*self.regs };

        // CAP.TO specifies the maximum disable transition time in 500 ms
        // units. A zero value still permits one 500 ms unit.
        let disable_timeout_ms = cap_timeout_ms(regs.cap.read(CAP::TO));

        // Disable the controller
        regs.cc.modify(CC::EN::CLEAR);

        if !wait_for(disable_timeout_ms, || regs.csts.read(CSTS::RDY) == 0) {
            log::error!(
                "NVMe: Timeout waiting {} ms for controller to disable",
                disable_timeout_ms
            );
            return Err(NvmeError::Timeout);
        }

        // Set admin queue attributes
        let admin_qsize = u32::from(self.admin_queue.depth - 1);
        regs.aqa
            .write(AQA::ASQS.val(admin_qsize) + AQA::ACQS.val(admin_qsize));

        // Program 64-bit queue addresses as low then high DWORD writes, as
        // required for NVMe queue-base registers.
        let admin_sq_address = self.admin_sq as u64;
        let admin_cq_address = self.admin_cq as u64;
        Self::write_queue_base(&regs.asq_low, &regs.asq_high, admin_sq_address);
        Self::write_queue_base(&regs.acq_low, &regs.acq_high, admin_cq_address);

        let programmed_asq = Self::read_queue_base(&regs.asq_low, &regs.asq_high);
        let programmed_acq = Self::read_queue_base(&regs.acq_low, &regs.acq_high);
        log::debug!(
            "NVMe admin queues: AQA={:#010x}, ASQ={:#018x}, ACQ={:#018x}",
            regs.aqa.get(),
            programmed_asq,
            programmed_acq
        );
        if programmed_asq != admin_sq_address || programmed_acq != admin_cq_address {
            log::error!(
                "NVMe admin queue register readback mismatch: expected ASQ={:#018x} ACQ={:#018x}",
                admin_sq_address,
                admin_cq_address
            );
            return Err(NvmeError::NotReady);
        }

        // Configure controller:
        // - Memory Page Size (MPS) = 0 (4KB)
        // - Command Set Selected (CSS) = 0 (NVM)
        // - Arbitration Mechanism Selected (AMS) = 0 (Round Robin)
        // - Shutdown Notification (SHN) = 0
        // - I/O Submission Queue Entry Size (IOSQES) = 6 (64 bytes)
        // - I/O Completion Queue Entry Size (IOCQES) = 4 (16 bytes)
        regs.cc.write(
            CC::CSS.val(0)
                + CC::MPS.val(0)
                + CC::AMS.val(0)
                + CC::SHN.val(0)
                + CC::IOSQES.val(6)
                + CC::IOCQES.val(4),
        );

        // NVMe 2.0 controllers may advertise the wider Controller Ready With
        // Media timeout in CRTO. Use the larger value because some devices
        // report a CRTO value smaller than the legacy CAP.TO value.
        let enable_timeout_ms = ready_timeout_ms(
            regs.cap.read(CAP::TO),
            regs.cap
                .is_set(CAP::CRMS_CRWMS)
                .then(|| u64::from(regs.crto.read(CRTO::CRWMT))),
        );

        let reread_cap = regs.cap.get();
        let reread_mqes = regs.cap.read(CAP::MQES) as u16;
        if !supports_4k_page(
            regs.cap.read(CAP::MPSMIN) as u8,
            regs.cap.read(CAP::MPSMAX) as u8,
        ) || effective_queue_depth(ADMIN_QUEUE_LIMIT, reread_mqes) < self.admin_queue.depth
            || effective_queue_depth(IO_QUEUE_LIMIT, reread_mqes) < self.io_queue.depth
            || regs.cap.read(CAP::DSTRD) != ((self.initial_cap >> 32) & 0xf)
        {
            log::error!(
                "NVMe: CAP changed incompatibly while enabling ({:#018x} -> {:#018x})",
                self.initial_cap,
                reread_cap
            );
            return Err(NvmeError::UnsupportedCapability);
        }
        log::debug!("NVMe CAP after CC programming: {:#018x}", regs.cap.get());
        regs.cc.modify(CC::EN::SET);

        let timeout = Timeout::from_ms(enable_timeout_ms);
        while !timeout.is_expired() {
            if regs.csts.read(CSTS::RDY) != 0 {
                log::debug!("NVMe controller ready");
                break;
            }
            if regs.csts.read(CSTS::CFS) != 0 {
                log::error!("Controller fatal status!");
                return Err(NvmeError::NotReady);
            }
            core::hint::spin_loop();
        }

        if regs.csts.read(CSTS::RDY) == 0 {
            return Err(NvmeError::NotReady);
        }

        log::info!("NVMe controller initialized");

        // Identify controller
        self.identify_controller()?;

        // Create I/O queues
        self.create_io_queues()?;

        // Identify namespaces
        self.identify_namespaces()?;

        Ok(())
    }

    fn submit_admin_command(&mut self, mut cmd: SubmissionQueueEntry) -> Result<u16, NvmeError> {
        self.refresh_dma_quarantine();
        if self.dma_quarantined {
            return Err(NvmeError::QueueFull);
        }
        let (cid, slot) = self.admin_queue.reserve().ok_or(NvmeError::QueueFull)?;
        cmd.set_cid(cid);
        unsafe { ptr::write_volatile(self.admin_sq.add(slot as usize), cmd) };
        self.admin_sq_dma
            .sync_for_device(0..self.admin_sq_dma.len(), DmaDirection::ToDevice)
            .map_err(|_| NvmeError::DmaError)?;
        self.ring_sq_doorbell(0, self.admin_queue.sq_tail);
        Ok(cid)
    }

    fn submit_io_command(&mut self, mut cmd: SubmissionQueueEntry) -> Result<u16, NvmeError> {
        self.refresh_dma_quarantine();
        if self.dma_quarantined {
            return Err(NvmeError::QueueFull);
        }
        let (cid, slot) = self.io_queue.reserve().ok_or(NvmeError::QueueFull)?;
        cmd.set_cid(cid);
        unsafe { ptr::write_volatile(self.io_sq.add(slot as usize), cmd) };
        let dma = self.io_sq_dma.as_ref().ok_or(NvmeError::NotReady)?;
        dma.sync_for_device(0..dma.len(), DmaDirection::ToDevice)
            .map_err(|_| NvmeError::DmaError)?;
        self.ring_sq_doorbell(1, self.io_queue.sq_tail);
        Ok(cid)
    }

    fn drain_cq(
        cq: *mut CompletionQueueEntry,
        state: &mut QueueState,
        queue_id: u16,
        requested_cid: Option<u16>,
    ) -> (Option<CompletionQueueEntry>, bool) {
        let mut requested = None;
        let mut drained = false;
        for _ in 0..state.depth {
            let head = state.cq_head as usize;
            let observed = unsafe { ptr::read_volatile(cq.add(head)) };
            if observed.phase() != state.cq_phase {
                break;
            }
            barrier::dma_read();
            let entry = unsafe { ptr::read_volatile(cq.add(head)) };
            if entry.phase() != state.cq_phase {
                break;
            }
            let cid = entry.cid();
            let sq_head = if entry.sq_id() == queue_id {
                entry.sq_head()
            } else {
                log::error!(
                    "NVMe CQ{}: completion CID {} reported unexpected SQID {}",
                    queue_id,
                    cid,
                    entry.sq_id()
                );
                state.sq_head
            };
            match state.retire(cid, sq_head) {
                Some(pending) if pending.timed_out => {
                    log::warn!("NVMe CQ{}: consumed late completion CID {}", queue_id, cid);
                }
                Some(_) => {}
                None => log::warn!(
                    "NVMe CQ{}: consumed completion for untracked CID {}",
                    queue_id,
                    cid
                ),
            }
            if requested_cid == Some(cid) {
                requested = Some(entry);
            }
            state.advance_cq();
            drained = true;
        }
        (requested, drained)
    }

    fn refresh_dma_quarantine(&mut self) {
        if self
            .admin_cq_dma
            .sync_for_cpu(0..self.admin_cq_dma.len(), DmaDirection::FromDevice)
            .is_err()
        {
            self.dma_quarantined = true;
            return;
        }
        let (admin_entry, admin_drained) =
            Self::drain_cq(self.admin_cq, &mut self.admin_queue, 0, None);
        debug_assert!(admin_entry.is_none());
        if admin_drained {
            self.ring_cq_doorbell(0, self.admin_queue.cq_head);
        }
        if !self.io_cq.is_null() {
            let Some(io_cq_dma) = self.io_cq_dma.as_ref() else {
                self.dma_quarantined = true;
                return;
            };
            if io_cq_dma
                .sync_for_cpu(0..io_cq_dma.len(), DmaDirection::FromDevice)
                .is_err()
            {
                self.dma_quarantined = true;
                return;
            }
            let (io_entry, io_drained) = Self::drain_cq(self.io_cq, &mut self.io_queue, 1, None);
            debug_assert!(io_entry.is_none());
            if io_drained {
                self.ring_cq_doorbell(1, self.io_queue.cq_head);
            }
        }
        self.dma_quarantined = self
            .admin_queue
            .pending()
            .chain(self.io_queue.pending())
            .any(|pending| pending.timed_out);
    }

    fn wait_completion(
        &mut self,
        queue_id: u16,
        cid: u16,
    ) -> Result<CompletionQueueEntry, NvmeError> {
        let timeout = Timeout::from_ms(COMMAND_TIMEOUT_MS);
        while !timeout.is_expired() {
            let (entry, drained, head) = if queue_id == 0 {
                self.admin_cq_dma
                    .sync_for_cpu(0..self.admin_cq_dma.len(), DmaDirection::FromDevice)
                    .map_err(|_| NvmeError::DmaError)?;
                let (entry, drained) =
                    Self::drain_cq(self.admin_cq, &mut self.admin_queue, 0, Some(cid));
                (entry, drained, self.admin_queue.cq_head)
            } else {
                let dma = self.io_cq_dma.as_ref().ok_or(NvmeError::NotReady)?;
                dma.sync_for_cpu(0..dma.len(), DmaDirection::FromDevice)
                    .map_err(|_| NvmeError::DmaError)?;
                let (entry, drained) = Self::drain_cq(self.io_cq, &mut self.io_queue, 1, Some(cid));
                (entry, drained, self.io_queue.cq_head)
            };
            if drained {
                self.ring_cq_doorbell(queue_id, head);
            }
            if let Some(entry) = entry {
                return if entry.is_error() {
                    Err(NvmeError::CommandFailed(
                        entry.status_code_type(),
                        entry.status_code(),
                    ))
                } else {
                    Ok(entry)
                };
            }
            core::hint::spin_loop();
        }
        let state = if queue_id == 0 {
            &mut self.admin_queue
        } else {
            &mut self.io_queue
        };
        state.mark_timed_out(cid);
        self.dma_quarantined = true;
        let regs = unsafe { &*self.regs };
        let current = unsafe {
            ptr::read_volatile(if queue_id == 0 {
                self.admin_cq.add(state.cq_head as usize)
            } else {
                self.io_cq.add(state.cq_head as usize)
            })
        };
        log::error!(
            "NVMe {} CQ timeout: requested CID={}, SQ head/tail={}/{}, CQ head/phase={}/{}, CSTS={:#x}, CQE cid={} phase={}",
            self.pci_address,
            cid,
            state.sq_head,
            state.sq_tail,
            state.cq_head,
            state.cq_phase as u8,
            regs.csts.get(),
            current.cid(),
            current.phase() as u8
        );
        for pending in state.pending() {
            log::error!(
                "NVMe pending CID={} timed_out={}",
                pending.cid,
                pending.timed_out
            );
        }
        Err(NvmeError::Timeout)
    }

    fn wait_admin_completion(&mut self, cid: u16) -> Result<CompletionQueueEntry, NvmeError> {
        self.wait_completion(0, cid)
    }

    fn wait_io_completion(&mut self, cid: u16) -> Result<CompletionQueueEntry, NvmeError> {
        self.wait_completion(1, cid)
    }

    /// Identify the controller
    fn identify_controller(&mut self) -> Result<(), NvmeError> {
        self.identify.as_mut_slice().fill(0);
        let identify_addr = self.identify.dma_address();
        self.identify
            .sync_for_device(0..self.identify.len(), DmaDirection::FromDevice)
            .map_err(|_| NvmeError::DmaError)?;
        let mut cmd = SubmissionQueueEntry::new();
        cmd.set_opcode(admin_cmd::IDENTIFY);
        cmd.prp1 = identify_addr;
        cmd.cdw10 = 0x01;
        let cid = self.submit_admin_command(cmd)?;
        self.wait_admin_completion(cid)?;
        self.identify
            .sync_for_cpu(0..self.identify.len(), DmaDirection::FromDevice)
            .map_err(|_| NvmeError::DmaError)?;
        let ctrl = unsafe { &*(identify_addr as *const IdentifyController) };
        let model = core::str::from_utf8(&ctrl.mn).unwrap_or("Unknown").trim();
        let serial = core::str::from_utf8(&ctrl.sn).unwrap_or("Unknown").trim();
        let firmware = core::str::from_utf8(&ctrl.fr).unwrap_or("Unknown").trim();
        log::info!(
            "NVMe Controller: {} (S/N: {}, FW: {})",
            model,
            serial,
            firmware
        );
        Ok(())
    }

    /// Create I/O submission and completion queues
    fn create_io_queues(&mut self) -> Result<(), NvmeError> {
        let io_sq_dma = DmaBuffer::allocate(
            usize::from(self.io_queue.depth) * core::mem::size_of::<SubmissionQueueEntry>(),
            DmaMask::bits64(),
            DmaCoherency::Coherent,
        )
        .map_err(|_| NvmeError::AllocationFailed)?;
        let io_cq_dma = DmaBuffer::allocate(
            usize::from(self.io_queue.depth) * core::mem::size_of::<CompletionQueueEntry>(),
            DmaMask::bits64(),
            DmaCoherency::Coherent,
        )
        .map_err(|_| NvmeError::AllocationFailed)?;
        self.io_sq = io_sq_dma.dma_address() as *mut SubmissionQueueEntry;
        self.io_cq = io_cq_dma.dma_address() as *mut CompletionQueueEntry;
        self.io_sq_dma = Some(io_sq_dma);
        self.io_cq_dma = Some(io_cq_dma);

        // Create I/O Completion Queue (queue ID = 1)
        let mut cmd = SubmissionQueueEntry::new();
        cmd.set_opcode(admin_cmd::CREATE_CQ);
        cmd.prp1 = self.io_cq as u64;
        cmd.cdw10 = (u32::from(self.io_queue.depth - 1) << 16) | 1; // QSIZE | QCQID
        cmd.cdw11 = 0x01; // PC=1 (physically contiguous), IEN=0, IV=0

        let cid = self.submit_admin_command(cmd)?;
        self.wait_admin_completion(cid)?;
        log::debug!("Created I/O completion queue 1");

        // Create I/O Submission Queue (queue ID = 1)
        let mut cmd = SubmissionQueueEntry::new();
        cmd.set_opcode(admin_cmd::CREATE_SQ);
        cmd.prp1 = self.io_sq as u64;
        cmd.cdw10 = (u32::from(self.io_queue.depth - 1) << 16) | 1; // QSIZE | QSQID
        cmd.cdw11 = (1 << 16) | 0x01; // CQID=1 | PC=1

        let cid = self.submit_admin_command(cmd)?;
        self.wait_admin_completion(cid)?;
        log::debug!("Created I/O submission queue 1");

        Ok(())
    }

    /// Identify namespaces
    fn identify_namespaces(&mut self) -> Result<(), NvmeError> {
        let mut largest_block = 0usize;
        let identify_addr = self.identify.dma_address();
        self.identify.as_mut_slice().fill(0);
        self.identify
            .sync_for_device(0..self.identify.len(), DmaDirection::FromDevice)
            .map_err(|_| NvmeError::DmaError)?;
        let mut cmd = SubmissionQueueEntry::new();
        cmd.set_opcode(admin_cmd::IDENTIFY);
        cmd.prp1 = identify_addr;
        cmd.cdw10 = 0x02;
        let cid = self.submit_admin_command(cmd)?;
        self.wait_admin_completion(cid)?;
        self.identify
            .sync_for_cpu(0..self.identify.len(), DmaDirection::FromDevice)
            .map_err(|_| NvmeError::DmaError)?;
        let mut namespace_ids = [0u32; 1024];
        namespace_ids.copy_from_slice(unsafe {
            core::slice::from_raw_parts(identify_addr as *const u32, 1024)
        });

        for nsid in namespace_ids.into_iter().take_while(|nsid| *nsid != 0) {
            self.identify.as_mut_slice().fill(0);
            self.identify
                .sync_for_device(0..self.identify.len(), DmaDirection::FromDevice)
                .map_err(|_| NvmeError::DmaError)?;
            let mut cmd = SubmissionQueueEntry::new();
            cmd.set_opcode(admin_cmd::IDENTIFY);
            cmd.nsid = nsid;
            cmd.prp1 = identify_addr;
            let cid = self.submit_admin_command(cmd)?;
            self.wait_admin_completion(cid)?;
            self.identify
                .sync_for_cpu(0..self.identify.len(), DmaDirection::FromDevice)
                .map_err(|_| NvmeError::DmaError)?;
            let ns = unsafe { &*(identify_addr as *const IdentifyNamespace) };
            if ns.nsze == 0 {
                log::warn!("NVMe namespace {} has zero size; skipping", nsid);
                continue;
            }
            let Some(block_size) = decode_lba_size(ns.flbas, ns.nlbaf, &ns.lbaf) else {
                log::warn!(
                    "NVMe namespace {} has unsupported LBA/metadata format",
                    nsid
                );
                continue;
            };
            let max_transfer = max_prp_transfer(self.controller_page_size)
                .ok_or(NvmeError::UnsupportedLbaFormat)?;
            if block_size as usize > max_transfer {
                log::warn!(
                    "NVMe namespace {} LBA size {} exceeds PRP limit {}",
                    nsid,
                    block_size,
                    max_transfer
                );
                continue;
            }
            largest_block = largest_block.max(block_size as usize);
            let namespace = NvmeNamespace {
                nsid,
                num_blocks: ns.nsze,
                block_size,
            };
            let size_mb = namespace
                .num_blocks
                .saturating_mul(u64::from(namespace.block_size))
                / (1024 * 1024);
            log::info!(
                "NVMe Namespace {}: {} blocks x {} bytes = {} MB",
                nsid,
                namespace.num_blocks,
                namespace.block_size,
                size_mb
            );
            if self.namespaces.push(namespace).is_err() {
                log::warn!("NVMe: namespace list full; skipping namespace {}", nsid);
            }
        }
        if self.namespaces.is_empty() {
            return Err(NvmeError::NoNamespaces);
        }
        self.staging = Some(
            DmaBuffer::allocate(
                largest_block.max(CONTROLLER_PAGE_SIZE),
                DmaMask::bits64(),
                DmaCoherency::Coherent,
            )
            .map_err(|_| NvmeError::AllocationFailed)?,
        );
        Ok(())
    }

    /// Get the first namespace
    pub fn get_namespace(&self, nsid: u32) -> Option<&NvmeNamespace> {
        self.namespaces.iter().find(|ns| ns.nsid == nsid)
    }

    /// Get the default namespace (usually namespace 1)
    pub fn default_namespace(&self) -> Option<&NvmeNamespace> {
        self.namespaces.first()
    }

    /// Get the PCI address of this controller
    pub fn pci_address(&self) -> PciAddress {
        self.pci_address
    }

    /// Read sectors from a namespace.
    ///
    /// Uses an internal page-aligned DMA buffer to avoid corruption when
    /// callers pass misaligned buffers (e.g., stack buffers).
    ///
    /// # Safety contract
    ///
    /// The caller must ensure that `buffer` points to a valid, writable memory
    /// region of at least `num_sectors * block_size` bytes. Passing an
    /// insufficiently sized buffer will result in memory corruption.
    pub fn read_sectors(
        &mut self,
        nsid: u32,
        start_lba: u64,
        num_sectors: u32,
        buffer: *mut u8,
    ) -> Result<(), NvmeError> {
        let ns = self
            .get_namespace(nsid)
            .ok_or(NvmeError::InvalidNamespace)?;
        let block_size = ns.block_size as usize;
        let namespace_blocks = ns.num_blocks;
        if num_sectors == 0 || buffer.is_null() {
            return Err(NvmeError::InvalidParameter);
        }
        let end_lba = start_lba
            .checked_add(u64::from(num_sectors))
            .ok_or(NvmeError::InvalidParameter)?;
        if end_lba > namespace_blocks {
            return Err(NvmeError::InvalidParameter);
        }
        let staging_len = self.staging.as_ref().ok_or(NvmeError::NotReady)?.len();
        let chunk_limit =
            sectors_per_chunk(block_size, staging_len).ok_or(NvmeError::UnsupportedLbaFormat)?;
        let mut remaining = num_sectors;
        let mut current_lba = start_lba;
        let mut byte_offset = 0usize;
        while remaining != 0 {
            let chunk = remaining.min(chunk_limit);
            let destination = buffer.wrapping_add(byte_offset);
            self.read_sectors_internal(nsid, current_lba, chunk, destination)?;
            remaining -= chunk;
            current_lba += u64::from(chunk);
            byte_offset = byte_offset
                .checked_add(chunk as usize * block_size)
                .ok_or(NvmeError::InvalidParameter)?;
        }
        Ok(())
    }

    /// Internal read function that uses the page-aligned DMA buffer.
    ///
    /// The caller MUST ensure that `num_sectors * block_size <= 4096` (one page),
    /// as the DMA buffer is exactly one page. This is enforced by an assertion.
    fn read_sectors_internal(
        &mut self,
        nsid: u32,
        start_lba: u64,
        num_sectors: u32,
        buffer: *mut u8,
    ) -> Result<(), NvmeError> {
        let block_size = self
            .get_namespace(nsid)
            .ok_or(NvmeError::InvalidNamespace)?
            .block_size as usize;
        let transfer_size = (num_sectors as usize)
            .checked_mul(block_size)
            .ok_or(NvmeError::InvalidParameter)?;
        if num_sectors == 0 || num_sectors > 65536 || buffer.is_null() {
            return Err(NvmeError::InvalidParameter);
        }

        let (prp1, prp2) = {
            let staging = self.staging.as_ref().ok_or(NvmeError::NotReady)?;
            if transfer_size > staging.len() {
                return Err(NvmeError::InvalidParameter);
            }
            let list_address = self.prp_list.dma_address();
            let list = unsafe {
                core::slice::from_raw_parts_mut(
                    list_address as *mut u64,
                    self.controller_page_size / core::mem::size_of::<u64>(),
                )
            };
            let prps = build_prps(
                staging.dma_address(),
                transfer_size,
                self.controller_page_size,
                list_address,
                list,
            )
            .ok_or(NvmeError::UnsupportedLbaFormat)?;
            self.prp_list
                .sync_for_device(0..self.prp_list.len(), DmaDirection::ToDevice)
                .map_err(|_| NvmeError::DmaError)?;
            staging
                .sync_for_device(0..transfer_size, DmaDirection::FromDevice)
                .map_err(|_| NvmeError::DmaError)?;
            (prps.prp1, prps.prp2)
        };

        let mut cmd = SubmissionQueueEntry::new();
        cmd.set_opcode(io_cmd::READ);
        cmd.nsid = nsid;
        cmd.prp1 = prp1;
        cmd.prp2 = prp2;
        cmd.cdw10 = start_lba as u32;
        cmd.cdw11 = (start_lba >> 32) as u32;
        cmd.cdw12 = num_sectors - 1;

        let cid = self.submit_io_command(cmd)?;
        self.wait_io_completion(cid)?;
        let staging = self.staging.as_ref().ok_or(NvmeError::NotReady)?;
        staging
            .sync_for_cpu(0..transfer_size, DmaDirection::FromDevice)
            .map_err(|_| NvmeError::DmaError)?;
        unsafe {
            ptr::copy_nonoverlapping(staging.dma_address() as *const u8, buffer, transfer_size);
        }
        Ok(())
    }

    /// Read one or more sectors into a buffer
    ///
    /// The number of sectors to read is inferred from the buffer size.
    /// If the buffer is larger than one sector, multiple sectors are read
    /// in a single operation for performance.
    pub fn read_sector(&mut self, nsid: u32, lba: u64, buffer: &mut [u8]) -> Result<(), NvmeError> {
        let ns = self
            .get_namespace(nsid)
            .ok_or(NvmeError::InvalidNamespace)?;

        let block_size = ns.block_size as usize;
        if buffer.len() < block_size {
            return Err(NvmeError::InvalidParameter);
        }

        let num_sectors = (buffer.len() / block_size) as u32;
        self.read_sectors(nsid, lba, num_sectors, buffer.as_mut_ptr())
    }
    // ========================================================================
    // Security Commands (TCG Opal, IEEE 1667)
    // ========================================================================

    /// NVMe Security Receive (admin opcode 0x82)
    ///
    /// Receives data from the security subsystem (e.g., TCG Opal response).
    ///
    /// # Arguments
    /// * `nsid` - Namespace ID (use 0 for controller-level operations)
    /// * `protocol_id` - Security Protocol ID (0x00=enumerate, 0x01=TCG, 0xEE=IEEE 1667)
    /// * `sp_specific` - Protocol-specific value (e.g., ComID for TCG)
    /// * `buffer` - Buffer to receive data
    ///
    /// # Returns
    /// Number of bytes transferred on success
    pub fn security_receive(
        &mut self,
        nsid: u32,
        protocol_id: u8,
        sp_specific: u16,
        buffer: &mut [u8],
    ) -> Result<usize, NvmeError> {
        if buffer.is_empty() || buffer.len() > 4096 {
            return Err(NvmeError::InvalidParameter);
        }

        log::debug!(
            "NVMe Security Receive: nsid={}, protocol={:#x}, sp_specific={:#x}, len={}",
            nsid,
            protocol_id,
            sp_specific,
            buffer.len()
        );

        // Build security receive command
        // CDW10: Security Protocol ID (bits 31:24), reserved (bits 23:16), SP Specific (bits 15:0)
        // CDW11: Allocation Length (transfer length in dwords)
        let mut cmd = SubmissionQueueEntry::new();
        cmd.set_opcode(admin_cmd::SECURITY_RECEIVE);
        let staging = self.staging.as_ref().ok_or(NvmeError::NotReady)?;
        if buffer.len() > staging.len() {
            return Err(NvmeError::InvalidParameter);
        }
        staging
            .sync_for_device(0..buffer.len(), DmaDirection::FromDevice)
            .map_err(|_| NvmeError::DmaError)?;
        cmd.nsid = nsid;
        cmd.prp1 = staging.dma_address();
        cmd.cdw10 = ((protocol_id as u32) << 24) | (sp_specific as u32);
        cmd.cdw11 = buffer.len() as u32; // Allocation length in bytes per NVMe spec

        let cid = self.submit_admin_command(cmd)?;
        let completion = self.wait_admin_completion(cid)?;

        // The completion DW0 contains the number of bytes transferred (for some implementations)
        // For simplicity, we assume the full buffer was used if no error
        let bytes_transferred = if completion.dw0 > 0 && completion.dw0 <= buffer.len() as u32 {
            completion.dw0 as usize
        } else {
            buffer.len()
        };

        let staging = self.staging.as_ref().ok_or(NvmeError::NotReady)?;
        staging
            .sync_for_cpu(0..bytes_transferred, DmaDirection::FromDevice)
            .map_err(|_| NvmeError::DmaError)?;
        unsafe {
            ptr::copy_nonoverlapping(
                staging.dma_address() as *const u8,
                buffer.as_mut_ptr(),
                bytes_transferred,
            );
        }

        log::debug!(
            "NVMe Security Receive: {} bytes transferred",
            bytes_transferred
        );
        Ok(bytes_transferred)
    }

    /// NVMe Security Send (admin opcode 0x81)
    ///
    /// Sends data to the security subsystem (e.g., TCG Opal command).
    ///
    /// # Arguments
    /// * `nsid` - Namespace ID (use 0 for controller-level operations)
    /// * `protocol_id` - Security Protocol ID (0x00=enumerate, 0x01=TCG, 0xEE=IEEE 1667)
    /// * `sp_specific` - Protocol-specific value (e.g., ComID for TCG)
    /// * `buffer` - Buffer containing data to send
    ///
    /// # Returns
    /// Ok(()) on success
    pub fn security_send(
        &mut self,
        nsid: u32,
        protocol_id: u8,
        sp_specific: u16,
        buffer: &[u8],
    ) -> Result<(), NvmeError> {
        if buffer.is_empty() || buffer.len() > 4096 {
            return Err(NvmeError::InvalidParameter);
        }

        log::debug!(
            "NVMe Security Send: nsid={}, protocol={:#x}, sp_specific={:#x}, len={}",
            nsid,
            protocol_id,
            sp_specific,
            buffer.len()
        );

        let staging = self.staging.as_mut().ok_or(NvmeError::NotReady)?;
        if buffer.len() > staging.len() {
            return Err(NvmeError::InvalidParameter);
        }
        staging.as_mut_slice()[..buffer.len()].copy_from_slice(buffer);
        staging
            .sync_for_device(0..buffer.len(), DmaDirection::ToDevice)
            .map_err(|_| NvmeError::DmaError)?;
        let staging_address = staging.dma_address();

        // Build security send command
        // CDW10: Security Protocol ID (bits 31:24), reserved (bits 23:16), SP Specific (bits 15:0)
        // CDW11: Transfer Length (in dwords)
        let mut cmd = SubmissionQueueEntry::new();
        cmd.set_opcode(admin_cmd::SECURITY_SEND);
        cmd.nsid = nsid;
        cmd.prp1 = staging_address;
        cmd.cdw10 = ((protocol_id as u32) << 24) | (sp_specific as u32);
        cmd.cdw11 = buffer.len() as u32; // Transfer length in bytes per NVMe spec

        let cid = self.submit_admin_command(cmd)?;
        self.wait_admin_completion(cid)?;

        log::debug!("NVMe Security Send: success");
        Ok(())
    }

    /// Get the list of namespaces
    pub fn namespaces(&self) -> &[NvmeNamespace] {
        &self.namespaces
    }

    /// Get the NVMe version from the controller
    pub fn nvme_version(&self) -> u32 {
        let regs = unsafe { &*self.regs };
        regs.vs.get()
    }

    fn shutdown_controller(&mut self) {
        self.refresh_dma_quarantine();
        let regs = unsafe { &*self.regs };
        let cc_before = regs.cc.get();
        let csts_before = regs.csts.get();
        regs.cc.modify(CC::SHN.val(1));
        if !wait_for(SHUTDOWN_TIMEOUT_MS, || regs.csts.read(CSTS::SHST) == 2) {
            log::error!(
                "NVMe {}: shutdown timeout; leaving CC.EN set until PCI bus mastering is disabled (budget={}ms CC={:#x} CSTS={:#x})",
                self.pci_address,
                SHUTDOWN_TIMEOUT_MS,
                regs.cc.get(),
                regs.csts.get()
            );
        } else {
            // CAP.TO applies to the ready transition after EN is cleared, not
            // to normal shutdown completion.
            regs.cc.modify(CC::EN::CLEAR + CC::SHN.val(0));
            let disable_budget = cap_timeout_ms(regs.cap.read(CAP::TO));
            if !wait_for(disable_budget, || regs.csts.read(CSTS::RDY) == 0) {
                log::error!(
                    "NVMe {}: HANDOFF UNSAFE, RDY stayed set (budget={}ms CC={:#x} CSTS={:#x}, initial CC={:#x} CSTS={:#x})",
                    self.pci_address,
                    disable_budget,
                    regs.cc.get(),
                    regs.csts.get(),
                    cc_before,
                    csts_before
                );
                for pending in self.admin_queue.pending().chain(self.io_queue.pending()) {
                    log::error!(
                        "NVMe pending CID={} timed_out={}",
                        pending.cid,
                        pending.timed_out
                    );
                }
            } else {
                self.dma_quarantined = false;
                log::debug!("NVMe {}: SHST complete and RDY=0", self.pci_address);
            }
        }
        if regs.csts.read(CSTS::CFS) != 0 {
            log::error!(
                "NVMe {}: controller fatal status at shutdown",
                self.pci_address
            );
        }
    }
}

/// Registry of initialized NVMe controllers
static NVME_CONTROLLERS: super::ControllerRegistry<NvmeController, 4> =
    super::ControllerRegistry::new("NVMe");

/// Initialize a single NVMe controller from a PCI device
///
/// Called by the PCI driver model when an NVMe device is discovered.
///
/// # Arguments
/// * `dev` - The PCI device to initialize as an NVMe controller
pub fn init_device(dev: &pci::PciDevice) -> Result<(), ()> {
    log::info!(
        "Initializing NVMe controller at {}: {:04x}:{:04x}",
        dev.address,
        dev.vendor_id,
        dev.device_id
    );

    let controller = NvmeController::new(dev).map_err(|e| {
        log::error!(
            "Failed to initialize NVMe controller at {}: {:?}",
            dev.address,
            e
        );
    })?;

    NVME_CONTROLLERS.register(controller)?;
    log::info!("NVMe controller at {} initialized", dev.address);
    Ok(())
}

/// Shutdown all NVMe controllers
///
/// Called during ExitBootServices to prepare for OS handoff.
/// Currently a placeholder — the OS will reset controllers during its own init.
pub fn shutdown() {
    let controllers = NVME_CONTROLLERS.controllers.lock();
    for ctrl_ptr in controllers.iter() {
        // SAFETY: the registry lock excludes controller users during handoff.
        unsafe { &mut *ctrl_ptr.0 }.shutdown_controller();
    }
    drop(controllers);
    NVME_CONTROLLERS.shutdown_log();
}

/// Initialize NVMe controllers (legacy entry point)
///
/// Scans PCI bus for NVMe controllers and initializes each one.
/// Prefer using `init_device()` via the PCI driver model instead.
pub fn init() {
    log::info!("Initializing NVMe controllers...");

    let nvme_devices = pci::find_nvme_controllers();

    if nvme_devices.is_empty() {
        log::info!("No NVMe controllers found");
        return;
    }

    for dev in nvme_devices.iter() {
        let _ = init_device(dev);
    }

    log::info!(
        "NVMe initialization complete: {} controllers",
        NVME_CONTROLLERS.count()
    );
}

/// Get a raw pointer to an NVMe controller
///
/// Returns a raw pointer rather than `&'static mut` to avoid aliasing UB.
/// Callers must ensure they do not create overlapping mutable references.
///
/// # Safety
///
/// The returned pointer is valid for the firmware lifetime. Callers must
/// convert to `&mut` only for the duration of their immediate operation
/// and must not hold the reference across calls that may also access
/// the same controller.
pub fn get_controller(index: usize) -> Option<*mut NvmeController> {
    NVME_CONTROLLERS.get(index)
}

// SAFETY: NvmeController contains raw pointers to MMIO registers and DMA buffers.
// These are:
// 1. Mapped from PCI BAR addresses that remain valid for the device's lifetime
// 2. DMA buffers allocated via the EFI page allocator that persist until shutdown
// 3. Only accessed while holding the NVME_CONTROLLERS mutex
// The firmware is single-threaded; concurrent hardware access is not possible.
unsafe impl Send for NvmeController {}

// ============================================================================
// Global NVMe Device for SimpleFileSystem Protocol
// ============================================================================

/// Global NVMe device info for filesystem reads
struct GlobalNvmeDevice {
    controller_index: usize,
    nsid: u32,
}

/// Pointer wrapper for global storage
struct GlobalNvmeDevicePtr(*mut GlobalNvmeDevice);

// SAFETY: GlobalNvmeDevicePtr wraps a pointer to GlobalNvmeDevice allocated via EFI.
// All access is protected by the GLOBAL_NVME_DEVICE mutex, ensuring no concurrent
// access. The pointed-to data contains only indices (not raw pointers to hardware),
// and the firmware runs single-threaded.
unsafe impl Send for GlobalNvmeDevicePtr {}

/// Global NVMe device for filesystem protocol
static GLOBAL_NVME_DEVICE: Mutex<Option<GlobalNvmeDevicePtr>> = Mutex::new(None);

/// Store NVMe device info globally for SimpleFileSystem protocol
///
/// # Arguments
/// * `controller_index` - Index of the NVMe controller
/// * `nsid` - Namespace ID to use for reads
///
/// # Returns
/// `true` if the device was stored successfully
pub fn store_global_device(controller_index: usize, nsid: u32) -> bool {
    let size = core::mem::size_of::<GlobalNvmeDevice>();

    match efi::allocator::allocate_pool(efi::allocator::MemoryType::BootServicesData, size) {
        Ok(ptr) => {
            let device_ptr = ptr as *mut GlobalNvmeDevice;
            unsafe {
                core::ptr::write(
                    device_ptr,
                    GlobalNvmeDevice {
                        controller_index,
                        nsid,
                    },
                );
            }

            *GLOBAL_NVME_DEVICE.lock() = Some(GlobalNvmeDevicePtr(device_ptr));
            log::info!(
                "NVMe device stored globally (controller={}, nsid={})",
                controller_index,
                nsid
            );
            true
        }
        Err(_) => {
            log::error!("Failed to allocate memory for global NVMe device");
            false
        }
    }
}

/// Read sectors from the global NVMe device
///
/// This function is used as the read callback for the SimpleFileSystem protocol.
/// Supports reading multiple sectors by inferring sector count from buffer size.
pub fn global_read_sectors(lba: u64, buffer: &mut [u8]) -> Result<(), ()> {
    // Get the device info
    let (controller_index, nsid) = match GLOBAL_NVME_DEVICE.lock().as_ref() {
        Some(ptr) => unsafe {
            let device = &*ptr.0;
            (device.controller_index, device.nsid)
        },
        None => {
            log::error!("global_read_sectors: no NVMe device stored");
            return Err(());
        }
    };

    // Get the controller
    // Safety: pointer valid for firmware lifetime; no overlapping &mut created
    let controller = match get_controller(controller_index) {
        Some(ptr) => unsafe { &mut *ptr },
        None => {
            log::error!(
                "global_read_sectors: no NVMe controller at index {}",
                controller_index
            );
            return Err(());
        }
    };

    // Read the sector
    controller.read_sector(nsid, lba, buffer).map_err(|e| {
        log::error!("global_read_sectors: read failed at LBA {}: {:?}", lba, e);
    })
}

/// Get the sector size of the global NVMe device
pub fn global_sector_size() -> Option<u32> {
    let (controller_index, nsid) = {
        let guard = GLOBAL_NVME_DEVICE.lock();
        let ptr = guard.as_ref()?;
        unsafe {
            let device = &*ptr.0;
            (device.controller_index, device.nsid)
        }
    };

    // Safety: pointer valid for firmware lifetime; no overlapping &mut created
    let controller = unsafe { &mut *get_controller(controller_index)? };
    let ns = controller.get_namespace(nsid)?;
    Some(ns.block_size)
}

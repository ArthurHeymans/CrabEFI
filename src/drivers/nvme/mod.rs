//! NVMe driver for CrabEFI
//!
//! This module provides a minimal NVMe driver for reading from NVMe SSDs.
//! It implements the basic NVMe command set needed for booting.

use crate::drivers::pci::{self, PciAddress, PciDevice};
use crate::efi;
use crate::time::{wait_for, Timeout};
use core::ptr;
use core::sync::atomic::{fence, Ordering};
use spin::Mutex;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use tock_registers::register_bitfields;
use tock_registers::registers::{ReadOnly, ReadWrite};

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
        MPSMAX OFFSET(52) NUMBITS(4) []
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
    /// Admin Submission Queue Base Address
    pub asq: ReadWrite<u64>,
    /// Admin Completion Queue Base Address
    pub acq: ReadWrite<u64>,
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
}

/// NVMe I/O commands
#[allow(dead_code)]
mod io_cmd {
    pub const FLUSH: u8 = 0x00;
    pub const WRITE: u8 = 0x01;
    pub const READ: u8 = 0x02;
}

/// Queue sizes (must be power of 2)
const ADMIN_QUEUE_SIZE: usize = 16;
const IO_QUEUE_SIZE: usize = 64;

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
    /// Pointer to memory-mapped registers
    regs: *const NvmeRegisters,
    /// MMIO base address (for doorbell access)
    mmio_base: u64,
    /// Doorbell stride (in bytes)
    doorbell_stride: usize,
    /// Admin submission queue
    admin_sq: *mut SubmissionQueueEntry,
    /// Admin completion queue
    admin_cq: *mut CompletionQueueEntry,
    /// Admin submission queue tail
    admin_sq_tail: u16,
    /// Admin completion queue head
    admin_cq_head: u16,
    /// Admin completion queue phase
    admin_cq_phase: bool,
    /// Command ID counter
    next_cid: u16,
    /// I/O submission queue
    io_sq: *mut SubmissionQueueEntry,
    /// I/O completion queue
    io_cq: *mut CompletionQueueEntry,
    /// I/O submission queue tail
    io_sq_tail: u16,
    /// I/O completion queue head
    io_cq_head: u16,
    /// I/O completion queue phase
    io_cq_phase: bool,
    /// Detected namespaces
    namespaces: heapless::Vec<NvmeNamespace, 8>,
    /// Page-aligned DMA buffer for data transfers (avoids corruption from misaligned buffers)
    dma_buffer: *mut u8,
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
}

impl NvmeController {
    /// Create a new NVMe controller from a PCI device
    pub fn new(pci_dev: &PciDevice) -> Result<Self, NvmeError> {
        let mmio_base = pci_dev.mmio_base().ok_or(NvmeError::NotReady)?;
        let regs = mmio_base as *const NvmeRegisters;

        // Enable the device (bus master + memory space)
        pci::enable_device(pci_dev);

        // Read capabilities using typed register access
        let regs_ref = unsafe { &*regs };
        let cap = regs_ref.cap.get();
        let doorbell_stride = 4usize << regs_ref.cap.read(CAP::DSTRD);
        let max_queue_entries = (regs_ref.cap.read(CAP::MQES) + 1) as usize;

        log::debug!("NVMe CAP: {:#018x}", cap);
        log::debug!("  Doorbell stride: {} bytes", doorbell_stride);
        log::debug!("  Max queue entries: {}", max_queue_entries);

        // Read version using typed register access
        let major = regs_ref.vs.read(VS::MJR);
        let minor = regs_ref.vs.read(VS::MNR);
        let tertiary = regs_ref.vs.read(VS::TER);
        log::info!("NVMe version: {}.{}.{}", major, minor, tertiary);

        // Allocate queues using EFI memory allocator
        // Each queue needs to be 4KB aligned
        let admin_sq_mem = efi::allocate_pages(1).ok_or(NvmeError::AllocationFailed)?;
        admin_sq_mem.fill(0);
        let admin_sq = admin_sq_mem.as_mut_ptr() as *mut SubmissionQueueEntry;

        let admin_cq_mem = efi::allocate_pages(1).ok_or(NvmeError::AllocationFailed)?;
        admin_cq_mem.fill(0);
        let admin_cq = admin_cq_mem.as_mut_ptr() as *mut CompletionQueueEntry;

        // Allocate a page-aligned DMA buffer for data transfers
        // This prevents corruption when callers pass misaligned buffers
        let dma_buffer_mem = efi::allocate_pages(1).ok_or(NvmeError::AllocationFailed)?;
        let dma_buffer = dma_buffer_mem.as_mut_ptr();

        let mut controller = Self {
            pci_address: pci_dev.address,
            regs,
            mmio_base,
            doorbell_stride,
            admin_sq,
            admin_cq,
            admin_sq_tail: 0,
            admin_cq_head: 0,
            admin_cq_phase: true,
            next_cid: 0,
            io_sq: ptr::null_mut(),
            io_cq: ptr::null_mut(),
            io_sq_tail: 0,
            io_cq_head: 0,
            io_cq_phase: true,
            namespaces: heapless::Vec::new(),
            dma_buffer,
        };

        controller.init()?;
        Ok(controller)
    }

    /// Write a doorbell register (doorbells are outside the typed register struct)
    #[inline]
    fn write_doorbell(&self, offset: u64, value: u32) {
        unsafe {
            ptr::write_volatile((self.mmio_base + offset) as *mut u32, value);
        }
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
        let regs = unsafe { &*(self.regs as *mut NvmeRegisters) };

        // Disable the controller
        regs.cc.modify(CC::EN::CLEAR);

        // Wait for controller to become disabled (up to 1 second)
        wait_for(1000, || regs.csts.read(CSTS::RDY) == 0);

        // Set admin queue attributes
        regs.aqa.write(
            AQA::ASQS.val((ADMIN_QUEUE_SIZE - 1) as u32)
                + AQA::ACQS.val((ADMIN_QUEUE_SIZE - 1) as u32),
        );

        // Set admin submission queue base address
        regs.asq.set(self.admin_sq as u64);

        // Set admin completion queue base address
        regs.acq.set(self.admin_cq as u64);

        // Configure controller:
        // - Memory Page Size (MPS) = 0 (4KB)
        // - Command Set Selected (CSS) = 0 (NVM)
        // - Arbitration Mechanism Selected (AMS) = 0 (Round Robin)
        // - Shutdown Notification (SHN) = 0
        // - I/O Submission Queue Entry Size (IOSQES) = 6 (64 bytes)
        // - I/O Completion Queue Entry Size (IOCQES) = 4 (16 bytes)
        regs.cc.write(
            CC::EN::SET
                + CC::CSS.val(0)
                + CC::MPS.val(0)
                + CC::AMS.val(0)
                + CC::SHN.val(0)
                + CC::IOSQES.val(6)
                + CC::IOCQES.val(4),
        );

        // Wait for controller to become ready (up to 2 seconds per spec)
        let timeout = Timeout::from_ms(2000);
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

    /// Get the next command ID
    fn next_command_id(&mut self) -> u16 {
        let cid = self.next_cid;
        self.next_cid = self.next_cid.wrapping_add(1);
        cid
    }

    /// Submit a command to the admin queue
    fn submit_admin_command(&mut self, cmd: &SubmissionQueueEntry) -> u16 {
        let tail = self.admin_sq_tail as usize;
        unsafe {
            ptr::write_volatile(self.admin_sq.add(tail), *cmd);
        }
        fence(Ordering::SeqCst);

        self.admin_sq_tail = ((tail + 1) % ADMIN_QUEUE_SIZE) as u16;
        self.ring_sq_doorbell(0, self.admin_sq_tail);

        (cmd.cdw0 >> 16) as u16 // Return CID
    }

    /// Wait for admin command completion
    fn wait_admin_completion(&mut self, cid: u16) -> Result<CompletionQueueEntry, NvmeError> {
        let timeout = Timeout::from_ms(5000); // 5 second timeout for admin commands

        while !timeout.is_expired() {
            fence(Ordering::SeqCst);
            let head = self.admin_cq_head as usize;
            let entry = unsafe { ptr::read_volatile(self.admin_cq.add(head)) };

            if entry.phase() == self.admin_cq_phase && entry.cid() == cid {
                // Advance head
                self.admin_cq_head = ((head + 1) % ADMIN_QUEUE_SIZE) as u16;
                if self.admin_cq_head == 0 {
                    self.admin_cq_phase = !self.admin_cq_phase;
                }
                self.ring_cq_doorbell(0, self.admin_cq_head);

                if entry.is_error() {
                    return Err(NvmeError::CommandFailed(
                        entry.status_code_type(),
                        entry.status_code(),
                    ));
                }
                return Ok(entry);
            }
            core::hint::spin_loop();
        }
        Err(NvmeError::Timeout)
    }

    /// Identify the controller
    fn identify_controller(&mut self) -> Result<(), NvmeError> {
        // Allocate a page for identify data
        let identify_mem = efi::allocate_pages(1).ok_or(NvmeError::AllocationFailed)?;
        let identify_addr = identify_mem.as_ptr() as u64;

        // Build identify command
        let mut cmd = SubmissionQueueEntry::new();
        cmd.set_opcode(admin_cmd::IDENTIFY);
        cmd.set_cid(self.next_command_id());
        cmd.nsid = 0;
        cmd.prp1 = identify_addr;
        cmd.cdw10 = 0x01; // CNS = 01 (Identify Controller)

        let cid = self.submit_admin_command(&cmd);
        self.wait_admin_completion(cid)?;

        // Parse identify data
        let ctrl = unsafe { &*(identify_mem.as_ptr() as *const IdentifyController) };

        // Extract model and serial number
        let model = core::str::from_utf8(&ctrl.mn).unwrap_or("Unknown").trim();
        let serial = core::str::from_utf8(&ctrl.sn).unwrap_or("Unknown").trim();
        let firmware = core::str::from_utf8(&ctrl.fr).unwrap_or("Unknown").trim();

        log::info!(
            "NVMe Controller: {} (S/N: {}, FW: {})",
            model,
            serial,
            firmware
        );

        // Free the identify data page
        efi::free_pages(identify_mem, 1);

        Ok(())
    }

    /// Create I/O submission and completion queues
    fn create_io_queues(&mut self) -> Result<(), NvmeError> {
        // Allocate I/O queues
        let io_sq_mem = efi::allocate_pages(1).ok_or(NvmeError::AllocationFailed)?;
        io_sq_mem.fill(0);
        self.io_sq = io_sq_mem.as_mut_ptr() as *mut SubmissionQueueEntry;

        let io_cq_mem = efi::allocate_pages(1).ok_or(NvmeError::AllocationFailed)?;
        io_cq_mem.fill(0);
        self.io_cq = io_cq_mem.as_mut_ptr() as *mut CompletionQueueEntry;

        // Create I/O Completion Queue (queue ID = 1)
        let mut cmd = SubmissionQueueEntry::new();
        cmd.set_opcode(admin_cmd::CREATE_CQ);
        cmd.set_cid(self.next_command_id());
        cmd.prp1 = self.io_cq as u64;
        cmd.cdw10 = ((IO_QUEUE_SIZE - 1) as u32) << 16 | 1; // QSIZE | QCQID
        cmd.cdw11 = 0x01; // PC=1 (physically contiguous), IEN=0, IV=0

        let cid = self.submit_admin_command(&cmd);
        self.wait_admin_completion(cid)?;
        log::debug!("Created I/O completion queue 1");

        // Create I/O Submission Queue (queue ID = 1)
        let mut cmd = SubmissionQueueEntry::new();
        cmd.set_opcode(admin_cmd::CREATE_SQ);
        cmd.set_cid(self.next_command_id());
        cmd.prp1 = self.io_sq as u64;
        cmd.cdw10 = ((IO_QUEUE_SIZE - 1) as u32) << 16 | 1; // QSIZE | QSQID
        cmd.cdw11 = (1 << 16) | 0x01; // CQID=1 | PC=1

        let cid = self.submit_admin_command(&cmd);
        self.wait_admin_completion(cid)?;
        log::debug!("Created I/O submission queue 1");

        Ok(())
    }

    /// Identify namespaces
    fn identify_namespaces(&mut self) -> Result<(), NvmeError> {
        // Allocate a page for identify data
        let identify_mem = efi::allocate_pages(1).ok_or(NvmeError::AllocationFailed)?;
        let identify_addr = identify_mem.as_ptr() as u64;

        // Get active namespace list
        let mut cmd = SubmissionQueueEntry::new();
        cmd.set_opcode(admin_cmd::IDENTIFY);
        cmd.set_cid(self.next_command_id());
        cmd.nsid = 0;
        cmd.prp1 = identify_addr;
        cmd.cdw10 = 0x02; // CNS = 02 (Active Namespace ID list)

        let cid = self.submit_admin_command(&cmd);
        self.wait_admin_completion(cid)?;

        // Parse namespace list
        let ns_list =
            unsafe { core::slice::from_raw_parts(identify_mem.as_ptr() as *const u32, 1024) };

        for &nsid in ns_list.iter() {
            if nsid == 0 {
                break;
            }

            // Identify this namespace
            let mut cmd = SubmissionQueueEntry::new();
            cmd.set_opcode(admin_cmd::IDENTIFY);
            cmd.set_cid(self.next_command_id());
            cmd.nsid = nsid;
            cmd.prp1 = identify_addr;
            cmd.cdw10 = 0x00; // CNS = 00 (Identify Namespace)

            let cid = self.submit_admin_command(&cmd);
            self.wait_admin_completion(cid)?;

            let ns = unsafe { &*(identify_mem.as_ptr() as *const IdentifyNamespace) };
            let lba_format_idx = ns.flbas & 0x0F;
            let lba_format = ns.lbaf[lba_format_idx as usize];
            let lba_data_size = (lba_format >> 16) & 0xFF;
            let block_size = 1u32 << lba_data_size;

            let namespace = NvmeNamespace {
                nsid,
                num_blocks: ns.nsze,
                block_size,
            };

            log::info!(
                "NVMe Namespace {}: {} blocks x {} bytes = {} MB",
                nsid,
                namespace.num_blocks,
                namespace.block_size,
                (namespace.num_blocks * namespace.block_size as u64) / (1024 * 1024)
            );

            if self.namespaces.push(namespace).is_err() {
                log::warn!(
                    "NVMe: Failed to add namespace {} - namespace list full",
                    nsid
                );
            }
        }

        efi::free_pages(identify_mem, 1);

        if self.namespaces.is_empty() {
            return Err(NvmeError::NoNamespaces);
        }

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

    /// Submit an I/O command
    fn submit_io_command(&mut self, cmd: &SubmissionQueueEntry) -> u16 {
        let tail = self.io_sq_tail as usize;
        unsafe {
            ptr::write_volatile(self.io_sq.add(tail), *cmd);
        }
        fence(Ordering::SeqCst);

        self.io_sq_tail = ((tail + 1) % IO_QUEUE_SIZE) as u16;
        self.ring_sq_doorbell(1, self.io_sq_tail);

        (cmd.cdw0 >> 16) as u16 // Return CID
    }

    /// Wait for I/O command completion
    fn wait_io_completion(&mut self, cid: u16) -> Result<CompletionQueueEntry, NvmeError> {
        let timeout = Timeout::from_ms(1000); // 1 second timeout for I/O

        while !timeout.is_expired() {
            fence(Ordering::SeqCst);
            let head = self.io_cq_head as usize;
            let entry = unsafe { ptr::read_volatile(self.io_cq.add(head)) };

            if entry.phase() == self.io_cq_phase && entry.cid() == cid {
                // Advance head
                self.io_cq_head = ((head + 1) % IO_QUEUE_SIZE) as u16;
                if self.io_cq_head == 0 {
                    self.io_cq_phase = !self.io_cq_phase;
                }
                self.ring_cq_doorbell(1, self.io_cq_head);

                if entry.is_error() {
                    return Err(NvmeError::CommandFailed(
                        entry.status_code_type(),
                        entry.status_code(),
                    ));
                }
                return Ok(entry);
            }
            core::hint::spin_loop();
        }
        Err(NvmeError::Timeout)
    }

    /// Read sectors from a namespace
    ///
    /// Uses an internal page-aligned DMA buffer to avoid corruption when
    /// callers pass misaligned buffers (e.g., stack buffers).
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
        let block_size = ns.block_size;

        if num_sectors == 0 {
            return Err(NvmeError::InvalidParameter);
        }

        let transfer_size = num_sectors as u64 * block_size as u64;

        // Our DMA buffer is one page (4096 bytes), so we can only transfer up to 4KB at a time
        // For larger transfers, we need to loop
        if transfer_size > 4096 {
            // Handle large transfers by reading one page at a time
            let sectors_per_page = 4096 / block_size;
            let mut remaining_sectors = num_sectors;
            let mut current_lba = start_lba;
            let mut current_buffer = buffer;

            while remaining_sectors > 0 {
                let sectors_this_read = core::cmp::min(remaining_sectors, sectors_per_page);
                self.read_sectors_internal(nsid, current_lba, sectors_this_read, current_buffer)?;
                remaining_sectors -= sectors_this_read;
                current_lba += sectors_this_read as u64;
                current_buffer =
                    unsafe { current_buffer.add((sectors_this_read * block_size) as usize) };
            }
            return Ok(());
        }

        self.read_sectors_internal(nsid, start_lba, num_sectors, buffer)
    }

    /// Internal read function that uses the page-aligned DMA buffer
    fn read_sectors_internal(
        &mut self,
        nsid: u32,
        start_lba: u64,
        num_sectors: u32,
        buffer: *mut u8,
    ) -> Result<(), NvmeError> {
        let ns = self
            .get_namespace(nsid)
            .ok_or(NvmeError::InvalidNamespace)?;
        let block_size = ns.block_size;
        let transfer_size = (num_sectors * block_size) as usize;

        // Use our page-aligned DMA buffer to avoid corruption from misaligned caller buffers
        // The DMA buffer is guaranteed to be 4KB aligned by allocate_pages()
        let mut cmd = SubmissionQueueEntry::new();
        cmd.set_opcode(io_cmd::READ);
        cmd.set_cid(self.next_command_id());
        cmd.nsid = nsid;
        cmd.prp1 = self.dma_buffer as u64; // Use aligned DMA buffer

        cmd.cdw10 = start_lba as u32;
        cmd.cdw11 = (start_lba >> 32) as u32;
        cmd.cdw12 = num_sectors - 1; // Number of logical blocks (0-based)

        let cid = self.submit_io_command(&cmd);
        self.wait_io_completion(cid)?;

        // Copy data from DMA buffer to caller's buffer
        unsafe {
            ptr::copy_nonoverlapping(self.dma_buffer, buffer, transfer_size);
        }

        Ok(())
    }

    /// Read a single sector (convenience method)
    pub fn read_sector(&mut self, nsid: u32, lba: u64, buffer: &mut [u8]) -> Result<(), NvmeError> {
        let ns = self
            .get_namespace(nsid)
            .ok_or(NvmeError::InvalidNamespace)?;

        if buffer.len() < ns.block_size as usize {
            return Err(NvmeError::InvalidParameter);
        }

        self.read_sectors(nsid, lba, 1, buffer.as_mut_ptr())
    }

    /// Write sectors to a namespace
    ///
    /// Uses an internal page-aligned DMA buffer to avoid corruption when
    /// callers pass misaligned buffers (e.g., stack buffers).
    pub fn write_sectors(
        &mut self,
        nsid: u32,
        start_lba: u64,
        num_sectors: u32,
        buffer: *const u8,
    ) -> Result<(), NvmeError> {
        let ns = self
            .get_namespace(nsid)
            .ok_or(NvmeError::InvalidNamespace)?;
        let block_size = ns.block_size;

        if num_sectors == 0 {
            return Err(NvmeError::InvalidParameter);
        }

        let transfer_size = num_sectors as u64 * block_size as u64;

        // Our DMA buffer is one page (4096 bytes), so we can only transfer up to 4KB at a time
        // For larger transfers, we need to loop
        if transfer_size > 4096 {
            // Handle large transfers by writing one page at a time
            let sectors_per_page = 4096 / block_size;
            let mut remaining_sectors = num_sectors;
            let mut current_lba = start_lba;
            let mut current_buffer = buffer;

            while remaining_sectors > 0 {
                let sectors_this_write = core::cmp::min(remaining_sectors, sectors_per_page);
                self.write_sectors_internal(nsid, current_lba, sectors_this_write, current_buffer)?;
                remaining_sectors -= sectors_this_write;
                current_lba += sectors_this_write as u64;
                current_buffer =
                    unsafe { current_buffer.add((sectors_this_write * block_size) as usize) };
            }
            return Ok(());
        }

        self.write_sectors_internal(nsid, start_lba, num_sectors, buffer)
    }

    /// Internal write function that uses the page-aligned DMA buffer
    fn write_sectors_internal(
        &mut self,
        nsid: u32,
        start_lba: u64,
        num_sectors: u32,
        buffer: *const u8,
    ) -> Result<(), NvmeError> {
        let ns = self
            .get_namespace(nsid)
            .ok_or(NvmeError::InvalidNamespace)?;
        let block_size = ns.block_size;
        let transfer_size = (num_sectors * block_size) as usize;

        // Copy data from caller's buffer to DMA buffer first
        unsafe {
            ptr::copy_nonoverlapping(buffer, self.dma_buffer, transfer_size);
        }

        // Use our page-aligned DMA buffer to avoid corruption from misaligned caller buffers
        // The DMA buffer is guaranteed to be 4KB aligned by allocate_pages()
        let mut cmd = SubmissionQueueEntry::new();
        cmd.set_opcode(io_cmd::WRITE);
        cmd.set_cid(self.next_command_id());
        cmd.nsid = nsid;
        cmd.prp1 = self.dma_buffer as u64; // Use aligned DMA buffer

        cmd.cdw10 = start_lba as u32;
        cmd.cdw11 = (start_lba >> 32) as u32;
        cmd.cdw12 = num_sectors - 1; // Number of logical blocks (0-based)

        let cid = self.submit_io_command(&cmd);
        self.wait_io_completion(cid)?;

        Ok(())
    }

    /// Write a single sector (convenience method)
    pub fn write_sector(&mut self, nsid: u32, lba: u64, buffer: &[u8]) -> Result<(), NvmeError> {
        let ns = self
            .get_namespace(nsid)
            .ok_or(NvmeError::InvalidNamespace)?;

        if buffer.len() < ns.block_size as usize {
            return Err(NvmeError::InvalidParameter);
        }

        self.write_sectors(nsid, lba, 1, buffer.as_ptr())
    }
}

/// Wrapper for NVMe controller pointer to implement Send
struct NvmeControllerPtr(*mut NvmeController);

// SAFETY: NvmeControllerPtr wraps a pointer to an NvmeController allocated via the EFI
// page allocator. The pointer remains valid for the firmware's lifetime and all access
// is protected by the NVME_CONTROLLERS mutex. The firmware runs single-threaded with
// interrupts disabled during NVMe operations.
unsafe impl Send for NvmeControllerPtr {}

/// Global list of NVMe controllers
static NVME_CONTROLLERS: Mutex<heapless::Vec<NvmeControllerPtr, 4>> =
    Mutex::new(heapless::Vec::new());

/// Initialize NVMe controllers
pub fn init() {
    log::info!("Initializing NVMe controllers...");

    let nvme_devices = pci::find_nvme_controllers();

    if nvme_devices.is_empty() {
        log::info!("No NVMe controllers found");
        return;
    }

    let mut controllers = NVME_CONTROLLERS.lock();

    for dev in nvme_devices.iter() {
        match NvmeController::new(dev) {
            Ok(controller) => {
                // Box the controller (we don't have alloc, so use EFI allocator)
                let size = core::mem::size_of::<NvmeController>();
                let pages = size.div_ceil(4096);
                log::debug!(
                    "NVMe: Allocating {} pages ({} bytes) for NvmeController",
                    pages,
                    size
                );
                let controller_mem = efi::allocate_pages(pages as u64);
                if let Some(mem) = controller_mem {
                    let controller_box = mem.as_mut_ptr() as *mut NvmeController;
                    unsafe {
                        ptr::write(controller_box, controller);
                    }
                    if controllers.push(NvmeControllerPtr(controller_box)).is_err() {
                        log::warn!(
                            "NVMe: Failed to register controller at {} - controller list full",
                            dev.address
                        );
                    } else {
                        log::info!("NVMe controller at {} initialized", dev.address);
                    }
                }
            }
            Err(e) => {
                log::error!(
                    "Failed to initialize NVMe controller at {}: {:?}",
                    dev.address,
                    e
                );
            }
        }
    }

    log::info!(
        "NVMe initialization complete: {} controllers",
        controllers.len()
    );
}

/// Get the first NVMe controller
pub fn get_controller(index: usize) -> Option<&'static mut NvmeController> {
    let controllers = NVME_CONTROLLERS.lock();
    controllers.get(index).map(|ptr| unsafe { &mut *ptr.0 })
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
    // Allocate memory for the device info
    let size = core::mem::size_of::<GlobalNvmeDevice>();
    let pages = size.div_ceil(4096);

    if let Some(mem) = efi::allocate_pages(pages as u64) {
        let device_ptr = mem.as_mut_ptr() as *mut GlobalNvmeDevice;
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
    } else {
        log::error!("Failed to allocate memory for global NVMe device");
        false
    }
}

/// Read a sector from the global NVMe device
///
/// This function is used as the read callback for the SimpleFileSystem protocol.
pub fn global_read_sector(lba: u64, buffer: &mut [u8]) -> Result<(), ()> {
    // Get the device info
    let (controller_index, nsid) = match GLOBAL_NVME_DEVICE.lock().as_ref() {
        Some(ptr) => unsafe {
            let device = &*ptr.0;
            (device.controller_index, device.nsid)
        },
        None => {
            log::error!("global_read_sector: no NVMe device stored");
            return Err(());
        }
    };

    // Get the controller
    let controller = match get_controller(controller_index) {
        Some(c) => c,
        None => {
            log::error!(
                "global_read_sector: no NVMe controller at index {}",
                controller_index
            );
            return Err(());
        }
    };

    // Read the sector
    controller.read_sector(nsid, lba, buffer).map_err(|e| {
        log::error!("global_read_sector: read failed at LBA {}: {:?}", lba, e);
    })
}

/// Get the sector size of the global NVMe device
pub fn global_sector_size() -> Option<u32> {
    let (controller_index, nsid) = match GLOBAL_NVME_DEVICE.lock().as_ref() {
        Some(ptr) => unsafe {
            let device = &*ptr.0;
            (device.controller_index, device.nsid)
        },
        None => return None,
    };

    let controller = get_controller(controller_index)?;
    let ns = controller.get_namespace(nsid)?;
    Some(ns.block_size)
}

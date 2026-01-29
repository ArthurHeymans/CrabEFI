//! AHCI Register Definitions using tock-registers
//!
//! This module defines AHCI (Advanced Host Controller Interface) registers
//! using type-safe tock-registers.

use tock_registers::register_bitfields;
use tock_registers::registers::{ReadOnly, ReadWrite};

// ============================================================================
// HBA Register Bitfield Definitions
// ============================================================================

register_bitfields! [
    u32,
    /// Host Capabilities (CAP) Register
    pub CAP [
        /// Number of Ports (0's based)
        NP OFFSET(0) NUMBITS(5) [],
        /// Supports External SATA
        SXS OFFSET(5) NUMBITS(1) [],
        /// Enclosure Management Supported
        EMS OFFSET(6) NUMBITS(1) [],
        /// Command Completion Coalescing Supported
        CCCS OFFSET(7) NUMBITS(1) [],
        /// Number of Command Slots (0's based)
        NCS OFFSET(8) NUMBITS(5) [],
        /// Partial State Capable
        PSC OFFSET(13) NUMBITS(1) [],
        /// Slumber State Capable
        SSC OFFSET(14) NUMBITS(1) [],
        /// PIO Multiple DRQ Block
        PMD OFFSET(15) NUMBITS(1) [],
        /// FIS-based Switching Supported
        FBSS OFFSET(16) NUMBITS(1) [],
        /// Supports Port Multiplier
        SPM OFFSET(17) NUMBITS(1) [],
        /// Supports AHCI Mode Only
        SAM OFFSET(18) NUMBITS(1) [],
        /// Interface Speed Support
        ISS OFFSET(20) NUMBITS(4) [],
        /// Supports Command List Override
        SCLO OFFSET(24) NUMBITS(1) [],
        /// Supports Activity LED
        SAL OFFSET(25) NUMBITS(1) [],
        /// Supports Aggressive Link Power Management
        SALP OFFSET(26) NUMBITS(1) [],
        /// Supports Staggered Spin-up
        SSS OFFSET(27) NUMBITS(1) [],
        /// Supports Mechanical Presence Switch
        SMPS OFFSET(28) NUMBITS(1) [],
        /// Supports SNotification Register
        SSNTF OFFSET(29) NUMBITS(1) [],
        /// Supports Native Command Queuing
        SNCQ OFFSET(30) NUMBITS(1) [],
        /// Supports 64-bit Addressing
        S64A OFFSET(31) NUMBITS(1) []
    ],

    /// Global HBA Control (GHC) Register
    pub GHC [
        /// HBA Reset
        HR OFFSET(0) NUMBITS(1) [],
        /// Interrupt Enable
        IE OFFSET(1) NUMBITS(1) [],
        /// MSI Revert to Single Message
        MRSM OFFSET(2) NUMBITS(1) [],
        /// AHCI Enable
        AE OFFSET(31) NUMBITS(1) []
    ],

    /// Interrupt Status (IS) Register - Each bit represents a port
    pub IS [
        /// Interrupt Pending Status (32-bit bitmap)
        IPS OFFSET(0) NUMBITS(32) []
    ],

    /// Ports Implemented (PI) Register
    pub PI [
        /// Port Implemented (32-bit bitmap)
        PI OFFSET(0) NUMBITS(32) []
    ],

    /// Version (VS) Register
    pub VS [
        /// Minor Version Number
        MNR OFFSET(0) NUMBITS(16) [],
        /// Major Version Number
        MJR OFFSET(16) NUMBITS(16) []
    ],

    /// Host Capabilities Extended (CAP2) Register
    pub CAP2 [
        /// BIOS/OS Handoff Supported
        BOH OFFSET(0) NUMBITS(1) [],
        /// NVMHCI Present
        NVMP OFFSET(1) NUMBITS(1) [],
        /// Automatic Partial to Slumber Transitions
        APST OFFSET(2) NUMBITS(1) [],
        /// Supports Device Sleep
        SDS OFFSET(3) NUMBITS(1) [],
        /// Supports Aggressive Device Sleep Management
        SADM OFFSET(4) NUMBITS(1) [],
        /// DevSleep Entrance from Slumber Only
        DESO OFFSET(5) NUMBITS(1) []
    ],

    /// BIOS/OS Handoff Control and Status (BOHC) Register
    pub BOHC [
        /// BIOS Owned Semaphore
        BOS OFFSET(0) NUMBITS(1) [],
        /// OS Owned Semaphore
        OOS OFFSET(1) NUMBITS(1) [],
        /// SMI on OS Ownership Change Enable
        SOOE OFFSET(2) NUMBITS(1) [],
        /// OS Ownership Change
        OOC OFFSET(3) NUMBITS(1) [],
        /// BIOS Busy
        BB OFFSET(4) NUMBITS(1) []
    ],

    /// Port Command and Status (PxCMD) Register
    pub PORT_CMD [
        /// Start
        ST OFFSET(0) NUMBITS(1) [],
        /// Spin-Up Device
        SUD OFFSET(1) NUMBITS(1) [],
        /// Power On Device
        POD OFFSET(2) NUMBITS(1) [],
        /// Command List Override
        CLO OFFSET(3) NUMBITS(1) [],
        /// FIS Receive Enable
        FRE OFFSET(4) NUMBITS(1) [],
        /// Current Command Slot
        CCS OFFSET(8) NUMBITS(5) [],
        /// Mechanical Presence Switch State
        MPSS OFFSET(13) NUMBITS(1) [],
        /// FIS Receive Running
        FR OFFSET(14) NUMBITS(1) [],
        /// Command List Running
        CR OFFSET(15) NUMBITS(1) [],
        /// Cold Presence State
        CPS OFFSET(16) NUMBITS(1) [],
        /// Port Multiplier Attached
        PMA OFFSET(17) NUMBITS(1) [],
        /// Hot Plug Capable Port
        HPCP OFFSET(18) NUMBITS(1) [],
        /// Mechanical Presence Switch Attached
        MPSP OFFSET(19) NUMBITS(1) [],
        /// Cold Presence Detection
        CPD OFFSET(20) NUMBITS(1) [],
        /// External SATA Port
        ESP OFFSET(21) NUMBITS(1) [],
        /// FIS-based Switching Capable Port
        FBSCP OFFSET(22) NUMBITS(1) [],
        /// Automatic Partial to Slumber Transitions Enabled
        APSTE OFFSET(23) NUMBITS(1) [],
        /// Device is ATAPI
        ATAPI OFFSET(24) NUMBITS(1) [],
        /// Drive LED on ATAPI Enable
        DLAE OFFSET(25) NUMBITS(1) [],
        /// Aggressive Link Power Management Enable
        ALPE OFFSET(26) NUMBITS(1) [],
        /// Aggressive Slumber/Partial
        ASP OFFSET(27) NUMBITS(1) [],
        /// Interface Communication Control
        ICC OFFSET(28) NUMBITS(4) [
            NoOp = 0,
            Active = 1,
            Partial = 2,
            Slumber = 6,
            DevSleep = 8
        ]
    ],

    /// Port Task File Data (PxTFD) Register
    pub PORT_TFD [
        /// Status: Error
        STS_ERR OFFSET(0) NUMBITS(1) [],
        /// Status: Command Specific bits
        STS_CS1 OFFSET(1) NUMBITS(2) [],
        /// Status: Data Request
        STS_DRQ OFFSET(3) NUMBITS(1) [],
        /// Status: Command Specific bits
        STS_CS2 OFFSET(4) NUMBITS(3) [],
        /// Status: Busy
        STS_BSY OFFSET(7) NUMBITS(1) [],
        /// Error Register
        ERR OFFSET(8) NUMBITS(8) []
    ],

    /// Port Serial ATA Status (PxSSTS) Register
    pub PORT_SSTS [
        /// Device Detection
        DET OFFSET(0) NUMBITS(4) [
            NotPresent = 0,
            PresentNoComm = 1,
            PresentComm = 3,
            PhyOffline = 4
        ],
        /// Current Interface Speed
        SPD OFFSET(4) NUMBITS(4) [
            NoDevice = 0,
            Gen1 = 1,
            Gen2 = 2,
            Gen3 = 3
        ],
        /// Interface Power Management
        IPM OFFSET(8) NUMBITS(4) [
            NotPresent = 0,
            Active = 1,
            Partial = 2,
            Slumber = 6,
            DevSleep = 8
        ]
    ],

    /// Port Serial ATA Control (PxSCTL) Register
    pub PORT_SCTL [
        /// Device Detection Initialization
        DET OFFSET(0) NUMBITS(4) [
            NoAction = 0,
            Comreset = 1,
            DisableSata = 4
        ],
        /// Speed Allowed
        SPD OFFSET(4) NUMBITS(4) [],
        /// Interface Power Management Transitions Allowed
        IPM OFFSET(8) NUMBITS(4) []
    ],

    /// Port Serial ATA Error (PxSERR) Register
    pub PORT_SERR [
        /// Recovered Data Integrity Error
        DIAG_I OFFSET(0) NUMBITS(1) [],
        /// Recovered Communications Error
        DIAG_M OFFSET(1) NUMBITS(1) [],
        /// Transient Data Integrity Error
        ERR_T OFFSET(8) NUMBITS(1) [],
        /// Persistent Communication or Data Integrity Error
        ERR_C OFFSET(9) NUMBITS(1) [],
        /// Protocol Error
        ERR_P OFFSET(10) NUMBITS(1) [],
        /// Internal Error
        ERR_E OFFSET(11) NUMBITS(1) [],
        /// PhyRdy Change
        DIAG_N OFFSET(16) NUMBITS(1) [],
        /// Phy Internal Error
        DIAG_I2 OFFSET(17) NUMBITS(1) [],
        /// Comm Wake
        DIAG_W OFFSET(18) NUMBITS(1) [],
        /// 10B to 8B Decode Error
        DIAG_B OFFSET(19) NUMBITS(1) [],
        /// Disparity Error
        DIAG_D OFFSET(20) NUMBITS(1) [],
        /// CRC Error
        DIAG_C OFFSET(21) NUMBITS(1) [],
        /// Handshake Error
        DIAG_H OFFSET(22) NUMBITS(1) [],
        /// Link Sequence Error
        DIAG_S OFFSET(23) NUMBITS(1) [],
        /// Transport state transition error
        DIAG_T OFFSET(24) NUMBITS(1) [],
        /// Unknown FIS Type
        DIAG_F OFFSET(25) NUMBITS(1) [],
        /// Exchanged
        DIAG_X OFFSET(26) NUMBITS(1) []
    ],

    /// Port Interrupt Status (PxIS) Register
    pub PORT_IS [
        /// Device to Host Register FIS Interrupt
        DHRS OFFSET(0) NUMBITS(1) [],
        /// PIO Setup FIS Interrupt
        PSS OFFSET(1) NUMBITS(1) [],
        /// DMA Setup FIS Interrupt
        DSS OFFSET(2) NUMBITS(1) [],
        /// Set Device Bits Interrupt
        SDBS OFFSET(3) NUMBITS(1) [],
        /// Unknown FIS Interrupt
        UFS OFFSET(4) NUMBITS(1) [],
        /// Descriptor Processed
        DPS OFFSET(5) NUMBITS(1) [],
        /// Port Connect Change Status
        PCS OFFSET(6) NUMBITS(1) [],
        /// Device Mechanical Presence Status
        DMPS OFFSET(7) NUMBITS(1) [],
        /// PhyRdy Change Status
        PRCS OFFSET(22) NUMBITS(1) [],
        /// Incorrect Port Multiplier Status
        IPMS OFFSET(23) NUMBITS(1) [],
        /// Overflow Status
        OFS OFFSET(24) NUMBITS(1) [],
        /// Interface Non-fatal Error Status
        INFS OFFSET(26) NUMBITS(1) [],
        /// Interface Fatal Error Status
        IFS OFFSET(27) NUMBITS(1) [],
        /// Host Bus Data Error Status
        HBDS OFFSET(28) NUMBITS(1) [],
        /// Host Bus Fatal Error Status
        HBFS OFFSET(29) NUMBITS(1) [],
        /// Task File Error Status
        TFES OFFSET(30) NUMBITS(1) [],
        /// Cold Port Detect Status
        CPDS OFFSET(31) NUMBITS(1) []
    ],

    /// Port Interrupt Enable (PxIE) Register - same bits as PxIS
    pub PORT_IE [
        /// Device to Host Register FIS Interrupt Enable
        DHRE OFFSET(0) NUMBITS(1) [],
        /// PIO Setup FIS Interrupt Enable
        PSE OFFSET(1) NUMBITS(1) [],
        /// DMA Setup FIS Interrupt Enable
        DSE OFFSET(2) NUMBITS(1) [],
        /// Set Device Bits Interrupt Enable
        SDBE OFFSET(3) NUMBITS(1) [],
        /// Unknown FIS Interrupt Enable
        UFE OFFSET(4) NUMBITS(1) [],
        /// Descriptor Processed Interrupt Enable
        DPE OFFSET(5) NUMBITS(1) [],
        /// Port Connect Change Interrupt Enable
        PCE OFFSET(6) NUMBITS(1) [],
        /// Device Mechanical Presence Enable
        DMPE OFFSET(7) NUMBITS(1) [],
        /// PhyRdy Change Interrupt Enable
        PRCE OFFSET(22) NUMBITS(1) [],
        /// Incorrect Port Multiplier Enable
        IPME OFFSET(23) NUMBITS(1) [],
        /// Overflow Enable
        OFE OFFSET(24) NUMBITS(1) [],
        /// Interface Non-fatal Error Enable
        INFE OFFSET(26) NUMBITS(1) [],
        /// Interface Fatal Error Enable
        IFE OFFSET(27) NUMBITS(1) [],
        /// Host Bus Data Error Enable
        HBDE OFFSET(28) NUMBITS(1) [],
        /// Host Bus Fatal Error Enable
        HBFE OFFSET(29) NUMBITS(1) [],
        /// Task File Error Enable
        TFEE OFFSET(30) NUMBITS(1) [],
        /// Cold Port Detect Enable
        CPDE OFFSET(31) NUMBITS(1) []
    ]
];

// ============================================================================
// AHCI HBA Register Memory Map
// ============================================================================

/// AHCI HBA Generic Host Control registers (0x00-0x2B)
#[repr(C)]
pub struct AhciHbaRegisters {
    /// Host Capabilities (0x00)
    pub cap: ReadOnly<u32, CAP::Register>,
    /// Global HBA Control (0x04)
    pub ghc: ReadWrite<u32, GHC::Register>,
    /// Interrupt Status (0x08)
    pub is: ReadWrite<u32, IS::Register>,
    /// Ports Implemented (0x0C)
    pub pi: ReadOnly<u32, PI::Register>,
    /// Version (0x10)
    pub vs: ReadOnly<u32, VS::Register>,
    /// Command Completion Coalescing Control (0x14)
    pub ccc_ctl: ReadWrite<u32>,
    /// Command Completion Coalescing Ports (0x18)
    pub ccc_ports: ReadWrite<u32>,
    /// Enclosure Management Location (0x1C)
    pub em_loc: ReadOnly<u32>,
    /// Enclosure Management Control (0x20)
    pub em_ctl: ReadWrite<u32>,
    /// Host Capabilities Extended (0x24)
    pub cap2: ReadOnly<u32, CAP2::Register>,
    /// BIOS/OS Handoff Control and Status (0x28)
    pub bohc: ReadWrite<u32, BOHC::Register>,
}

/// AHCI Port registers (each port has 0x80 bytes starting at 0x100)
#[repr(C)]
pub struct AhciPortRegisters {
    /// Port Command List Base Address (0x00)
    pub clb: ReadWrite<u32>,
    /// Port Command List Base Address Upper (0x04)
    pub clbu: ReadWrite<u32>,
    /// Port FIS Base Address (0x08)
    pub fb: ReadWrite<u32>,
    /// Port FIS Base Address Upper (0x0C)
    pub fbu: ReadWrite<u32>,
    /// Port Interrupt Status (0x10)
    pub is: ReadWrite<u32, PORT_IS::Register>,
    /// Port Interrupt Enable (0x14)
    pub ie: ReadWrite<u32, PORT_IE::Register>,
    /// Port Command and Status (0x18)
    pub cmd: ReadWrite<u32, PORT_CMD::Register>,
    /// Reserved (0x1C)
    _reserved0: u32,
    /// Port Task File Data (0x20)
    pub tfd: ReadOnly<u32, PORT_TFD::Register>,
    /// Port Signature (0x24)
    pub sig: ReadOnly<u32>,
    /// Port Serial ATA Status (0x28)
    pub ssts: ReadOnly<u32, PORT_SSTS::Register>,
    /// Port Serial ATA Control (0x2C)
    pub sctl: ReadWrite<u32, PORT_SCTL::Register>,
    /// Port Serial ATA Error (0x30)
    pub serr: ReadWrite<u32, PORT_SERR::Register>,
    /// Port Serial ATA Active (0x34)
    pub sact: ReadWrite<u32>,
    /// Port Command Issue (0x38)
    pub ci: ReadWrite<u32>,
    /// Port Serial ATA Notification (0x3C)
    pub sntf: ReadWrite<u32>,
    /// Port FIS-based Switching Control (0x40)
    pub fbs: ReadWrite<u32>,
    /// Port Device Sleep (0x44)
    pub devslp: ReadWrite<u32>,
    /// Reserved (0x48-0x6F)
    _reserved1: [u32; 10],
    /// Vendor Specific (0x70-0x7F)
    _vendor: [u32; 4],
}

// ============================================================================
// Constants
// ============================================================================

/// Port registers base offset from AHCI base
pub const PORT_BASE: u64 = 0x100;

/// Port register block size
pub const PORT_SIZE: u64 = 0x80;

/// SATA device signature for ATA (hard drive)
pub const SATA_SIG_ATA: u32 = 0x00000101;

/// SATA device signature for ATAPI (CD/DVD)
pub const SATA_SIG_ATAPI: u32 = 0xEB140101;

/// SATA device signature for SEMB (Enclosure Management Bridge)
pub const SATA_SIG_SEMB: u32 = 0xC33C0101;

/// SATA device signature for Port Multiplier
pub const SATA_SIG_PM: u32 = 0x96690101;

// ============================================================================
// FIS Types
// ============================================================================

/// Register FIS - Host to Device
pub const FIS_TYPE_REG_H2D: u8 = 0x27;

/// Register FIS - Device to Host  
pub const FIS_TYPE_REG_D2H: u8 = 0x34;

/// DMA Activate FIS - Device to Host
pub const FIS_TYPE_DMA_ACT: u8 = 0x39;

/// DMA Setup FIS - Bidirectional
pub const FIS_TYPE_DMA_SETUP: u8 = 0x41;

/// Data FIS - Bidirectional
pub const FIS_TYPE_DATA: u8 = 0x46;

/// PIO Setup FIS - Device to Host
pub const FIS_TYPE_PIO_SETUP: u8 = 0x5F;

/// Set Device Bits FIS - Device to Host
pub const FIS_TYPE_DEV_BITS: u8 = 0xA1;

// ============================================================================
// ATA Commands
// ============================================================================

/// Read DMA Extended (48-bit LBA)
pub const ATA_CMD_READ_DMA_EXT: u8 = 0x25;

/// Write DMA Extended (48-bit LBA)
pub const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;

/// Identify Device
pub const ATA_CMD_IDENTIFY: u8 = 0xEC;

/// Identify Packet Device (ATAPI)
pub const ATA_CMD_IDENTIFY_PACKET: u8 = 0xA1;

/// ATAPI Packet Command
pub const ATA_CMD_PACKET: u8 = 0xA0;

// ============================================================================
// SCSI Commands (used with ATAPI)
// ============================================================================

/// Read (10) - read sectors
pub const SCSI_CMD_READ_10: u8 = 0x28;

/// Read (12) - read sectors (extended)
pub const SCSI_CMD_READ_12: u8 = 0xA8;

/// Read Capacity (10) - get disk size
pub const SCSI_CMD_READ_CAPACITY_10: u8 = 0x25;

/// Test Unit Ready
pub const SCSI_CMD_TEST_UNIT_READY: u8 = 0x00;

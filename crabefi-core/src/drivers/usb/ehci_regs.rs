//! EHCI Register Definitions using tock-registers
//!
//! This module defines EHCI (USB 2.0) Enhanced Host Controller Interface registers
//! using type-safe tock-registers.
//!
//! # References
//! - EHCI Specification 1.0

use tock_registers::register_bitfields;
use tock_registers::registers::{ReadOnly, ReadWrite};

// ============================================================================
// Capability Register Bitfield Definitions
// ============================================================================

register_bitfields! [
    u32,
    /// Capability Register Length and Interface Version (offset 0x00)
    /// Lower byte is CAPLENGTH, upper word is HCIVERSION
    pub CAPLENGTH_HCIVERSION [
        /// Capability Registers Length (offset to operational registers)
        CAPLENGTH OFFSET(0) NUMBITS(8) [],
        /// Host Controller Interface Version Number
        HCIVERSION OFFSET(16) NUMBITS(16) []
    ],

    /// Structural Parameters (HCSPARAMS) - offset 0x04
    pub HCSPARAMS [
        /// Number of Ports
        N_PORTS OFFSET(0) NUMBITS(4) [],
        /// Port Power Control - ports have power switches
        PPC OFFSET(4) NUMBITS(1) [],
        /// Port Routing Rules
        PRR OFFSET(7) NUMBITS(1) [],
        /// Number of Ports per Companion Controller
        N_PCC OFFSET(8) NUMBITS(4) [],
        /// Number of Companion Controllers
        N_CC OFFSET(12) NUMBITS(4) [],
        /// Port Indicators
        P_INDICATOR OFFSET(16) NUMBITS(1) [],
        /// Debug Port Number
        DEBUG_N OFFSET(20) NUMBITS(4) []
    ],

    /// Capability Parameters (HCCPARAMS) - offset 0x08
    pub HCCPARAMS [
        /// 64-bit Addressing Capability
        AC64 OFFSET(0) NUMBITS(1) [],
        /// Programmable Frame List Flag
        PFLF OFFSET(1) NUMBITS(1) [],
        /// Asynchronous Schedule Park Capability
        ASPC OFFSET(2) NUMBITS(1) [],
        /// Isochronous Scheduling Threshold
        IST OFFSET(4) NUMBITS(4) [],
        /// EHCI Extended Capabilities Pointer
        EECP OFFSET(8) NUMBITS(8) []
    ]
];

// ============================================================================
// Operational Register Bitfield Definitions
// ============================================================================

register_bitfields! [
    u32,
    /// USB Command (USBCMD) - op offset 0x00
    pub USBCMD [
        /// Run/Stop
        RS OFFSET(0) NUMBITS(1) [],
        /// Host Controller Reset
        HCRESET OFFSET(1) NUMBITS(1) [],
        /// Frame List Size
        FLS OFFSET(2) NUMBITS(2) [
            Size1024 = 0,
            Size512 = 1,
            Size256 = 2,
            Reserved = 3
        ],
        /// Periodic Schedule Enable
        PSE OFFSET(4) NUMBITS(1) [],
        /// Asynchronous Schedule Enable
        ASE OFFSET(5) NUMBITS(1) [],
        /// Interrupt on Async Advance Doorbell
        IAAD OFFSET(6) NUMBITS(1) [],
        /// Light Host Controller Reset
        LHCRESET OFFSET(7) NUMBITS(1) [],
        /// Asynchronous Schedule Park Mode Count
        ASPMC OFFSET(8) NUMBITS(2) [],
        /// Asynchronous Schedule Park Mode Enable
        ASPME OFFSET(11) NUMBITS(1) [],
        /// Interrupt Threshold Control
        ITC OFFSET(16) NUMBITS(8) [
            Micro1 = 0x01,
            Micro2 = 0x02,
            Micro4 = 0x04,
            Micro8 = 0x08,
            Micro16 = 0x10,
            Micro32 = 0x20,
            Micro64 = 0x40
        ]
    ],

    /// USB Status (USBSTS) - op offset 0x04
    pub USBSTS [
        /// USB Interrupt
        USBINT OFFSET(0) NUMBITS(1) [],
        /// USB Error Interrupt
        USBERRINT OFFSET(1) NUMBITS(1) [],
        /// Port Change Detect
        PCD OFFSET(2) NUMBITS(1) [],
        /// Frame List Rollover
        FLR OFFSET(3) NUMBITS(1) [],
        /// Host System Error
        HSE OFFSET(4) NUMBITS(1) [],
        /// Interrupt on Async Advance
        IAA OFFSET(5) NUMBITS(1) [],
        /// HC Halted
        HCHALTED OFFSET(12) NUMBITS(1) [],
        /// Reclamation
        RECLAMATION OFFSET(13) NUMBITS(1) [],
        /// Periodic Schedule Status
        PSS OFFSET(14) NUMBITS(1) [],
        /// Asynchronous Schedule Status
        ASS OFFSET(15) NUMBITS(1) []
    ],

    /// USB Interrupt Enable (USBINTR) - op offset 0x08
    pub USBINTR [
        /// USB Interrupt Enable
        USBIE OFFSET(0) NUMBITS(1) [],
        /// USB Error Interrupt Enable
        USBEIE OFFSET(1) NUMBITS(1) [],
        /// Port Change Interrupt Enable
        PCIE OFFSET(2) NUMBITS(1) [],
        /// Frame List Rollover Enable
        FLRE OFFSET(3) NUMBITS(1) [],
        /// Host System Error Enable
        HSEE OFFSET(4) NUMBITS(1) [],
        /// Interrupt on Async Advance Enable
        IAAE OFFSET(5) NUMBITS(1) []
    ],

    /// Configure Flag (CONFIGFLAG) - op offset 0x40
    pub CONFIGFLAG [
        /// Configure Flag
        CF OFFSET(0) NUMBITS(1) []
    ],

    /// Port Status and Control (PORTSC) - per port, starting at op offset 0x44
    pub PORTSC [
        /// Current Connect Status (RO)
        CCS OFFSET(0) NUMBITS(1) [],
        /// Connect Status Change (RWC)
        CSC OFFSET(1) NUMBITS(1) [],
        /// Port Enabled/Disabled (RW)
        PE OFFSET(2) NUMBITS(1) [],
        /// Port Enable/Disable Change (RWC)
        PEC OFFSET(3) NUMBITS(1) [],
        /// Over-current Active (RO)
        OCA OFFSET(4) NUMBITS(1) [],
        /// Over-current Change (RWC)
        OCC OFFSET(5) NUMBITS(1) [],
        /// Force Port Resume (RW)
        FPR OFFSET(6) NUMBITS(1) [],
        /// Suspend (RW)
        SUSPEND OFFSET(7) NUMBITS(1) [],
        /// Port Reset (RW)
        PR OFFSET(8) NUMBITS(1) [],
        /// Line Status (RO)
        LS OFFSET(10) NUMBITS(2) [
            SE0 = 0,
            KState = 1,
            JState = 2,
            Undefined = 3
        ],
        /// Port Power (RW or RO depending on PPC)
        PP OFFSET(12) NUMBITS(1) [],
        /// Port Owner (RW)
        PO OFFSET(13) NUMBITS(1) [],
        /// Port Indicator Control (RW)
        PIC OFFSET(14) NUMBITS(2) [
            Off = 0,
            Amber = 1,
            Green = 2,
            Undefined = 3
        ],
        /// Port Test Control (RW)
        PTC OFFSET(16) NUMBITS(4) [
            Disabled = 0,
            JState = 1,
            KState = 2,
            SE0Nak = 3,
            Packet = 4,
            ForceEnable = 5
        ],
        /// Wake on Connect Enable (RW)
        WKCNNT_E OFFSET(20) NUMBITS(1) [],
        /// Wake on Disconnect Enable (RW)
        WKDSCNNT_E OFFSET(21) NUMBITS(1) [],
        /// Wake on Over-current Enable (RW)
        WKOC_E OFFSET(22) NUMBITS(1) []
    ]
];

// ============================================================================
// EHCI Capability Registers Memory Map
// ============================================================================

/// EHCI Capability Registers (read-only, minimum 0x10 bytes)
#[repr(C)]
pub struct EhciCapRegs {
    /// Capability Register Length and Interface Version
    pub caplength_hciversion: ReadOnly<u32, CAPLENGTH_HCIVERSION::Register>,
    /// Structural Parameters
    pub hcsparams: ReadOnly<u32, HCSPARAMS::Register>,
    /// Capability Parameters
    pub hccparams: ReadOnly<u32, HCCPARAMS::Register>,
    /// Companion Port Route Description (8 bytes)
    pub hcsp_portroute: [u8; 8],
}

/// EHCI Operational Registers
#[repr(C)]
pub struct EhciOpRegs {
    /// USB Command
    pub usbcmd: ReadWrite<u32, USBCMD::Register>,
    /// USB Status
    pub usbsts: ReadWrite<u32, USBSTS::Register>,
    /// USB Interrupt Enable
    pub usbintr: ReadWrite<u32, USBINTR::Register>,
    /// USB Frame Index
    pub frindex: ReadWrite<u32>,
    /// 4G Segment Selector
    pub ctrldssegment: ReadWrite<u32>,
    /// Periodic Frame List Base Address
    pub periodiclistbase: ReadWrite<u32>,
    /// Current Asynchronous List Address
    pub asynclistaddr: ReadWrite<u32>,
    /// Reserved
    _reserved: [u32; 9],
    /// Configure Flag Register
    pub configflag: ReadWrite<u32, CONFIGFLAG::Register>,
}

/// EHCI Port Register (one per port)
#[repr(C)]
pub struct EhciPortRegs {
    /// Port Status and Control
    pub portsc: ReadWrite<u32, PORTSC::Register>,
}

// ============================================================================
// Capability Register Offsets
// ============================================================================

/// CAPLENGTH and HCIVERSION register offset
pub const CAP_CAPLENGTH: u64 = 0x00;
/// HCSPARAMS register offset
pub const CAP_HCSPARAMS: u64 = 0x04;
/// HCCPARAMS register offset
pub const CAP_HCCPARAMS: u64 = 0x08;

// ============================================================================
// Operational Register Offsets
// ============================================================================

/// USBCMD register offset
pub const OP_USBCMD: u64 = 0x00;
/// USBSTS register offset
pub const OP_USBSTS: u64 = 0x04;
/// USBINTR register offset
pub const OP_USBINTR: u64 = 0x08;
/// FRINDEX register offset
pub const OP_FRINDEX: u64 = 0x0C;
/// CTRLDSSEGMENT register offset
pub const OP_CTRLDSSEGMENT: u64 = 0x10;
/// PERIODICLISTBASE register offset
pub const OP_PERIODICLISTBASE: u64 = 0x14;
/// ASYNCLISTADDR register offset
pub const OP_ASYNCLISTADDR: u64 = 0x18;
/// CONFIGFLAG register offset
pub const OP_CONFIGFLAG: u64 = 0x40;
/// PORTSC base offset (port 0)
pub const OP_PORTSC_BASE: u64 = 0x44;

// ============================================================================
// EHCI Extended Capabilities
// ============================================================================

/// USBLEGSUP (Legacy Support) Capability ID
pub const USBLEGSUP_CAP_ID: u8 = 0x01;

/// USBLEGSUP register bits
pub mod usblegsup {
    /// HC BIOS Owned Semaphore
    pub const HC_BIOS_OWNED: u32 = 1 << 16;
    /// HC OS Owned Semaphore
    pub const HC_OS_OWNED: u32 = 1 << 24;
}

// ============================================================================
// Queue Head (QH) Constants
// ============================================================================

/// QH Link pointer constants
pub mod qh_link {
    /// Terminate bit
    pub const TERMINATE: u32 = 1;
    /// Type: Isochronous Transfer Descriptor
    pub const TYPE_ITD: u32 = 0 << 1;
    /// Type: Queue Head
    pub const TYPE_QH: u32 = 1 << 1;
    /// Type: Split Transaction Isochronous Transfer Descriptor
    pub const TYPE_SITD: u32 = 2 << 1;
    /// Type: Frame Span Traversal Node
    pub const TYPE_FSTN: u32 = 3 << 1;
    /// Type mask
    pub const TYPE_MASK: u32 = 3 << 1;
}

/// QH Endpoint Characteristics constants
pub mod qh_ep_chars {
    /// Device Address mask
    pub const DEVADDR_MASK: u32 = 0x7F;
    /// Inactive on Next Transaction
    pub const INACTIVE: u32 = 1 << 7;
    /// Endpoint Number shift
    pub const ENDPT_SHIFT: u32 = 8;
    /// Endpoint Number mask
    pub const ENDPT_MASK: u32 = 0xF << 8;
    /// Endpoint Speed shift
    pub const EPS_SHIFT: u32 = 12;
    /// Endpoint Speed: Full Speed
    pub const EPS_FULL: u32 = 0 << 12;
    /// Endpoint Speed: Low Speed
    pub const EPS_LOW: u32 = 1 << 12;
    /// Endpoint Speed: High Speed
    pub const EPS_HIGH: u32 = 2 << 12;
    /// Data Toggle Control
    pub const DTC: u32 = 1 << 14;
    /// Head of Reclamation List Flag
    pub const HEAD: u32 = 1 << 15;
    /// Maximum Packet Length shift
    pub const MAXPKT_SHIFT: u32 = 16;
    /// Maximum Packet Length mask
    pub const MAXPKT_MASK: u32 = 0x7FF << 16;
    /// Control Endpoint Flag
    pub const CTRL: u32 = 1 << 27;
    /// NAK Count Reload shift
    pub const RL_SHIFT: u32 = 28;
    /// NAK Count Reload mask
    pub const RL_MASK: u32 = 0xF << 28;
}

/// QH Endpoint Capabilities constants
pub mod qh_ep_caps {
    /// Interrupt Schedule Mask shift
    pub const SMASK_SHIFT: u32 = 0;
    /// Split Completion Mask shift
    pub const CMASK_SHIFT: u32 = 8;
    /// Hub Address shift
    pub const HUBADDR_SHIFT: u32 = 16;
    /// Port Number shift
    pub const PORTNUM_SHIFT: u32 = 23;
    /// High-Bandwidth Pipe Multiplier shift
    pub const MULT_SHIFT: u32 = 30;
}

// ============================================================================
// Queue Element Transfer Descriptor (qTD) Constants
// ============================================================================

/// qTD Token constants
pub mod qtd_token {
    /// Status: Ping State / ERR
    pub const STATUS_PERR: u32 = 1 << 0;
    /// Status: Split Transaction State
    pub const STATUS_SPLIT: u32 = 1 << 1;
    /// Status: Missed Micro-Frame
    pub const STATUS_MISSED_UFRAME: u32 = 1 << 2;
    /// Status: Transaction Error
    pub const STATUS_XACT_ERR: u32 = 1 << 3;
    /// Status: Babble Detected
    pub const STATUS_BABBLE: u32 = 1 << 4;
    /// Status: Data Buffer Error
    pub const STATUS_BUFFER_ERR: u32 = 1 << 5;
    /// Status: Halted
    pub const STATUS_HALTED: u32 = 1 << 6;
    /// Status: Active
    pub const STATUS_ACTIVE: u32 = 1 << 7;
    /// Status mask (all status bits)
    pub const STATUS_MASK: u32 = 0xFF;

    /// PID Code: OUT Token
    pub const PID_OUT: u32 = 0 << 8;
    /// PID Code: IN Token
    pub const PID_IN: u32 = 1 << 8;
    /// PID Code: SETUP Token
    pub const PID_SETUP: u32 = 2 << 8;

    /// Error Counter shift
    pub const CERR_SHIFT: u32 = 10;
    /// Current Page shift
    pub const CPAGE_SHIFT: u32 = 12;
    /// Interrupt On Complete
    pub const IOC: u32 = 1 << 15;
    /// Total Bytes to Transfer shift
    pub const BYTES_SHIFT: u32 = 16;
    /// Total Bytes to Transfer mask
    pub const BYTES_MASK: u32 = 0x7FFF << 16;
    /// Data Toggle
    pub const TOGGLE: u32 = 1 << 31;

    /// Error bits mask (for checking transfer errors)
    pub const ERROR_MASK: u32 = STATUS_HALTED | STATUS_BUFFER_ERR | STATUS_BABBLE | STATUS_XACT_ERR;
}

/// qTD/QH terminate bit
pub const QTD_TERMINATE: u32 = 1;

// ============================================================================
// Port Status Change Bits (for clearing with RWC)
// ============================================================================

/// Mask for all write-clear status change bits in PORTSC
pub const PORTSC_WC_BITS: u32 = (1 << 1) | (1 << 3) | (1 << 5); // CSC | PEC | OCC

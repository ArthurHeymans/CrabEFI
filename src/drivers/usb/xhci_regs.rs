//! xHCI Register Definitions using tock-registers
//!
//! This module defines xHCI (USB 3.0) Host Controller Interface registers
//! using type-safe tock-registers.

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
        /// Capability Registers Length
        CAPLENGTH OFFSET(0) NUMBITS(8) [],
        /// Host Controller Interface Version Number
        HCIVERSION OFFSET(16) NUMBITS(16) []
    ],

    /// Structural Parameters 1 (HCSPARAMS1) - offset 0x04
    pub HCSPARAMS1 [
        /// Number of Device Slots
        MAX_SLOTS OFFSET(0) NUMBITS(8) [],
        /// Number of Interrupters
        MAX_INTRS OFFSET(8) NUMBITS(11) [],
        /// Number of Ports
        MAX_PORTS OFFSET(24) NUMBITS(8) []
    ],

    /// Structural Parameters 2 (HCSPARAMS2) - offset 0x08
    pub HCSPARAMS2 [
        /// Isochronous Scheduling Threshold
        IST OFFSET(0) NUMBITS(4) [],
        /// Event Ring Segment Table Max
        ERST_MAX OFFSET(4) NUMBITS(4) [],
        /// Max Scratchpad Buffers (Hi)
        MAX_SCRATCHPAD_HI OFFSET(21) NUMBITS(5) [],
        /// Scratchpad Restore
        SPR OFFSET(26) NUMBITS(1) [],
        /// Max Scratchpad Buffers (Lo)
        MAX_SCRATCHPAD_LO OFFSET(27) NUMBITS(5) []
    ],

    /// Structural Parameters 3 (HCSPARAMS3) - offset 0x0C
    pub HCSPARAMS3 [
        /// U1 Device Exit Latency
        U1_DEVICE_EXIT_LAT OFFSET(0) NUMBITS(8) [],
        /// U2 Device Exit Latency
        U2_DEVICE_EXIT_LAT OFFSET(16) NUMBITS(16) []
    ],

    /// Capability Parameters 1 (HCCPARAMS1) - offset 0x10
    pub HCCPARAMS1 [
        /// 64-bit Addressing Capability
        AC64 OFFSET(0) NUMBITS(1) [],
        /// Bandwidth Negotiation Capability
        BNC OFFSET(1) NUMBITS(1) [],
        /// Context Size (0=32 bytes, 1=64 bytes)
        CSZ OFFSET(2) NUMBITS(1) [],
        /// Port Power Control
        PPC OFFSET(3) NUMBITS(1) [],
        /// Port Indicators
        PIND OFFSET(4) NUMBITS(1) [],
        /// Light HC Reset Capability
        LHRC OFFSET(5) NUMBITS(1) [],
        /// Latency Tolerance Messaging Capability
        LTC OFFSET(6) NUMBITS(1) [],
        /// No Secondary SID Support
        NSS OFFSET(7) NUMBITS(1) [],
        /// Parse All Event Data
        PAE OFFSET(8) NUMBITS(1) [],
        /// Short Packet Capability
        SPC OFFSET(9) NUMBITS(1) [],
        /// Stopped EDTLA Capability
        SEC OFFSET(10) NUMBITS(1) [],
        /// Contiguous Frame ID Capability
        CFC OFFSET(11) NUMBITS(1) [],
        /// Maximum Primary Stream Array Size
        MAX_PSA_SIZE OFFSET(12) NUMBITS(4) [],
        /// xHCI Extended Capabilities Pointer
        XECP OFFSET(16) NUMBITS(16) []
    ],

    /// Doorbell Offset (DBOFF) - offset 0x14
    pub DBOFF [
        /// Doorbell Array Offset
        DOORBELL_OFFSET OFFSET(2) NUMBITS(30) []
    ],

    /// Runtime Register Space Offset (RTSOFF) - offset 0x18
    pub RTSOFF [
        /// Runtime Register Space Offset
        RUNTIME_OFFSET OFFSET(5) NUMBITS(27) []
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
        HCRST OFFSET(1) NUMBITS(1) [],
        /// Interrupter Enable
        INTE OFFSET(2) NUMBITS(1) [],
        /// Host System Error Enable
        HSEE OFFSET(3) NUMBITS(1) [],
        /// Light Host Controller Reset
        LHCRST OFFSET(7) NUMBITS(1) [],
        /// Controller Save State
        CSS OFFSET(8) NUMBITS(1) [],
        /// Controller Restore State
        CRS OFFSET(9) NUMBITS(1) [],
        /// Enable Wrap Event
        EWE OFFSET(10) NUMBITS(1) [],
        /// Enable U3 MFINDEX Stop
        EU3S OFFSET(11) NUMBITS(1) [],
        /// CEM Enable
        CME OFFSET(13) NUMBITS(1) []
    ],

    /// USB Status (USBSTS) - op offset 0x04
    pub USBSTS [
        /// Host Controller Halted
        HCH OFFSET(0) NUMBITS(1) [],
        /// Host System Error
        HSE OFFSET(2) NUMBITS(1) [],
        /// Event Interrupt
        EINT OFFSET(3) NUMBITS(1) [],
        /// Port Change Detect
        PCD OFFSET(4) NUMBITS(1) [],
        /// Save State Status
        SSS OFFSET(8) NUMBITS(1) [],
        /// Restore State Status
        RSS OFFSET(9) NUMBITS(1) [],
        /// Save/Restore Error
        SRE OFFSET(10) NUMBITS(1) [],
        /// Controller Not Ready
        CNR OFFSET(11) NUMBITS(1) [],
        /// Host Controller Error
        HCE OFFSET(12) NUMBITS(1) []
    ],

    /// Page Size (PAGESIZE) - op offset 0x08
    pub PAGESIZE [
        /// Page Size
        PAGE_SIZE OFFSET(0) NUMBITS(16) []
    ],

    /// Device Notification Control (DNCTRL) - op offset 0x14
    pub DNCTRL [
        /// Notification Enable
        N0_N15 OFFSET(0) NUMBITS(16) []
    ],

    /// Configure (CONFIG) - op offset 0x38
    pub CONFIG [
        /// Max Device Slots Enabled
        MAX_SLOTS_EN OFFSET(0) NUMBITS(8) [],
        /// U3 Entry Enable
        U3E OFFSET(8) NUMBITS(1) [],
        /// Configuration Information Enable
        CIE OFFSET(9) NUMBITS(1) []
    ],

    /// Port Status and Control (PORTSC) - per port
    pub PORTSC [
        /// Current Connect Status
        CCS OFFSET(0) NUMBITS(1) [],
        /// Port Enabled/Disabled
        PED OFFSET(1) NUMBITS(1) [],
        /// Over-current Active
        OCA OFFSET(3) NUMBITS(1) [],
        /// Port Reset
        PR OFFSET(4) NUMBITS(1) [],
        /// Port Link State
        PLS OFFSET(5) NUMBITS(4) [
            U0 = 0,
            U1 = 1,
            U2 = 2,
            U3 = 3,
            Disabled = 4,
            RxDetect = 5,
            Inactive = 6,
            Polling = 7,
            Recovery = 8,
            HotReset = 9,
            ComplianceMode = 10,
            TestMode = 11,
            Resume = 15
        ],
        /// Port Power
        PP OFFSET(9) NUMBITS(1) [],
        /// Port Speed
        SPEED OFFSET(10) NUMBITS(4) [
            Undefined = 0,
            FullSpeed = 1,
            LowSpeed = 2,
            HighSpeed = 3,
            SuperSpeed = 4,
            SuperSpeedPlus = 5
        ],
        /// Port Indicator Control
        PIC OFFSET(14) NUMBITS(2) [],
        /// Port Link State Write Strobe
        LWS OFFSET(16) NUMBITS(1) [],
        /// Connect Status Change
        CSC OFFSET(17) NUMBITS(1) [],
        /// Port Enabled/Disabled Change
        PEC OFFSET(18) NUMBITS(1) [],
        /// Warm Port Reset Change
        WRC OFFSET(19) NUMBITS(1) [],
        /// Over-current Change
        OCC OFFSET(20) NUMBITS(1) [],
        /// Port Reset Change
        PRC OFFSET(21) NUMBITS(1) [],
        /// Port Link State Change
        PLC OFFSET(22) NUMBITS(1) [],
        /// Port Config Error Change
        CEC OFFSET(23) NUMBITS(1) [],
        /// Cold Attach Status
        CAS OFFSET(24) NUMBITS(1) [],
        /// Wake on Connect Enable
        WCE OFFSET(25) NUMBITS(1) [],
        /// Wake on Disconnect Enable
        WDE OFFSET(26) NUMBITS(1) [],
        /// Wake on Over-current Enable
        WOE OFFSET(27) NUMBITS(1) [],
        /// Device Removable
        DR OFFSET(30) NUMBITS(1) [],
        /// Warm Port Reset
        WPR OFFSET(31) NUMBITS(1) []
    ]
];

register_bitfields! [
    u64,
    /// Command Ring Control (CRCR) - op offset 0x18
    pub CRCR [
        /// Ring Cycle State
        RCS OFFSET(0) NUMBITS(1) [],
        /// Command Stop
        CS OFFSET(1) NUMBITS(1) [],
        /// Command Abort
        CA OFFSET(2) NUMBITS(1) [],
        /// Command Ring Running
        CRR OFFSET(3) NUMBITS(1) [],
        /// Command Ring Pointer
        CRP OFFSET(6) NUMBITS(58) []
    ],

    /// Device Context Base Address Array Pointer (DCBAAP) - op offset 0x30
    pub DCBAAP [
        /// Device Context Base Address Array Pointer
        DCBAA_PTR OFFSET(6) NUMBITS(58) []
    ]
];

// ============================================================================
// xHCI Capability Registers Memory Map
// ============================================================================

/// xHCI Capability Registers (variable length, minimum 0x20 bytes)
#[repr(C)]
pub struct XhciCapRegs {
    /// Capability Register Length and Interface Version
    pub caplength_hciversion: ReadOnly<u32, CAPLENGTH_HCIVERSION::Register>,
    /// Structural Parameters 1
    pub hcsparams1: ReadOnly<u32, HCSPARAMS1::Register>,
    /// Structural Parameters 2
    pub hcsparams2: ReadOnly<u32, HCSPARAMS2::Register>,
    /// Structural Parameters 3
    pub hcsparams3: ReadOnly<u32, HCSPARAMS3::Register>,
    /// Capability Parameters 1
    pub hccparams1: ReadOnly<u32, HCCPARAMS1::Register>,
    /// Doorbell Offset
    pub dboff: ReadOnly<u32, DBOFF::Register>,
    /// Runtime Register Space Offset
    pub rtsoff: ReadOnly<u32, RTSOFF::Register>,
    /// Capability Parameters 2 (xHCI 1.1+)
    pub hccparams2: ReadOnly<u32>,
}

/// xHCI Operational Registers
#[repr(C)]
pub struct XhciOpRegs {
    /// USB Command
    pub usbcmd: ReadWrite<u32, USBCMD::Register>,
    /// USB Status
    pub usbsts: ReadWrite<u32, USBSTS::Register>,
    /// Page Size
    pub pagesize: ReadOnly<u32, PAGESIZE::Register>,
    /// Reserved
    _reserved0: [u32; 2],
    /// Device Notification Control
    pub dnctrl: ReadWrite<u32, DNCTRL::Register>,
    /// Command Ring Control (64-bit)
    pub crcr: ReadWrite<u64, CRCR::Register>,
    /// Reserved
    _reserved1: [u32; 4],
    /// Device Context Base Address Array Pointer (64-bit)
    pub dcbaap: ReadWrite<u64, DCBAAP::Register>,
    /// Configure
    pub config: ReadWrite<u32, CONFIG::Register>,
}

/// xHCI Port Register Set (one per port, 0x10 bytes each)
#[repr(C)]
pub struct XhciPortRegs {
    /// Port Status and Control
    pub portsc: ReadWrite<u32, PORTSC::Register>,
    /// Port Power Management Status and Control
    pub portpmsc: ReadWrite<u32>,
    /// Port Link Info
    pub portli: ReadOnly<u32>,
    /// Port Hardware LPM Control
    pub porthlpmc: ReadWrite<u32>,
}

// ============================================================================
// TRB Type Constants
// ============================================================================

/// Normal TRB
pub const TRB_TYPE_NORMAL: u32 = 1;
/// Setup Stage TRB
pub const TRB_TYPE_SETUP: u32 = 2;
/// Data Stage TRB
pub const TRB_TYPE_DATA: u32 = 3;
/// Status Stage TRB
pub const TRB_TYPE_STATUS: u32 = 4;
/// Isoch TRB
pub const TRB_TYPE_ISOCH: u32 = 5;
/// Link TRB
pub const TRB_TYPE_LINK: u32 = 6;
/// Event Data TRB
pub const TRB_TYPE_EVENT_DATA: u32 = 7;
/// No Op TRB
pub const TRB_TYPE_NOOP: u32 = 8;
/// Enable Slot Command
pub const TRB_TYPE_ENABLE_SLOT: u32 = 9;
/// Disable Slot Command
pub const TRB_TYPE_DISABLE_SLOT: u32 = 10;
/// Address Device Command
pub const TRB_TYPE_ADDRESS_DEVICE: u32 = 11;
/// Configure Endpoint Command
pub const TRB_TYPE_CONFIGURE_ENDPOINT: u32 = 12;
/// Evaluate Context Command
pub const TRB_TYPE_EVALUATE_CONTEXT: u32 = 13;
/// Reset Endpoint Command
pub const TRB_TYPE_RESET_ENDPOINT: u32 = 14;
/// Stop Endpoint Command
pub const TRB_TYPE_STOP_ENDPOINT: u32 = 15;
/// Set TR Dequeue Pointer Command
pub const TRB_TYPE_SET_TR_DEQUEUE: u32 = 16;
/// Reset Device Command
pub const TRB_TYPE_RESET_DEVICE: u32 = 17;
/// Transfer Event
pub const TRB_TYPE_TRANSFER_EVENT: u32 = 32;
/// Command Completion Event
pub const TRB_TYPE_COMMAND_COMPLETION: u32 = 33;
/// Port Status Change Event
pub const TRB_TYPE_PORT_STATUS_CHANGE: u32 = 34;
/// Host Controller Event
pub const TRB_TYPE_HOST_CONTROLLER: u32 = 37;

// ============================================================================
// TRB Completion Codes
// ============================================================================

/// Success
pub const TRB_CC_SUCCESS: u32 = 1;
/// Data Buffer Error
pub const TRB_CC_DATA_BUFFER_ERROR: u32 = 2;
/// Babble Detected Error
pub const TRB_CC_BABBLE_DETECTED: u32 = 3;
/// USB Transaction Error
pub const TRB_CC_USB_TRANSACTION_ERROR: u32 = 4;
/// TRB Error
pub const TRB_CC_TRB_ERROR: u32 = 5;
/// Stall Error
pub const TRB_CC_STALL_ERROR: u32 = 6;
/// Short Packet
pub const TRB_CC_SHORT_PACKET: u32 = 13;

// ============================================================================
// Extended Capability IDs
// ============================================================================

/// USB Legacy Support Capability
pub const XHCI_EXT_CAP_LEGACY: u8 = 0x01;
/// Supported Protocol Capability
pub const XHCI_EXT_CAP_PROTOCOL: u8 = 0x02;
/// Extended Power Management Capability
pub const XHCI_EXT_CAP_POWER: u8 = 0x03;
/// I/O Virtualization Capability
pub const XHCI_EXT_CAP_IOVIRT: u8 = 0x04;
/// USB Debug Capability
pub const XHCI_EXT_CAP_DEBUG: u8 = 0x0A;

// ============================================================================
// USB Legacy Support
// ============================================================================

/// BIOS Owned Semaphore bit
pub const USBLEGSUP_BIOS_OWNED: u32 = 1 << 16;
/// OS Owned Semaphore bit
pub const USBLEGSUP_OS_OWNED: u32 = 1 << 24;

// ============================================================================
// Port Status Change Bits (for clearing)
// ============================================================================

/// All status change bits that can be cleared by writing 1
pub const PORTSC_CHANGE_MASK: u32 =
    (1 << 17) | (1 << 18) | (1 << 19) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 23);

// ============================================================================
// Capability Register Offsets
// ============================================================================

/// CAPLENGTH and HCIVERSION register offset
pub const CAP_CAPLENGTH: u32 = 0x00;
/// HCSPARAMS1 register offset
pub const CAP_HCSPARAMS1: u32 = 0x04;
/// HCSPARAMS2 register offset
pub const CAP_HCSPARAMS2: u32 = 0x08;
/// HCSPARAMS3 register offset
pub const CAP_HCSPARAMS3: u32 = 0x0C;
/// HCCPARAMS1 register offset
pub const CAP_HCCPARAMS1: u32 = 0x10;
/// DBOFF register offset
pub const CAP_DBOFF: u32 = 0x14;
/// RTSOFF register offset
pub const CAP_RTSOFF: u32 = 0x18;

// ============================================================================
// Operational Register Offsets
// ============================================================================

/// USBCMD register offset
pub const OP_USBCMD: u32 = 0x00;
/// USBSTS register offset
pub const OP_USBSTS: u32 = 0x04;
/// PAGESIZE register offset
pub const OP_PAGESIZE: u32 = 0x08;
/// DNCTRL register offset
pub const OP_DNCTRL: u32 = 0x14;
/// CRCR register offset (64-bit)
pub const OP_CRCR: u32 = 0x18;
/// DCBAAP register offset (64-bit)
pub const OP_DCBAAP: u32 = 0x30;
/// CONFIG register offset
pub const OP_CONFIG: u32 = 0x38;

// ============================================================================
// Port Register Offsets (relative to port base)
// ============================================================================

/// PORTSC register offset
pub const PORT_PORTSC: u32 = 0x00;

// ============================================================================
// USBCMD Register Bits
// ============================================================================

/// Run/Stop
pub const USBCMD_RS: u32 = 1 << 0;
/// Host Controller Reset
pub const USBCMD_HCRST: u32 = 1 << 1;
/// Interrupter Enable
pub const USBCMD_INTE: u32 = 1 << 2;
/// Host System Error Enable
pub const USBCMD_HSEE: u32 = 1 << 3;

// ============================================================================
// USBSTS Register Bits
// ============================================================================

/// Host Controller Halted
pub const USBSTS_HCH: u32 = 1 << 0;
/// Host System Error
pub const USBSTS_HSE: u32 = 1 << 2;
/// Event Interrupt
pub const USBSTS_EINT: u32 = 1 << 3;
/// Port Change Detect
pub const USBSTS_PCD: u32 = 1 << 4;
/// Controller Not Ready
pub const USBSTS_CNR: u32 = 1 << 11;
/// Host Controller Error
pub const USBSTS_HCE: u32 = 1 << 12;

// ============================================================================
// PORTSC Register Bits
// ============================================================================

/// Current Connect Status
pub const PORTSC_CCS: u32 = 1 << 0;
/// Port Enabled/Disabled
pub const PORTSC_PED: u32 = 1 << 1;
/// Over-current Active
pub const PORTSC_OCA: u32 = 1 << 3;
/// Port Reset
pub const PORTSC_PR: u32 = 1 << 4;
/// Port Power
pub const PORTSC_PP: u32 = 1 << 9;
/// Port Speed Mask (bits 10-13)
pub const PORTSC_SPEED_MASK: u32 = 0xF << 10;
/// Port Reset Change
pub const PORTSC_PRC: u32 = 1 << 21;

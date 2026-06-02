//! OHCI Register Definitions using tock-registers
//!
//! This module defines OHCI (USB 1.1) Open Host Controller Interface registers
//! using type-safe tock-registers.
//!
//! # References
//! - OHCI Specification 1.0a

use tock_registers::register_bitfields;
use tock_registers::registers::{ReadOnly, ReadWrite};

// ============================================================================
// Operational Register Bitfield Definitions
// ============================================================================

register_bitfields! [
    u32,
    /// HC Revision (offset 0x00)
    pub HCREVISION [
        /// BCD representation of the OHCI spec revision
        REV OFFSET(0) NUMBITS(8) []
    ],

    /// HC Control (offset 0x04)
    pub HCCONTROL [
        /// Control Bulk Service Ratio
        CBSR OFFSET(0) NUMBITS(2) [],
        /// Periodic List Enable
        PLE OFFSET(2) NUMBITS(1) [],
        /// Isochronous Enable
        IE OFFSET(3) NUMBITS(1) [],
        /// Control List Enable
        CLE OFFSET(4) NUMBITS(1) [],
        /// Bulk List Enable
        BLE OFFSET(5) NUMBITS(1) [],
        /// Host Controller Functional State
        HCFS OFFSET(6) NUMBITS(2) [
            Reset = 0,
            Resume = 1,
            Operational = 2,
            Suspend = 3
        ],
        /// Interrupt Routing
        IR OFFSET(8) NUMBITS(1) [],
        /// Remote Wakeup Connected
        RWC OFFSET(9) NUMBITS(1) [],
        /// Remote Wakeup Enable
        RWE OFFSET(10) NUMBITS(1) []
    ],

    /// HC Command Status (offset 0x08)
    pub HCCOMMANDSTATUS [
        /// Host Controller Reset
        HCR OFFSET(0) NUMBITS(1) [],
        /// Control List Filled
        CLF OFFSET(1) NUMBITS(1) [],
        /// Bulk List Filled
        BLF OFFSET(2) NUMBITS(1) [],
        /// Ownership Change Request
        OCR OFFSET(3) NUMBITS(1) []
    ],

    /// HC Interrupt Status (offset 0x0C, W1C)
    pub HCINTERRUPTSTATUS [
        /// Scheduling Overrun
        SO OFFSET(0) NUMBITS(1) [],
        /// Writeback Done Head
        WDH OFFSET(1) NUMBITS(1) [],
        /// Start of Frame
        SF OFFSET(2) NUMBITS(1) [],
        /// Resume Detected
        RD OFFSET(3) NUMBITS(1) [],
        /// Unrecoverable Error
        UE OFFSET(4) NUMBITS(1) [],
        /// Frame Number Overflow
        FNO OFFSET(5) NUMBITS(1) [],
        /// Root Hub Status Change
        RHSC OFFSET(6) NUMBITS(1) [],
        /// Ownership Change
        OC OFFSET(30) NUMBITS(1) []
    ],

    /// HC Interrupt Enable (offset 0x10)
    pub HCINTERRUPTENABLE [
        /// Scheduling Overrun
        SO OFFSET(0) NUMBITS(1) [],
        /// Writeback Done Head
        WDH OFFSET(1) NUMBITS(1) [],
        /// Start of Frame
        SF OFFSET(2) NUMBITS(1) [],
        /// Resume Detected
        RD OFFSET(3) NUMBITS(1) [],
        /// Unrecoverable Error
        UE OFFSET(4) NUMBITS(1) [],
        /// Frame Number Overflow
        FNO OFFSET(5) NUMBITS(1) [],
        /// Root Hub Status Change
        RHSC OFFSET(6) NUMBITS(1) [],
        /// Ownership Change
        OC OFFSET(30) NUMBITS(1) [],
        /// Master Interrupt Enable
        MIE OFFSET(31) NUMBITS(1) []
    ],

    /// HC Interrupt Disable (offset 0x14)
    pub HCINTERRUPTDISABLE [
        /// Scheduling Overrun
        SO OFFSET(0) NUMBITS(1) [],
        /// Writeback Done Head
        WDH OFFSET(1) NUMBITS(1) [],
        /// Start of Frame
        SF OFFSET(2) NUMBITS(1) [],
        /// Resume Detected
        RD OFFSET(3) NUMBITS(1) [],
        /// Unrecoverable Error
        UE OFFSET(4) NUMBITS(1) [],
        /// Frame Number Overflow
        FNO OFFSET(5) NUMBITS(1) [],
        /// Root Hub Status Change
        RHSC OFFSET(6) NUMBITS(1) [],
        /// Ownership Change
        OC OFFSET(30) NUMBITS(1) [],
        /// Master Interrupt Enable
        MIE OFFSET(31) NUMBITS(1) []
    ],

    /// HC FM Interval (offset 0x34)
    pub HCFMINTERVAL [
        /// Frame Interval
        FI OFFSET(0) NUMBITS(14) [],
        /// FS Largest Data Packet
        FSMPS OFFSET(16) NUMBITS(15) [],
        /// Frame Interval Toggle
        FIT OFFSET(31) NUMBITS(1) []
    ],

    /// HC FM Remaining (offset 0x38)
    pub HCFMREMAINING [
        /// Frame Remaining
        FR OFFSET(0) NUMBITS(14) [],
        /// Frame Remaining Toggle
        FRT OFFSET(31) NUMBITS(1) []
    ],

    /// HC FM Number (offset 0x3C)
    pub HCFMNUMBER [
        /// Frame Number
        FN OFFSET(0) NUMBITS(16) []
    ],

    /// HC Periodic Start (offset 0x40)
    pub HCPERIODICSTART [
        /// Periodic Start
        PS OFFSET(0) NUMBITS(14) []
    ],

    /// HC LS Threshold (offset 0x44)
    pub HCLSTHRESHOLD [
        /// LS Threshold
        LST OFFSET(0) NUMBITS(12) []
    ],

    /// HC Root Hub Descriptor A (offset 0x48)
    pub HCRHDESCRIPTORA [
        /// Number of Downstream Ports
        NDP OFFSET(0) NUMBITS(8) [],
        /// Power Switching Mode
        PSM OFFSET(8) NUMBITS(1) [],
        /// No Power Switching
        NPS OFFSET(9) NUMBITS(1) [],
        /// Device Type
        DT OFFSET(10) NUMBITS(1) [],
        /// Over Current Protection Mode
        OCPM OFFSET(11) NUMBITS(1) [],
        /// No Over Current Protection
        NOCP OFFSET(12) NUMBITS(1) [],
        /// Power On to Power Good Time (in 2ms units)
        POTPGT OFFSET(24) NUMBITS(8) []
    ],

    /// HC Root Hub Status (offset 0x50)
    pub HCRHSTATUS [
        /// Local Power Status
        LPS OFFSET(0) NUMBITS(1) [],
        /// Over Current Indicator
        OCI OFFSET(1) NUMBITS(1) [],
        /// Device Remote Wakeup Enable
        DRWE OFFSET(15) NUMBITS(1) [],
        /// Local Power Status Change
        LPSC OFFSET(16) NUMBITS(1) [],
        /// Over Current Indicator Change
        OCIC OFFSET(17) NUMBITS(1) [],
        /// Clear Remote Wakeup Enable
        CRWE OFFSET(31) NUMBITS(1) []
    ],

    /// HC Root Hub Port Status (offset 0x54+, per port)
    pub HCRHPORTSTATUS [
        /// Current Connect Status
        CCS OFFSET(0) NUMBITS(1) [],
        /// Port Enable Status
        PES OFFSET(1) NUMBITS(1) [],
        /// Port Suspend Status
        PSS OFFSET(2) NUMBITS(1) [],
        /// Port Over Current Indicator
        POCI OFFSET(3) NUMBITS(1) [],
        /// Port Reset Status
        PRS OFFSET(4) NUMBITS(1) [],
        /// Port Power Status
        PPS OFFSET(8) NUMBITS(1) [],
        /// Low Speed Device Attached
        LSDA OFFSET(9) NUMBITS(1) [],
        /// Connect Status Change
        CSC OFFSET(16) NUMBITS(1) [],
        /// Port Enable Status Change
        PESC OFFSET(17) NUMBITS(1) [],
        /// Port Suspend Status Change
        PSSC OFFSET(18) NUMBITS(1) [],
        /// Over Current Indicator Change
        OCIC OFFSET(19) NUMBITS(1) [],
        /// Port Reset Status Change
        PRSC OFFSET(20) NUMBITS(1) []
    ]
];

// ============================================================================
// OHCI Operational Registers Memory Map
// ============================================================================

/// OHCI Operational Registers (all at fixed offsets from MMIO base)
#[repr(C)]
pub struct OhciRegs {
    /// HC Revision (0x00)
    pub hcrevision: ReadOnly<u32, HCREVISION::Register>,
    /// HC Control (0x04)
    pub hccontrol: ReadWrite<u32, HCCONTROL::Register>,
    /// HC Command Status (0x08)
    pub hccommandstatus: ReadWrite<u32, HCCOMMANDSTATUS::Register>,
    /// HC Interrupt Status (0x0C)
    pub hcinterruptstatus: ReadWrite<u32, HCINTERRUPTSTATUS::Register>,
    /// HC Interrupt Enable (0x10)
    pub hcinterruptenable: ReadWrite<u32, HCINTERRUPTENABLE::Register>,
    /// HC Interrupt Disable (0x14)
    pub hcinterruptdisable: ReadWrite<u32, HCINTERRUPTDISABLE::Register>,
    /// HC HCCA (0x18) - pointer to Host Controller Communication Area
    pub hchcca: ReadWrite<u32>,
    /// HC Period Current ED (0x1C)
    pub hcperiodcurrented: ReadOnly<u32>,
    /// HC Control Head ED (0x20)
    pub hccontrolheaded: ReadWrite<u32>,
    /// HC Control Current ED (0x24)
    pub hccontrolcurrented: ReadWrite<u32>,
    /// HC Bulk Head ED (0x28)
    pub hcbulkheaded: ReadWrite<u32>,
    /// HC Bulk Current ED (0x2C)
    pub hcbulkcurrented: ReadWrite<u32>,
    /// HC Done Head (0x30)
    pub hcdonehead: ReadOnly<u32>,
    /// HC FM Interval (0x34)
    pub hcfminterval: ReadWrite<u32, HCFMINTERVAL::Register>,
    /// HC FM Remaining (0x38)
    pub hcfmremaining: ReadOnly<u32, HCFMREMAINING::Register>,
    /// HC FM Number (0x3C)
    pub hcfmnumber: ReadOnly<u32, HCFMNUMBER::Register>,
    /// HC Periodic Start (0x40)
    pub hcperiodicstart: ReadWrite<u32, HCPERIODICSTART::Register>,
    /// HC LS Threshold (0x44)
    pub hclsthreshold: ReadWrite<u32, HCLSTHRESHOLD::Register>,
    /// HC Root Hub Descriptor A (0x48)
    pub hcrhdescriptora: ReadWrite<u32, HCRHDESCRIPTORA::Register>,
    /// HC Root Hub Descriptor B (0x4C) - port masks, plain u32
    pub hcrhdescriptorb: ReadWrite<u32>,
    /// HC Root Hub Status (0x50)
    pub hcrhstatus: ReadWrite<u32, HCRHSTATUS::Register>,
}

/// OHCI Port Register (one per port, starting at offset 0x54)
#[repr(C)]
pub struct OhciPortRegs {
    /// Port Status and Control
    pub portsc: ReadWrite<u32, HCRHPORTSTATUS::Register>,
}

// ============================================================================
// Register Offsets
// ============================================================================

/// HCREVISION register offset
pub const HCREVISION_OFFSET: u64 = 0x00;
/// HCCONTROL register offset
pub const HCCONTROL_OFFSET: u64 = 0x04;
/// HCCOMMANDSTATUS register offset
pub const HCCOMMANDSTATUS_OFFSET: u64 = 0x08;
/// HCINTERRUPTSTATUS register offset
pub const HCINTERRUPTSTATUS_OFFSET: u64 = 0x0C;
/// HCINTERRUPTENABLE register offset
pub const HCINTERRUPTENABLE_OFFSET: u64 = 0x10;
/// HCINTERRUPTDISABLE register offset
pub const HCINTERRUPTDISABLE_OFFSET: u64 = 0x14;
/// HCHCCA register offset
pub const HCHCCA_OFFSET: u64 = 0x18;
/// HCPERIODCURRENTED register offset
pub const HCPERIODCURRENTED_OFFSET: u64 = 0x1C;
/// HCCONTROLHEADED register offset
pub const HCCONTROLHEADED_OFFSET: u64 = 0x20;
/// HCCONTROLCURRENTED register offset
pub const HCCONTROLCURRENTED_OFFSET: u64 = 0x24;
/// HCBULKHEADED register offset
pub const HCBULKHEADED_OFFSET: u64 = 0x28;
/// HCBULKCURRENTED register offset
pub const HCBULKCURRENTED_OFFSET: u64 = 0x2C;
/// HCDONEHEAD register offset
pub const HCDONEHEAD_OFFSET: u64 = 0x30;
/// HCFMINTERVAL register offset
pub const HCFMINTERVAL_OFFSET: u64 = 0x34;
/// HCFMREMAINING register offset
pub const HCFMREMAINING_OFFSET: u64 = 0x38;
/// HCFMNUMBER register offset
pub const HCFMNUMBER_OFFSET: u64 = 0x3C;
/// HCPERIODICSTART register offset
pub const HCPERIODICSTART_OFFSET: u64 = 0x40;
/// HCLSTHRESHOLD register offset
pub const HCLSTHRESHOLD_OFFSET: u64 = 0x44;
/// HCRHDESCRIPTORA register offset
pub const HCRHDESCRIPTORA_OFFSET: u64 = 0x48;
/// HCRHDESCRIPTORB register offset
pub const HCRHDESCRIPTORB_OFFSET: u64 = 0x4C;
/// HCRHSTATUS register offset
pub const HCRHSTATUS_OFFSET: u64 = 0x50;
/// HCRHPORTSTATUS base offset (port 0)
pub const HCRHPORTSTATUS_BASE: u64 = 0x54;

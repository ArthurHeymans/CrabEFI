//! SDHCI Register Definitions using tock-registers
//!
//! This module defines the standard SDHCI (SD Host Controller Interface)
//! registers and bitfields as specified in the SD Host Controller Simplified
//! Specification, using type-safe tock-registers.

use tock_registers::register_bitfields;
use tock_registers::registers::{ReadOnly, ReadWrite, WriteOnly};

// ============================================================================
// Register Bitfield Definitions
// ============================================================================

register_bitfields! [
    u32,
    /// Present State Register (0x24)
    pub PRESENT_STATE [
        /// Command Inhibit (CMD)
        CMD_INHIBIT OFFSET(0) NUMBITS(1) [],
        /// Command Inhibit (DAT)
        DAT_INHIBIT OFFSET(1) NUMBITS(1) [],
        /// DAT Line Active
        DAT_ACTIVE OFFSET(2) NUMBITS(1) [],
        /// Re-Tuning Request
        RETUNE_REQUEST OFFSET(3) NUMBITS(1) [],
        /// Write Transfer Active
        WRITE_ACTIVE OFFSET(8) NUMBITS(1) [],
        /// Read Transfer Active
        READ_ACTIVE OFFSET(9) NUMBITS(1) [],
        /// Buffer Write Enable
        BUFFER_WRITE_ENABLE OFFSET(10) NUMBITS(1) [],
        /// Buffer Read Enable
        BUFFER_READ_ENABLE OFFSET(11) NUMBITS(1) [],
        /// Card Inserted
        CARD_INSERTED OFFSET(16) NUMBITS(1) [],
        /// Card State Stable
        CARD_STABLE OFFSET(17) NUMBITS(1) [],
        /// Card Detect Pin Level
        CARD_DETECT_PIN OFFSET(18) NUMBITS(1) [],
        /// Write Protect Switch Pin Level
        WRITE_PROTECT OFFSET(19) NUMBITS(1) [],
        /// DAT[3:0] Line Signal Level
        DAT_LEVEL OFFSET(20) NUMBITS(4) []
    ],

    /// Interrupt Status Register (0x30)
    pub INT_STATUS [
        /// Command Complete
        CMD_COMPLETE OFFSET(0) NUMBITS(1) [],
        /// Transfer Complete
        TRANSFER_COMPLETE OFFSET(1) NUMBITS(1) [],
        /// Block Gap Event
        BLOCK_GAP OFFSET(2) NUMBITS(1) [],
        /// DMA Interrupt
        DMA_INT OFFSET(3) NUMBITS(1) [],
        /// Buffer Write Ready
        BUFFER_WRITE_READY OFFSET(4) NUMBITS(1) [],
        /// Buffer Read Ready
        BUFFER_READ_READY OFFSET(5) NUMBITS(1) [],
        /// Card Insertion
        CARD_INSERT OFFSET(6) NUMBITS(1) [],
        /// Card Removal
        CARD_REMOVE OFFSET(7) NUMBITS(1) [],
        /// Card Interrupt
        CARD_INT OFFSET(8) NUMBITS(1) [],
        /// Error Interrupt
        ERROR OFFSET(15) NUMBITS(1) [],
        /// Command Timeout Error
        CMD_TIMEOUT OFFSET(16) NUMBITS(1) [],
        /// Command CRC Error
        CMD_CRC OFFSET(17) NUMBITS(1) [],
        /// Command End Bit Error
        CMD_END_BIT OFFSET(18) NUMBITS(1) [],
        /// Command Index Error
        CMD_INDEX OFFSET(19) NUMBITS(1) [],
        /// Data Timeout Error
        DATA_TIMEOUT OFFSET(20) NUMBITS(1) [],
        /// Data CRC Error
        DATA_CRC OFFSET(21) NUMBITS(1) [],
        /// Data End Bit Error
        DATA_END_BIT OFFSET(22) NUMBITS(1) [],
        /// Current Limit Error
        CURRENT_LIMIT OFFSET(23) NUMBITS(1) [],
        /// Auto CMD Error
        AUTO_CMD OFFSET(24) NUMBITS(1) [],
        /// ADMA Error
        ADMA OFFSET(25) NUMBITS(1) []
    ],

    /// Capabilities Register (0x40)
    pub CAPABILITIES [
        /// Timeout Clock Frequency
        TIMEOUT_CLK_FREQ OFFSET(0) NUMBITS(6) [],
        /// Timeout Clock Unit (0=KHz, 1=MHz)
        TIMEOUT_CLK_UNIT OFFSET(7) NUMBITS(1) [],
        /// Base Clock Frequency For SD Clock
        BASE_CLK_FREQ OFFSET(8) NUMBITS(8) [],
        /// Max Block Length
        MAX_BLOCK_LEN OFFSET(16) NUMBITS(2) [],
        /// 8-bit Support For Embedded Device
        SUPPORT_8BIT OFFSET(18) NUMBITS(1) [],
        /// ADMA2 Support
        SUPPORT_ADMA2 OFFSET(19) NUMBITS(1) [],
        /// ADMA1 Support (obsolete)
        SUPPORT_ADMA1 OFFSET(20) NUMBITS(1) [],
        /// High Speed Support
        SUPPORT_HIGHSPEED OFFSET(21) NUMBITS(1) [],
        /// SDMA Support
        SUPPORT_SDMA OFFSET(22) NUMBITS(1) [],
        /// Suspend/Resume Support
        SUPPORT_SUSPEND OFFSET(23) NUMBITS(1) [],
        /// Voltage Support 3.3V
        SUPPORT_3V3 OFFSET(24) NUMBITS(1) [],
        /// Voltage Support 3.0V
        SUPPORT_3V0 OFFSET(25) NUMBITS(1) [],
        /// Voltage Support 1.8V
        SUPPORT_1V8 OFFSET(26) NUMBITS(1) [],
        /// 64-bit System Bus Support
        SUPPORT_64BIT OFFSET(28) NUMBITS(1) []
    ],

    /// Capabilities 1 Register (0x44)
    pub CAPABILITIES_1 [
        /// SDR50 Support
        SUPPORT_SDR50 OFFSET(0) NUMBITS(1) [],
        /// SDR104 Support
        SUPPORT_SDR104 OFFSET(1) NUMBITS(1) [],
        /// DDR50 Support
        SUPPORT_DDR50 OFFSET(2) NUMBITS(1) [],
        /// Use Tuning for SDR50
        USE_SDR50_TUNING OFFSET(13) NUMBITS(1) [],
        /// Clock Multiplier
        CLK_MULTIPLIER OFFSET(16) NUMBITS(8) [],
        /// HS400 Support
        SUPPORT_HS400 OFFSET(31) NUMBITS(1) []
    ]
];

register_bitfields! [
    u16,
    /// Block Size Register (0x04)
    pub BLOCK_SIZE [
        /// Transfer Block Size
        BLOCK_SIZE OFFSET(0) NUMBITS(12) [],
        /// SDMA Buffer Boundary
        SDMA_BOUNDARY OFFSET(12) NUMBITS(3) []
    ],

    /// Transfer Mode Register (0x0C)
    pub TRANSFER_MODE [
        /// DMA Enable
        DMA_ENABLE OFFSET(0) NUMBITS(1) [],
        /// Block Count Enable
        BLOCK_COUNT_ENABLE OFFSET(1) NUMBITS(1) [],
        /// Auto CMD12 Enable
        AUTO_CMD12 OFFSET(2) NUMBITS(1) [],
        /// Auto CMD23 Enable
        AUTO_CMD23 OFFSET(3) NUMBITS(1) [],
        /// Data Transfer Direction (1=read, 0=write)
        DATA_DIRECTION OFFSET(4) NUMBITS(1) [],
        /// Multi Block Select
        MULTI_BLOCK OFFSET(5) NUMBITS(1) []
    ],

    /// Command Register (0x0E)
    pub COMMAND [
        /// Response Type
        RESPONSE_TYPE OFFSET(0) NUMBITS(2) [
            None = 0,
            Long136 = 1,
            Short48 = 2,
            Short48Busy = 3
        ],
        /// Command CRC Check Enable
        CRC_CHECK OFFSET(3) NUMBITS(1) [],
        /// Command Index Check Enable
        INDEX_CHECK OFFSET(4) NUMBITS(1) [],
        /// Data Present Select
        DATA_PRESENT OFFSET(5) NUMBITS(1) [],
        /// Command Type
        CMD_TYPE OFFSET(6) NUMBITS(2) [],
        /// Command Index
        CMD_INDEX OFFSET(8) NUMBITS(6) []
    ],

    /// Clock Control Register (0x2C)
    pub CLOCK_CONTROL [
        /// Internal Clock Enable
        INTERNAL_CLK_EN OFFSET(0) NUMBITS(1) [],
        /// Internal Clock Stable
        INTERNAL_CLK_STABLE OFFSET(1) NUMBITS(1) [],
        /// SD Clock Enable
        SD_CLK_EN OFFSET(2) NUMBITS(1) [],
        /// Programmable Clock Mode
        PROG_CLK_MODE OFFSET(5) NUMBITS(1) [],
        /// Upper Bits of SDCLK Frequency Select
        FREQ_SELECT_HI OFFSET(6) NUMBITS(2) [],
        /// SDCLK Frequency Select
        FREQ_SELECT OFFSET(8) NUMBITS(8) []
    ],

    /// Host Control 2 Register (0x3E)
    pub HOST_CONTROL2 [
        /// UHS Mode Select
        UHS_MODE OFFSET(0) NUMBITS(3) [
            SDR12 = 0,
            SDR25 = 1,
            SDR50 = 2,
            SDR104 = 3,
            DDR50 = 4,
            HS400 = 5
        ],
        /// 1.8V Signaling Enable
        SIGNALING_1V8 OFFSET(3) NUMBITS(1) [],
        /// Driver Strength Select
        DRIVER_STRENGTH OFFSET(4) NUMBITS(2) [
            TypeB = 0,
            TypeA = 1,
            TypeC = 2,
            TypeD = 3
        ],
        /// Execute Tuning
        EXEC_TUNING OFFSET(6) NUMBITS(1) [],
        /// Sampling Clock Select
        SAMPLING_CLK OFFSET(7) NUMBITS(1) [],
        /// Preset Value Enable
        PRESET_VALUE_EN OFFSET(15) NUMBITS(1) []
    ],

    /// Host Version Register (0xFE)
    pub HOST_VERSION [
        /// Specification Version Number
        SPEC_VERSION OFFSET(0) NUMBITS(8) [],
        /// Vendor Version Number
        VENDOR_VERSION OFFSET(8) NUMBITS(8) []
    ]
];

register_bitfields! [
    u8,
    /// Host Control Register (0x28)
    pub HOST_CONTROL [
        /// LED Control
        LED OFFSET(0) NUMBITS(1) [],
        /// Data Transfer Width (1=4-bit)
        DATA_WIDTH_4BIT OFFSET(1) NUMBITS(1) [],
        /// High Speed Enable
        HIGH_SPEED OFFSET(2) NUMBITS(1) [],
        /// DMA Select
        DMA_SELECT OFFSET(3) NUMBITS(2) [
            SDMA = 0,
            ADMA1 = 1,
            ADMA32 = 2,
            ADMA64 = 3
        ],
        /// Extended Data Transfer Width (1=8-bit)
        DATA_WIDTH_8BIT OFFSET(5) NUMBITS(1) [],
        /// Card Detect Test Level
        CD_TEST_LEVEL OFFSET(6) NUMBITS(1) [],
        /// Card Detect Signal Selection
        CD_SIGNAL_SEL OFFSET(7) NUMBITS(1) []
    ],

    /// Power Control Register (0x29)
    pub POWER_CONTROL [
        /// SD Bus Power
        BUS_POWER OFFSET(0) NUMBITS(1) [],
        /// SD Bus Voltage Select
        BUS_VOLTAGE OFFSET(1) NUMBITS(3) [
            V3_3 = 7,
            V3_0 = 6,
            V1_8 = 5
        ]
    ],

    /// Software Reset Register (0x2F)
    pub SOFTWARE_RESET [
        /// Software Reset For All
        RESET_ALL OFFSET(0) NUMBITS(1) [],
        /// Software Reset For CMD Line
        RESET_CMD OFFSET(1) NUMBITS(1) [],
        /// Software Reset For DAT Line
        RESET_DATA OFFSET(2) NUMBITS(1) []
    ]
];

// ============================================================================
// SDHCI Register Memory Map
// ============================================================================

/// SDHCI controller registers memory map
#[repr(C)]
pub struct SdhciRegisters {
    /// SDMA System Address / Argument 2 (0x00)
    pub sdma_addr: ReadWrite<u32>,
    /// Block Size Register (0x04)
    pub block_size: ReadWrite<u16, BLOCK_SIZE::Register>,
    /// Block Count Register (0x06)
    pub block_count: ReadWrite<u16>,
    /// Argument Register (0x08)
    pub argument: ReadWrite<u32>,
    /// Transfer Mode Register (0x0C)
    pub transfer_mode: ReadWrite<u16, TRANSFER_MODE::Register>,
    /// Command Register (0x0E)
    pub command: ReadWrite<u16, COMMAND::Register>,
    /// Response Register 0 (0x10)
    pub response0: ReadOnly<u32>,
    /// Response Register 1 (0x14)
    pub response1: ReadOnly<u32>,
    /// Response Register 2 (0x18)
    pub response2: ReadOnly<u32>,
    /// Response Register 3 (0x1C)
    pub response3: ReadOnly<u32>,
    /// Buffer Data Port Register (0x20)
    pub buffer_data: ReadWrite<u32>,
    /// Present State Register (0x24)
    pub present_state: ReadOnly<u32, PRESENT_STATE::Register>,
    /// Host Control Register (0x28)
    pub host_control: ReadWrite<u8, HOST_CONTROL::Register>,
    /// Power Control Register (0x29)
    pub power_control: ReadWrite<u8, POWER_CONTROL::Register>,
    /// Block Gap Control Register (0x2A)
    pub block_gap_control: ReadWrite<u8>,
    /// Wakeup Control Register (0x2B)
    pub wakeup_control: ReadWrite<u8>,
    /// Clock Control Register (0x2C)
    pub clock_control: ReadWrite<u16, CLOCK_CONTROL::Register>,
    /// Timeout Control Register (0x2E)
    pub timeout_control: ReadWrite<u8>,
    /// Software Reset Register (0x2F)
    pub software_reset: ReadWrite<u8, SOFTWARE_RESET::Register>,
    /// Normal Interrupt Status Register (0x30)
    pub int_status: ReadWrite<u32, INT_STATUS::Register>,
    /// Normal Interrupt Status Enable Register (0x34)
    pub int_enable: ReadWrite<u32, INT_STATUS::Register>,
    /// Normal Interrupt Signal Enable Register (0x38)
    pub signal_enable: ReadWrite<u32, INT_STATUS::Register>,
    /// Auto CMD Error Status Register (0x3C)
    pub acmd_error: ReadOnly<u16>,
    /// Host Control 2 Register (0x3E)
    pub host_control2: ReadWrite<u16, HOST_CONTROL2::Register>,
    /// Capabilities Register (0x40)
    pub capabilities: ReadOnly<u32, CAPABILITIES::Register>,
    /// Capabilities Register 1 (0x44)
    pub capabilities_1: ReadOnly<u32, CAPABILITIES_1::Register>,
    /// Maximum Current Capabilities Register (0x48)
    pub max_current: ReadOnly<u32>,
    /// Reserved (0x4C)
    _reserved0: u32,
    /// Force Event Register for Auto CMD Error Status (0x50)
    pub force_acmd_error: WriteOnly<u16>,
    /// Force Event Register for Error Interrupt Status (0x52)
    pub force_error: WriteOnly<u16>,
    /// ADMA Error Status Register (0x54)
    pub adma_error: ReadOnly<u8>,
    /// Reserved (0x55-0x57)
    _reserved1: [u8; 3],
    /// ADMA System Address Register (0x58)
    pub adma_addr: ReadWrite<u64>,
    /// Reserved (0x60-0xFB)
    _reserved2: [u8; 0x9C],
    /// Slot Interrupt Status Register (0xFC)
    pub slot_int_status: ReadOnly<u16>,
    /// Host Controller Version Register (0xFE)
    pub host_version: ReadOnly<u16, HOST_VERSION::Register>,
}

// ============================================================================
// Legacy Constants (for compatibility during transition)
// ============================================================================

/// SDHCI Specification Version 3.00
pub const SDHCI_SPEC_300: u8 = 2;

/// Maximum divider for SDHCI 2.0 (8-bit, powers of 2)
pub const SDHCI_MAX_DIV_SPEC_200: u32 = 256;

/// Maximum divider for SDHCI 3.0+ (10-bit)
pub const SDHCI_MAX_DIV_SPEC_300: u32 = 2046;

/// Default SDMA buffer boundary argument (7 = 512KB)
pub const SDHCI_DEFAULT_BOUNDARY_ARG: u16 = 7;

// ============================================================================
// SD/MMC Commands
// ============================================================================

/// GO_IDLE_STATE - Resets all cards to idle state
pub const MMC_CMD_GO_IDLE_STATE: u8 = 0;

/// ALL_SEND_CID - Asks all cards to send their CID
pub const MMC_CMD_ALL_SEND_CID: u8 = 2;

/// SELECT/DESELECT_CARD - Toggles card between stand-by and transfer states
pub const MMC_CMD_SELECT_CARD: u8 = 7;

/// SEND_CSD - Asks card to send its CSD
pub const MMC_CMD_SEND_CSD: u8 = 9;

/// STOP_TRANSMISSION - Forces card to stop transmission
pub const MMC_CMD_STOP_TRANSMISSION: u8 = 12;

/// SET_BLOCKLEN - Sets block length for block commands
pub const MMC_CMD_SET_BLOCKLEN: u8 = 16;

/// READ_SINGLE_BLOCK - Reads a single block
pub const MMC_CMD_READ_SINGLE_BLOCK: u8 = 17;

/// READ_MULTIPLE_BLOCK - Continuously reads blocks until STOP_TRANSMISSION
pub const MMC_CMD_READ_MULTIPLE_BLOCK: u8 = 18;

/// APP_CMD - Indicates next command is application specific
pub const MMC_CMD_APP_CMD: u8 = 55;

// SD-specific commands

/// SEND_RELATIVE_ADDR (SD) - Ask card to publish new RCA
pub const SD_CMD_SEND_RELATIVE_ADDR: u8 = 3;

/// SEND_IF_COND - Sends SD interface condition
pub const SD_CMD_SEND_IF_COND: u8 = 8;

/// SET_BUS_WIDTH (ACMD6) - Sets bus width
pub const SD_CMD_APP_SET_BUS_WIDTH: u8 = 6;

/// SD_SEND_OP_COND (ACMD41) - Sends host capacity support info
pub const SD_CMD_APP_SEND_OP_COND: u8 = 41;

// ============================================================================
// OCR (Operation Conditions Register) Bitfields
// ============================================================================

/// Card is busy (bit 31 = 0 means busy)
pub const OCR_BUSY: u32 = 1 << 31;

/// Card Capacity Status (HCS) - set for SDHC/SDXC
pub const OCR_HCS: u32 = 1 << 30;

/// Standard voltage range (2.7V - 3.6V)
pub const OCR_VDD_RANGE: u32 = 0x00FF_8000;

// ============================================================================
// Response Types
// ============================================================================

/// No response
pub const MMC_RSP_NONE: u8 = 0;

/// R1 - Normal response
pub const MMC_RSP_R1: u8 = 1;

/// R1b - Normal response with busy
pub const MMC_RSP_R1B: u8 = 2;

/// R2 - CID/CSD response (136 bits)
pub const MMC_RSP_R2: u8 = 3;

/// R3 - OCR response
pub const MMC_RSP_R3: u8 = 4;

/// R6 - RCA response (SD)
pub const MMC_RSP_R6: u8 = 5;

/// R7 - Card interface condition (SD)
pub const MMC_RSP_R7: u8 = 6;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create block size value with SDMA buffer boundary
#[inline]
pub const fn make_blksz(boundary: u16, blksz: u16) -> u16 {
    ((boundary & 0x7) << 12) | (blksz & 0xFFF)
}

/// Create command register value
#[inline]
pub const fn make_cmd(cmd_idx: u8, flags: u16) -> u16 {
    ((cmd_idx as u16) << 8) | (flags & 0xFF)
}

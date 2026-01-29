//! SDHCI Register Definitions
//!
//! This module defines the standard SDHCI (SD Host Controller Interface)
//! registers and bitfields as specified in the SD Host Controller Simplified
//! Specification.

// ============================================================================
// Register Offsets
// ============================================================================

/// SDMA System Address / Argument 2
pub const SDHCI_DMA_ADDRESS: u16 = 0x00;

/// Block Size Register
pub const SDHCI_BLOCK_SIZE: u16 = 0x04;

/// Block Count Register
pub const SDHCI_BLOCK_COUNT: u16 = 0x06;

/// Argument Register
pub const SDHCI_ARGUMENT: u16 = 0x08;

/// Transfer Mode Register
pub const SDHCI_TRANSFER_MODE: u16 = 0x0C;

/// Command Register
pub const SDHCI_COMMAND: u16 = 0x0E;

/// Response Register (4 DWORDs: 0x10, 0x14, 0x18, 0x1C)
pub const SDHCI_RESPONSE: u16 = 0x10;

/// Buffer Data Port Register
pub const SDHCI_BUFFER: u16 = 0x20;

/// Present State Register
pub const SDHCI_PRESENT_STATE: u16 = 0x24;

/// Host Control Register
pub const SDHCI_HOST_CONTROL: u16 = 0x28;

/// Power Control Register
pub const SDHCI_POWER_CONTROL: u16 = 0x29;

/// Block Gap Control Register
pub const SDHCI_BLOCK_GAP_CONTROL: u16 = 0x2A;

/// Wakeup Control Register
pub const SDHCI_WAKEUP_CONTROL: u16 = 0x2B;

/// Clock Control Register
pub const SDHCI_CLOCK_CONTROL: u16 = 0x2C;

/// Timeout Control Register
pub const SDHCI_TIMEOUT_CONTROL: u16 = 0x2E;

/// Software Reset Register
pub const SDHCI_SOFTWARE_RESET: u16 = 0x2F;

/// Normal Interrupt Status Register
pub const SDHCI_INT_STATUS: u16 = 0x30;

/// Normal Interrupt Status Enable Register
pub const SDHCI_INT_ENABLE: u16 = 0x34;

/// Normal Interrupt Signal Enable Register
pub const SDHCI_SIGNAL_ENABLE: u16 = 0x38;

/// Auto CMD Error Status Register
pub const SDHCI_ACMD12_ERR: u16 = 0x3C;

/// Host Control 2 Register
pub const SDHCI_HOST_CONTROL2: u16 = 0x3E;

/// Capabilities Register
pub const SDHCI_CAPABILITIES: u16 = 0x40;

/// Capabilities Register 1 (upper 32 bits)
pub const SDHCI_CAPABILITIES_1: u16 = 0x44;

/// Maximum Current Capabilities Register
pub const SDHCI_MAX_CURRENT: u16 = 0x48;

/// Force Event Register for Auto CMD Error Status
pub const SDHCI_SET_ACMD12_ERROR: u16 = 0x50;

/// Force Event Register for Error Interrupt Status
pub const SDHCI_SET_INT_ERROR: u16 = 0x52;

/// ADMA Error Status Register
pub const SDHCI_ADMA_ERROR: u16 = 0x54;

/// ADMA System Address Register
pub const SDHCI_ADMA_ADDRESS: u16 = 0x58;

/// ADMA System Address Register (upper 32 bits)
pub const SDHCI_ADMA_ADDRESS_HI: u16 = 0x5C;

/// Slot Interrupt Status Register
pub const SDHCI_SLOT_INT_STATUS: u16 = 0xFC;

/// Host Controller Version Register
pub const SDHCI_HOST_VERSION: u16 = 0xFE;

// ============================================================================
// Block Size Register (0x04) Bitfields
// ============================================================================

/// Create block size value with SDMA buffer boundary
/// boundary: 0=4K, 1=8K, 2=16K, 3=32K, 4=64K, 5=128K, 6=256K, 7=512K
#[inline]
pub const fn make_blksz(boundary: u16, blksz: u16) -> u16 {
    ((boundary & 0x7) << 12) | (blksz & 0xFFF)
}

// ============================================================================
// Transfer Mode Register (0x0C) Bitfields
// ============================================================================

/// DMA Enable
pub const SDHCI_TRNS_DMA: u16 = 1 << 0;

/// Block Count Enable
pub const SDHCI_TRNS_BLK_CNT_EN: u16 = 1 << 1;

/// Auto CMD12 Enable
pub const SDHCI_TRNS_ACMD12: u16 = 1 << 2;

/// Auto CMD23 Enable
pub const SDHCI_TRNS_ACMD23: u16 = 1 << 3;

/// Data Transfer Direction Read (1 = read, 0 = write)
pub const SDHCI_TRNS_READ: u16 = 1 << 4;

/// Multi Block Select
pub const SDHCI_TRNS_MULTI: u16 = 1 << 5;

// ============================================================================
// Command Register (0x0E) Bitfields
// ============================================================================

/// Response type mask
pub const SDHCI_CMD_RESP_MASK: u16 = 0x03;

/// No response
pub const SDHCI_CMD_RESP_NONE: u16 = 0x00;

/// Response length 136 bits
pub const SDHCI_CMD_RESP_LONG: u16 = 0x01;

/// Response length 48 bits
pub const SDHCI_CMD_RESP_SHORT: u16 = 0x02;

/// Response length 48 bits with busy
pub const SDHCI_CMD_RESP_SHORT_BUSY: u16 = 0x03;

/// Command CRC check enable
pub const SDHCI_CMD_CRC: u16 = 1 << 3;

/// Command index check enable
pub const SDHCI_CMD_INDEX: u16 = 1 << 4;

/// Data present select
pub const SDHCI_CMD_DATA: u16 = 1 << 5;

/// Command type - Abort
pub const SDHCI_CMD_ABORTCMD: u16 = 0xC0;

/// Create command register value
#[inline]
pub const fn make_cmd(cmd_idx: u8, flags: u16) -> u16 {
    ((cmd_idx as u16) << 8) | (flags & 0xFF)
}

/// Extract command index from command register value
#[inline]
pub const fn get_cmd(cmd_val: u16) -> u8 {
    ((cmd_val >> 8) & 0x3F) as u8
}

// ============================================================================
// Present State Register (0x24) Bitfields
// ============================================================================

/// Command Inhibit (CMD)
pub const SDHCI_CMD_INHIBIT: u32 = 1 << 0;

/// Command Inhibit (DAT)
pub const SDHCI_DATA_INHIBIT: u32 = 1 << 1;

/// DAT Line Active
pub const SDHCI_DAT_ACTIVE: u32 = 1 << 2;

/// Re-Tuning Request
pub const SDHCI_RETUNE_REQUEST: u32 = 1 << 3;

/// Write Transfer Active
pub const SDHCI_DOING_WRITE: u32 = 1 << 8;

/// Read Transfer Active
pub const SDHCI_DOING_READ: u32 = 1 << 9;

/// Buffer Write Enable
pub const SDHCI_SPACE_AVAILABLE: u32 = 1 << 10;

/// Buffer Read Enable
pub const SDHCI_DATA_AVAILABLE: u32 = 1 << 11;

/// Card Inserted
pub const SDHCI_CARD_PRESENT: u32 = 1 << 16;

/// Card State Stable
pub const SDHCI_CARD_STATE_STABLE: u32 = 1 << 17;

/// Card Detect Pin Level
pub const SDHCI_CARD_DETECT_PIN_LEVEL: u32 = 1 << 18;

/// Write Protect Switch Pin Level
pub const SDHCI_WRITE_PROTECT: u32 = 1 << 19;

/// DAT[3:0] Line Signal Level mask
pub const SDHCI_DATA_LVL_MASK: u32 = 0x00F0_0000;

/// DAT[0] Line Signal Level
pub const SDHCI_DATA_0_LVL_MASK: u32 = 1 << 20;

// ============================================================================
// Host Control Register (0x28) Bitfields
// ============================================================================

/// LED Control
pub const SDHCI_CTRL_LED: u8 = 1 << 0;

/// Data Transfer Width (1 = 4-bit mode)
pub const SDHCI_CTRL_4BITBUS: u8 = 1 << 1;

/// High Speed Enable
pub const SDHCI_CTRL_HISPD: u8 = 1 << 2;

/// DMA Select mask
pub const SDHCI_CTRL_DMA_MASK: u8 = 0x18;

/// SDMA select
pub const SDHCI_CTRL_SDMA: u8 = 0x00;

/// 32-bit Address ADMA1
pub const SDHCI_CTRL_ADMA1: u8 = 0x08;

/// 32-bit Address ADMA2
pub const SDHCI_CTRL_ADMA32: u8 = 0x10;

/// 64-bit Address ADMA2
pub const SDHCI_CTRL_ADMA64: u8 = 0x18;

/// Extended Data Transfer Width (1 = 8-bit mode)
pub const SDHCI_CTRL_8BITBUS: u8 = 1 << 5;

/// Card Detect Test Level
pub const SDHCI_CTRL_CD_TEST_INS: u8 = 1 << 6;

/// Card Detect Signal Selection
pub const SDHCI_CTRL_CD_TEST: u8 = 1 << 7;

// ============================================================================
// Power Control Register (0x29) Bitfields
// ============================================================================

/// SD Bus Power
pub const SDHCI_POWER_ON: u8 = 1 << 0;

/// SD Bus Voltage Select - 1.8V
pub const SDHCI_POWER_180: u8 = 0x0A;

/// SD Bus Voltage Select - 3.0V
pub const SDHCI_POWER_300: u8 = 0x0C;

/// SD Bus Voltage Select - 3.3V
pub const SDHCI_POWER_330: u8 = 0x0E;

// ============================================================================
// Clock Control Register (0x2C) Bitfields
// ============================================================================

/// Internal Clock Enable
pub const SDHCI_CLOCK_INT_EN: u16 = 1 << 0;

/// Internal Clock Stable
pub const SDHCI_CLOCK_INT_STABLE: u16 = 1 << 1;

/// SD Clock Enable
pub const SDHCI_CLOCK_CARD_EN: u16 = 1 << 2;

/// PLL Enable (SDHCI 3.0+)
pub const SDHCI_PROG_CLOCK_MODE: u16 = 1 << 5;

/// SDCLK Frequency Select (bits 15:8)
pub const SDHCI_DIVIDER_SHIFT: u16 = 8;

/// Upper bits of SDCLK Frequency Select (bits 7:6)
pub const SDHCI_DIVIDER_HI_SHIFT: u16 = 6;

/// Divider mask (8-bit)
pub const SDHCI_DIV_MASK: u16 = 0xFF;

/// Divider mask length
pub const SDHCI_DIV_MASK_LEN: u16 = 8;

/// Upper divider mask
pub const SDHCI_DIV_HI_MASK: u16 = 0x300;

// ============================================================================
// Software Reset Register (0x2F) Bitfields
// ============================================================================

/// Software Reset For All
pub const SDHCI_RESET_ALL: u8 = 1 << 0;

/// Software Reset For CMD Line
pub const SDHCI_RESET_CMD: u8 = 1 << 1;

/// Software Reset For DAT Line
pub const SDHCI_RESET_DATA: u8 = 1 << 2;

// ============================================================================
// Interrupt Status/Enable Registers (0x30, 0x34, 0x38) Bitfields
// ============================================================================

/// Command Complete
pub const SDHCI_INT_RESPONSE: u32 = 1 << 0;

/// Transfer Complete
pub const SDHCI_INT_DATA_END: u32 = 1 << 1;

/// Block Gap Event
pub const SDHCI_INT_BLK_GAP: u32 = 1 << 2;

/// DMA Interrupt
pub const SDHCI_INT_DMA_END: u32 = 1 << 3;

/// Buffer Write Ready
pub const SDHCI_INT_SPACE_AVAIL: u32 = 1 << 4;

/// Buffer Read Ready
pub const SDHCI_INT_DATA_AVAIL: u32 = 1 << 5;

/// Card Insertion
pub const SDHCI_INT_CARD_INSERT: u32 = 1 << 6;

/// Card Removal
pub const SDHCI_INT_CARD_REMOVE: u32 = 1 << 7;

/// Card Interrupt
pub const SDHCI_INT_CARD_INT: u32 = 1 << 8;

/// Error Interrupt
pub const SDHCI_INT_ERROR: u32 = 1 << 15;

/// Command Timeout Error
pub const SDHCI_INT_TIMEOUT: u32 = 1 << 16;

/// Command CRC Error
pub const SDHCI_INT_CRC: u32 = 1 << 17;

/// Command End Bit Error
pub const SDHCI_INT_END_BIT: u32 = 1 << 18;

/// Command Index Error
pub const SDHCI_INT_INDEX: u32 = 1 << 19;

/// Data Timeout Error
pub const SDHCI_INT_DATA_TIMEOUT: u32 = 1 << 20;

/// Data CRC Error
pub const SDHCI_INT_DATA_CRC: u32 = 1 << 21;

/// Data End Bit Error
pub const SDHCI_INT_DATA_END_BIT: u32 = 1 << 22;

/// Current Limit Error
pub const SDHCI_INT_BUS_POWER: u32 = 1 << 23;

/// Auto CMD Error
pub const SDHCI_INT_ACMD12ERR: u32 = 1 << 24;

/// ADMA Error
pub const SDHCI_INT_ADMA_ERROR: u32 = 1 << 25;

/// Normal interrupt mask
pub const SDHCI_INT_NORMAL_MASK: u32 = 0x0000_7FFF;

/// Error interrupt mask
pub const SDHCI_INT_ERROR_MASK: u32 = 0xFFFF_8000;

/// All interrupts mask
pub const SDHCI_INT_ALL_MASK: u32 = 0xFFFF_FFFF;

/// Command-related interrupt mask
pub const SDHCI_INT_CMD_MASK: u32 =
    SDHCI_INT_RESPONSE | SDHCI_INT_TIMEOUT | SDHCI_INT_CRC | SDHCI_INT_END_BIT | SDHCI_INT_INDEX;

/// Data-related interrupt mask
pub const SDHCI_INT_DATA_MASK: u32 = SDHCI_INT_DATA_END
    | SDHCI_INT_DMA_END
    | SDHCI_INT_SPACE_AVAIL
    | SDHCI_INT_DATA_AVAIL
    | SDHCI_INT_DATA_TIMEOUT
    | SDHCI_INT_DATA_CRC
    | SDHCI_INT_DATA_END_BIT
    | SDHCI_INT_ADMA_ERROR;

// ============================================================================
// Host Control 2 Register (0x3E) Bitfields
// ============================================================================

/// UHS Mode Select mask
pub const SDHCI_CTRL_UHS_MASK: u16 = 0x0007;

/// SDR12 mode
pub const SDHCI_CTRL_UHS_SDR12: u16 = 0x0000;

/// SDR25 mode
pub const SDHCI_CTRL_UHS_SDR25: u16 = 0x0001;

/// SDR50 mode
pub const SDHCI_CTRL_UHS_SDR50: u16 = 0x0002;

/// SDR104 mode
pub const SDHCI_CTRL_UHS_SDR104: u16 = 0x0003;

/// DDR50 mode
pub const SDHCI_CTRL_UHS_DDR50: u16 = 0x0004;

/// HS400 mode (non-standard)
pub const SDHCI_CTRL_HS400: u16 = 0x0005;

/// 1.8V Signaling Enable
pub const SDHCI_CTRL_VDD_180: u16 = 1 << 3;

/// Driver Strength Select mask
pub const SDHCI_CTRL_DRV_TYPE_MASK: u16 = 0x0030;

/// Driver Type B
pub const SDHCI_CTRL_DRV_TYPE_B: u16 = 0x0000;

/// Driver Type A
pub const SDHCI_CTRL_DRV_TYPE_A: u16 = 0x0010;

/// Driver Type C
pub const SDHCI_CTRL_DRV_TYPE_C: u16 = 0x0020;

/// Driver Type D
pub const SDHCI_CTRL_DRV_TYPE_D: u16 = 0x0030;

/// Execute Tuning
pub const SDHCI_CTRL_EXEC_TUNING: u16 = 1 << 6;

/// Sampling Clock Select
pub const SDHCI_CTRL_TUNED_CLK: u16 = 1 << 7;

/// Preset Value Enable
pub const SDHCI_CTRL_PRESET_VAL_ENABLE: u16 = 1 << 15;

// ============================================================================
// Capabilities Register (0x40) Bitfields
// ============================================================================

/// Timeout Clock Frequency mask
pub const SDHCI_TIMEOUT_CLK_MASK: u32 = 0x0000_003F;

/// Timeout Clock Frequency shift
pub const SDHCI_TIMEOUT_CLK_SHIFT: u32 = 0;

/// Timeout Clock Unit (0=KHz, 1=MHz)
pub const SDHCI_TIMEOUT_CLK_UNIT: u32 = 1 << 7;

/// Base Clock Frequency For SD Clock mask (SDHCI 1.0/2.0)
pub const SDHCI_CLOCK_BASE_MASK: u32 = 0x0000_3F00;

/// Base Clock Frequency For SD Clock mask (SDHCI 3.0)
pub const SDHCI_CLOCK_V3_BASE_MASK: u32 = 0x0000_FF00;

/// Base Clock Frequency shift
pub const SDHCI_CLOCK_BASE_SHIFT: u32 = 8;

/// Max Block Length mask
pub const SDHCI_MAX_BLOCK_MASK: u32 = 0x0003_0000;

/// Max Block Length shift
pub const SDHCI_MAX_BLOCK_SHIFT: u32 = 16;

/// 8-bit Support For Embedded Device
pub const SDHCI_CAN_DO_8BIT: u32 = 1 << 18;

/// ADMA2 Support
pub const SDHCI_CAN_DO_ADMA2: u32 = 1 << 19;

/// ADMA1 Support
pub const SDHCI_CAN_DO_ADMA1: u32 = 1 << 20;

/// High Speed Support
pub const SDHCI_CAN_DO_HISPD: u32 = 1 << 21;

/// SDMA Support
pub const SDHCI_CAN_DO_SDMA: u32 = 1 << 22;

/// Suspend/Resume Support
pub const SDHCI_CAN_DO_SUSPEND: u32 = 1 << 23;

/// Voltage Support 3.3V
pub const SDHCI_CAN_VDD_330: u32 = 1 << 24;

/// Voltage Support 3.0V
pub const SDHCI_CAN_VDD_300: u32 = 1 << 25;

/// Voltage Support 1.8V
pub const SDHCI_CAN_VDD_180: u32 = 1 << 26;

/// 64-bit System Bus Support
pub const SDHCI_CAN_64BIT: u32 = 1 << 28;

// ============================================================================
// Capabilities Register 1 (0x44) Bitfields
// ============================================================================

/// SDR50 Support
pub const SDHCI_SUPPORT_SDR50: u32 = 1 << 0;

/// SDR104 Support
pub const SDHCI_SUPPORT_SDR104: u32 = 1 << 1;

/// DDR50 Support
pub const SDHCI_SUPPORT_DDR50: u32 = 1 << 2;

/// HS400 Support
pub const SDHCI_SUPPORT_HS400: u32 = 1 << 31;

/// Use Tuning for SDR50
pub const SDHCI_USE_SDR50_TUNING: u32 = 1 << 13;

/// Clock Multiplier mask
pub const SDHCI_CLOCK_MUL_MASK: u32 = 0x00FF_0000;

/// Clock Multiplier shift
pub const SDHCI_CLOCK_MUL_SHIFT: u32 = 16;

// ============================================================================
// Host Controller Version Register (0xFE) Bitfields
// ============================================================================

/// Vendor Version Number mask
pub const SDHCI_VENDOR_VER_MASK: u16 = 0xFF00;

/// Vendor Version Number shift
pub const SDHCI_VENDOR_VER_SHIFT: u16 = 8;

/// Specification Version Number mask
pub const SDHCI_SPEC_VER_MASK: u16 = 0x00FF;

/// Specification Version Number shift
pub const SDHCI_SPEC_VER_SHIFT: u16 = 0;

/// SDHCI Specification Version 1.00
pub const SDHCI_SPEC_100: u8 = 0;

/// SDHCI Specification Version 2.00
pub const SDHCI_SPEC_200: u8 = 1;

/// SDHCI Specification Version 3.00
pub const SDHCI_SPEC_300: u8 = 2;

/// SDHCI Specification Version 4.00
pub const SDHCI_SPEC_400: u8 = 3;

/// SDHCI Specification Version 4.10
pub const SDHCI_SPEC_410: u8 = 4;

/// SDHCI Specification Version 4.20
pub const SDHCI_SPEC_420: u8 = 5;

// ============================================================================
// Maximum Dividers
// ============================================================================

/// Maximum divider for SDHCI 2.0 (8-bit, powers of 2)
pub const SDHCI_MAX_DIV_SPEC_200: u32 = 256;

/// Maximum divider for SDHCI 3.0+ (10-bit)
pub const SDHCI_MAX_DIV_SPEC_300: u32 = 2046;

// ============================================================================
// Default SDMA Buffer Boundary
// ============================================================================

/// Default SDMA buffer boundary (512KB)
pub const SDHCI_DEFAULT_BOUNDARY_SIZE: u32 = 512 * 1024;

/// Default SDMA buffer boundary argument (7 = 512KB)
pub const SDHCI_DEFAULT_BOUNDARY_ARG: u16 = 7;

// ============================================================================
// SD/MMC Commands
// ============================================================================

/// GO_IDLE_STATE - Resets all cards to idle state
pub const MMC_CMD_GO_IDLE_STATE: u8 = 0;

/// SEND_OP_COND - Sends host capacity support info and activates card init
pub const MMC_CMD_SEND_OP_COND: u8 = 1;

/// ALL_SEND_CID - Asks all cards to send their CID
pub const MMC_CMD_ALL_SEND_CID: u8 = 2;

/// SET_RELATIVE_ADDR (MMC) / SEND_RELATIVE_ADDR (SD)
pub const MMC_CMD_SET_RELATIVE_ADDR: u8 = 3;

/// SET_DSR - Programs the DSR of all cards
pub const MMC_CMD_SET_DSR: u8 = 4;

/// SWITCH - Switches card function
pub const MMC_CMD_SWITCH: u8 = 6;

/// SELECT/DESELECT_CARD - Toggles card between stand-by and transfer states
pub const MMC_CMD_SELECT_CARD: u8 = 7;

/// SEND_IF_COND (SD) / SEND_EXT_CSD (MMC)
pub const MMC_CMD_SEND_EXT_CSD: u8 = 8;

/// SEND_CSD - Asks card to send its CSD
pub const MMC_CMD_SEND_CSD: u8 = 9;

/// SEND_CID - Asks card to send its CID
pub const MMC_CMD_SEND_CID: u8 = 10;

/// STOP_TRANSMISSION - Forces card to stop transmission
pub const MMC_CMD_STOP_TRANSMISSION: u8 = 12;

/// SEND_STATUS - Asks card to send its status
pub const MMC_CMD_SEND_STATUS: u8 = 13;

/// SET_BLOCKLEN - Sets block length for block commands
pub const MMC_CMD_SET_BLOCKLEN: u8 = 16;

/// READ_SINGLE_BLOCK - Reads a single block
pub const MMC_CMD_READ_SINGLE_BLOCK: u8 = 17;

/// READ_MULTIPLE_BLOCK - Continuously reads blocks until STOP_TRANSMISSION
pub const MMC_CMD_READ_MULTIPLE_BLOCK: u8 = 18;

/// SEND_TUNING_BLOCK - Sends tuning block (SD)
pub const MMC_CMD_SEND_TUNING_BLOCK: u8 = 19;

/// SEND_TUNING_BLOCK_HS200 - Sends tuning block for HS200 (MMC)
pub const MMC_CMD_SEND_TUNING_BLOCK_HS200: u8 = 21;

/// SET_BLOCK_COUNT - Sets block count for next multi-block command
pub const MMC_CMD_SET_BLOCK_COUNT: u8 = 23;

/// WRITE_SINGLE_BLOCK - Writes a single block
pub const MMC_CMD_WRITE_SINGLE_BLOCK: u8 = 24;

/// WRITE_MULTIPLE_BLOCK - Continuously writes blocks until STOP_TRANSMISSION
pub const MMC_CMD_WRITE_MULTIPLE_BLOCK: u8 = 25;

/// ERASE_GROUP_START - Sets the first erase group
pub const MMC_CMD_ERASE_GROUP_START: u8 = 35;

/// ERASE_GROUP_END - Sets the last erase group
pub const MMC_CMD_ERASE_GROUP_END: u8 = 36;

/// ERASE - Erases all previously selected groups
pub const MMC_CMD_ERASE: u8 = 38;

/// APP_CMD - Indicates next command is application specific
pub const MMC_CMD_APP_CMD: u8 = 55;

/// GEN_CMD - General purpose command
pub const MMC_CMD_GEN_CMD: u8 = 56;

// SD-specific commands (application commands after CMD55)

/// SEND_RELATIVE_ADDR (SD) - Ask card to publish new RCA
pub const SD_CMD_SEND_RELATIVE_ADDR: u8 = 3;

/// SWITCH_FUNC - Check/switch card function
pub const SD_CMD_SWITCH_FUNC: u8 = 6;

/// SEND_IF_COND - Sends SD interface condition
pub const SD_CMD_SEND_IF_COND: u8 = 8;

/// VOLTAGE_SWITCH - Switch to 1.8V signaling
pub const SD_CMD_SWITCH_UHS18V: u8 = 11;

/// SET_BUS_WIDTH (ACMD6) - Sets bus width
pub const SD_CMD_APP_SET_BUS_WIDTH: u8 = 6;

/// SD_STATUS (ACMD13) - Sends SD status
pub const SD_CMD_APP_SD_STATUS: u8 = 13;

/// SEND_NUM_WR_BLOCKS (ACMD22) - Sends number of written blocks
pub const SD_CMD_APP_SEND_NUM_WR_BLKS: u8 = 22;

/// SET_WR_BLK_ERASE_COUNT (ACMD23) - Sets number of blocks to erase
pub const SD_CMD_APP_SET_WR_BLK_ERASE_COUNT: u8 = 23;

/// SD_SEND_OP_COND (ACMD41) - Sends host capacity support info
pub const SD_CMD_APP_SEND_OP_COND: u8 = 41;

/// SET_CLR_CARD_DETECT (ACMD42) - Connect/disconnect pull-up resistor
pub const SD_CMD_APP_SET_CLR_CARD_DETECT: u8 = 42;

/// SEND_SCR (ACMD51) - Reads SD Configuration Register
pub const SD_CMD_APP_SEND_SCR: u8 = 51;

// ============================================================================
// OCR (Operation Conditions Register) Bitfields
// ============================================================================

/// Card is busy (bit 31 = 0 means busy)
pub const OCR_BUSY: u32 = 1 << 31;

/// Card Capacity Status (HCS) - set for SDHC/SDXC
pub const OCR_HCS: u32 = 1 << 30;

/// Switching to 1.8V accepted
pub const OCR_S18R: u32 = 1 << 24;

/// Voltage window mask
pub const OCR_VOLTAGE_MASK: u32 = 0x007F_FF80;

/// 2.7-2.8V
pub const OCR_VDD_27_28: u32 = 1 << 15;

/// 2.8-2.9V
pub const OCR_VDD_28_29: u32 = 1 << 16;

/// 2.9-3.0V
pub const OCR_VDD_29_30: u32 = 1 << 17;

/// 3.0-3.1V
pub const OCR_VDD_30_31: u32 = 1 << 18;

/// 3.1-3.2V
pub const OCR_VDD_31_32: u32 = 1 << 19;

/// 3.2-3.3V
pub const OCR_VDD_32_33: u32 = 1 << 20;

/// 3.3-3.4V
pub const OCR_VDD_33_34: u32 = 1 << 21;

/// Standard voltage range (2.7V - 3.6V)
pub const OCR_VDD_RANGE: u32 = OCR_VDD_27_28
    | OCR_VDD_28_29
    | OCR_VDD_29_30
    | OCR_VDD_30_31
    | OCR_VDD_31_32
    | OCR_VDD_32_33
    | OCR_VDD_33_34;

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

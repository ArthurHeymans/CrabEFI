//! SFDP (Serial Flash Discoverable Parameters) parsing
//!
//! This module implements parsing of SFDP data structures as defined by
//! JEDEC JESD216. SFDP provides a standardized way for flash chips to
//! describe their capabilities.
//!
//! # Overview
//!
//! SFDP data is stored in a reserved area of the flash chip and can be
//! read using the RDSFDP command (0x5A). The structure contains:
//!
//! - An SFDP header with signature and revision info
//! - One or more parameter headers describing available tables
//! - Parameter tables containing capability information
//!
//! We primarily care about the Basic Flash Parameter Table (BFPT) which
//! contains flash size, page size, and erase type information.

use super::regs::JEDEC_RDSFDP;

/// SFDP signature magic value ("SFDP" in little-endian)
pub const SFDP_SIGNATURE: u32 = 0x50444653;

/// Basic Flash Parameter Table ID
pub const PARAM_ID_BASIC: u16 = 0xFF00;

// ============================================================================
// SFDP Types
// ============================================================================

/// Erase type from SFDP (up to 4 types supported)
#[derive(Debug, Clone, Copy, Default)]
pub struct SfdpEraseType {
    /// Erase opcode
    pub opcode: u8,
    /// Erase size in bytes (0 if not supported)
    pub size: u32,
}

impl SfdpEraseType {
    /// Check if this erase type is valid/supported
    pub fn is_valid(&self) -> bool {
        self.size > 0 && self.opcode != 0xFF && self.opcode != 0x00
    }

    /// Parse from size exponent (N where size = 2^N) and opcode
    pub fn from_raw(size_exp: u8, opcode: u8) -> Self {
        if size_exp == 0 || opcode == 0xFF || opcode == 0x00 {
            Self::default()
        } else {
            Self {
                opcode,
                size: 1u32 << size_exp,
            }
        }
    }
}

/// Flash addressing mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressMode {
    /// 3-byte addressing only (up to 16 MiB)
    #[default]
    ThreeByteOnly,
    /// 3-byte default, can switch to 4-byte
    ThreeOrFourByte,
    /// 4-byte addressing only (required for > 16 MiB)
    FourByteOnly,
}

impl AddressMode {
    /// Parse from BFPT DWORD 1 bits [18:17]
    pub fn from_bfpt(value: u8) -> Self {
        match value & 0x03 {
            0b00 => Self::ThreeByteOnly,
            0b01 => Self::ThreeOrFourByte,
            0b10 => Self::FourByteOnly,
            _ => Self::ThreeByteOnly,
        }
    }

    /// Check if 4-byte addressing is required
    pub fn requires_4byte(&self) -> bool {
        matches!(self, Self::FourByteOnly)
    }
}

/// Parsed SFDP information
#[derive(Debug, Clone, Default)]
pub struct SfdpInfo {
    /// Flash density in bytes
    pub density_bytes: u32,
    /// Page size in bytes (for programming)
    pub page_size: u32,
    /// Address mode support
    pub address_mode: AddressMode,
    /// Erase types (up to 4)
    pub erase_types: [SfdpEraseType; 4],
}

impl SfdpInfo {
    /// Get the smallest supported erase size
    pub fn min_erase_size(&self) -> Option<u32> {
        self.erase_types
            .iter()
            .filter(|e| e.is_valid())
            .map(|e| e.size)
            .min()
    }

    /// Check if 4-byte addressing is required based on density
    pub fn requires_4byte_addr(&self) -> bool {
        self.density_bytes > 16 * 1024 * 1024 || self.address_mode.requires_4byte()
    }

    /// Get the erase opcode for a given size, if supported
    pub fn erase_opcode_for_size(&self, size: u32) -> Option<u8> {
        self.erase_types
            .iter()
            .find(|e| e.is_valid() && e.size == size)
            .map(|e| e.opcode)
    }
}

// ============================================================================
// SFDP Parsing
// ============================================================================

/// SFDP header structure (first 8 bytes at address 0x00)
#[derive(Debug, Clone, Copy, Default)]
struct SfdpHeader {
    /// SFDP signature (should be 0x50444653)
    signature: u32,
    /// Minor revision
    minor: u8,
    /// Major revision
    major: u8,
    /// Number of parameter headers (0-based, so actual count is nph + 1)
    nph: u8,
}

impl SfdpHeader {
    fn parse(data: &[u8; 8]) -> Self {
        Self {
            signature: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            minor: data[4],
            major: data[5],
            nph: data[6],
        }
    }

    fn is_valid(&self) -> bool {
        self.signature == SFDP_SIGNATURE && self.major == 1
    }

    fn num_param_headers(&self) -> usize {
        (self.nph as usize) + 1
    }
}

/// Parameter header structure (8 bytes each, starting at address 0x08)
#[derive(Debug, Clone, Copy, Default)]
struct ParameterHeader {
    /// Parameter ID (MSB << 8 | LSB)
    id: u16,
    /// Parameter table length in DWORDs
    length_dwords: u8,
    /// Parameter table pointer (24-bit byte address)
    table_pointer: u32,
}

impl ParameterHeader {
    fn parse(data: &[u8; 8]) -> Self {
        Self {
            id: ((data[7] as u16) << 8) | (data[0] as u16),
            length_dwords: data[3],
            table_pointer: u32::from_le_bytes([data[4], data[5], data[6], 0]),
        }
    }

    fn length_bytes(&self) -> usize {
        (self.length_dwords as usize) * 4
    }

    fn is_basic(&self) -> bool {
        self.id == PARAM_ID_BASIC
    }
}

/// Result type for SFDP operations
pub type SfdpResult<T> = Result<T, SfdpError>;

/// SFDP error types
#[derive(Debug, Clone, Copy)]
pub enum SfdpError {
    /// SFDP not supported (invalid signature)
    NotSupported,
    /// Communication error
    ReadError,
    /// Invalid SFDP data
    InvalidData,
}

/// Trait for sending SFDP read commands
pub trait SfdpReader {
    /// Read SFDP data at the given address
    ///
    /// The RDSFDP command (0x5A) uses:
    /// - 3-byte address
    /// - 8 dummy cycles before data
    fn read_sfdp(&mut self, addr: u32, buf: &mut [u8]) -> SfdpResult<()>;
}

/// Probe for SFDP support and parse parameters
///
/// Returns `Err(NotSupported)` if the chip doesn't support SFDP.
pub fn probe<R: SfdpReader>(reader: &mut R) -> SfdpResult<SfdpInfo> {
    // Read and parse the SFDP header
    let mut header_buf = [0u8; 8];
    reader.read_sfdp(0x00, &mut header_buf)?;

    let header = SfdpHeader::parse(&header_buf);
    if !header.is_valid() {
        log::debug!(
            "SFDP signature invalid: {:#010x} (expected {:#010x})",
            header.signature,
            SFDP_SIGNATURE
        );
        return Err(SfdpError::NotSupported);
    }

    log::debug!(
        "SFDP header valid: revision {}.{}, {} parameter headers",
        header.major,
        header.minor,
        header.num_param_headers()
    );

    // Find and parse the Basic Flash Parameter Table
    for i in 0..header.num_param_headers().min(8) {
        let mut param_buf = [0u8; 8];
        let addr = 0x08 + (i as u32 * 8);
        reader.read_sfdp(addr, &mut param_buf)?;

        let param_header = ParameterHeader::parse(&param_buf);

        if param_header.is_basic() {
            log::debug!(
                "Found BFPT at {:#x}, {} DWORDs",
                param_header.table_pointer,
                param_header.length_dwords
            );
            return parse_bfpt(reader, &param_header);
        }
    }

    log::debug!("No Basic Flash Parameter Table found");
    Err(SfdpError::InvalidData)
}

/// Parse the Basic Flash Parameter Table
fn parse_bfpt<R: SfdpReader>(reader: &mut R, header: &ParameterHeader) -> SfdpResult<SfdpInfo> {
    let len = header.length_bytes();
    if len < 36 {
        // Minimum is 9 DWORDs (JESD216)
        return Err(SfdpError::InvalidData);
    }

    // Read the parameter table (up to 64 bytes / 16 DWORDs)
    let mut buf = [0u8; 64];
    let read_len = len.min(buf.len());
    reader.read_sfdp(header.table_pointer, &mut buf[..read_len])?;

    let mut info = SfdpInfo::default();

    // Helper to read a DWORD from the buffer
    let get_dword = |offset: usize| -> u32 {
        if offset + 4 <= read_len {
            u32::from_le_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ])
        } else {
            0
        }
    };

    // Parse DWORD 1: Address mode, fast read support, etc.
    let dword1 = get_dword(0);
    info.address_mode = AddressMode::from_bfpt(((dword1 >> 17) & 0x03) as u8);

    // Parse DWORD 2: Flash density
    let dword2 = get_dword(4);
    if (dword2 & (1 << 31)) == 0 {
        // Direct bit count
        let bits = dword2 & 0x7FFFFFFF;
        info.density_bytes = ((bits as u64 + 1) / 8) as u32;
    } else {
        // 2^N format
        let n = dword2 & 0x7FFFFFFF;
        if (3..=31).contains(&n) {
            info.density_bytes = 1u32 << (n - 3);
        }
    }

    // Parse DWORDs 8-9: Erase types
    let dword8 = get_dword(28);
    let dword9 = get_dword(32);

    info.erase_types[0] =
        SfdpEraseType::from_raw((dword8 & 0xFF) as u8, ((dword8 >> 8) & 0xFF) as u8);
    info.erase_types[1] =
        SfdpEraseType::from_raw(((dword8 >> 16) & 0xFF) as u8, ((dword8 >> 24) & 0xFF) as u8);
    info.erase_types[2] =
        SfdpEraseType::from_raw((dword9 & 0xFF) as u8, ((dword9 >> 8) & 0xFF) as u8);
    info.erase_types[3] =
        SfdpEraseType::from_raw(((dword9 >> 16) & 0xFF) as u8, ((dword9 >> 24) & 0xFF) as u8);

    // Parse DWORD 11: Page size (if available, requires 11+ DWORDs)
    if read_len >= 44 {
        let dword11 = get_dword(40);
        let page_size_exp = ((dword11 >> 4) & 0x0F) as u8;
        if page_size_exp > 0 {
            info.page_size = 1u32 << page_size_exp;
        } else {
            info.page_size = 256; // Default
        }
    } else {
        info.page_size = 256; // Default for older SFDP
    }

    // Validate
    if info.density_bytes == 0 {
        return Err(SfdpError::InvalidData);
    }

    log::info!(
        "SFDP: {} MB flash, {} byte pages",
        info.density_bytes / (1024 * 1024),
        info.page_size
    );

    // Log erase types
    for (i, et) in info.erase_types.iter().enumerate() {
        if et.is_valid() {
            log::debug!(
                "SFDP erase type {}: {} KB (opcode {:#04x})",
                i + 1,
                et.size / 1024,
                et.opcode
            );
        }
    }

    Ok(info)
}

/// Build RDSFDP command bytes
///
/// Format: [opcode, addr[23:16], addr[15:8], addr[7:0], dummy]
pub fn build_rdsfdp_command(addr: u32) -> [u8; 5] {
    [
        JEDEC_RDSFDP,
        (addr >> 16) as u8,
        (addr >> 8) as u8,
        addr as u8,
        0x00, // Dummy byte (8 cycles)
    ]
}

//! UEFI Authentication Data Structures
//!
//! This module defines the data structures used for UEFI authenticated variables
//! as specified in the UEFI Specification Chapter 8.
//!
//! Note: We use raw byte arrays instead of r_efi::Guid because Guid has alignment
//! requirements that conflict with packed structures.

use zerocopy::{FromBytes, Immutable, KnownLayout, Unaligned};

// ============================================================================
// EFI_TIME Structure
// ============================================================================

/// EFI_TIME structure for timestamps
///
/// Used in EFI_VARIABLE_AUTHENTICATION_2 to record when a variable was last updated.
/// The OS/firmware should reject updates with timestamps <= the stored timestamp.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct EfiTime {
    /// Year (1900 - 9999)
    pub year: u16,
    /// Month (1 - 12)
    pub month: u8,
    /// Day (1 - 31)
    pub day: u8,
    /// Hour (0 - 23)
    pub hour: u8,
    /// Minute (0 - 59)
    pub minute: u8,
    /// Second (0 - 59)
    pub second: u8,
    /// Padding
    pub pad1: u8,
    /// Nanoseconds (0 - 999,999,999)
    pub nanosecond: u32,
    /// Timezone (-1440 to 1440, or 2047 for unspecified)
    pub timezone: i16,
    /// Daylight savings flags
    pub daylight: u8,
    /// Padding
    pub pad2: u8,
}

impl EfiTime {
    /// Create a zero-initialized EFI_TIME
    pub const fn zero() -> Self {
        Self {
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0,
            pad1: 0,
            nanosecond: 0,
            timezone: 0,
            daylight: 0,
            pad2: 0,
        }
    }

    /// Compare two timestamps
    ///
    /// Returns:
    /// - `Ordering::Less` if self < other
    /// - `Ordering::Equal` if self == other
    /// - `Ordering::Greater` if self > other
    pub fn compare(&self, other: &EfiTime) -> core::cmp::Ordering {
        use core::cmp::Ordering;

        // Copy values out of packed struct to avoid alignment issues
        let self_year = self.year;
        let other_year = other.year;
        let self_ns = self.nanosecond;
        let other_ns = other.nanosecond;

        // Compare year, month, day, hour, minute, second, nanosecond in order
        match self_year.cmp(&other_year) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.month.cmp(&other.month) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.day.cmp(&other.day) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.hour.cmp(&other.hour) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.minute.cmp(&other.minute) {
            Ordering::Equal => {}
            ord => return ord,
        }
        match self.second.cmp(&other.second) {
            Ordering::Equal => {}
            ord => return ord,
        }
        self_ns.cmp(&other_ns)
    }

    /// Check if this timestamp is strictly after another
    pub fn is_after(&self, other: &EfiTime) -> bool {
        matches!(self.compare(other), core::cmp::Ordering::Greater)
    }

    /// Convert from SerializedTime (from varstore)
    pub fn from_serialized(st: &crate::efi::varstore::SerializedTime) -> Self {
        Self {
            year: st.year,
            month: st.month,
            day: st.day,
            hour: st.hour,
            minute: st.minute,
            second: st.second,
            pad1: 0,
            nanosecond: st.nanosecond,
            timezone: st.timezone,
            daylight: st.daylight,
            pad2: 0,
        }
    }

    /// Convert to SerializedTime (for varstore)
    pub fn to_serialized(&self) -> crate::efi::varstore::SerializedTime {
        crate::efi::varstore::SerializedTime {
            year: self.year,
            month: self.month,
            day: self.day,
            hour: self.hour,
            minute: self.minute,
            second: self.second,
            nanosecond: self.nanosecond,
            timezone: self.timezone,
            daylight: self.daylight,
        }
    }
}

// ============================================================================
// WIN_CERTIFICATE Structure
// ============================================================================

/// WIN_CERTIFICATE base structure
///
/// This is the base certificate structure. The actual certificate data follows
/// this header. The certificate type determines the format of the data.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct WinCertificate {
    /// Total length of the certificate including header
    pub dw_length: u32,
    /// Certificate revision (should be WIN_CERT_REVISION = 0x0200)
    pub w_revision: u16,
    /// Certificate type
    pub w_certificate_type: u16,
    // Certificate data follows...
}

impl WinCertificate {
    /// Size of the WinCertificate header
    pub const HEADER_SIZE: usize = core::mem::size_of::<Self>();

    /// Get the size of the certificate data (excluding header)
    pub fn data_size(&self) -> usize {
        let len = self.dw_length;
        (len as usize).saturating_sub(Self::HEADER_SIZE)
    }
}

/// WIN_CERTIFICATE_UEFI_GUID structure
///
/// This certificate type includes a GUID to identify the certificate format.
/// For authenticated variables, this is typically EFI_CERT_TYPE_PKCS7_GUID.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct WinCertificateUefiGuid {
    /// Base certificate header
    pub hdr: WinCertificate,
    /// Certificate type GUID (e.g., EFI_CERT_TYPE_PKCS7_GUID) - stored as raw bytes
    pub cert_type: [u8; 16],
    // Certificate data follows...
}

impl WinCertificateUefiGuid {
    /// Size of the WinCertificateUefiGuid header
    pub const HEADER_SIZE: usize = core::mem::size_of::<Self>();

    /// Get the size of the certificate data (excluding headers)
    pub fn data_size(&self) -> usize {
        let len = self.hdr.dw_length;
        (len as usize).saturating_sub(Self::HEADER_SIZE)
    }

    /// Check if the certificate type matches a GUID
    pub fn cert_type_matches(&self, guid_bytes: &[u8; 16]) -> bool {
        self.cert_type == *guid_bytes
    }
}

// ============================================================================
// EFI_VARIABLE_AUTHENTICATION_2 Structure
// ============================================================================

/// EFI_VARIABLE_AUTHENTICATION_2 structure
///
/// This structure prefixes the data of all variables with the
/// `EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS` attribute.
///
/// The actual variable data follows the AuthInfo field.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct EfiVariableAuthentication2 {
    /// Time when the variable was created/modified
    pub time_stamp: EfiTime,
    /// WIN_CERTIFICATE_UEFI_GUID containing the PKCS#7 signature
    /// Note: This is followed by variable-length certificate data
    pub auth_info: WinCertificateUefiGuid,
}

impl EfiVariableAuthentication2 {
    /// Minimum size of EFI_VARIABLE_AUTHENTICATION_2 header (without cert data)
    pub const MIN_SIZE: usize = core::mem::size_of::<Self>();

    /// Get the total size of the authentication header including certificate data
    pub fn total_size(&self) -> usize {
        let cert_len = self.auth_info.hdr.dw_length;
        core::mem::size_of::<EfiTime>() + cert_len as usize
    }

    /// Parse from a byte buffer
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() < Self::MIN_SIZE {
            return None;
        }

        // Use zerocopy to safely interpret the bytes
        Self::ref_from_prefix(data).ok().map(|(auth, _)| auth)
    }

    /// Get the PKCS#7 certificate data
    pub fn get_cert_data<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let header_offset = core::mem::size_of::<EfiTime>() + WinCertificateUefiGuid::HEADER_SIZE;
        let cert_size = self.auth_info.data_size();

        if data.len() < header_offset + cert_size {
            return None;
        }

        Some(&data[header_offset..header_offset + cert_size])
    }

    /// Get the actual variable data (after the authentication header)
    pub fn get_variable_data<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let total = self.total_size();
        if data.len() < total {
            return None;
        }
        Some(&data[total..])
    }
}

// ============================================================================
// EFI_SIGNATURE_LIST Structure
// ============================================================================

/// EFI_SIGNATURE_LIST structure
///
/// A signature database (db, dbx, KEK) contains one or more signature lists.
/// Each list contains signatures of the same type and size.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct EfiSignatureList {
    /// GUID identifying the signature type - stored as raw bytes
    pub signature_type: [u8; 16],
    /// Total size of the signature list including this header
    pub signature_list_size: u32,
    /// Size of the optional signature header (typically 0)
    pub signature_header_size: u32,
    /// Size of each signature in this list
    pub signature_size: u32,
    // Signature header follows (signature_header_size bytes)
    // Signatures follow (each signature_size bytes)
}

impl EfiSignatureList {
    /// Size of the EfiSignatureList header
    pub const HEADER_SIZE: usize = core::mem::size_of::<Self>();

    /// Get the number of signatures in this list
    pub fn signature_count(&self) -> usize {
        let list_size = self.signature_list_size;
        let header_size = self.signature_header_size;
        let sig_size = self.signature_size;

        let data_size = (list_size as usize)
            .saturating_sub(Self::HEADER_SIZE)
            .saturating_sub(header_size as usize);

        if sig_size == 0 {
            0
        } else {
            data_size / sig_size as usize
        }
    }

    /// Get the offset to the first signature data (after header and signature header)
    pub fn first_signature_offset(&self) -> usize {
        let header_size = self.signature_header_size;
        Self::HEADER_SIZE + header_size as usize
    }

    /// Check if the signature type matches a GUID
    pub fn type_matches(&self, guid_bytes: &[u8; 16]) -> bool {
        self.signature_type == *guid_bytes
    }
}

/// EFI_SIGNATURE_DATA structure
///
/// Each signature in a signature list starts with a SignatureOwner GUID,
/// followed by the actual signature data.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct EfiSignatureData {
    /// GUID identifying the owner of this signature - stored as raw bytes
    pub signature_owner: [u8; 16],
    // Signature data follows...
}

impl EfiSignatureData {
    /// Size of the EfiSignatureData header
    pub const HEADER_SIZE: usize = core::mem::size_of::<Self>();
}

// ============================================================================
// Iterator for Signature Lists
// ============================================================================

/// Iterator over signature lists in a signature database
pub struct SignatureListIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> SignatureListIterator<'a> {
    /// Create a new iterator over signature lists
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl<'a> Iterator for SignatureListIterator<'a> {
    type Item = (&'a EfiSignatureList, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        let remaining = &self.data[self.offset..];
        if remaining.len() < EfiSignatureList::HEADER_SIZE {
            return None;
        }

        let list = EfiSignatureList::ref_from_prefix(remaining).ok()?.0;

        let list_size = list.signature_list_size as usize;
        if list_size < EfiSignatureList::HEADER_SIZE || self.offset + list_size > self.data.len() {
            return None;
        }

        let list_data = &remaining[..list_size];
        self.offset += list_size;

        Some((list, list_data))
    }
}

/// Iterator over signatures within a signature list
pub struct SignatureIterator<'a> {
    list: &'a EfiSignatureList,
    data: &'a [u8],
    index: usize,
}

impl<'a> SignatureIterator<'a> {
    /// Create a new iterator over signatures in a list
    pub fn new(list: &'a EfiSignatureList, data: &'a [u8]) -> Self {
        Self {
            list,
            data,
            index: 0,
        }
    }
}

impl<'a> Iterator for SignatureIterator<'a> {
    /// Returns (SignatureOwner GUID bytes, signature data)
    type Item = ([u8; 16], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let count = self.list.signature_count();
        if self.index >= count {
            return None;
        }

        let sig_size = self.list.signature_size as usize;
        let offset = self.list.first_signature_offset() + self.index * sig_size;

        if offset + sig_size > self.data.len() {
            return None;
        }

        let sig_data = &self.data[offset..offset + sig_size];

        // Parse the signature owner GUID
        let owner = EfiSignatureData::ref_from_prefix(sig_data).ok()?.0;

        // The actual signature data follows the owner GUID
        let sig_content = &sig_data[EfiSignatureData::HEADER_SIZE..];

        self.index += 1;
        Some((owner.signature_owner, sig_content))
    }
}

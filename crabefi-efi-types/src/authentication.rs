//! Packed UEFI authenticated-variable and signature-list structures.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Packed EFI timestamp used by time-based authenticated variables.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
pub struct EfiTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub pad1: u8,
    pub nanosecond: u32,
    pub timezone: i16,
    pub daylight: u8,
    pub pad2: u8,
}

impl EfiTime {
    /// Construct an all-zero timestamp.
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

    /// Return whether every field is within the EFI-defined range.
    pub fn is_valid(&self) -> bool {
        let year = self.year;
        let month = self.month;
        let timezone = self.timezone;
        (1900..=9999).contains(&year)
            && (1..=12).contains(&month)
            && (1..=Self::days_in_month(year, month)).contains(&self.day)
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 59
            && self.nanosecond <= 999_999_999
            && (timezone == 0x7ff || (-1440..=1440).contains(&timezone))
            && self.pad1 == 0
            && self.pad2 == 0
    }

    /// Return whether this timestamp has greater nanosecond-precision UTC units.
    pub fn is_after(&self, other: &Self) -> bool {
        self.to_utc_units() > other.to_utc_units()
    }

    const fn leap_year(year: u16) -> bool {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    }

    const fn days_in_month(year: u16, month: u8) -> u8 {
        match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if Self::leap_year(year) => 29,
            2 => 28,
            _ => 0,
        }
    }

    const fn days_before_month(year: u16, month: u8) -> u16 {
        let days = match month {
            1 => 0,
            2 => 31,
            3 => 59,
            4 => 90,
            5 => 120,
            6 => 151,
            7 => 181,
            8 => 212,
            9 => 243,
            10 => 273,
            11 => 304,
            12 => 334,
            _ => 0,
        };
        if month > 2 && Self::leap_year(year) {
            days + 1
        } else {
            days
        }
    }

    fn to_utc_units(self) -> i128 {
        let completed_year = i128::from(self.year) - 1;
        let days = completed_year * 365 + completed_year / 4 - completed_year / 100
            + completed_year / 400
            + i128::from(Self::days_before_month(self.year, self.month))
            + i128::from(self.day.saturating_sub(1));
        let mut seconds = days * 86_400
            + i128::from(self.hour) * 3_600
            + i128::from(self.minute) * 60
            + i128::from(self.second);
        if self.timezone != 0x7ff {
            seconds -= i128::from(self.timezone) * 60;
        }
        seconds * 1_000_000_000 + i128::from(self.nanosecond)
    }
}

/// Base WIN_CERTIFICATE header.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct WinCertificate {
    pub dw_length: u32,
    pub w_revision: u16,
    pub w_certificate_type: u16,
}

/// WIN_CERTIFICATE header carrying an EFI certificate-type GUID.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct WinCertificateUefiGuid {
    pub hdr: WinCertificate,
    pub cert_type: [u8; 16],
}

impl WinCertificateUefiGuid {
    pub const HEADER_SIZE: usize = core::mem::size_of::<Self>();
}

/// Header for a time-based authenticated variable update.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct EfiVariableAuthentication2 {
    pub time_stamp: EfiTime,
    pub auth_info: WinCertificateUefiGuid,
}

impl EfiVariableAuthentication2 {
    pub fn from_bytes(data: &[u8]) -> Option<&Self> {
        Self::ref_from_prefix(data).ok().map(|(value, _)| value)
    }

    pub fn total_size(&self) -> Option<usize> {
        core::mem::size_of::<EfiTime>().checked_add(self.auth_info.hdr.dw_length as usize)
    }

    pub fn cert_data<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        let certificate_length = self.auth_info.hdr.dw_length as usize;
        if certificate_length < WinCertificateUefiGuid::HEADER_SIZE {
            return None;
        }
        let start = core::mem::size_of::<EfiTime>() + WinCertificateUefiGuid::HEADER_SIZE;
        let end = core::mem::size_of::<EfiTime>().checked_add(certificate_length)?;
        data.get(start..end)
    }

    pub fn variable_data<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        data.get(self.total_size()?..)
    }
}

/// Header for one list in an EFI signature database.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout, Unaligned)]
pub struct EfiSignatureList {
    pub signature_type: [u8; 16],
    pub signature_list_size: u32,
    pub signature_header_size: u32,
    pub signature_size: u32,
}

impl EfiSignatureList {
    pub const HEADER_SIZE: usize = core::mem::size_of::<Self>();
}

/// Validate that every byte belongs to a complete EFI signature list.
pub fn validate_signature_database(mut data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    let mut list_count = 0usize;
    while !data.is_empty() {
        let Ok((list, _)) = EfiSignatureList::ref_from_prefix(data) else {
            return false;
        };
        let size = list.signature_list_size as usize;
        let header = list.signature_header_size as usize;
        let signature = list.signature_size as usize;
        let Some(content_start) = EfiSignatureList::HEADER_SIZE.checked_add(header) else {
            return false;
        };
        if size < content_start
            || size > data.len()
            || signature < 16
            || size == content_start
            || !(size - content_start).is_multiple_of(signature)
        {
            return false;
        }
        let Some(remaining) = data.get(size..) else {
            return false;
        };
        data = remaining;
        list_count += 1;
    }
    list_count != 0
}

/// Iterator over complete lists in an EFI signature database.
pub struct SignatureListIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> SignatureListIterator<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl<'a> Iterator for SignatureListIterator<'a> {
    type Item = (&'a EfiSignatureList, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.data.get(self.offset..)?;
        if remaining.is_empty() {
            return None;
        }
        let list = EfiSignatureList::ref_from_prefix(remaining).ok()?.0;
        let size = list.signature_list_size as usize;
        let header = list.signature_header_size as usize;
        let signature = list.signature_size as usize;
        if size < EfiSignatureList::HEADER_SIZE
            || header > size - EfiSignatureList::HEADER_SIZE
            || signature < 16
            || !(size - EfiSignatureList::HEADER_SIZE - header).is_multiple_of(signature)
        {
            self.offset = self.data.len();
            return None;
        }
        let bytes = remaining.get(..size)?;
        self.offset = self.offset.checked_add(size)?;
        Some((list, bytes))
    }
}

/// Iterator over owner GUID and payload pairs in one signature list.
pub struct SignatureIterator<'a> {
    list: &'a EfiSignatureList,
    data: &'a [u8],
    index: usize,
    count: usize,
}

impl<'a> SignatureIterator<'a> {
    pub fn new(list: &'a EfiSignatureList, data: &'a [u8]) -> Self {
        let signature_size = list.signature_size as usize;
        let content = (list.signature_list_size as usize)
            .saturating_sub(EfiSignatureList::HEADER_SIZE)
            .saturating_sub(list.signature_header_size as usize);
        Self {
            list,
            data,
            index: 0,
            count: content.checked_div(signature_size).unwrap_or(0),
        }
    }
}

impl<'a> Iterator for SignatureIterator<'a> {
    type Item = ([u8; 16], &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        let size = self.list.signature_size as usize;
        let start = EfiSignatureList::HEADER_SIZE
            .checked_add(self.list.signature_header_size as usize)?
            .checked_add(self.index.checked_mul(size)?)?;
        let bytes = self.data.get(start..start.checked_add(size)?)?;
        let mut owner = [0u8; 16];
        for (destination, source) in owner.iter_mut().zip(bytes.get(..16)?.iter()) {
            *destination = *source;
        }
        self.index += 1;
        Some((owner, bytes.get(16..)?))
    }
}

#[cfg(test)]
mod tests {
    use super::EfiTime;

    fn time(year: u16, month: u8, day: u8) -> EfiTime {
        EfiTime {
            year,
            month,
            day,
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

    #[test]
    fn validates_gregorian_month_lengths() {
        assert!(time(2024, 2, 29).is_valid());
        assert!(!time(2025, 2, 29).is_valid());
        assert!(!time(1900, 2, 29).is_valid());
        assert!(time(2000, 2, 29).is_valid());
        assert!(!time(2025, 4, 31).is_valid());
    }

    #[test]
    fn orders_consecutive_gregorian_days() {
        assert!(time(2025, 2, 1).is_after(&time(2025, 1, 31)));
        assert!(time(2024, 3, 1).is_after(&time(2024, 2, 29)));
        assert!(time(2025, 1, 1).is_after(&time(2024, 12, 31)));
    }

    #[test]
    fn compares_timezone_equivalent_instants() {
        let utc = time(2025, 1, 31);
        let mut east = utc;
        east.hour = 1;
        east.timezone = 60;
        assert!(!utc.is_after(&east));
        assert!(!east.is_after(&utc));
    }
}

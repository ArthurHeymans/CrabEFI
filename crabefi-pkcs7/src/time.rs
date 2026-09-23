//! X.509 UTCTime/GeneralizedTime decoding and Unix-time conversion.

use crate::der::{DecodeError, Result, Tlv, tag};

/// A validated UTC calendar date and time of day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl DateTime {
    /// Decode a UTCTime (`YYMMDDHHMMSSZ`, years 1950-2049) or GeneralizedTime
    /// (`YYYYMMDDHHMMSS[.fff]Z`) element. Fractional seconds are validated
    /// and discarded.
    pub fn parse(time: Tlv<'_>) -> Result<Self> {
        let mut digits = Digits(time.value);
        let year = match time.tag {
            tag::UTC_TIME => match digits.two()? {
                year @ 50.. => 1900 + u16::from(year),
                year => 2000 + u16::from(year),
            },
            tag::GENERALIZED_TIME => digits.four()?,
            _ => return Err(DecodeError),
        };
        let date = Self {
            year,
            month: digits.two()?,
            day: digits.two()?,
            hour: digits.two()?,
            minute: digits.two()?,
            second: digits.two()?,
        };
        if time.tag == tag::GENERALIZED_TIME {
            digits.skip_fraction()?;
        }
        if digits.0 != b"Z" || !date.is_valid() {
            return Err(DecodeError);
        }
        Ok(date)
    }

    fn is_valid(&self) -> bool {
        let leap = (self.year.is_multiple_of(4) && !self.year.is_multiple_of(100))
            || self.year.is_multiple_of(400);
        let days_in_month = match self.month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return false,
        };
        (1..=days_in_month).contains(&self.day)
            && self.hour < 24
            && self.minute < 60
            && self.second < 60
    }

    /// Seconds since 1970-01-01T00:00:00Z (negative before the epoch).
    pub fn unix_timestamp(&self) -> i64 {
        // Days-from-civil (Howard Hinnant): shift March to month 0 so leap
        // days fall at the end of the year.
        let month = i64::from(self.month);
        let (year, month) = if month <= 2 {
            (i64::from(self.year) - 1, month + 9)
        } else {
            (i64::from(self.year), month - 3)
        };
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let day_of_year = (153 * month + 2) / 5 + i64::from(self.day) - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        let days = era * 146_097 + day_of_era - 719_468;
        days * 86_400
            + i64::from(self.hour) * 3_600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
    }
}

struct Digits<'a>(&'a [u8]);

impl Digits<'_> {
    fn digit(&mut self) -> Result<u8> {
        match self.0.split_first() {
            Some((&digit @ b'0'..=b'9', rest)) => {
                self.0 = rest;
                Ok(digit - b'0')
            }
            _ => Err(DecodeError),
        }
    }

    fn two(&mut self) -> Result<u8> {
        Ok(self.digit()? * 10 + self.digit()?)
    }

    fn four(&mut self) -> Result<u16> {
        Ok(u16::from(self.two()?) * 100 + u16::from(self.two()?))
    }

    /// Skip `.d{1,9}` without a trailing zero, if present.
    fn skip_fraction(&mut self) -> Result<()> {
        let Some((b'.', rest)) = self.0.split_first() else {
            return Ok(());
        };
        let count = rest.iter().take_while(|byte| byte.is_ascii_digit()).count();
        let (fraction, rest) = rest.split_at_checked(count).ok_or(DecodeError)?;
        if !(1..=9).contains(&count) || fraction.last() == Some(&b'0') {
            return Err(DecodeError);
        }
        self.0 = rest;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn time(tag: u8, value: &[u8]) -> Result<DateTime> {
        DateTime::parse(Tlv {
            tag,
            value,
            encoded: &[],
        })
    }

    fn at(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> i64 {
        DateTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
        .unix_timestamp()
    }

    #[test]
    fn known_timestamps() {
        assert_eq!(at(1970, 1, 1, 0, 0, 0), 0);
        assert_eq!(at(2000, 1, 1, 0, 0, 0), 946_684_800);
        assert_eq!(at(2024, 2, 29, 12, 0, 0), 1_709_208_000);
        assert_eq!(at(2038, 1, 19, 3, 14, 7), 2_147_483_647);
        assert_eq!(at(1950, 1, 1, 0, 0, 0), -631_152_000);
        assert_eq!(at(2025, 6, 15, 8, 30, 45), 1_749_976_245);
    }

    #[test]
    fn utc_time_maps_two_digit_years() {
        assert_eq!(time(tag::UTC_TIME, b"491231235959Z").unwrap().year, 2049);
        assert_eq!(time(tag::UTC_TIME, b"500101000000Z").unwrap().year, 1950);
    }

    #[test]
    fn generalized_time_accepts_canonical_fractions() {
        let date = time(tag::GENERALIZED_TIME, b"20240229120000Z").unwrap();
        assert_eq!(date.unix_timestamp(), 1_709_208_000);
        assert_eq!(time(tag::GENERALIZED_TIME, b"20240229120000.5Z"), Ok(date));
        for rejected in [
            &b"20240229120000.50Z"[..],
            b"20240229120000.Z",
            b"20240229120000.1234567891Z",
        ] {
            assert!(time(tag::GENERALIZED_TIME, rejected).is_err());
        }
    }

    #[test]
    fn rejects_invalid_dates_and_encodings() {
        for (tag, value) in [
            (tag::UTC_TIME, &b"230229000000Z"[..]),
            (tag::UTC_TIME, b"231301000000Z"),
            (tag::UTC_TIME, b"230101240000Z"),
            (tag::UTC_TIME, b"2301010000Z"),
            (tag::UTC_TIME, b"230101000000"),
            (tag::UTC_TIME, b"230101000000+0100"),
            (tag::UTC_TIME, b"230101000000.5Z"),
            (tag::GENERALIZED_TIME, b"20230100000000Z"),
            (tag::OCTET_STRING, b"20230101000000Z"),
        ] {
            assert!(
                time(tag, value).is_err(),
                "{:?}",
                core::str::from_utf8(value)
            );
        }
    }
}

//! Borrowed reader for Distinguished Encoding Rules (DER).
//!
//! Only single-byte tags and definite lengths of at most four bytes are
//! accepted, and every length must use its minimal encoding. Nothing panics on
//! hostile input: every access is bounds-checked and failures surface as
//! [`DecodeError`].

/// Input is not the expected DER structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError;

pub type Result<T> = core::result::Result<T, DecodeError>;

/// Universal and context-specific tag bytes.
pub mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const ENUMERATED: u8 = 0x0a;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;

    const CONSTRUCTED: u8 = 0x20;

    /// Primitive context-specific tag `[number]`.
    pub const fn context(number: u8) -> u8 {
        0x80 | number
    }

    /// Constructed context-specific tag `[number]`.
    pub const fn context_constructed(number: u8) -> u8 {
        context(number) | CONSTRUCTED
    }

    /// Whether `tag` has the constructed bit set.
    pub const fn is_constructed(tag: u8) -> bool {
        tag & CONSTRUCTED != 0
    }
}

/// One tag-length-value element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// Content octets.
    pub value: &'a [u8],
    /// Complete encoding including tag and length.
    pub encoded: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Read the first element of `input`, returning it and the bytes after it.
    pub fn read(input: &'a [u8]) -> Result<(Self, &'a [u8])> {
        let (&tag, rest) = input.split_first().ok_or(DecodeError)?;
        if tag & 0x1f == 0x1f {
            return Err(DecodeError);
        }
        let (&first, rest) = rest.split_first().ok_or(DecodeError)?;
        let (length, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let count = usize::from(first & 0x7f);
            let (bytes, rest) = rest.split_at_checked(count).ok_or(DecodeError)?;
            if !(1..=4).contains(&count) || bytes.first() == Some(&0) {
                return Err(DecodeError);
            }
            let length = bytes
                .iter()
                .fold(0usize, |length, byte| (length << 8) | usize::from(*byte));
            if length < 0x80 {
                return Err(DecodeError);
            }
            (length, rest)
        };
        let (value, remaining) = rest.split_at_checked(length).ok_or(DecodeError)?;
        let header = input.len() - rest.len();
        let encoded = input.get(..header + length).ok_or(DecodeError)?;
        Ok((
            Self {
                tag,
                value,
                encoded,
            },
            remaining,
        ))
    }

    /// Parse `input` as exactly one element.
    pub fn parse(input: &'a [u8]) -> Result<Self> {
        match Self::read(input)? {
            (tlv, []) => Ok(tlv),
            _ => Err(DecodeError),
        }
    }

    /// Require the element to carry `tag`.
    pub fn expect(self, tag: u8) -> Result<Self> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(DecodeError)
        }
    }

    /// Reader over the content octets of a constructed element with `tag`.
    pub fn contents(self, tag: u8) -> Result<Reader<'a>> {
        self.expect(tag).map(|tlv| Reader::new(tlv.value))
    }

    /// The single element inside this one.
    pub fn inner(self) -> Result<Tlv<'a>> {
        Tlv::parse(self.value)
    }

    /// Big-endian magnitude of a non-negative, minimally encoded INTEGER,
    /// without the sign-disambiguating leading zero byte.
    pub fn unsigned_integer(self) -> Result<&'a [u8]> {
        match self.expect(tag::INTEGER)?.value {
            [] => Err(DecodeError),
            [first, ..] if first & 0x80 != 0 => Err(DecodeError),
            [0, second, ..] if second & 0x80 == 0 => Err(DecodeError),
            [0, rest @ ..] if !rest.is_empty() => Ok(rest),
            value => Ok(value),
        }
    }

    /// Content of a BIT STRING without unused bits.
    pub fn bit_string_octets(self) -> Result<&'a [u8]> {
        match self.expect(tag::BIT_STRING)?.value {
            [0, octets @ ..] => Ok(octets),
            _ => Err(DecodeError),
        }
    }

    /// Content of an OCTET STRING.
    pub fn octet_string(self) -> Result<&'a [u8]> {
        self.expect(tag::OCTET_STRING).map(|tlv| tlv.value)
    }

    /// Encoded identifier of an OBJECT IDENTIFIER.
    pub fn oid(self) -> Result<&'a [u8]> {
        self.expect(tag::OID).map(|tlv| tlv.value)
    }

    /// Value of a DER BOOLEAN (`0x00` or `0xff`).
    pub fn boolean(self) -> Result<bool> {
        match self.expect(tag::BOOLEAN)?.value {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(DecodeError),
        }
    }
}

/// Sequential reader over concatenated elements.
///
/// Iteration yields each element in turn; a malformed element is yielded as
/// an error and ends the iteration.
#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    pub const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    /// Tag of the next element, if any.
    pub fn peek_tag(&self) -> Option<u8> {
        self.remaining.first().copied()
    }

    /// Read the next element.
    pub fn read(&mut self) -> Result<Tlv<'a>> {
        let (tlv, remaining) = Tlv::read(self.remaining)?;
        self.remaining = remaining;
        Ok(tlv)
    }

    /// Read the next element, requiring `tag`.
    pub fn read_tag(&mut self, tag: u8) -> Result<Tlv<'a>> {
        self.read()?.expect(tag)
    }

    /// Read the next element only if it carries `tag`.
    pub fn read_optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>> {
        if self.peek_tag() == Some(tag) {
            self.read().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Require that every element has been read.
    pub fn finish(self) -> Result<()> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(DecodeError)
        }
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Result<Tlv<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.is_empty() {
            return None;
        }
        let next = self.read();
        if next.is_err() {
            self.remaining = &[];
        }
        Some(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncated_indefinite_and_non_minimal_lengths() {
        for input in [
            &[][..],
            &[0x30],
            &[0x30, 0x80],
            &[0x30, 0x82, 0x01],
            &[0x30, 0x84, 0xff, 0xff, 0xff, 0xff],
            &[0x30, 0x81, 0x05, 0, 0, 0, 0, 0],
            &[0x30, 0x82, 0x00, 0x80],
            &[0x30, 0x85, 1, 0, 0, 0, 0],
            &[0x1f, 0x01, 0x00],
        ] {
            assert_eq!(Tlv::read(input), Err(DecodeError), "{input:02x?}");
        }
    }

    #[test]
    fn read_returns_first_element_and_trailing_bytes() {
        let data = [0x30, 0x03, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00];
        let (tlv, rest) = Tlv::read(&data).unwrap();
        assert_eq!(tlv.tag, tag::SEQUENCE);
        assert_eq!(tlv.encoded, &data[..5]);
        assert_eq!(tlv.value, &data[2..5]);
        assert_eq!(rest, &[0, 0, 0]);
        assert_eq!(Tlv::parse(&data), Err(DecodeError));

        let mut long = vec![0x04, 0x81, 0x80];
        long.extend([0xaa; 0x80]);
        let tlv = Tlv::parse(&long).unwrap();
        assert_eq!(tlv.value.len(), 0x80);
    }

    #[test]
    fn unsigned_integer_is_minimal_and_non_negative() {
        let integer = |value: &'static [u8]| Tlv {
            tag: tag::INTEGER,
            value,
            encoded: &[],
        };
        assert_eq!(integer(&[0x01]).unsigned_integer(), Ok(&[0x01][..]));
        assert_eq!(integer(&[0x00]).unsigned_integer(), Ok(&[0x00][..]));
        assert_eq!(integer(&[0x00, 0x80]).unsigned_integer(), Ok(&[0x80][..]));
        assert_eq!(integer(&[0x00, 0x7f]).unsigned_integer(), Err(DecodeError));
        assert_eq!(integer(&[0x80]).unsigned_integer(), Err(DecodeError));
        assert_eq!(integer(&[]).unsigned_integer(), Err(DecodeError));
    }

    #[test]
    fn reader_iteration_stops_after_malformed_element() {
        let data = [0x05, 0x00, 0x30, 0x05];
        let mut reader = Reader::new(&data);
        assert!(reader.next().unwrap().is_ok());
        assert_eq!(reader.next(), Some(Err(DecodeError)));
        assert_eq!(reader.next(), None);
    }
}

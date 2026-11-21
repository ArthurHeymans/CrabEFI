//! LUKS2 binary headers and JSON metadata.
//!
//! The header is unauthenticated input from the disk. Everything here is
//! bounded: header sizes, JSON nesting through serde, and every offset is
//! checked against the partition before use.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use serde::Deserialize;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};

use super::{LuksError, RawPartition};

const MAGIC_PRIMARY: &[u8; 6] = b"LUKS\xba\xbe";
const MAGIC_SECONDARY: &[u8; 6] = b"SKUL\xba\xbe";
pub(super) const BINARY_HEADER_SIZE: usize = 4096;
/// Largest header (binary part plus JSON area) accepted. cryptsetup creates
/// 16 KiB headers unless told otherwise; its maximum is 4 MiB.
const MAX_HEADER_SIZE: u64 = 256 * 1024;
const MIN_HEADER_SIZE: u64 = 16 * 1024;
/// Where cryptsetup looks for a secondary header when the primary is damaged.
const SECONDARY_OFFSETS: [u64; 5] = [0x4000, 0x8000, 0x10000, 0x20000, 0x40000];
const CSUM_OFFSET: usize = 448;
const CSUM_LEN: usize = 64;

/// A checked LUKS2 header and its metadata.
pub(crate) struct Header {
    pub uuid: String,
    pub label: String,
    pub hdr_size: u64,
    pub metadata: Metadata,
}

/// LUKS2 allows 32 keyslots and 32 tokens; segments and digests are fewer.
const MAX_OBJECTS: usize = 64;

type Objects = BTreeMap<String, Box<RawValue>>;

/// The JSON metadata. Objects stay unparsed JSON text until used, so a type
/// CrabEFI does not know does not reject the volume, and the parsed form
/// never takes much more memory than the header. Unknown members are
/// skipped without being built.
#[derive(Deserialize)]
pub(crate) struct Metadata {
    #[serde(deserialize_with = "bounded")]
    pub keyslots: Objects,
    /// Read by TPM token unlocking.
    #[cfg_attr(not(feature = "tpm"), allow(dead_code))]
    #[serde(default, deserialize_with = "bounded")]
    pub tokens: Objects,
    #[serde(deserialize_with = "bounded")]
    pub segments: Objects,
    #[serde(deserialize_with = "bounded")]
    pub digests: Objects,
    pub config: Config,
}

/// A JSON object of at most [`MAX_OBJECTS`] members.
fn bounded<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Objects, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Objects;
        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "an object of at most {MAX_OBJECTS} members")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Objects, A::Error> {
            let mut objects = Objects::new();
            while let Some((key, value)) = map.next_entry::<String, Box<RawValue>>()? {
                if objects.len() == MAX_OBJECTS {
                    return Err(serde::de::Error::custom("too many members"));
                }
                objects.insert(key, value);
            }
            Ok(objects)
        }
    }
    deserializer.deserialize_map(Visitor)
}

#[derive(Deserialize)]
pub(crate) struct Config {
    pub json_size: String,
    pub keyslots_size: String,
    #[serde(default)]
    pub requirements: Option<Requirements>,
}

#[derive(Deserialize)]
pub(crate) struct Requirements {
    #[serde(default, deserialize_with = "bounded_list::<_, _, 16>")]
    pub mandatory: Vec<String>,
}

/// A JSON array of at most `N` elements. Lists inside metadata members
/// are bounded too, so one member cannot expand far beyond its text.
pub(crate) fn bounded_list<'de, D, T, const N: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T, const N: usize>(core::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> serde::de::Visitor<'de> for Visitor<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "an array of at most {N} elements")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut list = Vec::new();
            while let Some(item) = seq.next_element()? {
                if list.len() == N {
                    return Err(serde::de::Error::custom("too many elements"));
                }
                list.push(item);
            }
            Ok(list)
        }
    }
    deserializer.deserialize_seq(Visitor::<T, N>(core::marker::PhantomData))
}

#[derive(Deserialize)]
pub(crate) struct Keyslot {
    #[serde(rename = "type")]
    pub kind: String,
    pub key_size: u32,
    pub af: Af,
    pub area: Area,
    pub kdf: Kdf,
    #[serde(default)]
    pub priority: Option<u32>,
}

#[derive(Deserialize)]
pub(crate) struct Af {
    #[serde(rename = "type")]
    pub kind: String,
    pub stripes: u32,
    pub hash: String,
}

#[derive(Deserialize)]
pub(crate) struct Area {
    #[serde(rename = "type")]
    pub kind: String,
    pub offset: String,
    pub size: String,
    pub encryption: String,
    pub key_size: u32,
}

/// A keyslot KDF. A flat struct rather than an internally tagged enum:
/// serde would buffer the whole member to find the tag.
#[derive(Deserialize)]
pub(crate) struct Kdf {
    /// `pbkdf2`, `argon2i` or `argon2id`.
    #[serde(rename = "type")]
    pub kind: String,
    pub salt: String,
    /// PBKDF2 only.
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub iterations: Option<u32>,
    /// Argon2 only.
    #[serde(default)]
    pub time: Option<u32>,
    #[serde(default)]
    pub memory: Option<u32>,
    #[serde(default)]
    pub cpus: Option<u32>,
}

#[derive(Deserialize)]
pub(crate) struct Segment {
    #[serde(rename = "type")]
    pub kind: String,
    pub offset: String,
    pub size: String,
    pub iv_tweak: String,
    pub encryption: String,
    pub sector_size: u32,
    /// Present means unsupported; its contents are skipped, not built.
    #[serde(default)]
    pub integrity: Option<serde::de::IgnoredAny>,
    #[serde(default, deserialize_with = "bounded_list::<_, _, 16>")]
    pub flags: Vec<String>,
}

#[derive(Deserialize)]
pub(crate) struct DigestEntry {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(deserialize_with = "bounded_list::<_, _, 32>")]
    pub keyslots: Vec<String>,
    #[serde(deserialize_with = "bounded_list::<_, _, 8>")]
    pub segments: Vec<String>,
    pub hash: String,
    pub iterations: u32,
    pub salt: String,
    pub digest: String,
}

/// Parse a LUKS2 size or offset: a decimal `u64` in a JSON string.
pub(crate) fn parse_u64(text: &str) -> Result<u64, LuksError> {
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(LuksError::Corrupt("bad number"));
    }
    text.parse().map_err(|_| LuksError::Corrupt("bad number"))
}

/// Whether the partition holds a LUKS header of any version: a primary
/// copy, or only a secondary one where the primary was damaged.
pub(crate) fn present(part: &mut dyn RawPartition) -> bool {
    let mut magic = [0u8; 6];
    let mut has = |offset: u64, expected: &[u8; 6]| {
        offset + 6 <= part.len() && part.read(offset, &mut magic).is_ok() && magic == *expected
    };
    has(0, MAGIC_PRIMARY)
        || SECONDARY_OFFSETS
            .iter()
            .any(|&offset| has(offset, MAGIC_SECONDARY))
}

/// Read a checked header copy at `offset`, or `None` if there is no intact
/// one there. A copy that cannot be read counts as damaged.
fn read_one(
    part: &mut dyn RawPartition,
    offset: u64,
    magic: &[u8; 6],
) -> Result<Option<(u64, Vec<u8>)>, LuksError> {
    let mut binary = [0u8; BINARY_HEADER_SIZE];
    if offset + BINARY_HEADER_SIZE as u64 > part.len() {
        return Ok(None);
    }
    if let Err(err) = part.read(offset, &mut binary) {
        log::warn!("LUKS2 header at {offset:#x}: {err}");
        return Ok(None);
    }
    if binary[..6] != *magic {
        return Ok(None);
    }
    if u16::from_be_bytes([binary[6], binary[7]]) != 2 {
        return Ok(None);
    }
    let be64 = |at: usize| u64::from_be_bytes(binary[at..at + 8].try_into().unwrap());
    let hdr_size = be64(8);
    let seqid = be64(16);
    if hdr_size > MAX_HEADER_SIZE {
        log::warn!("LUKS2 header at {offset:#x}: {hdr_size}-byte metadata is not supported");
        return Ok(None);
    }
    if !hdr_size.is_power_of_two() || hdr_size < MIN_HEADER_SIZE || be64(256) != offset {
        return Ok(None);
    }
    if cstr(&binary[72..104]) != Some("sha256") {
        log::warn!("LUKS2 header at {offset:#x}: unsupported checksum algorithm");
        return Ok(None);
    }
    if offset
        .checked_add(hdr_size)
        .is_none_or(|end| end > part.len())
    {
        return Ok(None);
    }
    let mut all = Vec::new();
    all.try_reserve_exact(hdr_size as usize)
        .map_err(|_| LuksError::OutOfMemory)?;
    all.resize(hdr_size as usize, 0);
    all[..BINARY_HEADER_SIZE].copy_from_slice(&binary);
    if let Err(err) = part.read(
        offset + BINARY_HEADER_SIZE as u64,
        &mut all[BINARY_HEADER_SIZE..],
    ) {
        log::warn!("LUKS2 header at {offset:#x}: {err}");
        return Ok(None);
    }
    let mut expected = [0u8; CSUM_LEN];
    expected.copy_from_slice(&all[CSUM_OFFSET..CSUM_OFFSET + CSUM_LEN]);
    all[CSUM_OFFSET..CSUM_OFFSET + CSUM_LEN].fill(0);
    let actual = Sha256::digest(&all);
    if expected[..32] != actual[..] || expected[32..].iter().any(|&b| b != 0) {
        log::warn!("LUKS2 header at {offset:#x}: checksum mismatch");
        return Ok(None);
    }
    all[CSUM_OFFSET..CSUM_OFFSET + CSUM_LEN].copy_from_slice(&expected);
    Ok(Some((seqid, all)))
}

/// Read the newest usable LUKS2 header copy of a partition: intact, with
/// metadata CrabEFI can parse. Like cryptsetup, prefer the newer copy.
pub(crate) fn read(part: &mut dyn RawPartition) -> Result<Header, LuksError> {
    let mut best: Option<(u64, Header)> = None;
    let mut consider = |copy: Option<(u64, Vec<u8>)>, offset: u64| {
        let Some((seqid, bytes)) = copy else {
            return;
        };
        match parse(&bytes) {
            Ok(header) if best.as_ref().is_none_or(|(newest, _)| seqid > *newest) => {
                best = Some((seqid, header));
            }
            Ok(_) => {}
            Err(err) => log::warn!("LUKS2 header at {offset:#x}: {err}"),
        }
    };
    let primary = read_one(part, 0, MAGIC_PRIMARY)?;
    // The secondary copy follows the primary; scan the places cryptsetup
    // uses when the primary does not say where.
    let secondary_at = primary.as_ref().map(|(_, bytes)| bytes.len() as u64);
    consider(primary, 0);
    match secondary_at {
        Some(offset) => consider(read_one(part, offset, MAGIC_SECONDARY)?, offset),
        None => {
            for offset in SECONDARY_OFFSETS {
                if let Some(copy) = read_one(part, offset, MAGIC_SECONDARY)? {
                    log::warn!("LUKS2: primary header damaged, using the copy at {offset:#x}");
                    consider(Some(copy), offset);
                    break;
                }
            }
        }
    }
    best.map(|(_, header)| header)
        .ok_or(LuksError::Corrupt("no usable LUKS2 header"))
}

fn cstr(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).ok()
}

/// Parse a header copy whose checksum was verified.
fn parse(bytes: &[u8]) -> Result<Header, LuksError> {
    let json = &bytes[BINARY_HEADER_SIZE..];
    let end = json
        .iter()
        .position(|&b| b == 0)
        .ok_or(LuksError::Corrupt("unterminated JSON"))?;
    let metadata: Metadata = serde_json::from_slice(&json[..end]).map_err(|err| {
        log::warn!("LUKS2 metadata: {err}");
        LuksError::Corrupt("invalid JSON metadata")
    })?;
    let hdr_size = bytes.len() as u64;
    if parse_u64(&metadata.config.json_size)? != hdr_size - BINARY_HEADER_SIZE as u64 {
        return Err(LuksError::Corrupt("JSON size mismatch"));
    }
    Ok(Header {
        uuid: cstr(&bytes[168..208]).unwrap_or("").into(),
        label: cstr(&bytes[24..72]).unwrap_or("").into(),
        hdr_size,
        metadata,
    })
}

impl Header {
    /// End of the keyslot area: nothing below it is volume data.
    pub(crate) fn metadata_end(&self) -> Result<u64, LuksError> {
        parse_u64(&self.metadata.config.keyslots_size)?
            .checked_add(2 * self.hdr_size)
            .ok_or(LuksError::Corrupt("keyslot area overflows"))
    }

    pub(crate) fn segment(&self) -> Result<Segment, LuksError> {
        if self.metadata.segments.len() != 1 {
            return Err(LuksError::Unsupported("more than one data segment"));
        }
        let value = self
            .metadata
            .segments
            .get("0")
            .ok_or(LuksError::Unsupported("data segment is not segment 0"))?;
        serde_json::from_str(value.get()).map_err(|_| LuksError::Unsupported("data segment"))
    }

    pub(crate) fn keyslot(&self, id: &str) -> Option<Keyslot> {
        serde_json::from_str(self.metadata.keyslots.get(id)?.get()).ok()
    }

    /// Digests that verify volume keys of segment 0.
    pub(crate) fn segment_digests(&self) -> impl Iterator<Item = DigestEntry> + '_ {
        self.metadata
            .digests
            .values()
            .filter_map(|value| serde_json::from_str::<DigestEntry>(value.get()).ok())
            .filter(|digest| digest.kind == "pbkdf2" && digest.segments.iter().any(|s| s == "0"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_are_strict_decimal() {
        assert_eq!(parse_u64("16777216").unwrap(), 16 << 20);
        for bad in ["", "-1", "0x10", " 1", "1 ", "18446744073709551616", "1e3"] {
            assert!(parse_u64(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn metadata_objects_are_bounded() {
        let many: String = (0..=MAX_OBJECTS)
            .map(|i| alloc::format!("\"{i}\":{{}}"))
            .collect::<Vec<_>>()
            .join(",");
        let json = alloc::format!(
            r#"{{"keyslots":{{{many}}},"segments":{{}},"digests":{{}},"config":{{"json_size":"1","keyslots_size":"1"}}}}"#
        );
        assert!(serde_json::from_str::<Metadata>(&json).is_err());
        let json = r#"{"keyslots":{"0":{"type":"x"}},"segments":{},"digests":{},
            "config":{"json_size":"1","keyslots_size":"1","flags":["a"]},"unknown":[1,2,{"deep":[]}]}"#;
        let metadata: Metadata = serde_json::from_str(json).unwrap();
        assert_eq!(metadata.keyslots["0"].get(), r#"{"type":"x"}"#);
    }

    #[test]
    fn kdf_variants_parse() {
        let pbkdf2: Kdf = serde_json::from_str(
            r#"{"type":"pbkdf2","hash":"sha512","iterations":1000,"salt":"AA=="}"#,
        )
        .unwrap();
        assert_eq!(pbkdf2.kind, "pbkdf2");
        assert_eq!(pbkdf2.iterations, Some(1000));
        // Unknown members, even large ones, are skipped.
        let argon: Kdf = serde_json::from_str(
            r#"{"type":"argon2id","time":4,"memory":65536,"cpus":4,"salt":"AA==","x":[[1],[2,{}]]}"#,
        )
        .unwrap();
        assert_eq!(
            (argon.kind.as_str(), argon.memory),
            ("argon2id", Some(65536))
        );
    }

    #[test]
    fn nested_lists_are_bounded() {
        let many = alloc::format!("[{}\"0\"]", "\"0\",".repeat(32));
        let digest = alloc::format!(
            r#"{{"type":"pbkdf2","keyslots":{many},"segments":["0"],"hash":"sha256","iterations":1,"salt":"","digest":""}}"#
        );
        assert!(serde_json::from_str::<DigestEntry>(&digest).is_err());
        let segment = r#"{"type":"crypt","offset":"0","size":"dynamic","iv_tweak":"0",
            "encryption":"aes-xts-plain64","sector_size":512,"integrity":{"type":"hmac","x":[1,2,3]}}"#;
        assert!(
            serde_json::from_str::<Segment>(segment)
                .unwrap()
                .integrity
                .is_some()
        );
    }
}

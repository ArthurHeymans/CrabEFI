//! Opening keyslots and reading decrypted data from an unlocked volume.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use super::crypto::{self, Hash, Secret, XtsCipher};
use super::header::{self, Header};
use super::{LuksError, RawPartition};
use crate::drivers::block::{BlockDevice, BlockDeviceInfo, BlockError, BlockRange};
use crate::drivers::storage::StorageId;

/// cryptsetup only creates keyslots with 4000 stripes.
const MAX_STRIPES: u32 = 4000;
const KEYSLOT_SECTOR: usize = 512;

/// The data segment of a volume, checked against its partition.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Layout {
    /// Byte offset of the first encrypted sector in the partition.
    pub offset: u64,
    /// Bytes of decrypted data.
    pub len: u64,
    pub sector_size: u32,
    /// `plain64` IV of the first sector, in 512-byte units.
    pub first_iv: u64,
}

impl Layout {
    pub(crate) fn check(header: &Header, partition_len: u64) -> Result<Self, LuksError> {
        if let Some(requirements) = &header.metadata.config.requirements
            && !requirements.mandatory.is_empty()
        {
            log::warn!(
                "LUKS2: unsupported mandatory requirements {:?}",
                requirements.mandatory
            );
            return Err(LuksError::Unsupported("mandatory requirement"));
        }
        let segment = header.segment()?;
        if segment.kind != "crypt" || segment.integrity.is_some() || !segment.flags.is_empty() {
            return Err(LuksError::Unsupported("data segment type"));
        }
        let sector_size = segment.sector_size;
        if !matches!(sector_size, 512 | 1024 | 2048 | 4096) {
            return Err(LuksError::Unsupported("sector size"));
        }
        let offset = header::parse_u64(&segment.offset)?;
        if offset % u64::from(sector_size) != 0
            || offset < header.metadata_end()?
            || offset >= partition_len
        {
            return Err(LuksError::Corrupt("data segment offset"));
        }
        let available = partition_len - offset;
        let len = if segment.size == "dynamic" {
            // Like dm-crypt, ignore a trailing partial sector.
            available - available % u64::from(sector_size)
        } else {
            let len = header::parse_u64(&segment.size)?;
            if len > available || len % u64::from(sector_size) != 0 {
                return Err(LuksError::Corrupt("data segment size"));
            }
            len
        };
        // LUKS2 counts plain64 IVs (and iv_tweak) in 512-byte units, also
        // with larger encryption sectors: cryptsetup never sets
        // iv_large_sectors for LUKS. Every sector's IV must fit plain64.
        let tweak = header::parse_u64(&segment.iv_tweak)?;
        // The last sector's IV, not the one after it.
        let last = len.saturating_sub(u64::from(sector_size)) / 512;
        if tweak.checked_add(last).is_none() {
            return Err(LuksError::Unsupported("IV tweak"));
        }
        // Validate the cipher name and key sizes before any key is derived.
        let digest_ok = header.segment_digests().next().is_some();
        if !digest_ok {
            return Err(LuksError::Corrupt("no digest for the data segment"));
        }
        if segment.encryption != "aes-xts-plain64" {
            log::warn!("LUKS2: cipher {} is not supported", segment.encryption);
            return Err(LuksError::Unsupported("cipher (only aes-xts-plain64)"));
        }
        Ok(Self {
            offset,
            len,
            sector_size,
            first_iv: tweak,
        })
    }
}

/// An unlocked volume. The cipher holds the volume key and is wiped on drop.
pub(crate) struct Volume {
    pub storage: StorageId,
    pub first_lba: u64,
    pub media: BlockDeviceInfo,
    pub layout: Layout,
    pub uuid: String,
    cipher: Box<XtsCipher>,
}

impl Volume {
    pub(crate) fn new(
        storage: StorageId,
        first_lba: u64,
        media: BlockDeviceInfo,
        layout: Layout,
        header: &Header,
        key: &[u8],
    ) -> Result<Self, LuksError> {
        let segment = header.segment()?;
        Ok(Self {
            storage,
            first_lba,
            media,
            layout,
            uuid: header.uuid.clone(),
            cipher: Box::new(XtsCipher::new(&segment.encryption, key)?),
        })
    }

    /// Clear the key schedule in place, for [`super::emergency_wipe`].
    ///
    /// # Safety
    /// The volume must not be used or dropped afterwards: the caller must
    /// forget it, or its cipher is dropped twice.
    pub(crate) unsafe fn wipe_in_place(&mut self) {
        // SAFETY: drops the cipher (zeroizing its keys) without freeing its
        // memory; the caller's contract keeps it from being dropped again.
        unsafe { core::ptr::drop_in_place(&mut *self.cipher) };
    }

    /// Read decrypted bytes at `offset` of the data segment.
    pub(crate) fn read(
        &self,
        disk: &mut dyn BlockDevice,
        range: &BlockRange,
        offset: u64,
        out: &mut [u8],
    ) -> Result<(), BlockError> {
        let layout = self.layout;
        let size = layout.sector_size as usize;
        if offset
            .checked_add(out.len() as u64)
            .is_none_or(|end| end > layout.len)
        {
            return Err(BlockError::OutOfRange);
        }
        // Cleared on every return, also after a failed read.
        let mut scratch = zeroize::Zeroizing::new([0u8; 4096]);
        let mut done = 0;
        while done < out.len() {
            let position = offset + done as u64;
            let sector = position / size as u64;
            let within = (position % size as u64) as usize;
            let remaining = out.len() - done;
            // Layout::check made every IV of the segment fit.
            let iv = layout.first_iv + sector * (size as u64 / 512);
            let disk_offset = layout.offset + sector * size as u64;
            if within == 0 && remaining >= size {
                // Whole sectors decrypt in place, in bounded batches.
                let len = (remaining - remaining % size).min(1 << 20);
                let chunk = &mut out[done..done + len];
                range.read(disk, disk_offset, chunk)?;
                self.cipher.decrypt(chunk, size, iv, size as u64 / 512);
                done += len;
            } else {
                let sector_bytes = &mut scratch[..size];
                range.read(disk, disk_offset, sector_bytes)?;
                self.cipher
                    .decrypt(sector_bytes, size, iv, size as u64 / 512);
                let len = (size - within).min(remaining);
                out[done..done + len].copy_from_slice(&sector_bytes[within..within + len]);
                done += len;
            }
        }
        Ok(())
    }
}

/// Which keyslots a key may open.
#[derive(Clone, Copy)]
pub(crate) enum Slots<'a> {
    /// A passphrase someone typed: every keyslot, with the costs
    /// cryptsetup allows.
    Any,
    /// A token secret: only the keyslots the token names, and only cheap
    /// key derivation, since nobody chose to wait for it.
    #[cfg_attr(not(feature = "tpm"), allow(dead_code))]
    Token(&'a [String]),
}

/// LUKS2 has at most 32 keyslots.
const MAX_CANDIDATES: usize = 32;

impl Slots<'_> {
    /// The key derivation limits for keys of this kind.
    pub(crate) fn limits(self) -> crypto::Limits {
        match self {
            Slots::Any => crypto::Limits::INTERACTIVE,
            Slots::Token(_) => crypto::Limits::UNATTENDED,
        }
    }
}

/// Try `passphrase` on the keyslots that unlock segment 0, high priority
/// first, within `budget` (see [`Slots::limits`]). Returns the verified
/// volume key.
pub(crate) fn open(
    part: &mut dyn RawPartition,
    header: &Header,
    passphrase: &[u8],
    slots: Slots<'_>,
    budget: &mut crypto::Budget,
) -> Result<Secret, LuksError> {
    let only = match slots {
        Slots::Any => None,
        Slots::Token(slots) => Some(slots),
    };
    let mut candidates: Vec<(u32, String)> = Vec::new();
    for digest in header.segment_digests() {
        for slot in digest.keyslots {
            if only.is_some_and(|only| !only.contains(&slot))
                || candidates.iter().any(|c| c.1 == slot)
                || candidates.len() == MAX_CANDIDATES
            {
                continue;
            }
            let Some(keyslot) = header.keyslot(&slot) else {
                log::warn!("LUKS2 keyslot {slot}: not a keyslot CrabEFI can read");
                continue;
            };
            // Priority 0 means "ignore unless named explicitly".
            let priority = keyslot.priority.unwrap_or(1);
            if priority == 0 && only.is_none() {
                continue;
            }
            candidates.push((priority, slot));
        }
    }
    if candidates.is_empty() {
        return Err(LuksError::Unsupported("no usable keyslot"));
    }
    candidates.sort_by_key(|c| core::cmp::Reverse(c.0));
    // I/O and memory failures win; then a wrong key, if some keyslot could
    // check it; else why none could.
    let mut failure = None;
    let mut refused = None;
    let mut checked = false;
    for (_, slot) in candidates {
        match open_keyslot(part, header, &slot, passphrase, budget) {
            Ok(key) => return Ok(key),
            Err(LuksError::WrongKey) => checked = true,
            Err(err) => {
                log::warn!("LUKS2 keyslot {slot}: {err}");
                match err {
                    LuksError::Io(_) | LuksError::OutOfMemory => {
                        failure.get_or_insert(err);
                    }
                    _ => {
                        refused.get_or_insert(err);
                    }
                }
            }
        }
    }
    Err(match (failure, refused) {
        (Some(err), _) => err,
        (None, Some(err)) if !checked => err,
        _ => LuksError::WrongKey,
    })
}

fn open_keyslot(
    part: &mut dyn RawPartition,
    header: &Header,
    slot: &str,
    passphrase: &[u8],
    budget: &mut crypto::Budget,
) -> Result<Secret, LuksError> {
    let keyslot = header
        .keyslot(slot)
        .ok_or(LuksError::Unsupported("keyslot"))?;
    if keyslot.kind != "luks2" || keyslot.af.kind != "luks1" || keyslot.area.kind != "raw" {
        return Err(LuksError::Unsupported("keyslot type"));
    }
    let key_size = keyslot.key_size as usize;
    if !matches!(key_size, 32 | 64) || !matches!(keyslot.area.key_size, 32 | 64) {
        return Err(LuksError::Unsupported("key size"));
    }
    if !(1..=MAX_STRIPES).contains(&keyslot.af.stripes) {
        return Err(LuksError::Unsupported("AF stripes"));
    }
    let af_hash = Hash::parse(&keyslot.af.hash)?;
    let area_offset = header::parse_u64(&keyslot.area.offset)?;
    let area_size = header::parse_u64(&keyslot.area.size)?;
    let material_len = key_size * keyslot.af.stripes as usize;
    let read_len = material_len.next_multiple_of(KEYSLOT_SECTOR);
    if area_offset < 2 * header.hdr_size
        || area_offset % KEYSLOT_SECTOR as u64 != 0
        || (read_len as u64) > area_size
        || area_offset
            .checked_add(area_size)
            .is_none_or(|end| end > header.metadata_end().unwrap_or(0) || end > part.len())
    {
        return Err(LuksError::Corrupt("keyslot area"));
    }
    // Check the area cipher before spending time on the KDF.
    XtsCipher::new(
        &keyslot.area.encryption,
        &[0; 64][..keyslot.area.key_size as usize],
    )?;

    let derived = crypto::derive(
        &keyslot.kdf,
        passphrase,
        keyslot.area.key_size as usize,
        budget,
    )?;
    let mut material = crypto::secret(read_len)?;
    part.read(area_offset, &mut material)?;
    XtsCipher::new(&keyslot.area.encryption, &derived)?.decrypt(
        &mut material,
        KEYSLOT_SECTOR,
        0,
        1,
    );
    let key = crypto::af_merge(&material[..material_len], key_size, af_hash)?;
    if verify(header, slot, &key, budget)? {
        Ok(key)
    } else {
        Err(LuksError::WrongKey)
    }
}

/// Check a candidate volume key against a digest bound to `slot`.
fn verify(
    header: &Header,
    slot: &str,
    key: &[u8],
    budget: &mut crypto::Budget,
) -> Result<bool, LuksError> {
    for digest in header.segment_digests() {
        if !digest.keyslots.iter().any(|s| s == slot) {
            continue;
        }
        let expected = crypto::base64(&digest.digest)?;
        // As cryptsetup: 20 bytes (the LUKS1 size) or the hash's own size.
        let hash = Hash::parse(&digest.hash)?;
        if expected.len() != 20 && expected.len() != hash.output_size() {
            return Err(LuksError::Corrupt("digest"));
        }
        let mut actual = crypto::secret(expected.len())?;
        crypto::pbkdf2(
            hash,
            key,
            &crypto::base64(&digest.salt)?,
            digest.iterations,
            &mut actual,
            budget,
        )?;
        if crypto::constant_time_eq(&actual, &expected) {
            return Ok(true);
        }
    }
    Ok(false)
}

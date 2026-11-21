//! LUKS2 volumes below ext boot volumes.
//!
//! A LUKS2 partition is unlocked with a passphrase or, with the `tpm`
//! feature, a `systemd-tpm2` token enrolled by `systemd-cryptenroll`. The
//! unlocked volume supplies decrypted bytes to the ext reader; nothing above
//! [`crate::fs::boot::BootFilesystem`] knows about encryption.
//!
//! Supported: LUKS2 with one `aes-xts-plain64` data segment, PBKDF2
//! (SHA-256/512) or Argon2i/id keyslots, and AF hashes SHA-256/512.
//! Not supported: LUKS1, other ciphers, integrity, detached headers,
//! reencryption in progress, and LVM or other layers inside the volume.
//!
//! # Key lifetime
//!
//! Volume keys stay in firmware memory only while the boot menu runs.
//! [`crate::preboot::end`] wipes them (with [`wipe_keys`]) before any OS or
//! EFI image code runs, so a boot entry chosen later (USB, another disk)
//! cannot find them. After that, CrabEFI no longer unlocks anything.

// Unlocked volumes need the built-in secret hygiene: the zero-on-free
// global heap and the stack scrub of CrabEFI's own payload entry. A host
// with its own allocator or entry point would keep freed plaintext.
#[cfg(all(
    target_os = "none",
    not(all(feature = "global-allocator", feature = "platform-entry"))
))]
compile_error!("`luks` requires the `global-allocator` and `platform-entry` features");

mod crypto;
mod header;
// The salted TPM session's ECDH; the `luks` feature always carries it.
#[cfg(not(feature = "tpm"))]
use p256 as _;
mod prompt;
#[cfg(feature = "tpm")]
mod tpm;
mod volume;

#[cfg(test)]
mod tests;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::cell::Local;
use crate::drivers::block::{BlockDevice, BlockDeviceInfo, BlockError, BlockRange};
use crate::drivers::storage::{self, StorageDevice, StorageId};
use crate::fs::gpt::Partition;
pub(crate) use volume::Layout;
use volume::Volume;

#[derive(Debug)]
pub(crate) enum LuksError {
    Io(BlockError),
    Corrupt(&'static str),
    Unsupported(&'static str),
    OutOfMemory,
    WrongKey,
}

impl core::fmt::Display for LuksError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Corrupt(what) => write!(f, "corrupt metadata: {what}"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
            Self::OutOfMemory => f.write_str("out of memory"),
            Self::WrongKey => f.write_str("no keyslot opens with this key"),
        }
    }
}

impl From<BlockError> for LuksError {
    fn from(err: BlockError) -> Self {
        Self::Io(err)
    }
}

/// Byte access to one whole partition.
pub(crate) trait RawPartition {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), BlockError>;
    fn len(&self) -> u64;
}

struct DiskPartition<'a> {
    disk: &'a mut dyn BlockDevice,
    range: BlockRange,
    len: u64,
}

impl<'a> DiskPartition<'a> {
    fn new(disk: &'a mut dyn BlockDevice, partition: &Partition) -> Result<Self, BlockError> {
        let range = BlockRange::new(disk, partition.first_lba, partition.size_sectors())?;
        let len = range.byte_len(disk)?;
        Ok(Self { disk, range, len })
    }
}

impl RawPartition for DiskPartition<'_> {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), BlockError> {
        self.range.read(self.disk, offset, out)
    }

    fn len(&self) -> u64 {
        self.len
    }
}

/// Handle of an unlocked volume. It stops resolving once keys are wiped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VolumeId(u32);

struct Unlocked {
    id: VolumeId,
    volume: Volume,
    /// Unlocked without a person: by a TPM token.
    unattended: bool,
}

static VOLUMES: Local<Vec<Unlocked>> = Local::new(Vec::new());
static NEXT_ID: AtomicU32 = AtomicU32::new(1);
/// Volumes already tried with the TPM this boot, by location and UUID.
#[cfg(feature = "tpm")]
static TPM_TRIED: Local<Vec<(StorageId, u64, String)>> = Local::new(Vec::new());

fn same_fixed_media(expected: BlockDeviceInfo, live: BlockDeviceInfo) -> bool {
    crate::fs::boot::same_fixed_media(expected, live)
}

/// What discovery found on a partition.
pub(crate) enum Probe {
    /// Not a LUKS volume.
    Plain,
    /// Already unlocked, now or earlier this boot.
    Unlocked(VolumeId),
    /// A supported LUKS2 volume that needs a passphrase.
    Locked { name: String },
    /// LUKS, but not something CrabEFI can open.
    Unsupported,
}

/// Disk text made safe for the console: no control characters (terminal
/// escapes), at most `max` characters.
pub(crate) fn sanitize(text: &str, max: usize) -> String {
    text.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// A display name for a volume: its label, else the start of its UUID.
fn volume_name(header: &header::Header) -> String {
    let label = sanitize(&header.label, 32);
    if !label.is_empty() {
        return label;
    }
    let mut name = String::from("LUKS ");
    name.push_str(&sanitize(&header.uuid, 8));
    name
}

fn registered(
    storage: StorageId,
    partition: &Partition,
    media: BlockDeviceInfo,
) -> Option<VolumeId> {
    VOLUMES
        .borrow()
        .iter()
        .find(|u| {
            u.volume.storage == storage
                && u.volume.first_lba == partition.first_lba
                && u.volume.media.media_id == media.media_id
        })
        .map(|u| u.id)
}

fn register(volume: Volume, unattended: bool) -> VolumeId {
    let id = VolumeId(NEXT_ID.fetch_add(1, Ordering::Relaxed));
    VOLUMES.borrow_mut().push(Unlocked {
        id,
        volume,
        unattended,
    });
    id
}

/// Find and check the LUKS2 header of a partition: the primary copy, or a
/// secondary copy when the primary's magic is gone.
pub(crate) fn detect(
    part: &mut dyn RawPartition,
) -> Option<Result<(header::Header, Layout), LuksError>> {
    if !header::present(part) {
        return None;
    }
    Some(header::read(part).and_then(|header| {
        let layout = Layout::check(&header, part.len())?;
        Ok((header, layout))
    }))
}

/// Read the header of a partition on fixed media, if it is LUKS.
fn read_header(
    storage: StorageId,
    partition: &Partition,
    media: BlockDeviceInfo,
) -> Option<Result<(header::Header, Layout), LuksError>> {
    storage::with_disk(storage, |disk| {
        if !same_fixed_media(media, disk.info()) {
            return None;
        }
        detect(&mut DiskPartition::new(disk, partition).ok()?)
    })
    .ok()
    .flatten()
}

/// Open a keyslot and build the volume, on the disk the header came from.
fn open_volume(
    storage: StorageId,
    partition: &Partition,
    media: BlockDeviceInfo,
    found: &(header::Header, Layout),
    passphrase: &[u8],
    slots: volume::Slots<'_>,
    budget: &mut crypto::Budget,
) -> Result<Volume, LuksError> {
    let (header, layout) = found;
    let key = storage::with_disk(storage, |disk| {
        if !same_fixed_media(media, disk.info()) {
            return Err(LuksError::Io(BlockError::MediaChanged));
        }
        let mut part = DiskPartition::new(disk, partition)?;
        volume::open(&mut part, header, passphrase, slots, budget)
    })
    .map_err(LuksError::Io)??;
    Volume::new(storage, partition.first_lba, media, *layout, header, &key)
}

/// Identify a partition, unlocking it with the TPM when a token allows.
pub(crate) fn probe(device: &StorageDevice, partition: &Partition) -> Probe {
    if let Some(id) = registered(device.id, partition, device.info) {
        return Probe::Unlocked(id);
    }
    let found = match read_header(device.id, partition, device.info) {
        None => return Probe::Plain,
        Some(Ok(found)) => found,
        Some(Err(err)) => {
            log::warn!(
                "LUKS volume on {} partition {} cannot be opened: {err}",
                device.label,
                partition.number
            );
            return Probe::Unsupported;
        }
    };
    log::info!(
        "LUKS2 volume {} on {} partition {}",
        sanitize(&found.0.uuid, 40),
        device.label,
        partition.number
    );
    #[cfg(feature = "tpm")]
    if let Some(id) = try_tpm(device, partition, &found) {
        return Probe::Unlocked(id);
    }
    Probe::Locked {
        name: volume_name(&found.0),
    }
}

#[cfg(feature = "tpm")]
fn try_tpm(
    device: &StorageDevice,
    partition: &Partition,
    found: &(header::Header, Layout),
) -> Option<VolumeId> {
    // Code CrabEFI does not own has run: it must not see a TPM secret, and
    // the PCRs have left their pre-boot values anyway.
    if crate::preboot::has_ended() {
        return None;
    }
    let key = (device.id, partition.first_lba, found.0.uuid.clone());
    if TPM_TRIED.borrow().contains(&key) {
        return None;
    }
    TPM_TRIED.borrow_mut().push(key);
    // One budget for every token of the volume: nobody waits for this.
    let mut budget = crypto::Budget::new(crypto::Limits::UNATTENDED);
    // Try each token until one's secret opens a keyslot it names.
    let volume = tpm::unlock(&found.0, |slots, passphrase| {
        match open_volume(
            device.id,
            partition,
            device.info,
            found,
            passphrase,
            volume::Slots::Token(slots),
            &mut budget,
        ) {
            Ok(volume) => Some(volume),
            Err(err) => {
                log::warn!("LUKS2: TPM secret did not open a keyslot: {err}");
                None
            }
        }
    })?;
    log::info!(
        "LUKS2 volume {} unlocked with the TPM",
        sanitize(&volume.uuid, 40)
    );
    Some(register(volume, true))
}

/// Ask for a passphrase until the volume opens or the user gives up.
/// `disk` names the disk, from the firmware's view, not the volume's.
pub(crate) fn unlock_interactive(
    storage: StorageId,
    partition: &Partition,
    media: BlockDeviceInfo,
    disk: &str,
) -> bool {
    if registered(storage, partition, media).is_some() {
        return true;
    }
    // Code CrabEFI does not own may have hooked the keyboard or the screen.
    if crate::preboot::has_ended() {
        log::warn!("LUKS2: other boot code ran since power-on; not asking for a passphrase");
        prompt::show_refusal();
        return false;
    }
    let found = match read_header(storage, partition, media) {
        Some(Ok(found)) => found,
        _ => {
            log::error!("LUKS2: the volume is gone or no longer readable");
            return false;
        }
    };
    let mut place = String::new();
    let _ = write!(place, "{disk}, partition {}", partition.number);
    let name = volume_name(&found.0);
    let mut error = None;
    for _ in 0..3 {
        let passphrase = prompt::read_passphrase(&name, &place, error);
        let Some(passphrase) = passphrase else {
            return false;
        };
        prompt::show_progress("Unlocking...");
        let result = open_volume(
            storage,
            partition,
            media,
            &found,
            passphrase.as_bytes(),
            volume::Slots::Any,
            &mut crypto::Budget::new(volume::Slots::Any.limits()),
        );
        drop(passphrase);
        match result {
            Ok(volume) => {
                log::info!(
                    "LUKS2 volume {} unlocked with a passphrase",
                    sanitize(&volume.uuid, 40)
                );
                register(volume, false);
                return true;
            }
            Err(LuksError::WrongKey) => {
                log::warn!("LUKS2: no keyslot opens with this passphrase");
                error = Some("No key available with this passphrase.");
            }
            Err(LuksError::Unsupported(what)) => {
                log::error!("LUKS2: unlocking refused: {what}");
                error = Some("This volume's keyslots are beyond the firmware's limits.");
            }
            Err(err) => {
                log::error!("LUKS2: unlocking failed: {err}");
                error = Some("Unlocking failed; see the log.");
            }
        }
    }
    false
}

/// A menu title for a locked volume.
pub(crate) fn unlock_title(name: &str, device: &StorageDevice, partition: &Partition) -> String {
    let mut title = String::new();
    let _ = write!(
        title,
        "Unlock {name} ({}, partition {})",
        device.label, partition.number
    );
    title
}

/// Whether a volume was unlocked without a person present (by the TPM).
/// Its boot entries must then boot as configured: an edited command line
/// (`init=/bin/sh`) would hand the unattended unlock to whoever is at the
/// keyboard.
pub(crate) fn unlocked_unattended(id: VolumeId) -> bool {
    VOLUMES.borrow().iter().any(|u| u.id == id && u.unattended)
}

/// Read decrypted data of an unlocked volume.
pub(crate) fn read(
    id: VolumeId,
    disk: &mut dyn BlockDevice,
    range: &BlockRange,
    offset: u64,
    out: &mut [u8],
) -> Result<(), BlockError> {
    let volumes = VOLUMES.borrow();
    let unlocked = volumes
        .iter()
        .find(|u| u.id == id)
        .ok_or(BlockError::NoMedia)?;
    unlocked.volume.read(disk, range, offset, out)
}

/// Decrypted length of an unlocked volume.
pub(crate) fn data_len(id: VolumeId) -> Option<u64> {
    VOLUMES
        .borrow()
        .iter()
        .find(|u| u.id == id)
        .map(|u| u.volume.layout.len)
}

#[cfg(feature = "luks-test-post-cap")]
pub(crate) use tpm::check_refused_after_cap;

/// Wipe every volume key on a fatal error: no allocation, no waiting for a
/// borrow. The keys' memory is cleared and then abandoned.
pub(crate) fn emergency_wipe() {
    if let Some(mut volumes) = VOLUMES.try_borrow_mut() {
        for unlocked in volumes.iter_mut() {
            unlocked.volume.wipe_in_place();
        }
        // The cleared ciphers must not be dropped again.
        core::mem::forget(core::mem::take(&mut *volumes));
    }
}

/// Wipe every volume key. Their handles stop resolving.
pub(crate) fn wipe_keys() {
    let wiped = core::mem::take(&mut *VOLUMES.borrow_mut());
    if !wiped.is_empty() {
        log::info!("LUKS2: wiping {} volume key(s)", wiped.len());
    }
    drop(wiped);
}

//! Unlock real cryptsetup volumes.
//!
//! These tests run `cryptsetup reencrypt --encrypt` offline, which needs no
//! root or device mapper. Without cryptsetup they are skipped, unless
//! `CRABEFI_REQUIRE_CRYPTSETUP=1` (CI) makes that a failure.

use std::path::Path;
use std::process::Command;
use std::vec::Vec;

use super::*;

const PASSPHRASE: &str = "correct horse";
const MIB: usize = 1 << 20;

struct MemDisk(Vec<u8>);

impl BlockDevice for MemDisk {
    fn info(&self) -> BlockDeviceInfo {
        BlockDeviceInfo {
            num_blocks: (self.0.len() / 512) as u64,
            block_size: 512,
            media_id: 1,
            removable: false,
            read_only: true,
        }
    }

    fn read_blocks(&mut self, lba: u64, count: u32, out: &mut [u8]) -> Result<(), BlockError> {
        self.validate_read(lba, count, out)?;
        let start = lba as usize * 512;
        out.copy_from_slice(&self.0[start..start + out.len()]);
        Ok(())
    }
}

impl RawPartition for (&mut MemDisk, BlockRange) {
    fn read(&mut self, offset: u64, out: &mut [u8]) -> Result<(), BlockError> {
        self.1.read(self.0, offset, out)
    }

    fn len(&self) -> u64 {
        self.0.0.len() as u64
    }
}

fn cryptsetup_available() -> bool {
    let found = Command::new("cryptsetup")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success());
    if !found {
        assert!(
            std::env::var_os("CRABEFI_REQUIRE_CRYPTSETUP").is_none(),
            "cryptsetup is required (CRABEFI_REQUIRE_CRYPTSETUP is set)"
        );
        std::eprintln!("cryptsetup not found; skipping LUKS2 interoperability test");
    }
    found
}

/// Plaintext that differs in every 16-byte block, so a wrong IV shows.
fn pattern(len: usize) -> Vec<u8> {
    (0..len / 4)
        .flat_map(|i| (i as u32).wrapping_mul(2654435761).to_le_bytes())
        .collect()
}

/// Encrypt `plain` in place with cryptsetup and return the image.
fn encrypt(dir: &Path, plain: &[u8], extra: &[&str]) -> Vec<u8> {
    let image = dir.join("luks.img");
    let key = dir.join("key");
    std::fs::write(&image, plain).unwrap();
    std::fs::write(&key, PASSPHRASE).unwrap();
    let status = Command::new("cryptsetup")
        .args([
            "reencrypt",
            "--batch-mode",
            "--disable-locks",
            "--encrypt",
            "--type",
            "luks2",
            "--reduce-device-size",
            "4M",
            "--luks2-keyslots-size",
            "1M",
            "--key-file",
        ])
        .arg(&key)
        .args(extra)
        .arg(&image)
        .status()
        .expect("run cryptsetup");
    assert!(status.success(), "cryptsetup failed: {status}");
    std::fs::read(&image).unwrap()
}

fn unlock(image: Vec<u8>, passphrase: &str) -> Result<(MemDisk, Volume), LuksError> {
    let mut disk = MemDisk(image);
    let range = BlockRange::new(&disk, 0, disk.info().num_blocks).unwrap();
    let mut part = (&mut disk, range);
    let header = header::read(&mut part)?;
    let layout = Layout::check(&header, part.len())?;
    let key = volume::open(
        &mut part,
        &header,
        passphrase.as_bytes(),
        volume::Slots::Any,
        &mut crypto::Budget::new(crypto::Limits::INTERACTIVE),
    )?;
    let info = disk.info();
    let volume = Volume::new(
        StorageId::Platform { index: 0 },
        0,
        info,
        layout,
        &header,
        &key,
    )?;
    Ok((disk, volume))
}

fn check(extra: &[&str]) {
    if !cryptsetup_available() {
        return;
    }
    let dir = tempfile_dir();
    let plain = pattern(8 * MIB);
    let image = encrypt(&dir, &plain, extra);
    assert!(matches!(
        unlock(image.clone(), "wrong"),
        Err(LuksError::WrongKey)
    ));
    let (mut disk, volume) = unlock(image, PASSPHRASE).unwrap();
    let range = BlockRange::new(&disk, 0, disk.info().num_blocks).unwrap();
    // The dynamic segment runs to the end of the partition; cryptsetup
    // keeps the first `size - reduce-device-size` bytes of the old data.
    let len = volume.layout.len as usize;
    let kept = plain.len() - 4 * MIB;
    assert!(len >= kept);
    // Aligned bulk, unaligned head and tail, and the last kept byte.
    let mut out = alloc::vec![0u8; kept];
    volume.read(&mut disk, &range, 0, &mut out).unwrap();
    assert!(out == plain[..kept], "decrypted data differs");
    let mut out = alloc::vec![0u8; 10_000];
    volume.read(&mut disk, &range, 4093, &mut out).unwrap();
    assert!(out == plain[4093..14_093], "unaligned read differs");
    let mut out = [0u8; 1];
    volume
        .read(&mut disk, &range, kept as u64 - 1, &mut out)
        .unwrap();
    assert_eq!(out[0], plain[kept - 1]);
    volume
        .read(&mut disk, &range, len as u64 - 1, &mut out)
        .unwrap();
    assert_eq!(
        volume.read(&mut disk, &range, len as u64, &mut out),
        Err(BlockError::OutOfRange)
    );
    std::fs::remove_dir_all(dir).unwrap();
}

fn tempfile_dir() -> std::path::PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let dir = std::env::temp_dir().join(std::format!(
        "crabefi-luks-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn pbkdf2_sha512_aes128_512_byte_sectors() {
    check(&[
        "--pbkdf",
        "pbkdf2",
        "--pbkdf-force-iterations",
        "1000",
        "--hash",
        "sha512",
        "--key-size",
        "256",
        "--sector-size",
        "512",
    ]);
}

#[test]
fn argon2id_aes256_4k_sectors() {
    check(&[
        "--pbkdf",
        "argon2id",
        "--pbkdf-memory",
        "32768",
        "--pbkdf-force-iterations",
        "4",
        "--pbkdf-parallel",
        "2",
        "--sector-size",
        "4096",
    ]);
}

#[test]
fn argon2i_keyslot() {
    check(&[
        "--pbkdf",
        "argon2i",
        "--pbkdf-memory",
        "32768",
        "--pbkdf-force-iterations",
        "4",
    ]);
}

#[test]
fn damaged_primary_header_falls_back_to_the_secondary() {
    if !cryptsetup_available() {
        return;
    }
    let dir = tempfile_dir();
    let plain = pattern(8 * MIB);
    let mut image = encrypt(
        &dir,
        &plain,
        &["--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"],
    );
    image[4096 + 10] ^= 0xff; // JSON of the primary copy
    let (mut disk, volume) = unlock(image, PASSPHRASE).unwrap();
    let range = BlockRange::new(&disk, 0, disk.info().num_blocks).unwrap();
    let mut out = [0u8; 4096];
    volume.read(&mut disk, &range, 0, &mut out).unwrap();
    assert_eq!(out[..], plain[..4096]);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn production_detection_survives_a_missing_primary_header() {
    if !cryptsetup_available() {
        return;
    }
    let dir = tempfile_dir();
    let plain = pattern(8 * MIB);
    let mut image = encrypt(
        &dir,
        &plain,
        &["--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"],
    );
    // Wipe the primary copy's magic: probing must still find LUKS2.
    image[..6].fill(0);
    let mut disk = MemDisk(image);
    let range = BlockRange::new(&disk, 0, disk.info().num_blocks).unwrap();
    let (header, _) = detect(&mut (&mut disk, range)).unwrap().unwrap();
    let key = volume::open(
        &mut (&mut disk, range),
        &header,
        PASSPHRASE.as_bytes(),
        volume::Slots::Any,
        &mut crypto::Budget::new(crypto::Limits::INTERACTIVE),
    );
    assert!(key.is_ok());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn iv_tweak_must_keep_every_iv_in_range() {
    if !cryptsetup_available() {
        return;
    }
    let dir = tempfile_dir();
    let image = encrypt(
        &dir,
        &pattern(8 * MIB),
        &["--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"],
    );
    let mut disk = MemDisk(image);
    let range = BlockRange::new(&disk, 0, disk.info().num_blocks).unwrap();
    let mut header = header::read(&mut (&mut disk, range)).unwrap();
    let segment = header.metadata.segments.get("0").unwrap().get();
    let patched = segment.replace(
        "\"iv_tweak\":\"0\"",
        "\"iv_tweak\":\"18446744073709551000\"",
    );
    assert_ne!(segment, patched);
    header.metadata.segments.insert(
        "0".into(),
        serde_json::value::RawValue::from_string(patched).unwrap(),
    );
    let len = disk.0.len() as u64;
    assert!(matches!(
        Layout::check(&header, len),
        Err(LuksError::Unsupported("IV tweak"))
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejects_non_luks2_and_corrupt_headers() {
    let mut disk = MemDisk(alloc::vec![0u8; MIB]);
    let range = BlockRange::new(&disk, 0, disk.info().num_blocks).unwrap();
    assert!(header::read(&mut (&mut disk, range)).is_err());
    assert!(detect(&mut (&mut disk, range)).is_none());
    // LUKS1 magic with version 1: LUKS, but not openable.
    disk.0[..8].copy_from_slice(b"LUKS\xba\xbe\x00\x01");
    assert!(matches!(detect(&mut (&mut disk, range)), Some(Err(_))));
}

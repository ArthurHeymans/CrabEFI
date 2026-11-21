//! LUKS2 cryptography: key derivation, anti-forensic merge and AES-XTS.

use aes::cipher::KeyInit;
use aes::{Aes128, Aes256};
use alloc::vec::Vec;
use base64::Engine as _;
use sha2::{Digest, Sha256, Sha512};
use xts_mode::Xts128;
use zeroize::Zeroizing;

use super::LuksError;
use super::header::Kdf;

pub(crate) type Secret = Zeroizing<Vec<u8>>;

const MAX_ARGON2_LANES: u32 = 16;
/// Bound digest PBKDF2 so a forged header cannot stall the firmware for
/// hours. cryptsetup's benchmark stays far below this.
const MAX_PBKDF2_ITERATIONS: u32 = 100_000_000;
const GIB_IN_KIB: u64 = 1024 * 1024;

/// Key derivation work the firmware accepts for one keyslot, and in total
/// for one unlock attempt. A forged header must fail fast, not stall the
/// boot or exhaust memory.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pbkdf2_iterations: u32,
    argon2_memory_kib: u64,
    /// Memory times passes, in KiB.
    argon2_work_kib: u64,
}

impl Limits {
    /// Typed passphrases: what cryptsetup can create (4 GiB of memory),
    /// up to 64 GiB of total Argon2 memory traffic.
    pub(crate) const INTERACTIVE: Self = Self {
        pbkdf2_iterations: MAX_PBKDF2_ITERATIONS,
        argon2_memory_kib: 4 * GIB_IN_KIB,
        argon2_work_kib: 64 * GIB_IN_KIB,
    };
    /// Token secrets, during discovery: systemd uses 1000 PBKDF2 rounds for
    /// keyslots and cryptsetup benchmarks digests to well under a million,
    /// since the secret already has full entropy.
    pub(crate) const UNATTENDED: Self = Self {
        pbkdf2_iterations: 4_000_000,
        argon2_memory_kib: GIB_IN_KIB / 4,
        argon2_work_kib: GIB_IN_KIB,
    };
}

/// What remains of an attempt's key derivation work: the per-keyslot
/// [`Limits`], and a total across keyslots, digests and tokens of four
/// times that.
pub(crate) struct Budget {
    limits: Limits,
    pbkdf2_left: u64,
    argon2_left: u64,
}

impl Budget {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            limits,
            pbkdf2_left: 4 * u64::from(limits.pbkdf2_iterations),
            argon2_left: 4 * limits.argon2_work_kib,
        }
    }

    fn pbkdf2(&mut self, iterations: u32) -> Result<(), LuksError> {
        let cost = u64::from(iterations);
        if iterations > self.limits.pbkdf2_iterations || cost > self.pbkdf2_left {
            log::warn!("LUKS2: PBKDF2 with {iterations} iterations exceeds the limits");
            return Err(LuksError::Unsupported("PBKDF2 cost"));
        }
        self.pbkdf2_left -= cost;
        Ok(())
    }

    fn argon2(&mut self, time: u32, memory: u32) -> Result<(), LuksError> {
        let work = u64::from(memory) * u64::from(time);
        if u64::from(memory) > self.limits.argon2_memory_kib
            || work > self.limits.argon2_work_kib
            || work > self.argon2_left
        {
            log::warn!("LUKS2: Argon2 with {memory} KiB x {time} passes exceeds the limits");
            return Err(LuksError::Unsupported("Argon2 cost"));
        }
        self.argon2_left -= work;
        Ok(())
    }
}

pub(crate) fn base64(text: &str) -> Result<Vec<u8>, LuksError> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| LuksError::Corrupt("bad base64"))
}

pub(crate) fn secret(len: usize) -> Result<Secret, LuksError> {
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| LuksError::OutOfMemory)?;
    out.resize(len, 0);
    Ok(Zeroizing::new(out))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hash {
    Sha256,
    Sha512,
}

impl Hash {
    pub(crate) fn parse(name: &str) -> Result<Self, LuksError> {
        match name {
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => Err(LuksError::Unsupported("hash algorithm")),
        }
    }

    fn pbkdf2(self, password: &[u8], salt: &[u8], rounds: u32, out: &mut [u8]) {
        match self {
            Self::Sha256 => pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, rounds, out),
            Self::Sha512 => pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, rounds, out),
        }
    }
}

/// Run a keyslot or digest PBKDF2, charged to `budget`.
pub(crate) fn pbkdf2(
    hash: Hash,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
    budget: &mut Budget,
) -> Result<(), LuksError> {
    if iterations == 0 {
        return Err(LuksError::Corrupt("PBKDF2 iteration count"));
    }
    budget.pbkdf2(iterations)?;
    hash.pbkdf2(password, salt, iterations, out);
    Ok(())
}

/// Derive a keyslot key from a passphrase, charged to `budget`.
pub(crate) fn derive(
    kdf: &Kdf,
    passphrase: &[u8],
    len: usize,
    budget: &mut Budget,
) -> Result<Secret, LuksError> {
    let mut key = secret(len)?;
    let missing = || LuksError::Corrupt("KDF parameters");
    match kdf.kind.as_str() {
        "pbkdf2" => pbkdf2(
            Hash::parse(kdf.hash.as_deref().ok_or_else(missing)?)?,
            passphrase,
            &base64(&kdf.salt)?,
            kdf.iterations.ok_or_else(missing)?,
            &mut key,
            budget,
        )?,
        kind @ ("argon2i" | "argon2id") => {
            let time = kdf.time.ok_or_else(missing)?;
            let memory = kdf.memory.ok_or_else(missing)?;
            budget.argon2(time, memory)?;
            let algorithm = if kind == "argon2i" {
                argon2::Algorithm::Argon2i
            } else {
                argon2::Algorithm::Argon2id
            };
            argon2(
                algorithm,
                passphrase,
                &base64(&kdf.salt)?,
                (time, memory, kdf.cpus.ok_or_else(missing)?),
                &mut key,
            )?;
        }
        _ => return Err(LuksError::Unsupported("KDF type")),
    }
    Ok(key)
}

/// Firmware pages for Argon2: up to 4 GiB is far too large for the heap.
/// The pages are cleared before they are returned.
#[cfg(not(test))]
struct ArgonMemory {
    pages: &'static mut [u8],
    count: u64,
}

#[cfg(test)]
struct ArgonMemory(Vec<argon2::Block>);

#[cfg(test)]
impl ArgonMemory {
    fn new(kib: u32) -> Result<Self, LuksError> {
        Ok(Self(alloc::vec![argon2::Block::new(); kib as usize]))
    }

    fn blocks(&mut self, count: usize) -> &mut [argon2::Block] {
        &mut self.0[..count]
    }
}

#[cfg(not(test))]
impl ArgonMemory {
    fn new(kib: u32) -> Result<Self, LuksError> {
        let bytes = u64::from(kib) * 1024;
        let count = bytes.div_ceil(crate::efi::allocator::PAGE_SIZE);
        let pages = crate::efi::allocate_pages(count).ok_or_else(|| {
            log::error!("LUKS2: cannot allocate {} MiB for Argon2", bytes >> 20);
            LuksError::OutOfMemory
        })?;
        Ok(Self { pages, count })
    }

    fn blocks(&mut self, count: usize) -> &mut [argon2::Block] {
        let bytes = count * argon2::Block::SIZE;
        assert!(bytes <= self.pages.len());
        // SAFETY: the allocation is page aligned, which covers Block's
        // 64-byte alignment; any bit pattern is a valid Block.
        unsafe {
            core::slice::from_raw_parts_mut(self.pages.as_mut_ptr().cast::<argon2::Block>(), count)
        }
    }
}

#[cfg(not(test))]
impl Drop for ArgonMemory {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut *self.pages);
        crate::efi::free_pages(self.pages, self.count);
    }
}

fn argon2(
    algorithm: argon2::Algorithm,
    passphrase: &[u8],
    salt: &[u8],
    (time, memory, cpus): (u32, u32, u32),
    out: &mut [u8],
) -> Result<(), LuksError> {
    if !(1..=MAX_ARGON2_LANES).contains(&cpus) {
        return Err(LuksError::Unsupported("Argon2 parameters"));
    }
    let params = argon2::Params::new(memory, time, cpus, Some(out.len()))
        .map_err(|_| LuksError::Unsupported("Argon2 parameters"))?;
    let mut pages = ArgonMemory::new(memory)?;
    argon2::Argon2::new(algorithm, argon2::Version::V0x13, params.clone())
        .hash_password_into_with_memory(passphrase, salt, out, pages.blocks(params.block_count()))
        .map_err(|_| LuksError::Unsupported("Argon2 parameters"))
}

/// The LUKS anti-forensic merge (`AF_merge`): recover a key of
/// `key_size` bytes from `material.len() / key_size` stripes.
pub(crate) fn af_merge(material: &[u8], key_size: usize, hash: Hash) -> Result<Secret, LuksError> {
    let stripes = material.len() / key_size;
    if key_size == 0 || stripes == 0 || !material.len().is_multiple_of(key_size) {
        return Err(LuksError::Corrupt("keyslot material"));
    }
    let mut block = secret(key_size)?;
    for stripe in material.chunks_exact(key_size).take(stripes - 1) {
        xor(&mut block, stripe);
        diffuse(&mut block, hash);
    }
    xor(&mut block, &material[(stripes - 1) * key_size..]);
    Ok(block)
}

fn xor(out: &mut [u8], data: &[u8]) {
    for (out, data) in out.iter_mut().zip(data) {
        *out ^= data;
    }
}

fn diffuse(block: &mut [u8], hash: Hash) {
    fn run<D: Digest>(block: &mut [u8]) {
        let size = <D as Digest>::output_size();
        for (index, chunk) in block.chunks_mut(size).enumerate() {
            let mut digest = D::new();
            digest.update((index as u32).to_be_bytes());
            digest.update(&*chunk);
            let mut out = digest.finalize();
            chunk.copy_from_slice(&out[..chunk.len()]);
            zeroize::Zeroize::zeroize(out.as_mut_slice());
        }
    }
    match hash {
        Hash::Sha256 => run::<Sha256>(block),
        Hash::Sha512 => run::<Sha512>(block),
    }
}

/// AES-XTS with the `plain64` IV: the little-endian sector number.
/// Volumes keep it boxed, so the variant size difference does not matter.
#[allow(clippy::large_enum_variant)]
pub(crate) enum XtsCipher {
    Aes128(Xts128<Aes128>),
    Aes256(Xts128<Aes256>),
}

impl XtsCipher {
    /// Only `aes-xts-plain64` with 256- or 512-bit keys is supported.
    pub(crate) fn new(spec: &str, key: &[u8]) -> Result<Self, LuksError> {
        if spec != "aes-xts-plain64" {
            return Err(LuksError::Unsupported("cipher (only aes-xts-plain64)"));
        }
        let (k1, k2) = key.split_at(key.len() / 2);
        match key.len() {
            32 => Ok(Self::Aes128(Xts128::new(
                Aes128::new_from_slice(k1).unwrap(),
                Aes128::new_from_slice(k2).unwrap(),
            ))),
            64 => Ok(Self::Aes256(Xts128::new(
                Aes256::new_from_slice(k1).unwrap(),
                Aes256::new_from_slice(k2).unwrap(),
            ))),
            _ => Err(LuksError::Unsupported("XTS key size")),
        }
    }

    /// Decrypt whole sectors in place. The first sector has IV `first`, and
    /// each following one `step` more (LUKS2 counts IVs in 512-byte units).
    pub(crate) fn decrypt(&self, data: &mut [u8], sector_size: usize, first: u64, step: u64) {
        debug_assert_eq!(data.len() % sector_size, 0);
        let tweak = |i: u128| xts_mode::get_tweak_default(u128::from(first) + i * u128::from(step));
        match self {
            Self::Aes128(xts) => xts.decrypt_area(data, sector_size, 0, tweak),
            Self::Aes256(xts) => xts.decrypt_area(data, sector_size, 0, tweak),
        }
    }

    #[cfg(test)]
    pub(crate) fn encrypt(&self, data: &mut [u8], sector_size: usize, first: u64) {
        let tweak = xts_mode::get_tweak_default;
        match self {
            Self::Aes128(xts) => xts.encrypt_area(data, sector_size, first.into(), tweak),
            Self::Aes256(xts) => xts.encrypt_area(data, sector_size, first.into(), tweak),
        }
    }
}

/// Compare secrets without leaking where they differ.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn xts_matches_ieee_1619_vector_10() {
        // IEEE P1619/D16 vector 10: AES-256-XTS, data unit sequence 0xff.
        let key = hex(concat!(
            "2718281828459045235360287471352662497757247093699959574966967627",
            "3141592653589793238462643383279502884197169399375105820974944592"
        ));
        let plain: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
        let cipher = XtsCipher::new("aes-xts-plain64", &key).unwrap();
        let mut data = plain.clone();
        cipher.encrypt(&mut data, 512, 0xff);
        assert_eq!(
            &data[..32],
            &hex("1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b")[..]
        );
        cipher.decrypt(&mut data, 512, 0xff, 1);
        assert_eq!(data, plain);
    }

    #[test]
    fn af_merge_inverts_split() {
        // Split a key the way cryptsetup does: random stripes, then the
        // last stripe chosen so the merge yields the key.
        let key: Vec<u8> = (0..64u8).collect();
        let stripes = 5;
        let mut material: Vec<u8> = (0..64 * stripes).map(|i| (i * 7 + 3) as u8).collect();
        let mut block = alloc::vec![0u8; 64];
        for stripe in material.chunks_exact(64).take(stripes - 1) {
            xor(&mut block, stripe);
            diffuse(&mut block, Hash::Sha256);
        }
        for (out, (b, k)) in material[64 * (stripes - 1)..]
            .iter_mut()
            .zip(block.iter().zip(&key))
        {
            *out = b ^ k;
        }
        assert_eq!(
            &af_merge(&material, 64, Hash::Sha256).unwrap()[..],
            &key[..]
        );
        assert_ne!(
            &af_merge(&material, 64, Hash::Sha512).unwrap()[..],
            &key[..]
        );
    }

    #[test]
    fn kdf_costs_are_bounded_per_keyslot_and_in_total() {
        let argon = |time, memory| Kdf {
            kind: "argon2id".into(),
            salt: "AAAAAAAAAAA=".into(),
            hash: None,
            iterations: None,
            time: Some(time),
            memory: Some(memory),
            cpus: Some(1),
        };
        // Refused before allocating 4 GiB or running 2^32 passes.
        for (time, memory) in [(4, 4 << 20), (u32::MAX, 1024), (8, 256 << 10)] {
            assert!(matches!(
                derive(
                    &argon(time, memory),
                    b"x",
                    32,
                    &mut Budget::new(Limits::UNATTENDED)
                ),
                Err(LuksError::Unsupported(_))
            ));
        }
        assert!(matches!(
            derive(
                &argon(u32::MAX, 1024),
                b"x",
                32,
                &mut Budget::new(Limits::INTERACTIVE)
            ),
            Err(LuksError::Unsupported(_))
        ));
        // Digests share the attempt's total.
        let mut budget = Budget::new(Limits::UNATTENDED);
        let mut out = [0u8; 32];
        for _ in 0..4 {
            budget.pbkdf2(4_000_000).unwrap();
        }
        assert!(pbkdf2(Hash::Sha256, b"x", b"salt", 1, &mut out, &mut budget).is_err());
    }

    #[test]
    fn pbkdf2_is_bounded() {
        let mut budget = Budget::new(Limits::INTERACTIVE);
        let mut out = [0u8; 32];
        assert!(pbkdf2(Hash::Sha256, b"x", b"salt", 0, &mut out, &mut budget).is_err());
        assert!(pbkdf2(Hash::Sha256, b"x", b"salt", u32::MAX, &mut out, &mut budget).is_err());
        // RFC 7914 section 11 (PBKDF2-HMAC-SHA256, c = 1).
        let mut out = [0u8; 64];
        pbkdf2(Hash::Sha256, b"passwd", b"salt", 1, &mut out, &mut budget).unwrap();
        assert_eq!(&out[..16], &hex("55ac046e56e3089fec1691c22544b605")[..]);
    }
}

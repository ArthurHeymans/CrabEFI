//! `systemd-tpm2` LUKS2 tokens, as enrolled by `systemd-cryptenroll`.
//!
//! The token holds an object sealed under the TPM's storage root key (SRK,
//! persistent handle from `tpm2_srk`) with a PCR policy. CrabEFI loads it,
//! satisfies the policy with `TPM2_PolicyPCR`, and unseals it in a policy
//! session salted to the SRK with response encryption, so the secret never
//! crosses the TPM bus in clear. As in systemd, the keyslot passphrase is the
//! base64 encoding of the unsealed secret.
//!
//! Supported: SHA-256 name algorithms, an ECC NIST P-256 SRK, and PCR
//! policies in any bank. Not supported (the token is skipped): TPM2 PINs,
//! signed PCR policies (`tpm2_pubkey`), pcrlock policies, and tokens
//! without a recorded SRK (systemd before v254).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use base64::Engine as _;
use hmac::{KeyInit, Mac};
use serde::Deserialize;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::crypto;
use super::header::{Header, bounded_list};

type HmacSha256 = hmac::Hmac<Sha256>;

const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_ST_SESSIONS: u16 = 0x8002;
const TPM_CC_LOAD: u32 = 0x157;
const TPM_CC_UNSEAL: u32 = 0x15E;
const TPM_CC_FLUSH_CONTEXT: u32 = 0x165;
const TPM_CC_READ_PUBLIC: u32 = 0x173;
const TPM_CC_START_AUTH_SESSION: u32 = 0x176;
const TPM_CC_POLICY_PCR: u32 = 0x17F;
const TPM_RH_NULL: u32 = 0x4000_0007;
const TPM_RS_PW: u32 = 0x4000_0009;
const TPM_SE_POLICY: u8 = 0x01;
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_SHA1: u16 = 0x0004;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_SHA384: u16 = 0x000C;
const TPM_ALG_SHA512: u16 = 0x000D;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_CFB: u16 = 0x0043;
const TPM_ECC_NIST_P256: u16 = 0x0003;
const TPMA_SESSION_ENCRYPT: u8 = 0x40;
const PERSISTENT_FIRST: u32 = 0x8100_0000;
const PERSISTENT_LAST: u32 = 0x81FF_FFFF;
const RESPONSE_SIZE: usize = 4096;

#[derive(Debug)]
enum TpmError {
    /// No hardware TPM 2.0 is available.
    Absent,
    Transport,
    /// The TPM rejected a command; the response code.
    Rc(u32, &'static str),
    Malformed(&'static str),
    Unsupported(&'static str),
    /// The SRK at the token's handle is not the key the token was sealed to.
    WrongSrk,
    /// The response was not authenticated by the session.
    BadResponseHmac,
    NoRandom,
}

impl core::fmt::Display for TpmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Absent => f.write_str("no TPM 2.0"),
            Self::Transport => f.write_str("TPM transport error"),
            Self::Rc(rc, what) => write!(f, "TPM2_{what} failed with {rc:#x}"),
            Self::Malformed(what) => write!(f, "malformed {what}"),
            Self::Unsupported(what) => write!(f, "unsupported {what}"),
            Self::WrongSrk => f.write_str("the TPM holds a different storage root key"),
            Self::BadResponseHmac => f.write_str("TPM response failed authentication"),
            Self::NoRandom => f.write_str("no working random number source"),
        }
    }
}

/// A `systemd-tpm2` token; [`TokenType`] checked the type. Lists are
/// bounded and the blob stays text until used.
#[derive(Deserialize)]
struct Token {
    #[serde(deserialize_with = "bounded_list::<_, _, 32>")]
    keyslots: Vec<String>,
    #[serde(rename = "tpm2-blob")]
    blob: Box<RawValue>,
    #[serde(
        rename = "tpm2-pcrs",
        default,
        deserialize_with = "bounded_list::<_, _, 24>"
    )]
    pcrs: Vec<u32>,
    #[serde(rename = "tpm2-pcr-bank", default)]
    bank: Option<String>,
    #[serde(rename = "tpm2-pin", default)]
    pin: bool,
    #[serde(rename = "tpm2_srk", default)]
    srk: Option<String>,
    #[serde(rename = "tpm2_pubkey", default)]
    pubkey: Option<String>,
    #[serde(
        rename = "tpm2_pubkey_pcrs",
        default,
        deserialize_with = "bounded_list::<_, _, 24>"
    )]
    pubkey_pcrs: Vec<u32>,
    #[serde(rename = "tpm2_pcrlock", default)]
    pcrlock: bool,
}

#[derive(Deserialize)]
struct TokenType {
    #[serde(rename = "type")]
    kind: String,
}

/// The token that unlocked a volume, kept to check after the separators
/// that the TPM refuses it (`luks-test-post-cap`).
#[cfg(feature = "luks-test-post-cap")]
static UNSEALED: crate::cell::Local<Option<String>> = crate::cell::Local::new(None);

/// Try each `systemd-tpm2` token in turn: unseal it and hand the keyslots
/// it names and the keyslot passphrase to `open`, until `open` succeeds.
/// Every secret is wiped after its attempt.
pub(super) fn unlock<T>(
    header: &Header,
    mut open: impl FnMut(&[String], &[u8]) -> Option<T>,
) -> Option<T> {
    // PCR 7 has its separator from startup in UEFI mode; PCRs 0-6 get
    // theirs when the trusted phase ends.
    if crate::efi::tcg::measured_boot::separators_measured(0x7F) {
        log::info!("LUKS2: PCRs 0-6 already left the pre-boot state; skipping TPM tokens");
        return None;
    }
    // Tokens are parsed one at a time, from their own JSON text.
    for (id, raw) in &header.metadata.tokens {
        let is_tpm2 = serde_json::from_str::<TokenType>(raw.get())
            .is_ok_and(|token| token.kind == "systemd-tpm2");
        if !is_tpm2 {
            continue;
        }
        let token = match serde_json::from_str::<Token>(raw.get()) {
            Ok(token) => token,
            Err(err) => {
                log::warn!("LUKS2 token {id}: malformed systemd-tpm2 token: {err}");
                continue;
            }
        };
        let secret = match unseal_token(&token) {
            Ok(secret) => secret,
            Err(TpmError::Absent) => {
                log::info!("LUKS2: no TPM 2.0 for token {id}");
                return None;
            }
            Err(err) => {
                log::warn!("LUKS2 token {id}: TPM unseal failed: {err}");
                continue;
            }
        };
        log::info!("LUKS2 token {id}: unsealed by the TPM");
        // systemd uses the base64 encoding as the keyslot passphrase.
        let passphrase = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .encode(&*secret)
                .into_bytes(),
        );
        drop(secret);
        if let Some(opened) = open(&token.keyslots, &passphrase) {
            #[cfg(feature = "luks-test-post-cap")]
            {
                *UNSEALED.borrow_mut() = Some(raw.get().into());
            }
            return Some(opened);
        }
    }
    None
}

/// Test only: try the token that unlocked a volume again, after the
/// separators. A TPM that still unseals it would leak it to the OS.
#[cfg(feature = "luks-test-post-cap")]
pub(crate) fn check_refused_after_cap() {
    let Some(raw) = UNSEALED.borrow_mut().take() else {
        return;
    };
    let Ok(token) = serde_json::from_str::<Token>(&raw) else {
        return;
    };
    // Only the PCR policy failing at Unseal shows the cap worked; any other
    // error (no RNG, transport) proves nothing.
    const TPM_RC_POLICY_FAIL: u32 = 0x09D;
    match unseal_token(&token) {
        Err(TpmError::Rc(rc, "Unseal")) if rc & 0xFF == TPM_RC_POLICY_FAIL => log::info!(
            "LUKS2 test: the TPM refuses the token after the separators: policy failure {rc:#x}"
        ),
        Ok(_) => log::error!("LUKS2 test: the TPM still unseals the token after the separators"),
        Err(err) => log::error!("LUKS2 test: post-cap unseal failed inconclusively: {err}"),
    }
}

fn unseal_token(token: &Token) -> Result<Zeroizing<Vec<u8>>, TpmError> {
    if token.pin {
        return Err(TpmError::Unsupported("TPM2 PIN"));
    }
    if token.pubkey.as_deref().is_some_and(|key| !key.is_empty()) || !token.pubkey_pcrs.is_empty() {
        return Err(TpmError::Unsupported("signed PCR policy"));
    }
    if token.pcrlock {
        return Err(TpmError::Unsupported("pcrlock policy"));
    }
    // One blob, as a string or a one-element array (newer systemd).
    let blob = serde_json::from_str::<String>(token.blob.get())
        .or_else(|_| serde_json::from_str::<[String; 1]>(token.blob.get()).map(|[blob]| blob))
        .map_err(|_| TpmError::Unsupported("tpm2-blob (several sealed blobs)"))?;
    let blob = decode(&blob)?;
    let mut reader = Reader::new(&blob);
    let private = reader.tpm2b_raw()?;
    let public = reader.tpm2b_raw()?;
    let sealed_name = name_of(&public[2..])?;

    let srk = Srk::parse(&decode(
        token
            .srk
            .as_deref()
            .ok_or(TpmError::Unsupported("token without tpm2_srk"))?,
    )?)?;
    let bank = match token.bank.as_deref().unwrap_or("sha256") {
        "sha1" => TPM_ALG_SHA1,
        "sha256" => TPM_ALG_SHA256,
        "sha384" => TPM_ALG_SHA384,
        "sha512" => TPM_ALG_SHA512,
        _ => return Err(TpmError::Unsupported("PCR bank")),
    };
    if token.pcrs.iter().any(|&pcr| pcr >= 24) {
        return Err(TpmError::Malformed("PCR index"));
    }
    if token.pcrs.is_empty() {
        log::warn!("LUKS2: TPM token is not bound to any PCR; any OS can unseal it");
    }

    // The TPM must hold the SRK the object was sealed under.
    let live_name = read_public_name(srk.handle)?;
    if live_name != srk.name {
        return Err(TpmError::WrongSrk);
    }

    let session = Session::start(&srk)?;
    let result = (|| {
        if !token.pcrs.is_empty() {
            policy_pcr(session.handle, bank, &token.pcrs)?;
        }
        let object = load(srk.handle, private, public)?;
        let secret = session.unseal(object, &sealed_name);
        flush(object, "sealed object");
        secret
    })();
    if result.is_err() {
        // A successful Unseal ended the session; anything else leaves it.
        flush(session.handle, "policy session");
    }
    result
}

fn decode(text: &str) -> Result<Vec<u8>, TpmError> {
    crypto::base64(text).map_err(|_| TpmError::Malformed("base64"))
}

/// TPM 2.0 name of an object: nameAlg followed by the digest of its public area.
fn name_of(public: &[u8]) -> Result<Vec<u8>, TpmError> {
    let alg = public.get(2..4).ok_or(TpmError::Malformed("public area"))?;
    if u16::from_be_bytes([alg[0], alg[1]]) != TPM_ALG_SHA256 {
        return Err(TpmError::Unsupported("name algorithm"));
    }
    let mut name = alg.to_vec();
    name.extend_from_slice(&Sha256::digest(public));
    Ok(name)
}

/// The storage root key a token was sealed under (`tpm2_srk`): a
/// serialized tpm2-tss `ESYS_TR` of a persistent ECC key.
struct Srk {
    handle: u32,
    name: Vec<u8>,
    x: [u8; 32],
    y: [u8; 32],
}

impl Srk {
    fn parse(serialized: &[u8]) -> Result<Self, TpmError> {
        let mut reader = Reader::new(serialized);
        let handle = reader.u32()?;
        let name = reader.tpm2b()?.to_vec();
        if reader.u32()? != 1 {
            return Err(TpmError::Malformed("tpm2_srk is not a key"));
        }
        let public = reader.tpm2b()?;
        if !(PERSISTENT_FIRST..=PERSISTENT_LAST).contains(&handle) {
            return Err(TpmError::Malformed("tpm2_srk handle"));
        }
        if name_of(public)? != name {
            return Err(TpmError::Malformed("tpm2_srk name"));
        }
        let mut public = Reader::new(public);
        match public.u16()? {
            TPM_ALG_ECC => {}
            TPM_ALG_RSA => return Err(TpmError::Unsupported("RSA storage root key")),
            _ => return Err(TpmError::Malformed("tpm2_srk type")),
        }
        public.u16()?; // nameAlg, checked by name_of
        public.u32()?; // objectAttributes
        public.tpm2b()?; // authPolicy
        if public.u16()? != TPM_ALG_NULL {
            public.u16()?; // keyBits
            public.u16()?; // mode
        }
        if public.u16()? != TPM_ALG_NULL {
            public.u16()?; // scheme hash
        }
        if public.u16()? != TPM_ECC_NIST_P256 {
            return Err(TpmError::Unsupported("SRK curve"));
        }
        if public.u16()? != TPM_ALG_NULL {
            public.u16()?; // kdf hash
        }
        let x = public
            .tpm2b()?
            .try_into()
            .map_err(|_| TpmError::Malformed("SRK point"))?;
        let y = public
            .tpm2b()?
            .try_into()
            .map_err(|_| TpmError::Malformed("SRK point"))?;
        Ok(Self { handle, name, x, y })
    }
}

/// A salted policy session (SHA-256, AES-128-CFB parameter encryption).
struct Session {
    handle: u32,
    key: Zeroizing<[u8; 32]>,
    nonce_tpm: Vec<u8>,
}

impl Session {
    fn start(srk: &Srk) -> Result<Self, TpmError> {
        use p256::elliptic_curve::sec1::ToSec1Point as _;

        let tpm_key = p256::PublicKey::from_sec1_bytes(&[&[4u8][..], &srk.x, &srk.y].concat())
            .map_err(|_| TpmError::Malformed("SRK point"))?;
        // The ephemeral key must not come from the TPM: anyone on the bus
        // would learn the salt. A scalar out of range is rare (2^-32).
        let mut ephemeral = None;
        for _ in 0..8 {
            let mut bytes = Zeroizing::new([0u8; 32]);
            random(&mut *bytes)?;
            if let Ok(key) = p256::SecretKey::from_slice(&*bytes) {
                ephemeral = Some(key);
                break;
            }
        }
        let ephemeral = ephemeral.ok_or(TpmError::NoRandom)?;
        let point = ephemeral.public_key().to_sec1_point(false);
        let (ex, ey) = (
            point.x().ok_or(TpmError::Malformed("point"))?,
            point.y().ok_or(TpmError::Malformed("point"))?,
        );
        let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), tpm_key.as_affine());
        let mut salt = Zeroizing::new([0u8; 32]);
        kdf_e(
            shared.raw_secret_bytes(),
            b"SECRET\0",
            ex,
            &srk.x,
            &mut salt,
        );

        let mut nonce_caller = [0u8; 32];
        random(&mut nonce_caller)?;
        let mut cmd = Command::new(TPM_ST_NO_SESSIONS, TPM_CC_START_AUTH_SESSION);
        cmd.u32(srk.handle);
        cmd.u32(TPM_RH_NULL);
        cmd.tpm2b(&nonce_caller);
        // TPM2B_ENCRYPTED_SECRET holding a TPMS_ECC_POINT.
        cmd.u16(2 + 32 + 2 + 32);
        cmd.tpm2b(ex);
        cmd.tpm2b(ey);
        cmd.u8(TPM_SE_POLICY);
        cmd.u16(TPM_ALG_AES);
        cmd.u16(128);
        cmd.u16(TPM_ALG_CFB);
        cmd.u16(TPM_ALG_SHA256);
        let mut response = [0u8; RESPONSE_SIZE];
        let mut rsp = transact(&cmd.finish(), &mut response, "StartAuthSession")?;
        let handle = rsp.u32()?;
        // From here on the TPM holds a session that must not leak.
        let nonce_tpm = match rsp.tpm2b() {
            Ok(nonce) if (16..=64).contains(&nonce.len()) => nonce.to_vec(),
            _ => {
                flush(handle, "policy session");
                return Err(TpmError::Malformed("StartAuthSession response"));
            }
        };
        let mut key = Zeroizing::new([0u8; 32]);
        kdf_a(&*salt, b"ATH\0", &nonce_tpm, &nonce_caller, &mut key);
        Ok(Self {
            handle,
            key,
            nonce_tpm,
        })
    }

    /// TPM2_Unseal with an encrypted, authenticated response. Ends the session.
    fn unseal(&self, object: u32, name: &[u8]) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        let mut nonce_caller = [0u8; 32];
        random(&mut nonce_caller)?;
        let attributes = TPMA_SESSION_ENCRYPT; // continueSession clear
        let cp_hash = {
            let mut hash = Sha256::new();
            hash.update(TPM_CC_UNSEAL.to_be_bytes());
            hash.update(name);
            hash.finalize()
        };
        let mut mac = HmacSha256::new_from_slice(&*self.key).unwrap();
        mac.update(&cp_hash);
        mac.update(&nonce_caller);
        mac.update(&self.nonce_tpm);
        mac.update(&[attributes]);
        let hmac = mac.finalize().into_bytes();

        let mut cmd = Command::new(TPM_ST_SESSIONS, TPM_CC_UNSEAL);
        cmd.u32(object);
        cmd.u32(4 + 2 + 32 + 1 + 2 + 32);
        cmd.u32(self.handle);
        cmd.tpm2b(&nonce_caller);
        cmd.u8(attributes);
        cmd.tpm2b(&hmac);
        let mut response = Zeroizing::new([0u8; RESPONSE_SIZE]);
        let mut rsp = transact(&cmd.finish(), &mut *response, "Unseal")?;
        let parameter_size = rsp.u32()? as usize;
        let parameters = rsp.take(parameter_size)?;
        let nonce_tpm = rsp.tpm2b()?;
        let rsp_attributes = rsp.u8()?;
        let rsp_hmac = rsp.tpm2b()?;

        let rp_hash = {
            let mut hash = Sha256::new();
            hash.update(0u32.to_be_bytes());
            hash.update(TPM_CC_UNSEAL.to_be_bytes());
            hash.update(parameters);
            hash.finalize()
        };
        let mut mac = HmacSha256::new_from_slice(&*self.key).unwrap();
        mac.update(&rp_hash);
        mac.update(nonce_tpm);
        mac.update(&nonce_caller);
        mac.update(&[rsp_attributes]);
        if mac.verify_slice(rsp_hmac).is_err() {
            return Err(TpmError::BadResponseHmac);
        }
        // Without the encrypt attribute the TPM would have sent the data in clear.
        if rsp_attributes & TPMA_SESSION_ENCRYPT == 0 {
            return Err(TpmError::Malformed("response not encrypted"));
        }

        let mut data = Reader::new(parameters);
        let mut secret = Zeroizing::new(data.tpm2b()?.to_vec());
        let mut stream = Zeroizing::new([0u8; 32]);
        kdf_a(&*self.key, b"CFB\0", nonce_tpm, &nonce_caller, &mut stream);
        aes128_cfb_decrypt(&stream[..16], &stream[16..], &mut secret);
        if secret.is_empty() {
            return Err(TpmError::Malformed("empty secret"));
        }
        Ok(secret)
    }
}

/// KDFe from TPM 2.0 part 1, section 11.4.10.3, for one SHA-256 block.
fn kdf_e(z: &[u8], label: &[u8], party_u: &[u8], party_v: &[u8], out: &mut [u8; 32]) {
    let mut hash = Sha256::new();
    hash.update(1u32.to_be_bytes());
    hash.update(z);
    hash.update(label);
    hash.update(party_u);
    hash.update(party_v);
    out.copy_from_slice(&hash.finalize());
}

/// KDFa from TPM 2.0 part 1, section 11.4.10.2, producing 256 bits.
fn kdf_a(key: &[u8], label: &[u8], context_u: &[u8], context_v: &[u8], out: &mut [u8; 32]) {
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(&1u32.to_be_bytes());
    mac.update(label);
    mac.update(context_u);
    mac.update(context_v);
    mac.update(&256u32.to_be_bytes());
    out.copy_from_slice(&mac.finalize().into_bytes());
}

fn aes128_cfb_decrypt(key: &[u8], iv: &[u8], data: &mut [u8]) {
    use aes::cipher::{Array, BlockCipherEncrypt};
    let cipher = aes::Aes128::new_from_slice(key).unwrap();
    let mut feedback = Array::<u8, _>::try_from(iv).unwrap();
    for chunk in data.chunks_mut(16) {
        let mut stream = feedback;
        cipher.encrypt_block(&mut stream);
        feedback[..chunk.len()].copy_from_slice(chunk);
        for (byte, key) in chunk.iter_mut().zip(stream.iter()) {
            *byte ^= key;
        }
    }
}

fn read_public_name(handle: u32) -> Result<Vec<u8>, TpmError> {
    let mut cmd = Command::new(TPM_ST_NO_SESSIONS, TPM_CC_READ_PUBLIC);
    cmd.u32(handle);
    let mut response = [0u8; RESPONSE_SIZE];
    let mut rsp = transact(&cmd.finish(), &mut response, "ReadPublic")?;
    rsp.tpm2b()?; // outPublic
    Ok(rsp.tpm2b()?.to_vec())
}

fn policy_pcr(session: u32, bank: u16, pcrs: &[u32]) -> Result<(), TpmError> {
    let mut select = [0u8; 3];
    for &pcr in pcrs {
        select[pcr as usize / 8] |= 1 << (pcr % 8);
    }
    let mut cmd = Command::new(TPM_ST_NO_SESSIONS, TPM_CC_POLICY_PCR);
    cmd.u32(session);
    cmd.tpm2b(&[]); // pcrDigest: let the TPM use the current values
    cmd.u32(1);
    cmd.u16(bank);
    cmd.u8(3);
    cmd.bytes(&select);
    let mut response = [0u8; RESPONSE_SIZE];
    transact(&cmd.finish(), &mut response, "PolicyPCR")?;
    Ok(())
}

fn load(parent: u32, private: &[u8], public: &[u8]) -> Result<u32, TpmError> {
    let mut cmd = Command::new(TPM_ST_SESSIONS, TPM_CC_LOAD);
    cmd.u32(parent);
    // The SRK has an empty authorization value: a password session.
    cmd.u32(4 + 2 + 1 + 2);
    cmd.u32(TPM_RS_PW);
    cmd.tpm2b(&[]);
    cmd.u8(0);
    cmd.tpm2b(&[]);
    cmd.bytes(private);
    cmd.bytes(public);
    let mut response = [0u8; RESPONSE_SIZE];
    let mut rsp = transact(&cmd.finish(), &mut response, "Load")?;
    rsp.u32()
}

fn flush(handle: u32, what: &str) {
    let mut cmd = Command::new(TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT);
    cmd.u32(handle);
    let mut response = [0u8; 64];
    if let Err(err) = transact(&cmd.finish(), &mut response, "FlushContext") {
        log::warn!("LUKS2: could not flush the {what} {handle:#x}: {err}");
    }
}

/// Random bytes from the CPU's tested RNG. Native boot never initialized
/// it, so the self-test runs on first use.
fn random(out: &mut [u8]) -> Result<(), TpmError> {
    use core::sync::atomic::{AtomicBool, Ordering};
    static TESTED: AtomicBool = AtomicBool::new(false);
    if !TESTED.swap(true, Ordering::SeqCst) && !crate::arch::rng::is_supported() {
        crate::arch::rng::init();
    }
    if !crate::arch::rng::is_supported() || !crate::arch::rng::fill_random(out) {
        return Err(TpmError::NoRandom);
    }
    Ok(())
}

/// Send a command, retry transient TPM states, and return a reader for the
/// response after its header.
fn transact<'a>(
    command: &[u8],
    response: &'a mut [u8],
    what: &'static str,
) -> Result<Reader<'a>, TpmError> {
    const TPM_RC_RETRY: u32 = 0x922;
    const TPM_RC_YIELDED: u32 = 0x908;
    const TPM_RC_TESTING: u32 = 0x90A;
    let mut attempts = 0;
    let len = loop {
        let len = match crate::efi::protocols::tcg2::submit_raw_command(command, response) {
            None => return Err(TpmError::Absent),
            Some(Err(_)) => return Err(TpmError::Transport),
            Some(Ok(len)) => len,
        };
        if len < 10 || len > response.len() {
            return Err(TpmError::Malformed("response length"));
        }
        let rc = u32::from_be_bytes(response[6..10].try_into().unwrap());
        if matches!(rc, TPM_RC_RETRY | TPM_RC_YIELDED | TPM_RC_TESTING) && attempts < 50 {
            attempts += 1;
            crate::time::delay_ms(20);
            continue;
        }
        if rc != 0 {
            return Err(TpmError::Rc(rc, what));
        }
        break len;
    };
    if u32::from_be_bytes(response[2..6].try_into().unwrap()) as usize != len {
        return Err(TpmError::Malformed("response size"));
    }
    Ok(Reader::new(&response[10..len]))
}

struct Command(Vec<u8>);

impl Command {
    fn new(tag: u16, code: u32) -> Self {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&tag.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&code.to_be_bytes());
        Self(buf)
    }
    fn u8(&mut self, value: u8) {
        self.0.push(value);
    }
    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    fn bytes(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }
    fn tpm2b(&mut self, value: &[u8]) {
        self.u16(value.len() as u16);
        self.bytes(value);
    }
    fn finish(mut self) -> Vec<u8> {
        let len = self.0.len() as u32;
        self.0[2..6].copy_from_slice(&len.to_be_bytes());
        self.0
    }
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], TpmError> {
        if len > self.data.len() {
            return Err(TpmError::Malformed("truncated"));
        }
        let (head, tail) = self.data.split_at(len);
        self.data = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, TpmError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, TpmError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, TpmError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn tpm2b(&mut self) -> Result<&'a [u8], TpmError> {
        let len = self.u16()? as usize;
        self.take(len)
    }
    /// A TPM2B including its size field.
    fn tpm2b_raw(&mut self) -> Result<&'a [u8], TpmError> {
        let before = self.data;
        let len = self.tpm2b()?.len();
        Ok(&before[..2 + len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_systemd_srk() {
        // tpm2_srk written by systemd 262 for an swtpm ECC SRK.
        let srk = Srk::parse(
            &crypto::base64(concat!(
                "gQAAAQAiAAuIMuunrzV+o9UQ1XWr6aoc03DnA9SQF1OSDWdih9ldhwAAAAEAWgAjAAsAAwRyAAAABgCAAEMAEAADABAAIGnvoexy/NH3VjldbYc6",
                "DjCn3KWKvtwXewZ8bSCH1qXMACDQtpgTm4KHU9pnAQ87QDbIAe8zeVLTWPXl3321vJVxrQ=="
            ))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(srk.handle, 0x8100_0001);
        assert_eq!(srk.name.len(), 34);
        assert_eq!(srk.x[0], 0x69);
    }

    #[test]
    fn cfb_round_trips_partial_blocks() {
        use aes::cipher::{Array, BlockCipherEncrypt};
        let key = [7u8; 16];
        let iv = [9u8; 16];
        let plain: Vec<u8> = (0..40u8).collect();
        // Encrypt with CFB128 by hand.
        let cipher = aes::Aes128::new_from_slice(&key).unwrap();
        let mut feedback = Array::<u8, _>::try_from(&iv[..]).unwrap();
        let mut data = plain.clone();
        for chunk in data.chunks_mut(16) {
            let mut stream = feedback;
            cipher.encrypt_block(&mut stream);
            for (byte, key) in chunk.iter_mut().zip(stream.iter()) {
                *byte ^= key;
            }
            feedback[..chunk.len()].copy_from_slice(chunk);
        }
        aes128_cfb_decrypt(&key, &iv, &mut data);
        assert_eq!(data, plain);
    }

    // KDFa, KDFe and the session HMACs are checked against swtpm by
    // `./crabefi test --app native-only-luks-tpm-linux`.
    #[test]
    fn kdfa_binds_context_order() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        kdf_a(b"key", b"ATH\0", b"u", b"v", &mut a);
        kdf_a(b"key", b"ATH\0", b"v", b"u", &mut b);
        assert_ne!(a, b);
    }
}

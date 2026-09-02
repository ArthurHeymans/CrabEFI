//! AArch64 Hardware Random Number Generation
//!
//! On ARMv8.5-A and later, the RNDR system register provides a
//! hardware random number source (FEAT_RNG). On QEMU, this may
//! or may not be available depending on the CPU model.
//!
//! Falls back to SMCCC TRNG (ARM True Random Number Generator)
//! interface via HVC/SMC if RNDR is not available.

use core::sync::atomic::{AtomicU8, Ordering};

/// SMCCC TRNG function IDs
const SMCCC_TRNG_VERSION: u32 = 0xC400_0050;
const SMCCC_TRNG_RND64: u32 = 0xC400_0053;

/// RNG method selector (written once during init, read many times).
/// Stored as AtomicU8 to avoid `static mut` unsoundness.
static RNG_METHOD: AtomicU8 = AtomicU8::new(RngMethod::None as u8);

#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
enum RngMethod {
    None = 0,
    Rndr = 1,
    SmcccTrng = 2,
}

impl RngMethod {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Rndr,
            2 => Self::SmcccTrng,
            _ => Self::None,
        }
    }
}

/// Check if RNDR instruction is available via ID_AA64ISAR0_EL1
fn has_rndr() -> bool {
    let isar0: u64;
    unsafe {
        core::arch::asm!(
            "mrs {}, ID_AA64ISAR0_EL1",
            out(reg) isar0,
            options(nomem, nostack, preserves_flags)
        );
    }
    // RNDR field is bits [63:60]
    ((isar0 >> 60) & 0xF) >= 1
}

/// Try to read a random value using the RNDR system register
///
/// Returns `Some(value)` on success, `None` if the entropy source
/// is temporarily exhausted.
fn rndr64() -> Option<u64> {
    for _ in 0..10 {
        let val: u64;
        let nzcv: u64;
        unsafe {
            // RNDR may fail (NZCV.Z set) if entropy is exhausted
            core::arch::asm!(
                "mrs {val}, S3_3_C2_C4_0", // RNDR
                "mrs {nzcv}, NZCV",
                val = out(reg) val,
                nzcv = out(reg) nzcv,
                options(nomem, nostack)
            );
        }
        // Check Zero flag (bit 30 of NZCV)
        if (nzcv & (1 << 30)) == 0 {
            return Some(val);
        }
        core::hint::spin_loop();
    }
    None
}

/// Check if SMCCC TRNG is available (via SMC to EL3 / TF-A)
fn check_smccc_trng() -> bool {
    let ret: u64;
    unsafe {
        core::arch::asm!(
            "mov w0, {func_id:w}",
            "smc #0",
            "mov {ret}, x0",
            func_id = in(reg) SMCCC_TRNG_VERSION,
            ret = out(reg) ret,
            out("x1") _,
            out("x2") _,
            out("x3") _,
            options(nomem, nostack)
        );
    }
    // Version should be >= 1.0 (0x10000)
    let version = ret as i64;
    version >= 0x10000
}

/// Get random value via SMCCC TRNG (SMC to EL3 / TF-A)
fn smccc_trng_rnd64() -> Option<u64> {
    let ret: u64;
    let val: u64;
    unsafe {
        core::arch::asm!(
            "mov w0, {func_id:w}",
            "mov x1, #64",      // 64 bits requested
            "smc #0",
            "mov {ret}, x0",
            "mov {val}, x3",    // Random value in x3
            func_id = in(reg) SMCCC_TRNG_RND64,
            ret = out(reg) ret,
            val = out(reg) val,
            out("x1") _,
            out("x2") _,
            options(nomem, nostack)
        );
    }
    // SUCCESS = 0
    if ret as i64 == 0 { Some(val) } else { None }
}

/// Initialize RNG support
///
/// Checks for RNDR instruction support and SMCCC TRNG availability.
pub fn init() {
    if has_rndr() {
        // Verify RNDR actually works
        if rndr64().is_some() {
            crate::state::with_drivers_mut(|d| d.rng_available = true);
            RNG_METHOD.store(RngMethod::Rndr as u8, Ordering::Release);
            log::info!("RNG: RNDR instruction available (FEAT_RNG)");
            return;
        }
    }

    if check_smccc_trng() {
        crate::state::with_drivers_mut(|d| d.rng_available = true);
        RNG_METHOD.store(RngMethod::SmcccTrng as u8, Ordering::Release);
        log::info!("RNG: SMCCC TRNG available");
        return;
    }

    log::warn!("RNG: No hardware RNG available");
}

/// Check if hardware RNG is available and functional
pub fn is_supported() -> bool {
    unsafe { &*crate::state::drivers_ptr() }.rng_available
}

/// Fill a byte buffer with random data
///
/// # Returns
/// `true` if the buffer was filled, `false` if RNG is not available
pub fn fill_random(buffer: &mut [u8]) -> bool {
    let method = RngMethod::from_u8(RNG_METHOD.load(Ordering::Acquire));
    let get_random = match method {
        RngMethod::Rndr => rndr64,
        RngMethod::SmcccTrng => smccc_trng_rnd64,
        RngMethod::None => return false,
    };

    let mut i = 0;
    while i < buffer.len() {
        match get_random() {
            Some(val) => {
                let bytes = val.to_le_bytes();
                let remaining = buffer.len() - i;
                let to_copy = core::cmp::min(remaining, 8);
                buffer[i..i + to_copy].copy_from_slice(&bytes[..to_copy]);
                i += to_copy;
            }
            None => return false,
        }
    }
    true
}

//! x86_64 Hardware Random Number Generation
//!
//! Provides access to the RDRAND instruction, which implements a
//! NIST SP800-90A AES-CTR-256 DRBG in hardware.

/// Maximum number of RDRAND retries per Intel SDM Section 7.3.17
const RDRAND_RETRY_LIMIT: usize = 10;

/// Number of samples for broken RDRAND detection
const RDRAND_TEST_SAMPLES: usize = 8;

/// Minimum number of different values required to pass broken RDRAND test
const RDRAND_MIN_CHANGE: usize = 5;

/// Check if RDRAND is supported via CPUID
///
/// Returns true if CPUID reports RDRAND support (ECX bit 30, leaf 1)
fn cpuid_has_rdrand() -> bool {
    let ecx: u32;

    // RBX is reserved by LLVM, so save/restore it around CPUID. Do not use
    // `options(nostack)`: the assembly intentionally uses push/pop.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 1",
            "cpuid",
            "pop rbx",
            out("ecx") ecx,
            out("eax") _,
            out("edx") _,
        );
    }

    (ecx & (1 << 30)) != 0
}

/// Execute RDRAND instruction to get a 64-bit random value
///
/// Returns `Some(value)` on success (CF=1), `None` on failure.
/// Retries up to `RDRAND_RETRY_LIMIT` times per Intel SDM recommendation.
pub fn rdrand64() -> Option<u64> {
    for _ in 0..RDRAND_RETRY_LIMIT {
        let val: u64;
        let ok: u8;
        unsafe {
            core::arch::asm!(
                "rdrand {val}",
                "setc {ok}",
                val = out(reg) val,
                ok = out(reg_byte) ok,
            );
        }
        if ok != 0 {
            return Some(val);
        }
    }
    None
}

/// Test for broken RDRAND implementations
///
/// Samples RDRAND multiple times and checks that we get different values.
/// This detects issues like AMD Zen 3 returning all-1s or suspend/resume bugs.
///
/// Returns true if RDRAND appears functional, false if it returns constant values.
fn test_rdrand() -> bool {
    let mut prev: u64 = 0;
    let mut changed = 0;

    for i in 0..RDRAND_TEST_SAMPLES {
        let sample = match rdrand64() {
            Some(v) => v,
            None => return false,
        };

        if i > 0 && sample != prev {
            changed += 1;
        }
        prev = sample;
    }

    changed >= RDRAND_MIN_CHANGE
}

/// Initialize RDRAND support
///
/// Checks CPUID for RDRAND support and runs the broken RDRAND test.
/// Must be called before `is_supported()` or `rdrand64()`.
pub fn init() {
    let available = cpuid_has_rdrand() && test_rdrand();
    crate::state::with_drivers_mut(|d| d.rng_available = available);

    if is_supported() {
        log::info!("RDRAND available (SP800-90 CTR-256)");
    } else {
        log::warn!("RDRAND not available or broken");
    }
}

/// Check if RDRAND is available and functional
pub fn is_supported() -> bool {
    crate::state::drivers().rng_available
}

/// Fill a byte buffer with random data from RDRAND
///
/// # Returns
/// `true` if the buffer was filled, `false` if RDRAND failed
pub fn fill_random(buffer: &mut [u8]) -> bool {
    let mut i = 0;
    while i < buffer.len() {
        match rdrand64() {
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

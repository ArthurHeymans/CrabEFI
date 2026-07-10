//! x86_64 Hardware Random Number Generation
//!
//! Provides access to the RDRAND instruction, which implements a
//! NIST SP800-90A AES-CTR-256 DRBG in hardware.

use x86_64::instructions::random::RdRand;

/// Maximum number of RDRAND retries per Intel SDM Section 7.3.17
const RDRAND_RETRY_LIMIT: usize = 10;

/// Number of samples for broken RDRAND detection
const RDRAND_TEST_SAMPLES: usize = 8;

/// Minimum number of different values required to pass broken RDRAND test
const RDRAND_MIN_CHANGE: usize = 5;

/// Execute RDRAND instruction to get a 64-bit random value
///
/// Returns `Some(value)` on success (CF=1), `None` on failure or when RDRAND
/// is unavailable. Retries up to `RDRAND_RETRY_LIMIT` times per Intel SDM
/// recommendation.
pub fn rdrand64() -> Option<u64> {
    rdrand64_with(RdRand::new()?)
}

fn rdrand64_with(rng: RdRand) -> Option<u64> {
    (0..RDRAND_RETRY_LIMIT).find_map(|_| rng.get_u64())
}

fn samples_vary(samples: &[u64; RDRAND_TEST_SAMPLES]) -> bool {
    samples.windows(2).filter(|pair| pair[0] != pair[1]).count() >= RDRAND_MIN_CHANGE
}

/// Test for broken RDRAND implementations
///
/// Samples RDRAND multiple times and checks that we get different values.
/// This detects issues like AMD Zen 3 returning all-1s or suspend/resume bugs.
fn test_rdrand(rng: RdRand) -> bool {
    let mut samples = [0; RDRAND_TEST_SAMPLES];
    for sample in &mut samples {
        let Some(value) = rdrand64_with(rng) else {
            return false;
        };
        *sample = value;
    }
    samples_vary(&samples)
}

/// Initialize RDRAND support
///
/// Checks CPUID for RDRAND support and runs the broken RDRAND test.
/// Must be called before `is_supported()`.
pub fn init() {
    let available = RdRand::new().is_some_and(test_rdrand);
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
    if buffer.is_empty() {
        return true;
    }
    let Some(rng) = RdRand::new() else {
        return false;
    };
    let mut i = 0;
    while i < buffer.len() {
        match rdrand64_with(rng) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broken_rdrand_sampling_threshold() {
        assert!(!samples_vary(&[7; RDRAND_TEST_SAMPLES]));
        assert!(!samples_vary(&[0, 1, 2, 3, 4, 4, 4, 4]));
        assert!(samples_vary(&[0, 1, 2, 3, 4, 5, 5, 5]));
    }

    #[test]
    fn empty_buffer_needs_no_rng() {
        assert!(fill_random(&mut []));
    }
}

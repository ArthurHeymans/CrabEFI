//! SHA-256 acceleration for the privileged AArch64 boot image.

use core::arch::aarch64::*;
#[cfg(target_os = "none")]
use core::arch::asm;
use sha2::digest::block_buffer::EagerBuffer;
use sha2::digest::typenum::U64;

// Initial state and round constants from FIPS 180-4, sections 5.3.3 and 4.2.2.
const INITIAL: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[cfg(target_os = "none")]
pub(super) fn available() -> bool {
    let el: u64;
    let isar0: u64;
    // SAFETY: the bare-metal boot image runs at EL1 or higher. Like its
    // baseline NEON code, it relies on higher ELs permitting SIMD and ID reads.
    // Read only registers accessible at the current EL, and never change traps.
    unsafe {
        asm!("mrs {}, CurrentEL", out(reg) el, options(nomem, nostack, preserves_flags));
        if el != 4 && el != 8 {
            return false;
        }
        asm!("mrs {}, ID_AA64ISAR0_EL1", out(reg) isar0, options(nomem, nostack, preserves_flags));
        if !has_sha256(isar0) {
            return false;
        }
        if el == 4 {
            let cpacr: u64;
            asm!("mrs {}, CPACR_EL1", out(reg) cpacr, options(nomem, nostack, preserves_flags));
            cpacr & (1 << 20) != 0 // FPEN allows execution at EL1
        } else {
            let hcr: u64;
            let cptr: u64;
            asm!("mrs {}, HCR_EL2", "mrs {}, CPTR_EL2", out(reg) hcr, out(reg) cptr,
                options(nomem, nostack, preserves_flags));
            simd_at_el2(hcr, cptr)
        }
    }
}

fn has_sha256(isar0: u64) -> bool {
    // 0b0001 implements SHA-256; 0b0010 adds SHA-512. Other values are reserved.
    matches!((isar0 >> 12) & 0xf, 1 | 2)
}

fn simd_at_el2(hcr: u64, cptr: u64) -> bool {
    if hcr & (1 << 34) != 0 {
        cptr & (1 << 20) != 0 // E2H=1: FPEN allows execution at EL2
    } else {
        cptr & (1 << 10) == 0 // E2H=0: TFP does not trap
    }
}

/// Hash ordered chunks without concatenating them or allocating.
///
/// # Safety
/// The caller must ensure SHA-256 and Advanced SIMD are usable for
/// the duration of the call.
#[target_feature(enable = "sha2")]
pub(super) unsafe fn digest<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut state = INITIAL;
    let mut buffer = EagerBuffer::<U64>::default();
    let mut bytes = 0u64;
    for chunk in chunks {
        bytes = bytes.wrapping_add(chunk.len() as u64);
        buffer.digest_blocks(chunk, |blocks| {
            for block in blocks {
                // SAFETY: the caller guarantees SHA-256 and SIMD support.
                unsafe { compress(&mut state, &block.0) };
            }
        });
    }
    buffer.len64_padding_be(bytes.wrapping_mul(8), |block| {
        // SAFETY: the caller guarantees SHA-256 and SIMD support.
        unsafe { compress(&mut state, &block.0) };
    });
    let mut output = [0; 32];
    for (word, chunk) in state.into_iter().zip(output.as_chunks_mut::<4>().0) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[target_feature(enable = "sha2")]
unsafe fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    // SAFETY: all vector loads and stores are from in-bounds, initialized
    // arrays. This module is only built for little-endian AArch64.
    unsafe {
        let initial_abcd = vld1q_u32(state.as_ptr());
        let initial_efgh = vld1q_u32(state.as_ptr().add(4));
        let (mut abcd, mut efgh) = (initial_abcd, initial_efgh);
        let mut schedule = core::array::from_fn::<_, 4, _>(|i| {
            vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block.as_ptr().add(i * 16))))
        });
        for (round, constants) in K.as_chunks::<4>().0.iter().enumerate() {
            let words = schedule[0];
            let wk = vaddq_u32(words, vld1q_u32(constants.as_ptr()));
            let previous_abcd = abcd;
            abcd = vsha256hq_u32(abcd, efgh, wk);
            efgh = vsha256h2q_u32(efgh, previous_abcd, wk);
            if round < 12 {
                schedule[0] = vsha256su1q_u32(
                    vsha256su0q_u32(words, schedule[1]),
                    schedule[2],
                    schedule[3],
                );
            }
            schedule.rotate_left(1);
        }
        vst1q_u32(state.as_mut_ptr(), vaddq_u32(initial_abcd, abcd));
        vst1q_u32(state.as_mut_ptr().add(4), vaddq_u32(initial_efgh, efgh));
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn feature_and_trap_fields() {
        for value in 0..16 {
            assert_eq!(has_sha256(value << 12), value == 1 || value == 2);
        }
        assert!(simd_at_el2(0, 0));
        assert!(!simd_at_el2(0, 1 << 10));
        assert!(!simd_at_el2(1 << 34, 0));
        assert!(simd_at_el2(1 << 34, 1 << 20));
    }

    #[test]
    fn hardware_matches_software_across_blocks_and_chunk_boundaries() {
        if !std::arch::is_aarch64_feature_detected!("sha2") {
            return;
        }
        let data: [u8; 1025] = core::array::from_fn(|i| (i ^ (i >> 4)) as u8);
        for len in [0, 1, 55, 56, 63, 64, 65, 119, 120, 128, 1025] {
            let bytes = &data[..len];
            let expected: [u8; 32] = Sha256::digest(bytes).into();
            // SAFETY: the host reports usable SHA-256 support.
            assert_eq!(unsafe { digest(bytes.chunks(13)) }, expected);
            assert_eq!(unsafe { digest([bytes]) }, expected);
        }
    }
}

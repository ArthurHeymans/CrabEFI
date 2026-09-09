//! Fixed-width stack RSA arithmetic for authenticated variables.
//!
//! Variable-time Montgomery modular exponentiation over big-endian byte
//! slices, using only fixed `[Word; MAX_LIMBS]` stack buffers. This replaces
//! the allocator-backed `BoxedUintIn` fork: upstream const-generic
//! multiplication monomorphizes Karatsuba recursion into a ~25 KiB stack
//! frame at 4096-bit widths, which does not fit the 16 KiB firmware stack.
//! The schoolbook Montgomery engine here keeps the worst frame around
//! 4 KiB (a handful of 512-byte operand buffers plus locals), enforced by
//! the link-time stack-sizes audit.
//!
//! # Design notes
//!
//! - Every operation runs at the full `MAX_LIMBS` width regardless of the
//!   modulus size. RSA *verification* only ever exponentiates by the public
//!   exponent (typically 65537, i.e. ~19 Montgomery multiplications), so the
//!   4x cost of padding a 2048-bit key to 4096 bits is irrelevant, and in
//!   exchange every loop is bounded by a compile-time constant: no `unsafe`,
//!   no runtime width invariant, and no bounds-check panic machinery for the
//!   runtime ELF audit to reject.
//! - Variable-time by design (square-and-multiply skips leading zero bits).
//!   All inputs are public: a public key, a signature, and a digest.
//! - Operands are big-endian byte slices; the output width is the modulus
//!   byte length, exactly like the previous implementation.

use core::cmp::Ordering;

type Word = u64;
type WideWord = u128;

const WORD_BITS: usize = 64;
const WORD_BYTES: usize = 8;

/// Maximum RSA width: 4096 bits = 64 limbs.
pub const MAX_LIMBS: usize = 64;
/// Maximum RSA operand size in bytes.
pub const MAX_BYTES: usize = MAX_LIMBS * WORD_BYTES;

/// Little-endian limb array; the Montgomery radix is `R = 2^(64 * MAX_LIMBS)`.
type Limbs = [Word; MAX_LIMBS];

/// Errors from stack RSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BigintError {
    /// An operand exceeds the stack-backed maximum width.
    TooLarge,
    /// An operand or modulus is invalid (empty, zero, or even modulus).
    InvalidInput,
}

/// Compare big-endian byte strings as integers (leading zeros ignored).
pub fn cmp_be(left: &[u8], right: &[u8]) -> Ordering {
    let left_len = significant_byte_len(left);
    let right_len = significant_byte_len(right);
    match left_len.cmp(&right_len) {
        // Big-endian bytes are already MSB-first: no rev(), unlike the
        // little-endian limb order in `compare` below.
        Ordering::Equal => left
            .iter()
            .skip(left.len() - left_len)
            .zip(right.iter().skip(right.len() - right_len))
            .find_map(|(l, r)| (l != r).then(|| l.cmp(r)))
            .unwrap_or(Ordering::Equal),
        ordering => ordering,
    }
}

fn significant_byte_len(bytes: &[u8]) -> usize {
    bytes.len() - bytes.iter().take_while(|byte| **byte == 0).count()
}

/// True for non-empty odd values. Leading zeros are ignored by callers that
/// need significance; oddness only depends on the last byte.
pub fn is_odd_nonzero(bytes: &[u8]) -> bool {
    bytes.last().is_some_and(|byte| byte & 1 == 1)
}

/// Compute `base^exponent mod modulus`, writing the fixed-width big-endian
/// result into `out`.
///
/// `out.len()` must equal the modulus byte length; all three inputs must be
/// non-empty with `len <= MAX_BYTES`, and the modulus must be odd and
/// nonzero. Failures are fail-closed errors, never panics.
pub fn mod_pow_vartime(
    base_be: &[u8],
    exponent_be: &[u8],
    modulus_be: &[u8],
    out_be: &mut [u8],
) -> Result<(), BigintError> {
    if base_be.is_empty()
        || exponent_be.is_empty()
        || modulus_be.is_empty()
        || out_be.len() != modulus_be.len()
    {
        return Err(BigintError::InvalidInput);
    }
    if base_be.len() > MAX_BYTES || exponent_be.len() > MAX_BYTES || modulus_be.len() > MAX_BYTES {
        return Err(BigintError::TooLarge);
    }
    if !is_odd_nonzero(modulus_be) {
        return Err(BigintError::InvalidInput);
    }

    let modulus = Modulus::from_be(modulus_be);

    // one = R mod m and r_squared = R^2 mod m, by repeated doubling of 1:
    // after MAX_LIMBS * 64 doublings the accumulator holds R mod m, after
    // twice that R^2 mod m.
    let mut accumulator = one();
    modulus.reduce_once(&mut accumulator);
    for _ in 0..MAX_LIMBS * WORD_BITS {
        modulus.double(&mut accumulator);
    }
    let montgomery_one = accumulator;
    for _ in 0..MAX_LIMBS * WORD_BITS {
        modulus.double(&mut accumulator);
    }
    let r_squared = accumulator;

    // base < R always holds (it fits in MAX_BYTES), so one Montgomery
    // multiplication by R^2 both reduces it modulo m and converts it to
    // Montgomery form without a separate remainder step.
    let base = modulus.montgomery_mul(&load_be(base_be), &r_squared);
    let mut result = montgomery_one;

    let mut started = false;
    for byte in exponent_be.iter() {
        for bit in (0..8).rev() {
            let set = (byte >> bit) & 1 != 0;
            if !started && !set {
                continue;
            }
            started = true;
            result = modulus.montgomery_mul(&result, &result);
            if set {
                result = modulus.montgomery_mul(&result, &base);
            }
        }
    }

    // Leaving Montgomery form is a multiplication by 1.
    let output = modulus.montgomery_mul(&result, &one());
    write_be_bytes(&output, out_be);
    Ok(())
}

/// An odd modulus together with `-m^-1 mod 2^64`, loaded once per operation.
struct Modulus {
    limbs: Limbs,
    neg_inverse: Word,
}

impl Modulus {
    fn from_be(bytes: &[u8]) -> Self {
        let limbs = load_be(bytes);
        Self {
            limbs,
            neg_inverse: invert_odd_word(limbs[0]).wrapping_neg(),
        }
    }

    /// `value -= m` if `value >= m`.
    fn reduce_once(&self, value: &mut Limbs) {
        if compare(value, &self.limbs) != Ordering::Less {
            subtract_assign(value, &self.limbs);
        }
    }

    /// `value = 2 * value mod m`, for `value < m`.
    fn double(&self, value: &mut Limbs) {
        let carry = shift_left(value);
        if carry || compare(value, &self.limbs) != Ordering::Less {
            subtract_assign(value, &self.limbs);
        }
    }

    /// Schoolbook CIOS Montgomery multiplication: `left * right * R^-1 mod m`.
    ///
    /// Requires `left < R` and `right < m`; the result is fully reduced.
    fn montgomery_mul(&self, left: &Limbs, right: &Limbs) -> Limbs {
        let mut output: Limbs = [0; MAX_LIMBS];
        let mut meta_carry: WideWord = 0;
        for left_limb in left.iter().copied() {
            let product = left_limb as WideWord * right[0] as WideWord + output[0] as WideWord;
            let factor = (product as Word).wrapping_mul(self.neg_inverse);
            let (sum, overflow) =
                (factor as WideWord * self.limbs[0] as WideWord).overflowing_add(product);
            let mut carry = ((overflow as WideWord) << WORD_BITS) | (sum >> WORD_BITS);
            // output[i - 1] = low(output[i] + left * right[i] + factor * m[i] + carry)
            for inner in 1..MAX_LIMBS {
                let product =
                    left_limb as WideWord * right[inner] as WideWord + output[inner] as WideWord;
                let reduction = factor as WideWord * self.limbs[inner] as WideWord + carry;
                let (sum, overflow) = product.overflowing_add(reduction);
                output[inner - 1] = sum as Word;
                carry = ((overflow as WideWord) << WORD_BITS) | (sum >> WORD_BITS);
            }
            carry += meta_carry;
            output[MAX_LIMBS - 1] = carry as Word;
            meta_carry = carry >> WORD_BITS;
        }
        if meta_carry != 0 || compare(&output, &self.limbs) != Ordering::Less {
            subtract_assign(&mut output, &self.limbs);
        }
        output
    }
}

fn one() -> Limbs {
    let mut limbs = [0; MAX_LIMBS];
    limbs[0] = 1;
    limbs
}

/// Load up to `MAX_BYTES` big-endian bytes into little-endian limbs.
fn load_be(bytes: &[u8]) -> Limbs {
    let mut limbs = [0; MAX_LIMBS];
    for (destination, chunk) in limbs.iter_mut().zip(bytes.rchunks(WORD_BYTES)) {
        *destination = chunk
            .iter()
            .fold(0, |word, byte| (word << 8) | Word::from(*byte));
    }
    limbs
}

fn compare(a: &Limbs, b: &Limbs) -> Ordering {
    a.iter()
        .rev()
        .zip(b.iter().rev())
        .find_map(|(left, right)| (left != right).then(|| left.cmp(right)))
        .unwrap_or(Ordering::Equal)
}

fn subtract_assign(a: &mut Limbs, b: &Limbs) {
    let mut borrow = false;
    for (left, right) in a.iter_mut().zip(b.iter()) {
        let (value, first) = left.overflowing_sub(*right);
        let (value, second) = value.overflowing_sub(Word::from(borrow));
        *left = value;
        borrow = first || second;
    }
}

/// Shift left by one bit; returns the bit shifted out of the top limb.
fn shift_left(value: &mut Limbs) -> bool {
    let mut carry = 0;
    for limb in value.iter_mut() {
        let next = *limb >> (WORD_BITS - 1);
        *limb = (*limb << 1) | carry;
        carry = next;
    }
    carry != 0
}

fn invert_odd_word(value: Word) -> Word {
    // Newton iteration doubles the number of correct low bits each round.
    let mut inverse: Word = 1;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(value.wrapping_mul(inverse)));
    }
    inverse
}

/// Write the low `output.len()` bytes of `limbs` in big-endian order.
fn write_be_bytes(limbs: &Limbs, output: &mut [u8]) {
    for (destination, source) in output
        .iter_mut()
        .rev()
        .zip(limbs.iter().flat_map(|limb| limb.to_le_bytes().into_iter()))
    {
        *destination = source;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Textbook RSA: p=61, q=53, n=3233, e=17, d=2753. m=65 -> c=2790.
    const N: &[u8] = &[0x0c, 0xa1];
    const E: &[u8] = &[0x11];
    const D: &[u8] = &[0x0a, 0xc1];
    const M: &[u8] = &[0x41];
    const C: &[u8] = &[0x0a, 0xe6];

    fn pow_to_vec(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; modulus.len()];
        mod_pow_vartime(base, exp, modulus, &mut out).unwrap();
        out
    }

    #[test]
    fn textbook_roundtrip() {
        // Encrypt then decrypt.
        assert_eq!(pow_to_vec(M, E, N), C);
        assert_eq!(pow_to_vec(C, D, N), [0x00, M[0]]);
        // Identity exponent and zero base edge cases (fixed-width output).
        assert_eq!(pow_to_vec(M, &[1], N), [0x00, M[0]]);
        let mut zero = [0u8; 2];
        mod_pow_vartime(&[0], E, N, &mut zero).unwrap();
        assert_eq!(zero, [0, 0]);
        // Base larger than the modulus is reduced first: 3233 + 65 -> 65^17.
        assert_eq!(pow_to_vec(&[0x0c, 0xe2], E, N), C);
        // Modulus 1: everything is congruent to zero.
        assert_eq!(pow_to_vec(M, E, &[1]), [0]);
    }

    #[test]
    fn rejects_invalid_inputs() {
        let mut out = [0u8; 2];
        // Empty inputs.
        assert_eq!(
            mod_pow_vartime(&[], E, N, &mut out),
            Err(BigintError::InvalidInput)
        );
        // Even modulus.
        assert_eq!(
            mod_pow_vartime(M, E, &[0x0c, 0xa0], &mut out),
            Err(BigintError::InvalidInput)
        );
        // Zero modulus.
        assert_eq!(
            mod_pow_vartime(M, E, &[0, 0], &mut out),
            Err(BigintError::InvalidInput)
        );
        // Output width must match modulus width.
        let mut wide = [0u8; 3];
        assert_eq!(
            mod_pow_vartime(M, E, N, &mut wide),
            Err(BigintError::InvalidInput)
        );
        // Over the stack-backed maximum.
        let big = [0xffu8; MAX_BYTES + 1];
        let mut big_out = [0u8; MAX_BYTES + 1];
        assert_eq!(
            mod_pow_vartime(&big, E, &big, &mut big_out),
            Err(BigintError::TooLarge)
        );
    }

    #[test]
    fn cmp_be_ignores_leading_zeros() {
        assert_eq!(cmp_be(&[0, 0, 1], &[1]), Ordering::Equal);
        assert_eq!(cmp_be(&[2], &[1]), Ordering::Greater);
        assert_eq!(cmp_be(&[], &[0]), Ordering::Equal);
        assert_eq!(cmp_be(&[1, 0], &[0, 255]), Ordering::Greater);
        // Multi-byte equal lengths decide at the most significant
        // difference (256 > 255 despite the low byte ordering).
        assert_eq!(cmp_be(&[0x01, 0x00], &[0x00, 0xff]), Ordering::Greater);
        assert_eq!(cmp_be(&[0x00, 0xff], &[0x01, 0x00]), Ordering::Less);
    }

    #[test]
    fn max_width_smoke() {
        // 4096-bit odd modulus stump: completes without panic and stays
        // below the modulus. Firmware stack fit is enforced separately by
        // the link-time stack-sizes audit (16 KiB budget).
        let modulus = [0xffu8; MAX_BYTES];
        let mut out = vec![0u8; MAX_BYTES];
        mod_pow_vartime(&[0xa5; MAX_BYTES], &[1], &modulus, &mut out).unwrap();
        assert_eq!(cmp_be(&out, &modulus), Ordering::Less);
        // x^1 mod m == x for x < m.
        let mut base = [0xa5u8; MAX_BYTES];
        base[0] = 0x7f;
        assert_eq!(pow_to_vec(&base, &[1], &modulus), base);
    }
}

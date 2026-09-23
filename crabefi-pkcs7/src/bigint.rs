//! Fixed-width stack Montgomery arithmetic for RSA verification.
//!
//! Variable-time modular exponentiation over big-endian byte slices using
//! only `[Word; LIMBS]` stack buffers, with schoolbook CIOS Montgomery
//! multiplication so the deepest frame stays a few operand buffers wide.
//!
//! Every operation runs at the full `LIMBS` width regardless of the modulus
//! size. Verification only exponentiates by the public exponent (~19
//! Montgomery multiplications for 65537), and in exchange every loop is
//! bounded by a compile-time constant: no `unsafe`, no runtime width
//! invariant and no bounds-check panics. Variable time is fine because all
//! inputs are public (key, signature, digest).

use core::cmp::Ordering;

type Word = u64;
type WideWord = u128;

const WORD_BITS: usize = Word::BITS as usize;
pub const LIMB_BYTES: usize = size_of::<Word>();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BigintError {
    /// An operand is wider than `LIMBS` words.
    TooLarge,
    /// An operand is empty, the output width differs from the modulus, or
    /// the modulus is even or zero.
    InvalidInput,
}

/// Compare big-endian byte strings as integers (leading zeros ignored).
pub fn cmp_be(left: &[u8], right: &[u8]) -> Ordering {
    let left = strip_leading_zeros(left);
    let right = strip_leading_zeros(right);
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    bytes.get(zeros..).unwrap_or_default()
}

/// Whether a big-endian value is odd (and therefore nonzero).
pub fn is_odd_nonzero(bytes: &[u8]) -> bool {
    bytes.last().is_some_and(|byte| byte & 1 == 1)
}

/// Compute `base^exponent mod modulus` into `out_be` (big-endian, modulus
/// width).
///
/// All inputs must be non-empty and at most `LIMBS` words wide, and the
/// modulus must be odd.
pub fn mod_pow_vartime<const LIMBS: usize>(
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
    let max_bytes = LIMBS * LIMB_BYTES;
    if base_be.len() > max_bytes || exponent_be.len() > max_bytes || modulus_be.len() > max_bytes {
        return Err(BigintError::TooLarge);
    }
    if !is_odd_nonzero(modulus_be) {
        return Err(BigintError::InvalidInput);
    }

    let modulus = Modulus::<LIMBS>::from_be(modulus_be);

    // Doubling 1 modulo m LIMBS * 64 times yields R mod m; doubling as many
    // times again yields R^2 mod m.
    let mut accumulator = one::<LIMBS>();
    modulus.reduce_once(&mut accumulator);
    for _ in 0..LIMBS * WORD_BITS {
        modulus.double(&mut accumulator);
    }
    let montgomery_one = accumulator;
    for _ in 0..LIMBS * WORD_BITS {
        modulus.double(&mut accumulator);
    }
    let r_squared = accumulator;

    // base < R, so one multiplication by R^2 both reduces it modulo m and
    // converts it to Montgomery form.
    let base = modulus.montgomery_mul(&load_be(base_be), &r_squared);
    let mut result = montgomery_one;
    let mut started = false;
    for byte in exponent_be {
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

/// An odd modulus with `-m^-1 mod 2^64`.
struct Modulus<const LIMBS: usize> {
    limbs: [Word; LIMBS],
    neg_inverse: Word,
}

impl<const LIMBS: usize> Modulus<LIMBS> {
    fn from_be(bytes: &[u8]) -> Self {
        let limbs = load_be::<LIMBS>(bytes);
        Self {
            limbs,
            neg_inverse: invert_odd_word(limbs[0]).wrapping_neg(),
        }
    }

    /// `value -= m` if `value >= m`.
    fn reduce_once(&self, value: &mut [Word; LIMBS]) {
        if compare(value, &self.limbs) != Ordering::Less {
            subtract_assign(value, &self.limbs);
        }
    }

    /// `value = 2 * value mod m`, for `value < m`.
    fn double(&self, value: &mut [Word; LIMBS]) {
        let carry = shift_left(value);
        if carry || compare(value, &self.limbs) != Ordering::Less {
            subtract_assign(value, &self.limbs);
        }
    }

    /// CIOS Montgomery multiplication: `left * right * R^-1 mod m`.
    ///
    /// Requires `left < R` and `right < m`; the result is fully reduced.
    fn montgomery_mul(&self, left: &[Word; LIMBS], right: &[Word; LIMBS]) -> [Word; LIMBS] {
        let mut output = [0; LIMBS];
        let mut meta_carry: WideWord = 0;
        for &left_limb in left {
            let product =
                WideWord::from(left_limb) * WideWord::from(right[0]) + WideWord::from(output[0]);
            let factor = (product as Word).wrapping_mul(self.neg_inverse);
            let (sum, overflow) =
                (WideWord::from(factor) * WideWord::from(self.limbs[0])).overflowing_add(product);
            let mut carry = (WideWord::from(overflow) << WORD_BITS) | (sum >> WORD_BITS);
            // output[i - 1] = low(output[i] + left * right[i] + factor * m[i] + carry)
            for inner in 1..LIMBS {
                let product = WideWord::from(left_limb) * WideWord::from(right[inner])
                    + WideWord::from(output[inner]);
                let reduction = WideWord::from(factor) * WideWord::from(self.limbs[inner]) + carry;
                let (sum, overflow) = product.overflowing_add(reduction);
                output[inner - 1] = sum as Word;
                carry = (WideWord::from(overflow) << WORD_BITS) | (sum >> WORD_BITS);
            }
            carry += meta_carry;
            output[LIMBS - 1] = carry as Word;
            meta_carry = carry >> WORD_BITS;
        }
        if meta_carry != 0 || compare(&output, &self.limbs) != Ordering::Less {
            subtract_assign(&mut output, &self.limbs);
        }
        output
    }
}

fn one<const LIMBS: usize>() -> [Word; LIMBS] {
    let mut limbs = [0; LIMBS];
    limbs[0] = 1;
    limbs
}

/// Load big-endian bytes into little-endian limbs.
fn load_be<const LIMBS: usize>(bytes: &[u8]) -> [Word; LIMBS] {
    let mut limbs = [0; LIMBS];
    for (destination, chunk) in limbs.iter_mut().zip(bytes.rchunks(LIMB_BYTES)) {
        *destination = chunk
            .iter()
            .fold(0, |word, byte| (word << 8) | Word::from(*byte));
    }
    limbs
}

fn compare<const LIMBS: usize>(a: &[Word; LIMBS], b: &[Word; LIMBS]) -> Ordering {
    a.iter().rev().cmp(b.iter().rev())
}

fn subtract_assign<const LIMBS: usize>(a: &mut [Word; LIMBS], b: &[Word; LIMBS]) {
    let mut borrow = false;
    for (left, right) in a.iter_mut().zip(b) {
        let (value, first) = left.overflowing_sub(*right);
        let (value, second) = value.overflowing_sub(Word::from(borrow));
        *left = value;
        borrow = first || second;
    }
}

/// Shift left by one bit; returns the bit shifted out of the top limb.
fn shift_left<const LIMBS: usize>(value: &mut [Word; LIMBS]) -> bool {
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
fn write_be_bytes<const LIMBS: usize>(limbs: &[Word; LIMBS], output: &mut [u8]) {
    for (destination, source) in output
        .iter_mut()
        .rev()
        .zip(limbs.iter().flat_map(|limb| limb.to_le_bytes()))
    {
        *destination = source;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMBS: usize = 64;
    const MAX_BYTES: usize = LIMBS * LIMB_BYTES;

    // Textbook RSA: p=61, q=53, n=3233, e=17, d=2753. m=65 -> c=2790.
    const N: &[u8] = &[0x0c, 0xa1];
    const E: &[u8] = &[0x11];
    const D: &[u8] = &[0x0a, 0xc1];
    const M: &[u8] = &[0x41];
    const C: &[u8] = &[0x0a, 0xe6];

    fn pow_to_vec(base: &[u8], exp: &[u8], modulus: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; modulus.len()];
        mod_pow_vartime::<LIMBS>(base, exp, modulus, &mut out).unwrap();
        out
    }

    #[test]
    fn textbook_roundtrip() {
        assert_eq!(pow_to_vec(M, E, N), C);
        assert_eq!(pow_to_vec(C, D, N), [0x00, M[0]]);
        assert_eq!(pow_to_vec(M, &[1], N), [0x00, M[0]]);
        let mut zero = [0u8; 2];
        mod_pow_vartime::<LIMBS>(&[0], E, N, &mut zero).unwrap();
        assert_eq!(zero, [0, 0]);
        // A base above the modulus is reduced first: 3233 + 65 -> 65^17.
        assert_eq!(pow_to_vec(&[0x0c, 0xe2], E, N), C);
        // Modulus 1: everything is congruent to zero.
        assert_eq!(pow_to_vec(M, E, &[1]), [0]);
    }

    #[test]
    fn widths_agree() {
        let mut narrow = [0u8; 2];
        mod_pow_vartime::<1>(C, D, N, &mut narrow).unwrap();
        let mut wide = [0u8; 2];
        mod_pow_vartime::<128>(C, D, N, &mut wide).unwrap();
        assert_eq!(narrow, [0x00, M[0]]);
        assert_eq!(wide, narrow);
    }

    #[test]
    fn rejects_invalid_inputs() {
        let mut out = [0u8; 2];
        assert_eq!(
            mod_pow_vartime::<LIMBS>(&[], E, N, &mut out),
            Err(BigintError::InvalidInput)
        );
        assert_eq!(
            mod_pow_vartime::<LIMBS>(M, E, &[0x0c, 0xa0], &mut out),
            Err(BigintError::InvalidInput)
        );
        assert_eq!(
            mod_pow_vartime::<LIMBS>(M, E, &[0, 0], &mut out),
            Err(BigintError::InvalidInput)
        );
        let mut wide = [0u8; 3];
        assert_eq!(
            mod_pow_vartime::<LIMBS>(M, E, N, &mut wide),
            Err(BigintError::InvalidInput)
        );
        let big = [0xffu8; MAX_BYTES + 1];
        let mut big_out = [0u8; MAX_BYTES + 1];
        assert_eq!(
            mod_pow_vartime::<LIMBS>(&big, E, &big, &mut big_out),
            Err(BigintError::TooLarge)
        );
    }

    #[test]
    fn cmp_be_ignores_leading_zeros() {
        assert_eq!(cmp_be(&[0, 0, 1], &[1]), Ordering::Equal);
        assert_eq!(cmp_be(&[2], &[1]), Ordering::Greater);
        assert_eq!(cmp_be(&[], &[0]), Ordering::Equal);
        assert_eq!(cmp_be(&[1, 0], &[0, 255]), Ordering::Greater);
        assert_eq!(cmp_be(&[0x00, 0xff], &[0x01, 0x00]), Ordering::Less);
    }

    #[test]
    fn max_width_smoke() {
        let modulus = [0xffu8; MAX_BYTES];
        let mut out = vec![0u8; MAX_BYTES];
        mod_pow_vartime::<LIMBS>(&[0xa5; MAX_BYTES], &[1], &modulus, &mut out).unwrap();
        assert_eq!(cmp_be(&out, &modulus), Ordering::Less);
        let mut base = [0xa5u8; MAX_BYTES];
        base[0] = 0x7f;
        assert_eq!(pow_to_vec(&base, &[1], &modulus), base);
    }
}

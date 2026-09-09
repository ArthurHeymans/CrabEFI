//! Fixed-width stack RSA arithmetic for authenticated variables.
//!
//! Variable-time Montgomery modular exponentiation over borrower-provided
//! byte slices, using only fixed `[Word; MAX_LIMBS]` stack buffers. This
//! replaces the allocator-backed `BoxedUintIn` fork: upstream const-generic
//! multiplication monomorphizes Karatsuba recursion into a ~25 KiB stack
//! frame at 4096-bit widths, which does not fit the 16 KiB firmware stack.
//! The schoolbook Montgomery engine here keeps the worst frame around
//! 4 KiB (six 512-byte operand buffers plus locals), enforced by the
//! link-time stack-sizes audit.
//!
//! # Panic-freedom
//!
//! The runtime image audit rejects any panic machinery (`panic_bounds_check`
//! and friends) in the final ELF, so even normally-harmless runtime bounds
//! checks are forbidden here. All hot loops therefore use iterators (which
//! cannot fail) or [`core::hint`]-free `get_unchecked` with an explicit
//! invariant: every index satisfies `i < n <= MAX_LIMBS`, where `n` is
//! validated once in [`mod_pow_vartime`] and threaded through unchanged.
//! Fallible conditions return [`BigintError`] instead of panicking.
//!
//! # Design notes
//!
//! - Variable-time by design (square-and-multiply skips leading zero bits),
//!   matching the previous implementation. Exponent bits are not considered
//!   secret from the OS caller in this firmware context.
//! - Every working buffer is [`zeroize::Zeroizing`]: secrets are scrubbed on
//!   all return paths, including errors.
//! - Operands are big-endian byte slices; widths are derived from the
//!   modulus, exactly like the previous implementation.

use core::cmp::Ordering;

use zeroize::Zeroizing;

type Word = u64;
type WideWord = u128;

const WORD_BITS: usize = 64;
const WORD_BYTES: usize = 8;

/// Maximum RSA width: 4096 bits = 64 limbs.
pub const MAX_LIMBS: usize = 64;
/// Maximum RSA operand size in bytes.
pub const MAX_BYTES: usize = MAX_LIMBS * WORD_BYTES;

/// Errors from stack RSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BigintError {
    /// An operand exceeds the stack-backed maximum width.
    TooLarge,
    /// An operand or modulus is invalid (empty, zero, or even modulus).
    InvalidInput,
}

/// Compare big-endian byte strings as integers (leading zeros ignored).
///
/// Iterator-only: the runtime image audit forbids even unreachable panic
/// machinery, so no indexing or subslicing appears here.
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
/// compare integer values; here only the low bit matters.
pub fn is_odd_nonzero(bytes: &[u8]) -> bool {
    !bytes.is_empty() && is_odd(bytes) && bytes.iter().any(|byte| *byte != 0)
}

fn is_odd(big_endian: &[u8]) -> bool {
    big_endian.last().is_some_and(|byte| byte & 1 != 0)
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
    // Width in limbs, derived from the modulus like the previous design.
    // Validated once here; every helper below upholds `i < n <= MAX_LIMBS`.
    let n = modulus_be.len().div_ceil(WORD_BYTES);
    debug_assert!(n > 0 && n <= MAX_LIMBS);

    let mut one = zeroed();
    one[0] = 1;
    reduce_once_sized(&mut one, modulus_be, n);
    // one = 2^(n*64) mod m = R mod m.
    let precision = n.checked_mul(WORD_BITS).ok_or(BigintError::TooLarge)?;
    for _ in 0..precision {
        double_mod_sized(&mut one, modulus_be, n);
    }
    // r2 = R^2 mod m.
    let mut r_squared = one.clone();
    for _ in 0..precision {
        double_mod_sized(&mut r_squared, modulus_be, n);
    }

    let inverse = invert_odd_word(low_word(modulus_be)).wrapping_neg();
    let reduced = remainder_sized(base_be, modulus_be, n);
    let base = montgomery_mul_sized(&reduced, &r_squared, modulus_be, inverse, n);
    let mut result = one.clone();

    let mut started = false;
    for byte in exponent_be.iter() {
        for bit in (0..8).rev() {
            let set = (byte >> bit) & 1 != 0;
            if !started && !set {
                continue;
            }
            started = true;
            result = montgomery_mul_sized(&result, &result, modulus_be, inverse, n);
            if set {
                result = montgomery_mul_sized(&result, &base, modulus_be, inverse, n);
            }
        }
    }

    let mut output = zeroed();
    montgomery_retrieve_sized(&result, &mut output, modulus_be, inverse, n);
    write_be_bytes(&output, n, out_be);
    Ok(())
}

/// Working buffer: always full width, only the low `n` limbs are live.
type Buffer = Zeroizing<[Word; MAX_LIMBS]>;

fn zeroed() -> Buffer {
    Zeroizing::new([0; MAX_LIMBS])
}

/// Least-significant limb of a big-endian byte string, via iterators only.
fn low_word(big_endian: &[u8]) -> Word {
    let mut low = 0;
    let mut shift = 0;
    for byte in big_endian.iter().rev().take(WORD_BYTES) {
        low |= Word::from(*byte) << shift;
        shift += 8;
    }
    low
}

/// Load big-endian bytes into the low limbs of a buffer.
fn load_be(buffer: &mut Buffer, bytes: &[u8], n: usize) {
    for (destination, chunk) in buffer.iter_mut().take(n).zip(bytes.rchunks(WORD_BYTES)) {
        *destination = chunk
            .iter()
            .fold(0, |word, byte| (word << 8) | Word::from(*byte));
    }
}

fn significant_len(value: &Buffer, n: usize) -> usize {
    value
        .iter()
        .take(n)
        .rposition(|limb| *limb != 0)
        .map_or(0, |index| index + 1)
}

fn compare(a: &Buffer, b: &Buffer, n: usize) -> Ordering {
    let a_len = significant_len(a, n);
    let b_len = significant_len(b, n);
    match a_len.cmp(&b_len) {
        Ordering::Equal => a
            .iter()
            .take(a_len)
            .rev()
            .zip(b.iter().take(b_len).rev())
            .find_map(|(left, right)| (left != right).then(|| left.cmp(right)))
            .unwrap_or(Ordering::Equal),
        ordering => ordering,
    }
}

fn subtract_assign(a: &mut Buffer, b: &Buffer, n: usize) {
    let mut borrow = false;
    for (left, right) in a.iter_mut().take(n).zip(b.iter().take(n)) {
        let (value, first) = left.overflowing_sub(*right);
        let (value, second) = value.overflowing_sub(Word::from(borrow));
        *left = value;
        borrow = first || second;
    }
}

fn reduce_once(value: &mut Buffer, modulus: &Buffer, n: usize) {
    if compare(value, modulus, n) != Ordering::Less {
        subtract_assign(value, modulus, n);
    }
}

fn shift_left_with_bit(value: &mut Buffer, n: usize, bit: Word) -> bool {
    let mut carry = bit;
    for limb in value.iter_mut().take(n) {
        let next = *limb >> (WORD_BITS - 1);
        *limb = (*limb << 1) | carry;
        carry = next;
    }
    carry != 0
}

fn double_mod(value: &mut Buffer, modulus: &Buffer, n: usize) {
    let carry = shift_left_with_bit(value, n, 0);
    if carry || compare(value, modulus, n) != Ordering::Less {
        subtract_assign(value, modulus, n);
    }
}

/// Sized wrappers loading the modulus fresh each call keep every helper
/// signature uniform: full buffers plus an explicit width.
fn reduce_once_sized(value: &mut Buffer, modulus_be: &[u8], n: usize) {
    let mut modulus = zeroed();
    load_be(&mut modulus, modulus_be, n);
    reduce_once(value, &modulus, n);
}

fn double_mod_sized(value: &mut Buffer, modulus_be: &[u8], n: usize) {
    let mut modulus = zeroed();
    load_be(&mut modulus, modulus_be, n);
    double_mod(value, &modulus, n);
}

fn remainder_sized(value_be: &[u8], modulus_be: &[u8], n: usize) -> Buffer {
    let mut modulus = zeroed();
    load_be(&mut modulus, modulus_be, n);
    let mut remainder = zeroed();
    // Process value bits MSB-first into an n-wide remainder.
    for byte in value_be.iter() {
        for bit in (0..8).rev() {
            shift_left_with_bit(&mut remainder, n, Word::from((byte >> bit) & 1));
            reduce_once(&mut remainder, &modulus, n);
        }
    }
    remainder
}

fn invert_odd_word(value: Word) -> Word {
    // Newton iteration doubles the number of correct low bits each round.
    let mut inverse: Word = 1;
    for _ in 0..6 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(value.wrapping_mul(inverse)));
    }
    inverse
}

fn montgomery_mul_sized(
    left: &Buffer,
    right: &Buffer,
    modulus_be: &[u8],
    inverse: Word,
    n: usize,
) -> Buffer {
    let mut modulus = zeroed();
    load_be(&mut modulus, modulus_be, n);
    let mut output = zeroed();
    let carry = montgomery_multiply(left, right, &mut output, &modulus, inverse, n);
    if carry != 0 || compare(&output, &modulus, n) != Ordering::Less {
        subtract_assign(&mut output, &modulus, n);
    }
    output
}

/// Schoolbook CIOS Montgomery multiplication: `output = left*right*R^-1`.
///
/// All buffers are full width; only the low `n` limbs participate.
/// Indexing uses `get_unchecked` because the runtime image audit forbids
/// even unreachable panic machinery: the caller upholds `0 < n <= MAX_LIMBS`
/// (validated once in [`mod_pow_vartime`]), so every index below satisfies
/// `i < n <= MAX_LIMBS` against full-width buffers.
fn montgomery_multiply(
    left: &Buffer,
    right: &Buffer,
    output: &mut Buffer,
    modulus: &Buffer,
    inverse: Word,
    n: usize,
) -> Word {
    debug_assert!(n > 0 && n <= MAX_LIMBS);
    let mut meta_carry: WideWord = 0;
    for index in 0..n {
        // SAFETY: index < n <= MAX_LIMBS; all buffers are full width.
        let left_limb = unsafe { *left.get_unchecked(index) };
        let first_right = unsafe { *right.get_unchecked(0) };
        let first_output = unsafe { *output.get_unchecked(0) };
        let first_modulus = unsafe { *modulus.get_unchecked(0) };
        let product = left_limb as WideWord * first_right as WideWord + first_output as WideWord;
        let factor = (product as Word).wrapping_mul(inverse);
        let (sum, overflow) =
            (factor as WideWord * first_modulus as WideWord).overflowing_add(product);
        let mut carry = ((overflow as WideWord) << WORD_BITS) | (sum >> WORD_BITS);
        for inner in 1..n {
            // SAFETY: 1 <= inner < n <= MAX_LIMBS; inner - 1 < n likewise.
            let right_limb = unsafe { *right.get_unchecked(inner) };
            let output_limb = unsafe { *output.get_unchecked(inner) };
            let modulus_limb = unsafe { *modulus.get_unchecked(inner) };
            let product = left_limb as WideWord * right_limb as WideWord + output_limb as WideWord;
            let reduction = factor as WideWord * modulus_limb as WideWord + carry;
            let (sum, overflow) = product.overflowing_add(reduction);
            unsafe { *output.get_unchecked_mut(inner - 1) = sum as Word };
            carry = ((overflow as WideWord) << WORD_BITS) | (sum >> WORD_BITS);
        }
        carry += meta_carry;
        // SAFETY: n - 1 < n <= MAX_LIMBS (n >= 1: the outer loop ran).
        unsafe { *output.get_unchecked_mut(n - 1) = carry as Word };
        meta_carry = carry >> WORD_BITS;
    }
    meta_carry as Word
}

fn montgomery_retrieve_sized(
    input: &Buffer,
    output: &mut Buffer,
    modulus_be: &[u8],
    inverse: Word,
    n: usize,
) {
    let mut modulus = zeroed();
    load_be(&mut modulus, modulus_be, n);
    montgomery_retrieve(input, output, &modulus, inverse, n);
}

fn montgomery_retrieve(
    input: &Buffer,
    output: &mut Buffer,
    modulus: &Buffer,
    inverse: Word,
    n: usize,
) {
    debug_assert!(n > 0 && n <= MAX_LIMBS);
    for index in 0..n {
        // SAFETY: index < n <= MAX_LIMBS against full-width buffers.
        let input_limb = unsafe { *input.get_unchecked(index) };
        let first_output = unsafe { *output.get_unchecked(0) };
        let factor = first_output.wrapping_add(input_limb).wrapping_mul(inverse);
        let first_modulus = unsafe { *modulus.get_unchecked(0) };
        let first = factor as WideWord * first_modulus as WideWord
            + input_limb as WideWord
            + first_output as WideWord;
        unsafe { *output.get_unchecked_mut(0) = (first >> WORD_BITS) as Word };
        for inner in 1..n {
            // SAFETY: 1 <= inner < n <= MAX_LIMBS; inner - 1 likewise.
            let modulus_limb = unsafe { *modulus.get_unchecked(inner) };
            let output_limb = unsafe { *output.get_unchecked(inner) };
            let previous = unsafe { *output.get_unchecked(inner - 1) };
            let sum = factor as WideWord * modulus_limb as WideWord
                + output_limb as WideWord
                + previous as WideWord;
            unsafe {
                *output.get_unchecked_mut(inner - 1) = sum as Word;
                *output.get_unchecked_mut(inner) = (sum >> WORD_BITS) as Word;
            }
        }
    }
}

fn write_be_bytes(buffer: &Buffer, limbs: usize, output: &mut [u8]) {
    debug_assert!(output.len() <= limbs * WORD_BYTES);
    for (destination, source) in output.iter_mut().rev().zip(
        buffer
            .iter()
            .take(limbs)
            .flat_map(|limb| limb.to_le_bytes().into_iter()),
    ) {
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
    }
}

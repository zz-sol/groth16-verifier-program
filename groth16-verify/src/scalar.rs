//! Big-endian `Fr` scalar helpers. No arithmetic — only the comparisons the
//! verifier needs, each a fixed-size byte compare.

use crate::constants::{FR_MODULUS, FR_SIZE};

/// `s < r`. Equal-length big-endian byte strings compare lexicographically in
/// the same order as the integers they encode.
#[inline]
pub fn is_canonical(s: &[u8; FR_SIZE]) -> bool {
    s.as_slice() < FR_MODULUS.as_slice()
}

/// All-zero bytes: the zero scalar, and also the syscall encoding of the
/// identity in G1 and G2, which is why the length is generic.
///
/// OR-reduces the bytes eight at a time rather than testing each one. On SBF
/// a byte-wise early-exit loop is cheap on random input and expensive on
/// all-zero input (32 iterations), and the unrolled byte-wise form the
/// compiler produces for a fixed array is the reverse; `N/8` word loads are
/// cheap in both cases and branch-free.
#[inline]
pub fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    const { assert!(N.is_multiple_of(8), "is_zero operates on whole words") }
    let mut acc = 0u64;
    for word in bytes.chunks_exact(8) {
        acc |= u64::from_ne_bytes(word.try_into().unwrap());
    }
    acc == 0
}

#[inline]
pub fn is_one(s: &[u8; FR_SIZE]) -> bool {
    s[FR_SIZE - 1] == 1 && s[..FR_SIZE - 1].iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modulus_boundary() {
        assert!(!is_canonical(&FR_MODULUS));
        let mut below = FR_MODULUS;
        below[FR_SIZE - 1] -= 1;
        assert!(is_canonical(&below));
        assert!(is_canonical(&[0u8; FR_SIZE]));
        assert!(!is_canonical(&[0xff; FR_SIZE]));
    }

    #[test]
    fn zero_and_one() {
        let zero = [0u8; FR_SIZE];
        let mut one = [0u8; FR_SIZE];
        one[FR_SIZE - 1] = 1;
        let mut two = one;
        two[FR_SIZE - 1] = 2;
        let mut high_one = [0u8; FR_SIZE];
        high_one[0] = 1;
        assert!(is_zero(&zero) && !is_one(&zero));
        assert!(is_one(&one) && !is_zero(&one));
        assert!(!is_one(&two) && !is_one(&high_one));
    }
}

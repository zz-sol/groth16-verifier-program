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
/// identity in G1 and G2, which is why this takes a slice.
#[inline]
pub fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
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

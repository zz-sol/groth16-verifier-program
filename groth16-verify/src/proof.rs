//! Zero-copy view over a serialized proof, `A ‖ B ‖ C`.

use crate::{
    constants::{
        G1_SIZE, G2_SIZE, PAIRING_ELEMENT_SIZE, PROOF_A_OFFSET, PROOF_B_OFFSET, PROOF_C_OFFSET,
        PROOF_SIZE,
    },
    error::Groth16Error,
};

/// A borrowed proof in the on-chain wire format. Construction checks only the
/// length; point validity is established by the pairing syscall.
#[derive(Debug, Clone, Copy)]
pub struct Proof<'a> {
    bytes: &'a [u8; PROOF_SIZE],
}

impl<'a> Proof<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, Groth16Error> {
        let bytes: &[u8; PROOF_SIZE] = bytes
            .try_into()
            .map_err(|_| Groth16Error::InvalidProofLength)?;
        Ok(Self { bytes })
    }

    /// Splits `A ‖ B ‖ C` off the front of `bytes`, returning the proof and
    /// whatever follows it (the public inputs, in the `Verify` instruction).
    #[inline]
    pub fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Groth16Error> {
        if bytes.len() < PROOF_SIZE {
            return Err(Groth16Error::InvalidProofLength);
        }
        let (proof, rest) = bytes.split_at(PROOF_SIZE);
        Ok((Self::from_bytes(proof)?, rest))
    }

    #[inline]
    pub fn as_bytes(&self) -> &'a [u8; PROOF_SIZE] {
        self.bytes
    }

    #[inline]
    pub fn a(&self) -> &'a [u8; G1_SIZE] {
        fixed(self.bytes, PROOF_A_OFFSET)
    }

    #[inline]
    pub fn b(&self) -> &'a [u8; G2_SIZE] {
        fixed(self.bytes, PROOF_B_OFFSET)
    }

    #[inline]
    pub fn c(&self) -> &'a [u8; G1_SIZE] {
        fixed(self.bytes, PROOF_C_OFFSET)
    }

    /// `A ‖ B`, already in pairing-slot order.
    #[inline]
    pub fn a_b(&self) -> &'a [u8; PAIRING_ELEMENT_SIZE] {
        fixed(self.bytes, PROOF_A_OFFSET)
    }
}

/// Fixed-size sub-array of `N` bytes at `offset`. The slice bounds check
/// stays; where `offset` is a constant (every proof and fixed key slot) it
/// folds away, and where it is not (`VerifyingKey::ic(i)`) it is one compare.
#[inline(always)]
pub(crate) fn fixed<const N: usize>(bytes: &[u8], offset: usize) -> &[u8; N] {
    bytes[offset..offset + N]
        .try_into()
        .expect("offset and length are compile-time constants within bounds")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_alias_the_expected_ranges() {
        let bytes: std::vec::Vec<u8> = (0..PROOF_SIZE as u16).map(|i| i as u8).collect();
        let proof = Proof::from_bytes(&bytes).unwrap();
        assert_eq!(proof.a(), &bytes[..G1_SIZE]);
        assert_eq!(proof.b(), &bytes[G1_SIZE..G1_SIZE + G2_SIZE]);
        assert_eq!(proof.c(), &bytes[G1_SIZE + G2_SIZE..]);
        assert_eq!(proof.a_b(), &bytes[..G1_SIZE + G2_SIZE]);
        assert_eq!(proof.as_bytes().len(), PROOF_SIZE);
    }

    #[test]
    fn length_is_exact_and_split_returns_the_rest() {
        assert_eq!(
            Proof::from_bytes(&[0u8; PROOF_SIZE - 1]).err(),
            Some(Groth16Error::InvalidProofLength)
        );
        assert_eq!(
            Proof::from_bytes(&[0u8; PROOF_SIZE + 1]).err(),
            Some(Groth16Error::InvalidProofLength)
        );
        let mut bytes = std::vec![0u8; PROOF_SIZE + 3];
        bytes[PROOF_SIZE..].copy_from_slice(&[7, 8, 9]);
        let (_, rest) = Proof::split_from(&bytes).unwrap();
        assert_eq!(rest, &[7, 8, 9]);
        assert_eq!(
            Proof::split_from(&bytes[..PROOF_SIZE - 1]).err(),
            Some(Groth16Error::InvalidProofLength)
        );
    }
}

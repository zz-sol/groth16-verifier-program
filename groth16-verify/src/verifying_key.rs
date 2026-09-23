//! Zero-copy view over a verifying-key body, `α ‖ −β ‖ −γ ‖ −δ ‖ IC₀..ICₙ`.
//!
//! `β`, `γ` and `δ` are stored *negated* so that the pairing input is built by
//! copying alone. See `docs/design.md §4`.

use crate::{
    constants::{
        vk_body_len, G1_SIZE, G2_SIZE, MAX_PUBLIC_INPUTS, PAIRING_ELEMENT_SIZE, VK_ALPHA_OFFSET,
        VK_FIXED_SIZE, VK_IC_OFFSET, VK_NEG_BETA_OFFSET, VK_NEG_DELTA_OFFSET, VK_NEG_GAMMA_OFFSET,
    },
    error::Groth16Error,
    proof::fixed,
};

/// A borrowed verifying key in the on-chain wire format.
#[derive(Debug, Clone, Copy)]
pub struct VerifyingKey<'a> {
    body: &'a [u8],
    num_public_inputs: usize,
}

impl<'a> VerifyingKey<'a> {
    /// Interprets `body` as a key, deriving `n` from its length. Rejects any
    /// length that is not `448 + 64·(n+1)` for some `n ≤ MAX_PUBLIC_INPUTS`.
    ///
    /// Layout only: the points are not checked. A body read from a published
    /// key account has already passed [`Self::validate_for_publish`]; a body
    /// from anywhere else should be put through it once when it is stored.
    /// Neither says which circuit the key belongs to — see the crate docs.
    #[inline]
    pub fn from_body(body: &'a [u8]) -> Result<Self, Groth16Error> {
        let ic_bytes = body
            .len()
            .checked_sub(VK_FIXED_SIZE)
            .ok_or(Groth16Error::InvalidKeyLength)?;
        if !ic_bytes.is_multiple_of(G1_SIZE) {
            return Err(Groth16Error::InvalidKeyLength);
        }
        let num_public_inputs = (ic_bytes / G1_SIZE)
            .checked_sub(1)
            .ok_or(Groth16Error::InvalidKeyLength)?;
        if num_public_inputs > MAX_PUBLIC_INPUTS {
            return Err(Groth16Error::InvalidKeyLength);
        }
        Ok(Self {
            body,
            num_public_inputs,
        })
    }

    /// Interprets `body` as a key for a *known* `n`, requiring the exact length.
    /// Used where `n` comes from an account header and must agree with the data.
    #[inline]
    pub fn from_body_with_len(
        body: &'a [u8],
        num_public_inputs: usize,
    ) -> Result<Self, Groth16Error> {
        if num_public_inputs > MAX_PUBLIC_INPUTS {
            return Err(Groth16Error::TooManyPublicInputs);
        }
        if body.len() != vk_body_len(num_public_inputs) {
            return Err(Groth16Error::InvalidKeyLength);
        }
        Ok(Self {
            body,
            num_public_inputs,
        })
    }

    /// Checks every point and rejects identity α, β, γ and δ, matching Publish.
    ///
    /// Constructors check only layout. Call this once when storing an inline
    /// key; verification does not repeat this registration-time validation.
    /// This is a well-formedness check: it says the bytes are a Groth16 key for
    /// which the verifier is sound, not that they are the key for any
    /// particular circuit. That is settled off-chain against the setup.
    pub fn validate_for_publish(&self) -> Result<(), Groth16Error> {
        crate::validation::validate_for_publish(self)
    }

    #[inline]
    pub fn body(&self) -> &'a [u8] {
        self.body
    }

    #[inline]
    pub fn num_public_inputs(&self) -> usize {
        self.num_public_inputs
    }

    #[inline]
    pub fn alpha(&self) -> &'a [u8; G1_SIZE] {
        fixed(self.body, VK_ALPHA_OFFSET)
    }

    #[inline]
    pub fn neg_beta(&self) -> &'a [u8; G2_SIZE] {
        fixed(self.body, VK_NEG_BETA_OFFSET)
    }

    #[inline]
    pub fn neg_gamma(&self) -> &'a [u8; G2_SIZE] {
        fixed(self.body, VK_NEG_GAMMA_OFFSET)
    }

    #[inline]
    pub fn neg_delta(&self) -> &'a [u8; G2_SIZE] {
        fixed(self.body, VK_NEG_DELTA_OFFSET)
    }

    /// `α ‖ −β`, already in pairing-slot order.
    #[inline]
    pub fn alpha_neg_beta(&self) -> &'a [u8; PAIRING_ELEMENT_SIZE] {
        fixed(self.body, VK_ALPHA_OFFSET)
    }

    /// `ICᵢ` for `0 ≤ i ≤ n`. Panics on `i > n`; callers iterate `0..=n`.
    #[inline]
    pub fn ic(&self, i: usize) -> &'a [u8; G1_SIZE] {
        debug_assert!(i <= self.num_public_inputs);
        fixed(self.body, VK_IC_OFFSET + i * G1_SIZE)
    }

    /// The whole `IC₀..ICₙ` table.
    #[inline]
    pub fn ic_table(&self) -> &'a [u8] {
        &self.body[VK_IC_OFFSET..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_inference() {
        for n in [0usize, 1, 7, MAX_PUBLIC_INPUTS] {
            let body = alloc_body(n);
            let vk = VerifyingKey::from_body(&body).unwrap();
            assert_eq!(vk.num_public_inputs(), n);
            assert_eq!(vk.ic_table().len(), G1_SIZE * (n + 1));
            VerifyingKey::from_body_with_len(&body, n).unwrap();
            assert_eq!(
                VerifyingKey::from_body_with_len(&body, n + 1).err(),
                Some(if n + 1 > MAX_PUBLIC_INPUTS {
                    Groth16Error::TooManyPublicInputs
                } else {
                    Groth16Error::InvalidKeyLength
                })
            );
        }
        // No IC₀ at all.
        assert_eq!(
            VerifyingKey::from_body(&[0u8; VK_FIXED_SIZE]).err(),
            Some(Groth16Error::InvalidKeyLength)
        );
        // Off by one.
        assert_eq!(
            VerifyingKey::from_body(&alloc_body(1)[..vk_body_len(1) - 1]).err(),
            Some(Groth16Error::InvalidKeyLength)
        );
        // One past the maximum.
        assert_eq!(
            VerifyingKey::from_body(&alloc_body(MAX_PUBLIC_INPUTS + 1)).err(),
            Some(Groth16Error::InvalidKeyLength)
        );
    }

    #[test]
    fn slot_views_alias_the_body() {
        let mut body = alloc_body(2);
        for (i, b) in body.iter_mut().enumerate() {
            *b = i as u8;
        }
        let vk = VerifyingKey::from_body(&body).unwrap();
        assert_eq!(&vk.alpha_neg_beta()[..G1_SIZE], vk.alpha());
        assert_eq!(&vk.alpha_neg_beta()[G1_SIZE..], vk.neg_beta());
        assert_eq!(vk.ic(0), &body[VK_IC_OFFSET..VK_IC_OFFSET + G1_SIZE]);
        assert_eq!(
            vk.ic(2),
            &body[VK_IC_OFFSET + 2 * G1_SIZE..VK_IC_OFFSET + 3 * G1_SIZE]
        );
    }

    fn alloc_body(n: usize) -> std::vec::Vec<u8> {
        std::vec![0u8; vk_body_len(n)]
    }
}

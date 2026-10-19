//! Zero-copy view over a verifying-key body, `α ‖ −β ‖ −γ ‖ −δ ‖ IC₀..ICₙ`.
//!
//! `β`, `γ` and `δ` are stored *negated* so that the pairing input is built by
//! copying alone. See `docs/design.md §4`.
//!
//! The view carries a type-level marker saying whether its points have been
//! validated. The constructors produce an [`Unchecked`] key, which only
//! [`VerifyingKey::validate_for_publish`] or
//! [`VerifyingKey::assume_validated`] turns into the [`Checked`] key that
//! [`verify`](crate::verify) accepts. The marker is zero-sized and never
//! inspected at runtime; its only job is to make the step from parsed bytes
//! to usable key visible in the caller's code.

use {
    crate::{
        constants::{
            vk_body_len, G1_SIZE, G2_SIZE, MAX_PUBLIC_INPUTS, PAIRING_ELEMENT_SIZE,
            VK_ALPHA_OFFSET, VK_FIXED_SIZE, VK_IC_OFFSET, VK_NEG_BETA_OFFSET, VK_NEG_DELTA_OFFSET,
            VK_NEG_GAMMA_OFFSET,
        },
        error::Groth16Error,
        proof::fixed,
    },
    core::marker::PhantomData,
};

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Unchecked {}
    impl Sealed for super::Checked {}
}

/// Whether a [`VerifyingKey`]'s points have been validated. Implemented only
/// by [`Unchecked`] and [`Checked`].
pub trait KeyState: sealed::Sealed + Copy + core::fmt::Debug {}

/// The constructors' output: layout checked, points not.
#[derive(Debug, Clone, Copy)]
pub struct Unchecked;

/// Every point validated, or asserted to have been. The only state
/// [`verify`](crate::verify) accepts.
#[derive(Debug, Clone, Copy)]
pub struct Checked;

impl KeyState for Unchecked {}
impl KeyState for Checked {}

/// A borrowed verifying key in the on-chain wire format.
///
/// `S` is [`Unchecked`] from the constructors and [`Checked`] after
/// [`validate_for_publish`](Self::validate_for_publish) or
/// [`assume_validated`](Self::assume_validated). Only a `Checked` key can be
/// passed to [`verify`](crate::verify).
#[derive(Debug, Clone, Copy)]
pub struct VerifyingKey<'a, S: KeyState = Unchecked> {
    body: &'a [u8],
    num_public_inputs: usize,
    state: PhantomData<S>,
}

impl<'a> VerifyingKey<'a, Unchecked> {
    /// Interprets `body` as a key, deriving `n` from its length. Rejects any
    /// length that is not `448 + 64·(n+1)` for some `n ≤ MAX_PUBLIC_INPUTS`.
    ///
    /// Layout only: the points are not checked, and the result cannot be
    /// verified against until it has been through
    /// [`validate_for_publish`](Self::validate_for_publish) or
    /// [`assume_validated`](Self::assume_validated). Neither says which circuit
    /// the key belongs to — see the crate docs.
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
            state: PhantomData,
        })
    }

    /// Interprets `body` as a key for a *known* `n`, requiring the exact length.
    /// Used where `n` comes from an account header and must agree with the data.
    /// Layout only, like [`from_body`](Self::from_body).
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
            state: PhantomData,
        })
    }

    /// Checks every point and rejects identity α, β, γ and δ, matching Publish.
    ///
    /// Call this once when a key is accepted or stored; it costs about
    /// `61,000 + 167·n` CU, and verification does not repeat it. It is a
    /// well-formedness check: every point is on the curve and in the
    /// prime-order subgroup, and the verification equation does not
    /// degenerate for any proof. It says nothing about the setup that
    /// produced the key or the circuit it belongs to — a well-formed key with
    /// a known trapdoor, or for the wrong circuit, passes. That is settled
    /// off-chain against the setup; see the crate docs.
    pub fn validate_for_publish(self) -> Result<VerifyingKey<'a, Checked>, Groth16Error> {
        crate::validation::validate_for_publish(&self)?;
        Ok(self.assume_validated())
    }

    /// Marks the key as validated without checking anything.
    ///
    /// The marker cannot outlive one execution, so every program that verifies
    /// against a stored key goes through here on each call. It is correct in
    /// exactly two situations, and the caller is asserting one of them:
    ///
    /// - The body was read from a key account **owned by the registry
    ///   program**, at the address the application pinned. `Publish` is the
    ///   only instruction that creates such an account and it validates the
    ///   body first. The discriminator alone proves nothing: any program can
    ///   write that byte into its own account, so the owner check is the
    ///   whole argument.
    /// - The caller stores the key itself and ran
    ///   [`validate_for_publish`](Self::validate_for_publish) on these exact
    ///   bytes before storing them.
    ///
    /// Anything else hands [`verify`](crate::verify) a key under which its
    /// result means nothing; see the crate docs for what can go wrong.
    #[inline]
    pub fn assume_validated(self) -> VerifyingKey<'a, Checked> {
        VerifyingKey {
            body: self.body,
            num_public_inputs: self.num_public_inputs,
            state: PhantomData,
        }
    }
}

impl<'a, S: KeyState> VerifyingKey<'a, S> {
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

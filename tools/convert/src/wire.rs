//! The on-chain wire format, written from and read back into arkworks types.
//!
//! Uncompressed, big-endian; `G2` coordinates are `c1 ‖ c0` (EIP-197 order,
//! which is also gnark's); the identity is all-zero bytes. The key body stores
//! `−β`, `−γ`, `−δ`.

use {
    crate::ConvertError,
    ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine},
    ark_ec::{
        short_weierstrass::{Affine, SWCurveConfig},
        AffineRepr,
    },
    ark_ff::{BigInteger, PrimeField},
    sha2::{Digest, Sha256},
    solana_groth16_verify::constants::{
        vk_body_len, FQ_SIZE, FR_SIZE, G1_SIZE, G2_SIZE, MAX_PUBLIC_INPUTS, PROOF_A_OFFSET,
        PROOF_B_OFFSET, PROOF_C_OFFSET, PROOF_SIZE, VK_ALPHA_OFFSET, VK_IC_OFFSET,
        VK_NEG_BETA_OFFSET, VK_NEG_DELTA_OFFSET, VK_NEG_GAMMA_OFFSET,
    },
};

// --- Encoding -----------------------------------------------------------------

pub fn fq_to_bytes(x: &Fq) -> [u8; FQ_SIZE] {
    x.into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("Fq is 32 bytes")
}

pub fn fq2_to_bytes(x: &Fq2) -> [u8; 2 * FQ_SIZE] {
    let mut out = [0u8; 2 * FQ_SIZE];
    out[..FQ_SIZE].copy_from_slice(&fq_to_bytes(&x.c1));
    out[FQ_SIZE..].copy_from_slice(&fq_to_bytes(&x.c0));
    out
}

pub fn fr_to_bytes(s: &Fr) -> [u8; FR_SIZE] {
    s.into_bigint()
        .to_bytes_be()
        .try_into()
        .expect("Fr is 32 bytes")
}

pub fn g1_to_bytes(p: &G1Affine) -> [u8; G1_SIZE] {
    let mut out = [0u8; G1_SIZE];
    if let Some((x, y)) = p.xy() {
        out[..FQ_SIZE].copy_from_slice(&fq_to_bytes(&x));
        out[FQ_SIZE..].copy_from_slice(&fq_to_bytes(&y));
    }
    out
}

pub fn g2_to_bytes(p: &G2Affine) -> [u8; G2_SIZE] {
    let mut out = [0u8; G2_SIZE];
    if let Some((x, y)) = p.xy() {
        out[..2 * FQ_SIZE].copy_from_slice(&fq2_to_bytes(&x));
        out[2 * FQ_SIZE..].copy_from_slice(&fq2_to_bytes(&y));
    }
    out
}

// --- Decoding -----------------------------------------------------------------

pub fn fq_from_bytes(bytes: &[u8; FQ_SIZE]) -> Result<Fq, ConvertError> {
    let x = Fq::from_be_bytes_mod_order(bytes);
    if fq_to_bytes(&x) != *bytes {
        return Err(ConvertError::NonCanonicalField);
    }
    Ok(x)
}

pub fn fq2_from_bytes(bytes: &[u8; 2 * FQ_SIZE]) -> Result<Fq2, ConvertError> {
    let c1 = fq_from_bytes(bytes[..FQ_SIZE].try_into().unwrap())?;
    let c0 = fq_from_bytes(bytes[FQ_SIZE..].try_into().unwrap())?;
    Ok(Fq2::new(c0, c1))
}

pub fn fr_from_bytes(bytes: &[u8; FR_SIZE]) -> Result<Fr, ConvertError> {
    let s = Fr::from_be_bytes_mod_order(bytes);
    if fr_to_bytes(&s) != *bytes {
        return Err(ConvertError::NonCanonicalField);
    }
    Ok(s)
}

/// Decodes and fully validates (on-curve, subgroup) a G1 point.
pub fn g1_from_bytes(bytes: &[u8; G1_SIZE]) -> Result<G1Affine, ConvertError> {
    if bytes.iter().all(|&b| b == 0) {
        return Ok(G1Affine::identity());
    }
    let x = fq_from_bytes(bytes[..FQ_SIZE].try_into().unwrap())?;
    let y = fq_from_bytes(bytes[FQ_SIZE..].try_into().unwrap())?;
    checked_affine(G1Affine::new_unchecked(x, y))
}

/// Decodes and fully validates (on-curve, subgroup) a G2 point.
pub fn g2_from_bytes(bytes: &[u8; G2_SIZE]) -> Result<G2Affine, ConvertError> {
    if bytes.iter().all(|&b| b == 0) {
        return Ok(G2Affine::identity());
    }
    let x = fq2_from_bytes(bytes[..2 * FQ_SIZE].try_into().unwrap())?;
    let y = fq2_from_bytes(bytes[2 * FQ_SIZE..].try_into().unwrap())?;
    checked_affine(G2Affine::new_unchecked(x, y))
}

pub(crate) fn checked_affine<C: SWCurveConfig>(p: Affine<C>) -> Result<Affine<C>, ConvertError> {
    if p.is_zero() || (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()) {
        Ok(p)
    } else {
        Err(ConvertError::InvalidPoint)
    }
}

// --- Key and proof ------------------------------------------------------------

/// A verifying key in the on-chain body layout, ready to upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnChainKey {
    body: Vec<u8>,
    num_public_inputs: usize,
}

impl OnChainKey {
    /// Builds the body from the key's elements, negating `β`, `γ`, `δ`.
    /// `ic` is `IC₀..ICₙ`, so `n = ic.len() − 1`.
    pub fn new(
        alpha: &G1Affine,
        beta: &G2Affine,
        gamma: &G2Affine,
        delta: &G2Affine,
        ic: &[G1Affine],
    ) -> Result<Self, ConvertError> {
        let num_public_inputs = ic
            .len()
            .checked_sub(1)
            .ok_or(ConvertError::Unsupported("key has no IC₀"))?;
        if num_public_inputs > MAX_PUBLIC_INPUTS {
            return Err(ConvertError::TooManyPublicInputs(num_public_inputs));
        }
        let mut body = vec![0u8; vk_body_len(num_public_inputs)];
        body[VK_ALPHA_OFFSET..VK_ALPHA_OFFSET + G1_SIZE].copy_from_slice(&g1_to_bytes(alpha));
        body[VK_NEG_BETA_OFFSET..VK_NEG_BETA_OFFSET + G2_SIZE]
            .copy_from_slice(&g2_to_bytes(&-*beta));
        body[VK_NEG_GAMMA_OFFSET..VK_NEG_GAMMA_OFFSET + G2_SIZE]
            .copy_from_slice(&g2_to_bytes(&-*gamma));
        body[VK_NEG_DELTA_OFFSET..VK_NEG_DELTA_OFFSET + G2_SIZE]
            .copy_from_slice(&g2_to_bytes(&-*delta));
        for (i, p) in ic.iter().enumerate() {
            let off = VK_IC_OFFSET + i * G1_SIZE;
            body[off..off + G1_SIZE].copy_from_slice(&g1_to_bytes(p));
        }
        Ok(Self {
            body,
            num_public_inputs,
        })
    }

    /// Wraps an existing body, validating its length and every point.
    pub fn from_body(body: Vec<u8>) -> Result<Self, ConvertError> {
        let (alpha, beta, gamma, delta, ic) = decode_body(&body)?;
        let rebuilt = Self::new(&alpha, &beta, &gamma, &delta, &ic)?;
        debug_assert_eq!(rebuilt.body, body);
        Ok(rebuilt)
    }

    /// Checks the same point and identity rules as on-chain Publish.
    /// Conversion alone does not require a publishable key.
    pub fn validate_for_publish(&self) -> Result<(), solana_groth16_verify::Groth16Error> {
        solana_groth16_verify::VerifyingKey::from_body(&self.body)?
            .validate_for_publish()
            .map(|_| ())
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn num_public_inputs(&self) -> usize {
        self.num_public_inputs
    }

    /// `sha256(body)` — the canonical account's PDA seed.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(&self.body).into()
    }

    /// Decodes back to `(α, β, γ, δ, IC)` with the negations undone.
    pub fn elements(
        &self,
    ) -> Result<(G1Affine, G2Affine, G2Affine, G2Affine, Vec<G1Affine>), ConvertError> {
        decode_body(&self.body)
    }
}

fn decode_body(
    body: &[u8],
) -> Result<(G1Affine, G2Affine, G2Affine, G2Affine, Vec<G1Affine>), ConvertError> {
    let vk = solana_groth16_verify::VerifyingKey::from_body(body)
        .map_err(|_| ConvertError::Unsupported("key body has an invalid length"))?;
    let alpha = g1_from_bytes(vk.alpha())?;
    let beta = -g2_from_bytes(vk.neg_beta())?;
    let gamma = -g2_from_bytes(vk.neg_gamma())?;
    let delta = -g2_from_bytes(vk.neg_delta())?;
    let ic = (0..=vk.num_public_inputs())
        .map(|i| g1_from_bytes(vk.ic(i)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok((alpha, beta, gamma, delta, ic))
}

/// A proof in the on-chain layout, `A ‖ B ‖ C`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OnChainProof(pub [u8; PROOF_SIZE]);

impl OnChainProof {
    pub fn new(a: &G1Affine, b: &G2Affine, c: &G1Affine) -> Self {
        let mut out = [0u8; PROOF_SIZE];
        out[PROOF_A_OFFSET..PROOF_A_OFFSET + G1_SIZE].copy_from_slice(&g1_to_bytes(a));
        out[PROOF_B_OFFSET..PROOF_B_OFFSET + G2_SIZE].copy_from_slice(&g2_to_bytes(b));
        out[PROOF_C_OFFSET..PROOF_C_OFFSET + G1_SIZE].copy_from_slice(&g1_to_bytes(c));
        Self(out)
    }

    pub fn elements(&self) -> Result<(G1Affine, G2Affine, G1Affine), ConvertError> {
        let a = g1_from_bytes(self.0[PROOF_A_OFFSET..PROOF_B_OFFSET].try_into().unwrap())?;
        let b = g2_from_bytes(self.0[PROOF_B_OFFSET..PROOF_C_OFFSET].try_into().unwrap())?;
        let c = g1_from_bytes(self.0[PROOF_C_OFFSET..].try_into().unwrap())?;
        Ok((a, b, c))
    }
}

/// Encodes public inputs as the `Verify` instruction carries them.
pub fn public_inputs_to_bytes(inputs: &[Fr]) -> Vec<[u8; FR_SIZE]> {
    inputs.iter().map(fr_to_bytes).collect()
}

/// Flattens [`public_inputs_to_bytes`] into one buffer.
pub fn public_inputs_flat(inputs: &[Fr]) -> Vec<u8> {
    inputs.iter().flat_map(fr_to_bytes).collect()
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        ark_bn254::{G1Projective, G2Projective},
        ark_ec::{CurveGroup, PrimeGroup},
        ark_ff::UniformRand,
        ark_std::test_rng,
    };

    #[test]
    fn identity_is_all_zero_and_round_trips() {
        assert_eq!(g1_to_bytes(&G1Affine::identity()), [0u8; G1_SIZE]);
        assert_eq!(g2_to_bytes(&G2Affine::identity()), [0u8; G2_SIZE]);
        assert_eq!(
            g1_from_bytes(&[0u8; G1_SIZE]).unwrap(),
            G1Affine::identity()
        );
        assert_eq!(
            g2_from_bytes(&[0u8; G2_SIZE]).unwrap(),
            G2Affine::identity()
        );
    }

    #[test]
    fn points_round_trip_and_off_curve_is_rejected() {
        let mut rng = test_rng();
        for _ in 0..8 {
            let p = G1Projective::rand(&mut rng).into_affine();
            let q = G2Projective::rand(&mut rng).into_affine();
            assert_eq!(g1_from_bytes(&g1_to_bytes(&p)).unwrap(), p);
            assert_eq!(g2_from_bytes(&g2_to_bytes(&q)).unwrap(), q);
        }
        let mut bad = g1_to_bytes(&G1Projective::generator().into_affine());
        bad[G1_SIZE - 1] ^= 1;
        assert_eq!(g1_from_bytes(&bad), Err(ConvertError::InvalidPoint));
    }

    #[test]
    fn g2_component_order_is_c1_then_c0() {
        let q = G2Projective::generator().into_affine();
        let bytes = g2_to_bytes(&q);
        let (x, _) = q.xy().unwrap();
        assert_eq!(&bytes[..FQ_SIZE], &fq_to_bytes(&x.c1));
        assert_eq!(&bytes[FQ_SIZE..2 * FQ_SIZE], &fq_to_bytes(&x.c0));
    }

    #[test]
    fn key_body_negates_g2_and_decodes_back() {
        let mut rng = test_rng();
        let alpha = G1Projective::rand(&mut rng).into_affine();
        let beta = G2Projective::rand(&mut rng).into_affine();
        let gamma = G2Projective::rand(&mut rng).into_affine();
        let delta = G2Projective::rand(&mut rng).into_affine();
        let ic: Vec<_> = (0..3)
            .map(|_| G1Projective::rand(&mut rng).into_affine())
            .collect();
        let key = OnChainKey::new(&alpha, &beta, &gamma, &delta, &ic).unwrap();
        assert_eq!(key.num_public_inputs(), 2);
        assert_eq!(key.body().len(), vk_body_len(2));

        let vk = solana_groth16_verify::VerifyingKey::from_body(key.body()).unwrap();
        assert_eq!(*vk.neg_beta(), g2_to_bytes(&-beta));

        let (a2, b2, g2, d2, ic2) = key.elements().unwrap();
        assert_eq!((a2, b2, g2, d2, ic2), (alpha, beta, gamma, delta, ic));
        assert_eq!(OnChainKey::from_body(key.body().to_vec()).unwrap(), key);
    }

    #[test]
    fn non_canonical_field_is_rejected() {
        let mut bytes = [0xffu8; FQ_SIZE];
        assert_eq!(fq_from_bytes(&bytes), Err(ConvertError::NonCanonicalField));
        bytes = fq_to_bytes(&Fq::from(7u64));
        assert_eq!(fq_from_bytes(&bytes).unwrap(), Fq::from(7u64));
        assert_eq!(
            fr_from_bytes(&solana_groth16_verify::constants::FR_MODULUS),
            Err(ConvertError::NonCanonicalField)
        );
    }

    #[test]
    fn publish_validation_matches_key_point_rules() {
        use solana_groth16_verify::Groth16Error;
        let g1 = G1Projective::generator().into_affine();
        let g2 = G2Projective::generator().into_affine();
        let key = OnChainKey::new(&g1, &g2, &g2, &g2, &[G1Affine::identity(), g1]).unwrap();
        key.validate_for_publish().unwrap();

        for (offset, size) in [
            (VK_ALPHA_OFFSET, G1_SIZE),
            (VK_NEG_BETA_OFFSET, G2_SIZE),
            (VK_NEG_GAMMA_OFFSET, G2_SIZE),
            (VK_NEG_DELTA_OFFSET, G2_SIZE),
        ] {
            let mut bad = key.clone();
            bad.body[offset..offset + size].fill(0);
            assert_eq!(
                bad.validate_for_publish(),
                Err(Groth16Error::IdentityKeyElement)
            );
        }
        // Both the pairing-validated IC₀ and addition-validated IC₁ must decode.
        for offset in [VK_IC_OFFSET, VK_IC_OFFSET + G1_SIZE] {
            let mut bad = key.clone();
            bad.body[offset..offset + G1_SIZE].fill(0xff);
            assert_eq!(bad.validate_for_publish(), Err(Groth16Error::InvalidPoint));
        }
        // A point on the twist outside G2's prime-order subgroup must fail too.
        let outside = (0u64..)
            .find_map(|i| {
                let point = G2Affine::get_point_from_x_unchecked(
                    Fq2::new(Fq::from(i), Fq::from(1u64)),
                    false,
                )?;
                (!point.is_in_correct_subgroup_assuming_on_curve()).then_some(point)
            })
            .unwrap();
        let bad = OnChainKey::new(&g1, &outside, &g2, &g2, &[g1]).unwrap();
        assert_eq!(bad.validate_for_publish(), Err(Groth16Error::InvalidPoint));
    }

    #[test]
    fn scalar_encoding_is_big_endian() {
        let s = Fr::from(0x0102u64);
        let bytes = fr_to_bytes(&s);
        assert_eq!(&bytes[FR_SIZE - 2..], &[0x01, 0x02]);
        assert!(bytes[..FR_SIZE - 2].iter().all(|&b| b == 0));
    }
}

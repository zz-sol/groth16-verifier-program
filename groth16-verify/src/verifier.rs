//! The verification itself, split into the stages the benchmark measures:
//! public-input preparation (the MSM), pairing-input assembly, and the pairing
//! check. [`verify`] runs all three.
//!
//! The equation checked is
//!
//! ```text
//! e(A, B) · e(α, −β) · e(L, −γ) · e(C, −δ) = 1,    L = IC₀ + Σᵢ aᵢ·ICᵢ
//! ```
//!
//! with the G2 negations pre-applied in the key, so this module performs no
//! field arithmetic of its own — only the syscalls and byte copies.

use crate::{
    constants::{
        FR_SIZE, G1_SIZE, PAIRING_INPUT_SIZE, PAIRING_SLOT_AB_OFFSET,
        PAIRING_SLOT_ALPHA_BETA_OFFSET, PAIRING_SLOT_C_OFFSET, PAIRING_SLOT_DELTA_OFFSET,
        PAIRING_SLOT_GAMMA_OFFSET, PAIRING_SLOT_L_OFFSET,
    },
    error::Groth16Error,
    proof::Proof,
    scalar,
    syscall::{g1_add, g1_mul, pairing_is_one},
    vk::VerifyingKey,
};

/// Verifies `proof` against `vk` for `public_inputs` (`n × 32` big-endian
/// canonical scalars, no leading constant-one term).
///
/// `Ok(())` means the proof verifies. See [`Groth16Error`] for the failure
/// modes; note that [`Groth16Error::InvalidPoint`] on this path means one of
/// `A`, `B`, `C` failed the syscall's curve or subgroup check.
#[inline]
pub fn verify(vk: &VerifyingKey, proof: &Proof, public_inputs: &[u8]) -> Result<(), Groth16Error> {
    let l = prepare_inputs(vk, public_inputs)?;
    let input = assemble_pairing_input(vk, proof, &l);
    check_pairing(&input)
}

/// Stage 1: `L = IC₀ + Σᵢ aᵢ·ICᵢ`.
///
/// Checks the input count and every scalar's canonicity before touching a
/// syscall. Inputs equal to `0` contribute nothing and are skipped entirely;
/// inputs equal to `1` skip the multiplication. Both are safe to special-case
/// because public inputs are public — the CU cost this makes data-dependent
/// leaks nothing.
pub fn prepare_inputs(
    vk: &VerifyingKey,
    public_inputs: &[u8],
) -> Result<[u8; G1_SIZE], Groth16Error> {
    let n = vk.num_public_inputs();
    if public_inputs.len() != n * FR_SIZE {
        return Err(Groth16Error::PublicInputCountMismatch);
    }

    // Reject any bad scalar before spending compute on the ones before it.
    for chunk in public_inputs.chunks_exact(FR_SIZE) {
        let s: &[u8; FR_SIZE] = chunk.try_into().unwrap();
        if !scalar::is_canonical(s) {
            return Err(Groth16Error::NonCanonicalScalar);
        }
    }

    let mut acc = *vk.ic(0);
    for (i, chunk) in public_inputs.chunks_exact(FR_SIZE).enumerate() {
        let s: &[u8; FR_SIZE] = chunk.try_into().unwrap();
        if scalar::is_zero(s) {
            continue;
        }
        let ic = vk.ic(i + 1);
        if scalar::is_one(s) {
            acc = g1_add(&acc, ic)?;
        } else {
            let term = g1_mul(ic, s)?;
            acc = g1_add(&acc, &term)?;
        }
    }
    Ok(acc)
}

/// Stage 2: lay out the four pairs. Pure copying; cannot fail.
#[inline]
pub fn assemble_pairing_input(
    vk: &VerifyingKey,
    proof: &Proof,
    l: &[u8; G1_SIZE],
) -> [u8; PAIRING_INPUT_SIZE] {
    let mut input = [0u8; PAIRING_INPUT_SIZE];
    write_pairing_input(&mut input, vk, proof, l);
    input
}

/// [`assemble_pairing_input`] into a caller-provided buffer.
#[inline]
pub fn write_pairing_input(
    input: &mut [u8; PAIRING_INPUT_SIZE],
    vk: &VerifyingKey,
    proof: &Proof,
    l: &[u8; G1_SIZE],
) {
    let a_b = proof.a_b();
    let alpha_beta = vk.alpha_neg_beta();
    let neg_gamma = vk.neg_gamma();
    let c = proof.c();
    let neg_delta = vk.neg_delta();

    input[PAIRING_SLOT_AB_OFFSET..PAIRING_SLOT_AB_OFFSET + a_b.len()].copy_from_slice(a_b);
    input[PAIRING_SLOT_ALPHA_BETA_OFFSET..PAIRING_SLOT_ALPHA_BETA_OFFSET + alpha_beta.len()]
        .copy_from_slice(alpha_beta);
    input[PAIRING_SLOT_L_OFFSET..PAIRING_SLOT_L_OFFSET + G1_SIZE].copy_from_slice(l);
    input[PAIRING_SLOT_GAMMA_OFFSET..PAIRING_SLOT_GAMMA_OFFSET + neg_gamma.len()]
        .copy_from_slice(neg_gamma);
    input[PAIRING_SLOT_C_OFFSET..PAIRING_SLOT_C_OFFSET + G1_SIZE].copy_from_slice(c);
    input[PAIRING_SLOT_DELTA_OFFSET..PAIRING_SLOT_DELTA_OFFSET + neg_delta.len()]
        .copy_from_slice(neg_delta);
}

/// Stage 3: the 4-pair check.
#[inline]
pub fn check_pairing(input: &[u8; PAIRING_INPUT_SIZE]) -> Result<(), Groth16Error> {
    if pairing_is_one(input)? {
        Ok(())
    } else {
        Err(Groth16Error::ProofInvalid)
    }
}

/// The identity cases from `docs/design.md §10`, on the host path. The G1
/// syscalls encode the identity as all-zero bytes; each case below pins that
/// the MSM and the pairing handle it where it can arise.
#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::constants::G1_IDENTITY,
        ark_bn254::{Fr, G1Affine, G2Affine},
        ark_ec::{AffineRepr, CurveGroup},
        groth16_convert::{
            wire::{fr_to_bytes, g1_to_bytes},
            OnChainKey, OnChainProof,
        },
        std::vec::Vec,
    };

    fn g1(k: u64) -> G1Affine {
        G1Affine::generator().mul_bigint([k]).into_affine()
    }

    fn g2(k: u64) -> G2Affine {
        G2Affine::generator().mul_bigint([k]).into_affine()
    }

    /// A key with fixed non-identity `α, β, γ, δ` and the given `IC` table.
    fn make_key(ic: &[G1Affine]) -> OnChainKey {
        OnChainKey::new(&g1(3), &g2(5), &g2(7), &g2(11), ic).unwrap()
    }

    fn inputs(scalars: &[u64]) -> Vec<u8> {
        scalars
            .iter()
            .flat_map(|&s| fr_to_bytes(&Fr::from(s)))
            .collect()
    }

    fn l(key: &OnChainKey, scalars: &[u64]) -> [u8; G1_SIZE] {
        let vk = VerifyingKey::from_body(key.body()).unwrap();
        prepare_inputs(&vk, &inputs(scalars)).unwrap()
    }

    #[test]
    fn final_l_is_identity_by_cancellation() {
        // IC₀ = P, IC₁ = Q, IC₂ = −(P+Q); inputs 1, 1 → L = O.
        let p = g1(2);
        let q = g1(9);
        let neg_sum = -(p + q).into_affine();
        let key = make_key(&[p, q, neg_sum]);
        assert_eq!(l(&key, &[1, 1]), G1_IDENTITY);
        // Same with a real multiplication in the way: IC₁ = Q with input 2,
        // IC₂ = −(P+2Q) with input 1.
        let key = make_key(&[p, q, -(p + q + q).into_affine()]);
        assert_eq!(l(&key, &[2, 1]), G1_IDENTITY);
    }

    #[test]
    fn final_l_is_identity_from_identity_ic0_and_zero_inputs() {
        let key = make_key(&[G1Affine::identity(), g1(4), g1(6)]);
        assert_eq!(l(&key, &[0, 0]), G1_IDENTITY);
        // And with IC₀ = O but nonzero inputs, L is the plain sum.
        assert_eq!(
            l(&key, &[1, 1]),
            g1_to_bytes(&(g1(4) + g1(6)).into_affine())
        );
    }

    #[test]
    fn intermediate_identity_with_nonzero_final_l() {
        // IC₀ = P, IC₁ = −P, IC₂ = Q; inputs 1, 1: the accumulator passes
        // through O after the first add and must come out as Q.
        let p = g1(13);
        let q = g1(17);
        let key = make_key(&[p, -p, q]);
        assert_eq!(l(&key, &[1, 1]), g1_to_bytes(&q));
    }

    #[test]
    fn identity_ic_terms_are_skipped_or_added_harmlessly() {
        // An identity ICᵢ contributes nothing whatever its input; the
        // multiplication syscall must accept the identity as a base point.
        let p = g1(21);
        let key = make_key(&[p, G1Affine::identity()]);
        assert_eq!(l(&key, &[1]), g1_to_bytes(&p));
        assert_eq!(l(&key, &[5]), g1_to_bytes(&p));
    }

    #[test]
    fn pairing_accepts_an_identity_l_and_rejects_the_proof() {
        // With L = O the equation cannot hold for a random proof, but the
        // failure must be ProofInvalid — the pairing decoded the identity in
        // slot 2 — not InvalidPoint.
        let key = make_key(&[G1Affine::identity(), g1(4)]);
        let vk = VerifyingKey::from_body(key.body()).unwrap();
        let proof_bytes = OnChainProof::new(&g1(23), &g2(29), &g1(31));
        let proof = Proof::from_bytes(&proof_bytes.0).unwrap();
        assert_eq!(
            verify(&vk, &proof, &inputs(&[0])),
            Err(Groth16Error::ProofInvalid)
        );
        // Sanity: the same proof with L ≠ O fails the same way, and an
        // off-curve A fails differently.
        assert_eq!(
            verify(&vk, &proof, &inputs(&[1])),
            Err(Groth16Error::ProofInvalid)
        );
        let mut bad = proof_bytes.0;
        bad[63] ^= 1;
        assert_eq!(
            verify(&vk, &Proof::from_bytes(&bad).unwrap(), &inputs(&[0])),
            Err(Groth16Error::InvalidPoint)
        );
    }
}

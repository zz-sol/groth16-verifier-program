//! Explicit key validation, shared by registration and host clients.

use crate::{
    constants::{G1_SIZE, PAIRING_ELEMENT_SIZE},
    scalar::is_zero,
    syscall::{g1_add, pairing_validate_points},
    Groth16Error, VerifyingKey,
};

/// Validates every key point through a syscall that performs the full check.
///
/// One 3-pair pairing call covers `α`, `IC₀` and the three G2 points —
/// pairing is the only `alt_bn128` opcode whose G2 deserialization includes
/// the subgroup check. `IC₁..ICₙ` go through `G1_ADD`, which deserializes with
/// full validation and is the cheapest G1 opcode; BN254's G1 has cofactor 1,
/// so on-curve is in-subgroup. The pairing *result* is ignored: these pairs
/// have no reason to multiply to one.
///
/// `α`, `−β`, `−γ`, `−δ` must not be the identity — the equation degenerates —
/// while any `ICᵢ` may be.
pub fn validate_for_publish(vk: &VerifyingKey) -> Result<(), Groth16Error> {
    let alpha = vk.alpha();
    let ic0 = vk.ic(0);
    if is_zero(alpha)
        || is_zero(vk.neg_beta())
        || is_zero(vk.neg_gamma())
        || is_zero(vk.neg_delta())
    {
        return Err(Groth16Error::IdentityKeyElement);
    }

    let mut input = [0u8; 3 * PAIRING_ELEMENT_SIZE];
    input[..PAIRING_ELEMENT_SIZE].copy_from_slice(vk.alpha_neg_beta());
    input[PAIRING_ELEMENT_SIZE..PAIRING_ELEMENT_SIZE + G1_SIZE].copy_from_slice(ic0);
    input[PAIRING_ELEMENT_SIZE + G1_SIZE..2 * PAIRING_ELEMENT_SIZE].copy_from_slice(vk.neg_gamma());
    input[2 * PAIRING_ELEMENT_SIZE..2 * PAIRING_ELEMENT_SIZE + G1_SIZE].copy_from_slice(ic0);
    input[2 * PAIRING_ELEMENT_SIZE + G1_SIZE..].copy_from_slice(vk.neg_delta());
    pairing_validate_points(&input)?;

    for i in 1..=vk.num_public_inputs() {
        let ic = vk.ic(i);
        g1_add(ic, ic)?;
    }
    Ok(())
}

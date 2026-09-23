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
/// the subgroup check. `IC₁..ICₙ` go through `G1_ADD`, which deserializes
/// *both* operands with full validation and is the cheapest G1 opcode; BN254's
/// G1 has cofactor 1, so on-curve is in-subgroup. Adjacent points are added in
/// pairs, so `n` points take `⌈n/2⌉` calls; an odd final point is added to
/// itself. Every result is ignored: the pairs have no reason to multiply to
/// one, and the sums mean nothing.
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

    let n = vk.num_public_inputs();
    for i in (1..=n).step_by(2) {
        let a = vk.ic(i);
        let b = if i < n { vk.ic(i + 1) } else { a };
        g1_add(a, b)?;
    }
    Ok(())
}

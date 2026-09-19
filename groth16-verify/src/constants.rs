//! Sizes, offsets and syscall opcodes shared by the verifier, the program and
//! the client-side builders. Everything here is in the on-chain wire format:
//! uncompressed, big-endian, exactly as `sol_alt_bn128_group_op` consumes it.

/// Size of a base-field element `Fq`.
pub const FQ_SIZE: usize = 32;
/// Size of a scalar-field element `Fr`.
pub const FR_SIZE: usize = 32;
/// Size of an uncompressed G1 point, `x ‖ y`.
pub const G1_SIZE: usize = 2 * FQ_SIZE;
/// Size of an uncompressed G2 point, `x ‖ y` with each `Fq2` as `c1 ‖ c0`.
pub const G2_SIZE: usize = 4 * FQ_SIZE;

/// The BN254 scalar-field modulus `r`, big-endian. Public inputs must be `< r`.
pub const FR_MODULUS: [u8; FR_SIZE] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// PDA seed prefix for canonical key accounts: `[b"vk", sha256(body)]`.
/// Lives here rather than in `state` so the `instruction` feature can be
/// used without `verify`.
pub const VK_SEED_PREFIX: &[u8] = b"vk";

/// The system program, spelled out so that neither the program nor the
/// instruction builders need a dependency for one all-zero constant.
pub const SYSTEM_PROGRAM_ID: pinocchio::Address = pinocchio::Address::new_from_array([0u8; 32]);

/// The syscall encoding of the G1 identity: all zeros.
pub const G1_IDENTITY: [u8; G1_SIZE] = [0u8; G1_SIZE];

// --- Proof: `A ‖ B ‖ C` -------------------------------------------------------

pub const PROOF_A_OFFSET: usize = 0;
pub const PROOF_B_OFFSET: usize = PROOF_A_OFFSET + G1_SIZE;
pub const PROOF_C_OFFSET: usize = PROOF_B_OFFSET + G2_SIZE;
/// Total proof size, 256 bytes.
pub const PROOF_SIZE: usize = PROOF_C_OFFSET + G1_SIZE;

// --- Verifying-key body: `α ‖ −β ‖ −γ ‖ −δ ‖ IC₀..ICₙ` ------------------------

pub const VK_ALPHA_OFFSET: usize = 0;
pub const VK_NEG_BETA_OFFSET: usize = VK_ALPHA_OFFSET + G1_SIZE;
pub const VK_NEG_GAMMA_OFFSET: usize = VK_NEG_BETA_OFFSET + G2_SIZE;
pub const VK_NEG_DELTA_OFFSET: usize = VK_NEG_GAMMA_OFFSET + G2_SIZE;
pub const VK_IC_OFFSET: usize = VK_NEG_DELTA_OFFSET + G2_SIZE;
/// Body size before the `IC` table: 448 bytes.
pub const VK_FIXED_SIZE: usize = VK_IC_OFFSET;

/// Largest `n` for which the canonical key account can be created in a single
/// CPI: `456 + 64·(n+1) ≤ MAX_PERMITTED_DATA_INCREASE (10,240)`.
pub const MAX_PUBLIC_INPUTS: usize = 151;

/// Length of a verifying-key body with `n` public inputs (`n + 1` IC points).
pub const fn vk_body_len(num_public_inputs: usize) -> usize {
    VK_FIXED_SIZE + G1_SIZE * (num_public_inputs + 1)
}

// --- Account sizes ------------------------------------------------------------
//
// Kept here rather than in `state` so that an instruction-only client (the
// `instruction` feature without `verify`) can size the staging account it has
// to create. `state` re-exports them.

/// Header of a canonical key account: discriminator, bump, `n`, reserved.
pub const KEY_HEADER_LEN: usize = 8;
/// Header of a staging account: discriminator, reserved, `n`, reserved,
/// 32-byte authority.
pub const STAGING_HEADER_LEN: usize = 40;

/// Total length of a canonical key account for `n` public inputs.
pub const fn key_account_len(num_public_inputs: usize) -> usize {
    KEY_HEADER_LEN + vk_body_len(num_public_inputs)
}

/// Total length of a staging account for `n` public inputs.
pub const fn staging_account_len(num_public_inputs: usize) -> usize {
    STAGING_HEADER_LEN + vk_body_len(num_public_inputs)
}

// --- Pairing input ------------------------------------------------------------

/// One `(G1, G2)` pair as the pairing syscall consumes it.
pub const PAIRING_ELEMENT_SIZE: usize = G1_SIZE + G2_SIZE;
/// Groth16 is a 4-pair check.
pub const PAIRING_NUM_PAIRS: usize = 4;
/// 768 bytes.
pub const PAIRING_INPUT_SIZE: usize = PAIRING_ELEMENT_SIZE * PAIRING_NUM_PAIRS;
/// The pairing syscall writes a 32-byte big-endian `0` or `1`.
pub const PAIRING_OUTPUT_SIZE: usize = 32;

/// Slot layout inside the pairing input. Slots 0 and 1 are single copies from
/// the proof and the key respectively; see `docs/design.md §5`.
pub const PAIRING_SLOT_AB_OFFSET: usize = 0;
pub const PAIRING_SLOT_ALPHA_BETA_OFFSET: usize = PAIRING_ELEMENT_SIZE;
pub const PAIRING_SLOT_L_OFFSET: usize = 2 * PAIRING_ELEMENT_SIZE;
pub const PAIRING_SLOT_GAMMA_OFFSET: usize = PAIRING_SLOT_L_OFFSET + G1_SIZE;
pub const PAIRING_SLOT_C_OFFSET: usize = 3 * PAIRING_ELEMENT_SIZE;
pub const PAIRING_SLOT_DELTA_OFFSET: usize = PAIRING_SLOT_C_OFFSET + G1_SIZE;

// --- `sol_alt_bn128_group_op` opcodes (big-endian variants) -------------------

pub const ALT_BN128_G1_ADD_BE: u64 = 0;
pub const ALT_BN128_G1_MUL_BE: u64 = 2;
pub const ALT_BN128_PAIRING_BE: u64 = 3;

/// `G1 ‖ G1`.
pub const G1_ADD_INPUT_SIZE: usize = 2 * G1_SIZE;
/// `G1 ‖ Fr`.
pub const G1_MUL_INPUT_SIZE: usize = G1_SIZE + FR_SIZE;

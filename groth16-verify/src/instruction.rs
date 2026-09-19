//! Client-side instruction builders and the program's canonical address.
//!
//! Instruction data is `tag ‖ payload`. Account orders match the README's
//! instruction table exactly.

extern crate alloc;

use {
    crate::constants::{staging_account_len, FR_SIZE, PROOF_SIZE, VK_SEED_PREFIX},
    alloc::{vec, vec::Vec},
    sha2::{Digest, Sha256},
    solana_address::{declare_id, Address},
    solana_instruction::{AccountMeta, Instruction},
};

declare_id!("GrPeAM83MtRfR8NvbW3tMMSBzQ9BsmQrgLjLCQNwZW4P");

pub use crate::{constants::SYSTEM_PROGRAM_ID, tag::Tag};

/// `sha256(body)`, the second PDA seed of a canonical key account.
pub fn vk_hash(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

/// Derives the canonical key account for a key body, with the canonical bump.
/// Matches what `Publish` computes on-chain with `find_program_address`.
pub fn find_key_address(program_id: &Address, vk_hash: &[u8; 32]) -> (Address, u8) {
    Address::find_program_address(&[VK_SEED_PREFIX, vk_hash], program_id)
}

/// Data `[0, n as u16 LE]`. Accounts: authority (s), staging (w).
///
/// Must be placed in the same transaction as the system-program
/// `create_account` that allocates `staging`; see the README's registration
/// section for why.
pub fn initialize_staging(
    program_id: &Address,
    authority: &Address,
    staging: &Address,
    num_public_inputs: u16,
) -> Instruction {
    let mut data = Vec::with_capacity(3);
    data.push(Tag::InitializeStaging as u8);
    data.extend_from_slice(&num_public_inputs.to_le_bytes());
    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*staging, false),
        ],
    )
}

/// System-program `CreateAccount` for a staging account sized for `n` public
/// inputs, followed by the `InitializeStaging` that claims it for `authority`.
///
/// **Submit both in one transaction**, in this order. `InitializeStaging`
/// cannot tell who paid for the account, so a staging account created in one
/// transaction and initialized in the next can be claimed by anyone in
/// between, who then owns its rent through `CloseStaging`. Returning the pair
/// as a unit is what makes the rule hard to break by accident.
///
/// `lamports` is the rent-exempt minimum for `staging_account_len(n)` bytes,
/// read from the cluster's `Rent`. `payer` and `staging` both sign
/// `CreateAccount`; `authority` signs `InitializeStaging`.
pub fn create_staging(
    program_id: &Address,
    payer: &Address,
    authority: &Address,
    staging: &Address,
    num_public_inputs: u16,
    lamports: u64,
) -> [Instruction; 2] {
    let space = staging_account_len(num_public_inputs as usize);
    // SystemInstruction::CreateAccount { lamports, space, owner }, bincode.
    let mut data = Vec::with_capacity(4 + 8 + 8 + 32);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&(space as u64).to_le_bytes());
    data.extend_from_slice(program_id.as_array());
    let create = Instruction::new_with_bytes(
        SYSTEM_PROGRAM_ID,
        &data,
        vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*staging, true),
        ],
    );
    [
        create,
        initialize_staging(program_id, authority, staging, num_public_inputs),
    ]
}

/// The `Write`s that upload a whole key body into a staging account, in
/// `chunk`-byte pieces at ascending offsets. Each fits in its own transaction
/// or several may share one, in any order; a transaction holds about 1,100
/// bytes of instruction data after the accounts and signature, so a `chunk`
/// between 800 and 900 is a practical default.
pub fn write_body(
    program_id: &Address,
    authority: &Address,
    staging: &Address,
    body: &[u8],
    chunk: usize,
) -> Vec<Instruction> {
    assert!(chunk > 0, "chunk must be nonzero");
    body.chunks(chunk)
        .enumerate()
        .map(|(i, piece)| write(program_id, authority, staging, (i * chunk) as u32, piece))
        .collect()
}

/// Data `[1, offset as u32 LE, bytes...]`, `offset` relative to the body.
/// Accounts: authority (s), staging (w).
pub fn write(
    program_id: &Address,
    authority: &Address,
    staging: &Address,
    offset: u32,
    bytes: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(5 + bytes.len());
    data.push(Tag::Write as u8);
    data.extend_from_slice(&offset.to_le_bytes());
    data.extend_from_slice(bytes);
    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*staging, false),
        ],
    )
}

/// Data `[2]`. Accounts: authority (s,w), payer (s,w), staging (w),
/// key PDA (w), system program.
///
/// `key` must be `find_key_address(program_id, &vk_hash(body)).0`; the program
/// recomputes it and rejects anything else.
pub fn publish(
    program_id: &Address,
    authority: &Address,
    payer: &Address,
    staging: &Address,
    key: &Address,
) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[Tag::Publish as u8],
        vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(*payer, true),
            AccountMeta::new(*staging, false),
            AccountMeta::new(*key, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
        ],
    )
}

/// Data `[3, proof (256), public_inputs (32·n)]`. Accounts: key PDA (r).
pub fn verify(
    program_id: &Address,
    key: &Address,
    proof: &[u8; PROOF_SIZE],
    public_inputs: &[[u8; FR_SIZE]],
) -> Instruction {
    let mut data = Vec::with_capacity(1 + PROOF_SIZE + FR_SIZE * public_inputs.len());
    data.push(Tag::Verify as u8);
    data.extend_from_slice(proof);
    for input in public_inputs {
        data.extend_from_slice(input);
    }
    Instruction::new_with_bytes(
        *program_id,
        &data,
        vec![AccountMeta::new_readonly(*key, false)],
    )
}

/// Data `[4]`. Accounts: authority (s,w), staging (w).
pub fn close_staging(program_id: &Address, authority: &Address, staging: &Address) -> Instruction {
    Instruction::new_with_bytes(
        *program_id,
        &[Tag::CloseStaging as u8],
        vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(*staging, false),
        ],
    )
}

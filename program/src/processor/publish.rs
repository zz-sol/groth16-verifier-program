//! `Publish`: turns a fully written staging account into the canonical,
//! immutable key account — in one instruction, so the canonical address never
//! exists in a partial state.
//!
//! Accounts: `[authority (s,w), payer (s,w), staging (w), key (w), system]`.
//! No data.
//!
//! Steps, in order (see the README's registration section):
//! 1. staging is ours, initialized, and signed for by its authority;
//! 2. `find_program_address([b"vk", sha256(body)])` equals `key`, and `key`
//!    is not already ours;
//! 3. every point in the body validates — G2 via a pairing call (the only
//!    opcode that subgroup-checks G2), G1 via addition;
//! 4. bring `key` into existence at exactly its final size (tolerating a
//!    pre-funded address), copy the body, write the header, close staging.
//!
//! The address checks come before point validation because they are cheap
//! (one hash, one derivation, one owner compare) and validation is not
//! (`61,299 + 334·⌈n/2⌉` CU). A republish or a wrong target fails before paying
//! for the pairing.

use {
    crate::{
        error::{map_groth16, Groth16ProgramError},
        processor,
    },
    pinocchio::{
        cpi::{Seed, Signer},
        error::ProgramError,
        sysvars::{rent::Rent, Sysvar},
        AccountView, Address, ProgramResult,
    },
    pinocchio_system::instructions::{Allocate, Assign, Transfer},
    solana_groth16_verify::{
        constants::SYSTEM_PROGRAM_ID,
        state::{key_account_len, write_key_header, KeyHeader, KEY_HEADER_LEN, VK_SEED_PREFIX},
        VerifyingKey,
    },
};

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    if !payload.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let [authority, payer, staging, key, system] = accounts else {
        return Err(ProgramError::InvalidArgument);
    };
    processor::expect_signer(authority)?;
    processor::expect_writable(authority)?;
    processor::expect_signer(payer)?;
    processor::expect_writable(payer)?;
    processor::expect_writable(staging)?;
    processor::expect_writable(key)?;
    processor::expect_owned_by(staging, program_id)?;
    processor::expect_distinct(authority, staging)?;
    // The CPIs below name the system program by id, so a wrong account here
    // would only fail later and less clearly.
    if system.address() != &SYSTEM_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    // --- 1. staging header ------------------------------------------------------
    // This borrow is held across the CPIs in step 4. That is fine: staging is
    // not among the accounts passed to them, so the runtime never touches it,
    // and the body is still needed afterwards for the copy into `key`.
    let staging_data = staging.try_borrow()?;
    let (header, body) = processor::authorized_staging(&staging_data, authority)?;
    let n = header.num_public_inputs;
    let vk = VerifyingKey::from_body_with_len(body, n).map_err(map_groth16)?;

    // --- 2. address -------------------------------------------------------------
    let hash = sha256(body);
    let (expected, bump) = Address::find_program_address(&[VK_SEED_PREFIX, &hash], program_id);
    if *key.address() != expected {
        return Err(Groth16ProgramError::KeyAddressMismatch.into());
    }
    if key.owned_by(program_id) {
        return Err(Groth16ProgramError::KeyAlreadyPublished.into());
    }
    // A PDA can only be allocated by this program, so anything other than a
    // blank system-owned account here is impossible; reject it anyway.
    if !key.owned_by(&SYSTEM_PROGRAM_ID) || key.data_len() != 0 {
        return Err(ProgramError::InvalidAccountData);
    }

    // --- 3. validate every point ------------------------------------------------
    vk.validate_for_publish().map_err(map_groth16)?;

    // --- 4. create, fill, close -------------------------------------------------
    let space = key_account_len(n);
    create_key_account(payer, key, program_id, &hash, bump, space)?;

    {
        let mut key_data = key.try_borrow_mut()?;
        write_key_header(
            &mut key_data,
            KeyHeader {
                bump,
                num_public_inputs: n,
            },
        );
        key_data[KEY_HEADER_LEN..].copy_from_slice(body);
    }
    drop(staging_data);

    processor::drain_and_close(staging, authority)
}

/// Brings the PDA into existence at `space` bytes, owned by this program.
///
/// Not `create_account`: that fails on a target with a nonzero balance, and
/// anyone can transfer lamports to any address. Top up to rent-exemption if
/// needed, then `allocate` and `assign`, each signed with the PDA seeds.
fn create_key_account(
    payer: &AccountView,
    key: &AccountView,
    program_id: &Address,
    hash: &[u8; 32],
    bump: u8,
    space: usize,
) -> ProgramResult {
    let required = Rent::get()?.try_minimum_balance(space)?;
    let shortfall = required.saturating_sub(key.lamports());
    if shortfall > 0 {
        Transfer {
            from: payer,
            to: key,
            lamports: shortfall,
        }
        .invoke()?;
    }

    let bump_seed = [bump];
    let seeds = [
        Seed::from(VK_SEED_PREFIX),
        Seed::from(hash),
        Seed::from(&bump_seed),
    ];
    let signer = Signer::from(&seeds[..]);

    let signers = core::slice::from_ref(&signer);

    Allocate {
        account: key,
        space: space as u64,
    }
    .invoke_signed(signers)?;
    Assign {
        account: key,
        owner: program_id,
    }
    .invoke_signed(signers)
}

#[inline(always)]
fn sha256(data: &[u8]) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[data]).to_bytes()
}

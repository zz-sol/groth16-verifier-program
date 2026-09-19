//! `Write`.
//!
//! Accounts: `[authority (s), staging (w)]`. Data: `offset: u32 LE ‖ bytes`.
//!
//! `offset` is relative to the staging *body*. The header is unreachable: the
//! write is bounds-checked against the body slice, with checked arithmetic on
//! `offset + len`.

use {
    crate::{error::Groth16ProgramError, processor},
    pinocchio::{error::ProgramError, AccountView, Address, ProgramResult},
    solana_groth16_verify::state::STAGING_HEADER_LEN,
};

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let (authority, staging) = processor::staging_pair(accounts, program_id)?;

    let (offset, bytes) = payload
        .split_at_checked(4)
        .ok_or(ProgramError::InvalidInstructionData)?;
    let offset = u32::from_le_bytes(offset.try_into().unwrap()) as usize;

    let mut data = staging.try_borrow_mut()?;
    processor::authorized_staging(&data, authority)?;
    let body = &mut data[STAGING_HEADER_LEN..];
    let end = offset
        .checked_add(bytes.len())
        .filter(|&end| end <= body.len())
        .ok_or(Groth16ProgramError::WriteOutOfBounds)?;
    body[offset..end].copy_from_slice(bytes);
    Ok(())
}

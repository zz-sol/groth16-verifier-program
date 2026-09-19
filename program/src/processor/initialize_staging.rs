//! `InitializeStaging`.
//!
//! Accounts: `[authority (s), staging (w)]`. Data: `n: u16 LE`.
//!
//! The staging account is created by the client through the system program
//! with this program as owner — in the *same transaction* as this instruction,
//! because nothing here can tell who paid for a blank account. This
//! instruction requires it to be blank and sized exactly for `n`, and records
//! the signer as its authority.

use {
    crate::{error::Groth16ProgramError, processor},
    pinocchio::{error::ProgramError, AccountView, Address, ProgramResult},
    solana_groth16_verify::{
        constants::MAX_PUBLIC_INPUTS,
        state::{
            staging_account_len, write_staging_header, StagingHeader, DISCRIMINATOR_OFFSET,
            DISCRIMINATOR_UNINITIALIZED,
        },
    },
};

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let (authority, staging) = processor::staging_pair(accounts, program_id)?;

    let n: &[u8; 2] = payload
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let n = u16::from_le_bytes(*n) as usize;
    if n > MAX_PUBLIC_INPUTS {
        return Err(Groth16ProgramError::TooManyPublicInputs.into());
    }
    if staging.data_len() != staging_account_len(n) {
        return Err(Groth16ProgramError::StagingSizeMismatch.into());
    }

    let mut data = staging.try_borrow_mut()?;
    if data[DISCRIMINATOR_OFFSET] != DISCRIMINATOR_UNINITIALIZED {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    write_staging_header(
        &mut data,
        StagingHeader {
            num_public_inputs: n,
            authority: *authority.address().as_array(),
        },
    );
    Ok(())
}

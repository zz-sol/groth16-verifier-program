//! `CloseStaging`.
//!
//! Accounts: `[authority (s,w), staging (w)]`. No data.
//!
//! Refunds the staging account's lamports to its recorded authority. Canonical
//! key accounts have no close path at all.

use {
    crate::processor,
    pinocchio::{error::ProgramError, AccountView, Address, ProgramResult},
};

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    if !payload.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (authority, staging) = processor::staging_pair(accounts, program_id)?;
    processor::expect_writable(authority)?;

    {
        let data = staging.try_borrow()?;
        processor::authorized_staging(&data, authority)?;
    }

    processor::drain_and_close(staging, authority)
}

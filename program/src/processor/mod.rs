//! One module per instruction, plus the account checks they share.
//!
//! Each processor destructures its account slice with an exact-length
//! pattern. Missing accounts are always rejected. Surplus accounts are rejected
//! only up to [`crate::MAX_ACCOUNTS`]: the eager entrypoint deserializes at
//! most that many and silently skips the rest, so an instruction that takes
//! fewer than `MAX_ACCOUNTS` sees, and rejects, extra accounts, while
//! `Publish` — which takes exactly `MAX_ACCOUNTS` — never sees a sixth. Extra
//! accounts carry no semantics for any instruction here, so neither behavior
//! affects correctness; the patterns exist to reject *too few*.

use {
    pinocchio::{error::ProgramError, AccountView, Address, ProgramResult},
    solana_groth16_verify::Tag,
};

pub mod close_staging;
pub mod initialize_staging;
pub mod publish;
pub mod verify;
pub mod write;

/// The entrypoint: splits `tag ‖ payload` and dispatches on the tag.
pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (&tag, payload) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match Tag::from_u8(tag).ok_or(ProgramError::InvalidInstructionData)? {
        Tag::Verify => verify::process(program_id, accounts, payload),
        Tag::InitializeStaging => initialize_staging::process(program_id, accounts, payload),
        Tag::Write => write::process(program_id, accounts, payload),
        Tag::Publish => publish::process(program_id, accounts, payload),
        Tag::CloseStaging => close_staging::process(program_id, accounts, payload),
    }
}

#[inline(always)]
pub(crate) fn expect_signer(account: &AccountView) -> Result<(), ProgramError> {
    if !account.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}

#[inline(always)]
pub(crate) fn expect_writable(account: &AccountView) -> Result<(), ProgramError> {
    if !account.is_writable() {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

/// Owner check by 32-byte value.
#[inline(always)]
pub(crate) fn expect_owned_by(account: &AccountView, owner: &Address) -> Result<(), ProgramError> {
    if !account.owned_by(owner) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    Ok(())
}

/// Rejects one account passed in two roles.
///
/// The staging account's key pair can sign for itself, so nothing else stops
/// a client from naming the staging account as its own authority. [`drain_and_close`]
/// on such a pair would credit and then zero the same balance, the runtime
/// would reject the unbalanced instruction, and — since only `CloseStaging`
/// and `Publish` can move lamports out of a staging account — its rent would
/// be stuck forever. Refusing at `InitializeStaging` prevents the account from
/// ever existing in that state; the other processors check too, cheaply.
#[inline(always)]
pub(crate) fn expect_distinct(a: &AccountView, b: &AccountView) -> Result<(), ProgramError> {
    if a.address() == b.address() {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

/// The `[authority (s), staging (w)]` pair that `InitializeStaging`, `Write`
/// and `CloseStaging` take, with the checks all three make: authority signs,
/// staging is writable and ours, and they are not the same account.
#[inline(always)]
pub(crate) fn staging_pair<'a>(
    accounts: &'a mut [AccountView],
    program_id: &Address,
) -> Result<(&'a mut AccountView, &'a mut AccountView), ProgramError> {
    let [authority, staging] = accounts else {
        return Err(ProgramError::InvalidArgument);
    };
    expect_signer(authority)?;
    expect_writable(staging)?;
    expect_owned_by(staging, program_id)?;
    expect_distinct(authority, staging)?;
    Ok((authority, staging))
}

/// Moves every lamport out of `from` into `to` and closes `from`.
///
/// `from` and `to` must be distinct accounts (see [`expect_distinct`]).
/// `close` zeroes the owner, lamports and length; lamports are zeroed here
/// too so the balance transfer reads as a transfer, not an assumption about
/// `close`.
#[inline(always)]
pub(crate) fn drain_and_close(
    from: &mut AccountView,
    to: &mut AccountView,
) -> Result<(), ProgramError> {
    let lamports = from.lamports();
    to.set_lamports(
        to.lamports()
            .checked_add(lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?,
    );
    from.set_lamports(0);
    from.close()
}

/// Parses an initialized staging account and checks its recorded authority.
/// Processors check ownership before borrowing and retain control of the borrow.
pub(crate) fn authorized_staging<'a>(
    data: &'a [u8],
    authority: &AccountView,
) -> Result<(solana_groth16_verify::state::StagingHeader, &'a [u8]), ProgramError> {
    let (header, body) = solana_groth16_verify::state::read_staging_account(data)
        .map_err(crate::error::map_groth16)?;
    if header.authority != *authority.address().as_array() {
        return Err(ProgramError::IncorrectAuthority);
    }
    Ok((header, body))
}

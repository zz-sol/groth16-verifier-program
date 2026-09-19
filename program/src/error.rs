//! Error surface of the program. Three kinds of failure, told apart by how
//! they are reported:
//!
//! - **Verification and layout** (`Custom(0..=8)`): every [`Groth16Error`]
//!   from [`solana_groth16_verify`], mapped one-to-one by [`map_groth16`], so a
//!   CPI caller can tell "proof did not verify" (`6`) apart from "malformed
//!   input" (the rest).
//! - **Registry semantics** (`Custom(100..)`): conditions only this program's
//!   registration flow can detect — a key body that does not hash to the
//!   supplied address, a key already published, a staging account of the wrong
//!   size, a `Write` past the body, an identity element where a key element
//!   must not be one. These have no standard `ProgramError` equivalent, so they
//!   get codes of their own.
//! - **Account and signature checks**: the standard variants that describe
//!   them — `MissingRequiredSignature`, `InvalidAccountOwner`,
//!   `IncorrectAuthority` (wrong staging authority), `InvalidArgument` (wrong
//!   account count or a read-only account that must be writable),
//!   `InvalidInstructionData` (unknown tag, wrong payload length),
//!   `AccountAlreadyInitialized`, `InvalidAccountData`, `ArithmeticOverflow`.
//!   None of these carry information a caller needs beyond the variant.

use {pinocchio::error::ProgramError, solana_groth16_verify::Groth16Error};

/// Custom error codes. Stable; append only.
///
/// `0..=8` mirror [`Groth16Error`] variant for variant; `100..` are the
/// registry's own. The gap keeps the two ranges from ever colliding as either
/// grows.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Groth16ProgramError {
    // --- Verification and layout, from `solana_groth16_verify` ----------------
    InvalidProofLength = 0,
    InvalidKeyLength = 1,
    TooManyPublicInputs = 2,
    PublicInputCountMismatch = 3,
    NonCanonicalScalar = 4,
    InvalidPoint = 5,
    ProofInvalid = 6,
    InvalidAccountData = 7,
    WrongDiscriminator = 8,

    // --- Registry semantics, this program's own ---------------------------------
    /// The supplied key account is not the canonical address for the staged
    /// key body (`find_program_address([b"vk", sha256(body)])`).
    KeyAddressMismatch = 100,
    /// The canonical key account already exists (is owned by this program).
    KeyAlreadyPublished = 101,
    /// The staging account's length does not match `40 + 448 + 64·(n+1)`.
    StagingSizeMismatch = 102,
    /// A `Write` would extend past the end of the staging body.
    WriteOutOfBounds = 103,
    /// A verifying-key element that must not be the identity is the identity.
    IdentityKeyElement = 104,
}

impl From<Groth16ProgramError> for ProgramError {
    fn from(e: Groth16ProgramError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

/// Maps a verifier error onto its stable custom code.
pub fn map_groth16(e: Groth16Error) -> ProgramError {
    use Groth16ProgramError as P;
    let code = match e {
        Groth16Error::InvalidProofLength => P::InvalidProofLength,
        Groth16Error::InvalidKeyLength => P::InvalidKeyLength,
        Groth16Error::TooManyPublicInputs => P::TooManyPublicInputs,
        Groth16Error::PublicInputCountMismatch => P::PublicInputCountMismatch,
        Groth16Error::NonCanonicalScalar => P::NonCanonicalScalar,
        Groth16Error::InvalidPoint => P::InvalidPoint,
        Groth16Error::ProofInvalid => P::ProofInvalid,
        Groth16Error::InvalidAccountData => P::InvalidAccountData,
        Groth16Error::WrongDiscriminator => P::WrongDiscriminator,
        Groth16Error::IdentityKeyElement => P::IdentityKeyElement,
    };
    code.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins every verifier error to its code. The test harness mirrors these
    /// numbers in `program/tests/common`; this is the table they mirror.
    #[test]
    fn verifier_errors_map_to_their_stable_codes() {
        let table = [
            (Groth16Error::InvalidProofLength, 0),
            (Groth16Error::InvalidKeyLength, 1),
            (Groth16Error::TooManyPublicInputs, 2),
            (Groth16Error::PublicInputCountMismatch, 3),
            (Groth16Error::NonCanonicalScalar, 4),
            (Groth16Error::InvalidPoint, 5),
            (Groth16Error::ProofInvalid, 6),
            (Groth16Error::InvalidAccountData, 7),
            (Groth16Error::WrongDiscriminator, 8),
            (Groth16Error::IdentityKeyElement, 104),
        ];
        for (error, code) in table {
            assert_eq!(map_groth16(error), ProgramError::Custom(code), "{error:?}");
        }
    }
}

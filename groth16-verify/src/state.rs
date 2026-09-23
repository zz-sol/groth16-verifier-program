//! On-chain account layouts: the canonical key account and the staging
//! account. Both are `header ‖ body`, where the body is exactly a
//! [`VerifyingKey`] body and the header is what differs.
//!
//! ```text
//! key account      [0] disc=1  [1] bump  [2..4] n (u16 LE)  [4..8] reserved  [8..] body
//! staging account  [0] disc=2  [1] reserved  [2..4] n  [4..8] reserved  [8..40] authority  [40..] body
//! ```

use crate::{constants::MAX_PUBLIC_INPUTS, error::Groth16Error, verifying_key::VerifyingKey};

pub use crate::constants::{
    key_account_len, staging_account_len, KEY_HEADER_LEN, STAGING_HEADER_LEN, VK_SEED_PREFIX,
};

pub const DISCRIMINATOR_UNINITIALIZED: u8 = 0;
pub const DISCRIMINATOR_KEY: u8 = 1;
pub const DISCRIMINATOR_STAGING: u8 = 2;

pub const DISCRIMINATOR_OFFSET: usize = 0;
pub const NUM_PUBLIC_INPUTS_OFFSET: usize = 2;

pub const KEY_BUMP_OFFSET: usize = 1;

pub const STAGING_AUTHORITY_OFFSET: usize = 8;

#[inline]
fn read_n(data: &[u8]) -> usize {
    u16::from_le_bytes([
        data[NUM_PUBLIC_INPUTS_OFFSET],
        data[NUM_PUBLIC_INPUTS_OFFSET + 1],
    ]) as usize
}

#[inline]
fn write_n(data: &mut [u8], n: usize) {
    data[NUM_PUBLIC_INPUTS_OFFSET..NUM_PUBLIC_INPUTS_OFFSET + 2]
        .copy_from_slice(&(n as u16).to_le_bytes());
}

// --- Canonical key account ----------------------------------------------------

/// Parsed header of a canonical key account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyHeader {
    pub bump: u8,
    pub num_public_inputs: usize,
}

/// Parses a canonical key account: checks the discriminator and that the
/// declared `n` matches the data length exactly, then returns the header and
/// a key view over the body.
///
/// This is `Verify`'s entire account check beyond ownership — one byte compare
/// and one length compare. See `docs/design.md §2`.
#[inline]
pub fn read_key_account(data: &[u8]) -> Result<(KeyHeader, VerifyingKey<'_>), Groth16Error> {
    if data.len() < KEY_HEADER_LEN {
        return Err(Groth16Error::InvalidAccountData);
    }
    if data[DISCRIMINATOR_OFFSET] != DISCRIMINATOR_KEY {
        return Err(Groth16Error::WrongDiscriminator);
    }
    let n = read_n(data);
    let vk = VerifyingKey::from_body_with_len(&data[KEY_HEADER_LEN..], n)?;
    Ok((
        KeyHeader {
            bump: data[KEY_BUMP_OFFSET],
            num_public_inputs: n,
        },
        vk,
    ))
}

/// Writes a canonical key account header into a freshly allocated account.
/// The caller copies the body into `data[KEY_HEADER_LEN..]`.
#[inline]
pub fn write_key_header(data: &mut [u8], header: KeyHeader) {
    data[DISCRIMINATOR_OFFSET] = DISCRIMINATOR_KEY;
    data[KEY_BUMP_OFFSET] = header.bump;
    write_n(data, header.num_public_inputs);
    data[4..KEY_HEADER_LEN].fill(0);
}

// --- Staging account -----------------------------------------------------------

/// Parsed header of a staging account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StagingHeader {
    pub num_public_inputs: usize,
    pub authority: [u8; 32],
}

/// Parses a staging account header and returns it with the body slice.
/// Requires the discriminator and that `n` agrees with the account length.
#[inline]
pub fn read_staging_account(data: &[u8]) -> Result<(StagingHeader, &[u8]), Groth16Error> {
    if data.len() < STAGING_HEADER_LEN {
        return Err(Groth16Error::InvalidAccountData);
    }
    if data[DISCRIMINATOR_OFFSET] != DISCRIMINATOR_STAGING {
        return Err(Groth16Error::WrongDiscriminator);
    }
    let n = read_n(data);
    if n > MAX_PUBLIC_INPUTS || data.len() != staging_account_len(n) {
        return Err(Groth16Error::InvalidAccountData);
    }
    let authority = data[STAGING_AUTHORITY_OFFSET..STAGING_HEADER_LEN]
        .try_into()
        .unwrap();
    Ok((
        StagingHeader {
            num_public_inputs: n,
            authority,
        },
        &data[STAGING_HEADER_LEN..],
    ))
}

/// Initializes a staging header. The account must be blank (discriminator
/// zero) and sized exactly for `n`; the caller checks both.
#[inline]
pub fn write_staging_header(data: &mut [u8], header: StagingHeader) {
    data[DISCRIMINATOR_OFFSET] = DISCRIMINATOR_STAGING;
    data[1] = 0;
    write_n(data, header.num_public_inputs);
    data[4..STAGING_AUTHORITY_OFFSET].fill(0);
    data[STAGING_AUTHORITY_OFFSET..STAGING_HEADER_LEN].copy_from_slice(&header.authority);
}

/// Mutable view of a staging account's body, for `Write`. Checks the
/// discriminator; the `offset + len ≤ body_len` check belongs to the caller,
/// which has the write's parameters.
#[inline]
pub fn staging_body_mut(data: &mut [u8]) -> Result<&mut [u8], Groth16Error> {
    if data.len() < STAGING_HEADER_LEN {
        return Err(Groth16Error::InvalidAccountData);
    }
    if data[DISCRIMINATOR_OFFSET] != DISCRIMINATOR_STAGING {
        return Err(Groth16Error::WrongDiscriminator);
    }
    Ok(&mut data[STAGING_HEADER_LEN..])
}

#[cfg(test)]
mod tests {
    use {super::*, crate::constants::vk_body_len};

    #[test]
    fn key_header_round_trip() {
        let n = 3;
        let mut data = std::vec![0u8; key_account_len(n)];
        write_key_header(
            &mut data,
            KeyHeader {
                bump: 254,
                num_public_inputs: n,
            },
        );
        let (h, vk) = read_key_account(&data).unwrap();
        assert_eq!(h.bump, 254);
        assert_eq!(h.num_public_inputs, n);
        assert_eq!(vk.num_public_inputs(), n);

        // Declared n disagreeing with the length is rejected.
        write_n(&mut data, n + 1);
        assert_eq!(
            read_key_account(&data).err(),
            Some(Groth16Error::InvalidKeyLength)
        );

        // Wrong discriminator.
        write_n(&mut data, n);
        data[0] = DISCRIMINATOR_STAGING;
        assert_eq!(
            read_key_account(&data).err(),
            Some(Groth16Error::WrongDiscriminator)
        );
    }

    #[test]
    fn staging_header_round_trip() {
        let n = 5;
        let mut data = std::vec![0u8; staging_account_len(n)];
        let authority = [7u8; 32];
        write_staging_header(
            &mut data,
            StagingHeader {
                num_public_inputs: n,
                authority,
            },
        );
        let (h, body) = read_staging_account(&data).unwrap();
        assert_eq!(h.authority, authority);
        assert_eq!(h.num_public_inputs, n);
        assert_eq!(body.len(), vk_body_len(n));
        assert_eq!(staging_body_mut(&mut data).unwrap().len(), vk_body_len(n));

        let mut short = data.clone();
        short.pop();
        assert_eq!(
            read_staging_account(&short).err(),
            Some(Groth16Error::InvalidAccountData)
        );
    }
}

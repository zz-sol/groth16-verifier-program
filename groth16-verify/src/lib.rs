#![no_std]

//! Stateless, allocation-free Groth16 (BN254) verification for Solana programs.
//!
//! This crate is the verifier used by `solana-groth16-program`. A program that wants
//! to verify inline — without a CPI — depends on it directly:
//!
//! ```ignore
//! use solana_groth16_verify::{Proof, VerifyingKey, verify};
//!
//! // `key_body` is a well-formed key whose provenance the caller has
//! // already established; see below for what each of those means.
//! let vk = VerifyingKey::from_body(key_body)?;
//! let (proof, public_inputs) = Proof::split_from(instruction_data)?;
//! verify(&vk, &proof, public_inputs)?;
//! ```
//!
//! # What is, and is not, checked about the key
//!
//! Two different things can be meant by "checking the verifying key", and this
//! crate does only the first.
//!
//! **Well-formedness.** [`VerifyingKey::from_body`] checks only the layout:
//! that the length is `448 + 64·(n+1)` for some `n`. It does not check that the
//! points are on the curve, in the prime-order subgroup, or non-identity where
//! they must be, and neither does [`verify`] — the pairing syscall rejects
//! off-curve points as it deserializes them, but not an identity `α`, `−β`,
//! `−γ` or `−δ`, under which the verification equation degenerates (an identity
//! `−γ` makes one fixed proof verify for every public input). Those checks are
//! [`VerifyingKey::validate_for_publish`]. They cost about `61,000 + 167·n` CU
//! and are meant to run **once when the key is accepted**, not on every proof.
//! They establish that the bytes are a Groth16 key for which the verifier is
//! sound, and nothing more.
//!
//! **Provenance.** Whether the key is *the right key* — produced by the trusted
//! setup for the intended circuit, rather than for a circuit with no
//! constraints — is a property of the setup, not of the bytes, and no on-chain
//! check can establish it. A well-formed key for the wrong circuit passes
//! `validate_for_publish` and verifies proofs of nothing. Provenance is
//! established off-chain, against the setup ceremony's transcript when there
//! is one, or by trusting whoever ran the setup when there is not; the
//! content-addressed key account then commits to exactly the bytes that were
//! checked. That is the consumer's responsibility whenever it pins a key.
//!
//! In the usual deployment the key is already well-formed by the time it
//! reaches this crate: it was read from a key account of
//! `solana-groth16-program`, and the only instruction that creates one,
//! `Publish`, runs `validate_for_publish` on the body before writing it. A key
//! that came from anywhere else — instruction data, a program's own account, a
//! compile-time constant — should be put through it once by whoever stores it:
//!
//! ```ignore
//! let vk = VerifyingKey::from_body(body)?;
//! vk.validate_for_publish()?; // once, when the key is stored or pinned
//! ```
//!
//! All byte formats are the on-chain wire format — uncompressed, big-endian,
//! G2 negations pre-applied in the key — documented in the repository README.
//! Use `groth16-convert` to produce them from gnark or arkworks artifacts.
//!
//! # Features
//!
//! - `verify` (default): the verifier, [`Proof`], [`VerifyingKey`], and the
//!   account header parsers in `state`. On-chain it calls
//!   `sol_alt_bn128_group_op`; off-chain it runs the host implementation from
//!   `solana-bn254`.
//! - `instruction` (default): client-side instruction builders and the
//!   program's canonical address.
//!
//! `constants` — sizes, offsets, account lengths, the PDA seed and the system
//! program id — needs neither feature.

#[cfg(test)]
extern crate std;

pub mod constants;
mod error;
mod tag;

#[cfg(feature = "instruction")]
pub mod instruction;

pub use tag::Tag;

#[cfg(feature = "verify")]
mod proof;
#[cfg(feature = "verify")]
pub mod scalar;
#[cfg(feature = "verify")]
pub mod state;
#[cfg(feature = "verify")]
pub mod syscall;
#[cfg(feature = "verify")]
mod validation;
#[cfg(feature = "verify")]
pub mod verifier;
#[cfg(feature = "verify")]
mod vk;

pub use error::Groth16Error;
#[cfg(feature = "verify")]
pub use {proof::Proof, verifier::verify, vk::VerifyingKey};

#![no_std]

//! Stage-isolating benchmark program. See `docs/cu-budget.md § Benchmark
//! methodology` for the tags and the arithmetic done on the measurements.
//!
//! Instruction data (all inputs arrive at runtime — nothing is a compile-time
//! constant, so the compiler cannot fold any stage away):
//!
//! ```text
//! tag (1) ‖ n (u16 LE) ‖ vk_body (448 + 64·(n+1)) ‖ proof (256) ‖ public_inputs (32·n) ‖ L (64)
//! ```
//!
//! `L` is the MSM result, precomputed off-chain, so that the pairing stage can
//! run without the MSM stage. Every tag parses the input and constructs the
//! key and proof views; every tag except `NULL` then writes exactly 64 bytes
//! of return data through `black_box`. So the return-data cost is constant
//! across tags and cancels in every stage delta, and `NULL` — identical to
//! `BASELINE` up to the write — measures exactly that write and nothing else.

use {
    core::hint::black_box,
    pinocchio::{
        entrypoint::InstructionContext, error::ProgramError, lazy_program_entrypoint, ProgramResult,
    },
    solana_groth16_verify::{
        constants::{vk_body_len, FR_SIZE, G1_SIZE, PROOF_SIZE},
        verifier::{assemble_pairing_input, check_pairing, prepare_inputs},
        Proof, VerifyingKey,
    },
};

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pinocchio::no_allocator!();
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pinocchio::nostd_panic_handler!();

lazy_program_entrypoint!(process_instruction);

/// Dispatch and parse, no return data.
pub const TAG_NULL: u8 = 0xff;
/// Dispatch and parse, plus the return-data write.
pub const TAG_BASELINE: u8 = 0;
/// Parse everything and assemble the pairing input from the supplied `L`.
pub const TAG_ASSEMBLE: u8 = 1;
/// The MSM (`prepare_inputs`) only.
pub const TAG_MSM: u8 = 2;
/// Assemble from the supplied `L`, then the pairing check.
pub const TAG_PAIRING: u8 = 3;
/// Full core verification: MSM, assemble, pairing.
pub const TAG_VERIFY: u8 = 4;

pub const RETURN_DATA_LEN: usize = 64;

pub fn process_instruction(context: InstructionContext) -> ProgramResult {
    let data = context.instruction_data()?;
    let (&tag, rest) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    let input = Input::parse(rest)?;
    // The bench measures the verifier's stages, not key validation; the key
    // is whatever the harness supplied.
    let vk = VerifyingKey::from_body_with_len(input.vk_body, input.n)
        .map_err(|_| ProgramError::InvalidInstructionData)?
        .assume_validated();
    let proof = Proof::from_bytes(input.proof).map_err(|_| ProgramError::InvalidInstructionData)?;

    let mut out = [0u8; RETURN_DATA_LEN];
    match tag {
        TAG_NULL => {
            // Same work as BASELINE minus the return-data write. `black_box`
            // keeps the parse and the views from being optimized away.
            black_box((&vk, &proof, &input));
            return Ok(());
        }
        TAG_BASELINE => {
            out.copy_from_slice(&input.vk_body[..RETURN_DATA_LEN]);
        }
        TAG_ASSEMBLE => {
            let buf = assemble_pairing_input(&vk, &proof, input.l);
            out.copy_from_slice(&black_box(buf)[..RETURN_DATA_LEN]);
        }
        TAG_MSM => {
            let l = prepare_inputs(&vk, input.public_inputs)
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            out.copy_from_slice(&black_box(l));
        }
        TAG_PAIRING => {
            let buf = assemble_pairing_input(&vk, &proof, input.l);
            let ok = check_pairing(black_box(&buf)).is_ok();
            out[0] = black_box(ok) as u8;
        }
        TAG_VERIFY => {
            let l = prepare_inputs(&vk, input.public_inputs)
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            let buf = assemble_pairing_input(&vk, &proof, &l);
            let ok = check_pairing(black_box(&buf)).is_ok();
            out[0] = black_box(ok) as u8;
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    }
    set_return_data(&black_box(out));
    Ok(())
}

struct Input<'a> {
    n: usize,
    vk_body: &'a [u8],
    proof: &'a [u8],
    public_inputs: &'a [u8],
    l: &'a [u8; G1_SIZE],
}

impl<'a> Input<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, ProgramError> {
        let (n, rest) = data
            .split_at_checked(2)
            .ok_or(ProgramError::InvalidInstructionData)?;
        let n = u16::from_le_bytes([n[0], n[1]]) as usize;
        let (vk_body, rest) = rest
            .split_at_checked(vk_body_len(n))
            .ok_or(ProgramError::InvalidInstructionData)?;
        let (proof, rest) = rest
            .split_at_checked(PROOF_SIZE)
            .ok_or(ProgramError::InvalidInstructionData)?;
        let (public_inputs, rest) = rest
            .split_at_checked(n * FR_SIZE)
            .ok_or(ProgramError::InvalidInstructionData)?;
        let l: &[u8; G1_SIZE] = rest
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        Ok(Self {
            n,
            vk_body,
            proof,
            public_inputs,
            l,
        })
    }
}

#[cfg(target_os = "solana")]
#[inline(always)]
fn set_return_data(data: &[u8]) {
    // SAFETY: `data` is valid for `data.len()` bytes for the duration of the call.
    unsafe { pinocchio::syscalls::sol_set_return_data(data.as_ptr(), data.len() as u64) };
}

#[cfg(not(target_os = "solana"))]
fn set_return_data(_data: &[u8]) {}

/// Builds the instruction data for a tag. Host-side helper for the CU test.
#[cfg(not(target_os = "solana"))]
pub fn instruction_data(
    tag: u8,
    vk_body: &[u8],
    proof: &[u8; PROOF_SIZE],
    public_inputs: &[u8],
    l: &[u8; G1_SIZE],
) -> alloc::vec::Vec<u8> {
    let n = (vk_body.len() - solana_groth16_verify::constants::VK_FIXED_SIZE) / G1_SIZE - 1;
    let mut data = alloc::vec::Vec::with_capacity(
        3 + vk_body.len() + PROOF_SIZE + public_inputs.len() + G1_SIZE,
    );
    data.push(tag);
    data.extend_from_slice(&(n as u16).to_le_bytes());
    data.extend_from_slice(vk_body);
    data.extend_from_slice(proof);
    data.extend_from_slice(public_inputs);
    data.extend_from_slice(l);
    data
}

#[cfg(not(target_os = "solana"))]
extern crate alloc;

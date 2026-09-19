//! Shared Mollusk harness for the SBF integration tests.
//!
//! Tests skip (return early) unless `SBF_OUT_DIR` points at a directory holding
//! `solana_groth16_program.so` (and `groth16_bench.so` for the CU test). `make
//! test-program` sets it.

#![allow(dead_code)]

pub mod circuit;

use {
    groth16_convert::OnChainKey,
    mollusk_svm::{
        program::keyed_account_for_system_program,
        result::{
            types::{TransactionProgramResult, TransactionResult},
            InstructionResult,
        },
        Mollusk,
    },
    solana_account::Account,
    solana_address::Address,
    solana_groth16_verify::{
        constants::PROOF_SIZE,
        instruction::{self as ix, find_key_address},
        state::{key_account_len, staging_account_len},
    },
    solana_instruction::{AccountMeta, Instruction},
    solana_program_error::ProgramError,
};

pub const PROGRAM_SO: &str = "solana_groth16_program";
pub const BENCH_SO: &str = "groth16_bench";

pub use solana_groth16_verify::constants::SYSTEM_PROGRAM_ID;

/// Custom error codes mirrored from `program/src/error.rs`.
pub mod code {
    pub const INVALID_PROOF_LENGTH: u32 = 0;
    pub const INVALID_KEY_LENGTH: u32 = 1;
    pub const TOO_MANY_PUBLIC_INPUTS: u32 = 2;
    pub const PUBLIC_INPUT_COUNT_MISMATCH: u32 = 3;
    pub const NON_CANONICAL_SCALAR: u32 = 4;
    pub const INVALID_POINT: u32 = 5;
    pub const PROOF_INVALID: u32 = 6;
    pub const INVALID_ACCOUNT_DATA: u32 = 7;
    pub const WRONG_DISCRIMINATOR: u32 = 8;
    pub const KEY_ADDRESS_MISMATCH: u32 = 100;
    pub const KEY_ALREADY_PUBLISHED: u32 = 101;
    pub const STAGING_SIZE_MISMATCH: u32 = 102;
    pub const WRITE_OUT_OF_BOUNDS: u32 = 103;
    pub const IDENTITY_KEY_ELEMENT: u32 = 104;
}

pub struct Harness {
    pub mollusk: Mollusk,
    pub program_id: Address,
}

/// `None` (with a note on stderr) when the SBF artifact is not available.
pub fn harness() -> Option<Harness> {
    harness_with(&[PROGRAM_SO])
}

pub fn harness_with(extra_programs: &[&str]) -> Option<Harness> {
    let out_dir = match std::env::var_os("SBF_OUT_DIR") {
        Some(d) => std::path::PathBuf::from(d),
        None => {
            eprintln!("skipping SBF test: set SBF_OUT_DIR (see `make test-program`)");
            return None;
        }
    };
    for name in extra_programs {
        let so = out_dir.join(format!("{name}.so"));
        assert!(
            so.exists(),
            "{} not found; run `make build-sbf` first",
            so.display()
        );
    }
    let program_id = ix::ID;
    let mut mollusk = Mollusk::default();
    mollusk.add_program(&program_id, PROGRAM_SO);
    Some(Harness {
        mollusk,
        program_id,
    })
}

impl Harness {
    pub fn rent_exempt(&self, data_len: usize) -> u64 {
        self.mollusk.sysvars.rent.minimum_balance(data_len)
    }

    /// A funded system-owned wallet.
    pub fn wallet(&self, lamports: u64) -> (Address, Account) {
        (
            Address::new_unique(),
            Account {
                lamports,
                data: vec![],
                owner: SYSTEM_PROGRAM_ID,
                executable: false,
                rent_epoch: 0,
            },
        )
    }

    /// System program `CreateAccount`: the transaction-level step that the
    /// client performs before `InitializeStaging`.
    pub fn create_account_ix(
        &self,
        payer: &Address,
        new_account: &Address,
        space: usize,
        owner: &Address,
    ) -> Instruction {
        let mut data = Vec::with_capacity(4 + 8 + 8 + 32);
        data.extend_from_slice(&0u32.to_le_bytes()); // SystemInstruction::CreateAccount
        data.extend_from_slice(&self.rent_exempt(space).to_le_bytes());
        data.extend_from_slice(&(space as u64).to_le_bytes());
        data.extend_from_slice(owner.as_array());
        Instruction::new_with_bytes(
            SYSTEM_PROGRAM_ID,
            &data,
            vec![
                AccountMeta::new(*payer, true),
                AccountMeta::new(*new_account, true),
            ],
        )
    }

    /// Executes `instructions` as **one transaction**: same message, same
    /// transaction context, all-or-nothing. This is what a client actually
    /// submits, and the only way to test that a failing instruction rolls back
    /// the ones before it. `process_instruction_chain`, by contrast, runs each
    /// instruction in its own context and keeps the effects of the ones that
    /// succeeded.
    pub fn run_atomic(
        &self,
        instructions: &[Instruction],
        accounts: &[(Address, Account)],
    ) -> TransactionResult {
        self.mollusk
            .process_transaction_instructions(instructions, accounts)
    }

    /// The full documented registration flow in one instruction chain:
    /// `create_account ‖ InitializeStaging ‖ Write… ‖ Publish`, with `Write`s
    /// chunked at `chunk` bytes.
    ///
    /// `key_target` is the account initially at the key PDA — normally
    /// `Account::default()` (nonexistent), or a pre-funded system account to
    /// exercise that path. `key_pda` overrides the derived address when a test
    /// wants to hand `Publish` the wrong one.
    pub fn register_chain(&self, req: RegisterRequest<'_>) -> (InstructionResult, Address) {
        let key = req.key;
        let n = key.num_public_inputs();
        let staging = Address::new_unique();
        let key_pda = req
            .key_pda
            .unwrap_or_else(|| find_key_address(&self.program_id, &key.hash()).0);
        let payer = req.payer.unwrap_or(req.authority);
        let body = req.body_override.unwrap_or_else(|| key.body().to_vec());

        // The library's own builders, so the happy path exercises them.
        let mut instructions = ix::create_staging(
            &self.program_id,
            &req.authority.0,
            &req.authority.0,
            &staging,
            n as u16,
            self.rent_exempt(staging_account_len(n)),
        )
        .to_vec();
        instructions.extend(ix::write_body(
            &self.program_id,
            &req.authority.0,
            &staging,
            &body,
            req.chunk,
        ));
        instructions.push(ix::publish(
            &self.program_id,
            &req.authority.0,
            &payer.0,
            &staging,
            &key_pda,
        ));

        let mut accounts = vec![
            req.authority.clone(),
            (staging, Account::default()),
            (key_pda, req.key_target.clone()),
            keyed_account_for_system_program(),
        ];
        if payer.0 != req.authority.0 {
            accounts.push(payer.clone());
        }

        let result = self
            .mollusk
            .process_instruction_chain(&instructions, &accounts);
        (result, key_pda)
    }

    /// Registers `key` from a fresh, well-funded authority and returns the
    /// published key account, asserting success.
    pub fn register(&self, key: &OnChainKey) -> (Address, Account) {
        let authority = self.wallet(10_000_000_000);
        let (result, key_pda) = self.register_chain(RegisterRequest::new(key, &authority));
        assert_success(&result);
        let account = account_of(&result, &key_pda);
        assert_eq!(account.owner, self.program_id);
        assert_eq!(account.data.len(), key_account_len(key.num_public_inputs()));
        (key_pda, account)
    }

    pub fn verify(
        &self,
        key: &(Address, Account),
        proof: &[u8; PROOF_SIZE],
        public_inputs: &[[u8; 32]],
    ) -> InstructionResult {
        let instruction = ix::verify(&self.program_id, &key.0, proof, public_inputs);
        self.mollusk
            .process_instruction(&instruction, std::slice::from_ref(key))
    }
}

/// Parameters for [`Harness::register_chain`]; `new` gives the happy path.
pub struct RegisterRequest<'a> {
    pub key: &'a OnChainKey,
    pub authority: &'a (Address, Account),
    pub payer: Option<&'a (Address, Account)>,
    pub chunk: usize,
    pub key_target: Account,
    pub key_pda: Option<Address>,
    /// Bytes to write instead of the real body (same length), to reach
    /// `Publish` with contents that don't match the address.
    pub body_override: Option<Vec<u8>>,
}

impl<'a> RegisterRequest<'a> {
    pub fn new(key: &'a OnChainKey, authority: &'a (Address, Account)) -> Self {
        Self {
            key,
            authority,
            payer: None,
            chunk: 800,
            key_target: Account::default(),
            key_pda: None,
            body_override: None,
        }
    }
}

fn lookup(accounts: &[(Address, Account)], address: &Address) -> Account {
    accounts
        .iter()
        .find(|(a, _)| a == address)
        .map(|(_, acc)| acc.clone())
        .unwrap_or_else(|| panic!("account {address} not in result"))
}

pub fn account_of(result: &InstructionResult, address: &Address) -> Account {
    lookup(&result.resulting_accounts, address)
}

pub fn assert_success(result: &InstructionResult) {
    assert!(
        result.program_result.is_ok(),
        "expected success, got {:?}",
        result.program_result
    );
}

pub fn assert_custom_error(result: &InstructionResult, code: u32) {
    assert_program_error(result, ProgramError::Custom(code));
}

pub fn assert_program_error(result: &InstructionResult, expected: ProgramError) {
    match &result.program_result {
        mollusk_svm::result::ProgramResult::Failure(e) if *e == expected => {}
        other => panic!("expected {expected:?}, got {other:?}"),
    }
}

pub fn tx_account_of(result: &TransactionResult, address: &Address) -> Account {
    lookup(&result.resulting_accounts, address)
}

pub fn assert_tx_success(result: &TransactionResult) {
    assert!(
        matches!(result.program_result, TransactionProgramResult::Success),
        "expected success, got {:?}",
        result.program_result
    );
}

/// The transaction failed at instruction `index` with `expected`.
pub fn assert_tx_program_error(result: &TransactionResult, index: usize, expected: ProgramError) {
    match &result.program_result {
        TransactionProgramResult::Failure(i, e) if *i == index && *e == expected => {}
        other => panic!("expected {expected:?} at instruction {index}, got {other:?}"),
    }
}

pub fn assert_tx_custom_error(result: &TransactionResult, index: usize, code: u32) {
    assert_tx_program_error(result, index, ProgramError::Custom(code));
}

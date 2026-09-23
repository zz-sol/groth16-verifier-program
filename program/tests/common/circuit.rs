//! A parameterized arkworks circuit for randomized end-to-end tests.
//!
//! `n` public inputs `pᵢ`, each constrained to be the square of a private
//! witness `wᵢ`. Any `n ≥ 0` works, so one circuit covers the size range
//! and, by choosing `wᵢ ∈ {0, 1}`, the trivial-scalar paths of the MSM.

use {
    ark_bn254::{Bn254, Fr},
    ark_ec::CurveGroup,
    ark_ff::{One, UniformRand},
    ark_groth16::{Groth16, PreparedVerifyingKey},
    ark_r1cs_std::{
        alloc::AllocVar,
        eq::EqGadget,
        fields::{fp::FpVar, FieldVar},
    },
    ark_relations::gr1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    ark_std::rand::{Rng, SeedableRng},
    groth16_convert::{arkworks, wire::g1_to_bytes, OnChainKey, OnChainProof},
    rand_chacha::ChaCha20Rng,
};

pub struct Squares {
    pub witnesses: Vec<Option<Fr>>,
}

impl Squares {
    /// Shape only, for setup.
    pub fn blank(n: usize) -> Self {
        Self {
            witnesses: vec![None; n],
        }
    }

    /// Fully assigned, for proving.
    pub fn assigned(w: Vec<Fr>) -> Self {
        Self {
            witnesses: w.into_iter().map(Some).collect(),
        }
    }

    pub fn public_inputs(&self) -> Vec<Fr> {
        self.witnesses
            .iter()
            .map(|w| {
                let w = w.expect("assigned");
                w * w
            })
            .collect()
    }
}

impl ConstraintSynthesizer<Fr> for Squares {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        for w in &self.witnesses {
            let w_var =
                FpVar::new_witness(cs.clone(), || w.ok_or(SynthesisError::AssignmentMissing))?;
            let p_var = FpVar::new_input(cs.clone(), || {
                w.map(|w| w * w).ok_or(SynthesisError::AssignmentMissing)
            })?;
            w_var.mul_equals(&w_var, &p_var)?;
        }
        if self.witnesses.is_empty() {
            // Keep the constraint system non-degenerate for n = 0.
            let one = FpVar::new_witness(cs, || Ok(Fr::one()))?;
            one.enforce_equal(&FpVar::Constant(Fr::one()))?;
        }
        Ok(())
    }
}

/// A fresh setup for `n` public inputs plus one proof, converted to the
/// on-chain format and — after a round trip back through `groth16-convert` —
/// verified by arkworks, so the conversion itself is checked on the host
/// before anything reaches the program.
pub struct Instance {
    pub seed: u64,
    /// Prepared from the *round-tripped* key, i.e. from the on-chain bytes.
    pub pvk: PreparedVerifyingKey<Bn254>,
    pub key: OnChainKey,
    pub proof: OnChainProof,
    pub inputs: Vec<Fr>,
    pub input_bytes: Vec<[u8; 32]>,
}

impl Instance {
    /// Random witnesses under a random setup.
    pub fn random(n: usize) -> Self {
        Self::with_seed(n, ark_std::rand::thread_rng().gen(), None)
    }

    /// Fixed witnesses (e.g. zeros and ones) under a random setup.
    pub fn with_witnesses(witnesses: Vec<Fr>) -> Self {
        Self::with_seed(
            witnesses.len(),
            ark_std::rand::thread_rng().gen(),
            Some(witnesses),
        )
    }

    /// Deterministic in `seed`. The seed is logged on stderr so a failing run
    /// can be replayed; `ChaCha20Rng` is used rather than `StdRng` because its
    /// output is specified and stable across `rand` versions.
    pub fn with_seed(n: usize, seed: u64, witnesses: Option<Vec<Fr>>) -> Self {
        eprintln!("arkworks instance: n = {n}, seed = {seed}");
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
            Squares::blank(n),
            &mut rng,
        )
        .expect("setup");
        let witnesses = witnesses.unwrap_or_else(|| (0..n).map(|_| Fr::rand(&mut rng)).collect());
        let circuit = Squares::assigned(witnesses);
        let inputs = circuit.public_inputs();
        let ark_proof =
            Groth16::<Bn254>::create_random_proof_with_reduction(circuit, &pk, &mut rng)
                .expect("prove");

        // Convert, then decode the on-chain bytes back into arkworks types and
        // verify *those*. This is what exercises the negations and the
        // serialization; verifying `pk.vk` against `ark_proof` would not.
        let key = arkworks::key(&pk.vk).expect("convert key");
        let proof = arkworks::proof(&ark_proof);
        let vk_rt = arkworks::key_from_on_chain(&key).expect("round-trip key");
        let proof_rt = arkworks::proof_from_on_chain(&proof).expect("round-trip proof");
        let pvk = ark_groth16::prepare_verifying_key(&vk_rt);
        assert!(
            Groth16::<Bn254>::verify_proof(&pvk, &proof_rt, &inputs).unwrap(),
            "arkworks rejects the round-tripped key/proof (seed {seed})"
        );

        let input_bytes = arkworks::public_inputs(&inputs);
        Self {
            seed,
            pvk,
            key,
            proof,
            inputs,
            input_bytes,
        }
    }

    /// The MSM result `L = IC₀ + Σ aᵢ·ICᵢ`, computed by arkworks — not by the
    /// verifier under test — for the bench program's pairing-only stage.
    pub fn l(&self) -> [u8; 64] {
        let l = Groth16::<Bn254>::prepare_inputs(&self.pvk, &self.inputs).expect("prepare inputs");
        g1_to_bytes(&l.into_affine())
    }
}

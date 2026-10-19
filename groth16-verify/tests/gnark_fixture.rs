//! Parses the gnark fixture under `tools/fixtures/gnark/` and checks the converted
//! bytes three ways: compressed and raw encodings agree, arkworks verifies the
//! round-tripped key and proof, and `solana-groth16-verify`'s host path accepts the
//! exact bytes the program will see.

use {
    ark_bn254::Bn254,
    ark_groth16::{prepare_verifying_key, Groth16},
    groth16_convert::{arkworks, gnark, wire::public_inputs_flat},
    solana_groth16_verify::{Proof, VerifyingKey},
};

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../tools/fixtures/gnark/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

#[test]
fn compressed_and_raw_encodings_convert_identically() {
    let vk = gnark::parse_verifying_key(&fixture("vk.bin")).unwrap();
    let vk_raw = gnark::parse_verifying_key(&fixture("vk.raw.bin")).unwrap();
    assert_eq!(vk.num_public_inputs(), 3);
    let (a1, b1, g1, d1, ic1) = vk.elements().unwrap();
    let (a2, b2, g2, d2, ic2) = vk_raw.elements().unwrap();
    assert_eq!(a1, a2, "alpha");
    assert_eq!(b1, b2, "beta");
    assert_eq!(g1, g2, "gamma");
    assert_eq!(d1, d2, "delta");
    assert_eq!(ic1, ic2, "ic");
    assert_eq!(vk, vk_raw);

    let proof = gnark::parse_proof(&fixture("proof.bin")).unwrap();
    let proof_raw = gnark::parse_proof(&fixture("proof.raw.bin")).unwrap();
    let (pa1, pb1, pc1) = proof.elements().unwrap();
    let (pa2, pb2, pc2) = proof_raw.elements().unwrap();
    assert_eq!(pa1, pa2, "proof.a");
    assert_eq!(pb1, pb2, "proof.b");
    assert_eq!(pc1, pc2, "proof.c");
    assert_eq!(proof, proof_raw);
}

#[test]
fn public_witness_is_3_times_5_equals_15() {
    let inputs = gnark::parse_public_witness(&fixture("public.bin")).unwrap();
    assert_eq!(
        inputs,
        vec![
            ark_bn254::Fr::from(3u64),
            ark_bn254::Fr::from(5u64),
            ark_bn254::Fr::from(15u64)
        ]
    );
}

#[test]
fn arkworks_verifies_the_converted_key_and_proof() {
    let key = gnark::parse_verifying_key(&fixture("vk.bin")).unwrap();
    let proof = gnark::parse_proof(&fixture("proof.bin")).unwrap();
    let inputs = gnark::parse_public_witness(&fixture("public.bin")).unwrap();

    let ark_vk = arkworks::key_from_on_chain(&key).unwrap();
    let ark_proof = arkworks::proof_from_on_chain(&proof).unwrap();
    let pvk = prepare_verifying_key(&ark_vk);
    assert!(Groth16::<Bn254>::verify_proof(&pvk, &ark_proof, &inputs).unwrap());

    let mut wrong = inputs.clone();
    wrong[2] = ark_bn254::Fr::from(16u64);
    assert!(!Groth16::<Bn254>::verify_proof(&pvk, &ark_proof, &wrong).unwrap());
}

#[test]
fn solana_groth16_verify_host_path_accepts_the_wire_bytes() {
    let key = gnark::parse_verifying_key(&fixture("vk.bin")).unwrap();
    let proof = gnark::parse_proof(&fixture("proof.bin")).unwrap();
    let inputs = gnark::parse_public_witness(&fixture("public.bin")).unwrap();

    let vk = VerifyingKey::from_body(key.body())
        .unwrap()
        .validate_for_publish()
        .unwrap();
    let proof = Proof::from_bytes(&proof.0).unwrap();
    let flat = public_inputs_flat(&inputs);
    solana_groth16_verify::verify(&vk, &proof, &flat).unwrap();

    let mut wrong = flat.clone();
    wrong[95] ^= 1;
    assert_eq!(
        solana_groth16_verify::verify(&vk, &proof, &wrong),
        Err(solana_groth16_verify::Groth16Error::ProofInvalid)
    );
    assert_eq!(
        solana_groth16_verify::verify(&vk, &proof, &flat[..64]),
        Err(solana_groth16_verify::Groth16Error::PublicInputCountMismatch)
    );
}

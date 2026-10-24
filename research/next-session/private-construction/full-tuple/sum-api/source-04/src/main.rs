//! ADR0062: consume only an actual public MPC aggregate; no financial proofs.
use std::io::{self, Read};
use jubjub::Scalar;
use rand::{rngs::StdRng, SeedableRng};
use redjubjub::{Binding, SigningKey, VerificationKey};
use sapling::value::{CommitmentSum, NoteValue, ValueCommitTrapdoor, ValueCommitment};
use serde_json::json;

fn cv(value: u64, blind: Scalar) -> ValueCommitment {
    ValueCommitment::derive(NoteValue::from_raw(value),
        ValueCommitTrapdoor::from_bytes(blind.to_bytes()).unwrap())
}

fn main() {
    let mut raw = String::new(); io::stdin().read_to_string(&mut raw).unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let fields = value.as_object().expect("typed public request");
    assert_eq!(fields.len(), 2);
    assert_eq!(fields["schema"], "kpx6-public-sum-binding-consumer/v1");
    let encoded = fields["scalar_hex32"].as_str().unwrap();
    assert!(encoded.len() == 64 && encoded.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    // Exact canonical JSON also rejects duplicate keys and unknown fields.
    assert_eq!(raw.trim_end_matches('\n'), value.to_string());
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&encoded[2*i..2*i+2], 16).unwrap();
    }
    let delta = Option::<Scalar>::from(Scalar::from_bytes(&bytes)).expect("canonical Jubjub Fr");
    // Independent public fixture: each input100, output99, fee1; blinds -1,-2,6.
    // Their global public commitment difference after fee3 is exactly 3*R.
    // The received delta is never substituted by the expected literal3.
    let inputs: CommitmentSum = [-Scalar::from(1u64), -Scalar::from(2u64), Scalar::from(6u64)]
        .into_iter().map(|r| cv(100, r)).sum();
    let outputs: CommitmentSum = (0..3).map(|_| cv(99, Scalar::zero())).sum();
    let bvk: VerificationKey<Binding> = (inputs.clone() - outputs.clone()).into_bvk(3);
    let digest = [0x62u8; 32];
    // Fixed public synthetic signing material only; no wallet key or proof.
    let mut rng = StdRng::from_seed([0x73u8; 32]);
    let key = SigningKey::<Binding>::from_bytes(&delta.to_bytes()).unwrap();
    let sig = key.sign(&mut rng, &digest);
    let correct = bvk.verify(&digest, &sig).is_ok();
    let wrong_key = SigningKey::<Binding>::from_bytes(&(delta + Scalar::from(1u64)).to_bytes()).unwrap();
    let wrong_sig = wrong_key.sign(&mut rng, &digest);
    let wrong_delta_rejected = bvk.verify(&digest, &wrong_sig).is_err();
    let mut changed_digest = digest; changed_digest[0] ^= 1;
    let wrong_digest_rejected = bvk.verify(&changed_digest, &sig).is_err();
    let wrong_fee_key: VerificationKey<Binding> = (inputs - outputs).into_bvk(4);
    let wrong_fee_rejected = wrong_fee_key.verify(&digest, &sig).is_err();
    assert!(correct && wrong_delta_rejected && wrong_digest_rejected && wrong_fee_rejected);
    println!("{}", json!({"schema":"kpx6-existing-curve-binding-consumer-result/v1",
        "actual_received_scalar_hex32": encoded, "correct_actual_delta_verifies":correct,
        "wrong_delta_rejected":wrong_delta_rejected,"wrong_digest_rejected":wrong_digest_rejected,
        "wrong_fee_rejected":wrong_fee_rejected,"synthetic_global_commitment_difference":"3*R",
        "Groth16_or_native_financial_proof_verified":false,"KAS_or_Sapling_transaction_validated":false}));
}

//! Verification-only entry for one exact-canonical frozen W1 proof receipt.
//! Input is bounded receipt bytes on stdin. No argument, assignment, prover,
//! R1CS, proving key, output path, network, or funds surface exists.

use kpi_private_batch_relation::counterfactual_w1::offline_verifier::{
    FROZEN_W1_PROOF_RECEIPT_MAX_BYTES, verify_frozen_round1_proof_receipt,
};
use std::{env, io::Read};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().count() != 1 {
        return Err("usage: verify_frozen_w1_round1_receipt < PROOF-RECEIPT.json".into());
    }
    let mut raw = Vec::new();
    std::io::stdin()
        .lock()
        .take(FROZEN_W1_PROOF_RECEIPT_MAX_BYTES as u64 + 1)
        .read_to_end(&mut raw)?;
    let commitment = verify_frozen_round1_proof_receipt(&raw)
        .map_err(|_| "fixed W1 round-1 proof receipt verification refused")?;
    println!("FROZEN_W1_VERIFIED_PROOF_RECEIPT_SHA256={commitment}");
    Ok(())
}

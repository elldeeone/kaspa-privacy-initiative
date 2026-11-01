//! Fixed offline proof entry for the one retained W1 round-1 assignment.
//! The sole argument is a create-new receipt path in an existing owner-only
//! directory. No assignment, artifact, round, public input, or randomness is
//! accepted from the caller.

use kpi_private_batch_relation::counterfactual_w1::offline_verifier::write_frozen_round1_proof_receipt;
use std::{env, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 {
        return Err("usage: prove_frozen_w1_round1 FRESH-PRIVATE-RECEIPT.json".into());
    }
    let commitment = write_frozen_round1_proof_receipt(Path::new(&arguments[0]))
        .map_err(|_| "fixed W1 round-1 proof refused")?;
    println!("FROZEN_W1_PROOF_RECEIPT_SHA256={commitment}");
    Ok(())
}

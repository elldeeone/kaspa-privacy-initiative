//! Preparation-only measurement for the one frozen W1 round-1 assignment.
//! No assignment values, proving key, proof, setup, network, or funds leave
//! this process.

use kpi_private_batch_relation::counterfactual_w1::offline_verifier::write_frozen_round1_assignment_receipt;
use std::{env, path::Path};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 1 {
        return Err("usage: prepare_frozen_w1_round1_assignment FRESH-RECEIPT.json".into());
    }
    write_frozen_round1_assignment_receipt(Path::new(&arguments[0]))
        .map_err(|_| "frozen W1 assignment preparation refused")?;
    println!("FROZEN_W1_ROUND1_ASSIGNMENT_PREPARED_NO_PROOF");
    Ok(())
}

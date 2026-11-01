//! Verification-only CLI for the non-authoritative offline W1 fixture.
//!
//! No proving key, setup, prover, network, funding, source-authority minter or
//! production bridge constructor is linked through this entrypoint.

use kpi_private_batch_relation::counterfactual_w1::offline_verifier::verify_request_file;
use std::path::Path;

fn main() {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 {
        eprintln!("OFFLINE_W1_AGGREGATE_VERIFIER_REFUSED");
        std::process::exit(2);
    }
    if verify_request_file(Path::new(&arguments[0]), Path::new(&arguments[1])).is_err() {
        eprintln!("OFFLINE_W1_AGGREGATE_VERIFIER_REFUSED");
        std::process::exit(1);
    }
    println!("OFFLINE_W1_AGGREGATE_VERIFICATION_RECEIPT_WRITTEN");
}

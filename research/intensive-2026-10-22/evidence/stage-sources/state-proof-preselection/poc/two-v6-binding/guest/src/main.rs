#![no_main]
use kpi_two_v6_binding::{compiled::CompiledResearchGate, INPUT_LEN};
use std::io::Read;
risc0_zkvm::guest::entry!(main);
fn main() {
    let mut bytes = Vec::new();
    risc0_zkvm::guest::env::stdin()
        .take((INPUT_LEN + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    let gate = CompiledResearchGate::new()
        .unwrap_or_else(|error| panic!("two-v6 fixed parameter rejection: {error}"));
    println!(
        "PROFILE fixed_parameters {}",
        risc0_zkvm::guest::env::cycle_count()
    );
    let verified = gate
        .verify(&bytes)
        .unwrap_or_else(|error| panic!("two-v6 binding rejection: {error}"));
    // Exactly42 bytes. No per-operation digest, fee, index, proof, anchor or
    // statement grouping is appended to the declared two-v6 public journal.
    risc0_zkvm::guest::env::commit_slice(&verified.journal);
}

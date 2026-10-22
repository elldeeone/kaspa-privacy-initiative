#![no_main]
use kpi_two_v6_state::{StateGate, INPUT_LEN};
use std::io::Read;
risc0_zkvm::guest::entry!(main);

fn main() {
    let mut input = Vec::new();
    risc0_zkvm::guest::env::stdin()
        .take((INPUT_LEN + 1) as u64)
        .read_to_end(&mut input)
        .unwrap();
    let gate = StateGate::new()
        .unwrap_or_else(|error| panic!("two-v6 state parameter rejection: {error}"));
    let assertion = gate
        .evaluate(&input)
        .unwrap_or_else(|error| panic!("two-v6 state rejection: {error}"));
    // This exact new J336 binds a declared predecessor and derived successor.
    // Actual native context must independently authenticate the predecessor.
    // This separate image cannot replace or reinterpret the original J42.
    risc0_zkvm::guest::env::commit_slice(&assertion.journal);
}

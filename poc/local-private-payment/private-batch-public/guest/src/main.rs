#![no_main]
use kpi_private_batch_public::{evaluate, PROJECTION_LEN};
use std::io::Read;
risc0_zkvm::guest::entry!(main);
fn main() {
    let mut input = Vec::new();
    risc0_zkvm::guest::env::stdin()
        .take((PROJECTION_LEN + 1) as u64)
        .read_to_end(&mut input)
        .unwrap();
    let journal = evaluate(&input)
        .unwrap_or_else(|error| panic!("private-batch public predicate rejected: {error}"));
    risc0_zkvm::guest::env::commit_slice(&journal);
}

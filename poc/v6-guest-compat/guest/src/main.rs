#![no_main]
use std::io::Read;
risc0_zkvm::guest::entry!(main);
fn main() {
    // Fixed public diagnostic bundle, bounded before allocation. Reading one
    // extra byte ensures a valid prefix plus trailing data is rejected.
    let mut bytes = Vec::new();
    risc0_zkvm::guest::env::stdin()
        .take((kpi_v6_guest_compat::BUNDLE_LEN + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    let journal = kpi_v6_guest_compat::verify_bundle(&bytes)
        .unwrap_or_else(|error| panic!("v6 compatibility rejection: {error}"));
    risc0_zkvm::guest::env::commit_slice(&journal);
}

//! Full reviewed relation, generic context. Pool/native admission is separate.
#![no_main]
use risc0_zkvm::guest::env;
risc0_zkvm::guest::entry!(main);
fn main() {
    let mut size = [0; 4];
    env::read_slice(&mut size);
    let size = u32::from_le_bytes(size) as usize;
    assert!(size <= kpi_wallet_core::MAX_INPUT, "oversized witness");
    let mut raw = vec![0; size];
    env::read_slice(&mut raw);
    let w = kpi_wallet_core::Witness::decode(&raw).expect("canonical witness");
    let journal = kpi_wallet_core::validate(&w).expect("wallet relation");
    env::commit_slice(&journal);
}

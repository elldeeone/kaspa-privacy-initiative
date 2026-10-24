//! Test-only canonicalization; no financial validation or acceptance authority.
//!
//! Keeping mutated transactions canonical prevents stale IDs or storage mass
//! from becoming the reason that a native script control is rejected.
use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    mass::MassCalculator,
    tx::{GenesisCovenantGroup, PopulatedTransaction, Transaction, UtxoEntry},
};
use serde_json::{json, Value};
use std::io::{self, Read};

fn run() -> Result<Value, Box<dyn std::error::Error>> {
    let mut raw = Vec::new();
    io::stdin()
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)?;
    if raw.len() > 4 * 1024 * 1024 {
        return Err("control request size".into());
    }
    let input: Value = serde_json::from_slice(&raw)?;
    let operation = input["operation"].as_str().ok_or("operation")?;
    let mut tx: Transaction = serde_json::from_value(input["case"]["transaction"].clone())?;
    let entries: Vec<UtxoEntry> = serde_json::from_value(input["case"]["entries"].clone())?;
    if tx.inputs.len() != entries.len() || tx.inputs.is_empty() || tx.outputs.is_empty() {
        return Err("control context cardinality".into());
    }
    match operation {
        "canonicalize" => (),
        "genesis-output-covenant" | "genesis-last-output-covenant" => {
            if tx.inputs.len() != 1
                || !(1..=2).contains(&tx.outputs.len())
                || entries[0].covenant_id.is_some()
            {
                return Err("ordinary input and single output required".into());
            }
            let output = if operation == "genesis-last-output-covenant" {
                tx.outputs.len() - 1
            } else {
                0
            };
            tx.populate_genesis_covenants(&[GenesisCovenantGroup::new(0, vec![output as u32])])?;
        }
        _ => return Err("unknown fixed control operation".into()),
    }
    let masses = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS)
        .calc_contextual_masses(&PopulatedTransaction::new(&tx, entries.clone()))
        .ok_or("control storage mass unavailable")?;
    tx.set_storage_mass(masses.storage_mass);
    tx.finalize();
    Ok(json!({"schema":"kpx8-test-only-native-control-codec/v1",
        "classification":"CANONICALIZATION_ONLY_NOT_NATIVE_OR_FINANCIAL_ACCEPTANCE",
        "case":{"transaction":tx,"entries":entries},
        "operation":operation,
        "native_VM_executed":false,
        "component_or_outer_G16_verified":false}))
}

fn main() {
    match run() {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("NATIVE_CONTROL_CODEC_REFUSED: {error}");
            std::process::exit(1);
        }
    }
}

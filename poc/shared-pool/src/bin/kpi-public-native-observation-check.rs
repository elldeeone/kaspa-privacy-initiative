//! Validate the NEW public observation adapter against the pinned native replay.
//! Only already-public VK/descriptor/transaction bodies enter this executable.
//! No keys, proving parameters, setup, fresh proofs, RPC or network operations.
use kaspa_consensus_core::tx::Transaction;
use kpi_shared_pool::{
    Result, native,
    protocol::hash,
    two_input::replay::{self, Descriptor, Replay},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{fs, path::Path};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicInput {
    descriptor: Descriptor,
    vk_hex: String,
    lineage: Vec<Value>,
    parents: Vec<Value>,
}

fn replay(input: &PublicInput) -> Result<Replay> {
    replay::replay(
        &input.descriptor,
        &hex::decode(&input.vk_hex)?,
        &input.lineage,
        &input.parents,
    )
}

fn change_transaction(
    input: &mut PublicInput,
    index: usize,
    mutate: impl FnOnce(&mut Transaction),
) -> Result<()> {
    let mut transaction = native::parse_tx(&input.lineage[index])?;
    mutate(&mut transaction);
    transaction.finalize();
    // An altered payload/output gets its correct new transaction ID. A parser
    // rejecting a stale ID cannot stand in for a covenant/proof rejection.
    input.lineage[index] = native::tx_json(&transaction);
    Ok(())
}

fn rejected(input: &PublicInput, name: &str, stage: &str) -> Result<Value> {
    match replay(input) {
        Ok(_) => Err(format!("{name}: altered public input unexpectedly accepted").into()),
        Err(error) => {
            let error = error.to_string();
            if !error.contains(stage) {
                return Err(format!("{name}: expected stage {stage:?}, got {error:?}").into());
            }
            Ok(
                json!({"name": name, "passed": true, "outcome": "rejected", "expected_stage":stage,"error":error}),
            )
        }
    }
}

fn check(input: &PublicInput, input_bytes: &[u8]) -> Result<Value> {
    let baseline = replay(input)?;
    let compact = baseline.state.compact()?;
    let mut controls = Vec::new();

    let mut bad = input.clone();
    change_transaction(&mut bad, 1, |tx| tx.inputs[0].signature_script[2] ^= 1)?;
    controls.push(rejected(
        &bad,
        "canonical_proof_mutation",
        "pool native validation",
    )?);

    let mut bad = input.clone();
    change_transaction(&mut bad, 1, |tx| tx.payload[8 + 213] ^= 1)?;
    controls.push(rejected(
        &bad,
        "canonical_authorization_fee_mutation",
        "public state/transaction reconstruction mismatch",
    )?);

    let mut bad = input.clone();
    change_transaction(&mut bad, 1, |tx| tx.payload[385] ^= 1)?;
    controls.push(rejected(
        &bad,
        "canonical_unbound_ciphertext_mutation",
        "v6 domain/reserve/cipher binding",
    )?);

    let mut bad = input.clone();
    change_transaction(&mut bad, 1, |tx| {
        tx.payload[385] ^= 1;
        let cipher_hash = hash(&tx.payload[385..755]);
        tx.payload[8 + 345..385].copy_from_slice(&cipher_hash);
    })?;
    controls.push(rejected(
        &bad,
        "canonical_rebound_ciphertext_requires_new_proof",
        "pool native validation",
    )?);

    let mut bad = input.clone();
    change_transaction(&mut bad, 1, |tx| tx.payload[860] ^= 1)?;
    controls.push(rejected(
        &bad,
        "canonical_public_witness_mutation",
        "public state/transaction reconstruction mismatch",
    )?);

    let mut bad = input.clone();
    change_transaction(&mut bad, 1, |tx| {
        // Preserve a supported SPK representation and alter a digest byte.
        let mut script = tx.outputs[0].script_public_key.script().to_vec();
        script[5] ^= 1;
        tx.outputs[0].script_public_key =
            kaspa_consensus_core::tx::ScriptPublicKey::from_vec(0, script);
    })?;
    controls.push(rejected(
        &bad,
        "canonical_successor_script_mutation",
        "public state/transaction reconstruction mismatch",
    )?);

    let mut bad = input.clone();
    let amount = bad.parents[0]["outputs"][0]["value"]
        .as_str()
        .ok_or("parent amount string")?
        .parse::<u64>()?;
    bad.parents[0]["outputs"][0]["value"] = json!((amount + 1).to_string());
    controls.push(rejected(
        &bad,
        "parent_body_keeps_stale_id",
        "unsupported or noncanonical funding parent",
    )?);

    // A parent signature is excluded from its transaction ID. Its missing input
    // UTXOs mean replay cannot authenticate that signature. Preserve this gap as
    // a positive limitation control; never upgrade parent-spend validity.
    let mut changed_parent_signature = input.clone();
    let mut parent = native::parse_tx(&changed_parent_signature.parents[0])?;
    parent.inputs[0].signature_script[1] ^= 1;
    parent.finalize();
    changed_parent_signature.parents[0] = native::tx_json(&parent);
    let limited = replay(&changed_parent_signature)?;
    if serde_json::to_value(&limited.state)? != serde_json::to_value(&baseline.state)? {
        return Err("parent-signature limitation changed public state".into());
    }
    controls.push(json!({
        "name":"parent_signature_unverified_without_ancestry", "passed":true,
        "outcome":"accepted_as_unverified_parent_context",
        "meaning":"selected funding outputs and parent ID checked; parent input signature not authenticated",
        "parent_spends_verified":false
    }));

    let mut prefixes = Vec::new();
    for count in [0usize, 1, 6] {
        let mut prefix = input.clone();
        prefix.lineage.truncate(count + 1);
        let result = replay(&prefix)?;
        prefixes.push(json!({
            "prefix_operations":count,
            "state_hex":hex::encode(result.state.compact()?.bytes()),
            "accounting":result.accounting,
            "bootstrap_validated":result.bootstrap_validated,
            "chain_acceptance_verified":result.chain_acceptance_verified,
            "records":result.records.iter().map(|r|json!({
                "transaction_id":r.transaction["id"],"full_hash":r.full_hash
            })).collect::<Vec<_>>()
        }));
    }

    Ok(json!({
        "schema":"kpi-public-native-observation-native-check-v1",
        "passed":true,
        "input_file_sha256":hex::encode(hash(input_bytes)),
        "native_source_dependency":"rusty-kaspa 01b532e8b553523216471682649693af92f0fd16",
        "scope":"new public observation adapter to unchanged v6 native replay; genuine retained proofs only",
        "baseline":{
            "state_hex":hex::encode(compact.bytes()),
            "accounting":baseline.accounting,
            "bootstrap_validated":baseline.bootstrap_validated,
            "transaction_id_recomputed":true,
            "native_vm_verified":true,
            "groth16_verified":true,
            "canonical_covenant_code_verified":true,
            "public_settlement_witness_recomputed":true,
            "funding_parent_spends_verified":false,
            "chain_acceptance_verified":false,
            "records":baseline.records.iter().map(|r|json!({
                "transaction_id":r.transaction["id"],"full_hash":r.full_hash,
                "authorization_sha256":r.authorization_sha256,"proof_sha256":r.proof_sha256
            })).collect::<Vec<_>>()
        },
        "controls":controls,"prefixes":prefixes,
        "limits":["descriptor and accepted-chain view require external authentication",
                  "missing funding-parent input ancestry is unverified",
                  "no current spendability, network acceptance, privacy or cryptographic audit claim"]
    }))
}

fn main() {
    let result = (|| -> Result<()> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        if args.len() != 1 {
            return Err("PUBLIC_PREFIX_INPUT_JSON".into());
        }
        let bytes = fs::read(Path::new(&args[0]))?;
        let input: PublicInput = serde_json::from_slice(&bytes)?;
        if input.lineage.len() != 14 || input.parents.len() != 1 {
            return Err(
                "this fixed public control runner requires 14 lineage bodies and one parent".into(),
            );
        }
        println!("{}", serde_json::to_string_pretty(&check(&input, &bytes)?)?);
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("public native observation check: {error}");
        std::process::exit(1);
    }
}

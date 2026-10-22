//! Four fixed offline controls over an existing public admission receipt.
//! Test-only adapter: no proof creation, signing, network or production changes.
//! This source must be independently reviewed and separately build-qualified.
use kaspa_consensus::processes::transaction_validator::tx_validation_in_utxo_context::TxValidationFlags;
use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    hashing::{sighash::SigHashReusedValuesUnsync, tx::hash as full_hash},
    mass::Gram,
    tx::{PopulatedTransaction, Transaction, UtxoEntry},
};
use kaspa_txscript::{
    caches::Cache, covenants::CovenantsContext, pay_to_script_hash_script,
    EngineCtx, EngineFlags, SigCacheKey, TxScriptEngine,
};
use kpi_shared_pool::{native, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path, time::Instant};

const FIXTURE: &str = "evidence/2026-10-20-wallet-lifecycle/positive";
const LINEAGE_SHA: &str = "06078979ed5c84cf3234fdfee362b75464701cdb514cf205b7ce808ee0a989c5";
const PARENTS_SHA: &str = "ab5d5e1de6d718dd0d8791cf89251743d1876fba72a958d0eb8082d178637408";
const VK_SHA: &str = "9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef";
const BASELINE_ID: &str = "b2af5cebd66b8e5593af9fe2ce34226b44d52d8ae1f19310690273f1a79e5ca3";
const BASELINE_FULL_HASH: &str = "7717bffe80fd65d1545d7928fa10bf0cab062a2608d7653f14552d716cefffc0";
const FEE: u64 = 40_000_000;
const CASES: [&str; 4] = [
    "genuine-admission-baseline", "funding-signature-attribution",
    "admission-successor-vk", "admission-successor-code",
];

fn require(condition: bool, message: &str) -> Result<()> {
    if condition { Ok(()) } else { Err(message.into()) }
}
fn sha(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn read_pinned(name: &str, expected: &str) -> Result<Vec<u8>> {
    let bytes = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURE).join(name))?;
    require(sha(&bytes) == expected, "public fixture hash mismatch")?;
    Ok(bytes)
}
fn emit(value: Value) -> Result<()> {
    println!("{value}");
    std::io::stdout().flush()?;
    Ok(())
}

// This checks the same populated-transaction prerequisites as native::validate.
// It is NEVER transaction acceptance: actual VM execution follows for both inputs,
// and the unmodified full production validator is run separately for every case.
fn pre_script_gate(tx: &Transaction, entries: &[UtxoEntry]) -> Result<u64> {
    native::metrics(tx, entries)?; // Includes native's private checked_fee guards.
    let validator = native::validator();
    validator.validate_tx_in_isolation(tx)?;
    Ok(validator.validate_populated_transaction_and_get_fee(
        &PopulatedTransaction::new(tx, entries.to_vec()),
        1_000_000_000, 2_000_000_000_000,
        TxValidationFlags::SkipScriptChecks, None, None,
    )?)
}

fn input_vm(tx: &Transaction, entries: &[UtxoEntry], index: usize) -> Result<Value> {
    // Keep the complete original transaction and both UTXOs. Removing the other
    // input would change introspection, covenant context and signature hashing.
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let covenants = CovenantsContext::from_tx(&populated)?;
    let cache: Cache<SigCacheKey, bool> = Cache::new(10);
    let reused = SigHashReusedValuesUnsync::new();
    let context = EngineCtx::new(&cache)
        .with_covenants_ctx(&covenants)
        .with_seq_commit_accessor_opt(None)
        .with_reused(&reused);
    let flags = EngineFlags { sigop_script_units: Gram(TESTNET_PARAMS.mass_per_sig_op).into() };
    let input = tx.inputs.get(index).ok_or("input index")?;
    let entry = entries.get(index).ok_or("UTXO index")?;
    let budget = input.compute_commit.allowed_script_units();
    let mut engine = TxScriptEngine::from_transaction_input_with_script_units_limit(
        &populated, input, index, entry, context, flags, budget,
    );
    let started = Instant::now();
    let result = engine.execute();
    let (accepted, error, variant) = match result {
        Ok(()) => (true, None, None),
        Err(error) => (false, Some(error.to_string()), Some(format!("{error:?}"))),
    };
    Ok(json!({"input_index":index,"accepted":accepted,"error":error,
        "error_variant":variant,"used_script_units":engine.used_script_units().0,
        "allowed_script_units":budget.0,"elapsed_seconds":started.elapsed().as_secs_f64(),
        "context":"full-transaction/full-utxos/CovenantsContext::from_tx",
        "seq_commit_accessor":null,"sigop_script_units":flags.sigop_script_units.0}))
}

fn run() -> Result<()> {
    require(std::env::args_os().len() == 1, "no arguments; fixed public fixture only")?;
    let lineage: Value = serde_json::from_slice(&read_pinned("lineage.json", LINEAGE_SHA)?)?;
    let parents: Value = serde_json::from_slice(&read_pinned("parents.json", PARENTS_SHA)?)?;
    let vk = read_pinned("vk.bin", VK_SHA)?;
    let original_json = lineage.get(2).ok_or("admission fixture index")?;
    let original = native::parse_tx(original_json)?;
    require(original.inputs.len() == 2 && original.outputs.len() == 1, "admission shape")?;
    require(original.id().to_string() == BASELINE_ID, "baseline ID")?;
    require(full_hash(&original).to_string() == BASELINE_FULL_HASH, "baseline native full hash")?;
    require(original.payload.len() == 5228 && original.payload[212] == 0, "admission mode")?;
    require(original.outputs[0].value == 3_120_000_000, "admission reserve value")?;
    let mut utxos = Vec::new();
    let mut entries = Vec::new();
    let ancestry = lineage.as_array().ok_or("lineage array")?.iter()
        .chain(parents.as_array().ok_or("parents array")?.iter());
    let ancestry: Vec<&Value> = ancestry.collect();
    for input in &original.inputs {
        let referenced_id = input.previous_outpoint.transaction_id.to_string();
        let matches: Vec<_> = ancestry.iter()
            .filter(|candidate| candidate["id"].as_str() == Some(referenced_id.as_str())).collect();
        require(matches.len() == 1, "missing or ambiguous public UTXO ancestry")?;
        let parent = native::parse_tx(matches[0])?;
        let index = input.previous_outpoint.index as usize;
        require(index < parent.outputs.len(), "public parent output index")?;
        // Match the existing public offline validator fixture: DAA 0, non-coinbase,
        // no covenant ID. This is not a claim about current chain UTXO state.
        let utxo = native::Utxo::output(&parent, index, 0);
        require(utxo.outpoint()? == input.previous_outpoint, "UTXO/outpoint mismatch")?;
        entries.push(utxo.entry()?);
        utxos.push(utxo);
    }
    let signature = &original.inputs[0].signature_script;
    require(signature.len() == 24709 && signature[..2] == [0x4c, 0x80]
        && signature[130..133] == [0x4d, 0x00, 0x60], "reserve proof/redeem framing")?;
    let redeem = &signature[133..];
    require(redeem.len() == 24576 && redeem[36] == 6 && original.payload[755] == 6,
        "v6 state locations")?;
    let mut successor = redeem[..36].to_vec();
    successor.extend_from_slice(&original.payload[755..860]);
    successor.push(0x75); // OpDrop, exactly as covenant::successor constructs it.
    successor.extend_from_slice(&redeem[142..]);
    require(pay_to_script_hash_script(&successor) == original.outputs[0].script_public_key,
        "reconstructed unchanged successor must match actual native output")?;
    require(vk.len() == 328 && vk[224..232] == 3u64.to_le_bytes()
        && vk[264..296] != vk[296..328], "canonical existing VK layout")?;
    let vk_matches: Vec<usize> = successor.windows(vk.len()).enumerate()
        .filter_map(|(index, window)| (window == vk.as_slice()).then_some(index)).collect();
    require(vk_matches.len() == 1, "unique existing VK in successor")?;
    let vk_offset = vk_matches[0];
    require(successor.ends_with(&[0x61, 0x61]), "successor trailing NOPs")?;
    let funding_signature = &original.inputs[1].signature_script;
    require(funding_signature.len() == 66 && funding_signature[0] == 65
        && funding_signature[65] == 1, "funding signature framing/SIGHASH_ALL")?;

    emit(json!({"record":"plan","schema":"kpi-admission-input-adapter-v1",
        "cases":CASES,"planned_cases":4,"fixtures":{"lineage":LINEAGE_SHA,
        "parents":PARENTS_SHA,"vk":VK_SHA},"baseline_full_hash":BASELINE_FULL_HASH,
        "proofs_generated":0,"chain_acceptance_verified":false,
        "pre_script_gate_is_transaction_acceptance":false}))?;
    for (case_index, name) in CASES.iter().enumerate() {
        let mut tx = original.clone();
        let mut expected_json = original_json.clone();
        let candidate_successor = match case_index {
            0 => None,
            1 => {
                // Change one interior signature byte, not its push or hash-type byte.
                tx.inputs[1].signature_script[32] ^= 1;
                expected_json["inputs"][1]["signatureScript"] = json!(hex::encode(&tx.inputs[1].signature_script));
                None
            }
            2 => {
                // Exchange two original canonical compressed IC points. No new VK
                // or proof is created; only the future redeem commitment changes.
                let mut changed = successor.clone();
                changed[vk_offset + 264..vk_offset + 296].copy_from_slice(&vk[296..328]);
                changed[vk_offset + 296..vk_offset + 328].copy_from_slice(&vk[264..296]);
                Some(changed)
            }
            3 => {
                let mut changed = successor.clone();
                let length = changed.len();
                changed[length - 2..].copy_from_slice(&[0x00, 0x75]); // OpFalse, OpDrop.
                Some(changed)
            }
            _ => unreachable!(),
        };
        if let Some(candidate) = &candidate_successor {
            require(candidate.len() == successor.len() && candidate != &successor,
                "isolated same-length successor change")?;
            tx.outputs[0].script_public_key = pay_to_script_hash_script(candidate);
            require(tx.outputs[0].script_public_key != original.outputs[0].script_public_key,
                "output commitment must change")?;
            expected_json["outputs"][0]["scriptPublicKey"] = json!(hex::encode(native::encode_spk(&tx.outputs[0].script_public_key)));
        }
        tx.finalize();
        let actual_json = native::tx_json(&tx);
        expected_json["id"] = actual_json["id"].clone();
        require(actual_json == expected_json, "mutation changed an unintended native field")?;
        let tx = native::parse_tx(&actual_json)?; // Canonical native bytes/ID prerequisite.
        require(tx.payload == original.payload && tx.inputs[0] == original.inputs[0]
            && tx.storage_mass() == original.storage_mass(), "proof/auth/state/mass preservation")?;

        let full_started = Instant::now();
        let full_result = native::validate(&tx, &entries);
        let full_elapsed = full_started.elapsed().as_secs_f64();
        let full = match full_result {
            Ok(fee) => json!({"accepted":true,"fee_sompi":fee.to_string(),"error":null}),
            Err(error) => json!({"accepted":false,"fee_sompi":null,"error":error.to_string()}),
        };
        let gate = match pre_script_gate(&tx, &entries) {
            Ok(fee) => json!({"passed":true,"fee_sompi":fee.to_string(),"error":null}),
            Err(error) => json!({"passed":false,"fee_sompi":null,"error":error.to_string()}),
        };
        // No VM evidence is credited after a failed pre-script prerequisite.
        let mut inputs = Vec::new();
        if gate["passed"] == true {
            inputs.push(input_vm(&tx, &entries, 0)?);
            inputs.push(input_vm(&tx, &entries, 1)?);
        }
        let prerequisites = gate["passed"] == true && gate["fee_sompi"] == FEE.to_string()
            && inputs.len() == 2;
        let passed = prerequisites && match case_index {
            0 => full["accepted"] == true && full["fee_sompi"] == FEE.to_string()
                && inputs[0]["accepted"] == true && inputs[1]["accepted"] == true,
            1 => full["accepted"] == false && inputs[0]["accepted"] == true
                && inputs[1]["accepted"] == false && inputs[1]["error_variant"] == "EvalFalse",
            2 | 3 => full["accepted"] == false && inputs[0]["accepted"] == false
                && inputs[0]["error_variant"] == "VerifyError"
                && inputs[1]["accepted"] == false && inputs[1]["error_variant"] == "EvalFalse",
            _ => false,
        };
        emit(json!({"record":"case","case":name,"passed":passed,
            "canonical_transaction":actual_json,"utxos":utxos,
            "full_hash":full_hash(&tx).to_string(),"full_native":full,
            "full_native_elapsed_seconds":full_elapsed,"pre_script_gate":gate,
            "pre_script_gate_is_transaction_acceptance":false,"per_input_vm":inputs,
            "proof_sha256":sha(&tx.inputs[0].signature_script[2..130]),
            "authorization_sha256":sha(&tx.payload[8..385]),"payload_sha256":sha(&tx.payload),
            "current_redeem_sha256":sha(redeem),"expected_successor_sha256":sha(&successor),
            "candidate_successor_sha256":candidate_successor.as_ref().map(|bytes| sha(bytes)),
            "only_declared_mutation_verified":true,"proofs_generated":0,
            "chain_acceptance_verified":false}))?;
        require(passed, "unexpected case result; stop without retry or guard-coverage credit")?;
    }
    emit(json!({"record":"summary","complete":true,"passed":true,"executed_cases":4,
        "proofs_generated":0,"chain_acceptance_verified":false}))
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{}", json!({"record":"fatal","complete":false,"error":error.to_string(),
            "retry_attempted":false,"chain_acceptance_verified":false}));
        std::process::exit(1);
    }
}

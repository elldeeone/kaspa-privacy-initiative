//! Fixed public-only budget qualification, independent original UTXO contexts.
//! Proofs, authorization, outputs, signatures and the original fee stay intact.
use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    mass::ScriptUnits,
    tx::{ComputeCommit, PopulatedTransaction, Transaction, UtxoEntry},
};
use kaspa_txscript::runtime_resource_meter::RuntimeResourceMeter;
use kpi_shared_pool::{
    Result, native,
    protocol::hash,
    two_input::{FEE, NOTE_FLOOR, PAYOUT_FLOOR},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, error::Error, fs};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicInput {
    descriptor: Value,
    vk_hex: String,
    lineage: Vec<Value>,
    parents: Vec<Value>,
}

fn same_error<E: Error + PartialEq + 'static>(got: &(dyn Error + 'static), expected: &E) -> bool {
    got.downcast_ref::<E>() == Some(expected)
}

fn same_error_enum<E: Error + 'static>(got: &(dyn Error + 'static), expected: &E) -> bool {
    let _ = expected;
    got.downcast_ref::<E>().is_some()
}

fn underbudget(error: &(dyn Error + 'static), expected_limit: u64) -> Result<Value> {
    let display = error.to_string();
    // Groth16's cost adapter serializes its meter error into ZkIntegrity.
    // Preserve the exact envelope; no other integrity failure may count.
    let (inner, outer_variant) = match display.strip_prefix("ZK Integrity: Kaspa txscript error: ")
    {
        Some(inner) => (inner, "ZkIntegrity"),
        None => (display.as_str(), "ExceededCommittedScriptUnits"),
    };
    let rest = inner
        .strip_prefix("script units exceeded the amount committed in the input: used=")
        .ok_or_else(|| {
            format!("not the expected VM underbudget error: display={display:?}; debug={error:?}")
        })?;
    let (used, limit) = rest
        .split_once(", limit=")
        .ok_or("underbudget error framing")?;
    let (used_n, limit_n) = (used.parse::<u64>()?, limit.parse::<u64>()?);
    if used_n.to_string() != used
        || limit_n.to_string() != limit
        || limit_n != expected_limit
        || used_n <= limit_n
    {
        return Err("underbudget error amount/limit mismatch".into());
    }
    // Type inference retains the concrete public method's error type without a
    // new dependency or naming txscript's private import of TxScriptError.
    let mut meter = RuntimeResourceMeter::new_script_units(ScriptUnits(0), ScriptUnits(limit_n));
    let expected = meter.consume_script_units(ScriptUnits(used_n)).unwrap_err();
    let exact_type_and_value = if outer_variant == "ZkIntegrity" {
        // TxScriptError derives Debug at the pinned commit. The downcast fixes
        // its enum type; exact Debug AND Display fix variant/String payload.
        same_error_enum(error, &expected)
            && format!("{error:?}")
                == format!(
                    "ZkIntegrity({:?})",
                    format!("Kaspa txscript error: {expected}")
                )
            && display == format!("ZK Integrity: Kaspa txscript error: {expected}")
    } else {
        same_error(error, &expected)
    };
    if !exact_type_and_value {
        return Err("underbudget error was not the exact typed VM variant".into());
    }
    Ok(
        json!({"cause_variant":"ExceededCommittedScriptUnits", "outer_variant":outer_variant,
              "typed_outer_match":true,"cause_is_serialized":outer_variant=="ZkIntegrity",
              "inner_message_matches_generated_typed_meter_error":true,
              "attempted_used_units":used_n,"limit_units":limit_n,"display":display}),
    )
}

fn contexts(tx: &Transaction, known: &HashMap<String, Transaction>) -> Result<Vec<UtxoEntry>> {
    tx.inputs
        .iter()
        .map(|input| {
            let parent = known
                .get(&input.previous_outpoint.transaction_id.to_string())
                .ok_or("missing original context parent")?;
            let output = parent
                .outputs
                .get(input.previous_outpoint.index as usize)
                .ok_or("original context output index")?;
            Ok(UtxoEntry::new(
                output.value,
                output.script_public_key.clone(),
                0,
                false,
                None,
            ))
        })
        .collect()
}

fn sighashes(tx: &Transaction, entries: &[UtxoEntry]) -> Vec<String> {
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    (0..tx.inputs.len())
        .map(|i| {
            calc_schnorr_signature_hash(
                &populated,
                i,
                SIG_HASH_ALL,
                &SigHashReusedValuesUnsync::new(),
            )
            .to_string()
        })
        .collect()
}

fn quote(metrics: &Value, original_fee: u64) -> Result<Vec<Value>> {
    let mining = metrics["mining_mass"].as_u64().ok_or("mining mass")?;
    let relay = metrics["relay_mass"].as_u64().ok_or("relay mass")?;
    [100u64, 200, 500].into_iter().map(|rate| {
        let conservative = mining.checked_mul(rate).ok_or("fee quote overflow")?;
        Ok(json!({"sompi_per_gram":rate,"necessary_fee_sompi":conservative.to_string(),
                  "relay_only_fee_sompi":relay.checked_mul(rate).ok_or("relay fee overflow")?.to_string(),
                  "original_fee_covers":original_fee >= conservative,
                  "minimum_note_covers_fee":NOTE_FLOOR >= conservative,
                  "minimum_claim_for_payout_floor_sompi":conservative.checked_add(PAYOUT_FLOOR).ok_or("minimum claim overflow")?.to_string()}))
    }).collect()
}

fn candidate(
    original: &Transaction,
    entries: &[UtxoEntry],
    ordinal: usize,
    budget: u16,
    baseline_units: &[u64],
    expected_pass: bool,
) -> Result<Value> {
    let mut tx = original.clone();
    tx.inputs[0].compute_commit = ComputeCommit::ComputeBudget(budget.into());
    tx.finalize();
    native::set_mass(&tx, entries)?;
    let parsed = native::parse_tx(&native::tx_json(&tx))?;
    if native::tx_json(&parsed) != native::tx_json(&tx) || tx.id() != original.id() {
        return Err("budget-only V1 candidate identity/canonical round trip".into());
    }
    let mut only_budget = native::tx_json(original);
    only_budget["inputs"][0]["computeBudget"] = json!(budget);
    only_budget["storageMass"] = json!(tx.storage_mass().to_string());
    if native::tx_json(&tx) != only_budget
        || sighashes(original, entries) != sighashes(&tx, entries)
    {
        return Err("budget mutation changed authorization/outputs/signatures/SIG_HASH_ALL".into());
    }
    let original_hash = kaspa_consensus_core::hashing::tx::hash(original).to_string();
    let candidate_hash = kaspa_consensus_core::hashing::tx::hash(&tx).to_string();
    if (budget != 3000) != (original_hash != candidate_hash) {
        return Err("full transaction hash budget binding".into());
    }
    let allowed = tx.inputs[0].compute_commit.allowed_script_units().0;
    if allowed != u64::from(budget) * 10_000 + 9_999 {
        return Err("pinned compute-budget conversion changed".into());
    }
    let reserve = native::script_units_at(&tx, entries, 0);
    let vm = match reserve {
        Ok(units) => {
            if !expected_pass || units != baseline_units[0] {
                return Err("unexpected reserve input pass/units".into());
            }
            json!({"passed":true,"used_units":units})
        }
        Err(error) => {
            if expected_pass {
                return Err(format!("expected reserve pass: {error}").into());
            }
            json!({"passed":false,"error":underbudget(error.as_ref(), allowed)?})
        }
    };
    let full = native::validate(&tx, entries);
    let full_result = match full {
        Ok(fee) => {
            if !expected_pass || fee != FEE {
                return Err("unexpected full-native pass/fee".into());
            }
            let units = (0..tx.inputs.len())
                .map(|i| native::script_units_at(&tx, entries, i))
                .collect::<Result<Vec<_>>>()?;
            if units != baseline_units {
                return Err("budget mutation changed per-input VM units".into());
            }
            native::policy(&tx, entries)?;
            json!({"passed":true,"fee_sompi":fee.to_string(),"per_input_units":units})
        }
        Err(error) => {
            let message = error.to_string();
            if expected_pass
                || !message.contains("script units exceeded the amount committed in the input:")
            {
                return Err(format!("wrong full-native rejection: {message}").into());
            }
            json!({"passed":false,"error":message,"stage":"native script-unit rejection; canonical parser already passed"})
        }
    };
    let metrics = native::metrics(&tx, entries)?;
    Ok(
        json!({"ordinal":ordinal,"mode":original.payload[212],"reserve_budget":budget,
              "allowed_reserve_units":allowed,"expected_pass":expected_pass,
              "original_transaction_id":original.id().to_string(),"candidate_transaction_id":tx.id().to_string(),
              "original_full_hash":original_hash,"candidate_full_hash":candidate_hash,
              "transaction_id_unchanged":true,"sig_hash_all_unchanged":true,
              "proof_authorization_ciphertexts_outputs_signatures_unchanged":true,
              "original_fee_sompi":FEE.to_string(),"reserve_input":vm,"full_native":full_result,
              "metrics":metrics,"fee_quotes":quote(&metrics,FEE)?,
              "context":"the original legitimate public UTXO entries; no mutated descendant reused"}),
    )
}

fn run(bytes: &[u8]) -> Result<Value> {
    let input: PublicInput = serde_json::from_slice(bytes)?;
    if input.lineage.len() != 14
        || input.parents.len() != 1
        || input.vk_hex.len() != 656
        || input.descriptor["network"] != "testnet-10"
    {
        return Err("fixed public input scope".into());
    }
    let mut known = HashMap::new();
    for body in input.parents.iter().chain(&input.lineage) {
        let tx = native::parse_tx(body)?;
        if known.insert(tx.id().to_string(), tx).is_some() {
            return Err("duplicate public transaction identity".into());
        }
    }
    // Classifier controls: a similarly worded infrastructure error or unrelated
    // proof-integrity error must never satisfy the budget stop condition.
    let mut tiny = RuntimeResourceMeter::new_script_units(ScriptUnits(0), ScriptUnits(5));
    let direct = tiny.consume_script_units(ScriptUnits(6)).unwrap_err();
    underbudget(&direct, 5)?;
    if underbudget(&direct, 4).is_ok()
        || underbudget(&std::io::Error::other(direct.to_string()), 5).is_ok()
    {
        return Err("underbudget classifier accepted a wrong limit/type".into());
    }
    let mut bad_proof = native::parse_tx(&input.lineage[1])?;
    let entries = contexts(&bad_proof, &known)?;
    bad_proof.inputs[0].signature_script[2] ^= 1;
    bad_proof.finalize();
    let unrelated = native::script_units_at(&bad_proof, &entries, 0)
        .err()
        .ok_or("classifier bad-proof control unexpectedly accepted")?;
    if underbudget(unrelated.as_ref(), 30_009_999).is_ok() {
        return Err("underbudget classifier accepted an unrelated proof failure".into());
    }
    let mut baselines = Vec::new();
    let mut reduced = Vec::new();
    let mut focused = Vec::new();
    let mut first_ordinary = None;
    for (ordinal, body) in input.lineage.iter().skip(1).enumerate() {
        let tx = native::parse_tx(body)?;
        let entries = contexts(&tx, &known)?;
        if tx.inputs[0].compute_commit.compute_budget() != Some(3000)
            || native::validate(&tx, &entries)? != FEE
        {
            return Err("original budget/fee/native baseline".into());
        }
        let units = (0..tx.inputs.len())
            .map(|i| native::script_units_at(&tx, &entries, i))
            .collect::<Result<Vec<_>>>()?;
        let baseline = candidate(&tx, &entries, ordinal, 3000, &units, true)?;
        let low = candidate(&tx, &entries, ordinal, 1600, &units, true)?;
        if ordinal == 0 {
            if units[0] / 10_000 != 1497 {
                return Err("frozen bootstrap boundary prediction failed".into());
            }
            for budget in [1500u16, 1497, 1496, 1474] {
                focused.push(candidate(
                    &tx,
                    &entries,
                    ordinal,
                    budget,
                    &units,
                    budget >= 1497,
                )?);
            }
        }
        if first_ordinary.is_none()
            && tx.payload[212] == 1
            && tx.payload[8 + 337..8 + 345] == [0; 8]
        {
            first_ordinary = Some(ordinal);
            if units[0] / 10_000 != 1496 {
                return Err("frozen ordinary SPEND boundary prediction failed".into());
            }
            for budget in [1500u16, 1497, 1496, 1495, 1474] {
                focused.push(candidate(
                    &tx,
                    &entries,
                    ordinal,
                    budget,
                    &units,
                    budget >= 1496,
                )?);
            }
        }
        baselines.push(baseline);
        reduced.push(low);
    }
    if first_ordinary != Some(4) {
        return Err("first ordinary public SPEND identity changed".into());
    }
    let maximum = reduced
        .iter()
        .map(|r| r["metrics"]["mining_mass"].as_u64().unwrap())
        .max()
        .unwrap();
    Ok(
        json!({"schema":"kpi-public-native-budget-screen-v1","passed":true,
              "input_sha256":hex::encode(hash(bytes)),"native_dependency":"01b532e8b553523216471682649693af92f0fd16",
              "baseline_budget":3000,"candidate_budget":1600,"original_fee_sompi":FEE.to_string(),
              "baselines":baselines,"candidate1600":reduced,"focused_boundaries":focused,
              "classifier_controls":["typed_direct_underbudget","wrong_limit_rejected",
                                      "same_display_wrong_type_rejected","unrelated_proof_integrity_rejected"],
              "summary":{"full_native_originals":13,"full_native_1600":13,"focused_cases":9,
                         "maximum_candidate_mining_mass":maximum,
                         "maximum_2x_necessary_fee_sompi":(maximum*200).to_string(),
                         "maximum_5x_necessary_fee_sompi":(maximum*500).to_string(),
                         "original_fee_covers_all_2x":maximum*200<=FEE,
                         "minimum_note_sompi":NOTE_FLOOR.to_string(),
                         "payout_floor_sompi":PAYOUT_FLOOR.to_string(),
                         "minimum_note_covers_worst_5x_fee":NOTE_FLOOR>=maximum*500,
                         "minimum_claim_for_worst_5x_payout_floor_sompi":(maximum*500+PAYOUT_FLOOR).to_string()},
              "scope":"fixed genuine public transactions in isolated original contexts; no default, fee, proof or output changes",
              "limits":["no fresh proof or broadcast","no general worst-case VM/path qualification",
                        "fee-rate stresses are conservative mining-mass quotes, not modified-fee proof executions",
                        "chain acceptance and funding-parent ancestry remain external"]}),
    )
}

fn main() {
    let result = (|| -> Result<()> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        if args.len() != 1 {
            return Err("PUBLIC_INPUT_JSON".into());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&run(&fs::read(&args[0])?)?)?
        );
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("native budget screen: {error}");
        std::process::exit(1);
    }
}

//! Actual v6 factory/default adoption regression using only retained public data.
//! No new setup/proof, private input, key, RPC, funding or broadcast.
use kaspa_consensus_core::{
    hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
    hashing::sighash_type::SIG_HASH_ALL,
    mass::ScriptUnits,
    tx::{ComputeCommit, PopulatedTransaction, Transaction, UtxoEntry},
};
use kaspa_txscript::runtime_resource_meter::RuntimeResourceMeter;
use kpi_shared_pool::{
    Result, native,
    protocol::hash,
    two_input::{
        self, Bundle, P_AUTH, P_CIPHER, P_STATE,
        replay::{self, Descriptor},
        tree::PublicState,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, error::Error, fs};

const INPUT_SHA: &str = "7fd8bd70774872a1748fb52d32754556e578f8abf89c76100e28e1fd315b02a1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    descriptor: Descriptor,
    vk_hex: String,
    lineage: Vec<Value>,
    parents: Vec<Value>,
}

fn bundle(tx: &Transaction) -> Result<Bundle> {
    if tx.payload.len() != two_input::PAYLOAD_SIZE
        || tx.inputs[0].signature_script.len() != two_input::covenant::WITNESS_LEN
        || tx.inputs[0].signature_script[..2] != [0x4c, 128]
    {
        return Err("genuine public bundle framing".into());
    }
    Ok(Bundle {
        authorization: hex::encode(&tx.payload[P_AUTH..P_CIPHER]),
        proof: hex::encode(&tx.inputs[0].signature_script[2..130]),
        ciphertexts: [
            hex::encode(&tx.payload[P_CIPHER..P_CIPHER + 185]),
            hex::encode(&tx.payload[P_CIPHER + 185..P_STATE]),
        ],
    })
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

fn same_error_enum<E: Error + 'static>(got: &(dyn Error + 'static), _: &E) -> bool {
    got.downcast_ref::<E>().is_some()
}

fn underbudget(error: &(dyn Error + 'static), limit: u64) -> Result<Value> {
    let display = error.to_string();
    let inner = display
        .strip_prefix("ZK Integrity: Kaspa txscript error: ")
        .ok_or("expected typed Groth16 meter envelope")?;
    let rest = inner
        .strip_prefix("script units exceeded the amount committed in the input: used=")
        .ok_or("expected meter cause")?;
    let (used, actual) = rest.split_once(", limit=").ok_or("meter message framing")?;
    let used: u64 = used.parse()?;
    let actual: u64 = actual.parse()?;
    if actual != limit || used <= limit {
        return Err("meter cause limit/used mismatch".into());
    }
    let mut meter = RuntimeResourceMeter::new_script_units(ScriptUnits(0), ScriptUnits(limit));
    let expected = meter.consume_script_units(ScriptUnits(used)).unwrap_err();
    if !same_error_enum(error, &expected)
        || format!("{error:?}")
            != format!(
                "ZkIntegrity({:?})",
                format!("Kaspa txscript error: {expected}")
            )
        || display != format!("ZK Integrity: Kaspa txscript error: {expected}")
    {
        return Err("wrong typed native underbudget cause".into());
    }
    Ok(
        json!({"typed_outer_variant":"ZkIntegrity","serialized_inner_variant":"ExceededCommittedScriptUnits",
        "used_units":used,"limit_units":limit,"display":display}),
    )
}

fn replay_body(input: &Input, vk: &[u8], lineage: &[Value]) -> Result<replay::Replay> {
    replay::replay(&input.descriptor, vk, lineage, &input.parents)
}

fn rejected(input: &Input, vk: &[u8], lineage: &[Value], name: &str, exact: &str) -> Result<Value> {
    let error = replay_body(input, vk, lineage)
        .err()
        .ok_or_else(|| format!("{name} unexpectedly replayed"))?
        .to_string();
    if error != exact {
        return Err(format!("{name}: expected exact {exact:?}, got {error:?}").into());
    }
    Ok(json!({"name":name,"rejected":true,"error":error}))
}

fn mutate_last(input: &[Value], f: impl FnOnce(&mut Transaction)) -> Result<Vec<Value>> {
    let mut result = input.to_vec();
    let mut tx = native::parse_tx(result.last().ok_or("empty control lineage")?)?;
    f(&mut tx);
    tx.finalize();
    *result.last_mut().ok_or("empty control lineage")? = native::tx_json(&tx);
    Ok(result)
}

fn run(bytes: &[u8]) -> Result<Value> {
    if hex::encode(hash(bytes)) != INPUT_SHA {
        return Err("allowlisted public input SHA".into());
    }
    let input: Input = serde_json::from_slice(bytes)?;
    if input.lineage.len() != 14
        || input.parents.len() != 1
        || two_input::covenant::BUDGET != 1600
        || kpi_shared_pool::covenant::BUDGET != 1600
        || kpi_shared_pool::compact::covenant::BUDGET != 2000
        || kpi_shared_pool::compact::deposits::covenant::BUDGET != 2000
        || kpi_shared_pool::anchored::covenant::BUDGET != 2000
    {
        return Err("fixed input/default scope or unrelated-version budget changed".into());
    }
    let vk = hex::decode(&input.vk_hex)?;
    let historical = replay_body(&input, &vk, &input.lineage)?;
    let mut known = HashMap::new();
    for body in input.parents.iter().chain(&input.lineage) {
        let tx = native::parse_tx(body)?;
        if known.insert(tx.id().to_string(), tx).is_some() {
            return Err("duplicate retained transaction".into());
        }
    }
    let mut state = PublicState::initial(input.descriptor.initial_commitment)?;
    let mut lineage = vec![input.lineage[0].clone()];
    let mut cases = Vec::new();
    let mut case_entries = Vec::new();
    for (ordinal, body) in input.lineage.iter().skip(1).enumerate() {
        let original = native::parse_tx(body)?;
        if original.inputs[0].compute_commit.compute_budget() != Some(3000) {
            return Err("historical3000 fixture changed".into());
        }
        let b = bundle(&original)?;
        let a = b.auth()?;
        let point = &original.inputs[0].previous_outpoint;
        let parent = known
            .get(&point.transaction_id.to_string())
            .ok_or("missing original reserve parent")?;
        let u = native::Utxo::output(parent, point.index as usize, 0);
        let external = if a.mode == 0 {
            let point = &original.inputs[1].previous_outpoint;
            Some(native::Utxo::output(
                known
                    .get(&point.transaction_id.to_string())
                    .ok_or("missing genuine public funding parent")?,
                point.index as usize,
                0,
            ))
        } else {
            None
        };
        let (mut factory, entries, next) = two_input::settle(
            &input.descriptor.domain,
            &state,
            &u,
            &vk,
            &b,
            external.as_ref(),
        )?;
        if external.is_some() {
            factory.inputs[1].signature_script = original.inputs[1].signature_script.clone();
        }
        factory.finalize();
        native::set_mass(&factory, &entries)?;
        if factory.inputs[0].compute_commit.compute_budget() != Some(1600) {
            return Err("factory did not select1600".into());
        }
        let original_json = native::tx_json(&original);
        let factory_json = native::tx_json(&factory);
        let mut expected = original_json.clone();
        expected["inputs"][0]["computeBudget"] = json!(1600);
        let original_full_hash = kaspa_consensus_core::hashing::tx::hash(&original).to_string();
        let factory_full_hash = kaspa_consensus_core::hashing::tx::hash(&factory).to_string();
        if factory.storage_mass() != original.storage_mass()
            || factory_json != expected
            || factory.id() != original.id()
            || original_full_hash == factory_full_hash
            || sighashes(&factory, &entries) != sighashes(&original, &entries)
            || original.inputs[0].signature_script != factory.inputs[0].signature_script
        {
            return Err("factory changed storage mass or a field other than reserve budget, identity, scripts, or SIG_HASH_ALL".into());
        }
        let parsed = native::parse_tx(&factory_json)?;
        if native::tx_json(&parsed) != factory_json
            || native::validate(&factory, &entries)? != a.fee
            || native::validate(&original, &entries)? != a.fee
        {
            return Err("factory/original native validation or roundtrip".into());
        }
        native::policy(&factory, &entries)?;
        native::policy(&original, &entries)?;
        let old_units = (0..original.inputs.len())
            .map(|i| native::script_units_at(&original, &entries, i))
            .collect::<Result<Vec<_>>>()?;
        let new_units = (0..factory.inputs.len())
            .map(|i| native::script_units_at(&factory, &entries, i))
            .collect::<Result<Vec<_>>>()?;
        if old_units != new_units {
            return Err("factory budget changed actual script units".into());
        }
        cases.push(json!({"ordinal":ordinal,"mode":a.mode,"factory_budget":1600,"historical_budget":3000,
            "transaction_id":original.id().to_string(),"historical_full_hash":original_full_hash,"factory_full_hash":factory_full_hash,
            "historical_sig_hash_all":sighashes(&original,&entries),"factory_sig_hash_all":sighashes(&factory,&entries),
            "redeem_script_sha256":hex::encode(hash(&original.inputs[0].signature_script[133..])),
            "reserve_spk_hex":hex::encode(native::encode_spk(&entries[0].script_public_key)),
            "full_native_historical":true,"full_native_factory":true,"native_policy_historical":true,"native_policy_factory":true,
            "all_other_fields_exact":true,"per_input_units":new_units,"factory_transaction":factory_json,
            "factory_metrics":native::metrics(&factory,&entries)?}));
        lineage.push(factory_json);
        case_entries.push(entries);
        state = next;
    }
    let current = replay_body(&input, &vk, &lineage)?;
    if serde_json::to_value(&historical.state)? != serde_json::to_value(&current.state)?
        || serde_json::to_value(&historical.accounting)?
            != serde_json::to_value(&current.accounting)?
        || serde_json::to_value(&state)? != serde_json::to_value(&current.state)?
        || historical.chain_acceptance_verified
        || current.chain_acceptance_verified
    {
        return Err("historical/factory replay state/accounting mismatch or chain claim".into());
    }
    let mut controls = Vec::new();
    // First bootstrap proof reaches the actual Groth16 meter before its fixed
    // cost can fit. Confirm precise typed cause directly and through replay.
    let mut low = native::parse_tx(&lineage[1])?;
    low.inputs[0].compute_commit = ComputeCommit::ComputeBudget(1474u16.into());
    low.finalize();
    native::set_mass(&low, &case_entries[0])?;
    let error = native::script_units_at(&low, &case_entries[0], 0)
        .err()
        .ok_or("underbudget native control accepted")?;
    let meter = underbudget(error.as_ref(), 14_749_999)?;
    let low_lineage = vec![lineage[0].clone(), native::tx_json(&low)];
    let expected =
        format!("pool native validation: failed to verify the signature script: {error}");
    let mut low_result = rejected(
        &input,
        &vk,
        &low_lineage,
        "underbudget_native_rejection",
        &expected,
    )?;
    low_result["typed_meter_cause"] = meter;
    controls.push(low_result);
    let prefix = &lineage[..6]; // Founding plus operations0..4; mutate only last.
    let bad = mutate_last(prefix, |tx| tx.payload[P_AUTH + 213] ^= 1)?;
    controls.push(rejected(
        &input,
        &vk,
        &bad,
        "unexpected_fee",
        "public state/transaction reconstruction mismatch",
    )?);
    let bad = mutate_last(prefix, |tx| tx.outputs[0].value -= 1)?;
    controls.push(rejected(
        &input,
        &vk,
        &bad,
        "unexpected_output",
        "public state/transaction reconstruction mismatch",
    )?);
    let other = native::parse_tx(&lineage[6])?;
    let bad = mutate_last(prefix, |tx| {
        tx.inputs[0].signature_script[2..130]
            .copy_from_slice(&other.inputs[0].signature_script[2..130])
    })?;
    controls.push(rejected(&input,&vk,&bad,"wrong_genuine_proof","pool native validation: failed to verify the signature script: ZK Integrity: Groth16 verification failed")?);
    let mut excessive = native::parse_tx(&lineage[1])?;
    excessive.inputs[0].compute_commit = ComputeCommit::ComputeBudget(65535u16.into());
    excessive.finalize();
    native::set_mass(&excessive, &case_entries[0])?;
    // Separate a genuine predicate pass from transaction admission policy.
    native::script_units_at(&excessive, &case_entries[0], 0)?;
    let excessive = vec![lineage[0].clone(), native::tx_json(&excessive)];
    controls.push(rejected(
        &input,
        &vk,
        &excessive,
        "excessive_budget_mass",
        "pool native mass: native block mass limit",
    )?);
    Ok(
        json!({"schema":"kpi-v6-budget-adoption-v1","passed":true,"input_sha256":INPUT_SHA,
        "factory_default_budget":two_input::covenant::BUDGET,"historical_retained_budget":3000,
        "case_count":cases.len(),"historical_replay_passed":true,"factory_replay_passed":true,
        "replay_preserves_declared_v1_budget":true,"full_native_validation_mandatory":true,
        "replay_native_mass_limits_mandatory":true,"factory_policy_checks_passed":true,
        "same_final_public_state":true,"same_integer_accounting":true,"chain_acceptance_verified":false,
        "other_version_budgets_unchanged":true,"cases":cases,"controls":controls,
        "historical_summary":historical.summary()?,"factory_summary":current.summary()?,
        "limits":["unchanged public rehearsal proof instances, not a worst-case or cryptographic correctness proof",
                  "no real funds, new setup/proof, private input, RPC or broadcast",
                  "mass/fee improvement does not fix singleton minimum-note exit at500sompi/gram"]}),
    )
}

fn main() {
    let result = (|| -> Result<()> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        if args.len() != 1 {
            return Err("PUBLIC_REHEARSAL_INPUT_JSON".into());
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&run(&fs::read(&args[0])?)?)?
        );
        Ok(())
    })();
    if let Err(error) = result {
        eprintln!("v6 budget adoption: {error}");
        std::process::exit(1);
    }
}

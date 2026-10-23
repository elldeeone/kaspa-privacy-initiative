//! Selected official native01 Full validation; raw-byte bridge from upstream API.
use crate::Result;
use kaspa_consensus::processes::transaction_validator::{
    TransactionValidator, tx_validation_in_utxo_context::TxValidationFlags,
};
use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    mass::{MassCalculator, transaction_estimated_serialized_size},
    tx::{PopulatedTransaction, Transaction, UtxoEntry},
};
use kaspa_txscript::{
    EngineCtx, EngineFlags, SigCacheKey, TxScriptEngine,
    caches::{Cache, TxScriptCacheCounters},
    covenants::CovenantsContext,
    script_class::ScriptClass,
};
use serde_json::{Value, json};
use std::sync::Arc;

pub fn calculator() -> MassCalculator {
    MassCalculator::new_with_consensus_params(&TESTNET_PARAMS)
}
pub fn set_mass(tx: &Transaction, entries: &[UtxoEntry]) -> Result<()> {
    let m = calculator()
        .calc_contextual_masses(&PopulatedTransaction::new(tx, entries.to_vec()))
        .ok_or("undefined contextual mass")?;
    tx.set_storage_mass(m.storage_mass);
    Ok(())
}
pub fn amounts(tx: &Transaction, entries: &[UtxoEntry]) -> Result<(u64, u64, u64)> {
    let ins = entries
        .iter()
        .try_fold(0u64, |s, e| s.checked_add(e.amount))
        .ok_or("input sum overflow")?;
    let outs = tx
        .outputs
        .iter()
        .try_fold(0u64, |s, o| s.checked_add(o.value))
        .ok_or("output sum overflow")?;
    Ok((
        ins,
        outs,
        ins.checked_sub(outs).ok_or("outputs exceed inputs")?,
    ))
}
pub fn metrics(tx: &Transaction, entries: &[UtxoEntry]) -> Result<Value> {
    let n = calculator().calc_non_contextual_masses(tx);
    let c = calculator()
        .calc_contextual_masses(&PopulatedTransaction::new(tx, entries.to_vec()))
        .ok_or("undefined mass")?;
    let relay = n.compute_mass.max(n.transient_mass.div_ceil(2));
    let mining = relay.max(c.storage_mass);
    let (ins, outs, fee) = amounts(tx, entries)?;
    let standard = entries
        .iter()
        .map(|e| &e.script_public_key)
        .chain(tx.outputs.iter().map(|o| &o.script_public_key))
        .all(|s| s.version() == 0 && ScriptClass::from_script(s) != ScriptClass::NonStandard);
    let sigops: Vec<_> = tx
        .inputs
        .iter()
        .zip(entries)
        .map(|(i, e)| kaspa_txscript::p2sh_sig_scanner(&i.signature_script, &e.script_public_key))
        .collect();
    Ok(
        json!({"estimated_bytes":transaction_estimated_serialized_size(tx),"compute_mass":n.compute_mass,"transient_mass":n.transient_mass,"storage_mass":c.storage_mass,"relay_noncontextual_mass":relay,"mining_mass":mining,"input_sum_sompi":ins,"output_sum_sompi":outs,"actual_fee_sompi":fee,"source_adapted_standardness":standard&&sigops.iter().all(|x|*x<=15),"sigops_scanner":sigops,"source_adapted_native_dimensions":n.compute_mass<=500_000&&n.transient_mass<=1_000_000&&c.storage_mass<=500_000,"default_relay_floor_sompi":relay.checked_mul(100).ok_or("relay overflow")?,"actual_relay_admission":false,"inclusion":false}),
    )
}
pub fn full(tx: &Transaction, entries: &[UtxoEntry]) -> Value {
    let p = TESTNET_PARAMS;
    let v = TransactionValidator::new(
        p.max_tx_inputs,
        p.max_tx_outputs,
        p.max_signature_script_len,
        p.max_script_public_key_len,
        p.coinbase_payload_script_public_key_max_len,
        p.coinbase_maturity(),
        p.ghostdag_k(),
        Arc::new(TxScriptCacheCounters::default()),
        calculator(),
        p.mass_per_sig_op,
    );
    if let Err(e) = v.validate_tx_in_isolation(tx) {
        return json!({"accepted":false,"stage":"Isolation","error":format!("{e:?}")});
    }
    match v.validate_populated_transaction_and_get_fee(
        &PopulatedTransaction::new(tx, entries.to_vec()),
        1_000_000_000,
        2_000_000_000_000,
        TxValidationFlags::Full,
        None,
        None,
    ) {
        Ok(f) => json!({"accepted":true,"stage":"Full","fee_sompi":f}),
        Err(e) => json!({"accepted":false,"stage":"Full","error":format!("{e:?}")}),
    }
}
pub fn meter(tx: &Transaction, entries: &[UtxoEntry]) -> Value {
    let pop = PopulatedTransaction::new(tx, entries.to_vec());
    let cov = match CovenantsContext::from_tx(&pop) {
        Ok(c) => c,
        Err(e) => return json!({"context_error":format!("{e:?}")}),
    };
    let rows:Vec<_>=tx.inputs.iter().zip(entries).enumerate().map(|(index,(input,entry))|{
 let cache:Cache<SigCacheKey,bool>=Cache::new(32);let reused=kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync::new();
 // Native01 has always-post-Toccata semantics; upstream9fdb comparison uses covenants_enabled=true.
 let mut vm=TxScriptEngine::from_transaction_input_with_script_units_limit(&pop,input,index,entry,EngineCtx::new(&cache).with_reused(&reused).with_covenants_ctx(&cov),EngineFlags::default(),input.compute_commit.allowed_script_units());
 let result=vm.execute();json!({"input":index,"accepted":result.is_ok(),"error":result.err().map(|e|format!("{e:?}")),"script_units":vm.used_script_units().0,"minimum_covering_budget_for_observed_units":vm.used_script_units().0/10_000,"committed_budget":input.compute_commit.compute_budget(),"allowed_script_units":input.compute_commit.allowed_script_units().0})}).collect();
    json!(rows)
}

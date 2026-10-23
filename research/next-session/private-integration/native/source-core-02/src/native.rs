//! Raw official native APIs, supplied contexts only. No wallet/prover subsystem.
use crate::policy::{self, Result};
use kaspa_consensus::processes::transaction_validator::{
    TransactionValidator, tx_validation_in_utxo_context::TxValidationFlags,
};
use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SigHashType,
    },
    mass::{Mass, MassCalculator, transaction_estimated_serialized_size},
    tx::{
        PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_txscript::{
    EngineCtx, SigCacheKey, TxScriptEngine,
    caches::{Cache, TxScriptCacheCounters},
    pay_to_script_hash_script,
    script_class::ScriptClass,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PrivateVector {
    pub auth_hex: String,
    pub cipher_hex: String,
    pub public_witness_hex: String,
    pub proof_hex: String,
    pub vk_hex: String,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RevealVector {
    pub state_hex: String,
    pub previous_txid_raw_hex: String,
    pub previous_index: u32,
    pub reserve_sompi: u64,
    pub payload_hex: String,
    pub native_secret_hex: String,
    pub vk_hex: String,
}
pub fn exact<const N: usize>(h: &str) -> Result<[u8; N]> {
    hex::decode(h)?
        .try_into()
        .map_err(|_| format!("expected{N} bytes").into())
}
fn n(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
pub fn p2pk(pk: &[u8; 32]) -> ScriptPublicKey {
    ScriptPublicKey::from_vec(0, [vec![32], pk.to_vec(), vec![0xac]].concat())
}
fn tx(
    previous: [u8; 32],
    index: u32,
    outputs: Vec<TransactionOutput>,
    payload: Vec<u8>,
    witness: Vec<u8>,
    budget: u16,
) -> Transaction {
    Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(kaspa_hashes::Hash::from_bytes(previous), index),
            witness,
            u64::MAX,
            budget,
        )],
        outputs,
        0,
        Default::default(),
        0,
        payload,
    )
}
pub fn set_mass(tx: &Transaction, e: &[UtxoEntry]) -> Result<()> {
    let m = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS)
        .calc_contextual_masses(&PopulatedTransaction::new(tx, e.to_vec()))
        .ok_or("undefined storage mass")?;
    tx.set_storage_mass(m.storage_mass);
    Ok(())
}
pub fn private_body(v: &PrivateVector) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let a = exact::<484>(&v.auth_hex)?;
    let vk = exact::<328>(&v.vk_hex)?;
    let proof = exact::<128>(&v.proof_hex)?;
    let cipher = exact::<528>(&v.cipher_hex)?;
    let w = exact::<3344>(&v.public_witness_hex)?;
    if &a[..8] != policy::AUTH_MAGIC || a[8..40] != policy::DOMAIN {
        return Err("private Auth magic/domain".into());
    }
    let old: [u8; 112] = a[76..188].try_into()?;
    let next: [u8; 112] = a[364..476].try_into()?;
    let redeem = policy::redeem(&old, &vk)?;
    let successor = policy::redeem(&next, &vk)?;
    let entry = UtxoEntry::new(
        n(&a, 188),
        pay_to_script_hash_script(&redeem),
        0,
        false,
        None,
    );
    let payload = [a.as_slice(), cipher.as_slice(), w.as_slice()].concat();
    let body = tx(
        a[40..72].try_into()?,
        u32::from_le_bytes(a[72..76].try_into()?),
        vec![TransactionOutput::new(
            n(&a, 476),
            pay_to_script_hash_script(&successor),
        )],
        payload,
        policy::witness(&[0; 65], &proof, &redeem)?,
        policy::PRIVATE_BUDGET,
    );
    let entries = vec![entry];
    set_mass(&body, &entries)?;
    Ok((body, entries))
}
pub fn reveal_body(v: &RevealVector) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let old = exact::<112>(&v.state_hex)?;
    let vk = exact::<328>(&v.vk_hex)?;
    let p = exact::<2029>(&v.payload_hex)?;
    if &p[..8] != policy::REVEAL_MAGIC || p[8] != 1 {
        return Err("new reveal magic/mode".into());
    }
    let secret = exact::<32>(&v.native_secret_hex)?;
    let native_key = secp256k1::SecretKey::from_slice(&secret)?;
    let secp = secp256k1::Secp256k1::new();
    let kp = secp256k1::Keypair::from_secret_key(&secp, &native_key);
    let pk = kp.x_only_public_key().0.serialize();
    if p[145..177] != pk {
        return Err("public development key does not match CM-bound nativePK".into());
    }
    let redeem = policy::redeem(&old, &vk)?;
    let principal = n(&p, 73);
    let payout = n(&p, 2021);
    let reserve = v.reserve_sompi;
    let remainder = reserve
        .checked_sub(principal)
        .ok_or("reserve below note principal")?;
    let mut outputs = vec![];
    if remainder > 0 {
        let mut next = old;
        next[76..108].copy_from_slice(&p[1981..2013]);
        let m = u32::from_le_bytes(old[108..112].try_into()?)
            .checked_add(1)
            .ok_or("NF count overflow")?;
        next[108..112].copy_from_slice(&m.to_le_bytes());
        outputs.push(TransactionOutput::new(
            remainder,
            pay_to_script_hash_script(&policy::redeem(&next, &vk)?),
        ))
    }
    outputs.push(TransactionOutput::new(payout, p2pk(&pk)));
    let mut body = tx(
        exact::<32>(&v.previous_txid_raw_hex)?,
        v.previous_index,
        outputs,
        p.to_vec(),
        policy::witness(&[0; 65], &[0; 128], &redeem)?,
        policy::REVEAL_BUDGET,
    );
    let entries = vec![UtxoEntry::new(
        reserve,
        pay_to_script_hash_script(&redeem),
        0,
        false,
        None,
    )];
    set_mass(&body, &entries)?;
    let digest = calc_schnorr_signature_hash(
        &PopulatedTransaction::new(&body, entries.clone()),
        0,
        SigHashType::from_u8(1)?,
        &SigHashReusedValuesUnsync::new(),
    );
    let sig = secp.sign_schnorr_no_aux_rand(
        &secp256k1::Message::from_digest_slice(&digest.as_bytes())?,
        &kp,
    );
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(sig.as_ref());
    bytes[64] = 1;
    body.inputs[0].signature_script = policy::witness(&bytes, &[0; 128], &redeem)?;
    body.finalize();
    set_mass(&body, &entries)?;
    Ok((body, entries))
}
fn validator() -> TransactionValidator {
    let p = TESTNET_PARAMS;
    TransactionValidator::new(
        p.max_tx_inputs,
        p.max_tx_outputs,
        p.max_signature_script_len,
        p.max_script_public_key_len,
        p.coinbase_payload_script_public_key_max_len,
        p.coinbase_maturity(),
        p.ghostdag_k(),
        Arc::new(TxScriptCacheCounters::default()),
        MassCalculator::new_with_consensus_params(&p),
        p.mass_per_sig_op,
    )
}
pub fn execute(tx: &Transaction, e: &[UtxoEntry]) -> Value {
    let v = validator();
    let iso = v.validate_tx_in_isolation(tx);
    let p = PopulatedTransaction::new(tx, e.to_vec());
    let full = if iso.is_ok() {
        v.validate_populated_transaction_and_get_fee(
            &p,
            1_000_000_000,
            2_000_000_000_000,
            TxValidationFlags::Full,
            None,
            None,
        )
        .map_err(|e| format!("{e:?}"))
    } else {
        Err(format!("isolation:{:?}", iso.as_ref().err()))
    };
    let cache: Cache<SigCacheKey, bool> = Cache::new(10);
    let reused = SigHashReusedValuesUnsync::new();
    let mut engine = TxScriptEngine::from_transaction_input_with_script_units_limit(
        &p,
        &tx.inputs[0],
        0,
        &e[0],
        EngineCtx::new(&cache).with_reused(&reused),
        Default::default(),
        tx.inputs[0].compute_commit.allowed_script_units(),
    );
    let vm = engine.execute();
    json!({"isolation":iso.map(|_|"PASS".to_string()).unwrap_or_else(|e|format!("{e:?}")),"Full":match full{Ok(f)=>json!({"accepted":true,"fee_sompi":f}),Err(e)=>json!({"accepted":false,"typed_error":e})},"ScriptEngine":match vm{Ok(_)=>json!({"accepted":true,"units":engine.used_script_units().0}),Err(e)=>json!({"accepted":false,"typed_error":format!("{e:?}"),"units":engine.used_script_units().0})},"allowed_script_units":tx.inputs[0].compute_commit.allowed_script_units().0})
}
pub fn metrics(tx: &Transaction, e: &[UtxoEntry]) -> Result<Value> {
    let c = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let nc = c.calc_non_contextual_masses(tx);
    let ctx = c
        .calc_contextual_masses(&PopulatedTransaction::new(tx, e.to_vec()))
        .ok_or("undefined storage mass")?;
    let factors = TESTNET_PARAMS.block_mass_limits.cofactors();
    let relay = nc.normalized_max(&factors);
    let mining = Mass::new(nc, ctx).normalized_max(&factors);
    let inputs = e.iter().try_fold(0u64, |s, u| {
        s.checked_add(u.amount).ok_or("input sum overflow")
    })?;
    let outputs = tx.outputs.iter().try_fold(0u64, |s, o| {
        s.checked_add(o.value).ok_or("output sum overflow")
    })?;
    let fee = inputs.checked_sub(outputs).ok_or("negative fee")?;
    let quote:Vec<Value>=[100u64,200,500].into_iter().map(|r|json!({"rate":r,"required_sompi":mining*r,"actual_sompi":fee,"passes":fee>=mining*r})).collect();
    let classes = e
        .iter()
        .map(|u| &u.script_public_key)
        .chain(tx.outputs.iter().map(|o| &o.script_public_key))
        .all(|s| s.version() == 0 && ScriptClass::from_script(s) != ScriptClass::NonStandard);
    let sigops = tx
        .inputs
        .iter()
        .zip(e)
        .map(|(i, u)| kaspa_txscript::p2sh_sig_scanner(&i.signature_script, &u.script_public_key))
        .collect::<Vec<_>>();
    Ok(
        json!({"estimated_bytes":transaction_estimated_serialized_size(tx),"compute_mass":nc.compute_mass,"transient_mass":nc.transient_mass,"storage_mass":ctx.storage_mass,"relay_mass":relay,"mining_mass":mining,"actual_fee_sompi":fee,"quotes":quote,"standard_script_classes":classes,"P2SH_sigop_counts":sigops,"source_adapted_sigop_policy":sigops.iter().all(|n|*n<=15),"source_adapted_block_mass_caps":nc.compute_mass<=500000&&nc.transient_mass<=1000000&&ctx.storage_mass<=500000,"source_adapted_default_relay_fee":fee>=relay*100}),
    )
}
pub fn supplied_context(e: &[UtxoEntry]) -> Value {
    json!(e.iter().map(|u|json!({"amount_sompi":u.amount,"script_public_key":hex::encode([u.script_public_key.version().to_be_bytes().as_slice(),u.script_public_key.script()].concat()),"block_daa_score":u.block_daa_score,"is_coinbase":u.is_coinbase})).collect::<Vec<_>>())
}

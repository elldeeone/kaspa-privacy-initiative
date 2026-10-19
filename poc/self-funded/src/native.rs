//! Native transaction construction, exact transport round trips, full consensus
//! validation with explicit UTXOs, and separately identified relay policy checks.
use crate::{Result, covenant, protocol::*};
use kaspa_consensus::processes::transaction_validator::{
    TransactionValidator, tx_validation_in_utxo_context::TxValidationFlags,
};
use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    hashing::sighash_type::SIG_HASH_ALL,
    mass::{MassCalculator, transaction_estimated_serialized_size},
    tx::{
        PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_hashes::Hash;
use kaspa_txscript::{
    EngineCtx, SigCacheKey, TxScriptEngine,
    caches::{Cache, TxScriptCacheCounters},
    pay_to_script_hash_script,
    script_class::ScriptClass,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;

mod decimal {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(x: &u64, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&x.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<u64, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Utxo {
    pub txid: String,
    pub index: u32,
    #[serde(with = "decimal")]
    pub amount: u64,
    pub spk: String,
    #[serde(with = "decimal")]
    pub daa: u64,
    pub is_coinbase: bool,
}
impl Utxo {
    pub fn entry(&self) -> Result<UtxoEntry> {
        Ok(UtxoEntry::new(
            self.amount,
            decode_spk(&self.spk)?,
            self.daa,
            self.is_coinbase,
            None,
        ))
    }
    pub fn outpoint(&self) -> Result<TransactionOutpoint> {
        Ok(TransactionOutpoint::new(
            Hash::from_bytes(
                hex::decode(&self.txid)?
                    .try_into()
                    .map_err(|_| "txid length")?,
            ),
            self.index,
        ))
    }
    pub fn output(tx: &Transaction, index: usize, daa: u64) -> Self {
        let o = &tx.outputs[index];
        Self {
            txid: tx.id().to_string(),
            index: index as u32,
            amount: o.value,
            spk: hex::encode(encode_spk(&o.script_public_key)),
            daa,
            is_coinbase: false,
        }
    }
}
pub fn encode_spk(spk: &ScriptPublicKey) -> Vec<u8> {
    [spk.version().to_be_bytes().as_slice(), spk.script()].concat()
}
pub fn decode_spk(s: &str) -> Result<ScriptPublicKey> {
    let b = hex::decode(s)?;
    if b.len() < 2 {
        return Err("SPK length".into());
    }
    Ok(ScriptPublicKey::from_vec(
        u16::from_be_bytes(b[..2].try_into()?),
        b[2..].to_vec(),
    ))
}
pub fn p2pk(key: &H) -> Result<ScriptPublicKey> {
    let secret = secp256k1::SecretKey::from_slice(key)?;
    let pair = secp256k1::Keypair::from_secret_key(&secp256k1::Secp256k1::new(), &secret);
    let (pk, _) = pair.x_only_public_key();
    Ok(ScriptPublicKey::from_vec(
        0,
        [&[0x20], pk.serialize().as_slice(), &[0xac]].concat(),
    ))
}
pub fn address(spk: &ScriptPublicKey) -> Result<String> {
    Ok(
        kaspa_txscript::extract_script_pub_key_address(spk, kaspa_addresses::Prefix::Testnet)?
            .to_string(),
    )
}
fn tx(
    input: &Utxo,
    signature: Vec<u8>,
    budget: u16,
    outputs: Vec<TransactionOutput>,
    payload: Vec<u8>,
) -> Result<Transaction> {
    Ok(Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            input.outpoint()?,
            signature,
            u64::MAX,
            budget,
        )],
        outputs,
        0,
        Default::default(),
        0,
        payload,
    ))
}
pub fn set_mass(tx: &Transaction, entry: &UtxoEntry) -> Result<()> {
    checked_fee(tx, entry)?;
    let populated = PopulatedTransaction::new(tx, vec![entry.clone()]);
    let m = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS)
        .calc_contextual_masses(&populated)
        .ok_or("undefined storage mass")?;
    tx.set_storage_mass(m.storage_mass);
    Ok(())
}
pub fn proof_tx(t: &Transition, vk: &[u8], proof: &[u8]) -> Result<(Transaction, UtxoEntry)> {
    t.old.check()?;
    let (mode, next, _) = parse_payload(&t.payload)?;
    let redeem = covenant::redeem(&t.domain, &t.old, vk)?;
    let input = Utxo {
        txid: hex::encode(t.txid),
        index: t.index,
        amount: t.reserve_in,
        spk: hex::encode(encode_spk(&pay_to_script_hash_script(&redeem))),
        daa: 0,
        is_coinbase: false,
    };
    let mut outputs = Vec::new();
    if mode != 3 {
        outputs.push(TransactionOutput::new(
            t.reserve_out,
            pay_to_script_hash_script(&covenant::redeem(&t.domain, &next, vk)?),
        ));
    }
    if mode != 1 {
        outputs.push(TransactionOutput::new(
            t.payout,
            decode_spk(&hex::encode(&t.payout_spk))?,
        ));
    }
    let tx = tx(
        &input,
        covenant::signature(proof, &redeem)?,
        covenant::BUDGET,
        outputs,
        t.payload.clone(),
    )?;
    let entry = input.entry()?;
    set_mass(&tx, &entry)?;
    Ok((tx, entry))
}
pub fn funding(
    input: &Utxo,
    key: &H,
    reserve_spk: ScriptPublicKey,
    rate: u64,
) -> Result<(Transaction, UtxoEntry)> {
    if input.is_coinbase || input.amount > MAX_SOMPI || input.amount <= RESERVE {
        return Err("ordinary funding UTXO range".into());
    }
    let change_spk = p2pk(key)?;
    if input.spk != hex::encode(encode_spk(&change_spk)) {
        return Err("funding key/UTXO mismatch".into());
    }
    let entry = input.entry()?;
    let mut fee = 1u64;
    loop {
        let change = input
            .amount
            .checked_sub(RESERVE)
            .and_then(|n| n.checked_sub(fee))
            .filter(|n| *n > 0)
            .ok_or("insufficient funding change")?;
        let mut tx = tx(
            input,
            vec![0; 66],
            10,
            vec![
                TransactionOutput::new(RESERVE, reserve_spk.clone()),
                TransactionOutput::new(change, change_spk.clone()),
            ],
            vec![],
        )?;
        set_mass(&tx, &entry)?;
        let m = metrics(&tx, &entry)?;
        let required = m["mining_mass"]
            .as_u64()
            .unwrap()
            .checked_mul(rate)
            .ok_or("fee overflow")?;
        if fee < required {
            fee = required;
            continue;
        }
        let signature = kaspa_consensus_core::sign::sign_input(
            &PopulatedTransaction::new(&tx, vec![entry.clone()]),
            0,
            key,
            SIG_HASH_ALL,
        );
        tx.inputs[0].signature_script = signature;
        tx.finalize();
        return Ok((tx, entry));
    }
}
pub fn validator() -> TransactionValidator {
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
pub fn validate(tx: &Transaction, entry: &UtxoEntry) -> Result<u64> {
    checked_fee(tx, entry)?;
    let v = validator();
    v.validate_tx_in_isolation(tx)?;
    Ok(v.validate_populated_transaction_and_get_fee(
        &PopulatedTransaction::new(tx, vec![entry.clone()]),
        1_000_000_000,
        2_000_000_000_000,
        TxValidationFlags::Full,
        None,
        None,
    )?)
}
pub fn meter(tx: &Transaction, entry: &UtxoEntry) -> Result<u64> {
    checked_fee(tx, entry)?;
    let pop = PopulatedTransaction::new(tx, vec![entry.clone()]);
    let cache: Cache<SigCacheKey, bool> = Cache::new(10);
    let reused = kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync::new();
    let mut engine = TxScriptEngine::from_transaction_input_with_script_units_limit(
        &pop,
        &tx.inputs[0],
        0,
        entry,
        EngineCtx::new(&cache).with_reused(&reused),
        Default::default(),
        tx.inputs[0].compute_commit.allowed_script_units(),
    );
    engine.execute()?;
    Ok(engine.used_script_units().0)
}
pub fn metrics(tx: &Transaction, entry: &UtxoEntry) -> Result<Value> {
    let fee = checked_fee(tx, entry)?;
    let calculator = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let m = calculator.calc_non_contextual_masses(tx);
    let stored = calculator
        .calc_contextual_masses(&PopulatedTransaction::new(tx, vec![entry.clone()]))
        .ok_or("storage mass")?
        .storage_mass;
    let relay_mass = m.compute_mass.max(m.transient_mass.div_ceil(2));
    let mining_mass = relay_mass.max(stored);
    Ok(
        json!({"estimated_bytes":transaction_estimated_serialized_size(tx),"compute_mass":m.compute_mass,"transient_mass":m.transient_mass,"storage_mass":stored,"relay_mass":relay_mass,"mining_mass":mining_mass,"relay_floor_sompi":relay_mass*100,"fee_sompi":fee}),
    )
}
fn checked_fee(tx: &Transaction, entry: &UtxoEntry) -> Result<u64> {
    if tx.inputs.len() != 1
        || tx.outputs.is_empty()
        || entry.amount == 0
        || entry.amount > MAX_SOMPI
    {
        return Err("unsupported input/output shape or input amount".into());
    }
    let mut sum = 0u64;
    for o in &tx.outputs {
        if o.value == 0 || o.value > MAX_SOMPI {
            return Err("output amount range".into());
        }
        sum = sum.checked_add(o.value).ok_or("output sum overflow")?;
    }
    entry
        .amount
        .checked_sub(sum)
        .ok_or_else(|| "outputs exceed input".into())
}
pub fn policy(tx: &Transaction, entry: &UtxoEntry) -> Result<Value> {
    let m = metrics(tx, entry)?;
    if m["compute_mass"].as_u64().unwrap() > 500_000
        || m["storage_mass"].as_u64().unwrap() > 500_000
        || m["transient_mass"].as_u64().unwrap() > 1_000_000
    {
        return Err("native block mass limit".into());
    }
    for spk in std::iter::once(&entry.script_public_key)
        .chain(tx.outputs.iter().map(|o| &o.script_public_key))
    {
        if spk.version() != 0 || ScriptClass::from_script(spk) == ScriptClass::NonStandard {
            return Err("nonstandard script".into());
        }
    }
    if kaspa_txscript::p2sh_sig_scanner(&tx.inputs[0].signature_script, &entry.script_public_key)
        > 15
    {
        return Err("P2SH sigop policy".into());
    }
    if m["fee_sompi"].as_u64().unwrap() < m["relay_floor_sompi"].as_u64().unwrap() {
        return Err("below default relay fee".into());
    }
    Ok(m)
}
pub fn tx_json(tx: &Transaction) -> Value {
    json!({"version":tx.version,"id":tx.id().to_string(),"inputs":tx.inputs.iter().map(|i|json!({"previousOutpoint":{"transactionId":i.previous_outpoint.transaction_id.to_string(),"index":i.previous_outpoint.index},"signatureScript":hex::encode(&i.signature_script),"sequence":i.sequence.to_string(),"sigOpCount":0,"computeBudget":i.compute_commit.compute_budget().unwrap()})).collect::<Vec<_>>(),"outputs":tx.outputs.iter().map(|o|json!({"value":o.value.to_string(),"scriptPublicKey":hex::encode(encode_spk(&o.script_public_key)),"covenant":null})).collect::<Vec<_>>(),"lockTime":tx.lock_time.to_string(),"subnetworkId":tx.subnetwork_id.to_string(),"gas":tx.gas.to_string(),"payload":hex::encode(&tx.payload),"storageMass":tx.storage_mass().to_string()})
}
pub fn parse_tx(v: &Value) -> Result<Transaction> {
    let s = |v: &Value| -> Result<String> { Ok(v.as_str().ok_or("expected string")?.into()) };
    let n =
        |v: &Value| -> Result<u64> { Ok(v.as_str().ok_or("expected decimal string")?.parse()?) };
    if v["version"] != 1
        || s(&v["subnetworkId"])? != "0000000000000000000000000000000000000000"
        || n(&v["gas"])? != 0
        || n(&v["lockTime"])? != 0
    {
        return Err("native envelope".into());
    }
    let mut inputs = Vec::new();
    for i in v["inputs"].as_array().ok_or("inputs")? {
        let h: H = hex::decode(s(&i["previousOutpoint"]["transactionId"])?)?
            .try_into()
            .map_err(|_| "txid length")?;
        inputs.push(TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(
                Hash::from_bytes(h),
                i["previousOutpoint"]["index"]
                    .as_u64()
                    .ok_or("index")?
                    .try_into()?,
            ),
            hex::decode(s(&i["signatureScript"])?)?,
            n(&i["sequence"])?,
            i["computeBudget"]
                .as_u64()
                .ok_or("compute budget")?
                .try_into()?,
        ));
    }
    let mut outputs = Vec::new();
    for o in v["outputs"].as_array().ok_or("outputs")? {
        if o["covenant"] != Value::Null {
            return Err("unexpected covenant binding".into());
        }
        outputs.push(TransactionOutput::new(
            n(&o["value"])?,
            decode_spk(&s(&o["scriptPublicKey"])?)?,
        ));
    }
    let t = Transaction::new(
        1,
        inputs,
        outputs,
        0,
        Default::default(),
        0,
        hex::decode(s(&v["payload"])?)?,
    );
    t.set_storage_mass(n(&v["storageMass"])?);
    if tx_json(&t) != *v {
        return Err("transaction is not canonical/ID mismatch".into());
    }
    Ok(t)
}

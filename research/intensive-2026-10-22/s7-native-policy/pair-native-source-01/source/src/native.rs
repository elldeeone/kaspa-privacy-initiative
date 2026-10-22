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
pub fn set_mass(tx: &Transaction, entries: &[UtxoEntry]) -> Result<()> {
    checked_fee(tx, entries)?;
    let populated = PopulatedTransaction::new(tx, entries.to_vec());
    let m = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS)
        .calc_contextual_masses(&populated)
        .ok_or("undefined storage mass")?;
    tx.set_storage_mass(m.storage_mass);
    Ok(())
}
pub fn proof_tx(
    t: &Transition,
    vk: &[u8],
    proof: &[u8],
    external: Option<&Utxo>,
) -> Result<(Transaction, Vec<UtxoEntry>)> {
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
    if mode >= 2 {
        outputs.push(TransactionOutput::new(
            t.payout,
            decode_spk(&hex::encode(&t.payout_spk))?,
        ));
    }
    let mut tx = tx(
        &input,
        covenant::signature(proof, &redeem)?,
        covenant::BUDGET,
        outputs,
        t.payload.clone(),
    )?;
    let mut entries = vec![input.entry()?];
    if mode == 0 {
        let e = external.ok_or("missing deposit UTXO")?;
        let expected = [
            hex::decode(&e.txid)?,
            u64::from(e.index).to_le_bytes().to_vec(),
            e.amount.to_le_bytes().to_vec(),
            hex::decode(&e.spk)?,
        ]
        .concat();
        if expected != t.deposit || e.is_coinbase {
            return Err("deposit context mismatch".into());
        }
        tx.inputs.push(TransactionInput::new_with_compute_budget(
            e.outpoint()?,
            vec![0; 66],
            u64::MAX,
            10,
        ));
        entries.push(e.entry()?);
    } else if external.is_some() {
        return Err("unexpected external input".into());
    }
    tx.finalize();
    set_mass(&tx, &entries)?;
    Ok((tx, entries))
}
pub fn deposit_bytes(u: &Utxo) -> Result<Vec<u8>> {
    Ok([
        hex::decode(&u.txid)?,
        u64::from(u.index).to_le_bytes().to_vec(),
        u.amount.to_le_bytes().to_vec(),
        hex::decode(&u.spk)?,
    ]
    .concat())
}
pub fn fee_for(mode: u8) -> Result<u64> {
    let state = State {
        commitments: vec![[1; 32]],
        nullifiers: vec![],
    };
    let external = Utxo {
        txid: hex::encode([8; 32]),
        index: 1,
        amount: 1_200_000_000,
        spk: hex::encode(encode_spk(&p2pk(&[7; 32])?)),
        daa: 0,
        is_coinbase: false,
    };
    let t = Transition {
        domain: [9; 32],
        old: state.clone(),
        txid: [6; 32],
        index: 0,
        reserve_in: RESERVE,
        reserve_out: if mode == 3 {
            0
        } else if mode == 0 {
            RESERVE + external.amount - 1
        } else {
            100_000_000
        },
        payout: if mode >= 2 { 100_000_000 } else { 0 },
        payout_spk: if mode >= 2 {
            encode_spk(&p2pk(&[5; 32])?)
        } else {
            vec![0; 36]
        },
        deposit: if mode == 0 {
            deposit_bytes(&external)?
        } else {
            vec![0; 84]
        },
        payload: payload(mode, &state, &[vec![0; 185], vec![0; 185]])?,
    };
    let (tx, entries) = proof_tx(
        &t,
        &[0; 328],
        &[0; 128],
        if mode == 0 { Some(&external) } else { None },
    )?;
    Ok(metrics(&tx, &entries)?["relay_floor_sompi"]
        .as_u64()
        .ok_or("fee estimate")?)
}
pub fn ordinary(
    input: &Utxo,
    key: &H,
    payments: Vec<TransactionOutput>,
) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let spk = p2pk(key)?;
    if input.is_coinbase || input.amount > MAX_SOMPI || input.spk != hex::encode(encode_spk(&spk)) {
        return Err("ordinary funding identity/range".into());
    }
    let entries = vec![input.entry()?];
    let total = payments
        .iter()
        .try_fold(0u64, |a, b| a.checked_add(b.value))
        .ok_or("sum overflow")?;
    let mut fee = 1;
    loop {
        let change = input
            .amount
            .checked_sub(total)
            .and_then(|v| v.checked_sub(fee))
            .filter(|v| *v > 0)
            .ok_or("insufficient change")?;
        let mut outputs = payments.clone();
        outputs.push(TransactionOutput::new(change, spk.clone()));
        let mut t = tx(input, vec![0; 66], 10, outputs, vec![])?;
        set_mass(&t, &entries)?;
        let required = metrics(&t, &entries)?["mining_mass"]
            .as_u64()
            .ok_or("mass")?
            .checked_mul(100)
            .ok_or("fee overflow")?;
        if fee < required {
            fee = required;
            continue;
        }
        sign(&mut t, &entries, 0, key)?;
        return Ok((t, entries));
    }
}
pub fn sign(tx: &mut Transaction, entries: &[UtxoEntry], index: usize, key: &H) -> Result<()> {
    if entries.len() != tx.inputs.len()
        || index >= entries.len()
        || p2pk(key)? != entries[index].script_public_key
    {
        return Err("signature ownership/context".into());
    }
    let signature = kaspa_consensus_core::sign::sign_input(
        &PopulatedTransaction::new(tx, entries.to_vec()),
        index,
        key,
        SIG_HASH_ALL,
    );
    tx.inputs[index].signature_script = signature;
    tx.finalize();
    set_mass(tx, entries)
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
pub fn validate(tx: &Transaction, entries: &[UtxoEntry]) -> Result<u64> {
    checked_fee(tx, entries)?;
    let v = validator();
    v.validate_tx_in_isolation(tx)?;
    Ok(v.validate_populated_transaction_and_get_fee(
        &PopulatedTransaction::new(tx, entries.to_vec()),
        1_000_000_000,
        2_000_000_000_000,
        TxValidationFlags::Full,
        None,
        None,
    )?)
}
pub fn meter(tx: &Transaction, entries: &[UtxoEntry]) -> Result<u64> {
    (0..tx.inputs.len()).try_fold(0u64, |sum, index| {
        Ok(sum + script_units_at(tx, entries, index)?)
    })
}
/// Execute a single input to distinguish reserve-proof rejection from an
/// unrelated depositor-signature failure in adversarial binding controls.
pub fn script_units_at(tx: &Transaction, entries: &[UtxoEntry], index: usize) -> Result<u64> {
    checked_fee(tx, entries)?;
    let i = tx.inputs.get(index).ok_or("script input index")?;
    let e = entries.get(index).ok_or("script UTXO index")?;
    let pop = PopulatedTransaction::new(tx, entries.to_vec());
    let cache: Cache<SigCacheKey, bool> = Cache::new(10);
    let reused = kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync::new();
    let mut engine = TxScriptEngine::from_transaction_input_with_script_units_limit(
        &pop,
        i,
        index,
        e,
        EngineCtx::new(&cache).with_reused(&reused),
        Default::default(),
        i.compute_commit.allowed_script_units(),
    );
    engine.execute()?;
    Ok(engine.used_script_units().0)
}
pub fn metrics(tx: &Transaction, entries: &[UtxoEntry]) -> Result<Value> {
    let fee = checked_fee(tx, entries)?;
    let calculator = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let m = calculator.calc_non_contextual_masses(tx);
    let stored = calculator
        .calc_contextual_masses(&PopulatedTransaction::new(tx, entries.to_vec()))
        .ok_or("storage mass")?
        .storage_mass;
    let relay_mass = m.compute_mass.max(m.transient_mass.div_ceil(2));
    let mining_mass = relay_mass.max(stored);
    Ok(
        json!({"estimated_bytes":transaction_estimated_serialized_size(tx),"compute_mass":m.compute_mass,"transient_mass":m.transient_mass,"storage_mass":stored,"relay_mass":relay_mass,"mining_mass":mining_mass,"relay_floor_sompi":relay_mass*100,"fee_sompi":fee}),
    )
}
fn checked_fee(tx: &Transaction, entries: &[UtxoEntry]) -> Result<u64> {
    if tx.inputs.is_empty()
        || tx.inputs.len() > 2
        || tx.inputs.len() != entries.len()
        || tx.outputs.is_empty()
    {
        return Err("unsupported native shape".into());
    }
    let mut ins = 0u64;
    let mut outs = 0u64;
    for e in entries {
        if e.amount == 0 || e.amount > MAX_SOMPI {
            return Err("input range".into());
        }
        ins = ins.checked_add(e.amount).ok_or("input overflow")?;
    }
    for o in &tx.outputs {
        if o.value == 0 || o.value > MAX_SOMPI {
            return Err("output range".into());
        }
        outs = outs.checked_add(o.value).ok_or("output overflow")?;
    }
    if ins > MAX_SOMPI || outs > MAX_SOMPI {
        return Err("aggregate amount range".into());
    }
    ins.checked_sub(outs)
        .ok_or_else(|| "outputs exceed inputs".into())
}
pub fn policy(tx: &Transaction, entries: &[UtxoEntry]) -> Result<Value> {
    let m = metrics(tx, entries)?;
    if m["compute_mass"].as_u64().unwrap() > 500_000
        || m["storage_mass"].as_u64().unwrap() > 500_000
        || m["transient_mass"].as_u64().unwrap() > 1_000_000
    {
        return Err("native block mass limit".into());
    }
    for spk in entries
        .iter()
        .map(|e| &e.script_public_key)
        .chain(tx.outputs.iter().map(|o| &o.script_public_key))
    {
        if spk.version() != 0 || ScriptClass::from_script(spk) == ScriptClass::NonStandard {
            return Err("nonstandard script".into());
        }
    }
    for (i, e) in tx.inputs.iter().zip(entries) {
        if kaspa_txscript::p2sh_sig_scanner(&i.signature_script, &e.script_public_key) > 15 {
            return Err("P2SH sigop policy".into());
        }
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

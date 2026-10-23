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
    if tx.inputs.is_empty() || tx.inputs.len() != e.len() {
        return json!({"fixture_schema_rejected":true,"reason":"one supplied entry per nonempty transaction input required","Full":{"accepted":false},"per_input_ScriptEngine":[],"all_input_engines_accepted":false});
    }
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
    let mut engines = vec![];
    for (index, input) in tx.inputs.iter().enumerate() {
        let reused = SigHashReusedValuesUnsync::new();
        let mut engine = TxScriptEngine::from_transaction_input_with_script_units_limit(
            &p,
            input,
            index,
            &e[index],
            EngineCtx::new(&cache).with_reused(&reused),
            Default::default(),
            input.compute_commit.allowed_script_units(),
        );
        let result = engine.execute();
        engines.push(match result{Ok(_)=>json!({"input_index":index,"accepted":true,"units":engine.used_script_units().0,"allowed_script_units":input.compute_commit.allowed_script_units().0}),Err(error)=>json!({"input_index":index,"accepted":false,"typed_error":format!("{error:?}"),"units":engine.used_script_units().0,"allowed_script_units":input.compute_commit.allowed_script_units().0})});
    }
    json!({"isolation":iso.map(|_|"PASS".to_string()).unwrap_or_else(|e|format!("{e:?}")),"Full":match full{Ok(f)=>json!({"accepted":true,"fee_sompi":f}),Err(e)=>json!({"accepted":false,"typed_error":e})},"ScriptEngine":engines[0],"all_input_engines_accepted":engines.iter().all(|e|e["accepted"]==true),"per_input_ScriptEngine":engines})
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

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AdmitVector {
    pub state_hex: String,
    pub previous_txid_raw_hex: String,
    pub previous_index: u32,
    pub reserve_sompi: u64,
    pub payload_hex: String,
    pub funding_previous_txid_raw_hex: String,
    pub funding_previous_index: u32,
    pub funding_amount_sompi: u64,
    pub funding_secret_hex: String,
    pub vk_hex: String,
    #[serde(default = "all_sighash")]
    pub funding_sighash_type: u8,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FoundingVector {
    pub note_hex: String,
    pub cipher_hex: String,
    pub funding_previous_txid_raw_hex: String,
    pub funding_previous_index: u32,
    pub funding_amount_sompi: u64,
    pub funding_secret_hex: String,
    pub fee_sompi: u64,
    pub change_sompi: u64,
    pub vk_hex: String,
    #[serde(default = "all_sighash")]
    pub funding_sighash_type: u8,
}
/// One finite ordinary P2PK body, used only to link the synthetic source to
/// the founding and admission coins. No private state or covenant execution.
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FundingPrepOutput {
    pub value_sompi: u64,
    pub xonly_public_key_hex: String,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct FundingPrepVector {
    pub source_previous_txid_raw_hex: String,
    pub source_previous_index: u32,
    pub source_amount_sompi: u64,
    pub source_secret_hex: String,
    pub outputs: Vec<FundingPrepOutput>,
    pub fee_sompi: u64,
    pub source_change_sompi: u64,
    #[serde(default = "all_sighash")]
    pub funding_sighash_type: u8,
}
fn all_sighash() -> u8 {
    1
}
fn funding_key(secret: &str) -> Result<([u8; 32], ScriptPublicKey)> {
    let key = exact::<32>(secret)?;
    let pair = secp256k1::Keypair::from_secret_key(
        &secp256k1::Secp256k1::new(),
        &secp256k1::SecretKey::from_slice(&key)?,
    );
    Ok((key, p2pk(&pair.x_only_public_key().0.serialize())))
}
fn sign_funding(
    tx: &mut Transaction,
    e: &[UtxoEntry],
    i: usize,
    key: &[u8; 32],
    typ: u8,
) -> Result<()> {
    tx.inputs[i].signature_script = kaspa_consensus_core::sign::sign_input(
        &PopulatedTransaction::new(tx, e.to_vec()),
        i,
        key,
        SigHashType::from_u8(typ)?,
    );
    tx.finalize();
    set_mass(tx, e)
}
pub fn admit_body(v: &AdmitVector) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let state = exact::<112>(&v.state_hex)?;
    let p = exact::<1344>(&v.payload_hex)?;
    let vk = exact::<328>(&v.vk_hex)?;
    let next = exact::<112>(&hex::encode(&p[1048..1160]))?;
    let redeem = policy::redeem(&state, &vk)?;
    let (key, fspk) = funding_key(&v.funding_secret_hex)?;
    let value = n(&p, 104);
    let change = n(&p, 1168);
    let next_amount = v
        .reserve_sompi
        .checked_add(value)
        .ok_or("admission reserve overflow")?;
    let mut outputs = vec![TransactionOutput::new(
        next_amount,
        pay_to_script_hash_script(&policy::redeem(&next, &vk)?),
    )];
    if change > 0 {
        outputs.push(TransactionOutput::new(change, fspk.clone()))
    }
    let mut body = tx(
        exact::<32>(&v.previous_txid_raw_hex)?,
        v.previous_index,
        outputs,
        p.to_vec(),
        policy::witness(&[0; 65], &[0; 128], &redeem)?,
        policy::ADMIT_BUDGET,
    );
    body.inputs.push(TransactionInput::new_with_compute_budget(
        TransactionOutpoint::new(
            kaspa_hashes::Hash::from_bytes(exact::<32>(&v.funding_previous_txid_raw_hex)?),
            v.funding_previous_index,
        ),
        vec![0; 66],
        u64::MAX,
        10,
    ));
    let entries = vec![
        UtxoEntry::new(
            v.reserve_sompi,
            pay_to_script_hash_script(&redeem),
            0,
            false,
            None,
        ),
        UtxoEntry::new(v.funding_amount_sompi, fspk, 0, false, None),
    ];
    set_mass(&body, &entries)?;
    sign_funding(&mut body, &entries, 1, &key, v.funding_sighash_type)?;
    Ok((body, entries))
}
pub fn founding_body(v: &FoundingVector) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let note = exact::<168>(&v.note_hex)?;
    let cipher = exact::<264>(&v.cipher_hex)?;
    let vk = exact::<328>(&v.vk_hex)?;
    let value = n(&note, 64);
    if value < policy::NOTE_FLOOR as u64 || value > policy::MAX as u64 || v.fee_sompi == 0 {
        return Err("founding note/fee range".into());
    }
    let amount = value
        .checked_add(v.fee_sompi)
        .and_then(|x| x.checked_add(v.change_sompi))
        .ok_or("founding amount overflow")?;
    if amount != v.funding_amount_sompi || amount > policy::MAX as u64 {
        return Err("founding funding amount mismatch/range".into());
    }
    let state = policy::singleton_state(&note);
    let (key, fspk) = funding_key(&v.funding_secret_hex)?;
    let mut outputs = vec![TransactionOutput::new(
        value,
        pay_to_script_hash_script(&policy::redeem(&state, &vk)?),
    )];
    if v.change_sompi > 0 {
        outputs.push(TransactionOutput::new(v.change_sompi, fspk.clone()))
    }
    use sha2::{Digest, Sha256};
    let payload = [
        b"KPX2GN01".as_slice(),
        &policy::DOMAIN,
        note.as_slice(),
        &policy::note_cm(&note),
        cipher.as_slice(),
        Sha256::digest(cipher).as_slice(),
    ]
    .concat();
    let mut body = tx(
        exact::<32>(&v.funding_previous_txid_raw_hex)?,
        v.funding_previous_index,
        outputs,
        payload,
        vec![0; 66],
        10,
    );
    let entries = vec![UtxoEntry::new(v.funding_amount_sompi, fspk, 0, false, None)];
    set_mass(&body, &entries)?;
    sign_funding(&mut body, &entries, 0, &key, v.funding_sighash_type)?;
    Ok((body, entries))
}
pub fn funding_prep_body(v: &FundingPrepVector) -> Result<(Transaction, Vec<UtxoEntry>)> {
    if v.outputs.is_empty()
        || v.outputs.len() > 2
        || v.fee_sompi == 0
        || v.source_amount_sompi > policy::MAX as u64
    {
        return Err("funding preparation source/output/fee range".into());
    }
    let (key, source_spk) = funding_key(&v.source_secret_hex)?;
    let mut total = v
        .fee_sompi
        .checked_add(v.source_change_sompi)
        .ok_or("funding preparation sum overflow")?;
    let mut outputs = Vec::with_capacity(3);
    for output in &v.outputs {
        if output.value_sompi == 0 || output.value_sompi > policy::MAX as u64 {
            return Err("funding preparation output range".into());
        }
        let public = exact::<32>(&output.xonly_public_key_hex)?;
        secp256k1::XOnlyPublicKey::from_slice(&public)?;
        total = total
            .checked_add(output.value_sompi)
            .ok_or("funding preparation sum overflow")?;
        outputs.push(TransactionOutput::new(output.value_sompi, p2pk(&public)));
    }
    if total != v.source_amount_sompi {
        return Err("funding preparation conservation mismatch".into());
    }
    if v.source_change_sompi > 0 {
        outputs.push(TransactionOutput::new(
            v.source_change_sompi,
            source_spk.clone(),
        ));
    }
    let mut body = tx(
        exact::<32>(&v.source_previous_txid_raw_hex)?,
        v.source_previous_index,
        outputs,
        vec![],
        vec![0; 66],
        10,
    );
    let entries = vec![UtxoEntry::new(
        v.source_amount_sompi,
        source_spk,
        0,
        false,
        None,
    )];
    set_mass(&body, &entries)?;
    sign_funding(&mut body, &entries, 0, &key, v.funding_sighash_type)?;
    Ok((body, entries))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationCase {
    pub transaction: Transaction,
    pub entries: Vec<UtxoEntry>,
}
/// Preparation only: re-sign a mutated public development control while
/// retaining its actual supplied SPK. Never executes a VM, contacts a node,
/// selects coins, derives a wallet, or persists keys.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResignControlVector {
    pub case: ValidationCase,
    pub input_index: usize,
    pub public_development_secret_hex: String,
    pub sighash_type: u8,
    pub common_reveal_witness: bool,
}
pub fn resign_control(v: ResignControlVector) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let mut body = v.case.transaction;
    let entries = v.case.entries;
    if body.inputs.is_empty()
        || body.inputs.len() != entries.len()
        || v.input_index >= entries.len()
    {
        return Err("control input/context dimensions".into());
    }
    let key = exact::<32>(&v.public_development_secret_hex)?;
    if v.common_reveal_witness {
        if v.input_index != 0 || body.inputs[0].signature_script.len() < policy::REDEEM_START {
            return Err("control common reveal witness dimensions".into());
        }
        let old = &body.inputs[0].signature_script;
        let proof: [u8; 128] = old[68..196].try_into()?;
        let redeem = old[policy::REDEEM_START..].to_vec();
        let secp = secp256k1::Secp256k1::new();
        let pair =
            secp256k1::Keypair::from_secret_key(&secp, &secp256k1::SecretKey::from_slice(&key)?);
        set_mass(&body, &entries)?;
        let digest = calc_schnorr_signature_hash(
            &PopulatedTransaction::new(&body, entries.clone()),
            0,
            SigHashType::from_u8(v.sighash_type)?,
            &SigHashReusedValuesUnsync::new(),
        );
        let sig = secp.sign_schnorr_no_aux_rand(
            &secp256k1::Message::from_digest_slice(&digest.as_bytes())?,
            &pair,
        );
        let mut bytes = [0; 65];
        bytes[..64].copy_from_slice(sig.as_ref());
        bytes[64] = v.sighash_type;
        body.inputs[0].signature_script = policy::witness(&bytes, &proof, &redeem)?;
        body.finalize();
        set_mass(&body, &entries)?;
    } else {
        sign_funding(&mut body, &entries, v.input_index, &key, v.sighash_type)?;
    }
    Ok((body, entries))
}

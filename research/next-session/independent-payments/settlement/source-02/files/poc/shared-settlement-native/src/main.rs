//! Unfunded W emitter/body oracle; no native VM, note witness, PK or network API.
//! Actual W always verifies the full receipt. A distinct marked hash-oracle
//! program exists only for public codec diagnostics and has no W authority.
mod policy;
mod receipt;

use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    mass::{transaction_estimated_serialized_size, Mass, MassCalculator},
    tx::{PopulatedTransaction, ScriptPublicKey, Transaction, UtxoEntry},
};
use kaspa_txscript::pay_to_script_hash_script;
use policy::{Kind, Profile};
use serde::{
    de::{Error as _, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Read};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

// serde_json::Value ordinarily keeps the last duplicate object member. This
// recursive wrapper rejects duplicates before any public body is interpreted.
struct Unique(Value);
struct UniqueVisitor;
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueVisitor)
    }
}
impl<'de> Visitor<'de> for UniqueVisitor {
    type Value = Unique;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("JSON with unique object keys")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
        Ok(Unique(Value::Bool(v)))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
        serde_json::Number::from_f64(v)
            .map(|n| Unique(Value::Number(n)))
            .ok_or_else(|| E::custom("finite JSON number required"))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
        Ok(Unique(v.into()))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> std::result::Result<Unique, E> {
        Ok(Unique(Value::String(v)))
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
        Ok(Unique(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Unique, A::Error> {
        let mut rows = Vec::new();
        while let Some(row) = seq.next_element::<Unique>()? {
            rows.push(row.0);
        }
        Ok(Unique(Value::Array(rows)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> std::result::Result<Unique, A::Error> {
        let mut rows = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if rows.contains_key(&key) {
                return Err(A::Error::custom("duplicate public JSON key"));
            }
            rows.insert(key, map.next_value::<Unique>()?.0);
        }
        Ok(Unique(Value::Object(rows)))
    }
}

fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
// Exact upstream txscript::SpkEncoding::to_bytes encoding. That trait is
// crate-private: introspection prefixes version u16 BIG-endian, then script.
fn spk_bytes(spk: &ScriptPublicKey) -> Vec<u8> {
    [spk.version().to_be_bytes().as_slice(), spk.script()].concat()
}
fn fields(value: &Value, expected: &[&str]) -> Result<()> {
    let object = value.as_object().ok_or("expected object")?;
    if object.len() != expected.len() || expected.iter().any(|k| !object.contains_key(*k)) {
        return Err("unexpected or missing public field".into());
    }
    Ok(())
}
fn bytes(value: &Value, width: Option<usize>) -> Result<Vec<u8>> {
    let raw = value.as_str().ok_or("hex string")?;
    if raw.len() % 2 != 0
        || !raw
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("canonical public hex".into());
    }
    let decoded = hex::decode(raw)?;
    if width.is_some_and(|n| decoded.len() != n) {
        return Err("public byte width".into());
    }
    Ok(decoded)
}
fn integer(value: &Value, max: u64) -> Result<u64> {
    let result = value.as_u64().ok_or("unsigned integer")?;
    if result > max {
        return Err("integer bound".into());
    }
    Ok(result)
}
fn number(raw: &[u8]) -> Result<u64> {
    Ok(u64::from_le_bytes(raw.try_into().map_err(|_| "u64 width")?))
}
fn checked_case(value: &Value) -> Result<(Transaction, Vec<UtxoEntry>)> {
    fields(value, &["transaction", "entries"])?;
    let body = &value["transaction"];
    fields(
        body,
        &[
            "version",
            "id",
            "inputs",
            "outputs",
            "lockTime",
            "subnetworkId",
            "gas",
            "payload",
            "mass",
        ],
    )?;
    integer(&body["version"], u16::MAX as u64)?;
    bytes(&body["id"], Some(32))?;
    integer(&body["lockTime"], u64::MAX)?;
    bytes(&body["subnetworkId"], Some(20))?;
    integer(&body["gas"], u64::MAX)?;
    integer(&body["mass"], u64::MAX)?;
    bytes(&body["payload"], None)?;
    let inputs = body["inputs"].as_array().ok_or("inputs array")?;
    let outputs = body["outputs"].as_array().ok_or("outputs array")?;
    let entries = value["entries"].as_array().ok_or("entries array")?;
    if inputs.len() != 1 || outputs.len() != 1 || entries.len() != 1 {
        return Err("one input/output/context required".into());
    }
    for input in inputs {
        fields(
            input,
            &[
                "previousOutpoint",
                "signatureScript",
                "sequence",
                "computeBudget",
            ],
        )?;
        fields(&input["previousOutpoint"], &["transactionId", "index"])?;
        bytes(&input["previousOutpoint"]["transactionId"], Some(32))?;
        integer(&input["previousOutpoint"]["index"], u32::MAX as u64)?;
        bytes(&input["signatureScript"], None)?;
        integer(&input["sequence"], u64::MAX)?;
        integer(&input["computeBudget"], u16::MAX as u64)?;
    }
    for output in outputs {
        fields(output, &["value", "scriptPublicKey", "covenant"])?;
        let amount = integer(&output["value"], policy::MAX as u64)?;
        if amount == 0 || !output["covenant"].is_null() {
            return Err("output amount/covenant".into());
        }
        bytes(&output["scriptPublicKey"], Some(37))?;
    }
    for entry in entries {
        fields(
            entry,
            &[
                "amount",
                "scriptPublicKey",
                "blockDaaScore",
                "isCoinbase",
                "covenantId",
            ],
        )?;
        if integer(&entry["amount"], policy::MAX as u64)? == 0
            || entry["isCoinbase"] != false
            || !entry["covenantId"].is_null()
        {
            return Err("context amount/flags".into());
        }
        integer(&entry["blockDaaScore"], u64::MAX)?;
        bytes(&entry["scriptPublicKey"], Some(37))?;
    }
    Ok((
        serde_json::from_value(body.clone())?,
        serde_json::from_value(value["entries"].clone())?,
    ))
}

fn financial_projection(tx: &Transaction, entry: &UtxoEntry) -> Result<Vec<u8>> {
    if tx.inputs.len() != 1 || tx.outputs.len() != 1 || tx.outputs[0].covenant.is_some() {
        return Err("financial projection dimensions".into());
    }
    let input = &tx.inputs[0];
    let output = &tx.outputs[0];
    let input_spk = spk_bytes(&entry.script_public_key);
    let output_spk = spk_bytes(&output.script_public_key);
    if input_spk.len() != 37 || output_spk.len() != 37 {
        return Err("financial SPK widths".into());
    }
    let mut raw = Vec::new();
    raw.extend_from_slice(b"KPX5FB01");
    raw.extend_from_slice(&tx.version.to_le_bytes());
    raw.extend_from_slice(&1u16.to_le_bytes());
    raw.extend_from_slice(&input.previous_outpoint.transaction_id.as_bytes());
    raw.extend_from_slice(&input.previous_outpoint.index.to_le_bytes());
    raw.extend_from_slice(&input.sequence.to_le_bytes());
    raw.extend_from_slice(&entry.amount.to_le_bytes());
    raw.extend_from_slice(&(input_spk.len() as u16).to_le_bytes());
    raw.extend_from_slice(&input_spk);
    raw.extend_from_slice(&1u16.to_le_bytes());
    raw.extend_from_slice(&output.value.to_le_bytes());
    raw.extend_from_slice(&(output_spk.len() as u16).to_le_bytes());
    raw.extend_from_slice(&output_spk);
    raw.push(0);
    raw.extend_from_slice(&tx.lock_time.to_le_bytes());
    raw.extend_from_slice(tx.subnetwork_id.as_ref());
    raw.extend_from_slice(&tx.gas.to_le_bytes());
    raw.extend_from_slice(&(tx.payload.len() as u32).to_le_bytes());
    raw.extend_from_slice(&tx.payload);
    if raw.len() != 8301 {
        return Err("financial projection8301".into());
    }
    Ok(raw)
}

fn body_oracle(value: &Value, p: &Profile, c: &receipt::Constants) -> Result<Value> {
    let (mut tx, entries) = checked_case(value)?;
    let entry = &entries[0];
    let input = &tx.inputs[0];
    let output = &tx.outputs[0];
    if tx.version != 1
        || tx.lock_time != 0
        || tx.gas != 0
        || tx.subnetwork_id.as_ref() != [0u8; 20]
        || input.sequence != u64::MAX
        || entry.is_coinbase
        || entry.covenant_id.is_some()
    {
        return Err("canonical wrapper header/context".into());
    }
    let frame = &input.signature_script;
    if frame.len() < policy::REDEEM_START + policy::METADATA_PREFIX
        || frame[..68] != [vec![65], vec![0; 65], vec![0x4c, 128]].concat()
        || frame[196] != 0x4d
        || frame.len() != 199 + u16::from_le_bytes(frame[197..199].try_into()?) as usize
    {
        return Err("canonical wrapper witness frame".into());
    }
    let redeem = &frame[199..];
    let state: [u8; 112] = redeem
        .get(2..114)
        .ok_or("wrapper state prefix")?
        .try_into()?;
    let image: [u8; 32] = redeem
        .get(policy::IMAGE_AT..policy::IMAGE_AT + 32)
        .ok_or("wrapper image metadata")?
        .try_into()?;
    let kind = Kind::from_marker(
        redeem
            .get(policy::KIND_AT..policy::KIND_AT + 8)
            .ok_or("wrapper kind metadata")?,
    )?;
    let expected = policy::wrapper_redeem(p, &state, &image, c, kind)?;
    if redeem != expected || entry.script_public_key != pay_to_script_hash_script(&expected) {
        return Err("exact current wrapper template/SPK".into());
    }
    let payload = &tx.payload;
    if payload.len() != policy::AGGREGATE_PAYLOAD || &payload[..12] != b"KPX5VP01\x01\x00\x02\x00" {
        return Err("exact two record frame".into());
    }
    for base in [policy::RECORD0, policy::RECORD1] {
        if &payload[base..base + 8] != policy::AUTH_MAGIC
            || payload[base + 8..base + 40] != policy::DOMAIN
            || payload[base + 300] != 2
            || payload[base + 301..base + 304] != [0; 3]
            || payload[base + 308..base + 332] != [0; 24]
            || payload[base + 484..base + 528] != [0; 44]
        {
            return Err("compact mode2/P0 record metadata".into());
        }
        for (at, min) in [
            (188, policy::NOTE_FLOOR as u64),
            (196, 1),
            (476, policy::NOTE_FLOOR as u64),
        ] {
            if !(min..=policy::MAX as u64).contains(&number(&payload[base + at..base + at + 8])?) {
                return Err("record financial bounds".into());
            }
        }
    }
    let first = policy::RECORD0;
    let second = policy::RECORD1;
    let point = [
        input.previous_outpoint.transaction_id.as_bytes().as_slice(),
        &input.previous_outpoint.index.to_le_bytes(),
    ]
    .concat();
    if payload[first + 40..first + 76] != point
        || payload[first + 76..first + 188] != state
        || number(&payload[first + 188..first + 196])? != entry.amount
        || payload[first + 364..first + 476] != payload[second + 76..second + 188]
        || payload[first + 476..first + 484] != payload[second + 188..second + 196]
    {
        return Err("exact starting point/state/reserve and child link".into());
    }
    let next: [u8; 112] = payload[policy::FINAL_STATE..policy::FINAL_STATE + 112].try_into()?;
    let next_redeem = policy::wrapper_redeem(p, &next, &image, c, kind)?;
    if output.value < policy::NOTE_FLOOR as u64
        || entry.amount < policy::NOTE_FLOOR as u64
        || output.value != number(&payload[policy::FINAL_RESERVE..policy::FINAL_RESERVE + 8])?
        || output.script_public_key != pay_to_script_hash_script(&next_redeem)
    {
        return Err("exact wrapper successor state/reserve/SPK".into());
    }
    let fee = entry
        .amount
        .checked_sub(output.value)
        .ok_or("negative outer fee")?;
    let allocated = number(&payload[first + 196..first + 204])?
        .checked_add(number(&payload[second + 196..second + 204])?)
        .ok_or("fee sum overflow")?;
    if fee == 0 || fee != allocated {
        return Err("exact allocated aggregate fee".into());
    }
    let projection = financial_projection(&tx, entry)?;
    let mut journal = Vec::new();
    journal.extend_from_slice(b"KPX5VS01\x01\x00");
    journal.extend_from_slice(&p.wrapper_domain);
    journal.extend_from_slice(&policy::DOMAIN);
    journal.extend_from_slice(&2u16.to_le_bytes());
    journal.extend_from_slice(&point);
    journal.extend_from_slice(&state);
    journal.extend_from_slice(&entry.amount.to_le_bytes());
    journal.extend_from_slice(&next);
    journal.extend_from_slice(&output.value.to_le_bytes());
    journal.extend_from_slice(&fee.to_le_bytes());
    journal.extend_from_slice(&hash(&payload[12..]));
    journal.extend_from_slice(&hash(&projection));
    if journal.len() != policy::JOURNAL_BYTES {
        return Err("journal424".into());
    }
    let calc = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let non = calc.calc_non_contextual_masses(&tx);
    let contextual = calc
        .calc_contextual_masses(&PopulatedTransaction::new(&tx, entries.clone()))
        .ok_or("storage mass")?;
    let normalized =
        Mass::new(non, contextual).normalized_max(&TESTNET_PARAMS.block_mass_limits.cofactors());
    let original_id = tx.id();
    tx.finalize();
    if tx.id() != original_id || tx.storage_mass() != contextual.storage_mass {
        return Err("canonical finalized id/storage mass required".into());
    }
    Ok(json!({"schema":"kpx5-native-financial-body-oracle/v1",
        "classification":"UNFUNDED_PUBLIC_BODY_CODEC_NO_RECEIPT_OR_VM_ACCEPTANCE",
        "template_kind":if kind==Kind::Receipt {"ACTUAL_R0_W"} else {"UNSAFE_HASH_ORACLE_ONLY"},
        "outer_image_hex32":hex::encode(image), "journal_hex424":hex::encode(&journal),
        "journal_sha256":hex::encode(hash(&journal)),"financial_projection_hex":hex::encode(&projection),
        "financial_projection_bytes":projection.len(),"financial_projection_sha256":hex::encode(hash(&projection)),
        "records_sha256":hex::encode(hash(&tx.payload[12..])),"transaction_id":tx.id().to_string(),
        "metrics":{"compute_mass":non.compute_mass,"transient_mass":non.transient_mass,
            "storage_mass":contextual.storage_mass,"mining_mass":normalized,"actual_fee_sompi":fee,
            "native_estimated_serialized_bytes":transaction_estimated_serialized_size(&tx),
            "allowed_script_units":tx.inputs[0].compute_commit.allowed_script_units().0},
        "native_VM_executed":false,"receipt_or_child_G16_verified":false,
        "accepted_backing_currentness_or_funding_authority":false}))
}

fn execute(value: Value) -> Result<Value> {
    let operation = value["operation"].as_str().ok_or("operation")?;
    let profile = Profile::selected()?;
    let constants = receipt::constants()?;
    match operation {
        "emit" | "emit-oracle" => {
            fields(&value, &["operation", "state_hex112", "outer_image_hex32"])?;
            let state: [u8; 112] = bytes(&value["state_hex112"], Some(112))?
                .try_into()
                .map_err(|_| "state width")?;
            let image: [u8; 32] = bytes(&value["outer_image_hex32"], Some(32))?
                .try_into()
                .map_err(|_| "image width")?;
            let kind = if operation == "emit" {
                Kind::Receipt
            } else {
                Kind::HashOracle
            };
            let redeem = policy::wrapper_redeem(&profile, &state, &image, &constants, kind)?;
            let witness = policy::witness(&[0; 128], &redeem)?;
            Ok(json!({"schema":"kpx5-native-wrapper-emission/v1",
                "classification":if kind==Kind::Receipt {"ACTUAL_R0_W_BYTES_NOT_ACCEPTANCE"} else {"UNSAFE_UNFUNDED_HASH_ORACLE_NO_FINANCIAL_AUTHORITY"},
                "template_kind":if kind==Kind::Receipt {"ACTUAL_R0_W"} else {"UNSAFE_HASH_ORACLE_ONLY"},
                "state_hex112":hex::encode(state),"outer_image_hex32":hex::encode(image),
                "redeem_hex":hex::encode(&redeem),"redeem_bytes":redeem.len(),
                "redeem_sha256":hex::encode(hash(&redeem)),"script_public_key":hex::encode(spk_bytes(&pay_to_script_hash_script(&redeem))),
                "zero_signature_zero_proof_witness_hex":hex::encode(witness),
                "standard_outer_vk_sha256":hex::encode(hash(&constants.vk)),
                "child_vk_sha256":hex::encode(hash(&profile.compact_vk)),
                "child_profile_source_sha256":hex::encode(hash(include_bytes!("../../shared-settlement-proof/child-profile.json"))),
                "actual_funding_native_VM_receipt_or_private_inputs":false}))
        }
        "body" => {
            fields(&value, &["operation", "case"])?;
            body_oracle(&value["case"], &profile, &constants)
        }
        _ => Err("unknown fixed public operation".into()),
    }
}

fn main() {
    let result = (|| -> Result<Value> {
        let mut raw = Vec::new();
        io::stdin()
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut raw)?;
        if raw.len() > 4 * 1024 * 1024 {
            return Err("public request exceeds fixed-contract bound".into());
        }
        execute(serde_json::from_slice::<Unique>(&raw)?.0)
    })();
    match result {
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("PUBLIC_WRAPPER_REFUSED: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recursive_duplicate_keys_and_numeric_aliases_reject() {
        for raw in [
            r#"{"operation":"emit","operation":"body"}"#,
            r#"{"case":{"entries":[],"entries":[]}}"#,
            r#"{"operation":1,"\u006fperation":2}"#,
        ] {
            assert!(serde_json::from_str::<Unique>(raw).is_err());
        }
        for value in [json!(true), json!(-1), json!(1.0), json!("1")] {
            assert!(integer(&value, u64::MAX).is_err());
        }
        assert_eq!(integer(&json!(u64::MAX), u64::MAX).unwrap(), u64::MAX);
    }
    #[test]
    fn marked_templates_and_witness_are_distinct_and_canonical() {
        let p = Profile::selected().unwrap();
        let c = receipt::constants().unwrap();
        let mut state = [0u8; 112];
        state[..8].copy_from_slice(policy::STATE_MAGIC);
        state[8..40].copy_from_slice(&policy::DOMAIN);
        state[72..76].copy_from_slice(&1u32.to_le_bytes());
        state[108..112].copy_from_slice(&1u32.to_le_bytes());
        let image = [17u8; 32];
        let real = policy::wrapper_redeem(&p, &state, &image, &c, Kind::Receipt).unwrap();
        let oracle = policy::wrapper_redeem(&p, &state, &image, &c, Kind::HashOracle).unwrap();
        assert_ne!(real, oracle);
        for (raw, kind) in [(&real, Kind::Receipt), (&oracle, Kind::HashOracle)] {
            assert_eq!(&raw[policy::IMAGE_AT..policy::IMAGE_AT + 32], &image);
            assert_eq!(&raw[policy::KIND_AT..policy::KIND_AT + 8], kind.marker());
            let frame = policy::witness(&[0; 128], raw).unwrap();
            assert_eq!(frame.len(), 199 + raw.len());
            assert_eq!(
                &frame[..68],
                &[vec![65], vec![0; 65], vec![0x4c, 128]].concat()
            );
            assert_eq!(&frame[199..], raw.as_slice());
        }
    }
}

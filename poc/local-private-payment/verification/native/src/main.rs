//! Public ADR0066 mixed/direct-exit emitter and body codec; never a VM or receipt verdict.
mod policy;
mod r0_fragment;
use kaspa_consensus_core::{
    config::params::TESTNET_PARAMS,
    mass::{transaction_estimated_serialized_size, Mass, MassCalculator},
    tx::{PopulatedTransaction, ScriptPublicKey, Transaction, UtxoEntry},
};
use kaspa_txscript::pay_to_script_hash_script;
use serde::{
    de::{Error as _, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{self, Read};
type Result<T> = policy::Result<T>;
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
    if inputs.len() != 1 || !(1..=2).contains(&outputs.len()) || entries.len() != 1 {
        return Err("one input, one or two outputs and one context required".into());
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
        let spk = bytes(&output["scriptPublicKey"], None)?;
        if ![36, 37].contains(&spk.len()) {
            return Err("output SPK width".into());
        }
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

fn selected_parameters(value: &Value) -> Result<([u8; 32], [u8; 32], [u8; 328])> {
    let image: [u8; 32] = bytes(&value["outer_image_hex32"], Some(32))?
        .try_into()
        .unwrap();
    let component: [u8; 32] = bytes(&value["component_profile_sha256"], Some(32))?
        .try_into()
        .unwrap();
    let exit_vk: [u8; 328] = bytes(&value["exit_vk_hex328"], Some(328))?
        .try_into()
        .unwrap();
    if image == [0; 32] || component == [0; 32] || exit_vk == [0; 328] {
        return Err("selected_image_component_exit_key_identity".into());
    }
    Ok((image, component, exit_vk))
}
fn financial_projection(tx: &Transaction, entry: &UtxoEntry) -> Result<Vec<u8>> {
    let input = &tx.inputs[0];
    let input_spk = spk_bytes(&entry.script_public_key);
    if input_spk.len() != 37 {
        return Err("input SPK width".into());
    }
    let mut raw = Vec::new();
    raw.extend(b"KPXAFX01");
    raw.extend(tx.version.to_le_bytes());
    raw.extend(1u16.to_le_bytes());
    raw.extend(input.previous_outpoint.transaction_id.as_bytes());
    raw.extend(input.previous_outpoint.index.to_le_bytes());
    raw.extend(input.sequence.to_le_bytes());
    raw.extend(entry.amount.to_le_bytes());
    raw.extend(37u16.to_le_bytes());
    raw.extend(input_spk);
    raw.extend((tx.outputs.len() as u16).to_le_bytes());
    for output in &tx.outputs {
        let spk = spk_bytes(&output.script_public_key);
        if ![36, 37].contains(&spk.len()) {
            return Err("output SPK width".into());
        }
        raw.extend(output.value.to_le_bytes());
        raw.extend((spk.len() as u16).to_le_bytes());
        raw.extend(spk);
        raw.push(0);
    }
    raw.extend(tx.lock_time.to_le_bytes());
    raw.extend_from_slice(tx.subnetwork_id.as_ref());
    raw.extend(tx.gas.to_le_bytes());
    raw.extend((tx.payload.len() as u32).to_le_bytes());
    raw.extend(&tx.payload);
    Ok(raw)
}
fn body(
    value: &Value,
    image: &[u8; 32],
    component: &[u8; 32],
    exit_vk: &[u8; 328],
    normalize: bool,
) -> Result<Value> {
    let (mut tx, entries) = checked_case(value)?;
    let entry = &entries[0];
    if tx.version != 1
        || tx.lock_time != 0
        || tx.gas != 0
        || tx.subnetwork_id.as_ref() != [0u8; 20]
        || tx.inputs[0].sequence != u64::MAX
        || entry.is_coinbase
        || entry.covenant_id.is_some()
        || tx.outputs.iter().any(|o| o.covenant.is_some())
    {
        return Err("native_header_or_context".into());
    }
    let frame = &tx.inputs[0].signature_script;
    if frame.len() < policy::REDEEM_START + policy::METADATA_PREFIX
        || frame[..2] != [0x4c, 128]
        || frame[130] != 0x4d
        || frame.len()
            != policy::REDEEM_START + u16::from_le_bytes(frame[131..133].try_into()?) as usize
    {
        return Err("canonical_witness_frame".into());
    }
    let redeem = &frame[policy::REDEEM_START..];
    let state: [u8; 112] = redeem[2..114].try_into()?;
    let expected = policy::redeem(&state, image, component, exit_vk)?;
    if redeem != expected || entry.script_public_key != pay_to_script_hash_script(&expected) {
        return Err("selected_current_template_SPK".into());
    }
    let payload = tx.payload.clone();
    let mixed =
        payload.len() == policy::BODY_LEN && &payload[..16] == b"KPXAPB01\x01\0\x01\0\x02\0\0\0";
    let exit = payload.len() == policy::EXIT_BODY_LEN
        && &payload[..16] == b"KPXAXB01\x01\0\x01\0\0\0\x01\0";
    if !(mixed || exit) || payload[16..48] != policy::DOMAIN || payload[148..260] != state {
        return Err("body_identity_or_state".into());
    }
    let next: [u8; 112] = payload[268..380].try_into()?;
    policy::validate_state(&next)?;
    let old_n = u32::from_le_bytes(state[72..76].try_into()?);
    let old_m = u32::from_le_bytes(state[108..112].try_into()?);
    let new_n = u32::from_le_bytes(next[72..76].try_into()?);
    let new_m = u32::from_le_bytes(next[108..112].try_into()?);
    let reserve = number(&payload[260..268])?;
    let remaining = number(&payload[380..388])?;
    let fee = number(&payload[388..396])?;
    let payout = number(&payload[396..404])?;
    let point = [
        tx.inputs[0]
            .previous_outpoint
            .transaction_id
            .as_bytes()
            .as_slice(),
        &tx.inputs[0].previous_outpoint.index.to_le_bytes(),
    ]
    .concat();
    let outsum = tx.outputs.iter().try_fold(0u64, |a, o| {
        a.checked_add(o.value).ok_or("output sum overflow")
    })?;
    let actual_fee = entry.amount.checked_sub(outsum).ok_or("negative_fee")?;
    if payload[112..148] != point
        || reserve != entry.amount
        || fee != actual_fee
        || !(1..=policy::MAX).contains(&fee)
        || !(policy::FLOOR..=policy::MAX).contains(&reserve)
        || remaining
            .checked_add(fee)
            .and_then(|n| n.checked_add(payout))
            != Some(reserve)
    {
        return Err("native_point_reserve_fee".into());
    }
    if mixed {
        if tx.outputs.len() != 1
            || payout != 0
            || payload[80..112] != [0; 32]
            || old_n < 1
            || old_n.checked_add(2) != Some(new_n)
            || old_m.checked_add(1) != Some(new_m)
            || !(policy::FLOOR..=policy::MAX).contains(&remaining)
            || tx.outputs[0].value != remaining
        {
            return Err("batch_money_or_state_counts".into());
        }
    } else {
        if payload[80..112] != [0; 32]
            || old_n != new_n
            || state[40..72] != next[40..72]
            || old_m.checked_add(1) != Some(new_m)
            || !(policy::PAYOUT_FLOOR..=policy::MAX).contains(&payout)
            || payload[404..407] != [0, 0, 0x20]
            || payload[439] != 0xac
            || payload[440..472] == [0; 32]
            || tx.outputs.len() != if remaining == 0 { 1 } else { 2 }
            || spk_bytes(&tx.outputs.last().unwrap().script_public_key) != payload[404..440]
            || tx.outputs.last().unwrap().value != payout
        {
            return Err("exit_money_state_or_destination".into());
        }
        if remaining != 0
            && (!(policy::FLOOR..=policy::MAX).contains(&remaining)
                || tx.outputs[0].value != remaining)
        {
            return Err("exit_remaining_reserve".into());
        }
    }
    if remaining != 0 {
        let next_redeem = policy::redeem(&next, image, component, exit_vk)?;
        if tx.outputs[0].script_public_key != pay_to_script_hash_script(&next_redeem) {
            return Err("same_tail_successor".into());
        }
    }
    let calc = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let contextual = calc
        .calc_contextual_masses(&PopulatedTransaction::new(&tx, entries.clone()))
        .ok_or("storage_mass")?;
    let original_id = tx.id();
    let original_mass = tx.storage_mass();
    if normalize {
        tx.set_storage_mass(contextual.storage_mass);
    }
    tx.finalize();
    if !normalize && (tx.id() != original_id || original_mass != contextual.storage_mass) {
        return Err("canonical_final_id_storage_mass".into());
    }
    let projection = financial_projection(&tx, entry)?;
    let prefix = projection.len() - payload.len();
    if (mixed && prefix != 193) || (exit && prefix != if remaining == 0 { 192 } else { 240 }) {
        return Err("projection width".into());
    }
    let core = if mixed { 3756 } else { policy::EXIT_BODY_LEN };
    let mut effects = b"KPXAEF01".to_vec();
    effects.extend(&projection[..prefix]);
    effects.extend(&payload[..core]);
    let effects = hash(&effects);
    let mut journal = b"KPXAJR01".to_vec();
    journal.extend(policy::DOMAIN);
    journal.extend(component);
    journal.extend(hash(&projection));
    let exit_statement = if exit {
        let mut b = b"KPXAEX01".to_vec();
        b.extend(policy::DOMAIN);
        b.extend(&state[40..72]);
        b.extend(&payload[440..472]);
        b.extend(effects);
        b.extend(payout.to_le_bytes());
        b.extend(fee.to_le_bytes());
        Some(hex::encode(b))
    } else {
        None
    };
    let non = calc.calc_non_contextual_masses(&tx);
    let normalized =
        Mass::new(non, contextual).normalized_max(&TESTNET_PARAMS.block_mass_limits.cofactors());
    Ok(
        json!({"schema":"local-private-payment-native-body-codec/v1","classification":"PUBLIC_BODY_CODEC_NOT_NATIVE_OR_G16_ACCEPTANCE",
        "mode":if mixed {"mixed"}else{"exit"},"case":{"transaction":tx,"entries":entries},
        "financial_projection_hex":hex::encode(&projection),"financial_projection_bytes":projection.len(),
        "financial_projection_sha256":hex::encode(hash(&projection)),"native_prefix_bytes":prefix,
        "effects_digest_hex32":hex::encode(effects),"exit_statement_hex152":exit_statement,
        "journal_hex104":hex::encode(&journal),"journal_sha256":hex::encode(hash(&journal)),
        "outer_image_hex32":hex::encode(image),"component_profile_sha256":hex::encode(component),
        "exit_vk_sha256":hex::encode(hash(exit_vk)),"witness_prefix_bytes":policy::REDEEM_START,
        "metrics":{"compute_mass":non.compute_mass,"transient_mass":non.transient_mass,"storage_mass":contextual.storage_mass,"mining_mass":normalized,
        "actual_fee_sompi":fee,"native_estimated_serialized_bytes":transaction_estimated_serialized_size(&tx),
        "allowed_script_units":tx.inputs[0].compute_commit.allowed_script_units().0},
        "native_VM_executed":false,"component_G16_or_outer_receipt_verified":false,"accepted_backing_or_currentness":false}),
    )
}
fn execute(value: Value) -> Result<Value> {
    let operation = value["operation"].as_str().ok_or("operation")?;
    let (image, component, exit_vk) = selected_parameters(&value)?;
    match operation {
        "emit" => {
            fields(
                &value,
                &[
                    "operation",
                    "state_hex112",
                    "outer_image_hex32",
                    "component_profile_sha256",
                    "exit_vk_hex328",
                ],
            )?;
            let state: [u8; 112] = bytes(&value["state_hex112"], Some(112))?
                .try_into()
                .unwrap();
            let redeem = policy::redeem(&state, &image, &component, &exit_vk)?;
            let witness = policy::witness(&[0; 128], &redeem)?;
            Ok(
                json!({"schema":"local-private-payment-native-emission/v1","classification":"EMITTED_BYTES_NOT_PROFILE_OR_ACCEPTANCE_AUTHORITY",
                "outer_image_hex32":hex::encode(image),"component_profile_sha256":hex::encode(component),
                "exit_vk_sha256":hex::encode(hash(&exit_vk)),"state_hex112":hex::encode(state),
                "redeem_hex":hex::encode(&redeem),"redeem_bytes":redeem.len(),"immutable_tail_hex":hex::encode(&redeem[114..]),
                "redeem_sha256":hex::encode(hash(&redeem)),"script_public_key":hex::encode(spk_bytes(&pay_to_script_hash_script(&redeem))),
                "zero_proof_witness_hex":hex::encode(witness),"witness_prefix_bytes":policy::REDEEM_START,
                "metadata_offsets":{"component_profile":policy::PROFILE_AT,"image":policy::IMAGE_AT,"exit_vk":policy::EXIT_VK_AT,"marker":policy::MARKER_AT},
                "native_VM_executed":false,"component_G16_or_outer_receipt_verified":false,"accepted_backing_or_currentness":false}),
            )
        }
        "body" | "normalize" => {
            fields(
                &value,
                &[
                    "operation",
                    "case",
                    "outer_image_hex32",
                    "component_profile_sha256",
                    "exit_vk_hex328",
                ],
            )?;
            body(
                &value["case"],
                &image,
                &component,
                &exit_vk,
                operation == "normalize",
            )
        }
        _ => Err("unknown_fixed_public_operation".into()),
    }
}
fn main() {
    let result = (|| -> Result<Value> {
        let mut raw = Vec::new();
        io::stdin()
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut raw)?;
        if raw.len() > 4 * 1024 * 1024 {
            return Err("public_request_width".into());
        }
        execute(serde_json::from_slice::<Unique>(&raw)?.0)
    })();
    match result {
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("LOCAL_PRIVATE_PAYMENT_NATIVE_REFUSED: {e}");
            std::process::exit(1)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> [u8; 112] {
        let mut s = [0; 112];
        s[..8].copy_from_slice(b"KPXAST01");
        s[8..40].copy_from_slice(&policy::DOMAIN);
        s[72..76].copy_from_slice(&1u32.to_le_bytes());
        s[108..112].copy_from_slice(&1u32.to_le_bytes());
        s
    }
    #[test]
    fn every_pinned_identity_changes_the_immutable_template() {
        let s = state();
        let a = policy::redeem(&s, &[7; 32], &[8; 32], &[9; 328]).unwrap();
        for b in [
            policy::redeem(&s, &[10; 32], &[8; 32], &[9; 328]).unwrap(),
            policy::redeem(&s, &[7; 32], &[10; 32], &[9; 328]).unwrap(),
            policy::redeem(&s, &[7; 32], &[8; 32], &[10; 328]).unwrap(),
        ] {
            assert_ne!(a, b);
        }
        assert_eq!(&a[policy::IMAGE_AT..policy::IMAGE_AT + 32], &[7; 32]);
        assert_eq!(&a[policy::PROFILE_AT..policy::PROFILE_AT + 32], &[8; 32]);
        assert_eq!(&a[policy::EXIT_VK_AT..policy::EXIT_VK_AT + 328], &[9; 328]);
        assert_eq!(&a[policy::MARKER_AT..policy::MARKER_AT + 8], policy::MARKER);
        let w = policy::witness(&[0; 128], &a).unwrap();
        assert_eq!(w.len(), 133 + a.len());
        assert_eq!(&w[..2], &[0x4c, 128]);
    }
    #[test]
    fn old_domain_and_unknown_parameters_refuse() {
        let mut s = state();
        s[..8].copy_from_slice(b"KPX8ST01");
        assert!(policy::redeem(&s, &[7; 32], &[8; 32], &[9; 328]).is_err());
        assert!(policy::redeem(&state(), &[0; 32], &[8; 32], &[9; 328]).is_err());
        assert!(policy::redeem(&state(), &[7; 32], &[8; 32], &[0; 328]).is_err());
        assert!(
            serde_json::from_str::<Unique>(r#"{"operation":"emit","operation":"body"}"#).is_err()
        );
        for v in [json!(true), json!(-1), json!(1.0), json!("1")] {
            assert!(integer(&v, u64::MAX).is_err());
        }
    }
}

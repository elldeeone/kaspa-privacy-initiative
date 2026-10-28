//! Public ADR-0074 native emitter/body codec; not a VM or receipt verdict.
pub(crate) mod policy;
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
pub(crate) struct Unique(pub(crate) Value);
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

pub(crate) fn array32(value: &Value) -> Result<[u8; 32]> {
    Ok(bytes(value, Some(32))?.try_into().unwrap())
}

pub(crate) fn manifest_key(value: &Value) -> Result<([u8; 328], [u8; 32])> {
    use kaspa_txscript::zk_deps::{
        ark_bn254::Bn254,
        ark_ec::AffineRepr,
        ark_groth16::VerifyingKey,
        ark_serialize::{CanonicalDeserialize, CanonicalSerialize},
    };
    fields(
        value,
        &["vk_hex328", "vk_sha256", "parameter_manifest_sha256"],
    )?;
    let raw: [u8; 328] = bytes(&value["vk_hex328"], Some(328))?.try_into().unwrap();
    let digest = array32(&value["vk_sha256"])?;
    if hash(&raw) != digest || array32(&value["parameter_manifest_sha256"])? == [0; 32] {
        return Err("component_key_or_parameter_digest".into());
    }
    let mut rest = raw.as_slice();
    let key = VerifyingKey::<Bn254>::deserialize_compressed(&mut rest)?;
    let mut canonical = Vec::new();
    key.serialize_compressed(&mut canonical)?;
    if !rest.is_empty()
        || canonical != raw
        || key.gamma_abc_g1.len() != 3
        || key.alpha_g1.is_zero()
        || key.beta_g2.is_zero()
        || key.gamma_g2.is_zero()
        || key.delta_g2.is_zero()
        || key.gamma_abc_g1.iter().any(|point| point.is_zero())
    {
        return Err("component_key_canonical_arity_or_identity".into());
    }
    Ok((raw, digest))
}

fn bind_component_manifest(raw: &[u8], p: &policy::Parameters) -> Result<()> {
    if hash(raw) != p.component {
        return Err("exact_component_manifest_sha256".into());
    }
    let file = serde_json::from_slice::<Unique>(raw)?.0;
    fields(
        &file,
        &[
            "schema",
            "selected",
            "classification",
            "chain_genesis_hex32",
            "pool_lineage_hex32",
            "profile_id_hex32",
            "domain_hex32",
            "service_policy_hex32",
            "aggregate",
            "output",
            "auth_exit",
            "value_generator_hex64",
            "blinding_generator_hex64",
            "curve_parameters_sha256",
            "input_count",
            "output_count",
            "note_floor_sompi",
            "max_value_sompi",
            "body_core_bytes",
            "body_bytes",
            "journal_bytes",
            "auth_exit_statement_bytes",
        ],
    )?;
    if file["schema"] != "private-batch-component-profile/v1"
        || file["selected"] != true
        || file["classification"] != "RESEARCH_TESTNET_ONLY"
        || integer(&file["input_count"], 3)? != 3
        || integer(&file["output_count"], 6)? != 6
        || integer(&file["note_floor_sompi"], policy::MAX)? != policy::FLOOR
        || integer(&file["max_value_sompi"], policy::MAX)? != policy::MAX
        || integer(&file["body_core_bytes"], policy::BODY_LEN as u64)? != policy::CORE_LEN as u64
        || integer(&file["body_bytes"], policy::BODY_LEN as u64)? != policy::BODY_LEN as u64
        || integer(&file["journal_bytes"], 104)? != 104
        || integer(&file["auth_exit_statement_bytes"], 152)? != 152
    {
        return Err("selected_component_manifest_shape".into());
    }
    for (key, expected) in [
        ("chain_genesis_hex32", &p.chain),
        ("pool_lineage_hex32", &p.pool),
        ("profile_id_hex32", &p.profile),
        ("domain_hex32", &p.domain),
        ("service_policy_hex32", &p.service),
    ] {
        if array32(&file[key])? != *expected {
            return Err("component_manifest_context".into());
        }
    }
    // The genuine payment guest also checks these against the inherited actual
    // relation generators. Here their exact selected bytes stay in the hash.
    bytes(&file["value_generator_hex64"], Some(64))?;
    bytes(&file["blinding_generator_hex64"], Some(64))?;
    if array32(&file["curve_parameters_sha256"])? == [0; 32] {
        return Err("selected_curve_parameter_digest".into());
    }
    let (_, aggregate) = manifest_key(&file["aggregate"])?;
    let (_, output) = manifest_key(&file["output"])?;
    let (exit_raw, exit) = manifest_key(&file["auth_exit"])?;
    if aggregate == output || aggregate == exit || output == exit || exit_raw != p.exit_vk {
        return Err("distinct_role_keys_and_selected_exit".into());
    }
    Ok(())
}

fn selected_parameters(value: &Value) -> Result<policy::Parameters> {
    fields(
        value,
        &[
            "domain_hex32",
            "chain_hex32",
            "pool_hex32",
            "profile_hex32",
            "service_hex32",
            "outer_image_hex32",
            "component_profile_sha256",
            "exit_vk_hex328",
            "component_manifest_hex",
        ],
    )?;
    let p = policy::Parameters {
        domain: array32(&value["domain_hex32"])?,
        chain: array32(&value["chain_hex32"])?,
        pool: array32(&value["pool_hex32"])?,
        profile: array32(&value["profile_hex32"])?,
        service: array32(&value["service_hex32"])?,
        image: array32(&value["outer_image_hex32"])?,
        component: array32(&value["component_profile_sha256"])?,
        exit_vk: bytes(&value["exit_vk_hex328"], Some(328))?
            .try_into()
            .unwrap(),
    };
    p.validate()?;
    bind_component_manifest(&bytes(&value["component_manifest_hex"], None)?, &p)?;
    Ok(p)
}

#[derive(Copy, Clone, PartialEq, Eq)]
enum Mode {
    Payment,
    Exit,
}

fn body_mode(payload: &[u8]) -> Result<Mode> {
    if payload.len() == policy::BODY_LEN && &payload[..8] == policy::PAYMENT_TAG {
        Ok(Mode::Payment)
    } else if payload.len() == policy::EXIT_BODY_LEN && &payload[..8] == policy::EXIT_TAG {
        Ok(Mode::Exit)
    } else {
        Err("new_profile_body_identity_or_width".into())
    }
}

fn payload_state(
    payload: &[u8],
    p: &policy::Parameters,
    mode: Mode,
    next: bool,
) -> Result<[u8; 112]> {
    let (cm, n, nf, m) = match (mode, next) {
        (_, false) => (204, 268, 236, 272),
        (Mode::Payment, true) => (284, 348, 316, 352),
        (Mode::Exit, true) => (204, 268, 316, 348),
    };
    let mut state = Vec::with_capacity(112);
    state.extend(policy::STATE_TAG);
    state.extend(p.domain);
    for (start, len) in [(cm, 32), (n, 4), (nf, 32), (m, 4)] {
        state.extend(&payload[start..start + len]);
    }
    Ok(state.try_into().map_err(|_| "reconstructed_state_width")?)
}

fn financial_projection(tx: &Transaction, entry: &UtxoEntry, mode: Mode) -> Result<Vec<u8>> {
    let input = &tx.inputs[0];
    let input_spk = spk_bytes(&entry.script_public_key);
    if input_spk.len() != 37 {
        return Err("input_SPK_width".into());
    }
    let mut raw = Vec::new();
    raw.extend(if mode == Mode::Payment {
        policy::PAYMENT_PROJECTION_TAG
    } else {
        policy::EXIT_PROJECTION_TAG
    });
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
            return Err("output_SPK_width".into());
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

pub(crate) fn canonicalize_case(value: &Value) -> Result<(Transaction, Vec<UtxoEntry>)> {
    let (mut tx, entries) = checked_case(value)?;
    let masses = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS)
        .calc_contextual_masses(&PopulatedTransaction::new(&tx, entries.clone()))
        .ok_or("storage_mass")?;
    tx.set_storage_mass(masses.storage_mass);
    tx.finalize();
    Ok((tx, entries))
}

pub(crate) fn body(value: &Value, p: &policy::Parameters, normalize: bool) -> Result<Value> {
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
    let expected = policy::redeem(&state, p)?;
    if redeem != expected || entry.script_public_key != pay_to_script_hash_script(&expected) {
        return Err("selected_current_template_SPK".into());
    }
    let payload = tx.payload.clone();
    let mode = body_mode(&payload)?;
    for (offset, expected) in [
        (8, &p.chain),
        (40, &p.pool),
        (72, &p.profile),
        (104, &p.domain),
        (136, &p.service),
    ] {
        if payload[offset..offset + 32] != *expected {
            return Err("selected_body_context".into());
        }
    }
    if payload_state(&payload, p, mode, false)? != state {
        return Err("body_old_state".into());
    }
    let next = payload_state(&payload, p, mode, true)?;
    policy::validate_state(&next, p)?;
    let old_n = u32::from_le_bytes(state[72..76].try_into()?);
    let old_m = u32::from_le_bytes(state[108..112].try_into()?);
    let new_n = u32::from_le_bytes(next[72..76].try_into()?);
    let new_m = u32::from_le_bytes(next[108..112].try_into()?);
    let reserve = number(&payload[276..284])?;
    let (remaining, fee, payout) = match mode {
        Mode::Payment => (number(&payload[356..364])?, number(&payload[364..372])?, 0),
        Mode::Exit => (
            number(&payload[352..360])?,
            number(&payload[360..368])?,
            number(&payload[368..376])?,
        ),
    };
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
        a.checked_add(o.value).ok_or("output_sum_overflow")
    })?;
    let actual_fee = entry.amount.checked_sub(outsum).ok_or("negative_fee")?;
    if payload[168..204] != point
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

    match mode {
        Mode::Payment => {
            if tx.outputs.len() != 1
                || old_n.checked_add(6) != Some(new_n)
                || old_m.checked_add(3) != Some(new_m)
                || !(policy::FLOOR..=policy::MAX).contains(&remaining)
                || tx.outputs[0].value != remaining
            {
                return Err("payment_money_or_state_counts".into());
            }
        }
        Mode::Exit => {
            if payload[284..316] == [0; 32]
                || old_n != new_n
                || state[40..72] != next[40..72]
                || old_m.checked_add(1) != Some(new_m)
                || !(policy::PAYOUT_FLOOR..=policy::MAX).contains(&payout)
                || payload[376..379] != [0, 0, 0x20]
                || payload[411] != 0xac
                || payload[412..444] == [0; 32]
                || tx.outputs.len() != if remaining == 0 { 1 } else { 2 }
                || spk_bytes(&tx.outputs.last().unwrap().script_public_key) != payload[376..412]
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
    }
    if remaining != 0 {
        let next_redeem = policy::redeem(&next, p)?;
        if tx.outputs[0].script_public_key != pay_to_script_hash_script(&next_redeem) {
            return Err("same_immutable_tail_successor".into());
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
    let projection = financial_projection(&tx, entry, mode)?;
    let prefix = projection.len() - payload.len();
    if (mode == Mode::Payment && projection.len() != policy::PROJECTION_LEN)
        || (mode == Mode::Exit && prefix != if remaining == 0 { 192 } else { 240 })
    {
        return Err("projection_width".into());
    }
    let effects = match mode {
        Mode::Payment => hash(&payload[..policy::CORE_LEN]),
        Mode::Exit => {
            let mut raw = policy::EXIT_DIGEST_TAG.to_vec();
            raw.extend(&projection);
            hash(&raw)
        }
    };
    let mut journal = policy::JOURNAL_TAG.to_vec();
    journal.extend(p.domain);
    journal.extend(p.component);
    journal.extend(hash(&projection));
    let exit_statement = if mode == Mode::Exit {
        let mut raw = policy::EXIT_STATEMENT_TAG.to_vec();
        raw.extend(p.domain);
        raw.extend(&state[40..72]);
        raw.extend(&payload[412..444]);
        raw.extend(effects);
        raw.extend(payout.to_le_bytes());
        raw.extend(fee.to_le_bytes());
        if raw.len() != 152 {
            return Err("exit_statement_width".into());
        }
        Some(hex::encode(raw))
    } else {
        None
    };
    let non = calc.calc_non_contextual_masses(&tx);
    let normalized =
        Mass::new(non, contextual).normalized_max(&TESTNET_PARAMS.block_mass_limits.cofactors());
    Ok(json!({"schema":"private-batch-native-body-codec/v1",
        "classification":"PUBLIC_BODY_CODEC_NOT_NATIVE_OR_G16_ACCEPTANCE",
        "mode":if mode == Mode::Payment {"payment"}else{"exit"},
        "case":{"transaction":tx,"entries":entries},
        "financial_projection_hex":hex::encode(&projection),"financial_projection_bytes":projection.len(),
        "financial_projection_sha256":hex::encode(hash(&projection)),"native_prefix_bytes":prefix,
        "effects_digest_hex32":hex::encode(effects),"exit_statement_hex152":exit_statement,
        "journal_hex104":hex::encode(&journal),"journal_sha256":hex::encode(hash(&journal)),
        "outer_image_hex32":hex::encode(p.image),"component_profile_sha256":hex::encode(p.component),
        "exit_vk_sha256":hex::encode(hash(&p.exit_vk)),"witness_prefix_bytes":policy::REDEEM_START,
        "metrics":{"compute_mass":non.compute_mass,"transient_mass":non.transient_mass,
        "storage_mass":contextual.storage_mass,"mining_mass":normalized,"actual_fee_sompi":fee,
        "native_estimated_serialized_bytes":transaction_estimated_serialized_size(&tx),
        "allowed_script_units":tx.inputs[0].compute_commit.allowed_script_units().0},
        "native_VM_executed":false,"component_G16_or_outer_receipt_verified":false,
        "accepted_backing_or_currentness":false}))
}

fn execute(value: Value) -> Result<Value> {
    let operation = value["operation"].as_str().ok_or("operation")?;
    let p = selected_parameters(&value["parameters"])?;
    match operation {
        "emit" => {
            fields(&value, &["operation", "parameters", "state_hex112"])?;
            let state: [u8; 112] = bytes(&value["state_hex112"], Some(112))?
                .try_into()
                .unwrap();
            let redeem = policy::redeem(&state, &p)?;
            let witness = policy::witness(&[0; 128], &redeem)?;
            Ok(json!({"schema":"private-batch-native-emission/v1",
                "classification":"EMITTED_BYTES_NOT_PROFILE_OR_ACCEPTANCE_AUTHORITY",
                "state_hex112":hex::encode(state),"redeem_hex":hex::encode(&redeem),
                "redeem_bytes":redeem.len(),"immutable_tail_hex":hex::encode(&redeem[114..]),
                "redeem_sha256":hex::encode(hash(&redeem)),
                "script_public_key":hex::encode(spk_bytes(&pay_to_script_hash_script(&redeem))),
                "zero_proof_witness_hex":hex::encode(witness),"witness_prefix_bytes":policy::REDEEM_START,
                "metadata_offsets":{"chain":policy::CHAIN_AT,"pool":policy::POOL_AT,
                "profile":policy::PROFILE_AT,"service":policy::SERVICE_AT,
                "component_manifest":policy::COMPONENT_AT,"image":policy::IMAGE_AT,
                "exit_vk":policy::EXIT_VK_AT,"marker":policy::MARKER_AT},
                "native_VM_executed":false,"component_G16_or_outer_receipt_verified":false,
                "accepted_backing_or_currentness":false}))
        }
        "body" | "normalize" => {
            fields(&value, &["operation", "parameters", "case"])?;
            body(&value["case"], &p, operation == "normalize")
        }
        "canonicalize-control" => {
            fields(&value, &["operation", "parameters", "case"])?;
            let (tx, entries) = canonicalize_case(&value["case"])?;
            Ok(
                json!({"schema":"private-batch-native-control-canonicalization/v1",
                "classification":"TEST_ONLY_ID_AND_STORAGE_MASS_NOT_FINANCIAL_OR_NATIVE_ACCEPTANCE",
                "case":{"transaction":tx,"entries":entries},"native_VM_executed":false,
                "component_G16_or_outer_receipt_verified":false}),
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
        Ok(value) => println!("{value}"),
        Err(error) => {
            eprintln!("PRIVATE_BATCH_NATIVE_REFUSED: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn params() -> policy::Parameters {
        policy::Parameters {
            domain: [1; 32],
            chain: [2; 32],
            pool: [3; 32],
            profile: [4; 32],
            service: [5; 32],
            image: [6; 32],
            component: [7; 32],
            exit_vk: [8; 328],
        }
    }
    fn state(p: &policy::Parameters) -> [u8; 112] {
        let mut out = [0; 112];
        out[..8].copy_from_slice(policy::STATE_TAG);
        out[8..40].copy_from_slice(&p.domain);
        out[72..76].copy_from_slice(&1u32.to_le_bytes());
        out[108..112].copy_from_slice(&1u32.to_le_bytes());
        out
    }
    #[test]
    fn metadata_and_every_identity_change_the_actual_immutable_tail() {
        let p = params();
        let s = state(&p);
        let baseline = policy::redeem(&s, &p).unwrap();
        for field in 0..8 {
            let mut q = p.clone();
            match field {
                0 => q.domain = [9; 32],
                1 => q.chain = [9; 32],
                2 => q.pool = [9; 32],
                3 => q.profile = [9; 32],
                4 => q.service = [9; 32],
                5 => q.image = [9; 32],
                6 => q.component = [9; 32],
                _ => q.exit_vk = [9; 328],
            }
            let altered = policy::redeem(&state(&q), &q).unwrap();
            assert_ne!(baseline, altered);
        }
        for (at, expected) in [
            (policy::CHAIN_AT, &p.chain),
            (policy::POOL_AT, &p.pool),
            (policy::PROFILE_AT, &p.profile),
            (policy::SERVICE_AT, &p.service),
            (policy::COMPONENT_AT, &p.component),
            (policy::IMAGE_AT, &p.image),
        ] {
            assert_eq!(&baseline[at..at + 32], expected);
        }
        assert_eq!(
            &baseline[policy::EXIT_VK_AT..policy::EXIT_VK_AT + 328],
            &p.exit_vk
        );
        assert_eq!(
            &baseline[policy::MARKER_AT..policy::MARKER_AT + 8],
            policy::MARKER
        );
        assert_eq!(
            policy::witness(&[0; 128], &baseline).unwrap().len(),
            133 + baseline.len()
        );
        let mut zero = p.clone();
        zero.image = [0; 32];
        assert!(policy::redeem(&s, &zero).is_err());
    }
    #[test]
    fn split_state_and_exit_statement_abi_are_distinct_from_legacy_layout() {
        let p = params();
        let mut body = vec![0; policy::BODY_LEN];
        body[..8].copy_from_slice(policy::PAYMENT_TAG);
        body[204..236].fill(11);
        body[236..268].fill(12);
        body[268..272].copy_from_slice(&4u32.to_le_bytes());
        body[272..276].copy_from_slice(&2u32.to_le_bytes());
        body[284..316].fill(13);
        body[316..348].fill(14);
        body[348..352].copy_from_slice(&10u32.to_le_bytes());
        body[352..356].copy_from_slice(&5u32.to_le_bytes());
        let old = payload_state(&body, &p, Mode::Payment, false).unwrap();
        let next = payload_state(&body, &p, Mode::Payment, true).unwrap();
        assert_eq!(&old[40..72], &[11; 32]);
        assert_eq!(&old[76..108], &[12; 32]);
        assert_eq!(&next[40..72], &[13; 32]);
        assert_eq!(&next[76..108], &[14; 32]);
        assert_eq!(u32::from_le_bytes(next[72..76].try_into().unwrap()), 10);
        assert_eq!(u32::from_le_bytes(next[108..112].try_into().unwrap()), 5);
        let exit = payload_state(&body, &p, Mode::Exit, true).unwrap();
        assert_eq!(&exit[40..72], &old[40..72]);
        assert_eq!(&exit[72..76], &old[72..76]);
        assert!(
            serde_json::from_str::<Unique>(r#"{"operation":"emit","operation":"body"}"#).is_err()
        );
    }
}

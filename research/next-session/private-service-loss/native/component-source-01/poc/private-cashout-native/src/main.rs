//! Keyless public Auth528 assembly and official native quote/Full validation.
//! No seed, signing secret, private circuit witness, PK, prover or RPC interface.
use kaspa_consensus_core::{
    hashing::sighash::SigHashReusedValuesUnsync,
    tx::{
        PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_txscript::{
    opcodes::codes::*, parse_script, pay_to_script_hash_script, script_builder::ScriptBuilder,
};
use kpi_private_exit_native::{native, policy};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

type Result<T> = std::result::Result<T, &'static str>;
const MAX: u64 = 2_870_000_000_000_000_000;
const FLOOR: u64 = 60_000_000;
const PAYOUT_FLOOR: u64 = 10_000_000;
const GENESIS: &str = "f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370";
const REQUEST_SCHEMA: &str = "kpx3-public-native-action/v1";
const RESULT_SCHEMA: &str = "kpx3-public-native-result/v1";
const ZERO_PROOF_ERROR: &str =
    "ZkIntegrity(\"ARK serialization error: the input buffer contained invalid data\")";
const QUOTE_TAG: &[u8] = b"KPX3/PUBLIC-NATIVE-QUOTE/v1\0";

#[derive(Deserialize)]
#[serde(tag = "mode", deny_unknown_fields)]
enum Request {
    #[serde(rename = "quote")]
    Quote(Action),
    #[serde(rename = "verify")]
    Verify(Action),
    #[serde(rename = "genesis")]
    Genesis(Genesis),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Point {
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Utxo {
    amount_sompi: String,
    script_public_key: String,
    block_daa_score: String,
    is_coinbase: bool,
    covenant_id: Value,
}

fn present_quote_id<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(decoder).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Action {
    schema: String,
    network_id: String,
    genesis_hash_hex: String,
    domain_hex32: String,
    current_redeem_hex: String,
    previous_outpoint: Point,
    supplied_utxo: Utxo,
    auth_hex528: String,
    cipher_hex528: String,
    public_witness_hex3344: String,
    vk_hex328: String,
    proof_hex128: String,
    fee_rate_sompi_per_mass: String,
    #[serde(default, deserialize_with = "present_quote_id")]
    expected_quote_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Genesis {
    schema: String,
    network_id: String,
    genesis_hash_hex: String,
    domain_hex32: String,
    vk_hex328: String,
    note_hex168: String,
    cipher_hex264: String,
}

fn bytes(value: &str) -> Result<Vec<u8>> {
    let result = hex::decode(value).map_err(|_| "CANONICAL_HEX_REQUIRED")?;
    if hex::encode(&result) != value {
        return Err("CANONICAL_HEX_REQUIRED");
    }
    Ok(result)
}
fn fixed<const N: usize>(value: &str) -> Result<[u8; N]> {
    bytes(value)?.try_into().map_err(|_| "HEX_WIDTH")
}
fn number(value: &str) -> Result<u64> {
    let n: u64 = value.parse().map_err(|_| "UNSIGNED_DECIMAL_REQUIRED")?;
    if n.to_string() != value {
        return Err("UNSIGNED_DECIMAL_REQUIRED");
    }
    Ok(n)
}
fn amount(value: &str) -> Result<u64> {
    let n = number(value)?;
    if n > MAX {
        return Err("AMOUNT_RANGE");
    }
    Ok(n)
}
fn n(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}
fn hash(raw: &[u8]) -> [u8; 32] {
    Sha256::digest(raw).into()
}
fn full_spk(script: &ScriptPublicKey) -> String {
    hex::encode([script.version().to_be_bytes().as_slice(), script.script()].concat())
}
fn network(schema: &str, network: &str, genesis: &str) -> Result<()> {
    if schema != REQUEST_SCHEMA || network != "testnet-10" || genesis != GENESIS {
        return Err("TN10_SCHEMA_REQUIRED");
    }
    Ok(())
}

/// Exact source-built program. Caller hashes never approve arbitrary bytecode.
fn program(state: &[u8; 112], domain: &[u8; 32], vk: &[u8; 328]) -> Result<Vec<u8>> {
    if &state[..8] != policy::STATE_MAGIC || state[8..40] != *domain {
        return Err("STATE_DOMAIN");
    }
    let mut stub = *state;
    stub[8..40].copy_from_slice(&policy::DOMAIN);
    let baseline = policy::redeem(&stub, &[0; 328]).map_err(|_| "SOURCE_PROGRAM")?;
    if baseline.len() != 24417 {
        return Err("SOURCE_PROGRAM_WIDTH");
    }
    let mut result = baseline.clone();
    result[2..114].copy_from_slice(state);
    let (mut cursor, mut domains, mut keys) = (0, 0, 0);
    for opcode in parse_script::<PopulatedTransaction<'_>, SigHashReusedValuesUnsync>(&baseline) {
        let opcode = opcode.map_err(|_| "SOURCE_OPCODE_PARSE")?;
        let encoded = opcode.serialize();
        if baseline.get(cursor..cursor + encoded.len()) != Some(encoded.as_slice()) {
            return Err("SOURCE_OPCODE_CANONICAL");
        }
        if opcode.value() == OpData32 && opcode.get_data() == policy::DOMAIN {
            result[cursor + 1..cursor + 33].copy_from_slice(domain);
            domains += 1;
        } else if opcode.value() == OpPushData2 && opcode.get_data() == [0; 328] {
            result[cursor + 3..cursor + 331].copy_from_slice(vk);
            keys += 1;
        }
        cursor += encoded.len();
    }
    if cursor != baseline.len() || domains != 10 || keys != 1 {
        return Err("SOURCE_OPERAND_LAYOUT");
    }
    Ok(result)
}

fn frame(proof: &[u8; 128], redeem: &[u8]) -> Result<Vec<u8>> {
    let mut builder = ScriptBuilder::new();
    builder
        .add_data(&[0; 65])
        .map_err(|_| "SIG_FRAME")?
        .add_data(proof)
        .map_err(|_| "PROOF_FRAME")?
        .add_data(redeem)
        .map_err(|_| "REDEEM_FRAME")?;
    let result = builder.drain();
    if result.len() != 199 + 24417 || result[0] != 65 || result[66..68] != [76, 128] {
        return Err("COMMON_FRAME");
    }
    Ok(result)
}

fn genesis(request: Genesis) -> Result<Value> {
    network(
        &request.schema,
        &request.network_id,
        &request.genesis_hash_hex,
    )?;
    let domain = fixed::<32>(&request.domain_hex32)?;
    let vk = fixed::<328>(&request.vk_hex328)?;
    let note = fixed::<168>(&request.note_hex168)?;
    let cipher = fixed::<264>(&request.cipher_hex264)?;
    let value = n(&note, 64);
    if !(FLOOR..=MAX).contains(&value) {
        return Err("GENESIS_VALUE");
    }
    // Recompute under requested D. Old policy::note_cm/singleton_state use AA.
    let cm = hash(&[b"KPX1NOT\0".as_slice(), domain.as_slice(), note.as_slice()].concat());
    let mut root = cm;
    for sibling in policy::cm_empty_siblings() {
        root = hash(&[b"KPX1CMN\0".as_slice(), root.as_slice(), sibling.as_slice()].concat());
    }
    let mut state = [0; 112];
    state[..8].copy_from_slice(policy::STATE_MAGIC);
    state[8..40].copy_from_slice(&domain);
    state[40..72].copy_from_slice(&root);
    state[72..76].copy_from_slice(&1u32.to_le_bytes());
    // Sentinel/empty NF tags contain no domain. This public helper is generic.
    state[76..108].copy_from_slice(&policy::sentinel_nf_root());
    state[108..112].copy_from_slice(&1u32.to_le_bytes());
    let redeem = program(&state, &domain, &vk)?;
    let payload = [
        b"KPX2GN01".as_slice(),
        domain.as_slice(),
        note.as_slice(),
        cm.as_slice(),
        cipher.as_slice(),
        hash(&cipher).as_slice(),
    ]
    .concat();
    if payload.len() != 536 {
        return Err("GENESIS_PAYLOAD");
    }
    Ok(
        json!({"schema":RESULT_SCHEMA,"mode":"genesis","domain_hex32":request.domain_hex32,
        "state_hex112":hex::encode(state),"redeem_hex":hex::encode(&redeem),"script_public_key_hex":full_spk(&pay_to_script_hash_script(&redeem)),
        "payload_hex536":hex::encode(payload),"reserve_sompi":value.to_string(),"note_cm_hex32":hex::encode(cm),
        "verified":false,"accepted_chain_backing_proved_here":false,"network_contacted":false,"signing_performed":false}),
    )
}

fn context(entries: &[UtxoEntry]) -> Value {
    json!(entries.iter().map(|e| json!({"amount_sompi":e.amount.to_string(),"script_public_key":full_spk(&e.script_public_key),
        "block_daa_score":e.block_daa_score.to_string(),"is_coinbase":e.is_coinbase,"covenant_id":null})).collect::<Vec<_>>())
}

fn quote_id(transaction: &Transaction, entries: &[UtxoEntry], rate: u64) -> Result<String> {
    let mut normalized = transaction.clone();
    let witness = &mut normalized.inputs[0].signature_script;
    if witness.len() != 24616
        || witness[0] != 65
        || witness[66..68] != [76, 128]
        || witness[196] != 77
    {
        return Err("QUOTE_NORMALIZATION_FRAME");
    }
    // Preserve EVERY other byte/field, including zero sig65 and all UTXO data.
    witness[68..196].fill(0);
    let raw = serde_json::to_vec(&native::ValidationCase {
        transaction: normalized,
        entries: entries.to_vec(),
    })
    .map_err(|_| "QUOTE_CASE_SERIALIZATION")?;
    let mut h = Sha256::new();
    h.update(QUOTE_TAG);
    h.update((raw.len() as u64).to_le_bytes());
    h.update(raw);
    h.update(rate.to_le_bytes());
    Ok(hex::encode(h.finalize()))
}

fn action(request: Action, verify: bool) -> Result<Value> {
    network(
        &request.schema,
        &request.network_id,
        &request.genesis_hash_hex,
    )?;
    if verify != request.expected_quote_id.is_some() {
        return Err("QUOTE_ID_MODE");
    }
    let domain = fixed::<32>(&request.domain_hex32)?;
    let vk = fixed::<328>(&request.vk_hex328)?;
    let redeem = bytes(&request.current_redeem_hex)?;
    if redeem.len() != 24417 || redeem[..2] != [76, 112] {
        return Err("CURRENT_REDEEM_FRAME");
    }
    let state: [u8; 112] = redeem[2..114].try_into().unwrap();
    if program(&state, &domain, &vk)? != redeem {
        return Err("CURRENT_PROGRAM_NOT_APPROVED");
    }
    let auth = fixed::<528>(&request.auth_hex528)?;
    let cipher = fixed::<528>(&request.cipher_hex528)?;
    let updates = fixed::<3344>(&request.public_witness_hex3344)?;
    let proof = fixed::<128>(&request.proof_hex128)?;
    if verify == (proof == [0; 128]) {
        return Err("PROOF_MODE");
    }
    let previous = fixed::<32>(&request.previous_outpoint.transaction_id)?;
    if &auth[..8] != b"KPX3AU01"
        || auth[8..40] != domain
        || auth[40..72] != previous
        || auth[72..76] != request.previous_outpoint.index.to_le_bytes()
        || auth[76..188] != state
    {
        return Err("AUTH_CURRENT_CONTEXT");
    }
    let input_spk = pay_to_script_hash_script(&redeem);
    let reserve = amount(&request.supplied_utxo.amount_sompi)?;
    let daa = number(&request.supplied_utxo.block_daa_score)?;
    if reserve != n(&auth, 188)
        || !(FLOOR..=MAX).contains(&reserve)
        || request.supplied_utxo.script_public_key != full_spk(&input_spk)
        || request.supplied_utxo.is_coinbase
        || !request.supplied_utxo.covenant_id.is_null()
    {
        return Err("ACTUAL_UTXO_CONTEXT");
    }
    let (fee, remaining, paid) = (n(&auth, 196), n(&auth, 476), n(&auth, 484));
    if !(1..=MAX).contains(&fee)
        || remaining > MAX
        || paid > MAX
        || reserve.checked_sub(fee).and_then(|r| r.checked_sub(paid)) != Some(remaining)
        || remaining != 0 && remaining < FLOOR
    {
        return Err("PUBLIC_AMOUNT_RELATION");
    }
    if paid == 0 {
        if remaining == 0 || auth[492..528] != [0; 36] {
            return Err("P0_DESTINATION");
        }
    } else if paid < PAYOUT_FLOOR || auth[492..495] != [0, 0, 32] || auth[527] != 172 {
        return Err("PAYOUT_SPK");
    }
    let next: [u8; 112] = auth[364..476].try_into().unwrap();
    if &next[..8] != policy::STATE_MAGIC || next[8..40] != domain {
        return Err("NEXT_STATE_DOMAIN");
    }
    let mut outputs = vec![];
    if remaining > 0 {
        let mut successor = redeem.clone();
        successor[2..114].copy_from_slice(&next);
        outputs.push(TransactionOutput::new(
            remaining,
            pay_to_script_hash_script(&successor),
        ));
    }
    if paid > 0 {
        outputs.push(TransactionOutput::new(
            paid,
            ScriptPublicKey::from_vec(0, auth[494..528].to_vec()),
        ));
    }
    let body = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(
                kaspa_hashes::Hash::from_bytes(previous),
                request.previous_outpoint.index,
            ),
            frame(&proof, &redeem)?,
            u64::MAX,
            1600,
        )],
        outputs,
        0,
        Default::default(),
        0,
        [auth.as_slice(), cipher.as_slice(), updates.as_slice()].concat(),
    );
    let entries = vec![UtxoEntry::new(reserve, input_spk, daa, false, None)];
    native::set_mass(&body, &entries).map_err(|_| "NATIVE_STORAGE_MASS")?;
    let metrics = native::metrics(&body, &entries).map_err(|_| "NATIVE_MASS")?;
    let mining = metrics["mining_mass"]
        .as_u64()
        .ok_or("NATIVE_MINING_MASS")?;
    let rate = number(&request.fee_rate_sompi_per_mass)?;
    if rate == 0 {
        return Err("POSITIVE_FEE_RATE");
    }
    let required = mining.checked_mul(rate).ok_or("FEE_PRODUCT_OVERFLOW")?;
    if metrics["actual_fee_sompi"] != fee {
        return Err("EXACT_NATIVE_FEE");
    }
    let quote = quote_id(&body, &entries, rate)?;
    if let Some(expected) = &request.expected_quote_id {
        fixed::<32>(expected)?;
        if expected != &quote {
            return Err("QUOTE_ID_MISMATCH");
        }
    }
    let validation = native::execute(&body, &entries);
    if verify {
        if fee < required {
            return Err("FEE_BELOW_REQUIRED");
        }
        if validation["isolation"] != "PASS"
            || validation["Full"]["accepted"] != true
            || validation["all_input_engines_accepted"] != true
            || validation["per_input_ScriptEngine"]
                .as_array()
                .map(|r| r.len())
                != Some(1)
        {
            return Err("NATIVE_FULL_REJECTED");
        }
    } else {
        let expected_full = format!("SignatureInvalid({ZERO_PROOF_ERROR})");
        if validation["isolation"] != "PASS"
            || validation["Full"]["accepted"] != false
            || validation["Full"]["typed_error"] != expected_full
            || validation["per_input_ScriptEngine"][0]["typed_error"] != ZERO_PROOF_ERROR
            || validation["per_input_ScriptEngine"][0]["units"]
                .as_u64()
                .unwrap_or(0)
                < 14750000
        {
            return Err("PUBLIC_CHECKS_DID_NOT_REACH_G16");
        }
    }
    Ok(
        json!({"schema":RESULT_SCHEMA,"mode":if verify {"verify"} else {"quote"},"quote_id":quote,
        "transaction_id":hex::encode(body.id().as_bytes()),"transaction":body,"supplied_context":context(&entries),
        "metrics":metrics,"native_validation":validation,"fee_sompi":fee.to_string(),"required_fee_sompi":required.to_string(),
        "fee_rate_sompi_per_mass":rate.to_string(),"mining_mass":mining.to_string(),
        "successor_state_hex112":if remaining>0 {Some(hex::encode(next))} else {None},
        "verified":verify,"public_checks_reached_G16":true,"accepted_chain_backing_proved_here":false,"network_contacted":false,
        "native_policy_source_sha256":hex::encode(hash(include_bytes!("../../private-exit-native/src/policy.rs")))}),
    )
}

fn parse_request(raw: &str) -> Result<Request> {
    // Derive accepts visit_seq arrays for structs. Check map form separately,
    // then deserialize ORIGINAL bytes so duplicate-field rejection is retained.
    let shape: Value = serde_json::from_str(raw).map_err(|_| "INVALID_REQUEST")?;
    let object = shape.as_object().ok_or("INVALID_REQUEST")?;
    if matches!(
        object.get("mode").and_then(Value::as_str),
        Some("quote" | "verify")
    ) {
        if !object
            .get("previous_outpoint")
            .is_some_and(Value::is_object)
            || !object.get("supplied_utxo").is_some_and(Value::is_object)
        {
            return Err("INVALID_REQUEST");
        }
    }
    serde_json::from_str(raw).map_err(|_| "INVALID_REQUEST")
}

fn main() {
    let result = (|| {
        let mut raw = String::new();
        std::io::stdin()
            .read_to_string(&mut raw)
            .map_err(|_| "STDIN")?;
        let request = parse_request(&raw)?;
        match request {
            Request::Quote(r) => action(r, false),
            Request::Verify(r) => action(r, true),
            Request::Genesis(r) => genesis(r),
        }
    })();
    match result {
        Ok(value) => {
            let _ = writeln!(std::io::stdout(), "{value}");
        }
        Err(code) => {
            let _ = writeln!(std::io::stderr(), "{code}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn genesis_json() -> Value {
        json!({"mode":"genesis","schema":REQUEST_SCHEMA,"network_id":"testnet-10","genesis_hash_hex":GENESIS,
            "domain_hex32":"11".repeat(32),"vk_hex328":"00".repeat(328),"note_hex168":"00".repeat(168),"cipher_hex264":"00".repeat(264)})
    }
    #[test]
    fn strict_map_and_duplicate_fields() {
        let g = genesis_json();
        assert!(parse_request(&g.to_string()).is_ok());
        assert!(parse_request("[]").is_err());
        let duplicate = g.to_string().replacen('{', "{\"mode\":\"genesis\",", 1);
        assert!(parse_request(&duplicate).is_err());
        let mut extra = g;
        extra["native_secret_hex32"] = json!("00".repeat(32));
        assert!(parse_request(&extra.to_string()).is_err());
    }
    #[test]
    fn actual_fresh_domain_genesis() {
        let mut g = genesis_json();
        let mut note = [0; 168];
        note[64..72].copy_from_slice(&FLOOR.to_le_bytes());
        g["note_hex168"] = hex::encode(note).into();
        let result = match parse_request(&g.to_string()).unwrap() {
            Request::Genesis(r) => genesis(r).unwrap(),
            _ => panic!(),
        };
        let state = fixed::<112>(result["state_hex112"].as_str().unwrap()).unwrap();
        assert_eq!(&state[8..40], &[0x11; 32]);
        assert_ne!(result["note_cm_hex32"], hex::encode(policy::note_cm(&note)));
        assert_eq!(
            fixed::<536>(result["payload_hex536"].as_str().unwrap()).unwrap()[8..40],
            [0x11; 32]
        );
    }
}

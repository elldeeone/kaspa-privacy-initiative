//! PK-free generic owner REVEAL construction from authenticated actual bytecode.
//! No domain-specific factory, RPC, prover, key loader or request/secret logging.
use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SigHashType,
    },
    tx::{
        PopulatedTransaction, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput, UtxoEntry,
    },
};
use kaspa_txscript::{
    opcodes::codes::*, parse_script, pay_to_script_hash_script, script_builder::ScriptBuilder,
};
use kpi_future_native_union::{native, policy};
use kpi_private_exit_native::policy as private_policy;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

type Result<T> = std::result::Result<T, &'static str>;
const MAX: u64 = 2_870_000_000_000_000_000;
const NOTE_FLOOR: u64 = 60_000_000;
const PAYOUT_FLOOR: u64 = 10_000_000;
const BUDGET: u16 = 200;
const CONSENT: &str =
    "I_ACCEPT_PUBLIC_NOTE_VALUE_COMMITMENT_NULLIFIER_KEY_AND_PAYOUT_KEY_DISCLOSURE";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Point {
    #[serde(rename = "transactionId")]
    transaction_id: String,
    index: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    mode: String,
    domain_hex32: String,
    current_redeem_hex: String,
    immutable_tail_sha256: String,
    current_script_public_key_hex: String,
    previous_outpoint: Point,
    reserve_sompi: String,
    payload_hex2029: String,
    block_daa_score: String,
    native_secret_hex32: Option<String>,
    expected_unsigned_txid_raw_hex: Option<String>,
    consent: Option<String>,
}

fn bytes(value: &str) -> Result<Vec<u8>> {
    let raw = hex::decode(value).map_err(|_| "CANONICAL_HEX_REQUIRED")?;
    if hex::encode(&raw) != value {
        return Err("CANONICAL_HEX_REQUIRED");
    }
    Ok(raw)
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

fn u64le(raw: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(raw[at..at + 8].try_into().unwrap())
}

fn full_spk(script: &ScriptPublicKey) -> String {
    hex::encode([script.version().to_be_bytes().as_slice(), script.script()].concat())
}

fn frame(signature: &[u8; 65], redeem: &[u8]) -> Result<Vec<u8>> {
    let mut builder = ScriptBuilder::new();
    builder
        .add_data(signature)
        .map_err(|_| "WITNESS_SIGNATURE")?
        .add_data(&[0; 128])
        .map_err(|_| "WITNESS_ZERO_PROOF")?
        .add_data(redeem)
        .map_err(|_| "WITNESS_REDEEM")?;
    let result = builder.drain();
    if result.len() != 199 + redeem.len() {
        return Err("CANONICAL_COMMON_WITNESS");
    }
    Ok(result)
}

struct Prepared {
    transaction: Transaction,
    entries: Vec<UtxoEntry>,
    payload: [u8; 2029],
    redeem: Vec<u8>,
    next_state: Option<[u8; 112]>,
    quote_validation: Value,
    metrics: Value,
    fee: u64,
    approved_policy: &'static str,
}

/// Approve the complete known opcode program, allowing only its documented
/// per-instance State112, literal domain operands and public VK328 operand.
/// The caller's adjacent tail digest is consistency, never software authority.
fn template_matches(
    baseline: Vec<u8>,
    template_domain: &[u8; 32],
    redeem: &[u8],
    state: &[u8; 112],
    domain: &[u8; 32],
) -> Result<bool> {
    if baseline.len() != redeem.len() {
        return Ok(false);
    }
    let mut expected = baseline.clone();
    expected[2..114].copy_from_slice(state);
    let mut cursor = 0;
    let mut domains = 0;
    let mut keys = 0;
    for opcode in parse_script::<PopulatedTransaction<'_>, SigHashReusedValuesUnsync>(&baseline) {
        let opcode = opcode.map_err(|_| "APPROVED_OPCODE_PARSE")?;
        let encoded = opcode.serialize();
        if baseline.get(cursor..cursor + encoded.len()) != Some(encoded.as_slice()) {
            return Err("APPROVED_OPCODE_ENCODING");
        }
        if opcode.value() == OpData32 && opcode.get_data() == template_domain {
            expected[cursor + 1..cursor + 33].copy_from_slice(domain);
            domains += 1;
        } else if opcode.value() == OpPushData2 && opcode.get_data() == [0; 328] {
            expected[cursor + 3..cursor + 331].copy_from_slice(&redeem[cursor + 3..cursor + 331]);
            keys += 1;
        }
        cursor += encoded.len();
    }
    // These counts are part of the exact source-approved program layout.
    if cursor != baseline.len() || domains != 10 || keys != 1 {
        return Err("APPROVED_DOMAIN_OR_VK_OPERAND_LAYOUT");
    }
    Ok(expected == redeem)
}

fn approve_program(redeem: &[u8], state: &[u8; 112], domain: &[u8; 32]) -> Result<&'static str> {
    if &state[..8] != b"KPX2ST01" {
        return Err("UNSUPPORTED_APPROVED_POLICY_VERSION");
    }
    let mut stub = [0; 112];
    stub[..8].copy_from_slice(policy::STATE_MAGIC);
    stub[72..76].copy_from_slice(&1u32.to_le_bytes());
    stub[108..112].copy_from_slice(&1u32.to_le_bytes());
    stub[8..40].copy_from_slice(&policy::DOMAIN);
    let original = policy::redeem(&stub, &[0; 328]).map_err(|_| "APPROVED_POLICY_CONSTRUCTION")?;
    if template_matches(original, &policy::DOMAIN, redeem, state, domain)? {
        return Ok("SOURCE_DERIVED_KPX2_THREE_BRANCH_UNION");
    }
    stub[8..40].copy_from_slice(&private_policy::DOMAIN);
    let private_exit =
        private_policy::redeem(&stub, &[0; 328]).map_err(|_| "APPROVED_POLICY_CONSTRUCTION")?;
    if template_matches(private_exit, &private_policy::DOMAIN, redeem, state, domain)? {
        return Ok("SOURCE_DERIVED_KPX3_UNIFIED_PRIVATE_BALANCE_UNION");
    }
    Err("APPROVED_POLICY_TEMPLATE_MISMATCH")
}

fn approved_source_sha(program: &str) -> String {
    if program == "SOURCE_DERIVED_KPX2_THREE_BRANCH_UNION" {
        hex::encode(Sha256::digest(include_bytes!(
            "../../../future-native-union/src/policy.rs"
        )))
    } else {
        hex::encode(Sha256::digest(include_bytes!(
            "../../../private-exit-native/src/policy.rs"
        )))
    }
}

fn prepare(request: &Request) -> Result<Prepared> {
    let domain = fixed::<32>(&request.domain_hex32)?;
    let redeem = bytes(&request.current_redeem_hex)?;
    if !(256..=65535).contains(&redeem.len()) || redeem[..2] != [0x4c, 0x70] {
        return Err("CANONICAL_STATE112_REDEEM");
    }
    let state: [u8; 112] = redeem[2..114].try_into().unwrap();
    let expected_magic = match &state[..8] {
        b"KPX2ST01" => b"KPX2RV01",
        b"KPX3ST01" => b"KPX3RV01",
        _ => return Err("UNSUPPORTED_STATE_VERSION"),
    };
    if state[8..40] != domain {
        return Err("DOMAIN_MISMATCH");
    }
    let approved_policy = approve_program(&redeem, &state, &domain)?;
    if fixed::<32>(&request.immutable_tail_sha256)?
        != <[u8; 32]>::from(Sha256::digest(&redeem[114..]))
    {
        return Err("IMMUTABLE_POLICY_MISMATCH");
    }
    let input_spk = pay_to_script_hash_script(&redeem);
    if full_spk(&input_spk) != request.current_script_public_key_hex {
        return Err("CURRENT_RESERVE_SPK_MISMATCH");
    }
    let payload = fixed::<2029>(&request.payload_hex2029)?;
    if &payload[..8] != expected_magic || payload[8] != 1 {
        return Err("REVEAL_MAGIC_MODE");
    }
    let reserve = amount(&request.reserve_sompi)?;
    let value = u64le(&payload, 73);
    let fee = u64le(&payload, 2013);
    let payout = u64le(&payload, 2021);
    if !(NOTE_FLOOR..=MAX).contains(&reserve)
        || !(NOTE_FLOOR..=MAX).contains(&value)
        || !(PAYOUT_FLOOR..=MAX).contains(&payout)
        || !(1..=MAX).contains(&fee)
        || payout.checked_add(fee) != Some(value)
    {
        return Err("REVEAL_VALUE_FEE_RANGE");
    }
    let remainder = reserve.checked_sub(value).ok_or("RESERVE_BELOW_CLAIM")?;
    if remainder != 0 && remainder < NOTE_FLOOR {
        return Err("REMAINDER_BELOW_PROFILE_FLOOR");
    }
    let mut outputs = vec![];
    let next_state = if remainder > 0 {
        let mut next = state;
        next[76..108].copy_from_slice(&payload[1981..2013]);
        let count = u32::from_le_bytes(state[108..112].try_into().unwrap())
            .checked_add(1)
            .ok_or("NF_COUNTER_OVERFLOW")?;
        next[108..112].copy_from_slice(&count.to_le_bytes());
        let mut successor = redeem.clone();
        successor[2..114].copy_from_slice(&next);
        if successor[114..] != redeem[114..] {
            return Err("SUCCESSOR_POLICY_CHANGED");
        }
        outputs.push(TransactionOutput::new(
            remainder,
            pay_to_script_hash_script(&successor),
        ));
        Some(next)
    } else {
        None
    };
    let pk: [u8; 32] = payload[145..177].try_into().unwrap();
    secp256k1::XOnlyPublicKey::from_slice(&pk).map_err(|_| "INVALID_PAYOUT_PUBLIC_KEY")?;
    outputs.push(TransactionOutput::new(payout, native::p2pk(&pk)));
    let mut zero_all = [0; 65];
    zero_all[64] = 1;
    let transaction = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(
                kaspa_hashes::Hash::from_bytes(fixed::<32>(
                    &request.previous_outpoint.transaction_id,
                )?),
                request.previous_outpoint.index,
            ),
            frame(&zero_all, &redeem)?,
            u64::MAX,
            BUDGET,
        )],
        outputs,
        0,
        Default::default(),
        0,
        payload.to_vec(),
    );
    let entries = vec![UtxoEntry::new(
        reserve,
        input_spk,
        number(&request.block_daa_score)?,
        false,
        None,
    )];
    native::set_mass(&transaction, &entries).map_err(|_| "NATIVE_STORAGE_MASS")?;
    let metrics = native::metrics(&transaction, &entries).map_err(|_| "NATIVE_MASS_ACCOUNTING")?;
    if metrics["actual_fee_sompi"] != fee {
        return Err("NATIVE_FEE_MISMATCH");
    }
    let validation = native::execute(&transaction, &entries);
    if validation["isolation"] != "PASS"
        || validation["Full"]["accepted"] != false
        || validation["Full"]["typed_error"] != "SignatureInvalid(EvalFalse)"
        || validation["per_input_ScriptEngine"][0]["typed_error"] != "EvalFalse"
    {
        return Err("PUBLIC_REVEAL_CHECKS_DID_NOT_REACH_OWNER_SIGNATURE");
    }
    Ok(Prepared {
        transaction,
        entries,
        payload,
        redeem,
        next_state,
        quote_validation: validation,
        metrics,
        fee,
        approved_policy,
    })
}

fn handle(request: Request) -> Result<Value> {
    if request.mode != "quote" && request.mode != "sign" {
        return Err("MODE_QUOTE_OR_SIGN_REQUIRED");
    }
    if request.mode == "quote"
        && (request.native_secret_hex32.is_some()
            || request.consent.is_some()
            || request.expected_unsigned_txid_raw_hex.is_some())
    {
        return Err("QUOTE_MUST_NOT_RECEIVE_SIGNING_SECRET_OR_CONSENT");
    }
    if request.mode == "sign" && request.consent.as_deref() != Some(CONSENT) {
        return Err("EXPLICIT_REVEAL_PRIVACY_CONSENT_REQUIRED");
    }
    let mut prepared = prepare(&request)?;
    let id = hex::encode(prepared.transaction.id().as_bytes());
    if request.mode == "quote" {
        return Ok(json!({
            "schema":"kpx-independent-native-reveal/v1","mode":"quote", "transaction_id":id,
            "mining_mass":prepared.metrics["mining_mass"],"fee_sompi":prepared.fee,
            "metrics":prepared.metrics,"public_checks_reached_owner_signature":true,
            "quote_native_validation":prepared.quote_validation,
            "approved_policy_program":prepared.approved_policy,
            "approved_policy_source_sha256":approved_source_sha(prepared.approved_policy),
            "transaction_or_revealing_payload_returned":false,"broadcast":false,
            "accepted_chain_backing_proved_here":false
        }));
    }
    let expected_id = request
        .expected_unsigned_txid_raw_hex
        .as_deref()
        .ok_or("QUOTED_TXID_REQUIRED")?;
    fixed::<32>(expected_id)?;
    if expected_id != id {
        return Err("QUOTED_TRANSACTION_CHANGED");
    }
    let secret = fixed::<32>(
        request
            .native_secret_hex32
            .as_deref()
            .ok_or("OWNER_SIGNING_KEY_REQUIRED")?,
    )?;
    let secret =
        secp256k1::SecretKey::from_slice(&secret).map_err(|_| "OWNER_SIGNING_KEY_INVALID")?;
    let secp = secp256k1::Secp256k1::new();
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &secret);
    let pk = keypair.x_only_public_key().0.serialize();
    if pk != prepared.payload[145..177] {
        return Err("OWNER_KEY_DOES_NOT_MATCH_NOTE_PAYOUT_KEY");
    }
    let signature_hash = calc_schnorr_signature_hash(
        &PopulatedTransaction::new(&prepared.transaction, prepared.entries.clone()),
        0,
        SigHashType::from_u8(1).map_err(|_| "ALL_SIGHASH_TYPE")?,
        &SigHashReusedValuesUnsync::new(),
    );
    let message = secp256k1::Message::from_digest_slice(&signature_hash.as_bytes())
        .map_err(|_| "SIGNATURE_MESSAGE")?;
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    let mut all = [0; 65];
    all[..64].copy_from_slice(signature.as_ref());
    all[64] = 1;
    prepared.transaction.inputs[0].signature_script = frame(&all, &prepared.redeem)?;
    prepared.transaction.finalize();
    native::set_mass(&prepared.transaction, &prepared.entries)
        .map_err(|_| "SIGNED_STORAGE_MASS")?;
    if hex::encode(prepared.transaction.id().as_bytes()) != id {
        return Err("SIGNED_V1_ID_CHANGED");
    }
    let validation = native::execute(&prepared.transaction, &prepared.entries);
    if validation["Full"]["accepted"] != true || validation["all_input_engines_accepted"] != true {
        return Err("AUTHORIZED_NATIVE_BODY_REJECTED");
    }
    let metrics = native::metrics(&prepared.transaction, &prepared.entries)
        .map_err(|_| "SIGNED_MASS_ACCOUNTING")?;
    if metrics != prepared.metrics {
        return Err("QUOTE_SIGNED_MASS_OR_FEE_CHANGED");
    }
    Ok(json!({
        "schema":"kpx-independent-native-reveal/v1","mode":"sign","transaction_id":id,
        "transaction":prepared.transaction,"supplied_context":native::supplied_context(&prepared.entries),
        "native_validation":validation,"metrics":metrics,"mining_mass":metrics["mining_mass"],
        "fee_sompi":prepared.fee,"successor_state_hex112":prepared.next_state.map(hex::encode),
        "original_immutable_tail_sha256":hex::encode(Sha256::digest(&prepared.redeem[114..])),
        "sighash_type":1,"signature_hash_hex32":hex::encode(signature_hash.as_bytes()),
        "approved_policy_program":prepared.approved_policy,
        "approved_policy_source_sha256":approved_source_sha(prepared.approved_policy),
        "privacy_consent":CONSENT,"broadcast":false,"accepted_chain_backing_proved_here":false
    }))
}

fn main() {
    let result = (|| {
        let mut raw = String::new();
        std::io::stdin()
            .take(1_000_001)
            .read_to_string(&mut raw)
            .map_err(|_| "REQUEST_IO")?;
        if raw.len() > 1_000_000 {
            return Err("REQUEST_EXCEEDS_CANONICAL_MAXIMUM");
        }
        let request: Request = serde_json::from_str(&raw).map_err(|_| "INVALID_HELPER_REQUEST")?;
        handle(request)
    })();
    match result {
        Ok(value) => {
            let mut out = std::io::stdout().lock();
            if serde_json::to_writer(&mut out, &value).is_err() || out.write_all(b"\n").is_err() {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("recovery native helper rejected: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_integer_and_hex_boundaries() {
        for bad in ["", "-1", "+1", "00", "01", "1.0", "18446744073709551616"] {
            assert!(number(bad).is_err());
        }
        assert_eq!(amount("0").unwrap(), 0);
        assert_eq!(amount(&MAX.to_string()).unwrap(), MAX);
        assert!(amount(&(MAX + 1).to_string()).is_err());
        assert!(fixed::<32>(&"AA".repeat(32)).is_err());
        assert!(fixed::<32>(&"00".repeat(31)).is_err());
    }
    #[test]
    fn strict_request_rejects_unknown_and_numeric_amounts() {
        assert!(serde_json::from_str::<Request>("{\"mode\":\"quote\",\"unexpected\":1}").is_err());
        assert!(serde_json::from_str::<Request>("{\"reserve_sompi\":60000000}").is_err());
    }
}

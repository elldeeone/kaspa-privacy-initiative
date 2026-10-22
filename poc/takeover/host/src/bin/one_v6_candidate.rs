//! Source-only prepared comparison of one fixed, already-public v6 bundle.
//! No proof generation, native execution, alternate fixture, or proving-key loading.
use kpi_accelerated_bn254::Verifier;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Valid};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

const SOURCE_BASE: &str = "ec6aa15d586bcc8a90f7232b433fd48d8c73d509";
const PROTOCOL_SHA256: &str = "b01cd6bbb4b0d9f097277e5986b0b4de7001b97896f5f74f3777d1ff50919932";
const FIXTURE_DIR: &str = "poc/shared-pool/evidence/2026-10-20-two-input-tn10";
const DOMAIN: &str = "d36fda2e668fa858ae852484e63ea6dabb259403901fd9c88a16e9c5b17e5baa";
const VK_SHA: &str = "9e6ab30d2442fb6ab6fbb5c8aa9f11d8f161fe47ada094d7810fd9240ee119ef";
const AUTH_SHA: &str = "04beb1a621fc1c2a96da05e9eeda47cdc0b44c1b088ccdc677b908b93987a2af";
const PROOF_SHA: &str = "01b2cdc52131f4a612fb354fb5f86e0ad7c5c5f4a2e4146d18484514180a6b9b";
const CIPHER0_SHA: &str = "9d31bd540d3d80ba16a6e9400610fbddbf64656386024dcd9c5213c403d705ff";
const CIPHER1_SHA: &str = "7d015f1a2f0a102aae90f0c8c11d6dd478eec58c96603b05789c2084d70808c4";
const CIPHER_PAIR_SHA: &str = "0b5b7654a35d68d12ab002c375a75b89cbea67ed20db3907ad3650f6728930c3";
const TXID: &str = "aa87d613bf36c6da5dfda60dd371360f5b4cfdf455f5ce74ce9795ec996db0e7";
const GENESIS: &str = "f896a3034873be1739fc4359236899fd3d65d2bc94f9780df0d0da3eb1cc4370";
const ANCHOR: &str = "4c6661670094ebad2f8de5dd1ba1187eea213cf5bd0ff9b0cd96671a5d35fc7a";
const MAX_SOMPI: u64 = 2_900_000_000_000_000_000;
const DECIMAL_INPUTS: [&str; 2] = [
    "272864832706577085329381808629324299780",
    "233458794052009950193355542024787113152",
];

#[derive(Debug)]
struct Failure {
    class: &'static str,
    message: String,
}
type Result<T> = std::result::Result<T, Failure>;

fn failure(class: &'static str, message: impl Into<String>) -> Failure {
    Failure { class, message: message.into() }
}

fn require(condition: bool, class: &'static str, message: &str) -> Result<()> {
    if condition { Ok(()) } else { Err(failure(class, message)) }
}

fn stage(report: &mut Value, name: &str) {
    report["stage"] = json!(name);
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    kpi_groth16_comparison::proxy::hash(bytes)
}

fn check_hash(bytes: &[u8], expected: &str, label: &str) -> Result<()> {
    require(
        hex::encode(hash(bytes)) == expected,
        "fixture_integrity",
        &format!("{label}: SHA-256 mismatch"),
    )
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value.get(key).and_then(Value::as_str)
        .ok_or_else(|| failure("fixture_integrity", format!("missing string field: {key}")))
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>> {
    hex::decode(value).map_err(|e| failure("fixture_integrity", format!("{label}: {e}")))
}

fn array32(bytes: &[u8], label: &str) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| failure("fixture_integrity", format!("{label}: expected 32 bytes")))
}

fn u64le(bytes: &[u8], label: &str) -> Result<u64> {
    let value: [u8; 8] = bytes.try_into()
        .map_err(|_| failure("fixture_integrity", format!("{label}: expected 8 bytes")))?;
    Ok(u64::from_le_bytes(value))
}

fn repository_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(3)
        .ok_or_else(|| failure("infrastructure", "manifest path has no repository ancestor"))?
        .canonicalize()
        .map_err(|e| failure("infrastructure", format!("repository path: {e}")))
}

// The only file-content reads in this program are these three fixed JSON files.
// Metadata/canonical-path checks reject symlinked fixture paths; no arbitrary path argument exists.
fn read_pinned_json(root: &Path, relative: &str, expected_sha: &str) -> Result<Value> {
    let expected_path = root.join(FIXTURE_DIR).join(relative);
    let actual_path = expected_path.canonicalize()
        .map_err(|e| failure("infrastructure", format!("{relative}: unavailable: {e}")))?;
    require(actual_path == expected_path, "fixture_integrity", "fixture path contains a symlink")?;
    let metadata = fs::symlink_metadata(&expected_path)
        .map_err(|e| failure("infrastructure", format!("{relative}: metadata: {e}")))?;
    require(metadata.file_type().is_file(), "fixture_integrity", "fixture is not a regular file")?;
    let raw = fs::read(&actual_path)
        .map_err(|e| failure("infrastructure", format!("{relative}: read: {e}")))?;
    check_hash(&raw, expected_sha, relative)?;
    serde_json::from_slice(&raw)
        .map_err(|e| failure("fixture_integrity", format!("{relative}: JSON: {e}")))
}

// This checks selection metadata only. It never verifies a proof or tries a fallback bundle.
fn metadata_qualifies(transaction: &Value, domain: &[u8]) -> Result<bool> {
    let Some(payload_hex) = transaction.get("payload").and_then(Value::as_str) else {
        return Ok(false);
    };
    let payload = decode_hex(payload_hex, "selection payload")?;
    if payload.len() != 5228 || &payload[..8] != b"KPICR06\0" {
        return Ok(false);
    }
    let auth = &payload[8..385];
    Ok(&auth[..8] == b"KPICU06\0"
        && &auth[8..40] == domain
        && auth[204] == 1
        && u64le(&auth[205..213], "selection payout")? == 0
        && auth[221..345].iter().all(|b| *b == 0))
}

fn decode_canonical<T: CanonicalDeserialize + CanonicalSerialize>(
    raw: &[u8], label: &str,
) -> Result<T> {
    let mut remaining = raw;
    let value = T::deserialize_compressed(&mut remaining)
        .map_err(|e| failure("canonical_decode_rejected", format!("{label}: {e}")))?;
    require(remaining.is_empty(), "canonical_decode_rejected", &format!("{label}: trailing bytes"))?;
    value.check()
        .map_err(|e| failure("canonical_decode_rejected", format!("{label}: validity: {e}")))?;
    let mut encoded = Vec::new();
    value.serialize_compressed(&mut encoded)
        .map_err(|e| failure("canonical_encoding", format!("{label}: {e}")))?;
    require(encoded == raw, "canonical_encoding", &format!("{label}: round-trip differs"))?;
    Ok(value)
}

fn encode<T: CanonicalSerialize>(value: &T, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes)
        .map_err(|e| failure("canonical_encoding", format!("{label}: {e}")))?;
    Ok(bytes)
}

fn run(report: &mut Value) -> Result<()> {
    stage(report, "fixed_input_preflight");
    require(std::env::args_os().len() == 1, "infrastructure",
        "no arguments accepted; only the three fixed original public JSON files are allowed")?;
    let root = repository_root()?;
    let descriptor = read_pinned_json(&root, "rehearsal/descriptor.json",
        "795eebdefb3eabea6446b3b1a9bd8c80e7f262fe32f7dfcf39efccbe7bbc07ac")?;
    let vk_json = read_pinned_json(&root, "verification-key.json",
        "4fd7dc563e4a1f843c99d5517485ba7664a7dcb69057784ca2fac066b20cddaf")?;
    let chain = read_pinned_json(&root, "rehearsal/chain-confirmed.json",
        "75ad01a25b1c534a59f5690c69556584a72e31cb6afeb914530104f00962b3b8")?;
    require(string(&descriptor, "format")? == "kpi-two-input-live-v1",
        "fixture_integrity", "descriptor format differs")?;
    require(string(&descriptor, "network")? == "testnet-10",
        "fixture_integrity", "descriptor network differs")?;
    require(string(&descriptor, "genesis")? == GENESIS,
        "fixture_integrity", "descriptor genesis differs")?;
    require(string(&descriptor, "vk_sha256")? == VK_SHA,
        "fixture_integrity", "descriptor VK digest differs")?;
    let expected_domain = decode_hex(DOMAIN, "compiled domain")?;
    let domain_values = descriptor.get("domain").and_then(Value::as_array)
        .ok_or_else(|| failure("fixture_integrity", "descriptor domain is not an array"))?;
    let domain: Vec<u8> = domain_values.iter().map(|v| {
        let n = v.as_u64().ok_or_else(|| failure("fixture_integrity", "noninteger domain byte"))?;
        u8::try_from(n).map_err(|_| failure("fixture_integrity", "out-of-range domain byte"))
    }).collect::<Result<_>>()?;
    require(domain == expected_domain, "fixture_integrity", "descriptor domain differs")?;

    let rows = chain.get("transactions").and_then(Value::as_array)
        .ok_or_else(|| failure("fixture_integrity", "missing transaction rows"))?;
    require(rows.len() == 15, "fixture_integrity", "public receipt row count differs")?;
    let mut first_qualifying = None;
    for (index, row) in rows.iter().enumerate() {
        let tx = row.get("transaction")
            .ok_or_else(|| failure("fixture_integrity", "missing transaction body"))?;
        if metadata_qualifies(tx, &domain)? {
            first_qualifying = Some(index);
            break;
        }
    }
    require(first_qualifying == Some(6), "fixture_integrity",
        "fixed first qualifying metadata row is not index 6")?;
    let transaction = rows[6].get("transaction")
        .ok_or_else(|| failure("fixture_integrity", "missing selected transaction"))?;
    require(string(transaction, "id")? == TXID, "fixture_integrity",
        "source-supplied selected transaction ID differs")?;
    let payload = decode_hex(string(transaction, "payload")?, "selected payload")?;
    let signature_hex = transaction.pointer("/inputs/0/signatureScript").and_then(Value::as_str)
        .ok_or_else(|| failure("fixture_integrity", "missing reserve signatureScript"))?;
    let signature = decode_hex(signature_hex, "selected signatureScript")?;
    require(payload.len() == 5228, "fixture_integrity", "selected payload length differs")?;
    require(signature.len() == 24709 && signature.starts_with(&[0x4c, 0x80]),
        "fixture_integrity", "proof push framing/length differs")?;
    let auth = &payload[8..385];
    let proof_bytes = &signature[2..130];
    let cipher0 = &payload[385..570];
    let cipher1 = &payload[570..755];
    let vk_bytes = decode_hex(string(&vk_json, "hex")?, "verification key")?;
    require(vk_bytes.len() == 328, "fixture_integrity", "verification key length differs")?;
    require(string(&vk_json, "sha256")? == VK_SHA, "fixture_integrity", "VK JSON digest differs")?;
    check_hash(&vk_bytes, VK_SHA, "verification key bytes")?;
    check_hash(auth, AUTH_SHA, "authorization")?;
    check_hash(proof_bytes, PROOF_SHA, "proof")?;
    check_hash(cipher0, CIPHER0_SHA, "ciphertext slot 0")?;
    check_hash(cipher1, CIPHER1_SHA, "ciphertext slot 1")?;
    let ordered_ciphers = [cipher0, cipher1].concat();
    check_hash(&ordered_ciphers, CIPHER_PAIR_SHA, "ordered ciphertext pair")?;
    require(hash(&ordered_ciphers).as_slice() == &auth[345..377],
        "statement_binding", "ordered ciphertext digest differs from authorization")?;
    require(&auth[..8] == b"KPICU06\0" && &auth[8..40] == domain.as_slice()
        && auth[204] == 1 && u64le(&auth[205..213], "payout")? == 0
        && auth[221..345].iter().all(|b| *b == 0),
        "statement_binding", "authorization does not match the fixed narrow profile")?;
    let count_bytes: [u8; 4] = auth[40..44].try_into()
        .map_err(|_| failure("fixture_integrity", "count length"))?;
    require(u32::from_le_bytes(count_bytes) == 9 && hex::encode(&auth[44..76]) == ANCHOR,
        "fixture_integrity", "count/anchor differs from fixed public metadata")?;
    let fee = u64le(&auth[213..221], "fee")?;
    require((1..=MAX_SOMPI).contains(&fee) && fee == 40_000_000,
        "statement_binding", "fixed fee differs or is outside relation range")?;
    let nfs = [array32(&auth[76..108], "nullifier 0")?, array32(&auth[108..140], "nullifier 1")?];
    let cms = [array32(&auth[140..172], "commitment 0")?, array32(&auth[172..204], "commitment 1")?];
    require(nfs[0] != [0; 32] && nfs[1] != [0; 32] && nfs[0] != nfs[1],
        "statement_binding", "active nullifier shape differs")?;
    require(cms[0] != [0; 32] && cms[1] != [0; 32] && cms[0] != cms[1],
        "statement_binding", "output commitment shape differs")?;

    report["fixture"] = json!({
        "verified_file_sha256": {
            "rehearsal/descriptor.json": "795eebdefb3eabea6446b3b1a9bd8c80e7f262fe32f7dfcf39efccbe7bbc07ac",
            "verification-key.json": "4fd7dc563e4a1f843c99d5517485ba7664a7dcb69057784ca2fac066b20cddaf",
            "rehearsal/chain-confirmed.json": "75ad01a25b1c534a59f5690c69556584a72e31cb6afeb914530104f00962b3b8"
        },
        "transaction_pointer": "/transactions/6/transaction",
        "source_supplied_txid": TXID,
        "consensus_id_recomputed": false,
        "authorization_payload_range": [8, 385],
        "proof_signature_script_range": [2, 130],
        "ciphertext_payload_ranges": [[385, 570], [570, 755]],
        "component_sha256": {
            "vk": hex::encode(hash(&vk_bytes)), "authorization": hex::encode(hash(auth)),
            "proof": hex::encode(hash(proof_bytes)), "ciphertext0": hex::encode(hash(cipher0)),
            "ciphertext1": hex::encode(hash(cipher1)), "ordered_ciphertexts": hex::encode(hash(&ordered_ciphers))
        },
        "domain": hex::encode(&domain), "count": 9, "anchor": ANCHOR,
        "fee_sompi": fee.to_string(), "ordered_ciphertext_binding": true
    });

    stage(report, "canonical_vk_and_proof");
    let vk: VerifyingKey<Bn254> = decode_canonical(&vk_bytes, "VK")?;
    require(vk.gamma_abc_g1.len() == 3, "statement_binding", "VK IC arity is not 3")?;
    let proof: Proof<Bn254> = decode_canonical(proof_bytes, "proof")?;
    let vk_on_curve = vk.alpha_g1.is_on_curve() && vk.beta_g2.is_on_curve()
        && vk.gamma_g2.is_on_curve() && vk.delta_g2.is_on_curve()
        && vk.gamma_abc_g1.iter().all(|p| p.is_on_curve());
    require(vk_on_curve, "canonical_decode_rejected", "VK point is off curve")?;
    let vk_subgroup = vk.alpha_g1.is_in_correct_subgroup_assuming_on_curve()
        && vk.beta_g2.is_in_correct_subgroup_assuming_on_curve()
        && vk.gamma_g2.is_in_correct_subgroup_assuming_on_curve()
        && vk.delta_g2.is_in_correct_subgroup_assuming_on_curve()
        && vk.gamma_abc_g1.iter().all(|p| p.is_in_correct_subgroup_assuming_on_curve());
    require(vk_subgroup, "canonical_decode_rejected", "VK point outside subgroup")?;
    let proof_on_curve = proof.a.is_on_curve() && proof.b.is_on_curve() && proof.c.is_on_curve();
    require(proof_on_curve, "canonical_decode_rejected", "proof point is off curve")?;
    let proof_subgroup = proof.a.is_in_correct_subgroup_assuming_on_curve()
        && proof.b.is_in_correct_subgroup_assuming_on_curve()
        && proof.c.is_in_correct_subgroup_assuming_on_curve();
    require(proof_subgroup, "canonical_decode_rejected", "proof point outside subgroup")?;
    let proof_nonidentity = !proof.a.infinity && !proof.b.infinity && !proof.c.infinity;
    report["canonical"] = json!({
        "vk_complete_consumption_and_roundtrip": true,
        "proof_complete_consumption_and_roundtrip": true,
        "vk_roundtrip_sha256": hex::encode(hash(&encode(&vk, "VK")?)),
        "proof_roundtrip_sha256": hex::encode(hash(&encode(&proof, "proof")?)),
        "vk_ic_count": vk.gamma_abc_g1.len(),
        "vk_on_curve": vk_on_curve, "vk_in_subgroup": vk_subgroup,
        "vk_identity_flags": {
            "alpha": vk.alpha_g1.infinity, "beta": vk.beta_g2.infinity,
            "gamma": vk.gamma_g2.infinity, "delta": vk.delta_g2.infinity,
            "ic": vk.gamma_abc_g1.iter().map(|p| p.infinity).collect::<Vec<_>>()
        },
        "vk_identity_policy": "reported; no additional one-sided native-key policy imposed",
        "proof_on_curve": proof_on_curve, "proof_in_subgroup": proof_subgroup,
        "proof_nonidentity": proof_nonidentity
    });
    require(proof_nonidentity, "canonical_decode_rejected", "identity proof A/B/C rejected")?;

    stage(report, "independent_authorization_inputs");
    let digest = hash(auth);
    let mut integers = [0u128; 2];
    for (i, value) in integers.iter_mut().enumerate() {
        let bytes: [u8; 16] = digest[i * 16..(i + 1) * 16].try_into()
            .map_err(|_| failure("statement_binding", "hash limb length"))?;
        *value = u128::from_le_bytes(bytes);
        require(value.to_string() == DECIMAL_INPUTS[i], "statement_binding",
            "independently derived decimal input differs")?;
    }
    let inputs = [Fr::from(integers[0]), Fr::from(integers[1])];
    let mut scalar_rows = Vec::new();
    for (i, scalar) in inputs.iter().enumerate() {
        let bytes = encode(scalar, "scalar")?;
        let mut expected = [0u8; 32];
        expected[..16].copy_from_slice(&digest[i * 16..(i + 1) * 16]);
        require(bytes == expected, "statement_binding", "canonical scalar bytes differ")?;
        let decoded: Fr = decode_canonical(&bytes, "scalar")?;
        require(decoded == *scalar, "canonical_encoding", "scalar round-trip value differs")?;
        scalar_rows.push(json!({
            "index": i, "decimal": integers[i].to_string(), "canonical_le_hex": hex::encode(&bytes),
            "complete_consumption_and_roundtrip": true
        }));
    }
    report["inputs"] = json!(scalar_rows);

    stage(report, "same_bound_statement_verification");
    // The constructor does not validate the key or authenticate its id.
    // All fixed bytes, key digest, canonical point checks and IC arity passed above.
    let key_id = hash(&vk_bytes);
    require(hex::encode(key_id) == VK_SHA, "statement_binding", "candidate key id differs")?;
    let verifier = Verifier::from_validated_program_key(&vk, key_id);
    match verifier.verify_inputs(proof_bytes, &inputs) {
        Ok(()) => {
            report["verification"] = json!({
                "attempted": true, "accepted": true, "return": "Ok(())",
                "path": "from_validated_program_key + verify_inputs; Arkworks 0.5 checked key"
            });
        }
        Err(message) => {
            report["verification"] = json!({
                "attempted": true, "accepted": false, "return": "Err", "error": message,
                "path": "from_validated_program_key + verify_inputs; Arkworks 0.5 checked key"
            });
            let class = if message == "invalid proof" { "verification_rejected" } else { "verifier_interface_error" };
            return Err(failure(class, format!("candidate verifier: {message}")));
        }
    }
    stage(report, "complete");
    Ok(())
}

fn main() -> ExitCode {
    let started = Instant::now();
    let mut report = json!({
        "schema": "kpi-one-v6-verifier-compatibility-v1",
        "implementation": "candidate-arkworks-0.5.0-substrate-bn-22108fe",
        "scope": "one fixed retained public bundle; host verification only",
        "status": "incomplete",
        "expected_source_pins": {
            "scientific_base": SOURCE_BASE, "protocol_sha256": PROTOCOL_SHA256,
            "workspace_lock_sha256": "6e2715918e0dfb9d1a9968021513065bc6653d8ae22d4b97d9b2d5e7d993e0ea"
        },
        "provenance_boundary": "source pins above are expected constants, not self-attestation of this executable",
        "external_coordinator_required": [
            "actual adapter source/commit and executable hashes", "effective dependency feature/cfg graph",
            "actual toolchain/target/build identity", "peak memory and process/resource supervision"
        ],
        "compiled_arch": std::env::consts::ARCH,
        "compiled_os": std::env::consts::OS,
        "native_execution": false, "proof_generation": false,
        "guest_execution": false, "chain_acceptance_checked": false
    });
    let outcome = run(&mut report);
    report["elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
    let code = match outcome {
        Ok(()) => {
            report["status"] = json!("pass");
            ExitCode::SUCCESS
        }
        Err(error) => {
            report["status"] = json!("failed");
            report["failure_class"] = json!(error.class);
            report["failure"] = json!(error.message);
            ExitCode::FAILURE
        }
    };
    println!("{report}");
    code
}

#[cfg(test)]
mod changed_input_control {
    use super::*;

    const CHANGED_X0: u128 = 272864832706577085329381808629324299781;

    fn scalar_rows(values: &[u128; 2], fields: &[Fr; 2]) -> Result<Value> {
        let mut rows = Vec::new();
        for (index, (integer, field)) in values.iter().zip(fields).enumerate() {
            let bytes = encode(field, "control scalar")?;
            let mut expected = [0u8; 32];
            expected[..16].copy_from_slice(&integer.to_le_bytes());
            require(bytes == expected, "canonical_encoding", "control scalar bytes differ")?;
            let decoded: Fr = decode_canonical(&bytes, "control scalar")?;
            require(decoded == *field, "canonical_encoding", "control scalar round-trip differs")?;
            rows.push(json!({
                "index": index, "decimal": integer.to_string(),
                "canonical_le_hex": hex::encode(bytes),
                "complete_consumption_and_roundtrip": true
            }));
        }
        Ok(json!(rows))
    }

    fn control(report: &mut Value) -> Result<()> {
        stage(report, "fixed_public_fixture_preflight");
        let root = repository_root()?;
        let descriptor = read_pinned_json(&root, "rehearsal/descriptor.json",
            "795eebdefb3eabea6446b3b1a9bd8c80e7f262fe32f7dfcf39efccbe7bbc07ac")?;
        let vk_json = read_pinned_json(&root, "verification-key.json",
            "4fd7dc563e4a1f843c99d5517485ba7664a7dcb69057784ca2fac066b20cddaf")?;
        let chain = read_pinned_json(&root, "rehearsal/chain-confirmed.json",
            "75ad01a25b1c534a59f5690c69556584a72e31cb6afeb914530104f00962b3b8")?;
        require(string(&descriptor, "format")? == "kpi-two-input-live-v1"
            && string(&descriptor, "network")? == "testnet-10"
            && string(&descriptor, "genesis")? == GENESIS
            && string(&descriptor, "vk_sha256")? == VK_SHA,
            "fixture_integrity", "fixed descriptor metadata differs")?;
        let domain = decode_hex(DOMAIN, "compiled domain")?;
        let descriptor_domain = descriptor.get("domain").and_then(Value::as_array)
            .ok_or_else(|| failure("fixture_integrity", "missing descriptor domain"))?;
        let descriptor_domain: Vec<u8> = descriptor_domain.iter().map(|v| {
            let integer = v.as_u64().ok_or_else(|| failure("fixture_integrity", "noninteger domain byte"))?;
            u8::try_from(integer).map_err(|_| failure("fixture_integrity", "out-of-range domain byte"))
        }).collect::<Result<_>>()?;
        require(descriptor_domain == domain, "fixture_integrity", "descriptor domain differs")?;
        let transaction = chain.pointer("/transactions/6/transaction")
            .ok_or_else(|| failure("fixture_integrity", "fixed transaction row unavailable"))?;
        require(string(transaction, "id")? == TXID && metadata_qualifies(transaction, &domain)?,
            "fixture_integrity", "fixed row/domain/profile differs")?;
        let payload = decode_hex(string(transaction, "payload")?, "selected payload")?;
        let signature_hex = transaction.pointer("/inputs/0/signatureScript").and_then(Value::as_str)
            .ok_or_else(|| failure("fixture_integrity", "missing reserve signatureScript"))?;
        let signature = decode_hex(signature_hex, "selected signatureScript")?;
        require(payload.len() == 5228 && payload.starts_with(b"KPICR06\0"),
            "fixture_integrity", "fixed payload framing differs")?;
        require(signature.len() == 24709 && signature.starts_with(&[0x4c, 0x80]),
            "fixture_integrity", "fixed proof framing differs")?;
        let authorization = &payload[8..385];
        let proof_bytes = &signature[2..130];
        let cipher0 = &payload[385..570];
        let cipher1 = &payload[570..755];
        let vk_bytes = decode_hex(string(&vk_json, "hex")?, "verification key")?;
        require(vk_bytes.len() == 328 && string(&vk_json, "sha256")? == VK_SHA,
            "fixture_integrity", "fixed VK framing differs")?;
        check_hash(&vk_bytes, VK_SHA, "verification key")?;
        check_hash(authorization, AUTH_SHA, "authorization")?;
        check_hash(proof_bytes, PROOF_SHA, "proof")?;
        check_hash(cipher0, CIPHER0_SHA, "ciphertext slot 0")?;
        check_hash(cipher1, CIPHER1_SHA, "ciphertext slot 1")?;
        let ordered_ciphers = [cipher0, cipher1].concat();
        check_hash(&ordered_ciphers, CIPHER_PAIR_SHA, "ordered ciphertext pair")?;
        require(hash(&ordered_ciphers).as_slice() == &authorization[345..377],
            "statement_binding", "ordered ciphertext binding differs")?;

        stage(report, "checked_key_proof_and_scalars");
        let vk: VerifyingKey<Bn254> = decode_canonical(&vk_bytes, "VK")?;
        let proof: Proof<Bn254> = decode_canonical(proof_bytes, "proof")?;
        require(vk.gamma_abc_g1.len() == 3, "statement_binding", "VK IC count is not 3")?;
        require(!proof.a.infinity && !proof.b.infinity && !proof.c.infinity,
            "canonical_decode_rejected", "identity proof point")?;
        let digest = hash(authorization);
        let mut original_integers = [0u128; 2];
        for (index, value) in original_integers.iter_mut().enumerate() {
            let limb: [u8; 16] = digest[index * 16..(index + 1) * 16].try_into()
                .map_err(|_| failure("statement_binding", "authorization hash limb length"))?;
            *value = u128::from_le_bytes(limb);
            require(value.to_string() == DECIMAL_INPUTS[index],
                "statement_binding", "original independently derived input differs")?;
        }
        let changed_x0 = original_integers[0].checked_add(1)
            .ok_or_else(|| failure("statement_binding", "x0 increment overflow"))?;
        require(changed_x0 == CHANGED_X0, "statement_binding", "changed x0 differs from frozen value")?;
        let changed_integers = [changed_x0, original_integers[1]];
        let original = [Fr::from(original_integers[0]), Fr::from(original_integers[1])];
        let changed = [Fr::from(changed_integers[0]), original[1]];
        require(original[0] != changed[0] && original[1] == changed[1],
            "statement_binding", "control must change only the first field")?;
        let original_rows = scalar_rows(&original_integers, &original)?;
        let changed_rows = scalar_rows(&changed_integers, &changed)?;
        report["fixture"] = json!({
            "transaction_pointer": "/transactions/6/transaction", "source_supplied_txid": TXID,
            "domain": DOMAIN, "vk_sha256": VK_SHA, "proof_sha256": PROOF_SHA,
            "authorization_sha256": AUTH_SHA, "ciphertext0_sha256": CIPHER0_SHA,
            "ciphertext1_sha256": CIPHER1_SHA, "ordered_ciphertexts_sha256": CIPHER_PAIR_SHA,
            "checked_canonical_vk_and_proof_roundtrips": true, "vk_ic_count": 3,
            "proof_nonidentity": true, "ordered_ciphertext_binding": true,
            "content_inputs": ["rehearsal/descriptor.json", "verification-key.json", "rehearsal/chain-confirmed.json"]
        });
        report["original"] = json!({"inputs": original_rows, "attempted": false});
        report["changed"] = json!({"inputs": changed_rows, "attempted": false, "only_change": "x0 + 1"});
        let key_id = hash(&vk_bytes);
        require(hex::encode(key_id) == VK_SHA, "statement_binding", "checked VK identity differs")?;
        let verifier = Verifier::from_validated_program_key(&vk, key_id);

        stage(report, "original_positive_control");
        report["original"]["attempted"] = json!(true);
        let original_result: std::result::Result<(), &'static str> = verifier.verify_inputs(proof_bytes, &original);
        match original_result {
            Ok(()) => report["original"]["result"] = json!({"variant": "Ok", "accepted": true, "value": "()"}),
            Err(error) => {
                report["original"]["result"] = json!({"variant": "Err", "accepted": false, "error": error, "error_type": "&'static str"});
                return Err(failure("positive_control_failed", error));
            }
        }
        stage(report, "changed_input_rejection_control");
        report["changed"]["attempted"] = json!(true);
        let changed_result: std::result::Result<(), &'static str> = verifier.verify_inputs(proof_bytes, &changed);
        match changed_result {
            Err("invalid proof") => {
                // This exact helper error is returned only after a false Groth16 pairing equation.
                report["changed"]["result"] = json!({
                    "variant": "Err", "accepted": false, "error": "invalid proof",
                    "error_type": "&'static str", "classification": "cryptographic_rejection"
                });
            }
            Err(error) => {
                report["changed"]["result"] = json!({"variant": "Err", "accepted": false, "error": error, "error_type": "&'static str"});
                return Err(failure("unexpected_verifier_error", error));
            }
            Ok(()) => {
                report["changed"]["result"] = json!({"variant": "Ok", "accepted": true, "value": "()"});
                return Err(failure("changed_input_accepted", "changed-input proof unexpectedly accepted"));
            }
        }
        stage(report, "complete");
        Ok(())
    }

    #[test]
    fn changed_first_public_input_is_cryptographically_rejected() {
        let started = Instant::now();
        let mut report = json!({
            "schema": "kpi-one-v6-input-binding-control-v1", "status": "incomplete",
            "scope": "one retained public proof; original inputs then x0 + 1 only",
            "expected_source_base": "acba8b04237e62a5bbc3eb93eb10faa1722a59ea",
            "protocol_sha256": PROTOCOL_SHA256,
            "verification_path": "checked explicit VK; from_validated_program_key + verify_inputs",
            "native_execution": false, "guest_execution": false, "proof_generation": false,
            "chain_acceptance_checked": false
        });
        let outcome = control(&mut report);
        let success = outcome.is_ok();
        if let Err(error) = outcome {
            report["failure_class"] = json!(error.class);
            report["failure"] = json!(error.message);
        }
        report["status"] = json!(if success { "pass" } else { "failed" });
        report["elapsed_seconds"] = json!(started.elapsed().as_secs_f64());
        println!("KPI_ONE_V6_INPUT_BINDING_CONTROL={report}");
        // Panics, fixture/decoder failures and every non-pairing verifier error fail the test.
        assert!(success, "changed-input control failed; see structured report");
    }
}

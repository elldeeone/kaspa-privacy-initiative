//! Qualify an established signature API against public fixtures, not payouts.
use anyhow::{ensure, Context, Result};
use curve25519_dalek::{constants::EIGHT_TORSION, scalar::Scalar};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use kpi_recovery_auth_vectors::{canonical_point, credit_message, verify_profile};
use serde_json::{json, Value};
use std::{fs, io::Write, path::Path};

fn blob(v: &Value) -> Result<Vec<u8>> {
    Ok(hex::decode(v.as_str().context("hex string")?)?)
}
fn reject(pk: &[u8], msg: &[u8], sig: &[u8], cases: &mut Vec<Value>) -> Result<()> {
    ensure!(
        verify_profile(pk, msg, sig).is_err(),
        "invalid signature/profile accepted"
    );
    cases.push(json!({"public_key":hex::encode(pk),"message":hex::encode(msg),"signature":hex::encode(sig)}));
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 4,
        "RFC_VECTORS INTENT_GOLDEN NEW_OUTPUT_DIRECTORY"
    );
    let rfc: Value = serde_json::from_slice(&fs::read(&args[1])?)?;
    let intents: Value = serde_json::from_slice(&fs::read(&args[2])?)?;
    let out = Path::new(&args[3]);
    fs::create_dir(out)?;
    let mut negative = vec![];
    let mut standard = 0;
    for v in rfc["vectors"].as_array().context("RFC vectors")? {
        let sk: [u8; 32] = blob(&v["sk"])?
            .try_into()
            .map_err(|_| anyhow::anyhow!("SK length"))?;
        let key = SigningKey::from_bytes(&sk);
        let pk = blob(&v["pk"])?;
        let msg = blob(&v["message"])?;
        let sig = blob(&v["signature"])?;
        ensure!(
            key.verifying_key().as_bytes().as_slice() == pk,
            "RFC public key mismatch"
        );
        ensure!(
            key.sign(&msg).to_bytes().as_slice() == sig,
            "RFC signature mismatch"
        );
        verify_profile(&pk, &msg, &sig)?;
        standard += 1;
        let mut bad_msg = msg.clone();
        bad_msg.push(0);
        reject(&pk, &bad_msg, &sig, &mut negative)?;
        for offset in [0, 31, 32, 63] {
            let mut bad = sig.clone();
            bad[offset] ^= 1;
            reject(&pk, &msg, &bad, &mut negative)?;
        }
        for length in [0, 31, 33] {
            reject(&vec![0; length], &msg, &sig, &mut negative)?;
        }
        for length in [0, 63, 65] {
            reject(&pk, &msg, &vec![0; length], &mut negative)?;
        }
        let mut wrong_pk = pk.clone();
        wrong_pk[0] ^= 1;
        reject(&wrong_pk, &msg, &sig, &mut negative)?;
        // Explicit group-order boundary, not a reduced/modular scalar alias.
        let order =
            hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")?;
        for scalar in [order, vec![255; 32]] {
            let mut bad = sig.clone();
            bad[32..].copy_from_slice(&scalar);
            reject(&pk, &msg, &bad, &mut negative)?;
        }
    }
    let v = &rfc["vectors"][0];
    let pk = blob(&v["pk"])?;
    let msg = blob(&v["message"])?;
    let sig = blob(&v["signature"])?;
    let other_pk = blob(&rfc["vectors"][1]["pk"])?;
    canonical_point(&other_pk)?;
    reject(&other_pk, &msg, &sig, &mut negative)?;
    let mut torsion_cases = 0;
    for torsion in EIGHT_TORSION {
        let point = torsion.compress().to_bytes();
        ensure!(
            canonical_point(&point).is_err(),
            "small-order point admitted"
        );
        reject(&point, &msg, &sig, &mut negative)?;
        let mut bad = sig.clone();
        bad[..32].copy_from_slice(&point);
        reject(&pk, &msg, &bad, &mut negative)?;
        torsion_cases += 2;
    }
    // y=p+1 and negative-zero identity aliases are valid ZIP-215 parses;
    // our candidate canonical prime-order profile rejects them explicitly.
    let mut negative_zero = [0; 32];
    negative_zero[0] = 1;
    negative_zero[31] = 128;
    let mut alias =
        hex::decode("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")?;
    let mut aliases = vec![alias.clone(), negative_zero.to_vec()];
    alias[31] |= 128;
    aliases.push(alias);
    let mut aliases_seen = 0;
    for raw in aliases {
        ensure!(
            VerifyingKey::from_bytes(raw.as_slice().try_into()?).is_ok(),
            "expected ZIP-215 parse changed"
        );
        ensure!(canonical_point(&raw).is_err(), "alias admitted");
        reject(&raw, &msg, &sig, &mut negative)?;
        let mut bad = sig.clone();
        bad[..32].copy_from_slice(&raw);
        reject(&pk, &msg, &bad, &mut negative)?;
        aliases_seen += 1;
    }
    let key = VerifyingKey::from_bytes(pk.as_slice().try_into()?)?;
    let mut mixed_cases = 0;
    for torsion in EIGHT_TORSION.into_iter().skip(1) {
        let mixed = (key.to_edwards() + torsion).compress().to_bytes();
        ensure!(
            canonical_point(&mixed).is_err(),
            "mixed-order point admitted"
        );
        reject(&mixed, &msg, &sig, &mut negative)?;
        let mut bad = sig.clone();
        bad[..32].copy_from_slice(&mixed);
        reject(&pk, &msg, &bad, &mut negative)?;
        mixed_cases += 2;
    }
    // Verify the known group-order constant's boundary semantics independently.
    let max_scalar =
        hex::decode("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")?;
    ensure!(
        bool::from(Scalar::from_canonical_bytes(max_scalar.as_slice().try_into()?).is_some()),
        "l-1 scalar not canonical"
    );
    let mut tuple_vectors = vec![];
    let sk: [u8; 32] = blob(&rfc["vectors"][0]["sk"])?
        .try_into()
        .map_err(|_| anyhow::anyhow!("SK length"))?;
    let signer = SigningKey::from_bytes(&sk);
    for v in intents["vectors"].as_array().context("intents")? {
        let g: [u8; 32] = blob(&v["intent"]["G_hash"])?
            .try_into()
            .map_err(|_| anyhow::anyhow!("G hash length"))?;
        let id: [u8; 32] = blob(&v["intentId"])?
            .try_into()
            .map_err(|_| anyhow::anyhow!("intent ID length"))?;
        let message = credit_message(&g, &id);
        let signature = signer.sign(&message).to_bytes();
        verify_profile(&pk, &message, &signature)?;
        for at in [
            0,
            kpi_recovery_auth_vectors::CREDIT_TAG.len(),
            message.len() - 1,
        ] {
            let mut changed = message.clone();
            changed[at] ^= 1;
            reject(&pk, &changed, &signature, &mut negative)?;
        }
        tuple_vectors.push(json!({"intentLabel":v["label"],"G_hash":hex::encode(g),"intent_id":hex::encode(id),
            "message":hex::encode(message),"public_key":hex::encode(&pk),"signature":hex::encode(signature)}));
    }
    let report = json!({"scope":"PUBLIC_ESTABLISHED_RECOVERY_SIGNATURE_PROFILE_NOT_NATIVE_AUTHORITY_OR_AUDIT",
        "rfc8032PlainEd25519Vectors":standard,"negativeCasesRejected":negative.len(),
        "smallOrderKeyAndRCases":torsion_cases,"noncanonicalAliases":aliases_seen,
        "mixedOrderKeyAndRCases":mixed_cases,"creditTupleVectors":tuple_vectors.len(),
        "fullWalletRelationImplemented":false,"nativeTransactions":0,
        "note":"Tuple signatures use published RFC test keys and unrelated structural intents; never fund them."});
    for (name, value) in [
        ("report.json", report.clone()),
        (
            "negative-cases.json",
            json!({"scope":"PUBLIC_INVALID_SIGNATURE_PROFILE_CASES","vectors":negative}),
        ),
        (
            "credit-tuples.json",
            json!({"scope":"SYNTHETIC_PUBLIC_CREDIT_TUPLES_NOT_VALID_PAYMENTS","vectors":tuple_vectors}),
        ),
    ] {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(out.join(name))?;
        f.write_all(&serde_json::to_vec_pretty(&value)?)?;
        f.sync_all()?;
    }
    println!("{report}");
    Ok(())
}

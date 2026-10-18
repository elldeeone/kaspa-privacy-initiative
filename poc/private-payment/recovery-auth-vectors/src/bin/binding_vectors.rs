//! Review-fix public binding vectors; no wallet/native authorization.
use anyhow::{ensure, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use kpi_recovery_auth_vectors::{
    authorization_digest, credit_message, expected_journal, parse_authorization, verify_profile,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path};

fn bytes(v: &Value) -> Result<Vec<u8>> {
    Ok(hex::decode(v.as_str().context("hex string")?)?)
}
fn a32(v: &Value) -> Result<[u8; 32]> {
    bytes(v)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("32 bytes required"))
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(a.len() == 4, "INTENT_GOLDEN RFC_VECTORS NEW_OUTPUT");
    let intents: Value = serde_json::from_slice(&fs::read(&a[1])?)?;
    let rfc: Value = serde_json::from_slice(&fs::read(&a[2])?)?;
    let signer = SigningKey::from_bytes(&a32(&rfc["vectors"][0]["sk"])?);
    let mut rows = vec![];
    let mut rejections = 0;
    let mut signature_mutations = 0;
    for v in intents["vectors"].as_array().context("golden vectors")? {
        let intent = &v["intent"];
        let kind = u8::try_from(intent["operation_kind"].as_u64().context("kind")?)?;
        let encoded = bytes(&v["encodedHex"])?;
        let id: [u8; 32] = Sha256::digest(&encoded).into();
        ensure!(id == a32(&v["intentId"])?, "golden intent digest mismatch");
        let ids = [
            a32(&intent["G_hash"])?,
            a32(&intent["statement_id"])?,
            a32(&intent["proof_suite_id"])?,
            a32(&intent["wallet_program_or_vk_hash"])?,
        ];
        let auth = if kind == 0 {
            let message = credit_message(&ids[0], &id);
            let sig = signer.sign(&message).to_bytes();
            let pk = a32(&intent["deposit_reference"]["recovery_public_key"])?;
            verify_profile(&pk, &message, &sig)?;
            [vec![1], sig.to_vec()].concat()
        } else {
            vec![0]
        };
        parse_authorization(kind, &auth)?;
        let digest = authorization_digest(kind, &auth)?;
        let journal = expected_journal(&ids, &id, &digest);
        for stop in 0..auth.len() {
            ensure!(
                parse_authorization(kind, &auth[..stop]).is_err(),
                "truncated auth accepted"
            );
            rejections += 1;
        }
        for suffix in [0u8, 1, 255] {
            let mut bad = auth.clone();
            bad.push(suffix);
            ensure!(
                parse_authorization(kind, &bad).is_err(),
                "trailing auth accepted"
            );
            rejections += 1;
        }
        for flag in [2u8, 255] {
            let mut bad = auth.clone();
            bad[0] = flag;
            ensure!(
                parse_authorization(kind, &bad).is_err(),
                "unknown flag accepted"
            );
            rejections += 1;
        }
        if kind == 0 {
            for offset in 1..65 {
                let mut changed = auth.clone();
                changed[offset] ^= 1;
                ensure!(
                    authorization_digest(kind, &changed)? != digest,
                    "signature mutation not bound"
                );
                ensure!(
                    expected_journal(&ids, &id, &authorization_digest(kind, &changed)?) != journal,
                    "auth journal alias"
                );
                ensure!(
                    verify_profile(
                        &a32(&intent["deposit_reference"]["recovery_public_key"])?,
                        &credit_message(&ids[0], &id),
                        &changed[1..]
                    )
                    .is_err(),
                    "bad signature accepted"
                );
                signature_mutations += 1;
            }
        }
        rows.push(json!({"label":v["label"],"authorizationHex":hex::encode(&auth),"authorizationDigest":hex::encode(digest),"journalHex":hex::encode(journal)}));
    }
    ensure!(
        parse_authorization(3, &[0]).is_err(),
        "unknown kind accepted"
    );
    let out = Path::new(&a[3]);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)?;
    let report = json!({"scope":"PUBLIC_AUTHORIZATION_JOURNAL_BINDING_VECTORS_NOT_PAYMENT_PROOFS","vectors":rows,"authFramingRejections":rejections,"signatureByteMutationsRejectedAndBound":signature_mutations,"actualWalletProof":false});
    f.write_all(&serde_json::to_vec_pretty(&report)?)?;
    f.sync_all()?;
    println!("binding vectors generated");
    Ok(())
}

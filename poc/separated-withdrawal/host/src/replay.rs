//! Public-only replay, without wallet backups, issuer secrets or proving keys.
use crate::{prover::Result, read, save};
use blind_rsa_signatures::{MessageRandomizer, PublicKey, Randomized, Sha384, Signature, PSS};
use kpi_batched_payment_core as app;
use kpi_private_note_wallet::protocol::*;
use serde_json::{json, Value};
use std::{collections::BTreeSet, fs, path::Path};
const TAG: &[u8] = b"KPI-anonymous-eligibility-v1\0";
fn bytes(v: &Value) -> Result<Vec<u8>> {
    Ok(hex::decode(v.as_str().ok_or("hex")?)?)
}
pub fn run(root: &Path, out: &Path) -> Result<()> {
    let configs = if root.join("configs.json").exists() {
        read(&root.join("configs.json"))?
    } else {
        json!([read(&root.join("config.json"))?])
    };
    let state: app::State = bincode::deserialize(&bytes(&configs[0]["stateBincodeHex"])?)?;
    let verifier = app::Verifier::new(&state.wallet_vk)?;
    let mut claims = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for line in fs::read_to_string(root.join("operator.jsonl"))?.lines() {
        let row: Value = serde_json::from_str(line)?;
        let r = &row["request"];
        if row["response"].get("error").is_some() {
            return Err("unexpected failed registration".into());
        }
        if r["kind"] == "issue" {
            let op: Operation = serde_json::from_value(r["operation"].clone())?;
            let s = &op.statement;
            if s.kind != EXIT || !claims.insert(s.nullifier) {
                return Err("eligibility kind/replay".into());
            }
            let mut matches = 0;
            for cfg in configs.as_array().ok_or("configs")? {
                let round: H = serde_json::from_value(cfg["round"].clone())?;
                let issuer: H = serde_json::from_value(cfg["issuer"].clone())?;
                if hash(&bytes(&cfg["issuerDer"])?) != issuer {
                    return Err("issuer fingerprint".into());
                }
                let context = hash(
                    &[
                        TAG,
                        &round,
                        &issuer,
                        &s.nullifier,
                        &bytes(&r["blindMessage"])?,
                    ]
                    .concat(),
                );
                if context == s.exit_destination
                    && cfg["principalSompi"].as_u64() == Some(s.exit_value)
                {
                    matches += 1;
                }
            }
            if matches != 1 {
                return Err("eligibility context".into());
            }
            let mut current = state.ledger.clone();
            current.apply(&verifier, &op)?;
        } else if r["kind"] == "redeem" {
            if claims.len() != 3 {
                return Err("issuance barrier".into());
            }
            let msg = bytes(&r["message"])?;
            let mut matches = 0;
            for cfg in configs.as_array().ok_or("configs")? {
                let round: H = serde_json::from_value(cfg["round"].clone())?;
                let issuer: H = serde_json::from_value(cfg["issuer"].clone())?;
                let value = cfg["principalSompi"].as_u64().ok_or("principal")?;
                let prefix = [TAG, &round, &issuer, &value.to_le_bytes()].concat();
                if msg.len() != prefix.len() + 32 || !msg.starts_with(&prefix) {
                    continue;
                }
                let pk =
                    PublicKey::<Sha384, PSS, Randomized>::from_der(&bytes(&cfg["issuerDer"])?)?;
                pk.verify(
                    &Signature(bytes(&r["signature"])?),
                    Some(MessageRandomizer(
                        bytes(&r["randomizer"])?
                            .try_into()
                            .map_err(|_| "randomizer")?,
                    )),
                    &msg,
                )?;
                let key = msg[msg.len() - 32..].to_vec();
                secp256k1::XOnlyPublicKey::from_slice(&key)?;
                if row["response"]["recipientKey"] != hex::encode(&key) || !keys.insert(key) {
                    return Err("redemption response/replay".into());
                }
                matches += 1;
            }
            if matches != 1 {
                return Err("redemption context".into());
            }
        } else {
            return Err("request kind".into());
        }
    }
    let intent: app::WithdrawalIntent = serde_json::from_value(read(&root.join("intent.json"))?)?;
    let approvals: Vec<Operation> = serde_json::from_value(read(&root.join("approvals.json"))?)?;
    intent.validate(&state, &approvals)?;
    let intent_claims = intent.claims.iter().copied().collect::<BTreeSet<_>>();
    let intent_keys = intent
        .payouts
        .iter()
        .map(|p| p[3..35].to_vec())
        .collect::<BTreeSet<_>>();
    if claims.len() != 3 || keys.len() != 3 || claims != intent_claims || keys != intent_keys {
        return Err("actual common set mismatch".into());
    }
    save(
        out,
        &json!({"genuineEligibilityProofs":3,"verifiedRfc9474Credentials":3,"exactActualClaimAndPayoutSets":true,"privateMaterialRead":false}),
    )
}

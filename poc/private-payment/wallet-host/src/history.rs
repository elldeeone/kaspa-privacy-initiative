//! Complete synthetic history pinned externally, never self-authenticating data.
use crate::{
    fixture::{self, Backup},
    scan,
    state::State,
};
use anyhow::{ensure, Context, Result};
use kpi_wallet_core::*;
use risc0_zkvm::Receipt;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub name: String,
    pub intent: String,
    pub authorization: String,
    pub receipt_sha256: String,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct History {
    pub profile: String,
    pub synthetic_policy_credit_intent: String,
    pub records: Vec<Record>,
}
pub fn load_receipt(proofs: &Path, name: &str, expected: &str) -> Result<Receipt> {
    ensure!(
        !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "unsafe history name"
    );
    let raw = fs::read(proofs.join(name).join("proof/wallet-receipt.bin"))?;
    ensure!(
        hex::encode(hash(&raw)) == expected,
        "missing/changed receipt"
    );
    crate::proof::decode_receipt(&raw)
}
pub fn replay(raw: &[u8], expected: &[u8; 32], proofs: &Path) -> Result<(State, Vec<Intent>)> {
    ensure!(
        &hash(raw) == expected,
        "missing/changed/incomplete pinned history"
    );
    let h: History = serde_json::from_slice(raw)?;
    ensure!(
        h.profile == "OFFLINE_SYNTHETIC_COMPLETE_HISTORY_V1",
        "unsupported history"
    );
    let policy = Intent::decode(&hex::decode(&h.synthetic_policy_credit_intent)?)?;
    let mut state = State::genesis(&policy)?;
    let mut accepted = Vec::new();
    for r in &h.records {
        let i = hex::decode(&r.intent)?;
        let auth = hex::decode(&r.authorization)?;
        let receipt = load_receipt(proofs, &r.name, &r.receipt_sha256)?;
        // Unavailable files/hash mismatches propagate above; they are never
        // classified as invalid accepted transactions or interpreted as zero.
        let (valid, _reason) = state.apply(&i, &auth, &receipt)?;
        if valid {
            accepted.push(Intent::decode(&i)?);
        }
    }
    state.reconcile()?;
    Ok((state, accepted))
}
pub fn keys(backup: &Backup) -> Result<Vec<[u8; 32]>> {
    ensure!(
        backup.profile == "OFFLINE_ONLY_PLAINTEXT_RESEARCH_BACKUP_V1",
        "unsupported backup"
    );
    ensure!(
        !backup.orchard_keys.is_empty(),
        "empty spending-key inventory"
    );
    let decoded = backup
        .orchard_keys
        .iter()
        .map(|s| {
            hex::decode(s)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("backup key length"))
        })
        .collect::<Result<Vec<[u8; 32]>>>()?;
    let unique: std::collections::BTreeSet<_> = decoded.iter().collect();
    ensure!(
        unique.len() == decoded.len(),
        "duplicate spending key in backup"
    );
    Ok(decoded)
}
pub fn restore(
    raw: &[u8],
    expected: &[u8; 32],
    proofs: &Path,
    backup: &Backup,
) -> Result<(State, Vec<OldNote>)> {
    let (state, history) = replay(raw, expected, proofs)?;
    ensure!(
        backup.context == state.ids.iter().map(hex::encode).collect::<Vec<_>>(),
        "backup context mismatch"
    );
    ensure!(
        backup.pending_deposit_seed.is_some() == backup.pending_deposit_reference.is_some(),
        "incomplete pending recovery inventory"
    );
    if let Some(seed) = &backup.pending_deposit_seed {
        let seed: [u8; 32] = hex::decode(seed)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("deposit seed width"))?;
        ensure!(
            ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes()
                == state.deposit.key,
            "pending recovery seed/key mismatch"
        );
        let expected = [
            state.deposit.tx.to_vec(),
            state.deposit.index.to_le_bytes().to_vec(),
            state.deposit.descriptor.to_vec(),
            state.deposit.key.to_vec(),
            state.reserve.to_le_bytes().to_vec(),
        ]
        .concat();
        ensure!(
            hex::decode(
                backup
                    .pending_deposit_reference
                    .as_ref()
                    .context("pending reference")?
            )? == expected,
            "pending deposit reference mismatch"
        );
    }
    let owned = scan::scan(&keys(backup)?, &history, &state)?;
    Ok((state, owned))
}
pub fn seal(cases: &Path, proofs: &Path, out: &Path, names: &[&str]) -> Result<[u8; 32]> {
    let mut records = Vec::new();
    for name in names {
        let i = fs::read(cases.join(name).join("intent.bin"))?;
        let a = fs::read(cases.join(name).join("authorization.bin"))?;
        let receipt = fs::read(proofs.join(name).join("proof/wallet-receipt.bin"))?;
        records.push(Record {
            name: name.to_string(),
            intent: hex::encode(i),
            authorization: hex::encode(a),
            receipt_sha256: hex::encode(hash(&receipt)),
        });
    }
    let h = History {
        profile: "OFFLINE_SYNTHETIC_COMPLETE_HISTORY_V1".into(),
        synthetic_policy_credit_intent: hex::encode(fs::read(cases.join("credit/intent.bin"))?),
        records,
    };
    let raw = serde_json::to_vec_pretty(&h)?;
    let pin = hash(&raw);
    replay(&raw, &pin, proofs)?;
    fixture::save(out, &raw)?;
    Ok(pin)
}

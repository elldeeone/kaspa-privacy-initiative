//! Wallet-local check before a blind payout credential is redeemed.
//! A server-provided transcript is evidence of genuine claims, not evidence
//! that every wallet received the transcript at the same time.
use crate::{proof::H, prover::Result};
use kpi_batched_payment_core as app;
use kpi_private_note_wallet::protocol::{EXIT, Operation, hash};
use serde_json::Value;
use std::{collections::BTreeSet, fs, path::Path};

const TAG: &[u8] = b"KPI-anonymous-eligibility-v1\0";

pub fn verify(dir: &Path, request: &Value) -> Result<()> {
    let own: Value = serde_json::from_slice(&fs::read(dir.join("registration.json"))?)?;
    let own_issue = &own["issue"];
    let config = &request["config"];
    let round: H = serde_json::from_value(config["round"].clone())?;
    let issuer: H = serde_json::from_value(config["issuer"].clone())?;
    let der = hex::decode(config["issuerDer"].as_str().ok_or("issuer key")?)?;
    if hash(&der) != issuer {
        return Err("cohort issuer key identity".into());
    }
    let principal = config["principalSompi"].as_u64().ok_or("principal")?;
    let state: app::State = bincode::deserialize(&hex::decode(
        config["stateBincodeHex"].as_str().ok_or("state")?,
    )?)?;
    let verifier = app::Verifier::new(&state.wallet_vk)?;
    // The issuer sends the public cohort with the blind-signature response.
    // This gives a dishonest issuer control over when each wallet can redeem.
    let response: Value = serde_json::from_slice(&fs::read(dir.join("issue-response.json"))?)?;
    let issues = response["cohortIssues"].as_array().ok_or("cohort issues")?;
    if issues.len() != 3 {
        return Err("complete three-claim cohort required".into());
    }
    let mut nullifiers = BTreeSet::new();
    let mut own_seen = 0;
    for issue in issues {
        if issue["kind"] != "issue" || issue.as_object().ok_or("issue object")?.len() != 3 {
            return Err("cohort issue framing".into());
        }
        let op: Operation = serde_json::from_value(issue["operation"].clone())?;
        let statement = &op.statement;
        let blind = hex::decode(issue["blindMessage"].as_str().ok_or("blind request")?)?;
        let expected = hash(&[TAG, &round, &issuer, &statement.nullifier, &blind].concat());
        if statement.kind != EXIT
            || statement.exit_value != principal
            || statement.exit_destination != expected
            || !nullifiers.insert(statement.nullifier)
        {
            return Err("cohort round, value, or unique claim mismatch".into());
        }
        // Each proof is checked against this exact public state. A coordinator
        // cannot fabricate a second owner's claim under a different round.
        state.ledger.clone().apply(&verifier, &op)?;
        if issue == own_issue {
            own_seen += 1;
        }
    }
    if own_seen != 1 {
        return Err("own issued claim missing from cohort".into());
    }
    Ok(())
}

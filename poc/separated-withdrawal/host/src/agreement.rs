//! Wallet-local check before a blind payout credential is redeemed.
//! A server-provided transcript is evidence of genuine claims, not evidence
//! that every wallet received the transcript at the same time.
use crate::{proof::H, prover::Result};
use blind_rsa_signatures::reexports::{crypto_bigint::BoxedUint, rsa};
use blind_rsa_signatures::{PSS, PublicKey, Randomized, Sha384};
use kpi_batched_payment_core as app;
use kpi_private_note_wallet::protocol::{EXIT, Operation, hash};
use rsa::traits::PublicKeyParts;
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

/// Experimental wallet check for one atomically published public payload.
/// A queued private reply is never a usable credential.
pub fn verify_board(dir: &Path, request: &Value, board_path: &Path) -> Result<()> {
    let entries = verify_board_public(&request["config"], board_path)?;
    let own: Value = serde_json::from_slice(&fs::read(dir.join("registration.json"))?)?;
    let mut own_signature = None;
    let mut issues = Vec::with_capacity(3);
    for (issue, signature) in entries {
        if issue == own["issue"] && own_signature.replace(signature).is_some() {
            return Err("duplicate own reply".into());
        }
        issues.push(issue);
    }
    let signature = own_signature.ok_or("own reply missing")?;
    fs::write(
        dir.join("issue-response.json"),
        serde_json::to_vec(&serde_json::json!({"blindSignature":signature,"cohortIssues":issues}))?,
    )?;
    verify(dir, request)
}

pub fn verify_board_public(config: &Value, board_path: &Path) -> Result<Vec<(Value, Value)>> {
    let board: Value = serde_json::from_slice(&fs::read(board_path)?)?;
    if board.as_object().ok_or("board object")?.len() != 3
        || board["version"] != 1
        || board["round"] != config["round"]
    {
        return Err("board framing or round".into());
    }
    let entries = board["entries"].as_array().ok_or("board entries")?;
    if entries.len() != 3 {
        return Err("complete three-reply board required".into());
    }
    let der = hex::decode(config["issuerDer"].as_str().ok_or("issuer key")?)?;
    let pk = PublicKey::<Sha384, PSS, Randomized>::from_der(&der)?;
    let public: &rsa::RsaPublicKey = pk.as_ref();
    let mut verified = Vec::with_capacity(3);
    for entry in entries {
        if entry.as_object().ok_or("board entry")?.len() != 2 {
            return Err("board entry framing".into());
        }
        let issue = &entry["issue"];
        let blinded = hex::decode(issue["blindMessage"].as_str().ok_or("blind request")?)?;
        let signature = hex::decode(entry["blindSignature"].as_str().ok_or("blind reply")?)?;
        if blinded.len() != public.size() || signature.len() != public.size() {
            return Err("blind reply width".into());
        }
        let bits = public.n().bits_precision();
        let blind_uint = BoxedUint::from_be_slice(&blinded, bits)?;
        let signature_uint = BoxedUint::from_be_slice(&signature, bits)?;
        if blind_uint >= public.n().as_ref().clone()
            || signature_uint >= public.n().as_ref().clone()
            || rsa::hazmat::rsa_encrypt(public, &signature_uint)? != blind_uint
        {
            // RFC9474's raw blinded RSA relation. This is not a spending
            // authorization or a replacement for final signature checking.
            return Err("invalid blinded reply".into());
        }
        verified.push((issue.clone(), entry["blindSignature"].clone()));
    }
    Ok(verified)
}

//! Deployment/observer experiment. All economic and wallet relations are reused.
#![allow(dead_code)]
#[path = "../../../cached-approval-verification/host/src/actor.rs"]
mod actor;
#[cfg(feature = "round-agreement")]
mod agreement;
#[path = "../../../cached-approval-verification/host/src/anonymous.rs"]
mod anonymous;
#[path = "../../../batched-payment-costs/host/src/circuit.rs"]
mod circuit;
#[path = "../../../batched-payment-costs/host/src/native.rs"]
mod native;
#[path = "../../../batched-payment-costs/host/src/proof.rs"]
mod proof;
#[path = "../../../batched-payment-costs/host/src/prover.rs"]
mod prover;
#[path = "../../../batched-payment-costs/host/src/receipt_script.rs"]
mod receipt_script;
mod replay;
mod tagged;
#[cfg(feature = "round-agreement")]
mod timed;

use kpi_batched_payment_core as app;
use kpi_private_note_wallet::{ledger::Ledger, protocol::*};
use prover::Result;
use rand::{RngCore, rngs::OsRng};
use serde_json::{Value, json};
use std::{fs, path::Path};
fn read(p: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}
fn save(p: &Path, v: &Value) -> Result<()> {
    prover::write(p, &serde_json::to_vec_pretty(v)?)
}
fn state(p: &Path) -> Result<app::State> {
    Ok(bincode::deserialize(&hex::decode(
        read(p)?["state"].as_str().ok_or("state")?,
    )?)?)
}
fn save_state(p: &Path, s: &app::State) -> Result<()> {
    save(
        p,
        &json!({"state":hex::encode(bincode::serialize(s)?),"root":hex::encode(s.root()),"reserveSompi":s.ledger.reserve,"liabilitySompi":s.ledger.private_liability}),
    )
}
fn fresh() -> [u8; 32] {
    let mut v = [0; 32];
    OsRng.fill_bytes(&mut v);
    v
}
fn main() -> Result<()> {
    let a = std::env::args().collect::<Vec<_>>();
    let p = |i: usize| a.get(i).map(Path::new).ok_or("path argument");
    match a.get(1).map(String::as_str) {
        Some("actor") => actor::run(p(2)?, p(3)?)?,
        Some("serve") => anonymous::serve(p(2)?, p(3)?, p(4)?, a[5].parse()?)?,
        Some("tagged-serve") => tagged::serve(p(2)?, p(3)?, p(4)?, a[5].parse()?)?,
        #[cfg(feature = "round-agreement")]
        Some("cohort-serve") => timed::serve(
            p(2)?,
            p(3)?,
            p(4)?,
            a[5].parse()?,
            a[6].as_str(),
            a.get(7).map(Path::new),
        )?,
        #[cfg(feature = "round-agreement")]
        Some("agreement-check") => agreement::verify(p(2)?, &read(p(3)?)?)?,
        #[cfg(feature = "round-agreement")]
        Some("board-check") => agreement::verify_board(p(2)?, &read(p(3)?)?, p(4)?)?,
        #[cfg(feature = "round-agreement")]
        Some("board-public-check") => {
            agreement::verify_board_public(&read(p(2)?)?, p(3)?)?;
        }
        Some("replay") => replay::run(p(2)?, p(3)?)?,
        Some("init") => {
            let addresses = read(p(2)?)?;
            let vk = app::WALLET_VK.to_vec();
            let mut ledger = Ledger::new(hash(&vk));
            let pool = fresh();
            ledger.register_authenticated_fixture_deposit(
                pool,
                4_000_000_000,
                serde_json::from_value(addresses[0]["owner"].clone())?,
            )?;
            let s = app::State {
                ledger,
                pool,
                wallet_vk: vk,
                fee_refund_spk: serde_json::from_value(addresses[0]["fundingSpk"].clone())?,
            };
            save_state(p(3)?, &s)?;
        }
        Some("apply") => {
            let mut s = state(p(2)?)?;
            let ops: Vec<Operation> = serde_json::from_value(read(p(3)?)?)?;
            let v = app::Verifier::new(&s.wallet_vk)?;
            for op in ops {
                s.ledger.apply(&v, &op)?;
            }
            save_state(p(4)?, &s)?;
        }
        Some("round") => {
            anonymous::new_round(&state(p(2)?)?, p(3)?)?;
        }
        Some("intent") => {
            let s = state(p(2)?)?;
            let rows = fs::read_to_string(p(3)?)?;
            let mut claims = vec![];
            let mut payouts = vec![];
            for l in rows.lines() {
                let r: Value = serde_json::from_str(l)?;
                if r["response"].get("error").is_some() {
                    continue;
                }
                if r["request"]["kind"] == "issue" {
                    claims.push(serde_json::from_value::<[u8; 32]>(
                        r["request"]["operation"]["statement"]["nullifier"].clone(),
                    )?);
                } else if r["request"]["kind"] == "redeem" {
                    let k = hex::decode(r["response"]["recipientKey"].as_str().ok_or("key")?)?;
                    payouts.push([vec![0, 0, 32], k, vec![0xac]].concat());
                }
            }
            if claims.len() != 3 || payouts.len() != 3 {
                return Err("incomplete cohort".into());
            }
            claims.sort();
            payouts.sort();
            let i = app::WithdrawalIntent {
                protocol_domain: domain(),
                pool: s.pool,
                verifier: s.ledger.verifier,
                reference_anchor: s.ledger.tree.root(),
                nonce: fresh(),
                refund_key_hash: hash(&s.fee_refund_spk),
                denomination: 1_000_000_000,
                fee_cap: 20_000_000,
                claims,
                payouts,
            };
            save(p(4)?, &serde_json::to_value(i)?)?;
        }
        Some("check") => {
            let s = state(p(2)?)?;
            let intent: app::WithdrawalIntent = serde_json::from_value(read(p(3)?)?)?;
            let ops: Vec<Operation> = serde_json::from_value(read(p(4)?)?)?;
            intent.validate(&s, &ops)?;
            let image = risc0_zkvm::compute_image_id(&fs::read(p(5)?)?)?
                .as_bytes()
                .try_into()?;
            let policy = native::Policy { image };
            let fee = 20_000_000u64;
            // Compute the prospective root with the same genuine Ledger rules.
            let mut next = s.clone();
            let v = app::Verifier::new(&s.wallet_vk)?;
            for op in &ops {
                next.ledger.apply(&v, op)?;
            }
            for (i, op) in ops.iter().enumerate() {
                next.ledger.confirm_authenticated_fixture_payout(
                    op.statement.id(),
                    op.statement.exit_value,
                    op.statement.exit_destination,
                    hash(&[b"projection".as_slice(), &(i as u64).to_le_bytes()].concat()),
                )?;
            }
            // Paid record IDs are normalized away by execute(); only the
            // canonical successor root is used here. No unpaid exit is erased.
            next.ledger.exits.clear();
            next.ledger.paid_native_outputs.clear();
            let mut outputs = vec![app::NativeOutput {
                value: next.ledger.reserve + 200_000_000 - fee,
                spk: native::encoded(&policy.spk(next.root())),
            }];
            outputs.extend(intent.payouts.iter().map(|p| app::NativeOutput {
                value: intent.denomination,
                spk: p.clone(),
            }));
            let input = app::Input {
                state: s,
                packet: app::Packet {
                    mode: app::JOINT,
                    operations: ops,
                    intent: Some(intent),
                },
                effects: app::Effects {
                    previous: fresh(),
                    index: 0,
                    input_value: 4_200_000_000,
                    outputs,
                },
            };
            let result = app::execute(&input)?;
            save(
                p(6)?,
                &json!({"genuineWalletProofsVerified":3,"unchangedEconomicKernel":true,"payoutSompi":result.payout_principal,"remainingPrincipalSompi":result.state.ledger.reserve,"remainingLiabilitySompi":result.state.ledger.private_liability,"feeSompi":result.fee,"outerReceiptOrNativeAcceptanceTested":false}),
            )?;
        }
        _ => return Err("actor|serve|tagged-serve|init|apply|round|intent|check".into()),
    }
    Ok(())
}

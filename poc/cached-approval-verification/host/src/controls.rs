//! Adversarial economic controls. A host closure is a test double, never a proof.
use crate::prover::Result;
use kpi_batched_payment_core as app;
use serde_json::{Value, json};
use std::{fs, path::Path};
fn certified(input: &app::Input, journal: &[u8]) -> std::result::Result<app::Output, String> {
    app::execute_with_certificate(input, journal, |_| Ok(()))
}
pub fn run(cases: &Path, out: &Path) -> Result<()> {
    let originals = (0..3)
        .map(|i| {
            bincode::deserialize::<app::Input>(&fs::read(
                cases.join(i.to_string()).join("input.bin"),
            )?)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let journal = app::authorize_packet(&originals[0])?;
    let mut results: Vec<Value> = vec![];
    for (i, input) in originals.iter().enumerate() {
        assert_eq!(journal, app::authorization_journal(input)?);
        assert_eq!(
            bincode::serialize(&app::execute(input)?)?,
            bincode::serialize(&certified(input, &journal)?)?
        );
        results.push(json!({"case":format!("context-{i}-economic-equivalence"),"accepted":true}));
    }
    let valid = &originals[0];
    let mut refuse = |name: &str, input: app::Input, layer: &str| -> Result<()> {
        let error = certified(&input, &journal)
            .err()
            .ok_or_else(|| format!("accepted {name}"))?;
        if !error.contains(layer) {
            return Err(format!("{name}: expected {layer}, got {error}").into());
        }
        results.push(json!({"case":name,"error":error}));
        Ok(())
    };
    let mut b = valid.clone();
    b.state.pool[0] ^= 1;
    refuse("cross-pool", b, "certificate exact journal")?;
    let mut b = valid.clone();
    b.state.wallet_vk[0] ^= 1;
    refuse("changed verifier", b, "certificate pinned verifier")?;
    let mut b = valid.clone();
    b.state.ledger.verifier[0] ^= 1;
    refuse(
        "changed verifier identity",
        b,
        "certificate verifier identity",
    )?;
    let mut b = valid.clone();
    b.packet.operations[0].proof[0] ^= 1;
    refuse("changed proof", b, "certificate exact journal")?;
    let mut b = valid.clone();
    b.packet.operations[0].deliveries[0].ciphertext.push(1);
    refuse("changed delivery", b, "certificate exact journal")?;
    let mut b = valid.clone();
    b.packet.intent.as_mut().unwrap().nonce[0] ^= 1;
    refuse("changed intent nonce", b, "certificate exact journal")?;
    let mut b = valid.clone();
    b.packet.intent.as_mut().unwrap().payouts[0][3] ^= 1;
    refuse("changed approved recipient", b, "certificate exact journal")?;
    let mut b = valid.clone();
    b.packet.intent.as_mut().unwrap().fee_cap += 1;
    refuse("changed approved cap", b, "certificate exact journal")?;
    let mut b = valid.clone();
    b.packet.operations.reverse();
    refuse("changed operation order", b, "certificate exact journal")?;
    let mut b = valid.clone();
    b.packet.mode = app::NAMED;
    refuse("changed mode", b, "certificate exact journal")?;
    let mut b = valid.clone();
    b.state
        .ledger
        .nullifiers
        .insert(b.packet.operations[0].statement.nullifier);
    refuse(
        "currently spent note",
        b,
        "current economic nullifier spent",
    )?;
    let mut b = valid.clone();
    b.state
        .ledger
        .anchors
        .remove(&b.packet.intent.as_ref().unwrap().reference_anchor);
    refuse(
        "unaccepted intent anchor",
        b,
        "intent accepted reference anchor",
    )?;
    let mut b = valid.clone();
    b.effects.outputs[1].spk[3] ^= 1;
    refuse("actual payout substitution", b, "intent actual payout set")?;
    let mut b = valid.clone();
    b.effects.outputs[0].value = b.effects.input_value
        - 3 * b.packet.intent.as_ref().unwrap().denomination
        - b.packet.intent.as_ref().unwrap().fee_cap
        - 1;
    refuse("actual fee exceeds consent", b, "intent fee cap")?;
    let mut b = valid.clone();
    b.effects.input_value = 0;
    refuse("missing native backing", b, "native input backing")?;
    let mut b = valid.clone();
    b.effects.outputs[0].value = u64::MAX;
    refuse("output range", b, "native output range")?;
    let mut b = valid.clone();
    b.effects.outputs[0].value = b.effects.input_value + 1;
    refuse("native inflation", b, "native value inflation")?;
    let mut b = valid.clone();
    b.effects.outputs.clear();
    refuse("missing native outputs", b, "native output count")?;
    let mut b = valid.clone();
    b.effects.outputs[0].value = 0;
    refuse("zero output", b, "native output range")?;
    let mut b = valid.clone();
    b.effects.input_value = app::MAX_SOMPI + 1;
    refuse("input above supply bound", b, "native input range")?;
    let mut b = valid.clone();
    let output = b.effects.outputs[0].clone();
    b.effects.outputs = vec![output; 8];
    for o in &mut b.effects.outputs {
        o.value = app::MAX_SOMPI;
    }
    refuse(
        "checked output sum overflow",
        b,
        "native output sum overflow",
    )?;
    let mut b = valid.clone();
    b.effects.input_value = app::MAX_SOMPI;
    b.effects.outputs[0].value = app::MAX_SOMPI
        - 3 * b.packet.intent.as_ref().unwrap().denomination
        - app::execute(valid)?.fee;
    certified(&b, &journal)?;
    results.push(json!({"case":"maximum canonical input and exact backing arithmetic","hostAccepted":true,"suppliedStateOnly":true}));
    for (name, mut b, expected) in [
        (
            "fresh validity certificate with changed consent",
            valid.clone(),
            "complete native effects authorization",
        ),
        (
            "fresh validity certificate for unknown mode",
            valid.clone(),
            "packet mode",
        ),
    ] {
        if name.contains("consent") {
            b.packet.intent.as_mut().unwrap().nonce[0] ^= 1;
        } else {
            b.packet.mode = 255;
        }
        let static_journal = app::authorize_packet(&b)?;
        let error = certified(&b, &static_journal)
            .err()
            .ok_or("static validity became spending authority")?;
        if !error.contains(expected) {
            return Err(format!("wrong semantic refusal: {error}").into());
        }
        results.push(
            json!({"case":name,"staticProofValidityAccepted":true,"freshEconomicError":error}),
        );
    }
    let mut b = valid.clone();
    b.effects.previous[0] ^= 1;
    let new = certified(&b, &journal)?;
    assert_ne!(new.journal, certified(valid, &journal)?.journal);
    results.push(json!({"case":"new native predecessor requires different final claim","differentFinalJournal":true}));
    let error =
        app::execute_with_certificate(valid, &journal, |_| Err("missing verified receipt".into()))
            .err()
            .ok_or("ignored certificate verifier")?;
    results.push(json!({"case":"certificate verifier failure propagated","error":error}));
    let mut changed = valid.clone();
    changed.packet.operations[0].proof[0] ^= 1;
    assert!(app::authorize_packet(&changed).is_err());
    results.push(json!({"case":"corrupt proof cannot create certificate","rejected":true}));
    let mut trailing = valid.packet.bytes();
    trailing.push(0);
    assert!(app::Packet::read(&trailing).is_err());
    results.push(json!({"case":"trailing packet bytes","rejected":true}));
    fs::write(
        out,
        serde_json::to_vec_pretty(
            &json!({"scope":"host economic controls with explicit certificate test double; not receipt/native evidence","controls":results}),
        )?,
    )?;
    println!("{} economic controls passed", results.len());
    Ok(())
}

//! Mutate genuine transactions below all friendly builder checks. In particular,
//! state-retention controls update the successor hash too, avoiding a trivial
//! unrelated hash failure. Rejection must come from the native settlement rules.
use super::*;
use serde_json::{Value, json};
use std::path::Path;
fn raw_state_script(
    d: &H,
    state: &State,
    vk: &[u8],
) -> Result<kaspa_consensus_core::tx::ScriptPublicKey> {
    let valid = State {
        commitments: vec![[1; 32]],
        nullifiers: vec![],
    };
    let mut r = covenant::redeem(d, &valid, vk)?;
    r[37..37 + STATE_LEN].copy_from_slice(&state.bytes());
    Ok(pay_to_script_hash_script(&r))
}
fn replace_state(tx: &mut Transaction, d: &H, state: &State, vk: &[u8]) -> Result<()> {
    tx.payload[P_STATE..].copy_from_slice(&state.bytes());
    if tx.outputs.len() == 2 || tx.payload[P_AUTH + A_MODE] == 1 {
        tx.outputs[0].script_public_key = raw_state_script(d, state, vk)?;
    }
    Ok(())
}
fn replace_auth(tx: &mut Transaction, a: &Authorization) {
    tx.payload[P_AUTH..P_CIPHER].copy_from_slice(&a.bytes());
}
fn reject(
    results: &mut Vec<Value>,
    name: &str,
    step: u32,
    mut tx: Transaction,
    entries: &[UtxoEntry],
) -> Result<()> {
    tx.finalize();
    native::set_mass(&tx, entries)?;
    let error = native::validate(&tx, entries)
        .err()
        .ok_or_else(|| format!("native accepted hostile {name} at step {step}"))?;
    results
        .push(json!({"step":step,"control":name,"rejected":true,"native_error":error.to_string()}));
    Ok(())
}
pub fn run(public: &Path) -> Result<Value> {
    let (m, vk) = experiment::manifest(public)?;
    let h = experiment::history(public, 5, &m, &vk)?;
    if h.reserve.is_some() {
        return Err("control workload did not drain".into());
    }
    let mut results = Vec::new();
    for step in 1usize..=5 {
        let tx = &h.transactions[step];
        let input = native::Utxo::output(&h.transactions[step - 1], 0, 0);
        let entries = vec![input.entry()?];
        let (a, next) = parse_payload(&tx.payload)?;
        native::validate(tx, &entries)?;
        let mut bad = tx.clone();
        bad.inputs[0].signature_script[2] ^= 1;
        reject(&mut results, "malformed proof", step as u32, bad, &entries)?;
        let mut bad = tx.clone();
        bad.payload[P_AUTH + 8] ^= 1;
        reject(
            &mut results,
            "wrong pool domain",
            step as u32,
            bad,
            &entries,
        )?;
        let mut bad = tx.clone();
        bad.payload[P_AUTH + A_ANCHOR] ^= 1;
        reject(
            &mut results,
            "false historical anchor",
            step as u32,
            bad,
            &entries,
        )?;
        let mut bad = tx.clone();
        bad.payload[P_AUTH + A_COUNT] = CAP as u8 + 1;
        reject(
            &mut results,
            "future or oversized anchor",
            step as u32,
            bad,
            &entries,
        )?;
        let mut bad = tx.clone();
        bad.inputs[0] = TransactionInput::new_with_compute_budget(
            tx.inputs[0].previous_outpoint.clone(),
            tx.inputs[0].signature_script.clone(),
            u64::MAX,
            1,
        );
        reject(
            &mut results,
            "insufficient script budget",
            step as u32,
            bad,
            &entries,
        )?;
        let mut bad = tx.clone();
        bad.outputs.push(TransactionOutput::new(
            PAYOUT_FLOOR,
            native::p2pk(&[19; 32])?,
        ));
        // Keep aggregate outputs below inputs so this is a real shape predicate.
        bad.outputs[0].value -= PAYOUT_FLOOR;
        reject(
            &mut results,
            "extra unauthorized output",
            step as u32,
            bad,
            &entries,
        )?;
        let mut bad = tx.clone();
        let mut changed = a.clone();
        changed.fee += 1;
        replace_auth(&mut bad, &changed);
        bad.outputs[0].value -= 1;
        reject(
            &mut results,
            "changed authorized fee with balanced native outputs",
            step as u32,
            bad,
            &entries,
        )?;
        let mut bad = tx.clone();
        bad.outputs[0].value -= 1;
        reject(
            &mut results,
            "reserve or payout short by one sompi",
            step as u32,
            bad,
            &entries,
        )?;
        let mut bad = tx.clone();
        let mut changed = a.clone();
        bad.payload[P_CIPHER] ^= 1;
        changed.cipher_hash = hash(&bad.payload[P_CIPHER..P_STATE]);
        replace_auth(&mut bad, &changed);
        reject(
            &mut results,
            "changed ciphertext and digest",
            step as u32,
            bad,
            &entries,
        )?;
        if step == 1 {
            let mut bad = tx.clone();
            bad.outputs[0].value += 1;
            let mut es = entries.clone();
            es[0].amount += 1;
            reject(
                &mut results,
                "initial liability does not equal backing",
                step as u32,
                bad,
                &es,
            )?;
        }
        if a.mode == 1 || tx.outputs.len() == 2 {
            let mut bad = tx.clone();
            let mut wrong_vk = vk.clone();
            wrong_vk[0] ^= 1;
            bad.outputs[0].script_public_key = raw_state_script(&m.domain, &next, &wrong_vk)?;
            reject(
                &mut results,
                "changed successor verification key",
                step as u32,
                bad,
                &entries,
            )?;
            let mut bad = tx.clone();
            let mut wrong_domain = m.domain;
            wrong_domain[0] ^= 1;
            bad.outputs[0].script_public_key = raw_state_script(&wrong_domain, &next, &vk)?;
            reject(
                &mut results,
                "changed successor pool domain",
                step as u32,
                bad,
                &entries,
            )?;
            let mut bad = tx.clone();
            let mut changed = next.clone();
            changed.commitments[0][0] ^= 1;
            replace_state(&mut bad, &m.domain, &changed, &vk)?;
            reject(
                &mut results,
                "changed retained commitment with matching successor hash",
                step as u32,
                bad,
                &entries,
            )?;
            let mut bad = tx.clone();
            let mut changed = next.clone();
            changed.nullifiers[0][0] ^= 1;
            replace_state(&mut bad, &m.domain, &changed, &vk)?;
            reject(
                &mut results,
                "dropped or changed nullifier with matching successor hash",
                step as u32,
                bad,
                &entries,
            )?;
            if next.nullifiers.len() > 1 {
                let mut bad = tx.clone();
                let mut changed = next.clone();
                changed.nullifiers.swap(0, 1);
                replace_state(&mut bad, &m.domain, &changed, &vk)?;
                reject(
                    &mut results,
                    "reordered nullifier history",
                    step as u32,
                    bad,
                    &entries,
                )?;
            }
            let mut bad = tx.clone();
            let mut changed = next.clone();
            changed.commitments.pop();
            replace_state(&mut bad, &m.domain, &changed, &vk)?;
            reject(
                &mut results,
                "dropped commitment and count",
                step as u32,
                bad,
                &entries,
            )?;
        }
        if a.mode == 1 {
            let mut bad = tx.clone();
            let mut changed = a.clone();
            let mut state = next.clone();
            changed.outputs[0][0] ^= 1;
            let n = state.commitments.len();
            state.commitments[n - 2] = changed.outputs[0];
            replace_auth(&mut bad, &changed);
            replace_state(&mut bad, &m.domain, &state, &vk)?;
            reject(
                &mut results,
                "unauthorized new commitment and consistent next state",
                step as u32,
                bad,
                &entries,
            )?;
        } else {
            let index = tx.outputs.len() - 1;
            let mut bad = tx.clone();
            let mut changed = a.clone();
            changed.spk = native::encode_spk(&native::p2pk(&[23; 32])?)
                .try_into()
                .unwrap();
            replace_auth(&mut bad, &changed);
            bad.outputs[index].script_public_key = native::decode_spk(&hex::encode(changed.spk))?;
            reject(
                &mut results,
                "changed payout recipient in authorization and output",
                step as u32,
                bad,
                &entries,
            )?;
            if index == 1 {
                let mut bad = tx.clone();
                let mut changed = a.clone();
                changed.payout += 1;
                replace_auth(&mut bad, &changed);
                bad.outputs[1].value += 1;
                bad.outputs[0].value -= 1;
                reject(
                    &mut results,
                    "changed payout value with balanced reserve",
                    step as u32,
                    bad,
                    &entries,
                )?;
                let mut bad = tx.clone();
                bad.outputs.remove(0);
                reject(
                    &mut results,
                    "terminal exit while other claims remain",
                    step as u32,
                    bad,
                    &entries,
                )?;
            }
        }
    }
    // Reuse the genuine Bob authorization after it has ALREADY been consumed.
    // There is enough reserve for this attempted theft; only current spentness
    // may decide it, not a friendly builder's duplicate-nullifier filter.
    let bob = &h.transactions[3];
    let (a, after_bob) = parse_payload(&bob.payload)?;
    let input = native::Utxo::output(bob, 0, 0);
    let mut next = after_bob.clone();
    next.nullifiers.push(a.nullifier);
    let proof = &bob.inputs[0].signature_script[2..130];
    let mut replay = bob.clone();
    replay.inputs[0].previous_outpoint = input.outpoint()?;
    replay.inputs[0].signature_script =
        covenant::signature(proof, &covenant::redeem(&m.domain, &after_bob, &vk)?)?;
    replay.outputs[0].value = input.amount - a.payout - a.fee;
    replace_state(&mut replay, &m.domain, &next, &vk)?;
    reject(
        &mut results,
        "same authorization after nullifier consumed",
        4,
        replay,
        &[input.entry()?],
    )?;

    // The old SETTLEMENT, unlike its authorization, cannot discard Alice's update.
    let before_alice = experiment::history(public, 1, &m, &vk)?;
    let bundle: Bundle = experiment::read(&public.join("bob.bundle.json"))?;
    let (mut stale, _) = settle(
        &m.domain,
        &before_alice.state,
        before_alice.reserve.as_ref().unwrap(),
        &vk,
        &bundle,
    )?;
    let after_alice = experiment::history(public, 2, &m, &vk)?;
    let current = after_alice.reserve.as_ref().unwrap();
    stale.inputs[0].previous_outpoint = current.outpoint()?;
    stale.inputs[0].signature_script = covenant::signature(
        &hex::decode(&bundle.proof)?,
        &covenant::redeem(&m.domain, &after_alice.state, &vk)?,
    )?;
    stale.outputs[0].value = current.amount - a.payout - a.fee;
    reject(
        &mut results,
        "stale settlement discards Alice payment",
        3,
        stale,
        &[current.entry()?],
    )?;
    // Explicit-context boundary fixtures, not fabricated accepted-chain history:
    // the largest reachable odd count in this transfer-only variant is 23.
    // At capacity, retaining the original proof still permits a terminal exit.
    let mut capacity = before_alice.state.clone();
    for i in capacity.commitments.len()..CAP - 1 {
        capacity.commitments.push(hash(&[b'c', i as u8]));
    }
    capacity.nullifiers = (0..CAP - 2).map(|i| hash(&[b'n', i as u8])).collect();
    let u = native::Utxo {
        txid: hex::encode([91; 32]),
        index: 0,
        amount: a.payout + a.fee,
        spk: hex::encode(native::encode_spk(&pay_to_script_hash_script(
            &covenant::redeem(&m.domain, &capacity, &vk)?,
        ))),
        daa: 0,
        is_coinbase: false,
    };
    let (terminal, es) = settle(&m.domain, &capacity, &u, &vk, &bundle)?;
    native::validate(&terminal, &es)?;
    let capacity_metrics = native::policy(&terminal, &es)?;
    if terminal.outputs.len() != 1 {
        return Err("capacity exit not terminal".into());
    }
    Ok(
        json!({"native_rejections":results.len(),"results":results,"current_nullifier_double_spend_rejected":true,
        "stale_settlement_rejected":true,"synthetic_capacity_terminal_accepted":true,"capacity_metrics":capacity_metrics}),
    )
}

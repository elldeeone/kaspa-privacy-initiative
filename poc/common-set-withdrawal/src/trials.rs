//! Actual native VM positives/negatives plus a separately labelled spentness model.
use crate::{
    native::{self, Policy},
    proof::{self, Authorization, Engine, H},
};
use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionOutpoint, TransactionOutput,
};
use serde_json::{Value, json};
use std::collections::HashMap;

pub fn wallet_check(tx: &Transaction, key: &ScriptPublicKey) -> Result<(), String> {
    let matches = tx
        .outputs
        .iter()
        .filter(|o| &o.script_public_key == key)
        .collect::<Vec<_>>();
    if matches.len() != 1 || matches[0].value != native::PRINCIPAL {
        return Err("wallet full entitlement/multiplicity".into());
    }
    Ok(())
}
fn signed(
    engine: &mut Engine,
    p: &Policy,
    secrets: &[H; 3],
    keys: &[ScriptPublicKey; 3],
    mask: u8,
    solo: Option<usize>,
    mut tx: Transaction,
) -> (Transaction, Vec<Authorization>) {
    let context = p.context(mask, solo, &tx);
    let owners = solo
        .map(|i| vec![i])
        .unwrap_or_else(|| native::active(mask));
    for i in &owners {
        wallet_check(&tx, &keys[*i])
            .expect("owner refuses missing/duplicated entitlement before proving");
    }
    let a = owners
        .iter()
        .map(|i| engine.prove(secrets[*i], context))
        .collect::<Vec<_>>();
    tx.inputs[0].signature_script = p.witness(mask, solo, &a);
    tx.finalize();
    (tx, a)
}
fn record(
    out: &mut Vec<Value>,
    name: &str,
    p: &Policy,
    mask: u8,
    mut tx: Transaction,
    accept: bool,
    proof_layer: bool,
) {
    tx.finalize();
    let r = native::execute(p, mask, &tx);
    assert_eq!(r.is_ok(), accept, "native case {name}: {r:?}");
    if proof_layer {
        let error = r.as_ref().unwrap_err();
        assert!(
            error.contains("Groth16") || error.contains("ZK") || error.contains("Zk"),
            "wrong rejection layer {name}: {error}"
        );
    }
    out.push(json!({"case":name,"accepted":r.is_ok(),"expectedAccept":accept,"nativeResult":format!("{r:?}")}));
}
fn snapshot(tx: &Transaction, p: &Policy) -> Value {
    json!({"version":tx.version,"subnetwork":hex::encode(tx.subnetwork_id.as_bytes()),"lockTime":tx.lock_time,"gas":tx.gas,"payload":hex::encode(&tx.payload),"inputs":tx.inputs.iter().map(|i|json!({"transactionId":i.previous_outpoint.transaction_id.to_string(),"index":i.previous_outpoint.index,"sequence":i.sequence,"computeBudget":i.compute_commit.compute_budget(),"sigOpCount":i.compute_commit.sig_op_count(),"signatureScript":hex::encode(&i.signature_script)})).collect::<Vec<_>>(),"outputs":tx.outputs.iter().map(|o|json!({"valueSompi":o.value,"scriptPublicKey":hex::encode(native::encoded(&o.script_public_key)),"covenant":o.covenant.as_ref().map(|c|json!({"authorizingInput":c.authorizing_input,"covenantId":c.covenant_id.to_string()}))})).collect::<Vec<_>>(),"activePublicClaims":p.claims.iter().map(hex::encode).collect::<Vec<_>>(),"policyRedeemScript":hex::encode(&p.scripts[7])})
}
#[derive(Clone)]
struct LocalUtxos {
    active: HashMap<TransactionOutpoint, u8>,
}
impl LocalUtxos {
    fn new(point: TransactionOutpoint) -> Self {
        Self {
            active: HashMap::from([(point, 7)]),
        }
    }
    fn accept(&mut self, p: &Policy, tx: &Transaction) -> Result<(), String> {
        if tx.inputs.len() != 1 {
            return Err("model input shape".into());
        }
        let point = tx.inputs[0].previous_outpoint;
        let mask = *self
            .active
            .get(&point)
            .ok_or("model missing/spent actual outpoint")?;
        native::execute(p, mask, tx)?;
        // Only accept successors that preserve exactly one fewer current claim
        // and carry the exact native policy/value. The VM enforces this too.
        let successor = if tx.outputs.len() == 2 && tx.outputs[1].value != native::PRINCIPAL {
            let o = &tx.outputs[1];
            let next = (1..7)
                .find(|m| {
                    m & mask == *m
                        && native::active(*m).len() + 1 == native::active(mask).len()
                        && o.value == native::reserve(*m)
                        && o.script_public_key == p.spk(*m)
                })
                .ok_or("model invalid successor")?;
            Some((TransactionOutpoint::new(tx.id(), 1), next))
        } else {
            None
        };
        if let Some((point, mask)) = successor {
            if self.active.contains_key(&point) {
                return Err("model duplicate successor".into());
            }
            self.active.insert(point, mask);
        }
        self.active.remove(&point);
        Ok(())
    }
}
pub struct TrialResult {
    pub report: Value,
    pub public_native: Value,
}
pub fn run(engine: &mut Engine, secrets: &[H; 3], keys: &[ScriptPublicKey; 3]) -> TrialResult {
    let p = Policy::new(
        std::array::from_fn(|i| proof::hash(&secrets[i])),
        &proof::serialize(&engine.vk),
    );
    let previous = native::fake_outpoint(proof::hash(b"public synthetic reserve; never fund"));
    let mut joint_keys = keys.to_vec();
    joint_keys.sort_by_key(native::encoded);
    let unsigned = p.transaction(7, None, previous, &joint_keys);
    for k in keys {
        wallet_check(&unsigned, k).unwrap();
    }
    eprintln!("Proving common-set joint authorizations...");
    let (joint, auth) = signed(engine, &p, secrets, keys, 7, None, unsigned);
    let mut results = vec![];
    record(
        &mut results,
        "valid_joint_three_claims",
        &p,
        7,
        joint.clone(),
        true,
        false,
    );
    let mut t = joint.clone();
    // Choose a fresh distinct destination so duplication guards do not mask the
    // actual changed-context Groth16 rejection.
    let secp = secp256k1::Secp256k1::new();
    let kp = secp256k1::Keypair::new(&secp, &mut rand::rngs::OsRng);
    let (x, _) = kp.x_only_public_key();
    t.outputs[0].script_public_key = ScriptPublicKey::new(
        0,
        [vec![32], x.serialize().to_vec(), vec![0xac]]
            .concat()
            .into(),
    );
    record(
        &mut results,
        "changed_distinct_recipient_same_proofs",
        &p,
        7,
        t,
        false,
        true,
    );
    let mut t = joint.clone();
    t.inputs[0].previous_outpoint.index += 1;
    record(
        &mut results,
        "changed_current_outpoint",
        &p,
        7,
        t,
        false,
        true,
    );
    let mut t = joint.clone();
    t.outputs.swap(0, 1);
    record(
        &mut results,
        "changed_output_order_same_authorizations",
        &p,
        7,
        t,
        false,
        true,
    );
    let mut t = joint.clone();
    t.subnetwork_id = kaspa_consensus_core::subnets::SubnetworkId::from_bytes([1; 20]);
    record(
        &mut results,
        "cross_subnetwork_replay",
        &p,
        7,
        t,
        false,
        false,
    );
    record(
        &mut results,
        "wrong_active_claim_subset",
        &p,
        6,
        joint.clone(),
        false,
        false,
    );
    let mut t = joint.clone();
    t.inputs.push(t.inputs[0].clone());
    record(
        &mut results,
        "duplicate_native_input_outpoint",
        &p,
        7,
        t,
        false,
        false,
    );
    let mut t = joint.clone();
    t.outputs[1] = t.outputs[0].clone();
    record(
        &mut results,
        "duplicate_payout_script",
        &p,
        7,
        t,
        false,
        false,
    );
    let mut t = joint.clone();
    t.outputs[0].value -= 1;
    t.outputs[1].value += 1;
    record(
        &mut results,
        "compensated_wrong_principal",
        &p,
        7,
        t,
        false,
        false,
    );
    let mut t = joint.clone();
    t.outputs.push(t.outputs[0].clone());
    record(&mut results, "extra_output", &p, 7, t, false, false);
    let mut t = joint.clone();
    t.payload = vec![1];
    record(
        &mut results,
        "uncommitted_payload_forbidden",
        &p,
        7,
        t,
        false,
        false,
    );
    let mut t = joint.clone();
    t.lock_time = 1;
    record(
        &mut results,
        "forced_locktime_forbidden",
        &p,
        7,
        t,
        false,
        false,
    );
    let mut t = joint.clone();
    t.inputs[0].sequence = 1;
    record(
        &mut results,
        "changed_sequence_forbidden",
        &p,
        7,
        t,
        false,
        false,
    );
    let mut t = joint.clone();
    let mut wrong = auth.clone();
    wrong.swap(0, 1);
    t.inputs[0].signature_script = p.witness(7, None, &wrong);
    record(
        &mut results,
        "other_claim_authorization",
        &p,
        7,
        t,
        false,
        true,
    );
    let mut t = joint.clone();
    let mut wrong = auth.clone();
    wrong[1] = wrong[0].clone();
    t.inputs[0].signature_script = p.witness(7, None, &wrong);
    record(
        &mut results,
        "reused_claim_authorization",
        &p,
        7,
        t,
        false,
        true,
    );
    let mut t = joint.clone();
    let raw = proof::serialize(&auth[0].proof);
    let at = t.inputs[0]
        .signature_script
        .windows(raw.len())
        .position(|s| s == raw)
        .unwrap();
    t.inputs[0].signature_script[at] ^= 0xff;
    record(&mut results, "corrupt_actual_proof", &p, 7, t, false, true);
    let mut t = joint.clone();
    t.inputs[0].signature_script = p.witness(7, None, &auth[..2]);
    record(
        &mut results,
        "missing_authorization",
        &p,
        7,
        t,
        false,
        false,
    );
    let mut t = joint.clone();
    t.inputs[0].signature_script[32] = 0xff;
    record(
        &mut results,
        "malformed_public_field",
        &p,
        7,
        t,
        false,
        true,
    );
    let mut t = joint.clone();
    t.outputs[0].value = 1 << 63;
    record(
        &mut results,
        "native_amount_outside_signed_range",
        &p,
        7,
        t,
        false,
        false,
    );
    // Wrong-domain/context proof is otherwise genuinely produced for this claim.
    let mut wrong_context = p.context(7, None, &joint);
    wrong_context[0] ^= 1;
    let mut wrong = auth.clone();
    wrong[0] = engine.prove(secrets[0], wrong_context);
    let mut t = joint.clone();
    t.inputs[0].signature_script = p.witness(7, None, &wrong);
    record(
        &mut results,
        "genuine_proof_for_wrong_context_domain",
        &p,
        7,
        t,
        false,
        true,
    );
    let mut wallet_bad = joint.clone();
    wallet_bad
        .outputs
        .retain(|o| o.script_public_key != keys[0]);
    assert!(wallet_check(&wallet_bad, &keys[0]).is_err());
    let mut wallet_bad = joint.clone();
    wallet_bad
        .outputs
        .push(TransactionOutput::new(native::PRINCIPAL, keys[0].clone()));
    assert!(wallet_check(&wallet_bad, &keys[0]).is_err());

    eprintln!("Proving independently executable solo branches...");
    let mut initial_solo = vec![];
    for i in 0..3 {
        let tx = p.transaction(7, Some(i), previous, &[keys[i].clone()]);
        wallet_check(&tx, &keys[i]).unwrap();
        let (tx, a) = signed(engine, &p, secrets, keys, 7, Some(i), tx);
        record(
            &mut results,
            &format!("solo_owner_{i}_without_registration_server"),
            &p,
            7,
            tx.clone(),
            true,
            false,
        );
        initial_solo.push(tx.clone());
        let mut t = tx.clone();
        t.outputs[1].value -= 1;
        record(
            &mut results,
            &format!("solo_{i}_incorrect_successor_backing"),
            &p,
            7,
            t,
            false,
            false,
        );
        let mut t = tx.clone();
        t.outputs[1].script_public_key = p.spk(7);
        record(
            &mut results,
            &format!("solo_{i}_successor_keeps_spent_claim"),
            &p,
            7,
            t,
            false,
            false,
        );
        let mut t = tx.clone();
        t.inputs[0].signature_script = p.witness(7, Some(i), &[auth[i].clone()]);
        record(
            &mut results,
            &format!("joint_proof_replayed_as_solo_{i}"),
            &p,
            7,
            t,
            false,
            true,
        );
        assert!(engine.verify(&a[0]));
    }
    // Separate local UTXO model: native VM does not know whether a supplied
    // outpoint is already spent. Do not call this a chain/reorg test.
    let mut joint_first = LocalUtxos::new(previous);
    joint_first.accept(&p, &joint).unwrap();
    assert!(
        joint_first
            .accept(&p, &joint)
            .unwrap_err()
            .contains("missing/spent")
    );
    let joint_then_solo = joint_first.accept(&p, &initial_solo[0]).unwrap_err();
    let mut solo_first = LocalUtxos::new(previous);
    solo_first.accept(&p, &initial_solo[0]).unwrap();
    let solo_then_joint = solo_first.accept(&p, &joint).unwrap_err();
    let mut solo_model = LocalUtxos::new(previous);
    let mut mask = 7;
    let mut point = previous;
    let mut solo_chain = vec![];
    for i in 0..3 {
        let (tx, _) = if i == 0 {
            (initial_solo[0].clone(), vec![])
        } else {
            let tx = p.transaction(mask, Some(i), point, &[keys[i].clone()]);
            signed(engine, &p, secrets, keys, mask, Some(i), tx)
        };
        record(
            &mut results,
            &format!("sequential_solo_drain_{i}"),
            &p,
            mask,
            tx.clone(),
            true,
            false,
        );
        solo_model.accept(&p, &tx).unwrap();
        mask &= !(1 << i);
        solo_chain.push(json!({"owner":i,"remainingPrincipalSompi":native::active(mask).len() as u64*native::PRINCIPAL,"remainingReserveSompi":native::reserve(mask)}));
        if mask != 0 {
            point = kaspa_consensus_core::tx::TransactionOutpoint::new(tx.id(), 1);
        }
    }
    assert_eq!(mask, 0);
    assert!(solo_model.active.is_empty());
    let after_first = kaspa_consensus_core::tx::TransactionOutpoint::new(initial_solo[0].id(), 1);
    let mut remaining = vec![keys[1].clone(), keys[2].clone()];
    remaining.sort_by_key(native::encoded);
    let tx = p.transaction(6, None, after_first, &remaining);
    let (mixed, _) = signed(engine, &p, secrets, keys, 6, None, tx);
    record(
        &mut results,
        "solo_then_remaining_two_joint",
        &p,
        6,
        mixed.clone(),
        true,
        false,
    );
    solo_first.accept(&p, &mixed).unwrap();
    assert!(solo_first.active.is_empty());
    let mut stale = mixed.clone();
    stale.inputs[0].previous_outpoint = previous;
    record(
        &mut results,
        "remaining_joint_stale_prior_outpoint",
        &p,
        6,
        stale,
        false,
        true,
    );
    let mut wrong_secret = secrets[0];
    wrong_secret[0] ^= 1;
    let impostor = engine.prove(wrong_secret, p.context(7, None, &joint));
    let mut t = joint.clone();
    let mut bad = auth.clone();
    bad[0] = impostor;
    t.inputs[0].signature_script = p.witness(7, None, &bad);
    record(&mut results, "unregistered_secret", &p, 7, t, false, true);
    TrialResult {
        public_native: snapshot(&joint, &p),
        report: json!({"scope":"native script engine and separately stated local supplied-UTXO model; no full node/chain validation","jointPrincipalSompi":3*native::PRINCIPAL,"jointFeeAllowanceSompi":3*native::FEE,"initialReserveSompi":native::reserve(7),"nativeCases":results,"soloDrain":solo_chain,"jointSoloConflictsRejectedByLocalSpentnessModel":{"jointThenSolo":joint_then_solo,"soloThenJoint":solo_then_joint},"remainingTwoJointFinalPrincipalSompi":0,"scriptBytesByActiveSubset":(1..=7).map(|m|json!({"subset":m,"bytes":p.scripts[m as usize].len()})).collect::<Vec<_>>(),"jointMassQuote":native::mass(&p,7,&joint),"jointSignatureScriptBytes":joint.inputs[0].signature_script.len()}),
    }
}

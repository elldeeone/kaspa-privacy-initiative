//! Execute the actual wallet, delivery scanning and atomic kernel in both worlds.
use crate::{circuit, native::PRINCIPAL as D, proof};
use kpi_private_note_wallet::{
    ProofVerifier,
    circuit::{WalletCircuit, Witness},
    ledger::Ledger,
    protocol::*,
    wallet::{Engine as OldEngine, Wallet},
};
use serde_json::{Value, json};
use std::time::Instant;

pub struct Lifecycle {
    pub engine: proof::Engine,
    pub old: OldEngine,
    pub state: Ledger,
    pub old_state: Ledger,
    pub witnesses: [Witness; 3],
    pub old_ops: Vec<Operation>,
    pub ops: Vec<Operation>,
    pub checks: Vec<Value>,
    pub timing: Value,
}
fn no_deliveries() -> [Delivery; 2] {
    [Delivery::absent(), Delivery::absent()]
}
fn reject<V: ProofVerifier>(s: &mut Ledger, v: &V, op: &Operation, name: &str) -> Value {
    let before = s.state_hash();
    let error = s.apply(v, op).unwrap_err();
    assert_eq!(before, s.state_hash());
    json!({"case":name,"error":error,"stateUnchanged":true})
}
pub fn build() -> Lifecycle {
    let start = Instant::now();
    let wallets = [Wallet::new(), Wallet::new(), Wallet::new()];
    let a = &wallets[0];
    let b = &wallets[1];
    let c = &wallets[2];
    let n = a.note(3 * D);
    let dep = hash(b"fresh unfunded real-wallet integration deposit fixture");
    let mut s = Statement::new(CREDIT, [0; 32], Tree::default().root());
    s.deposit = dep;
    s.deposit_value = 3 * D;
    s.deposit_owner = a.address.owner;
    let w = a.witness(
        a.authority_note(),
        [n.clone(), Note::dummy()],
        [[0; 32]; DEPTH],
        [false; DEPTH],
    );
    let mut ds = [n.deliver().unwrap(), Delivery::absent()];
    s.outputs[0] = ds[0].commitment;
    s.delivery[0] = hash(&ds[0].ciphertext);
    eprintln!("Setting up original and digest-packed complete wallet relations...");
    let original_sample = WalletCircuit {
        statement: s.clone(),
        witness: w.clone(),
    };
    let (original_constraints, valid) = original_sample.check().unwrap();
    assert!(valid);
    let t = Instant::now();
    let old = OldEngine::setup(original_sample).unwrap();
    let old_setup = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let mut engine = proof::Engine::setup(circuit::WalletCircuit {
        statement: s.clone(),
        witness: w.clone(),
    });
    let packed_setup = t.elapsed().as_secs_f64();
    let mut state = Ledger::new(engine.id());
    let mut old_state = Ledger::new(old.id());
    for st in [&mut state, &mut old_state] {
        st.register_authenticated_fixture_deposit(dep, 3 * D, a.address.owner)
            .unwrap();
    }
    let mut ops = vec![];
    let mut old_ops = vec![];
    let mut checks = vec![];
    let mut prove_pair =
        |s: Statement, w: Witness, ds: [Delivery; 2], st: &mut Ledger, ost: &mut Ledger| {
            let original = old.prove(s.clone(), w.clone(), ds.clone()).unwrap();
            let packed = engine.prove(s, w, ds);
            assert_eq!(original.statement.nullifier, packed.statement.nullifier);
            assert_eq!(original.statement.outputs, packed.statement.outputs);
            ost.apply(&old.verifier(), &original).unwrap();
            st.apply(&engine, &packed).unwrap();
            assert_eq!(ost.tree.root(), st.tree.root());
            assert_eq!(ost.nullifiers, st.nullifiers);
            assert_eq!(ost.private_liability, st.private_liability);
            old_ops.push(original);
            ops.push(packed);
        };
    prove_pair(s, w, ds, &mut state, &mut old_state);
    let bob20 = b.note(2 * D);
    let alice10 = a.note(D);
    let (p, q) = state.tree.path(0).unwrap();
    let mut s = Statement::new(TRANSFER, [0; 32], state.tree.root());
    s.nullifier = a.nf(&n);
    ds = [bob20.deliver().unwrap(), alice10.deliver().unwrap()];
    let w = a.witness(n, [bob20.clone(), alice10], p, q);
    let t_sample = {
        let mut x = s.clone();
        x.outputs = [ds[0].commitment, ds[1].commitment];
        x.delivery = [hash(&ds[0].ciphertext), hash(&ds[1].ciphertext)];
        x
    };
    // Differential full-relation checks: all cases must agree, including refusal.
    let mut cases = vec![("valid_transfer", w.clone(), t_sample.clone(), true)];
    let mut z = w.clone();
    z.secret[0] ^= 1;
    cases.push(("wrong_owner", z, t_sample.clone(), false));
    let mut z = w.clone();
    z.siblings[0][0] ^= 1;
    cases.push(("wrong_membership", z, t_sample.clone(), false));
    let mut z = t_sample.clone();
    z.nullifier[0] ^= 1;
    cases.push(("wrong_nullifier", w.clone(), z, false));
    let mut z = w.clone();
    z.outputs[0].value += 1;
    cases.push(("unbalanced_outputs", z, t_sample.clone(), false));
    let mut z = t_sample.clone();
    z.exit_value = 1;
    cases.push(("transfer_illegal_exit", w.clone(), z, false));
    let mut z = t_sample.clone();
    z.domain[0] ^= 1;
    cases.push(("wrong_domain", w.clone(), z, false));
    for (name, witness, statement, expected) in cases {
        let x = WalletCircuit {
            statement: statement.clone(),
            witness: witness.clone(),
        }
        .check()
        .unwrap()
        .1;
        let y = circuit::WalletCircuit { statement, witness }
            .check()
            .unwrap()
            .1;
        assert_eq!((x, y), (expected, expected), "differential {name}");
        checks.push(json!({"case":name,"original":x,"packed":y,"expected":expected}));
    }
    prove_pair(s, w, ds, &mut state, &mut old_state);
    let received = b.discover(&state.deliveries, &state.tree, &state.nullifiers);
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].0.value, 2 * D);
    let (p, q) = state.tree.path(received[0].1).unwrap();
    let carol10 = c.note(D);
    let bob10 = b.note(D);
    let mut s = Statement::new(TRANSFER, [0; 32], state.tree.root());
    s.nullifier = b.nf(&received[0].0);
    let w = b.witness(
        received[0].0.clone(),
        [carol10.clone(), bob10.clone()],
        p,
        q,
    );
    prove_pair(
        s,
        w,
        [carol10.deliver().unwrap(), bob10.deliver().unwrap()],
        &mut state,
        &mut old_state,
    );
    drop(prove_pair);
    checks.push(reject(
        &mut state,
        &engine,
        &ops[1],
        "duplicate_received_note_spend",
    ));
    let mut bad = ops[2].clone();
    bad.proof[0] ^= 1;
    checks.push(reject(
        &mut state,
        &engine,
        &bad,
        "corrupt_real_transfer_proof",
    ));
    let mut bad = ops[2].clone();
    bad.statement.anchor[0] ^= 1;
    checks.push(reject(
        &mut state,
        &engine,
        &bad,
        "changed_anchor_same_proof",
    ));
    let witnesses = std::array::from_fn(|i| {
        // Restore from user-held backup, using only actual public deliveries.
        let restored = Wallet::restore_local(&wallets[i].local_backup());
        let found = restored.discover(&state.deliveries, &state.tree, &state.nullifiers);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0.value, D);
        let (p, q) = state.tree.path(found[0].1).unwrap();
        restored.witness(found[0].0.clone(), [Note::dummy(), Note::dummy()], p, q)
    });
    let timing = json!({"originalConstraints":original_constraints,"packedConstraints":engine.constraints,"originalSetupSeconds":old_setup,"packedSetupSeconds":packed_setup,"initialLifecycleSeconds":start.elapsed().as_secs_f64(),"originalPublicInputs":14,"packedPublicInputs":2,"recipientRespend":true,"restoredWalletsDiscoverFinalNotes":3,"privatePaymentsSompi":[2*D,D],"usefulPaymentSompi":3*D,"privateLiabilityBeforeExitsSompi":state.private_liability,"depositNativeAuthentication":"fixture, no chain","delivery":"actual encrypted wallet delivery and recipient decryption"});
    Lifecycle {
        engine,
        old,
        state,
        old_state,
        witnesses,
        old_ops,
        ops,
        checks,
        timing,
    }
}
pub fn direct_exits(l: &mut Lifecycle, keys: &[H; 3]) -> Vec<Operation> {
    let anchor = l.old_state.tree.root();
    (0..3)
        .map(|i| {
            let mut s = Statement::new(EXIT, l.old.id(), anchor);
            s.nullifier = nullifier(&l.witnesses[i].secret, &l.witnesses[i].input);
            s.exit_value = D;
            s.exit_destination = hash(&[vec![0], keys[i].to_vec()].concat());
            let op = l
                .old
                .prove(s, l.witnesses[i].clone(), no_deliveries())
                .unwrap();
            l.old_state.apply(&l.old.verifier(), &op).unwrap();
            l.old_state
                .confirm_authenticated_fixture_payout(
                    op.statement.id(),
                    D,
                    op.statement.exit_destination,
                    hash(&[b"baseline output".as_slice(), &[i as u8]].concat()),
                )
                .unwrap();
            op
        })
        .collect()
}

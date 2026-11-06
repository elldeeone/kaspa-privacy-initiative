use crate::{
    circuit,
    native::{self, Policy},
    proof::{self, Engine, H},
    prover::{self, Result},
    registration,
};
use kaspa_consensus_core::tx::*;
use kpi_batched_payment_core as app;
use kpi_private_note_wallet::{circuit::Witness, ledger::Ledger, protocol::*, wallet::Wallet};
use rand::{RngCore, rngs::OsRng};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::{Value, json};
use std::{collections::HashMap, fs, path::Path, time::Instant};
const FEE_BUFFER: u64 = 200_000_000;
fn save(p: &Path, v: &Value) -> Result<()> {
    prover::write(p, &serde_json::to_vec_pretty(v)?)
}
fn fresh() -> H {
    let mut b = [0; 32];
    OsRng.fill_bytes(&mut b);
    b
}
fn key() -> SecretKey {
    SecretKey::new(&mut OsRng)
}
fn pubkey(s: &SecretKey) -> H {
    Keypair::from_secret_key(&Secp256k1::new(), s)
        .x_only_public_key()
        .0
        .serialize()
}
fn recipient(s: &SecretKey) -> ScriptPublicKey {
    ScriptPublicKey::new(
        0,
        [vec![32], pubkey(s).to_vec(), vec![0xac]].concat().into(),
    )
}

struct Work {
    engine: Engine,
    initial: app::State,
    operations: Vec<Operation>,
    post: app::State,
    wallets: [Wallet; 3],
    witnesses: [Witness; 3],
    payout_keys: [SecretKey; 3],
    funding_key: SecretKey,
    source: TransactionOutpoint,
    source_value: u64,
    d: u64,
    setup_seconds: f64,
    inner_seconds: f64,
}
fn workload(d: u64, out: &Path) -> Result<Work> {
    fs::create_dir(out)?;
    fs::create_dir(out.join("private"))?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(out.join("private"), fs::Permissions::from_mode(0o700))?;
    let t = Instant::now();
    let wallets = [Wallet::new(), Wallet::new(), Wallet::new()];
    let a = &wallets[0];
    let b = &wallets[1];
    let c = &wallets[2];
    let funding_key = key();
    let payout_keys = [key(), key(), key()];
    let source = native::fake_point(fresh());
    let pool = hash(
        &[
            b"KPI-native-batch-pool-v1\0".as_slice(),
            kaspa_consensus_core::config::params::TESTNET_PARAMS
                .genesis
                .hash
                .as_bytes()
                .as_slice(),
            source.transaction_id.as_bytes().as_slice(),
        ]
        .concat(),
    );
    let credit = a.note(3 * d);
    let delivery = credit.deliver()?;
    let mut s = Statement::new(CREDIT, [0; 32], Tree::default().root());
    s.deposit = pool;
    s.deposit_owner = a.address.owner;
    s.deposit_value = 3 * d;
    s.outputs[0] = delivery.commitment;
    s.delivery[0] = hash(&delivery.ciphertext);
    let witness = a.witness(
        a.authority_note(),
        [credit.clone(), Note::dummy()],
        [[0; 32]; DEPTH],
        [false; DEPTH],
    );
    let mut engine = Engine::setup(circuit::WalletCircuit {
        statement: s.clone(),
        witness: witness.clone(),
    });
    let setup_seconds = t.elapsed().as_secs_f64();
    let t = Instant::now();
    let mut ledger = Ledger::new(engine.id());
    ledger.register_authenticated_fixture_deposit(pool, 3 * d, a.address.owner)?;
    let initial = app::State {
        ledger,
        pool,
        wallet_vk: proof::serialize(&engine.vk),
        fee_refund_spk: native::encoded(&recipient(&funding_key)),
    };
    let mut post = initial.clone();
    let mut operations = vec![];
    let op = engine.prove(s, witness, [delivery, Delivery::absent()]);
    post.ledger.apply(&engine, &op)?;
    operations.push(op);
    let bob20 = b.note(2 * d);
    let alice10 = a.note(d);
    let (p, q) = post.ledger.tree.path(0)?;
    let mut s = Statement::new(TRANSFER, engine.id(), post.ledger.tree.root());
    s.nullifier = a.nf(&credit);
    let op = engine.prove(
        s,
        a.witness(credit, [bob20.clone(), alice10.clone()], p, q),
        [bob20.deliver()?, alice10.deliver()?],
    );
    post.ledger.apply(&engine, &op)?;
    operations.push(op);
    let received = b.discover(
        &post.ledger.deliveries,
        &post.ledger.tree,
        &post.ledger.nullifiers,
    );
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].0.value, 2 * d);
    let carol10 = c.note(d);
    let bob10 = b.note(d);
    let (p, q) = post.ledger.tree.path(received[0].1)?;
    let mut s = Statement::new(TRANSFER, engine.id(), post.ledger.tree.root());
    s.nullifier = b.nf(&received[0].0);
    let op = engine.prove(
        s,
        b.witness(
            received[0].0.clone(),
            [carol10.clone(), bob10.clone()],
            p,
            q,
        ),
        [carol10.deliver()?, bob10.deliver()?],
    );
    post.ledger.apply(&engine, &op)?;
    operations.push(op);
    let witnesses = std::array::from_fn(|i| {
        let restored = Wallet::restore_local(&wallets[i].local_backup());
        let notes = restored.discover(
            &post.ledger.deliveries,
            &post.ledger.tree,
            &post.ledger.nullifiers,
        );
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].0.value, d);
        let (p, q) = post.ledger.tree.path(notes[0].1).unwrap();
        restored.witness(notes[0].0.clone(), [Note::dummy(), Note::dummy()], p, q)
    });
    let inner_seconds = t.elapsed().as_secs_f64();
    prover::write(
        &out.join("private/proving-parameters.bin"),
        &proof::serialize(&engine.pk),
    )?;
    let backups = wallets
        .iter()
        .map(|w| hex::encode(w.local_backup()))
        .collect::<Vec<_>>();
    save(
        &out.join("private/wallets.json"),
        &json!({"walletBackups":backups,"payoutKeys":payout_keys.iter().map(|k|hex::encode(k.secret_bytes())).collect::<Vec<_>>(),"fundingKey":hex::encode(funding_key.secret_bytes())}),
    )?;
    fs::set_permissions(
        out.join("private/wallets.json"),
        fs::Permissions::from_mode(0o600),
    )?;
    save(
        &out.join("initial-public-state.json"),
        &json!({"bincodeHex":hex::encode(bincode::serialize(&initial)?),"root":hex::encode(initial.root())}),
    )?;
    save(
        &out.join("private-payment-operations.json"),
        &json!(operations),
    )?;
    save(
        &out.join("wallet-resources.json"),
        &json!({"setupSeconds":setup_seconds,"innerProofSeconds":inner_seconds,"constraints":engine.constraints,"recipientActuallyDecryptsAndRespends":true,"restoredFinalWallets":3,"provingParametersRetainedInGit":false}),
    )?;
    Ok(Work {
        engine,
        initial,
        operations,
        post,
        wallets,
        witnesses,
        payout_keys,
        funding_key,
        source,
        source_value: 3 * d + FEE_BUFFER + 100_000_000,
        d,
        setup_seconds,
        inner_seconds,
    })
}
fn funding(work: &Work, policy: &Policy) -> Result<(Transaction, UtxoEntry, Value)> {
    let source_entry = UtxoEntry::new(
        work.source_value,
        recipient(&work.funding_key),
        0,
        false,
        None,
    );
    let bank = 3 * work.d + FEE_BUFFER;
    let mut tx = native::transaction(
        work.source,
        vec![
            TransactionOutput::new(bank, policy.spk(work.initial.root())),
            TransactionOutput::new(100_000_000, recipient(&work.funding_key)),
        ],
        bincode::serialize(&work.initial)?,
        20,
    );
    tx.inputs[0].signature_script = vec![0; 66];
    let fee = native::quote(&tx, &source_entry)["minimumDefaultRelayFeeSompi"]
        .as_u64()
        .unwrap();
    tx.outputs[1].value -= fee;
    let pop = PopulatedTransaction::new(&tx, vec![source_entry.clone()]);
    tx.inputs[0].signature_script = kaspa_consensus_core::sign::sign_input(
        &pop,
        0,
        &work.funding_key.secret_bytes(),
        kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL,
    );
    tx.finalize();
    let report = native::validate(&tx, &source_entry)?;
    assert_eq!(report["feeSompi"], fee);
    let bank_entry = UtxoEntry::new(
        bank,
        tx.outputs[0].script_public_key.clone(),
        0,
        false,
        None,
    );
    Ok((tx, bank_entry, report))
}
fn preview(state: &app::State, w: &Work, owners: &[usize]) -> Result<app::State> {
    let mut next = state.clone();
    for i in owners {
        let nf = nullifier(&w.witnesses[*i].secret, &w.witnesses[*i].input);
        if !next.ledger.nullifiers.insert(nf) {
            return Err("preview current NF already spent".into());
        }
        next.ledger.private_liability = next
            .ledger
            .private_liability
            .checked_sub(w.d)
            .ok_or("preview liability")?;
        next.ledger.reserve = next
            .ledger
            .reserve
            .checked_sub(w.d)
            .ok_or("preview principal")?;
    }
    next.ledger.invariant()?;
    Ok(next)
}
struct Step {
    tx: Transaction,
    input: app::Input,
    output: app::Output,
    report: Value,
}
fn prepare_step(
    w: &mut Work,
    policy: &Policy,
    state: &app::State,
    point: TransactionOutpoint,
    value: u64,
    mode: u8,
    ops: &[Operation],
    owners: &[usize],
) -> Result<Step> {
    let preparation_started = Instant::now();
    let proofs_before = w.engine.proofs;
    let old = state.root();
    let mut next = state.clone();
    let mut packet = app::Packet {
        mode,
        operations: ops.to_vec(),
    };
    let new_root;
    let mut outputs = vec![];
    if mode == app::PAYMENT {
        for op in ops {
            next.ledger.apply(&w.engine, op)?;
        }
        new_root = next.root();
        outputs.push(TransactionOutput::new(value, policy.spk(new_root)));
    } else {
        next = preview(state, w, owners)?;
        new_root = if next.ledger.reserve == 0 {
            [0; 32]
        } else {
            next.root()
        };
        let fees = value - state.ledger.reserve;
        if next.ledger.reserve > 0 {
            outputs.push(TransactionOutput::new(
                next.ledger.reserve + fees,
                policy.spk(new_root),
            ));
        }
        let mut payouts = owners
            .iter()
            .map(|i| TransactionOutput::new(w.d, recipient(&w.payout_keys[*i])))
            .collect::<Vec<_>>();
        if mode == app::JOINT {
            payouts.sort_by_key(|o| native::encoded(&o.script_public_key));
        }
        outputs.extend(payouts);
        if next.ledger.reserve == 0 {
            outputs.push(TransactionOutput::new(
                fees,
                native::spk(&state.fee_refund_spk),
            ));
        }
        packet.operations = owners
            .iter()
            .map(|i| {
                let mut s = Statement::new(EXIT, w.engine.id(), state.ledger.tree.root());
                s.nullifier = nullifier(&w.witnesses[*i].secret, &w.witnesses[*i].input);
                s.exit_value = w.d;
                s.exit_destination = [1; 32];
                Operation {
                    statement: s,
                    deliveries: [Delivery::absent(), Delivery::absent()],
                    proof: vec![0; 128],
                }
            })
            .collect();
    }
    let mut tx = native::transaction(point, outputs, packet.bytes(), native::BUDGET);
    tx.inputs[0].signature_script = policy.witness(old, new_root, &[0; 128]);
    let entry = UtxoEntry::new(value, policy.spk(old), 0, false, None);
    let fee = native::quote(&tx, &entry)["minimumDefaultRelayFeeSompi"]
        .as_u64()
        .unwrap();
    let fee_output = if next.ledger.reserve > 0 {
        0
    } else {
        tx.outputs.len() - 1
    };
    tx.outputs[fee_output].value = tx.outputs[fee_output]
        .value
        .checked_sub(fee)
        .ok_or("fee buffer")?;
    if mode != app::PAYMENT {
        let context = native::effects(&tx, value).context(old);
        let mut actual = vec![];
        for i in owners {
            let spk = recipient(&w.payout_keys[*i]);
            let matches = tx
                .outputs
                .iter()
                .filter(|o| o.script_public_key == spk)
                .collect::<Vec<_>>();
            if matches.len() != 1 || matches[0].value != w.d {
                return Err("owner full entitlement check".into());
            }
            let dest = if mode == app::NAMED {
                hash(&[vec![0], pubkey(&w.payout_keys[*i]).to_vec()].concat())
            } else {
                context
            };
            actual.push(
                w.engine
                    .authorize(&w.witnesses[*i], dest, state.ledger.tree.root()),
            );
        }
        packet.operations = actual;
        tx.payload = packet.bytes();
    }
    tx.finalize();
    let mut final_quote = native::quote(&tx, &entry);
    assert_eq!(
        final_quote["minimumDefaultRelayFeeSompi"], fee,
        "placeholder and real canonical wire size"
    );
    let input = app::Input {
        state: state.clone(),
        packet,
        effects: native::effects(&tx, value),
    };
    let output = app::execute(&input)?;
    assert_eq!(&output.journal[32..64], new_root);
    assert_eq!(output.state.root(), next.root());
    final_quote["walletPreparationSeconds"] = json!(preparation_started.elapsed().as_secs_f64());
    final_quote["genuineNewWalletProofs"] = json!(w.engine.proofs - proofs_before);
    Ok(Step {
        tx,
        input,
        output,
        report: final_quote,
    })
}
fn finish(step: &mut Step, policy: &Policy, proof: &[u8], entry: &UtxoEntry) -> Result<()> {
    let root = step.input.state.root();
    let new: H = step.output.journal[32..64].try_into().unwrap();
    let id = step.tx.id();
    step.tx.inputs[0].signature_script = policy.witness(root, new, proof);
    step.tx.finalize();
    assert_eq!(
        id,
        step.tx.id(),
        "native txid must not depend on proof witness"
    );
    let preparation = step.report["walletPreparationSeconds"].clone();
    let count = step.report["genuineNewWalletProofs"].clone();
    step.report = native::validate(&step.tx, entry)?;
    step.report["walletPreparationSeconds"] = preparation;
    step.report["genuineNewWalletProofs"] = count;
    assert_eq!(step.report["feeSompi"], step.output.fee);
    Ok(())
}
#[derive(Clone)]
struct World {
    state: app::State,
    point: TransactionOutpoint,
    value: u64,
    active: HashMap<TransactionOutpoint, UtxoEntry>,
    records: Vec<Value>,
}
impl World {
    fn start(w: &Work, tx: &Transaction, entry: &UtxoEntry, report: &Value) -> Self {
        let point = TransactionOutpoint::new(tx.id(), 0);
        Self {
            state: w.initial.clone(),
            point,
            value: entry.amount,
            active: HashMap::from([(point, entry.clone())]),
            records: vec![json!({"kind":"deposit","transaction":tx,"report":report})],
        }
    }
    fn entry(&self) -> Result<UtxoEntry> {
        Ok(self
            .active
            .get(&self.point)
            .ok_or("local missing/spent bank outpoint")?
            .clone())
    }
    fn accept(&mut self, step: &Step) -> Result<()> {
        if self.point != step.tx.inputs[0].previous_outpoint {
            return Err("local stale bank outpoint".into());
        }
        let entry = self.entry()?;
        native::validate(&step.tx, &entry)?;
        self.active.remove(&self.point);
        self.state = step.output.state.clone();
        if self.state.ledger.reserve > 0 {
            self.point = TransactionOutpoint::new(step.tx.id(), 0);
            self.value = step.tx.outputs[0].value;
            self.active.insert(
                self.point,
                UtxoEntry::new(
                    self.value,
                    step.tx.outputs[0].script_public_key.clone(),
                    0,
                    false,
                    None,
                ),
            );
        } else {
            self.value = 0;
        }
        self.records.push(json!({"kind":"settlement","transaction":step.tx,"report":step.report,"inputBincodeHex":hex::encode(bincode::serialize(&step.input)?),"postStateBincodeHex":hex::encode(bincode::serialize(&step.output.state)?),"payoutPrincipalSompi":step.output.payout_principal,"refundedFeeSompi":step.output.refunded_fee}));
        Ok(())
    }
}
fn world(
    program: &[u8],
    policy: &Policy,
    w: &mut Work,
    fund: &Transaction,
    entry: &UtxoEntry,
    fund_report: &Value,
    out: &Path,
    batched: bool,
) -> Result<World> {
    fs::create_dir(out)?;
    let mut world = World::start(w, fund, entry, fund_report);
    let groups = if batched {
        vec![w.operations.clone()]
    } else {
        w.operations.iter().map(|o| vec![o.clone()]).collect()
    };
    for (i, ops) in groups.iter().enumerate() {
        let mut step = prepare_step(
            w,
            policy,
            &world.state,
            world.point,
            world.value,
            app::PAYMENT,
            ops,
            &[],
        )?;
        let entry = world.entry()?;
        let (proof, stats) =
            prover::prove(program, &step.input, &out.join(format!("payment-{i}")))?;
        finish(&mut step, policy, &proof, &entry)?;
        step.report["proving"] = stats;
        world.accept(&step)?;
        save(
            &out.join(format!("payment-{i}-native.json")),
            world.records.last().unwrap(),
        )?;
    }
    assert_eq!(world.state.root(), w.post.root());
    if batched {
        let started = Instant::now();
        let claims =
            std::array::from_fn(|i| nullifier(&w.witnesses[i].secret, &w.witnesses[i].input));
        let keys = std::array::from_fn(|i| pubkey(&w.payout_keys[i]));
        let reg = registration::run(
            &mut w.engine,
            &w.witnesses,
            world.state.ledger.tree.root(),
            claims,
            keys,
            w.d,
        );
        save(&out.join("registration.json"), &reg.candidate)?;
        save(
            &out.join("registration-controls.json"),
            &json!(reg.controls),
        )?;
        save(
            &out.join("registration-resources.json"),
            &json!({"seconds":started.elapsed().as_secs_f64(),"genuineEligibilityProofs":3,"nativeFeeSompi":0}),
        )?;
        save(
            &out.parent()
                .unwrap()
                .join("private")
                .join("registration-truth.json"),
            &json!({"round":hex::encode(reg.round),"ownerPayouts":keys.iter().enumerate().map(|(i,k)|json!({"owner":format!("owner-{}",i+1),"recipientKey":hex::encode(k),"randomizer":hex::encode(reg.randomizers[i])})).collect::<Vec<_>>(),"identifiedControl":reg.baseline}),
        )?;
    }
    let groups = if batched {
        vec![vec![0, 1, 2]]
    } else {
        vec![vec![0], vec![1], vec![2]]
    };
    for (i, owners) in groups.iter().enumerate() {
        let mode = if batched { app::JOINT } else { app::NAMED };
        let mut step = prepare_step(
            w,
            policy,
            &world.state,
            world.point,
            world.value,
            mode,
            &[],
            owners,
        )?;
        let entry = world.entry()?;
        let (proof, stats) =
            prover::prove(program, &step.input, &out.join(format!("withdraw-{i}")))?;
        finish(&mut step, policy, &proof, &entry)?;
        step.report["proving"] = stats;
        world.accept(&step)?;
        save(
            &out.join(format!("withdraw-{i}-native.json")),
            world.records.last().unwrap(),
        )?;
    }
    assert_eq!(world.state.ledger.reserve, 0);
    assert_eq!(world.state.ledger.private_liability, 0);
    assert!(world.state.canonical());
    assert!(world.active.is_empty());
    let fees = world
        .records
        .iter()
        .map(|r| r["report"]["feeSompi"].as_u64().unwrap())
        .sum::<u64>();
    let proof_seconds = world
        .records
        .iter()
        .skip(1)
        .map(|r| {
            r["report"]["proving"]["totalProofSeconds"]
                .as_f64()
                .unwrap()
        })
        .sum::<f64>();
    save(
        &out.join("world.json"),
        &json!({"batched":batched,"usefulPaymentSompi":3*w.d,"nativeTransactionCount":world.records.len(),"totalNativeFeeSompi":fees,"networkFeePercent":fees as f64*100.0/(3*w.d) as f64,"outerProofSeconds":proof_seconds,"walletSetupSeconds":w.setup_seconds,"walletPaymentProofSeconds":w.inner_seconds,"finalPrincipalSompi":0,"finalPrivateLiabilitySompi":0,"finalUnpaidExits":0,"transactions":world.records,"nativeFullValidation":true,"offlineRelayChecks":true,"chainAcceptance":false,"providerInvoiceUsd":0,"hardwareCostValuation":"measured usage separately; no claim of zero electricity/depreciation"}),
    )?;
    Ok(world)
}
pub fn run(program_path: &Path, out: &Path) -> Result<()> {
    assert!(!out.exists());
    fs::create_dir(out)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(out, fs::Permissions::from_mode(0o700))?;
    let program = fs::read(program_path)?;
    let image = risc0_zkvm::compute_image_id(&program)?;
    let policy = Policy {
        image: image.into(),
    };
    assert_eq!(app::MAX_SOMPI, kaspa_consensus_core::constants::MAX_SOMPI);
    let mut w = workload(1_000_000_000, &out.join("30-kas"))?;
    let (fund, entry, fund_report) = funding(&w, &policy)?;
    save(
        &out.join("30-kas/deposit.json"),
        &json!({"transaction":fund,"report":fund_report,"suppliedSourceUtxo":true}),
    )?;
    let _baseline = world(
        &program,
        &policy,
        &mut w,
        &fund,
        &entry,
        &fund_report,
        &out.join("30-kas/named"),
        false,
    )?;
    let _candidate = world(
        &program,
        &policy,
        &mut w,
        &fund,
        &entry,
        &fund_report,
        &out.join("30-kas/batched"),
        true,
    )?;
    let mut larger = workload(2_500_000_000, &out.join("75-kas"))?;
    let (fund, entry, fund_report) = funding(&larger, &policy)?;
    let _large = world(
        &program,
        &policy,
        &mut larger,
        &fund,
        &entry,
        &fund_report,
        &out.join("75-kas/batched"),
        true,
    )?;
    Ok(())
}

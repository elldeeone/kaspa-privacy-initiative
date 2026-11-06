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
fn cached_step(path: &Path, world: &World) -> Result<Option<Step>> {
    let (Ok(from), Ok(to)) = (
        std::env::var("KPI_BATCH_REUSE_FROM"),
        std::env::var("KPI_BATCH_OUTPUT"),
    ) else {
        return Ok(None);
    };
    let source = Path::new(&from).join(path.strip_prefix(to)?);
    if !source.exists() {
        return Ok(None);
    }
    let step = recorded_step(&read(&source)?)?;
    if step.input.state.root() != world.state.root()
        || step.tx.inputs[0].previous_outpoint != world.point
        || step.input.effects.input_value != world.value
        || bincode::serialize(&step.input.effects)?
            != bincode::serialize(&native::effects(&step.tx, world.value))?
        || step.tx.payload != step.input.packet.bytes()
    {
        return Err("cached native step lineage/effects mismatch".into());
    }
    native::validate(&step.tx, &world.entry()?)?;
    Ok(Some(step))
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
    joint: bool,
) -> Result<World> {
    fs::create_dir(out)?;
    let mut world = World::start(w, fund, entry, fund_report);
    let groups = if batched {
        vec![w.operations.clone()]
    } else {
        w.operations.iter().map(|o| vec![o.clone()]).collect()
    };
    for (i, ops) in groups.iter().enumerate() {
        let mut step = if let Some(step) =
            cached_step(&out.join(format!("payment-{i}-native.json")), &world)?
        {
            if step.input.packet.mode != app::PAYMENT
                || bincode::serialize(&step.input.packet.operations)? != bincode::serialize(ops)?
            {
                return Err("cached payment operations".into());
            }
            step
        } else {
            prepare_step(
                w,
                policy,
                &world.state,
                world.point,
                world.value,
                app::PAYMENT,
                ops,
                &[],
            )?
        };
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
    if joint {
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
        let mode = if joint { app::JOINT } else { app::NAMED };
        let mut step = if let Some(step) =
            cached_step(&out.join(format!("withdraw-{i}-native.json")), &world)?
        {
            let claims = owners
                .iter()
                .map(|i| nullifier(&w.witnesses[*i].secret, &w.witnesses[*i].input))
                .collect::<Vec<_>>();
            if step.input.packet.mode != mode
                || step
                    .input
                    .packet
                    .operations
                    .iter()
                    .map(|o| o.statement.nullifier)
                    .collect::<Vec<_>>()
                    != claims
            {
                return Err("cached withdrawal claims/mode".into());
            }
            for i in owners {
                if step
                    .tx
                    .outputs
                    .iter()
                    .filter(|o| {
                        o.value == w.d && o.script_public_key == recipient(&w.payout_keys[*i])
                    })
                    .count()
                    != 1
                {
                    return Err("cached owner full entitlement".into());
                }
            }
            step
        } else {
            prepare_step(
                w,
                policy,
                &world.state,
                world.point,
                world.value,
                mode,
                &[],
                owners,
            )?
        };
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
        &json!({"batched":batched,"joint":joint,"usefulPaymentSompi":3*w.d,"nativeTransactionCount":world.records.len(),"totalNativeFeeSompi":fees,"networkFeePercent":fees as f64*100.0/(3*w.d) as f64,"outerProofSeconds":proof_seconds,"walletSetupSeconds":w.setup_seconds,"walletPaymentProofSeconds":w.inner_seconds,"finalPrincipalSompi":0,"finalPrivateLiabilitySompi":0,"finalUnpaidExits":0,"transactions":world.records,"nativeFullValidation":true,"offlineRelayChecks":true,"chainAcceptance":false,"providerInvoiceUsd":0,"hardwareCostValuation":"measured usage separately; no claim of zero electricity/depreciation"}),
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
    let (mut w, fund, entry, fund_report) =
        if let Ok(previous) = std::env::var("KPI_BATCH_REUSE_FROM") {
            let previous = Path::new(&previous);
            let restored = restored_work(previous)?;
            fs::create_dir(out.join("30-kas"))?;
            fs::create_dir(out.join("30-kas/private"))?;
            fs::set_permissions(
                out.join("30-kas/private"),
                fs::Permissions::from_mode(0o700),
            )?;
            for name in [
                "initial-public-state.json",
                "private-payment-operations.json",
                "wallet-resources.json",
                "deposit.json",
                "private/wallets.json",
                "private/proving-parameters.bin",
            ] {
                fs::copy(
                    previous.join("30-kas").join(name),
                    out.join("30-kas").join(name),
                )?;
            }
            if restored.1.outputs[0].script_public_key != policy.spk(restored.0.initial.root()) {
                return Err("resumed bank program/root mismatch".into());
            }
            restored
        } else {
            let w = workload(1_000_000_000, &out.join("30-kas"))?;
            let (fund, entry, report) = funding(&w, &policy)?;
            save(
                &out.join("30-kas/deposit.json"),
                &json!({"transaction":fund,"report":report,"suppliedSourceUtxo":true}),
            )?;
            (w, fund, entry, report)
        };
    let _baseline = world(
        &program,
        &policy,
        &mut w,
        &fund,
        &entry,
        &fund_report,
        &out.join("30-kas/named"),
        false,
        false,
    )?;
    let _matched_named = world(
        &program,
        &policy,
        &mut w,
        &fund,
        &entry,
        &fund_report,
        &out.join("30-kas/named-batched"),
        true,
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
        true,
    )?;
    Ok(())
}

fn from_hex<T: serde::de::DeserializeOwned>(v: &Value) -> Result<T> {
    Ok(bincode::deserialize(&hex::decode(
        v.as_str().ok_or("hex string")?,
    )?)?)
}
fn read(p: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}
fn read_transaction(value: &Value) -> Result<Transaction> {
    let mut tx: Transaction = serde_json::from_value(value.clone())?;
    let provided = tx.id();
    tx.finalize();
    if tx.id() != provided {
        return Err("serialized transaction identifier mismatch".into());
    }
    Ok(tx)
}
fn recorded_step(r: &Value) -> Result<Step> {
    let input: app::Input = from_hex(&r["inputBincodeHex"])?;
    let output = app::execute(&input)?;
    let recorded: app::State = from_hex(&r["postStateBincodeHex"])?;
    if output.state.root() != recorded.root() {
        return Err("recorded post state".into());
    }
    Ok(Step {
        tx: read_transaction(&r["transaction"])?,
        input,
        output,
        report: r["report"].clone(),
    })
}
fn restored_work(run: &Path) -> Result<(Work, Transaction, UtxoEntry, Value)> {
    use ark_serialize::CanonicalDeserialize;
    let base = run.join("30-kas");
    let initial: app::State =
        from_hex(&read(&base.join("initial-public-state.json"))?["bincodeHex"])?;
    let secrets = read(&base.join("private/wallets.json"))?;
    let wallets: [Wallet; 3] = std::array::from_fn(|i| {
        Wallet::restore_local(
            &hex::decode(secrets["walletBackups"][i].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        )
    });
    let payout_keys = std::array::from_fn(|i| {
        SecretKey::from_slice(&hex::decode(secrets["payoutKeys"][i].as_str().unwrap()).unwrap())
            .unwrap()
    });
    let funding_key = SecretKey::from_slice(&hex::decode(
        secrets["fundingKey"].as_str().ok_or("funding key")?,
    )?)?;
    let pk = ark_groth16::ProvingKey::<ark_bn254::Bn254>::deserialize_compressed(
        fs::read(base.join("private/proving-parameters.bin"))?.as_slice(),
    )?;
    let resources = read(&base.join("wallet-resources.json"))?;
    let engine = Engine {
        vk: pk.vk.clone(),
        pk,
        proofs: 0,
        constraints: resources["constraints"].as_u64().ok_or("constraints")? as usize,
    };
    if engine.id() != initial.ledger.verifier {
        return Err("restored setup key".into());
    }
    let operations: Vec<Operation> =
        serde_json::from_value(read(&base.join("private-payment-operations.json"))?)?;
    let mut post = initial.clone();
    for op in &operations {
        post.ledger.apply(&engine, op)?;
    }
    let witnesses = std::array::from_fn(|i| {
        let notes = wallets[i].discover(
            &post.ledger.deliveries,
            &post.ledger.tree,
            &post.ledger.nullifiers,
        );
        assert_eq!(notes.len(), 1);
        let (p, q) = post.ledger.tree.path(notes[0].1).unwrap();
        wallets[i].witness(notes[0].0.clone(), [Note::dummy(), Note::dummy()], p, q)
    });
    let deposit = read(&base.join("deposit.json"))?;
    let fund = read_transaction(&deposit["transaction"])?;
    let d = initial.ledger.reserve / 3;
    let entry = UtxoEntry::new(
        fund.outputs[0].value,
        fund.outputs[0].script_public_key.clone(),
        0,
        false,
        None,
    );
    let source = fund.inputs[0].previous_outpoint;
    Ok((
        Work {
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
            setup_seconds: resources["setupSeconds"].as_f64().unwrap(),
            inner_seconds: resources["innerProofSeconds"].as_f64().unwrap(),
        },
        fund,
        entry,
        deposit["report"].clone(),
    ))
}
fn prepare_refund(w: &mut Work, policy: &Policy, world: &World) -> Result<Step> {
    let started = Instant::now();
    let state = &world.state;
    let root = state.root();
    let principal = state.ledger.reserve;
    let mut s = Statement::new(RECOVER, w.engine.id(), state.ledger.tree.root());
    s.deposit = state.pool;
    s.deposit_owner = w.wallets[0].address.owner;
    s.deposit_value = principal;
    s.exit_value = principal;
    s.exit_destination = [1; 32];
    let mut packet = app::Packet {
        mode: app::REFUND,
        operations: vec![Operation {
            statement: s.clone(),
            deliveries: [Delivery::absent(), Delivery::absent()],
            proof: vec![0; 128],
        }],
    };
    let mut tx = native::transaction(
        world.point,
        vec![
            TransactionOutput::new(principal, recipient(&w.payout_keys[0])),
            TransactionOutput::new(world.value - principal, native::spk(&state.fee_refund_spk)),
        ],
        packet.bytes(),
        native::BUDGET,
    );
    tx.inputs[0].signature_script = policy.witness(root, [0; 32], &[0; 128]);
    let entry = world.entry()?;
    let mut report = native::quote(&tx, &entry);
    let fee = report["minimumDefaultRelayFeeSompi"]
        .as_u64()
        .ok_or("refund fee")?;
    tx.outputs[1].value = tx.outputs[1]
        .value
        .checked_sub(fee)
        .ok_or("refund allowance")?;
    s.exit_destination = native::effects(&tx, world.value).context(root);
    packet.operations[0] = w.engine.prove(
        s,
        w.wallets[0].witness(
            w.wallets[0].authority_note(),
            [Note::dummy(), Note::dummy()],
            [[0; 32]; DEPTH],
            [false; DEPTH],
        ),
        [Delivery::absent(), Delivery::absent()],
    );
    tx.payload = packet.bytes();
    tx.finalize();
    assert_eq!(
        native::quote(&tx, &entry)["minimumDefaultRelayFeeSompi"],
        fee
    );
    let input = app::Input {
        state: state.clone(),
        packet,
        effects: native::effects(&tx, world.value),
    };
    let output = app::execute(&input)?;
    assert_eq!(&output.journal[32..64], &[0; 32]);
    report["walletPreparationSeconds"] = json!(started.elapsed().as_secs_f64());
    report["genuineNewWalletProofs"] = json!(1);
    Ok(Step {
        tx,
        input,
        output,
        report,
    })
}
fn host_reject(cases: &mut Vec<Value>, name: &str, input: &app::Input, reason: &str) -> Result<()> {
    let error = app::execute(input).err().ok_or("host accepted negative")?;
    if !error.contains(reason) {
        return Err(format!("{name}: wrong rejection {error}; wanted {reason}").into());
    }
    cases.push(json!({"case":name,"layer":"real wallet kernel","error":error}));
    Ok(())
}
fn negative_controls(
    program: &[u8],
    policy: &Policy,
    step: &Step,
    entry: &UtxoEntry,
) -> Result<Vec<Value>> {
    let mut cases = vec![];
    let mut new_point = step.input.clone();
    new_point.effects.previous = fresh();
    host_reject(
        &mut cases,
        "owner_approval_bound_to_exact_bank_outpoint",
        &new_point,
        "complete native effects authorization",
    )?;
    cases.push(json!({"case":"stale_owner_approval_guest","layer":"real guest executor","error":prover::reject_guest(program,&new_point)?}));
    let mut wrong_amount_entry = entry.clone();
    wrong_amount_entry.amount += 1;
    cases.push(json!({"case":"actual_input_amount_mismatch","layer":"native Full","error":native::validate(&step.tx,&wrong_amount_entry).err().ok_or("wrong actual input accepted")?}));
    let mut wrong_root_entry = entry.clone();
    wrong_root_entry.script_public_key = policy.spk(fresh());
    cases.push(json!({"case":"actual_prior_state_root_mismatch","layer":"native Full","error":native::validate(&step.tx,&wrong_root_entry).err().ok_or("wrong actual prior root accepted")?}));
    for name in [
        "payout_destination",
        "payout_amount",
        "input_outpoint",
        "public_payload",
        "new_root",
        "compressed_proof",
    ] {
        let mut tx = step.tx.clone();
        match name {
            "payout_destination" => tx.outputs[0].script_public_key = recipient(&key()),
            "payout_amount" => {
                tx.outputs[0].value -= 1;
                tx.outputs.last_mut().unwrap().value += 1;
            }
            "input_outpoint" => tx.inputs[0].previous_outpoint = native::fake_point(fresh()),
            "public_payload" => {
                let last = tx.payload.len() - 1;
                tx.payload[last] ^= 1;
            }
            "new_root" => {
                tx.inputs[0].signature_script = policy.witness(
                    step.input.state.root(),
                    fresh(),
                    &step.tx.inputs[0].signature_script[2..130],
                );
            }
            "compressed_proof" => {
                let mut proof = vec![0u8; 128];
                proof[0] = 1;
                tx.inputs[0].signature_script = policy.witness(
                    step.input.state.root(),
                    step.output.journal[32..64].try_into().unwrap(),
                    &proof,
                );
            }
            _ => unreachable!(),
        }
        // Keep fee and byte classes where applicable so native scripts/proof checks are reached.
        tx.finalize();
        let error = native::validate(&tx, entry)
            .err()
            .ok_or(format!("native accepted {name}"))?;
        cases.push(json!({"case":name,"layer":"native Full","error":error}));
    }
    let mut bad = step.input.clone();
    bad.packet.operations[0].statement.exit_value += 1;
    host_reject(&mut cases, "changed_authorized_amount", &bad, "proof")?;
    let mut bad = step.input.clone();
    bad.packet.operations[1] = bad.packet.operations[0].clone();
    host_reject(&mut cases, "duplicate_nullifier", &bad, "nullifier")?;
    let mut bad = step.input.clone();
    bad.packet.operations.truncate(2);
    host_reject(
        &mut cases,
        "partial_group_cannot_pay_three",
        &bad,
        "output shape",
    )?;
    cases.push(json!({"case":"partial_group_guest","layer":"real guest executor","error":prover::reject_guest(program,&bad)?}));
    let mut bad = step.input.clone();
    bad.state
        .ledger
        .nullifiers
        .insert(bad.packet.operations[0].statement.nullifier);
    host_reject(
        &mut cases,
        "already_spent_current_nullifier",
        &bad,
        "authorization",
    )?;
    let mut bad = step.input.clone();
    bad.effects.input_value = app::MAX_SOMPI + 1;
    host_reject(
        &mut cases,
        "native_input_above_money_supply",
        &bad,
        "input range",
    )?;
    let mut bad = step.input.clone();
    bad.effects.outputs[0].value = 0;
    host_reject(&mut cases, "native_zero_output", &bad, "output range")?;
    let mut bad = step.input.clone();
    bad.effects.outputs = vec![
        app::NativeOutput {
            value: app::MAX_SOMPI,
            spk: vec![]
        };
        8
    ];
    host_reject(&mut cases, "output_sum_overflow", &bad, "overflow")?;
    let mut bad = step.input.clone();
    bad.effects.input_value = 0;
    host_reject(
        &mut cases,
        "native_principal_underbacking",
        &bad,
        "input backing",
    )?;
    let mut bad = step.input.clone();
    bad.effects.outputs.last_mut().unwrap().value = 1;
    host_reject(
        &mut cases,
        "fee_cannot_take_principal_or_exceed_cap",
        &bad,
        "fee allowance",
    )?;
    Ok(cases)
}
/// Separate campaign using saved real wallets; core run remains immutable.
pub fn extras(program_path: &Path, run: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    let program = fs::read(program_path)?;
    let policy = Policy {
        image: risc0_zkvm::compute_image_id(&program)?.into(),
    };
    let (mut w, fund, entry, report) = restored_work(run)?;
    let record = read(&run.join("30-kas/batched/payment-0-native.json"))?;
    let payment = recorded_step(&record)?;
    let mut paid = World::start(&w, &fund, &entry, &report);
    paid.accept(&payment)?;
    // Aborted fork: new registration keys, real proofs, only two approvals delivered.
    let abort_started = Instant::now();
    let proof_before = w.engine.proofs;
    let final_keys = w.payout_keys;
    w.payout_keys = [key(), key(), key()];
    let claims = std::array::from_fn(|i| nullifier(&w.witnesses[i].secret, &w.witnesses[i].input));
    let abort_reg = registration::run(
        &mut w.engine,
        &w.witnesses,
        paid.state.ledger.tree.root(),
        claims,
        std::array::from_fn(|i| pubkey(&w.payout_keys[i])),
        w.d,
    );
    save(&out.join("abort-registration.json"), &abort_reg.candidate)?;
    let valid_abort = prepare_step(
        &mut w,
        &policy,
        &paid.state,
        paid.point,
        paid.value,
        app::JOINT,
        &[],
        &[0, 1, 2],
    )?;
    let mut incomplete = valid_abort.input.clone();
    incomplete.packet.operations.truncate(2);
    let root_before = paid.state.root();
    let point_before = paid.point;
    let mut abort_cases = vec![];
    host_reject(
        &mut abort_cases,
        "missing_third_approval",
        &incomplete,
        "output shape",
    )?;
    let guest_error = prover::reject_guest(&program, &incomplete)?;
    assert_eq!(root_before, paid.state.root());
    assert_eq!(point_before, paid.point);
    assert!(paid.entry().is_ok());
    save(
        &out.join("abort.json"),
        &json!({"seconds":abort_started.elapsed().as_secs_f64(),"generatedWalletProofs":w.engine.proofs-proof_before,"deliveredExitApprovals":2,"generatedExitApprovals":3,"nativeFeeSompi":0,"principalLostSompi":0,"unchangedState":hex::encode(root_before),"unchangedOutpoint":point_before,"guestError":guest_error,"hostCases":abort_cases,"inputBincodeHex":hex::encode(bincode::serialize(&incomplete)?),"scope":"withheld approval; local synthetic fork, no submission"}),
    )?;
    w.payout_keys = final_keys;
    let retry_started = Instant::now();
    let before = w.engine.proofs;
    let retry_reg = registration::run(
        &mut w.engine,
        &w.witnesses,
        paid.state.ledger.tree.root(),
        claims,
        std::array::from_fn(|i| pubkey(&w.payout_keys[i])),
        w.d,
    );
    assert_ne!(abort_reg.round, retry_reg.round);
    save(&out.join("retry-registration.json"), &retry_reg.candidate)?;
    let mut retry = prepare_step(
        &mut w,
        &policy,
        &paid.state,
        paid.point,
        paid.value,
        app::JOINT,
        &[],
        &[0, 1, 2],
    )?;
    let prior = paid.entry()?;
    let (proof, stats) = prover::prove(&program, &retry.input, &out.join("retry-proof"))?;
    finish(&mut retry, &policy, &proof, &prior)?;
    retry.report["proving"] = stats;
    let mut drained = paid.clone();
    drained.accept(&retry)?;
    assert!(drained.active.is_empty());
    let retry_replay_error = drained
        .accept(&retry)
        .err()
        .ok_or("terminal payout replay accepted")?;
    save(
        &out.join("retry.json"),
        &json!({"seconds":retry_started.elapsed().as_secs_f64(),"newWalletProofs":w.engine.proofs-before,"nativeFeeSompi":retry.output.fee,"record":drained.records.last(),"terminalReplayRejected":retry_replay_error.to_string()}),
    )?;
    let mut controls = negative_controls(&program, &policy, &retry, &prior)?;
    let receipt: risc0_zkvm::Receipt =
        bincode::deserialize(&fs::read(out.join("retry-proof/candidate-compressed.bin"))?)?;
    let wrong_image = risc0_zkvm::sha::Digest::from_bytes(fresh());
    controls.push(json!({"case":"wrong_guest_image","layer":"strict SDK complete receipt","error":prover::verify(&receipt,wrong_image,&retry.output.journal).err().ok_or("wrong image accepted")?.to_string()}));
    let mut wrong_journal = retry.output.journal.clone();
    wrong_journal[0] ^= 1;
    controls.push(json!({"case":"wrong_exact_journal","layer":"strict SDK complete receipt","error":prover::verify(&receipt,risc0_zkvm::compute_image_id(&program)?,&wrong_journal).err().ok_or("wrong journal accepted")?.to_string()}));
    let mut changed_successor = payment.tx.clone();
    changed_successor.outputs[0].script_public_key =
        Policy { image: fresh() }.spk(payment.output.state.root());
    changed_successor.finalize();
    let successor_error = native::validate(&changed_successor, &entry)
        .err()
        .ok_or("changed successor accepted")?;
    controls.push(
        json!({"case":"changed_successor_program","layer":"native Full","error":successor_error}),
    );
    let mut changed_root = payment.tx.clone();
    changed_root.inputs[0].signature_script = policy.witness(
        payment.input.state.root(),
        fresh(),
        &payment.tx.inputs[0].signature_script[2..130],
    );
    changed_root.finalize();
    controls.push(json!({"case":"changed_successor_state_root","layer":"native Full","error":native::validate(&changed_root,&entry).err().ok_or("changed root accepted")?}));
    save(&out.join("negative-controls.json"), &json!(controls))?;
    // Each backup owner independently exits, retaining everyone else's backing.
    let mut solo = paid.clone();
    fs::create_dir(out.join("private"))?;
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(out.join("private"), fs::Permissions::from_mode(0o700))?;
    }
    for i in 0..3 {
        let restored = Wallet::restore_local(&w.wallets[i].local_backup());
        let found = restored.discover(
            &solo.state.ledger.deliveries,
            &solo.state.ledger.tree,
            &solo.state.ledger.nullifiers,
        );
        assert_eq!(found.len(), 1);
        let (p, q) = solo.state.ledger.tree.path(found[0].1)?;
        w.payout_keys[i] = key();
        prover::write(
            &out.join(format!("private/solo-{i}-native-key.bin")),
            &w.payout_keys[i].secret_bytes(),
        )?;
        w.witnesses[i] = restored.witness(found[0].0.clone(), [Note::dummy(), Note::dummy()], p, q);
        let mut step = prepare_step(
            &mut w,
            &policy,
            &solo.state,
            solo.point,
            solo.value,
            app::SOLO,
            &[],
            &[i],
        )?;
        let prior = solo.entry()?;
        let (proof, stats) = prover::prove(&program, &step.input, &out.join(format!("solo-{i}")))?;
        finish(&mut step, &policy, &proof, &prior)?;
        step.report["proving"] = stats;
        solo.accept(&step)?;
        assert!(solo.accept(&step).is_err());
        let mut ledger_replay = solo.state.ledger.clone();
        let nf = step.input.packet.operations[0].statement.nullifier;
        assert!(ledger_replay.nullifiers.contains(&nf));
        let nf_error = ledger_replay
            .apply(&w.engine, &step.input.packet.operations[0])
            .err()
            .ok_or("paid NF replay accepted after normalization")?;
        assert!(nf_error.contains("current economic nullifier spent"));
        save(
            &out.join(format!("solo-{i}-nf-replay.json")),
            &json!({"genuinePriorProof":true,"sameAcceptedHistoricalAnchor":true,"error":nf_error,"economicNullifiersRetained":solo.state.ledger.nullifiers.len()}),
        )?;
        save(
            &out.join(format!("solo-{i}-native.json")),
            solo.records.last().unwrap(),
        )?;
    }
    assert_eq!(solo.state.ledger.reserve, 0);
    assert_eq!(solo.state.ledger.private_liability, 0);
    assert!(solo.active.is_empty());
    save(
        &out.join("solo.json"),
        &json!({"records":solo.records,"finalPrincipalSompi":0,"restoredWallets":3,"issuerOrPeerAuthorizationRequired":false,"freshNativeRecipientKeys":true,"walletSeedsRestoredWithoutRegistration":true,"scope":"common-set solo fallback still reveals one-owner exits"}),
    )?;
    let mut initial = World::start(&w, &fund, &entry, &report);
    let mut refund = prepare_refund(&mut w, &policy, &initial)?;
    let mut unauthorized = refund.input.clone();
    unauthorized.packet.operations[0].statement.deposit_owner = w.wallets[1].address.owner;
    let error = app::execute(&unauthorized)
        .err()
        .ok_or("non-owner refund accepted")?;
    let (proof, stats) = prover::prove(&program, &refund.input, &out.join("refund-proof"))?;
    finish(&mut refund, &policy, &proof, &initial.entry()?)?;
    refund.report["proving"] = stats;
    initial.accept(&refund)?;
    assert!(initial.active.is_empty());
    assert_eq!(initial.state.ledger.reserve, 0);
    assert!(initial.accept(&refund).is_err());
    save(
        &out.join("refund.json"),
        &json!({"records":initial.records,"principalRefundedSompi":3*w.d,"wrongOwnerRejected":error,"replayRejected":true,"finalPrincipalSompi":0}),
    )?;
    Ok(())
}

pub fn replay(program_path: &Path, run: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    let program = fs::read(program_path)?;
    let image = risc0_zkvm::compute_image_id(&program)?;
    let policy = Policy {
        image: image.into(),
    };
    let mut reports = vec![];
    for name in [
        "30-kas/named",
        "30-kas/named-batched",
        "30-kas/batched",
        "75-kas/batched",
    ] {
        let dir = run.join(name);
        let world = read(&dir.join("world.json"))?;
        let txs = world["transactions"]
            .as_array()
            .ok_or("world transactions")?;
        let fund = read_transaction(&txs[0]["transaction"])?;
        let initial: app::State = bincode::deserialize(&fund.payload)?;
        if fund.outputs[0].script_public_key != policy.spk(initial.root()) {
            return Err("deposit root/policy".into());
        }
        let source = UtxoEntry::new(
            initial.ledger.reserve + FEE_BUFFER + 100_000_000,
            fund.outputs[1].script_public_key.clone(),
            0,
            false,
            None,
        );
        native::validate(&fund, &source)?;
        let mut state = initial;
        let mut point = TransactionOutpoint::new(fund.id(), 0);
        let mut entry = UtxoEntry::new(
            fund.outputs[0].value,
            fund.outputs[0].script_public_key.clone(),
            0,
            false,
            None,
        );
        let mut pay_i = 0;
        let mut exit_i = 0;
        let mut fees = txs[0]["report"]["feeSompi"].as_u64().unwrap();
        for record in txs.iter().skip(1) {
            let step = recorded_step(record)?;
            if state.root() != step.input.state.root()
                || point != step.tx.inputs[0].previous_outpoint
            {
                return Err("public replay lineage/state".into());
            }
            if bincode::serialize(&native::effects(&step.tx, entry.amount))?
                != bincode::serialize(&step.input.effects)?
                || step.tx.payload != step.input.packet.bytes()
            {
                return Err("public replay actual effects/payload".into());
            }
            use ark_serialize::CanonicalDeserialize;
            let vk = ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(
                state.wallet_vk.as_slice(),
            )?;
            for op in &step.input.packet.operations {
                if !proof::verify(&vk, op) {
                    return Err("independent Arkworks public wallet verification".into());
                }
            }
            if step.input.packet.mode == app::JOINT {
                let registration = registration::verify_public(
                    &read(&dir.join("registration.json"))?,
                    &state,
                    &step.input.packet.operations,
                )?;
                let keys = registration["registeredKeys"].as_array().unwrap();
                for k in keys {
                    let expected = [
                        vec![0, 0, 32],
                        hex::decode(k.as_str().unwrap())?,
                        vec![0xac],
                    ]
                    .concat();
                    if step
                        .tx
                        .outputs
                        .iter()
                        .filter(|o| native::encoded(&o.script_public_key) == expected)
                        .count()
                        != 1
                    {
                        return Err("registered/actual payout key".into());
                    }
                }
            }
            let d = if step.input.packet.mode == app::PAYMENT {
                let d = dir.join(format!("payment-{pay_i}"));
                pay_i += 1;
                d
            } else {
                let d = dir.join(format!("withdraw-{exit_i}"));
                exit_i += 1;
                d
            };
            let receipt: risc0_zkvm::Receipt =
                bincode::deserialize(&fs::read(d.join("candidate-compressed.bin"))?)?;
            prover::verify(&receipt, image, &step.output.journal)?;
            let raw = prover::native_proof(&receipt)?;
            if raw != fs::read(d.join("native-proof.bin"))?
                || step.tx.inputs[0].signature_script
                    != policy.witness(
                        state.root(),
                        step.output.journal[32..64].try_into().unwrap(),
                        &raw,
                    )
            {
                return Err("replayed actual native proof".into());
            }
            let q = native::validate(&step.tx, &entry)?;
            fees += q["feeSompi"].as_u64().unwrap();
            state = step.output.state;
            if state.ledger.reserve > 0 {
                point = TransactionOutpoint::new(step.tx.id(), 0);
                entry = UtxoEntry::new(
                    step.tx.outputs[0].value,
                    step.tx.outputs[0].script_public_key.clone(),
                    0,
                    false,
                    None,
                );
            }
        }
        assert_eq!(state.ledger.reserve, 0);
        assert_eq!(state.ledger.private_liability, 0);
        assert!(state.canonical());
        assert_eq!(world["totalNativeFeeSompi"], fees);
        reports.push(json!({"world":name,"transactions":txs.len(),"realCompleteReceipts":txs.len()-1,"feesSompi":fees,"finalPrincipalSompi":0,"allNativeFull":true,"privateFilesRead":false}));
    }
    save(
        &out.join("public-replay.json"),
        &json!({"image":image.to_string(),"worlds":reports,"scope":"offline complete proof/native replay with supplied source UTXO"}),
    )?;
    Ok(())
}

fn state_view(s: &app::State) -> Value {
    let app::State {
        ledger,
        pool,
        wallet_vk,
        fee_refund_spk,
    } = s;
    let Ledger {
        verifier,
        tree,
        anchors,
        nullifiers,
        deposits,
        exits,
        paid_native_outputs,
        deliveries,
        reserve,
        private_liability,
        batch,
    } = ledger;
    json!({"root":hex::encode(s.root()),"pool":pool,"wallet_vk":wallet_vk,"fee_refund_spk":fee_refund_spk,"ledger":{"verifier":verifier,"tree":tree,"anchors":anchors,"nullifiers":nullifiers,"deposits":deposits.iter().map(|(h,d)|(hex::encode(h),d)).collect::<std::collections::BTreeMap<_,_>>(),"exits":exits.iter().map(|(h,d)|(hex::encode(h),d)).collect::<std::collections::BTreeMap<_,_>>(),"paid_native_outputs":paid_native_outputs,"deliveries":deliveries,"reserve":reserve,"private_liability":private_liability,"batch":batch}})
}
pub fn views(run: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    for name in [
        "30-kas/named",
        "30-kas/named-batched",
        "30-kas/batched",
        "75-kas/batched",
    ] {
        let dir = run.join(name);
        if !dir.join("world.json").exists() {
            continue;
        }
        let world = read(&dir.join("world.json"))?;
        let initial: app::State = bincode::deserialize(
            &serde_json::from_value::<Transaction>(
                world["transactions"][0]["transaction"].clone(),
            )?
            .payload,
        )?;
        let mut steps = vec![];
        for record in world["transactions"].as_array().unwrap().iter().skip(1) {
            let step = recorded_step(record)?;
            steps.push(json!({"beforeState":state_view(&step.input.state),"packet":step.input.packet,"effects":step.input.effects,"context":hex::encode(step.input.effects.context(step.input.state.root())),"afterState":state_view(&step.output.state),"journalHex":hex::encode(&step.output.journal),"inputBincodeHex":record["inputBincodeHex"],"postStateBincodeHex":record["postStateBincodeHex"]}));
        }
        save(
            &out.join(name.replace('/', "-") + ".json"),
            &json!({"schema":"batched-payment-public-view-v1","world":world,"initialState":state_view(&initial),"steps":steps,"rawBincodeIsCompletePublicState":true,"sourceWorldSha256":hex::encode(hash(&fs::read(dir.join("world.json"))?))}),
        )?;
    }
    Ok(())
}

pub fn replay_extras(program_path: &Path, core: &Path, extras: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    let program = fs::read(program_path)?;
    let image = risc0_zkvm::compute_image_id(&program)?;
    let policy = Policy {
        image: image.into(),
    };
    let core_world = read(&core.join("30-kas/batched/world.json"))?;
    let retry = read(&extras.join("retry.json"))?;
    let solo = read(&extras.join("solo.json"))?;
    let refund = read(&extras.join("refund.json"))?;
    let retry_records = vec![
        core_world["transactions"][0].clone(),
        core_world["transactions"][1].clone(),
        retry["record"].clone(),
    ];
    let groups = [
        ("retry", retry_records),
        (
            "solo",
            solo["records"].as_array().ok_or("solo records")?.clone(),
        ),
        (
            "refund",
            refund["records"]
                .as_array()
                .ok_or("refund records")?
                .clone(),
        ),
    ];
    let mut reports = vec![];
    for (name, records) in groups {
        let fund = read_transaction(&records[0]["transaction"])?;
        let mut state: app::State = bincode::deserialize(&fund.payload)?;
        if fund.outputs[0].script_public_key != policy.spk(state.root()) {
            return Err("recovery initial root/policy".into());
        }
        let source = UtxoEntry::new(
            state.ledger.reserve + FEE_BUFFER + 100_000_000,
            fund.outputs[1].script_public_key.clone(),
            0,
            false,
            None,
        );
        native::validate(&fund, &source)?;
        let mut point = TransactionOutpoint::new(fund.id(), 0);
        let mut entry = UtxoEntry::new(
            fund.outputs[0].value,
            fund.outputs[0].script_public_key.clone(),
            0,
            false,
            None,
        );
        let mut solo_i = 0;
        let mut checked = 0;
        for record in records.iter().skip(1) {
            let step = recorded_step(record)?;
            if step.input.state.root() != state.root()
                || step.tx.inputs[0].previous_outpoint != point
                || bincode::serialize(&step.input.effects)?
                    != bincode::serialize(&native::effects(&step.tx, entry.amount))?
                || step.tx.payload != step.input.packet.bytes()
            {
                return Err("recovery actual lineage/effects".into());
            }
            let proof_dir = match step.input.packet.mode {
                app::PAYMENT => core.join("30-kas/batched/payment-0"),
                app::JOINT => extras.join("retry-proof"),
                app::SOLO => {
                    let d = extras.join(format!("solo-{solo_i}"));
                    solo_i += 1;
                    d
                }
                app::REFUND => extras.join("refund-proof"),
                _ => return Err("recovery mode".into()),
            };
            let receipt: risc0_zkvm::Receipt =
                bincode::deserialize(&fs::read(proof_dir.join("candidate-compressed.bin"))?)?;
            prover::verify(&receipt, image, &step.output.journal)?;
            let raw = prover::native_proof(&receipt)?;
            if step.tx.inputs[0].signature_script
                != policy.witness(
                    state.root(),
                    step.output.journal[32..64].try_into().unwrap(),
                    &raw,
                )
            {
                return Err("recovery actual native proof".into());
            }
            use ark_serialize::CanonicalDeserialize;
            let vk = ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(
                state.wallet_vk.as_slice(),
            )?;
            for op in &step.input.packet.operations {
                if !proof::verify(&vk, op) {
                    return Err("recovery independent wallet verifier".into());
                }
            }
            if step.input.packet.mode == app::JOINT {
                registration::verify_public(
                    &read(&extras.join("retry-registration.json"))?,
                    &state,
                    &step.input.packet.operations,
                )?;
            }
            native::validate(&step.tx, &entry)?;
            state = step.output.state;
            checked += 1;
            if state.ledger.reserve > 0 {
                point = TransactionOutpoint::new(step.tx.id(), 0);
                entry = UtxoEntry::new(
                    step.tx.outputs[0].value,
                    step.tx.outputs[0].script_public_key.clone(),
                    0,
                    false,
                    None,
                );
            }
            if step.input.packet.mode == app::SOLO {
                let mut ledger = state.ledger.clone();
                let error = ledger
                    .apply(
                        &app::Verifier::new(&state.wallet_vk)?,
                        &step.input.packet.operations[0],
                    )
                    .err()
                    .ok_or("public NF replay accepted")?;
                if !error.contains("current economic nullifier spent") {
                    return Err("wrong NF replay layer".into());
                }
            }
        }
        if state.ledger.reserve != 0 || state.ledger.private_liability != 0 || !state.canonical() {
            return Err("recovery final liabilities".into());
        }
        reports.push(json!({"world":name,"transactions":records.len(),"completeReceipts":checked,"nativeFull":true,"independentWalletProofs":true,"finalPrincipalSompi":0,"privateFilesRead":false}));
    }
    save(
        &out.join("extra-public-replay.json"),
        &json!({"image":image.to_string(),"worlds":reports,"scope":"public receipt/native replay for fresh retry, all restored solo exits and pending deposit refund"}),
    )?;
    Ok(())
}

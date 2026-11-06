include!("../../../batched-payment-costs/host/src/bench.rs");

fn self_payment_outputs(wallet: &Wallet, value: u64) -> [Note; 2] {
    [wallet.note(value / 2), wallet.note(value - value / 2)]
}

/// Minimal regression at the exact full-circuit seam; no setup/prover/GPU needed.
pub fn transfer_check(core: &Path, busy: &Path, out: &Path) -> Result<()> {
    let state: app::State =
        from_hex(&read(&busy.join("pinned-initial.native.json"))?["postStateBincodeHex"])?;
    let secret = read(&core.join("30-kas/private/wallets.json"))?;
    let wallet = Wallet::restore_local(
        &hex::decode(secret["walletBackups"][0].as_str().ok_or("backup")?)?
            .try_into()
            .map_err(|_| "backup size")?,
    );
    let notes = wallet.discover(
        &state.ledger.deliveries,
        &state.ledger.tree,
        &state.ledger.nullifiers,
    );
    if notes.len() != 1 {
        return Err("repro unspent note".into());
    }
    let (p, q) = state.ledger.tree.path(notes[0].1)?;
    let mut cases = vec![];
    for positive_outputs in [1, 2] {
        let v = notes[0].0.value;
        let [a, b] = if positive_outputs == 1 {
            [wallet.note(v), Note::dummy()]
        } else {
            self_payment_outputs(&wallet, v)
        };
        let deliveries = [
            a.deliver()?,
            if positive_outputs == 1 {
                Delivery::absent()
            } else {
                b.deliver()?
            },
        ];
        let mut s = Statement::new(TRANSFER, state.ledger.verifier, state.ledger.tree.root());
        s.nullifier = wallet.nf(&notes[0].0);
        for i in 0..2 {
            s.outputs[i] = deliveries[i].commitment;
            s.delivery[i] = if deliveries[i].ciphertext.is_empty() {
                [0; 32]
            } else {
                hash(&deliveries[i].ciphertext)
            };
        }
        let circuit = circuit::WalletCircuit {
            statement: s,
            witness: wallet.witness(notes[0].0.clone(), [a, b], p, q),
        };
        let (constraints, satisfied) = circuit.check()?;
        cases.push(json!({"positiveOutputs":positive_outputs,"fullCircuitSatisfied":satisfied,"constraints":constraints}));
    }
    save(
        out,
        &json!({"actualFailedFixture":busy,"cases":cases,"privateWitnessPrintedOrRetained":false}),
    )?;
    if cases[0]["fullCircuitSatisfied"].as_bool().unwrap()
        || !cases[1]["fullCircuitSatisfied"].as_bool().unwrap()
    {
        return Err("self-payment full-circuit regression".into());
    }
    Ok(())
}

/// Host-only checked generator, before building the new image.
pub fn pin(state_path: &Path, pins: &Path) -> Result<()> {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    let state: app::State = from_hex(&read(state_path)?["bincodeHex"])?;
    let raw = &state.wallet_vk;
    let mut r = raw.as_slice();
    let vk = ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(&mut r)?;
    if !r.is_empty() || proof::serialize(&vk) != *raw || vk.gamma_abc_g1.len() != 3 {
        return Err("checked canonical wallet key/arity".into());
    }
    if hash(raw) != state.ledger.verifier {
        return Err("state key identity".into());
    }
    let mut full = vec![];
    vk.serialize_uncompressed(&mut full)?;
    prover::write(&pins.join("vk-compressed.bin"), raw)?;
    prover::write(&pins.join("vk-uncompressed.bin"), &full)?;
    save(
        &pins.join("CHECKED.json"),
        &json!({"compressedSha256":hex::encode(hash(raw)),"uncompressedSha256":hex::encode(hash(&full)),"publicInputs":2,"checkedCanonicalSubgroups":true}),
    )
}

fn settle(
    program: &[u8],
    policy: &Policy,
    world: &mut World,
    mut step: Step,
    out: &Path,
) -> Result<Value> {
    let (p, stats) = prover::prove(program, &step.input, out)?;
    finish(&mut step, policy, &p, &world.entry()?)?;
    world.accept(&step)?;
    save(
        &out.with_extension("native.json"),
        &world.records.last().unwrap(),
    )?;
    Ok(stats)
}
fn rediscover(w: &mut Work, state: &app::State) -> Result<()> {
    for i in 0..3 {
        let wallet = Wallet::restore_local(&w.wallets[i].local_backup());
        let notes = wallet.discover(
            &state.ledger.deliveries,
            &state.ledger.tree,
            &state.ledger.nullifiers,
        );
        if notes.is_empty() || (i != 0 && notes.len() != 1) {
            return Err("one unspent note per restored wallet".into());
        }
        let (p, q) = state.ledger.tree.path(notes[0].1)?;
        w.witnesses[i] = wallet.witness(notes[0].0.clone(), [Note::dummy(), Note::dummy()], p, q);
    }
    Ok(())
}

pub fn busy(program_path: &Path, dynamic_path: &Path, core: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    let program = fs::read(program_path)?;
    let dynamic = fs::read(dynamic_path)?;
    let (mut w, _, _, _) = restored_work(core)?;
    let policy = Policy {
        image: risc0_zkvm::compute_image_id(&program)?
            .as_bytes()
            .try_into()?,
    };
    let (fund, entry, report) = funding(&w, &policy)?;
    let mut world = World::start(&w, &fund, &entry, &report);
    let ops = w.operations.clone();
    let initial = prepare_step(
        &mut w,
        &policy,
        &world.state,
        world.point,
        world.value,
        app::PAYMENT,
        &ops,
        &[],
    )?;
    // Both real programs prove the EXACT same public input and journal. Only the
    // pinned image is accepted by this fresh bank's immutable native verifier.
    let (dp, dynamic_stats) =
        prover::prove(&dynamic, &initial.input, &out.join("dynamic-control"))?;
    let mut wrong_image_tx = initial.tx.clone();
    wrong_image_tx.inputs[0].signature_script = policy.witness(
        initial.input.state.root(),
        initial.output.journal[32..64].try_into()?,
        &dp,
    );
    wrong_image_tx.finalize();
    let wrong_image = native::validate(&wrong_image_tx, &world.entry()?)
        .err()
        .ok_or("wrong guest image accepted")?
        .to_string();
    let pinned_stats = settle(
        &program,
        &policy,
        &mut world,
        initial,
        &out.join("pinned-initial"),
    )?;
    let stale_started = Instant::now();
    let stale = prepare_step(
        &mut w,
        &policy,
        &world.state,
        world.point,
        world.value,
        app::JOINT,
        &[],
        &[1, 2],
    )?;
    let stale_seconds = stale_started.elapsed().as_secs_f64();
    let cohort_nfs = [
        stale.input.packet.operations[0].statement.nullifier,
        stale.input.packet.operations[1].statement.nullifier,
    ];
    save(
        &out.join("stale-prepared.json"),
        &json!({"inputBincodeHex":hex::encode(bincode::serialize(&stale.input)?),"transaction":stale.tx,"walletPreparationSeconds":stale_seconds,"actualWalletProofs":2}),
    )?;
    // Alice pays herself. Neither Bob's nor Carol's note is touched.
    let alice = &w.wallets[0];
    // The unchanged TRANSFER relation requires two positive outputs.
    let [new_note, change_note] = self_payment_outputs(alice, w.d);
    let mut s = Statement::new(TRANSFER, w.engine.id(), world.state.ledger.tree.root());
    s.nullifier = nullifier(&w.witnesses[0].secret, &w.witnesses[0].input);
    let mut witness = w.witnesses[0].clone();
    witness.outputs = [new_note.clone(), change_note.clone()];
    let op = w
        .engine
        .prove(s, witness, [new_note.deliver()?, change_note.deliver()?]);
    let busy = prepare_step(
        &mut w,
        &policy,
        &world.state,
        world.point,
        world.value,
        app::PAYMENT,
        &[op],
        &[],
    )?;
    let busy_stats = settle(
        &program,
        &policy,
        &mut world,
        busy,
        &out.join("unrelated-payment"),
    )?;
    assert!(
        cohort_nfs
            .iter()
            .all(|n| !world.state.ledger.nullifiers.contains(n))
    );
    let stale_point = world
        .accept(&stale)
        .err()
        .ok_or("stale point accepted")?
        .to_string();
    let mut stale_at_current = stale.input.clone();
    stale_at_current.state = world.state.clone();
    stale_at_current.effects.previous = world.point.transaction_id.as_bytes().try_into()?;
    stale_at_current.effects.index = world.point.index;
    stale_at_current.effects.input_value = world.value;
    // Reprice/rebase the old proposed continuation while retaining every old
    // authorization. Refusal must concern authorization, not mere value balance.
    stale_at_current.effects.outputs[0].value -= stale.input.effects.input_value - world.value;
    let stale_context = app::execute(&stale_at_current)
        .err()
        .ok_or("stale context accepted")?;
    if stale_context != "complete native effects authorization" {
        return Err(format!("wrong stale rejection: {stale_context}").into());
    }
    let actual_guest = prover::reject_guest(&program, &stale_at_current)?;
    rediscover(&mut w, &world.state)?;
    let retry = prepare_step(
        &mut w,
        &policy,
        &world.state,
        world.point,
        world.value,
        app::JOINT,
        &[],
        &[1, 2],
    )?;
    let retry_stats = settle(
        &program,
        &policy,
        &mut world,
        retry,
        &out.join("fresh-joint"),
    )?;
    // Restored Alice independently exits each of her two self-payment notes.
    w.d = w.witnesses[0].input.value;
    let solo = prepare_step(
        &mut w,
        &policy,
        &world.state,
        world.point,
        world.value,
        app::SOLO,
        &[],
        &[0],
    )?;
    let solo_stats = settle(
        &program,
        &policy,
        &mut world,
        solo,
        &out.join("restored-solo"),
    )?;
    let restored = Wallet::restore_local(&w.wallets[0].local_backup());
    let remaining = restored.discover(
        &world.state.ledger.deliveries,
        &world.state.ledger.tree,
        &world.state.ledger.nullifiers,
    );
    if remaining.len() != 1 {
        return Err("restored remaining self-payment note".into());
    }
    let (p, q) = world.state.ledger.tree.path(remaining[0].1)?;
    w.witnesses[0] = restored.witness(remaining[0].0.clone(), [Note::dummy(), Note::dummy()], p, q);
    w.d = remaining[0].0.value;
    let last = prepare_step(
        &mut w,
        &policy,
        &world.state,
        world.point,
        world.value,
        app::SOLO,
        &[],
        &[0],
    )?;
    let last_solo_stats = settle(
        &program,
        &policy,
        &mut world,
        last,
        &out.join("restored-solo-last"),
    )?;
    assert_eq!(world.state.ledger.reserve, 0);
    assert_eq!(world.state.ledger.private_liability, 0);
    assert!(world.active.is_empty());
    assert!(world.state.canonical());
    let fee: u64 = world
        .records
        .iter()
        .map(|r| r["report"]["feeSompi"].as_u64().unwrap())
        .sum();
    let result = json!({"schema":"busy-bank-followup-v1","scope":"offline genuine complete receipts and native Full; supplied synthetic source","exactInputDynamicControl":dynamic_stats,"exactInputPinned":pinned_stats,"wrongImageNativeRejection":wrong_image,"busyPayment":busy_stats,"freshJoint":retry_stats,"restoredSolo":solo_stats,"restoredSoloLast":last_solo_stats,"staleOutpointRejection":stale_point,"staleEffectsRejection":stale_context,"actualGuestStaleRejection":actual_guest,"cohortNotesStillUnspentAfterUnrelatedPayment":true,"wastedApprovalProofs":2,"wastedApprovalSeconds":stale_seconds,"wastedApprovalNativeFeeSompi":0,"totalNativeFeeSompi":fee,"principalPayoutSompi":w.initial.ledger.reserve,"finalReserveSompi":0,"finalPrivateLiabilitySompi":0,"finalActiveBankOutputs":0,"records":world.records});
    save(&out.join("RESULT.json"), &result)?;
    eprintln!("BUSY_COMPLETE native_fee_sompi={fee}");
    Ok(())
}

pub fn privacy(core: &Path, out: &Path) -> Result<()> {
    let (mut w, _, _, _) = restored_work(core)?;
    fs::create_dir(out)?;
    crate::anonymous::prepare(&mut w.engine, &w.witnesses, &w.post, out)
}

/// Genuine unequal private payments and complete owner-disclosure control.
/// Wallet proofs + host Ledger/effects only; no outer/native acceptance claim.
pub fn unequal(core: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    fs::create_dir(out.join("private"))?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(out.join("private"), fs::Permissions::from_mode(0o700))?;
    let (mut w, _, _, _) = restored_work(core)?;
    let pool = hash(b"KPI-unequal-disclosure-control-2026-11-06");
    let mut ledger = Ledger::new(w.engine.id());
    let kas = 100_000_000;
    ledger.register_authenticated_fixture_deposit(pool, 60 * kas, w.wallets[0].address.owner)?;
    let initial = app::State {
        ledger,
        pool,
        wallet_vk: proof::serialize(&w.engine.vk),
        fee_refund_spk: w.initial.fee_refund_spk.clone(),
    };
    let mut state = initial.clone();
    let credit = w.wallets[0].note(60 * kas);
    let mut s = Statement::new(CREDIT, w.engine.id(), state.ledger.tree.root());
    s.deposit = pool;
    s.deposit_value = 60 * kas;
    s.deposit_owner = w.wallets[0].address.owner;
    let op = w.engine.prove(
        s,
        w.wallets[0].witness(
            w.wallets[0].authority_note(),
            [credit.clone(), Note::dummy()],
            [[0; 32]; DEPTH],
            [false; DEPTH],
        ),
        [credit.deliver()?, Delivery::absent()],
    );
    state.ledger.apply(&w.engine, &op)?;
    let mut ops = vec![op];
    for (payer, receiver, value, change) in [
        (0, 1, 23, 37),
        (1, 2, 9, 14),
        (0, 0, 5, 32),
        (1, 1, 5, 9),
        (2, 2, 5, 4),
    ] {
        let wallet = &w.wallets[payer];
        let notes = wallet.discover(
            &state.ledger.deliveries,
            &state.ledger.tree,
            &state.ledger.nullifiers,
        );
        if notes.len() != 1 {
            return Err("unequal payer discovery".into());
        }
        let note = &notes[0];
        let (p, q) = state.ledger.tree.path(note.1)?;
        let n0 = w.wallets[receiver].note(value * kas);
        let n1 = wallet.note(change * kas);
        let mut s = Statement::new(TRANSFER, w.engine.id(), state.ledger.tree.root());
        s.nullifier = wallet.nf(&note.0);
        let op = w.engine.prove(
            s,
            wallet.witness(note.0.clone(), [n0.clone(), n1.clone()], p, q),
            [n0.deliver()?, n1.deliver()?],
        );
        state.ledger.apply(&w.engine, &op)?;
        ops.push(op);
    }
    // Restore backups and discover both each person's 5-KAS note and change.
    let mut changes = vec![];
    for i in 0..3 {
        let wallet = Wallet::restore_local(&w.wallets[i].local_backup());
        let notes = wallet.discover(
            &state.ledger.deliveries,
            &state.ledger.tree,
            &state.ledger.nullifiers,
        );
        assert_eq!(notes.len(), 2);
        let small = notes
            .iter()
            .find(|n| n.0.value == 5 * kas)
            .ok_or("small note")?;
        let other = notes
            .iter()
            .find(|n| n.0.value != 5 * kas)
            .ok_or("change note")?;
        let (p, q) = state.ledger.tree.path(small.1)?;
        w.witnesses[i] = wallet.witness(small.0.clone(), [Note::dummy(), Note::dummy()], p, q);
        let (p, q) = state.ledger.tree.path(other.1)?;
        changes.push(wallet.witness(other.0.clone(), [Note::dummy(), Note::dummy()], p, q));
    }
    let policy = Policy { image: [0x55; 32] };
    let mut point = native::fake_point(hash(b"unfunded unequal host-only predecessor"));
    let mut value = state.ledger.reserve + FEE_BUFFER;
    w.d = 5 * kas;
    let joint = prepare_step(
        &mut w,
        &policy,
        &state,
        point,
        value,
        app::JOINT,
        &[],
        &[0, 1, 2],
    )?;
    let mut records = vec![];
    let mut truth = vec![];
    for i in 0..3 {
        truth.push(json!({"owner":format!("owner-{}",i+1),"recipientKey":hex::encode(pubkey(&w.payout_keys[i])),"commonSompi":5*kas,"changeSompi":changes[i].input.value}));
    }
    records.push(json!({"kind":"joint","inputBincodeHex":hex::encode(bincode::serialize(&joint.input)?),"transaction":joint.tx,"nativeAccepted":false}));
    point = TransactionOutpoint::new(joint.tx.id(), 0);
    value = joint.tx.outputs[0].value;
    state = joint.output.state;
    for i in 0..3 {
        w.witnesses[i] = changes[i].clone();
        w.d = changes[i].input.value;
        // A later disclosure identifies each remaining payout. Fresh keys keep
        // key reuse from being an unstated source of this controlled disclosure.
        w.payout_keys[i] = key();
        let step = prepare_step(&mut w, &policy, &state, point, value, app::SOLO, &[], &[i])?;
        truth[i]["changeRecipientKey"] = json!(hex::encode(pubkey(&w.payout_keys[i])));
        records.push(json!({"kind":"later-solo","inputBincodeHex":hex::encode(bincode::serialize(&step.input)?),"transaction":step.tx,"nativeAccepted":false}));
        if step.output.state.ledger.reserve > 0 {
            point = TransactionOutpoint::new(step.tx.id(), 0);
            value = step.tx.outputs[0].value;
        }
        state = step.output.state;
    }
    assert_eq!(state.ledger.reserve, 0);
    assert_eq!(state.ledger.private_liability, 0);
    assert!(state.canonical());
    save(
        &out.join("public.json"),
        &json!({"schema":"unequal-wallet-lifecycle-v1","scope":"genuine wallet proofs, restored decrypt/respend, host Ledger/effects; no native Full or outer receipt","initialStateBincodeHex":hex::encode(bincode::serialize(&initial)?),"paymentOperations":ops,"initialPublicFundingSompi":60*kas,"records":records,"finalStateBincodeHex":hex::encode(bincode::serialize(&state)?)}),
    )?;
    save(
        &out.join("private/truth.json"),
        &json!({"owners":truth,"paymentsSompi":[23*kas,9*kas]}),
    )?;
    Ok(())
}

pub fn replay_busy(program_path: &Path, run: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    let program = fs::read(program_path)?;
    let r = read(&run.join("RESULT.json"))?;
    let image = risc0_zkvm::compute_image_id(&program)?;
    let records = r["records"].as_array().ok_or("records")?;
    let fund = read_transaction(&records[0]["transaction"])?;
    let fee = records[0]["report"]["feeSompi"]
        .as_u64()
        .ok_or("deposit fee")?;
    let source_value = fund.outputs.iter().map(|o| o.value).sum::<u64>() + fee;
    // Deposit is signed by this fixture's public funding/refund key.
    let source_entry = UtxoEntry::new(
        source_value,
        fund.outputs[1].script_public_key.clone(),
        0,
        false,
        None,
    );
    native::validate(&fund, &source_entry)?;
    let mut previous = TransactionOutpoint::new(fund.id(), 0);
    let mut entry = UtxoEntry::new(
        fund.outputs[0].value,
        fund.outputs[0].script_public_key.clone(),
        0,
        false,
        None,
    );
    let mut last: Option<app::State> = None;
    let mut verified = vec![];
    for (record, name) in records[1..].iter().zip([
        "pinned-initial",
        "unrelated-payment",
        "fresh-joint",
        "restored-solo",
        "restored-solo-last",
    ]) {
        let tx = read_transaction(&record["transaction"])?;
        let input: app::Input = from_hex(&record["inputBincodeHex"])?;
        if tx.inputs[0].previous_outpoint != previous {
            return Err("replay linked outpoint".into());
        }
        if let Some(ref before) = last {
            if before.root() != input.state.root() {
                return Err("replay linked state".into());
            }
        }
        if native::effects(&tx, entry.amount).context(input.state.root())
            != input.effects.context(input.state.root())
        {
            return Err("replay actual effects".into());
        }
        let output = app::execute(&input)?;
        let dir = run.join(name);
        if fs::read(dir.join("input.bin"))? != bincode::serialize(&input)?
            || fs::read(dir.join("expected-journal.bin"))? != output.journal
        {
            return Err("replay retained input/journal".into());
        }
        let receipt: risc0_zkvm::Receipt =
            bincode::deserialize(&fs::read(dir.join("candidate-compressed.bin"))?)?;
        prover::verify(&receipt, image, &output.journal)?;
        if prover::native_proof(&receipt)? != fs::read(dir.join("native-proof.bin"))? {
            return Err("replay native proof".into());
        }
        let report = native::validate(&tx, &entry)?;
        verified.push(json!({"name":name,"report":report}));
        if output.state.ledger.reserve > 0 {
            previous = TransactionOutpoint::new(tx.id(), 0);
            entry = UtxoEntry::new(
                tx.outputs[0].value,
                tx.outputs[0].script_public_key.clone(),
                0,
                false,
                None,
            );
        }
        last = Some(output.state);
    }
    if records.len() != 6
        || verified.len() != 5
        || last.as_ref().ok_or("no final state")?.ledger.reserve != 0
    {
        return Err("replay complete lifecycle".into());
    }
    let first: app::Input = bincode::deserialize(&fs::read(run.join("pinned-initial/input.bin"))?)?;
    let dynamic: risc0_zkvm::Receipt = bincode::deserialize(&fs::read(
        run.join("dynamic-control/candidate-compressed.bin"),
    )?)?;
    if fs::read(run.join("dynamic-control/input.bin"))? != bincode::serialize(&first)? {
        return Err("exact matched dynamic input".into());
    }
    let dynamic_program = fs::read(
        run.parent()
            .ok_or("run parent")?
            .join("dynamic.program.bin"),
    )?;
    prover::verify(
        &dynamic,
        risc0_zkvm::compute_image_id(&dynamic_program)?,
        &app::execute(&first)?.journal,
    )?;
    save(
        &out.join("VERIFIED.json"),
        &json!({"newProcess":true,"image":image.to_string(),"genuinePinnedReceipts":5,"actualNativeFullTransactions":6,"exactInputDynamicJournalEqual":true,"verified":verified,"noSecretsOrProvingKeyUsed":true}),
    )
}

pub fn verify_unequal(public: &Path, out: &Path) -> Result<()> {
    use ark_serialize::CanonicalDeserialize;
    let v = read(public)?;
    let mut state: app::State = from_hex(&v["initialStateBincodeHex"])?;
    let vk = ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(
        state.wallet_vk.as_slice(),
    )?;
    let verifier = app::Verifier::new(&state.wallet_vk)?;
    let mut count = 0;
    for op in v["paymentOperations"].as_array().ok_or("operations")? {
        let op: Operation = serde_json::from_value(op.clone())?;
        if !proof::verify(&vk, &op) {
            return Err("independent unequal payment proof".into());
        }
        state.ledger.apply(&verifier, &op)?;
        count += 1;
    }
    for record in v["records"].as_array().ok_or("records")? {
        let input: app::Input = from_hex(&record["inputBincodeHex"])?;
        if input.state.root() != state.root() {
            return Err("unequal linked state".into());
        }
        let tx = read_transaction(&record["transaction"])?;
        if native::effects(&tx, input.effects.input_value).context(state.root())
            != input.effects.context(state.root())
        {
            return Err("unequal actual effects".into());
        }
        if tx.payload != input.packet.bytes() {
            return Err("unequal actual packet".into());
        }
        for op in &input.packet.operations {
            if !proof::verify(&vk, op) {
                return Err("independent unequal exit proof".into());
            }
            count += 1;
        }
        state = app::execute(&input)?.state;
    }
    let final_state: app::State = from_hex(&v["finalStateBincodeHex"])?;
    if state.root() != final_state.root()
        || state.ledger.reserve != 0
        || state.ledger.private_liability != 0
    {
        return Err("unequal final conservation".into());
    }
    save(
        out,
        &json!({"genuineWalletProofs":count,"independentArkworksReplay":true,"hostKernelOnly":true,"nativeAcceptanceClaimed":false,"finalReserveSompi":0,"finalLiabilitySompi":0,"privateMaterialUsed":false}),
    )
}

pub fn pinned_negatives(program_path: &Path, run: &Path, out: &Path) -> Result<()> {
    let program = fs::read(program_path)?;
    let input: app::Input = bincode::deserialize(&fs::read(run.join("pinned-initial/input.bin"))?)?;
    let mut wrong = input.clone();
    wrong.state.wallet_vk[0] ^= 1;
    let raw = bincode::serialize(&wrong)?;
    let err = risc0_zkvm::default_executor()
        .execute(prover::env(&raw)?, &program)
        .err()
        .ok_or("changed pinned key accepted")?;
    let error = format!("{err:#}");
    if !error.contains("Guest panicked:") || !error.contains("pinned wallet key mismatch") {
        return Err(format!("wrong pinned rejection: {error}").into());
    }
    let mut bad = input.clone();
    bad.packet.operations[0].proof[0] ^= 1;
    let malformed = prover::reject_guest(&program, &bad)?;
    save(
        out,
        &json!({"actualPinnedGuestChangedKeyRejection":error,"actualPinnedGuestMalformedProofRejection":malformed,"untrustedPointChecksPreserved":true}),
    )
}

pub fn dropout(program_path: &Path, quiet: &Path, out: &Path) -> Result<()> {
    let program = fs::read(program_path)?;
    let input: app::Input =
        bincode::deserialize(&fs::read(quiet.join("quiet-terminal/input.bin"))?)?;
    let before = input.state.root();
    let mut partial = input.clone();
    partial.packet.operations.pop().ok_or("three-owner input")?;
    if partial.packet.operations.len() != 2 {
        return Err("three-owner dropout control".into());
    }
    let expected = app::execute(&partial)
        .err()
        .ok_or("partial group accepted")?;
    if expected != "native complete output shape" {
        return Err(format!("wrong dropout layer: {expected}").into());
    }
    let guest = prover::reject_guest(&program, &partial)?;
    if partial.state.root() != before {
        return Err("partial round mutated state".into());
    }
    save(
        out,
        &json!({"actualPinnedGuestRejection":guest,"deliveredGenuineApprovals":2,"requiredGenuineApprovals":3,"nativeFeeSompi":0,"principalLostSompi":0,"stateUnchanged":true,"scope":"withheld approval counterfactual using genuine completed owner proofs, no transition accepted"}),
    )
}

pub fn quiet(
    program_path: &Path,
    busy: &Path,
    core: &Path,
    network: &Path,
    out: &Path,
) -> Result<()> {
    fs::create_dir(out)?;
    let program = fs::read(program_path)?;
    let (mut w, _, _, _) = restored_work(core)?;
    let r = read(&busy.join("RESULT.json"))?;
    let records = r["records"].as_array().ok_or("busy records")?;
    let tx = read_transaction(&records[1]["transaction"])?;
    let state: app::State = from_hex(&records[1]["postStateBincodeHex"])?;
    let cfg = read(&network.join("fixture/config.json"))?;
    let registered_state: app::State = from_hex(&cfg["stateBincodeHex"])?;
    if registered_state.root() != state.root() {
        return Err("network eligibility anchored to actual quiet state".into());
    }
    for i in 0..3 {
        let client = read(&network.join(format!("fixture/private/client-{i}.json")))?;
        w.payout_keys[i] = SecretKey::from_slice(&hex::decode(
            client["nativeSecretKey"]
                .as_str()
                .ok_or("client native key backup")?,
        )?)?;
        let msg = hex::decode(client["message"].as_str().ok_or("registration message")?)?;
        if msg[msg.len() - 32..] != pubkey(&w.payout_keys[i]) {
            return Err("client restored native key".into());
        }
    }
    let point = TransactionOutpoint::new(tx.id(), 0);
    let value = tx.outputs[0].value;
    let entry = UtxoEntry::new(
        value,
        tx.outputs[0].script_public_key.clone(),
        0,
        false,
        None,
    );
    let policy = Policy {
        image: risc0_zkvm::compute_image_id(&program)?
            .as_bytes()
            .try_into()?,
    };
    // Re-verify the exact accepted prefix before branching this counterfactual.
    let first: app::Input = from_hex(&records[1]["inputBincodeHex"])?;
    let receipt: risc0_zkvm::Receipt = bincode::deserialize(&fs::read(
        busy.join("pinned-initial/candidate-compressed.bin"),
    )?)?;
    prover::verify(
        &receipt,
        risc0_zkvm::compute_image_id(&program)?,
        &app::execute(&first)?.journal,
    )?;
    if app::execute(&first)?.state.root() != state.root() {
        return Err("quiet prefix state".into());
    }
    let initial_bank = read_transaction(&records[0]["transaction"])?;
    native::validate(
        &tx,
        &UtxoEntry::new(
            initial_bank.outputs[0].value,
            initial_bank.outputs[0].script_public_key.clone(),
            0,
            false,
            None,
        ),
    )?;
    let mut world = World {
        state,
        point,
        value,
        active: HashMap::from([(point, entry)]),
        records: records[..2].to_vec(),
    };
    let step = prepare_step(
        &mut w,
        &policy,
        &world.state,
        world.point,
        world.value,
        app::JOINT,
        &[],
        &[0, 1, 2],
    )?;
    let preparation = step.report["walletPreparationSeconds"].clone();
    let stats = settle(
        &program,
        &policy,
        &mut world,
        step,
        &out.join("quiet-terminal"),
    )?;
    if world.state.ledger.reserve != 0
        || world.state.ledger.private_liability != 0
        || !world.active.is_empty()
    {
        return Err("quiet full drainage".into());
    }
    let fees: u64 = world
        .records
        .iter()
        .map(|r| r["report"]["feeSompi"].as_u64().unwrap())
        .sum();
    // Restore client-local native keys and actually spend each paid output.
    // Keep native output order; never publish the private owner/key association.
    let terminal = read_transaction(&world.records.last().ok_or("quiet terminal")?["transaction"])?;
    let mut key_controls = vec![];
    for (index, paid) in terminal.outputs[..3].iter().enumerate() {
        let owner_key = w
            .payout_keys
            .iter()
            .find(|k| recipient(k) == paid.script_public_key)
            .ok_or("restored registered payout key")?;
        let entry = UtxoEntry::new(paid.value, paid.script_public_key.clone(), 0, false, None);
        let mut spend = native::transaction(
            TransactionOutpoint::new(terminal.id(), index as u32),
            vec![TransactionOutput::new(paid.value, recipient(owner_key))],
            b"unfunded restored native payout key control".to_vec(),
            20,
        );
        spend.inputs[0].signature_script = vec![0; 66];
        let fee = native::quote(&spend, &entry)["minimumDefaultRelayFeeSompi"]
            .as_u64()
            .ok_or("native key spend fee")?;
        spend.outputs[0].value -= fee;
        let pop = PopulatedTransaction::new(&spend, vec![entry.clone()]);
        spend.inputs[0].signature_script = kaspa_consensus_core::sign::sign_input(
            &pop,
            0,
            &owner_key.secret_bytes(),
            kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL,
        );
        spend.finalize();
        let report = native::validate(&spend, &entry)?;
        key_controls.push(json!({"transaction":spend,"report":report}));
    }
    save(
        &out.join("RESULT.json"),
        &json!({"counterfactual":"quiet path branching from exact genuine initial prefix; not accepted alongside busy path","reusedPrefix":busy,"initialProof":r["exactInputPinned"],"terminalProof":stats,"terminalWalletPreparationSeconds":preparation,"totalNativeFeeSompi":fees,"usefulPaymentSompi":3*w.d,"finalReserveSompi":0,"finalLiabilitySompi":0,"nativePayoutKeyRecoveryControls":key_controls,"records":world.records}),
    )
}

pub fn verify_quiet(
    program_path: &Path,
    quiet: &Path,
    busy: &Path,
    network: &Path,
    out: &Path,
) -> Result<()> {
    let program = fs::read(program_path)?;
    let image = risc0_zkvm::compute_image_id(&program)?;
    let q = read(&quiet.join("RESULT.json"))?;
    let b = read(&busy.join("RESULT.json"))?;
    let records = q["records"].as_array().ok_or("quiet records")?;
    if records.len() != 3
        || q["records"][0] != b["records"][0]
        || q["records"][1] != b["records"][1]
    {
        return Err("quiet exact prefix".into());
    }
    let fund = read_transaction(&records[0]["transaction"])?;
    let source_amount = fund.outputs.iter().map(|o| o.value).sum::<u64>()
        + records[0]["report"]["feeSompi"].as_u64().ok_or("fee")?;
    native::validate(
        &fund,
        &UtxoEntry::new(
            source_amount,
            fund.outputs[1].script_public_key.clone(),
            0,
            false,
            None,
        ),
    )?;
    let mut prev = fund;
    let mut state: Option<app::State> = None;
    for (record, dir) in records[1..]
        .iter()
        .zip([busy.join("pinned-initial"), quiet.join("quiet-terminal")])
    {
        let tx = read_transaction(&record["transaction"])?;
        let input: app::Input = from_hex(&record["inputBincodeHex"])?;
        if let Some(ref old) = state {
            if input.state.root() != old.root() {
                return Err("quiet linked state".into());
            }
        }
        if tx.inputs[0].previous_outpoint != TransactionOutpoint::new(prev.id(), 0)
            || tx.payload != input.packet.bytes()
        {
            return Err("quiet linked native input/payload".into());
        }
        let entry = UtxoEntry::new(
            prev.outputs[0].value,
            prev.outputs[0].script_public_key.clone(),
            0,
            false,
            None,
        );
        if native::effects(&tx, entry.amount).context(input.state.root())
            != input.effects.context(input.state.root())
        {
            return Err("quiet actual effects".into());
        }
        let output = app::execute(&input)?;
        if fs::read(dir.join("input.bin"))? != bincode::serialize(&input)? {
            return Err("quiet exact public proving input".into());
        }
        let receipt: risc0_zkvm::Receipt =
            bincode::deserialize(&fs::read(dir.join("candidate-compressed.bin"))?)?;
        prover::verify(&receipt, image, &output.journal)?;
        native::validate(&tx, &entry)?;
        state = Some(output.state);
        prev = tx;
    }
    if state.ok_or("quiet empty")?.ledger.reserve != 0 {
        return Err("quiet final principal".into());
    }
    let cfg = read(&network.join("config.json"))?;
    let registered: app::State = from_hex(&cfg["stateBincodeHex"])?;
    let initial_post: app::State = from_hex(&records[1]["postStateBincodeHex"])?;
    if registered.root() != initial_post.root() {
        return Err("registration actual bank state".into());
    }
    let terminal: app::Input = from_hex(&records[2]["inputBincodeHex"])?;
    let tx = read_transaction(&records[2]["transaction"])?;
    let mut eligible = std::collections::BTreeSet::new();
    let mut keys = std::collections::BTreeSet::new();
    for line in fs::read_to_string(network.join("onion/operator.jsonl"))?.lines() {
        let e: Value = serde_json::from_str(line)?;
        if e["response"].get("error").is_some() {
            continue;
        }
        if e["request"]["kind"] == "issue" {
            let op: Operation = serde_json::from_value(e["request"]["operation"].clone())?;
            eligible.insert(op.statement.nullifier);
        } else if e["request"]["kind"] == "redeem" {
            keys.insert(
                e["response"]["recipientKey"]
                    .as_str()
                    .ok_or("registered key")?
                    .to_owned(),
            );
        }
    }
    let exited = terminal
        .packet
        .operations
        .iter()
        .map(|o| o.statement.nullifier)
        .collect::<std::collections::BTreeSet<_>>();
    let paid = tx.outputs[..3]
        .iter()
        .map(|o| hex::encode(&o.script_public_key.script()[1..33]))
        .collect::<std::collections::BTreeSet<_>>();
    if eligible != exited || keys != paid || keys.len() != 3 {
        return Err("actual native payouts must match anonymous registration".into());
    }
    let controls = q["nativePayoutKeyRecoveryControls"]
        .as_array()
        .ok_or("native key recovery controls")?;
    let mut spent = std::collections::BTreeSet::new();
    for control in controls {
        let spend = read_transaction(&control["transaction"])?;
        let point = spend.inputs[0].previous_outpoint;
        if point.transaction_id != tx.id() || point.index >= 3 || !spent.insert(point.index) {
            return Err("native key recovery outpoint".into());
        }
        let paid = &tx.outputs[point.index as usize];
        native::validate(
            &spend,
            &UtxoEntry::new(paid.value, paid.script_public_key.clone(), 0, false, None),
        )?;
    }
    if spent.len() != 3 {
        return Err("all native payout keys restored".into());
    }
    save(
        out,
        &json!({"newProcess":true,"genuinePinnedReceipts":2,"nativeFullTransactions":3,"nativePayoutKeySpendControls":3,"prefixReusedAndVerified":true,"completeQuietPath":true,"nativePayoutKeysEqualTorRegisteredKeys":true,"actualNativeExitNullifiersEqualTorEligibilityNullifiers":true,"registeredStateEqualsNativeAcceptedPrefixState":true,"privateMaterialUsed":false}),
    )
}

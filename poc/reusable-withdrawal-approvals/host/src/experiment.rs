fn save_public(p: &Path, v: &Value) -> Result<()> {
    save(p, v)
}

fn approval_digest(ops: &[Operation]) -> String {
    hex::encode(hash(&bincode::serialize(ops).unwrap()))
}
fn make_intent(w: &Work, state: &app::State) -> app::WithdrawalIntent {
    let mut claims = [1, 2]
        .iter()
        .map(|i| nullifier(&w.witnesses[*i].secret, &w.witnesses[*i].input))
        .collect::<Vec<_>>();
    claims.sort();
    let mut payouts = [1, 2]
        .iter()
        .map(|i| native::encoded(&recipient(&w.payout_keys[*i])))
        .collect::<Vec<_>>();
    payouts.sort();
    app::WithdrawalIntent {
        protocol_domain: domain(),
        pool: state.pool,
        verifier: state.ledger.verifier,
        reference_anchor: state.ledger.tree.root(),
        nonce: fresh(),
        refund_key_hash: hash(&state.fee_refund_spk),
        denomination: w.d,
        fee_cap: 20_000_000,
        claims,
        payouts,
    }
}
fn approve(w: &mut Work, intent: &app::WithdrawalIntent) -> Result<Vec<Operation>> {
    let mut ops = vec![];
    for i in [1, 2] {
        let nf = nullifier(&w.witnesses[i].secret, &w.witnesses[i].input);
        if !intent.claims.contains(&nf)
            || !intent
                .payouts
                .contains(&native::encoded(&recipient(&w.payout_keys[i])))
            || intent.denomination != w.witnesses[i].input.value
        {
            return Err("wallet own complete entitlement check".into());
        }
        ops.push(w.engine.authorize(
            &w.witnesses[i],
            intent.commitment(),
            intent.reference_anchor,
        ));
    }
    ops.sort_by_key(|o| o.statement.nullifier);
    Ok(ops)
}

/// No wallet, secret, witness or proving key is accepted by this refresh API.
fn intent_step(
    policy: &Policy,
    world: &World,
    intent: &app::WithdrawalIntent,
    approvals: &[Operation],
    extra_fee: u64,
) -> Result<Step> {
    let state = &world.state;
    intent.validate(state, approvals)?;
    let mut next = state.clone();
    for nf in &intent.claims {
        if !next.ledger.nullifiers.insert(*nf) {
            return Err("current economic nullifier spent".into());
        }
        next.ledger.private_liability = next
            .ledger
            .private_liability
            .checked_sub(intent.denomination)
            .ok_or("intent liability")?;
        next.ledger.reserve = next
            .ledger
            .reserve
            .checked_sub(intent.denomination)
            .ok_or("intent reserve")?;
    }
    next.ledger.invariant()?;
    let old = state.root();
    let new = if next.ledger.reserve == 0 {
        [0; 32]
    } else {
        next.root()
    };
    let allowance = world
        .value
        .checked_sub(state.ledger.reserve)
        .ok_or("intent current backing")?;
    let mut outputs = vec![];
    if next.ledger.reserve > 0 {
        outputs.push(TransactionOutput::new(
            next.ledger.reserve + allowance,
            policy.spk(new),
        ));
    }
    outputs.extend(
        intent
            .payouts
            .iter()
            .map(|p| TransactionOutput::new(intent.denomination, native::spk(p))),
    );
    if next.ledger.reserve == 0 {
        outputs.push(TransactionOutput::new(
            allowance,
            native::spk(&state.fee_refund_spk),
        ));
    }
    let packet = app::Packet {
        mode: app::JOINT,
        operations: approvals.to_vec(),
        intent: Some(intent.clone()),
    };
    let mut tx = native::transaction(world.point, outputs, packet.bytes(), native::BUDGET);
    tx.inputs[0].signature_script = policy.witness(old, new, &[0; 128]);
    let entry = world.entry()?;
    let fee = native::quote(&tx, &entry)["minimumDefaultRelayFeeSompi"]
        .as_u64()
        .ok_or("fee quote")?
        .checked_add(extra_fee)
        .ok_or("fee overflow")?;
    let fee_output = if next.ledger.reserve > 0 {
        0
    } else {
        tx.outputs.len() - 1
    };
    tx.outputs[fee_output].value = tx.outputs[fee_output]
        .value
        .checked_sub(fee)
        .ok_or("fee allowance exhausted")?;
    tx.finalize();
    let input = app::Input {
        state: state.clone(),
        packet,
        effects: native::effects(&tx, world.value),
    };
    let output = app::execute(&input)?;
    if output.state.root() != next.root() {
        return Err("intent computed successor state".into());
    }
    let mut report = native::quote(&tx, &entry);
    report["walletPreparationSeconds"] = json!(0);
    report["genuineNewWalletProofs"] = json!(0);
    Ok(Step {
        tx,
        input,
        output,
        report,
    })
}

fn restore_note(w: &mut Work, state: &app::State, i: usize, value: u64) -> Result<()> {
    let wallet = Wallet::restore_local(&w.wallets[i].local_backup());
    let notes = wallet.discover(
        &state.ledger.deliveries,
        &state.ledger.tree,
        &state.ledger.nullifiers,
    );
    let n = notes
        .iter()
        .find(|n| n.0.value == value)
        .ok_or("restored current note")?;
    let (p, q) = state.ledger.tree.path(n.1)?;
    w.witnesses[i] = wallet.witness(n.0.clone(), [Note::dummy(), Note::dummy()], p, q);
    Ok(())
}
fn apply_new(
    program: &[u8],
    policy: &Policy,
    world: &mut World,
    mut step: Step,
    out: &Path,
    host_only: bool,
) -> Result<Value> {
    if !host_only {
        let (proof, stats) = prover::prove(program, &step.input, out)?;
        finish(&mut step, policy, &proof, &world.entry()?)?;
        world.accept(&step)?;
        save_public(
            &out.with_extension("native.json"),
            world.records.last().unwrap(),
        )?;
        return Ok(stats);
    }
    // Explicit host preflight, never counted as native or receipt acceptance.
    fs::create_dir(out)?;
    save_public(
        &out.join("HOST-ONLY.json"),
        &json!({"inputBincodeHex":hex::encode(bincode::serialize(&step.input)?),"nativeFullValidation":false,"receiptCreated":false}),
    )?;
    world.active.remove(&world.point);
    world.state = step.output.state.clone();
    if world.state.ledger.reserve > 0 {
        world.point = TransactionOutpoint::new(step.tx.id(), 0);
        world.value = step.tx.outputs[0].value;
        world.active.insert(
            world.point,
            UtxoEntry::new(
                world.value,
                step.tx.outputs[0].script_public_key.clone(),
                0,
                false,
                None,
            ),
        );
    } else {
        world.value = 0;
    }
    step.report["nativeFullValidation"] = json!(false);
    world.records.push(json!({"transaction":step.tx,"inputBincodeHex":hex::encode(bincode::serialize(&step.input)?),"postStateBincodeHex":hex::encode(bincode::serialize(&step.output.state)?),"payoutPrincipalSompi":step.output.payout_principal,"refundedFeeSompi":step.output.refunded_fee,"report":step.report}));
    Ok(json!({"hostOnly":true}))
}
fn refused(cases: &mut Vec<Value>, name: &str, input: &app::Input, expected: &str) -> Result<()> {
    let error = app::execute(input)
        .err()
        .ok_or(format!("negative accepted: {name}"))?;
    if !error.contains(expected) {
        return Err(format!("{name}: wrong rejection {error}, wanted {expected}").into());
    }
    cases.push(json!({"case":name,"expectedLayer":expected,"error":error}));
    Ok(())
}
fn host_controls(valid: &app::Input, spent: &World) -> Result<Vec<Value>> {
    let mut cases = vec![];
    macro_rules! intent_bad {
        ($name:expr,$field:ident,$value:expr,$why:expr) => {{
            let mut v = valid.clone();
            v.packet.intent.as_mut().unwrap().$field = $value;
            refused(&mut cases, $name, &v, $why)?;
        }};
    }
    intent_bad!("other pool", pool, [9; 32], "intent pool");
    intent_bad!(
        "other network/profile",
        protocol_domain,
        [9; 32],
        "intent domain"
    );
    intent_bad!("other verifier", verifier, [9; 32], "intent verifier");
    intent_bad!(
        "changed refund policy",
        refund_key_hash,
        [9; 32],
        "intent refund policy"
    );
    intent_bad!("zero nonce", nonce, [0; 32], "intent nonce");
    intent_bad!(
        "changed nonce",
        nonce,
        [9; 32],
        "complete native effects authorization"
    );
    intent_bad!("zero principal", denomination, 0, "intent denomination");
    intent_bad!(
        "out of monetary range",
        denomination,
        app::MAX_SOMPI + 1,
        "intent denomination"
    );
    intent_bad!(
        "aggregate overflow/range",
        denomination,
        app::MAX_SOMPI,
        "intent aggregate range"
    );
    intent_bad!("zero cap", fee_cap, 0, "intent fee bound");
    intent_bad!("over hard cap", fee_cap, 50_000_001, "intent fee bound");
    intent_bad!("fee above consent", fee_cap, 1, "intent fee cap");
    intent_bad!(
        "unaccepted historical root",
        reference_anchor,
        [9; 32],
        "intent accepted reference anchor"
    );
    let mut v = valid.clone();
    v.packet.intent.as_mut().unwrap().reference_anchor = Tree::default().root();
    refused(
        &mut cases,
        "different accepted anchor",
        &v,
        "intent reference anchor binding",
    )?;
    let mut v = valid.clone();
    v.packet.operations.pop();
    refused(
        &mut cases,
        "missing cohort member",
        &v,
        "joint branch cohort",
    )?;
    let mut v = valid.clone();
    v.packet.operations[1] = v.packet.operations[0].clone();
    refused(
        &mut cases,
        "duplicate economic claim",
        &v,
        "intent exact claim set",
    )?;
    let mut v = valid.clone();
    v.packet.operations[0].statement.nullifier = [8; 32];
    refused(
        &mut cases,
        "substituted cohort note",
        &v,
        "intent exact claim set",
    )?;
    let mut v = valid.clone();
    v.packet.intent.as_mut().unwrap().claims.reverse();
    refused(
        &mut cases,
        "noncanonical claims",
        &v,
        "intent canonical distinct claims",
    )?;
    let mut v = valid.clone();
    let n = v.packet.intent.as_ref().unwrap().claims[0];
    v.packet.intent.as_mut().unwrap().claims[1] = n;
    refused(
        &mut cases,
        "duplicate intended claim",
        &v,
        "intent canonical distinct claims",
    )?;
    let mut v = valid.clone();
    v.packet.intent.as_mut().unwrap().payouts.reverse();
    refused(
        &mut cases,
        "noncanonical payout set",
        &v,
        "intent canonical distinct payouts",
    )?;
    let mut v = valid.clone();
    let p = v.packet.intent.as_ref().unwrap().payouts[0].clone();
    v.packet.intent.as_mut().unwrap().payouts[1] = p;
    refused(
        &mut cases,
        "duplicate payout",
        &v,
        "intent canonical distinct payouts",
    )?;
    let mut v = valid.clone();
    v.packet.intent.as_mut().unwrap().payouts[0].truncate(35);
    refused(
        &mut cases,
        "malformed payout",
        &v,
        "intent standard payouts",
    )?;
    let mut v = valid.clone();
    v.packet.intent = None;
    refused(
        &mut cases,
        "strip intent into old branch",
        &v,
        "complete native effects authorization",
    )?;
    let mut v = valid.clone();
    v.packet.mode = app::NAMED;
    refused(
        &mut cases,
        "reinterpret as named",
        &v,
        "intent requires joint mode",
    )?;
    let mut v = valid.clone();
    v.packet.operations[0].proof.pop();
    refused(&mut cases, "malformed genuine proof", &v, "encoding/arity")?;
    let mut v = valid.clone();
    v.effects.outputs[0].spk[3] ^= 1;
    refused(
        &mut cases,
        "changed actual recipient",
        &v,
        "intent actual payout set",
    )?;
    let mut v = valid.clone();
    v.effects.outputs[0].value += 1;
    v.effects.outputs[1].value -= 1;
    refused(
        &mut cases,
        "compensated principal changes",
        &v,
        "intent actual payout set",
    )?;
    let mut v = valid.clone();
    v.effects.input_value = app::MAX_SOMPI + 1;
    refused(
        &mut cases,
        "native input out of range",
        &v,
        "native input range",
    )?;
    let mut v = valid.clone();
    v.effects.input_value = v.state.ledger.reserve - 1;
    refused(
        &mut cases,
        "underbacked native input",
        &v,
        "native input backing",
    )?;
    let mut v = valid.clone();
    v.effects.outputs[0].value = 0;
    refused(&mut cases, "zero native output", &v, "native output range")?;
    let mut v = valid.clone();
    v.effects.outputs[0].value = app::MAX_SOMPI;
    refused(&mut cases, "native inflation", &v, "native value inflation")?;
    let mut v = valid.clone();
    v.state = spent.state.clone();
    v.effects.previous = spent.point.transaction_id.as_bytes().try_into()?;
    v.effects.index = spent.point.index;
    v.effects.input_value = spent.value;
    let principal = v.packet.intent.as_ref().unwrap().denomination * 2;
    v.effects.outputs.last_mut().unwrap().value = spent.value - principal - 16_500_000;
    refused(
        &mut cases,
        "genuine spent cohort note with enough other backing",
        &v,
        "current economic nullifier spent",
    )?;
    let mut v = valid.clone();
    v.packet.intent.as_mut().unwrap().payouts[0][3] ^= 1;
    v.packet.intent.as_mut().unwrap().payouts.sort();
    refused(
        &mut cases,
        "changed approved recipient set",
        &v,
        "complete native effects authorization",
    )?;
    let mut v = valid.clone();
    v.packet.intent.as_mut().unwrap().fee_cap += 1;
    refused(
        &mut cases,
        "raise cap without fresh consent",
        &v,
        "complete native effects authorization",
    )?;
    let mut v = valid.clone();
    let original_fee =
        v.effects.input_value - v.effects.outputs.iter().map(|o| o.value).sum::<u64>();
    let extra = v.packet.intent.as_ref().unwrap().fee_cap - original_fee + 1;
    v.effects.outputs.last_mut().unwrap().value -= extra;
    refused(
        &mut cases,
        "actual fee exceeds unchanged approved cap",
        &v,
        "intent fee cap",
    )?;
    let mut v = valid.clone();
    v.effects.input_value = v.state.ledger.reserve;
    v.effects.outputs.pop();
    v.effects.outputs[0].value -= 100;
    refused(
        &mut cases,
        "attempt fee from principal",
        &v,
        "fee allowance/principal separation",
    )?;
    let mut v = valid.clone();
    v.effects.outputs = vec![
        app::NativeOutput {
            value: app::MAX_SOMPI,
            spk: vec![]
        };
        8
    ];
    refused(
        &mut cases,
        "native output sum overflow",
        &v,
        "native output sum overflow",
    )?;
    let mut v = valid.clone();
    let fee = v.effects.input_value - v.effects.outputs.iter().map(|o| o.value).sum::<u64>();
    v.effects.input_value = v.state.ledger.reserve + fee;
    v.effects.outputs.pop();
    let zero = app::execute(&v)?;
    if zero.refunded_fee != 0 {
        return Err("zero allowance refund branch".into());
    }
    cases.push(json!({"case":"zero unused allowance, unchanged approvals","hostKernelAccepted":true,"nativeReceiptForThisBoundaryCreated":false}));
    let mut raw = valid.packet.bytes();
    raw.push(0);
    if app::Packet::read(&raw).is_ok() {
        return Err("trailing packet bytes accepted".into());
    }
    cases.push(json!({"case":"strict packet trailing bytes","rejected":true}));
    let mut reordered = valid.clone();
    reordered.packet.operations.reverse();
    app::execute(&reordered)?;
    cases.push(json!({"case":"no claim-position to payout-position ownership map","operationPermutationAccepted":true}));
    Ok(cases)
}

pub fn experiment(program_path: &Path, core: &Path, out: &Path) -> Result<()> {
    campaign(program_path, core, out, false)
}
pub fn preflight(program_path: &Path, core: &Path, out: &Path) -> Result<()> {
    campaign(program_path, core, out, true)
}
fn campaign(program_path: &Path, core: &Path, out: &Path, host_only: bool) -> Result<()> {
    fs::create_dir(out)?;
    let program = fs::read(program_path)?;
    let (mut w, _, _, _) = restored_work(core)?;
    let policy = Policy {
        image: risc0_zkvm::compute_image_id(&program)?
            .as_bytes()
            .try_into()?,
    };
    let (fund, entry, report) = funding(&w, &policy)?;
    let mut world = World::start(&w, &fund, &entry, &report);
    let ops = w.operations.clone();
    let step = prepare_step(
        &mut w,
        &policy,
        &world.state,
        world.point,
        world.value,
        app::PAYMENT,
        &ops,
        &[],
    )?;
    apply_new(
        &program,
        &policy,
        &mut world,
        step,
        &out.join("initial"),
        host_only,
    )?;
    let legacy = prepare_step(
        &mut w,
        &policy,
        &world.state,
        world.point,
        world.value,
        app::JOINT,
        &[],
        &[1, 2],
    )?;
    let intent = make_intent(&w, &world.state);
    let t = Instant::now();
    let approvals = approve(&mut w, &intent)?;
    let approval_seconds = t.elapsed().as_secs_f64();
    let hash_before = approval_digest(&approvals);
    let proofs_after_approval = w.engine.proofs;
    save_public(
        &out.join("APPROVALS.json"),
        &json!({"intent":intent,"operations":approvals,"proofBytesSha256":hash_before,"walletApprovalSeconds":approval_seconds,"cohortApprovalsCreated":2}),
    )?;
    let pre = intent_step(&policy, &world, &intent, &approvals, 0)?;
    save_public(
        &out.join("before-activity.json"),
        &json!({"inputBincodeHex":hex::encode(bincode::serialize(&pre.input)?),"currentRoot":hex::encode(world.state.root())}),
    )?;
    let note0 = w.wallets[0].note(w.d / 2);
    let note1 = w.wallets[0].note(w.d - w.d / 2);
    let mut s = Statement::new(TRANSFER, w.engine.id(), world.state.ledger.tree.root());
    s.nullifier = nullifier(&w.witnesses[0].secret, &w.witnesses[0].input);
    let mut witness = w.witnesses[0].clone();
    witness.outputs = [note0.clone(), note1.clone()];
    let pay = w
        .engine
        .prove(s, witness, [note0.deliver()?, note1.deliver()?]);
    let step = prepare_step(
        &mut w,
        &policy,
        &world.state,
        world.point,
        world.value,
        app::PAYMENT,
        &[pay],
        &[],
    )?;
    apply_new(
        &program,
        &policy,
        &mut world,
        step,
        &out.join("unrelated-payment"),
        host_only,
    )?;
    let mut old = legacy.input.clone();
    old.state = world.state.clone();
    old.effects.previous = world.point.transaction_id.as_bytes().try_into()?;
    old.effects.index = world.point.index;
    old.effects.input_value = world.value;
    old.effects.outputs[0].value -= legacy.input.effects.input_value - world.value;
    let rejection = app::execute(&old)
        .err()
        .ok_or("old exact approval unexpectedly reusable")?;
    if rejection != "complete native effects authorization" {
        return Err(format!("wrong baseline rejection: {rejection}").into());
    }
    let after_pay = intent_step(&policy, &world, &intent, &approvals, 1_000)?;
    let continuing_input = after_pay.input.clone();
    let continuing_tx = after_pay.tx.clone();
    let mut continuing = world.clone();
    let continuing_stats = apply_new(
        &program,
        &policy,
        &mut continuing,
        after_pay,
        &out.join("continuing-intent"),
        host_only,
    )?;
    save_public(
        &out.join("continuing-world.json"),
        &json!({"records":continuing.records,"remainingReserveSompi":continuing.state.ledger.reserve,"remainingLiabilitySompi":continuing.state.ledger.private_liability,"counterfactual":true}),
    )?;
    // Genuine accepted spend of Bob's cohort note: enough Alice/Carol backing
    // remains, so current spentness is the decisive refusal, not lack of funds.
    restore_note(&mut w, &world.state, 1, intent.denomination)?;
    let bob = prepare_step(
        &mut w,
        &policy,
        &world.state,
        world.point,
        world.value,
        app::SOLO,
        &[],
        &[1],
    )?;
    let mut spent = world.clone();
    apply_new(
        &program,
        &policy,
        &mut spent,
        bob,
        &out.join("spent-note-control"),
        host_only,
    )?;
    save_public(
        &out.join("spent-world.json"),
        &json!({"records":spent.records,"reserveSompi":spent.state.ledger.reserve,"counterfactual":true}),
    )?;
    for name in ["alice-solo-first", "alice-solo-last"] {
        let half = intent.denomination / 2;
        restore_note(&mut w, &world.state, 0, half)?;
        w.d = half;
        let step = prepare_step(
            &mut w,
            &policy,
            &world.state,
            world.point,
            world.value,
            app::SOLO,
            &[],
            &[0],
        )?;
        apply_new(
            &program,
            &policy,
            &mut world,
            step,
            &out.join(name),
            host_only,
        )?;
    }
    let terminal = intent_step(&policy, &world, &intent, &approvals, 0)?;
    let valid = terminal.input.clone();
    let terminal_entry = world.entry()?;
    let controls = host_controls(&valid, &spent)?;
    save_public(&out.join("HOST-CONTROLS.json"), &json!(controls))?;
    let old_point = world
        .accept(&Step {
            tx: continuing_tx,
            input: continuing_input.clone(),
            output: app::execute(&continuing_input)?,
            report: json!({}),
        })
        .err()
        .ok_or("stale native outpoint accepted")?
        .to_string();
    let mut native_controls = vec![];
    if !host_only {
        let proof = fs::read(out.join("continuing-intent/native-proof.bin"))?;
        let mut attack = terminal.tx.clone();
        attack.inputs[0].signature_script = policy.witness(valid.state.root(), [0; 32], &proof);
        attack.finalize();
        let err = native::validate(&attack, &terminal_entry)
            .err()
            .ok_or("old receipt accepted at changed state")?;
        if !err.contains("ZkIntegrity") || !err.contains("Groth16 verification failed") {
            return Err(format!("wrong stale receipt layer: {err}").into());
        }
        native_controls.push(json!({"case":"old actual receipt at different current state/input","error":err,"actualNativeFullRejection":true}));
        let mut bad = valid.clone();
        bad.effects.outputs[0].spk[3] ^= 1;
        native_controls.push(json!({"case":"changed owner-approved recipient","actualGuestError":prover::reject_guest(&program,&bad)?}));
        let mut bad = valid.clone();
        bad.state = spent.state.clone();
        bad.effects.previous = spent.point.transaction_id.as_bytes().try_into()?;
        bad.effects.index = spent.point.index;
        bad.effects.input_value = spent.value;
        bad.effects.outputs.last_mut().unwrap().value =
            spent.value - 2 * intent.denomination - 16_500_000;
        native_controls.push(json!({"case":"genuine spent cohort note","actualGuestError":prover::reject_guest(&program,&bad)?}));
    }
    let terminal_stats = apply_new(
        &program,
        &policy,
        &mut world,
        terminal,
        &out.join("terminal-intent"),
        host_only,
    )?;
    if world.state.ledger.reserve != 0
        || world.state.ledger.private_liability != 0
        || !world.active.is_empty()
    {
        return Err("main world incomplete drainage".into());
    }
    if approval_digest(&approvals) != hash_before {
        return Err("owner approvals changed".into());
    }
    // Only Alice's one private payment, Bob's control exit and Alice's two solo
    // exits were proved after approval creation. No cohort reapproval occurs.
    if w.engine.proofs != proofs_after_approval + 4 {
        return Err("unexpected wallet reproving".into());
    }
    let fees: u64 = world
        .records
        .iter()
        .map(|r| {
            r["report"]["feeSompi"].as_u64().unwrap_or_else(|| {
                let input: app::Input = from_hex(&r["inputBincodeHex"]).unwrap();
                app::execute(&input).unwrap().fee
            })
        })
        .sum();
    save_public(
        &out.join("RESULT.json"),
        &json!({"schema":"reusable-owner-withdrawal-intent-v1","hostOnlyPreflight":host_only,"records":world.records,"mainFinalReserveSompi":0,"mainFinalLiabilitySompi":0,"mainFinalActiveBankOutputs":0,"mainNativeFeeSompi":fees,"cohortApprovalsCreated":2,"newCohortApprovalsAfterUnrelatedUpdates":0,"approvalBytesSha256Before":hash_before,"approvalBytesSha256After":approval_digest(&approvals),"walletApprovalSeconds":approval_seconds,"unrelatedAcceptedUpdatesBeforeTerminalPayout":3,"continuingReceipt":continuing_stats,"terminalReceipt":terminal_stats,"legacyExactEffectRejection":rejection,"staleBankOutpointRejection":old_point,"nativeAndGuestControls":native_controls,"remainingCounterfactualBackingSompi":continuing.state.ledger.reserve,"outerProofMustStillBeFresh":true,"approvalTransportQualified":false}),
    )?;
    eprintln!("INTENT_CAMPAIGN_COMPLETE host_only={host_only} fee_sompi={fees}");
    Ok(())
}


// Coordinator receives only public operations. Wallet witnesses stay in actors.
use std::{
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
};
struct PublicVerifier(ark_groth16::VerifyingKey<ark_bn254::Bn254>);
impl kpi_private_note_wallet::ProofVerifier for PublicVerifier {
    fn id(&self) -> H {
        hash(&proof::serialize(&self.0))
    }
    fn verify(&self, o: &Operation) -> std::result::Result<(), String> {
        if proof::verify(&self.0, o) {
            Ok(())
        } else {
            Err("public wallet pairing".into())
        }
    }
}
struct WalletProcess {
    child: Child,
    input: std::process::ChildStdin,
    output: std::io::BufReader<std::process::ChildStdout>,
}
struct Actors {
    root: PathBuf,
    params: PathBuf,
    calls: Vec<Value>,
    processes: HashMap<usize, WalletProcess>,
}
impl Actors {
    fn call(
        &mut self,
        who: usize,
        mut request: Value,
        state: Option<&app::State>,
    ) -> Result<Value> {
        if let Some(s) = state {
            request["state"] = json!(hex::encode(bincode::serialize(s)?));
        }
        if !self.processes.contains_key(&who) {
            let log = self.root.join(format!("wallet-{who}-stderr.log"));
            let stderr = fs::OpenOptions::new().create(true).append(true).open(log)?;
            let mut child = Command::new(std::env::current_exe()?)
                .arg("actor")
                .arg(self.root.join(format!("wallet-{who}")))
                .arg(&self.params)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(stderr)
                .spawn()?;
            let input = child.stdin.take().ok_or("wallet stdin")?;
            let output = BufReader::new(child.stdout.take().ok_or("wallet stdout")?);
            self.processes.insert(
                who,
                WalletProcess {
                    child,
                    input,
                    output,
                },
            );
        }
        let p = self.processes.get_mut(&who).unwrap();
        writeln!(p.input, "{}", request)?;
        p.input.flush()?;
        let mut line = String::new();
        if p.output.read_line(&mut line)? == 0 {
            return Err(format!("wallet {who} stopped; see its private stderr log").into());
        }
        let response: Value = serde_json::from_str(&line)?;
        // These are real identified local calls. Do not erase their ownership links.
        self.calls
            .push(json!({"actor":who,"request":request,"response":response}));
        let mut log = fs::OpenOptions::new().create(true).append(true).open(
            self.root
                .parent()
                .ok_or("actor root parent")?
                .join("actor-calls.jsonl"),
        )?;
        writeln!(log, "{}", self.calls.last().unwrap())?;
        Ok(response["result"].clone())
    }
    fn operations(
        &mut self,
        who: usize,
        request: Value,
        state: &app::State,
    ) -> Result<Vec<Operation>> {
        Ok(serde_json::from_value(
            self.call(who, request, Some(state))?["operations"].clone(),
        )?)
    }
}
impl Actors {
    fn restart(&mut self) {
        for (_, mut p) in self.processes.drain() {
            let _ = p.child.kill();
            let _ = p.child.wait();
        }
    }
}
impl Drop for Actors {
    fn drop(&mut self) {
        self.restart();
    }
}
fn public_verifier(state: &app::State) -> Result<PublicVerifier> {
    use ark_serialize::CanonicalDeserialize;
    Ok(PublicVerifier(
        ark_groth16::VerifyingKey::deserialize_compressed(state.wallet_vk.as_slice())?,
    ))
}
fn payment(policy: &Policy, world: &World, ops: Vec<Operation>) -> Result<Step> {
    let mut next = world.state.clone();
    let verifier = public_verifier(&next)?;
    for op in &ops {
        next.ledger.apply(&verifier, op)?;
    }
    let packet = app::Packet {
        mode: app::PAYMENT,
        operations: ops,
        intent: None,
    };
    public_step(policy, world, next, packet, vec![])
}
fn public_step(
    policy: &Policy,
    world: &World,
    next: app::State,
    packet: app::Packet,
    payouts: Vec<TransactionOutput>,
) -> Result<Step> {
    let old = world.state.root();
    let new = if next.ledger.reserve == 0 {
        [0; 32]
    } else {
        next.root()
    };
    let allowance = world
        .value
        .checked_sub(world.state.ledger.reserve)
        .ok_or("backing")?;
    let mut outputs = vec![];
    if next.ledger.reserve > 0 {
        outputs.push(TransactionOutput::new(
            next.ledger
                .reserve
                .checked_add(allowance)
                .ok_or("backing range")?,
            policy.spk(new),
        ));
    }
    outputs.extend(payouts);
    if next.ledger.reserve == 0 {
        outputs.push(TransactionOutput::new(
            allowance,
            native::spk(&world.state.fee_refund_spk),
        ));
    }
    let mut tx = native::transaction(world.point, outputs, packet.bytes(), native::BUDGET);
    tx.inputs[0].signature_script = policy.witness(old, new, &[0; 128]);
    let entry = world.entry()?;
    let fee = native::quote(&tx, &entry)["minimumDefaultRelayFeeSompi"]
        .as_u64()
        .ok_or("fee")?;
    let slot = if next.ledger.reserve > 0 {
        0
    } else {
        tx.outputs.len() - 1
    };
    tx.outputs[slot].value = tx.outputs[slot]
        .value
        .checked_sub(fee)
        .ok_or("fee allowance exhausted")?;
    tx.finalize();
    let input = app::Input {
        state: world.state.clone(),
        packet,
        effects: native::effects(&tx, world.value),
    };
    let output = app::execute(&input)?;
    if output.state.root() != next.root() {
        return Err("public expected successor".into());
    }
    Ok(Step {
        report: native::quote(&tx, &entry),
        tx,
        input,
        output,
    })
}
fn named(
    policy: &Policy,
    world: &World,
    ops: Vec<Operation>,
    payouts: Vec<TransactionOutput>,
) -> Result<Step> {
    let mut next = world.state.clone();
    for op in &ops {
        if !next.ledger.nullifiers.insert(op.statement.nullifier) {
            return Err("named NF spent".into());
        }
        next.ledger.reserve = next
            .ledger
            .reserve
            .checked_sub(op.statement.exit_value)
            .ok_or("named reserve")?;
        next.ledger.private_liability = next
            .ledger
            .private_liability
            .checked_sub(op.statement.exit_value)
            .ok_or("named liability")?;
    }
    next.ledger.invariant()?;
    public_step(
        policy,
        world,
        next,
        app::Packet {
            mode: app::NAMED,
            operations: ops,
            intent: None,
        },
        payouts,
    )
}
fn launch(program: &Path, step: &Step, dir: &Path) -> Result<Child> {
    let raw = dir.with_extension("input.bin");
    prover::write(&raw, &bincode::serialize(&step.input)?)?;
    Ok(Command::new(std::env::current_exe()?)
        .arg("prove")
        .arg(program)
        .arg(raw)
        .arg(dir)
        .stdout(
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.with_extension("stdout.log"))?,
        )
        .stderr(
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.with_extension("stderr.log"))?,
        )
        .spawn()?)
}
fn collect(policy: &Policy, world: &mut World, step: &mut Step, dir: &Path) -> Result<Value> {
    let receipt: risc0_zkvm::Receipt =
        bincode::deserialize(&fs::read(dir.join("candidate-compressed.bin"))?)?;
    let program_image = risc0_zkvm::sha::Digest::from_bytes(policy.image);
    prover::verify(&receipt, program_image, &step.output.journal)?;
    let raw = prover::native_proof(&receipt)?;
    if raw != fs::read(dir.join("native-proof.bin"))? {
        return Err("receipt/native proof mismatch".into());
    }
    finish(step, policy, &raw, &world.entry()?)?;
    world.accept(step)?;
    Ok(read(&dir.join("proof-report.json"))?)
}
fn settle(
    program: &Path,
    policy: &Policy,
    world: &mut World,
    mut step: Step,
    dir: &Path,
    host: bool,
) -> Result<Value> {
    if host {
        return apply_new(&fs::read(program)?, policy, world, step, dir, true);
    }
    let mut child = launch(program, &step, dir)?;
    if !child.wait()?.success() {
        return Err(format!("prover failed: {}", dir.display()).into());
    }
    collect(policy, world, &mut step, dir)
}
fn transfers(
    actors: &mut Actors,
    who: usize,
    state: &mut app::State,
    recipient: &Value,
    input: u64,
    amount: u64,
) -> Result<Vec<Operation>> {
    let ops = actors.operations(
        who,
        json!({"method":"transfer","inputValue":input,"amount":amount,"recipient":recipient}),
        state,
    )?;
    for o in &ops {
        state.ledger.apply(&public_verifier(state)?, o)?;
    }
    Ok(ops)
}
fn funding_public(
    actors: &mut Actors,
    policy: &Policy,
    initial: &app::State,
    source: TransactionOutpoint,
    spk: &ScriptPublicKey,
) -> Result<(Transaction, UtxoEntry, Value)> {
    let entry = UtxoEntry::new(4_300_000_000, spk.clone(), 0, false, None);
    let mut tx = native::transaction(
        source,
        vec![
            TransactionOutput::new(4_200_000_000, policy.spk(initial.root())),
            TransactionOutput::new(100_000_000, spk.clone()),
        ],
        bincode::serialize(initial)?,
        20,
    );
    tx.inputs[0].signature_script = vec![0; 66];
    let fee = native::quote(&tx, &entry)["minimumDefaultRelayFeeSompi"]
        .as_u64()
        .ok_or("fund fee")?;
    tx.outputs[1].value -= fee;
    tx.finalize();
    let signed=actors.call(0,json!({"method":"sign","funding":true,"image":policy.image,"transaction":hex::encode(bincode::serialize(&tx)?),"entry":hex::encode(bincode::serialize(&entry)?)}),None)?;
    tx = bincode::deserialize(&hex::decode(
        signed["transaction"].as_str().ok_or("signed")?,
    )?)?;
    Ok((tx.clone(), entry.clone(), native::validate(&tx, &entry)?))
}
fn prepare_arrival(
    actors: &mut Actors,
    projected: &mut app::State,
    addresses: &[Value],
    n: usize,
) -> Result<Vec<Operation>> {
    let (who, input, amount) = [
        (1, 800_000_000, 100_000_000),
        (2, 700_000_000, 300_000_000),
        (0, 400_000_000, 100_000_000),
    ][n];
    transfers(actors, 3, projected, &addresses[who], input, amount)
}
fn queue_controls(valid: &app::Input) -> Result<Vec<Value>> {
    let mut cases = vec![];
    let mut bad = valid.clone();
    bad.packet.intent.as_mut().unwrap().pool = [9; 32];
    refused(&mut cases, "wrong pool", &bad, "intent pool")?;
    let mut bad = valid.clone();
    bad.packet.intent.as_mut().unwrap().reference_anchor = [0; 32];
    refused(
        &mut cases,
        "unaccepted root",
        &bad,
        "intent accepted reference anchor",
    )?;
    let mut bad = valid.clone();
    let nf = bad.packet.operations[0].statement.nullifier;
    bad.state.ledger.nullifiers.insert(nf);
    refused(
        &mut cases,
        "cohort claim already spent",
        &bad,
        "current economic nullifier spent",
    )?;
    let mut bad = valid.clone();
    bad.packet.operations.push(bad.packet.operations[0].clone());
    refused(
        &mut cases,
        "duplicate cohort claim",
        &bad,
        "intent complete cohort",
    )?;
    let mut bad = valid.clone();
    bad.effects.outputs[1].spk[3] ^= 1;
    refused(
        &mut cases,
        "changed payout",
        &bad,
        "intent actual payout set",
    )?;
    let mut bad = valid.clone();
    let cap = bad.packet.intent.as_ref().unwrap().fee_cap;
    let payout =
        bad.packet.intent.as_ref().unwrap().denomination * bad.packet.operations.len() as u64;
    bad.effects.outputs[0].value = bad.effects.input_value - payout - cap - 1;
    refused(&mut cases, "fee exceeds owner cap", &bad, "intent fee cap")?;
    Ok(cases)
}
pub fn preflight_controls(run: &Path) -> Result<()> {
    let input: app::Input =
        from_hex(&read(&run.join("priority-withdrawal/HOST-ONLY.json"))?["inputBincodeHex"])?;
    app::execute(&input)?;
    println!(
        "{}",
        json!({"hostOnly":true,"controls":queue_controls(&input)?})
    );
    Ok(())
}
pub fn run_busy(program: &Path, params: &Path, out: &Path, host: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir(out)?;
    fs::create_dir(out.join("private"))?;
    fs::set_permissions(out.join("private"), fs::Permissions::from_mode(0o700))?;
    let mut actors = Actors {
        root: out.join("private"),
        params: params.into(),
        calls: vec![],
        processes: HashMap::new(),
    };
    let mut addresses = vec![];
    for who in 0..4 {
        addresses.push(actors.call(who, json!({"method":"public"}), None)?);
    }
    let policy = Policy {
        image: risc0_zkvm::compute_image_id(&fs::read(program)?)?
            .as_bytes()
            .try_into()?,
    };
    if hex::encode(policy.image)
        != "8f62f0eeaf41c7b331672ffee123bde15b37a80f12507e09c917bbcc4414493f"
    {
        return Err("unchanged intent program required".into());
    }
    let source = native::fake_point(fresh());
    let pool = hash(
        &[
            b"KPI-busy-pool-v1\0".as_slice(),
            source.transaction_id.as_bytes().as_slice(),
        ]
        .concat(),
    );
    let vk =
        include_bytes!("../../../reusable-withdrawal-approvals/pins/vk-compressed.bin").to_vec();
    let mut ledger = Ledger::new(hash(&vk));
    let owner: H = serde_json::from_value(addresses[0]["owner"].clone())?;
    ledger.register_authenticated_fixture_deposit(pool, 4_000_000_000, owner)?;
    let refund: Vec<u8> = serde_json::from_value(addresses[0]["fundingSpk"].clone())?;
    let initial = app::State {
        ledger,
        pool,
        wallet_vk: vk,
        fee_refund_spk: refund.clone(),
    };
    let (fund, source_entry, report) = funding_public(
        &mut actors,
        &policy,
        &initial,
        source,
        &native::spk(&refund),
    )?;
    let bankpoint = TransactionOutpoint::new(fund.id(), 0);
    let bankentry = UtxoEntry::new(
        fund.outputs[0].value,
        fund.outputs[0].script_public_key.clone(),
        0,
        false,
        None,
    );
    let mut world = World {
        state: initial.clone(),
        point: bankpoint,
        value: bankentry.amount,
        active: HashMap::from([(bankpoint, bankentry)]),
        records: vec![
            json!({"kind":"deposit","transaction":fund,"sourceEntryBincodeHex":hex::encode(bincode::serialize(&source_entry)?),"report":report}),
        ],
    };
    let mut projected = initial;
    let mut ops = actors.operations(0, json!({"method":"credit"}), &projected)?;
    for op in &ops {
        projected.ledger.apply(&public_verifier(&projected)?, op)?;
    }
    ops.extend(transfers(
        &mut actors,
        0,
        &mut projected,
        &addresses[1],
        4_000_000_000,
        2_000_000_000,
    )?);
    ops.extend(transfers(
        &mut actors,
        1,
        &mut projected,
        &addresses[2],
        2_000_000_000,
        1_000_000_000,
    )?);
    ops.extend(transfers(
        &mut actors,
        0,
        &mut projected,
        &addresses[3],
        2_000_000_000,
        1_000_000_000,
    )?);
    eprintln!("PHASE initial genuine payments");
    let step = payment(&policy, &world, ops)?;
    settle(
        program,
        &policy,
        &mut world,
        step,
        &out.join("initial"),
        host,
    )?;
    let mut claims = vec![];
    let mut payouts = vec![];
    for who in 0..3 {
        let e = actors.call(
            who,
            json!({"method":"entitlement","value":1_000_000_000u64}),
            Some(&world.state),
        )?;
        claims.push(serde_json::from_value::<H>(e["nullifier"].clone())?);
        payouts.push(serde_json::from_value::<Vec<u8>>(e["payout"].clone())?);
    }
    claims.sort();
    payouts.sort();
    let intent = app::WithdrawalIntent {
        protocol_domain: domain(),
        pool,
        verifier: world.state.ledger.verifier,
        reference_anchor: world.state.ledger.tree.root(),
        nonce: fresh(),
        refund_key_hash: hash(&refund),
        denomination: 1_000_000_000,
        fee_cap: 20_000_000,
        claims,
        payouts,
    };
    let mut approvals = vec![];
    for who in 0..3 {
        approvals.extend(actors.operations(
            who,
            json!({"method":"approve","intent":intent}),
            &world.state,
        )?);
    }
    approvals.sort_by_key(|o| o.statement.nullifier);
    let approval_hash = approval_digest(&approvals);
    save_public(
        &out.join("APPROVALS.json"),
        &json!({"intent":intent,"operations":approvals,"hash":approval_hash,"identifiedSourceLinks":true}),
    )?;
    let mut stale = intent_step(&policy, &world, &intent, &approvals, 0)?;
    save_public(
        &out.join("HOST-CONTROLS.json"),
        &json!(queue_controls(&stale.input)?),
    )?;
    projected = world.state.clone();
    let external_ops = transfers(
        &mut actors,
        3,
        &mut projected,
        &addresses[0],
        1_000_000_000,
        200_000_000,
    )?;
    let mut external = payment(&policy, &world, external_ops)?;
    let mut scheduler = crate::queue::Queue::default();
    scheduler.push(crate::queue::Kind::Withdrawal, usize::MAX)?;
    let active = scheduler.lease(32)?;
    let mut queued = vec![];
    let mut arrival_events = vec![];
    let started = Instant::now();
    let mut first_seconds = 0.0;
    if host {
        apply_new(
            &fs::read(program)?,
            &policy,
            &mut world,
            external,
            &out.join("external"),
            true,
        )?;
        for n in 0..3 {
            queued.extend(prepare_arrival(&mut actors, &mut projected, &addresses, n)?);
            scheduler.push(crate::queue::Kind::Payment, n)?;
            arrival_events.push(json!({"index":n,"seconds":0,"hostPreflight":true}));
        }
    } else {
        eprintln!("PHASE precompute genuine competing update (charged separately)");
        let mut child = launch(program, &external, &out.join("external"))?;
        if !child.wait()?.success() {
            return Err("external prover failed".into());
        }
        let race = Instant::now();
        eprintln!("PHASE real withdrawal proving with timed arrivals");
        let mut child = launch(program, &stale, &out.join("stale"))?;
        let mut accepted = false;
        loop {
            let elapsed = race.elapsed().as_secs_f64();
            if !accepted && elapsed >= 30.0 {
                if child.try_wait()?.is_some() {
                    return Err("withdrawal finished before race injection".into());
                }
                collect(&policy, &mut world, &mut external, &out.join("external"))?;
                accepted = true;
                arrival_events.push(json!({"event":"external accepted","seconds":elapsed,"withdrawalProverPid":child.id(),"withdrawalProcessStillRunning":true,"preparedBeforeRace":true}));
                eprintln!("PHASE competing update accepted during withdrawal proof");
            }
            let n = queued.len();
            if n < 3 && elapsed >= [90.0, 330.0, 570.0][n] {
                queued.extend(prepare_arrival(&mut actors, &mut projected, &addresses, n)?);
                scheduler.push(crate::queue::Kind::Payment, n)?;
                arrival_events.push(json!({"event":"payment queued","index":n,"seconds":race.elapsed().as_secs_f64(),"settled":false}));
            }
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    return Err("stale prover failed".into());
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        first_seconds = race.elapsed().as_secs_f64();
        let receipt: risc0_zkvm::Receipt =
            bincode::deserialize(&fs::read(out.join("stale/candidate-compressed.bin"))?)?;
        prover::verify(
            &receipt,
            risc0_zkvm::compute_image_id(&fs::read(program)?)?,
            &stale.output.journal,
        )?;
        let stale_entry = UtxoEntry::new(
            stale.input.effects.input_value,
            policy.spk(stale.input.state.root()),
            0,
            false,
            None,
        );
        finish(
            &mut stale,
            &policy,
            &prover::native_proof(&receipt)?,
            &stale_entry,
        )?;
        let error = world
            .accept(&stale)
            .err()
            .ok_or("stale bank was accepted")?
            .to_string();
        let mut rebased = intent_step(&policy, &world, &intent, &approvals, 0)?;
        let root = rebased.input.state.root();
        let new = rebased.output.journal[32..64].try_into()?;
        rebased.tx.inputs[0].signature_script =
            policy.witness(root, new, &prover::native_proof(&receipt)?);
        rebased.tx.finalize();
        let crypto = native::validate(&rebased.tx, &world.entry()?)
            .err()
            .ok_or("stale proof survived new effects")?
            .to_string();
        if !crypto.contains("ZkIntegrity") && !crypto.contains("Groth16") {
            return Err(format!("wrong stale receipt failure: {crypto}").into());
        }
        save_public(
            &out.join("STALE.json"),
            &json!({"outpointError":error,"rebasedReceiptError":crypto,"feePaidSompi":0,"completeReceipt":true,"seconds":first_seconds,"record":{"transaction":stale.tx,"inputBincodeHex":hex::encode(bincode::serialize(&stale.input)?)}}),
        )?;
        // Save the shared prefix before either scheduler arm advances it.
        save_public(
            &out.join("COMMON.json"),
            &json!({"records":world.records,"worldState":hex::encode(bincode::serialize(&world.state)?),"firstProofSeconds":first_seconds}),
        )?;
        // The candidate begins retry immediately. New arrivals never reset its age.
        scheduler.retry(active.clone())?;
        let active_retry = scheduler.lease(32)?;
        if active_retry.len() != 1 || active_retry[0].kind != crate::queue::Kind::Withdrawal {
            return Err("oldest withdrawal lost queue priority".into());
        }
        let mut retry = intent_step(&policy, &world, &intent, &approvals, 0)?;
        let mut child = launch(program, &retry, &out.join("priority-withdrawal"))?;
        loop {
            let n = queued.len();
            if n < 3 && race.elapsed().as_secs_f64() >= [90.0, 330.0, 570.0][n] {
                queued.extend(prepare_arrival(&mut actors, &mut projected, &addresses, n)?);
                scheduler.push(crate::queue::Kind::Payment, n)?;
                arrival_events.push(json!({"event":"payment queued","index":n,"seconds":race.elapsed().as_secs_f64(),"settled":false}));
            }
            if let Some(status) = child.try_wait()? {
                if !status.success() {
                    return Err("priority prover failed".into());
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        collect(
            &policy,
            &mut world,
            &mut retry,
            &out.join("priority-withdrawal"),
        )?;
        scheduler.accepted(&active_retry)?;
        save_public(
            &out.join("PRIORITY-WAIT.json"),
            &json!({"groupWaitSeconds":race.elapsed().as_secs_f64(),"sharedFirstProofSeconds":first_seconds,"newWalletApprovals":0}),
        )?;
        while queued.len() < 3 {
            let n = queued.len();
            if race.elapsed().as_secs_f64() >= [90.0, 330.0, 570.0][n] {
                queued.extend(prepare_arrival(&mut actors, &mut projected, &addresses, n)?);
                scheduler.push(crate::queue::Kind::Payment, n)?;
                arrival_events.push(json!({"event":"payment queued","index":n,"seconds":race.elapsed().as_secs_f64(),"settled":false}));
            } else {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
    let mut reference = world.clone();
    if host {
        scheduler.retry(active)?;
        let active = scheduler.lease(32)?;
        let retry = intent_step(&policy, &world, &intent, &approvals, 0)?;
        settle(
            program,
            &policy,
            &mut world,
            retry,
            &out.join("priority-withdrawal"),
            true,
        )?;
        scheduler.accepted(&active)?;
    } else {
        // Restore the genuine shared external prefix for the sequential reference arm.
        let common = read(&out.join("COMMON.json"))?;
        reference.state = from_hex(&common["worldState"])?;
        reference.records = serde_json::from_value(common["records"].clone())?;
        let tx = read_transaction(&reference.records.last().ok_or("prefix")?["transaction"])?;
        reference.point = TransactionOutpoint::new(tx.id(), 0);
        reference.value = tx.outputs[0].value;
        reference.active = HashMap::from([(
            reference.point,
            UtxoEntry::new(
                reference.value,
                tx.outputs[0].script_public_key.clone(),
                0,
                false,
                None,
            ),
        )]);
    }
    eprintln!("PHASE batch queued payments after withdrawal");
    let batch_jobs = scheduler.lease(32)?;
    if batch_jobs.iter().map(|j| j.payload).collect::<Vec<_>>() != vec![0, 1, 2] {
        return Err("queued payment order changed".into());
    }
    let error = payment(&policy, &world, vec![queued[1].clone()])
        .err()
        .ok_or("projected child settled without parent")?
        .to_string();
    if !error.contains("anchor") {
        return Err(format!("wrong pending child failure: {error}").into());
    }
    let error2 = payment(&policy, &world, vec![queued[0].clone(), queued[0].clone()])
        .err()
        .ok_or("queued double spend accepted")?
        .to_string();
    if !error2.contains("nullifier spent") {
        return Err(format!("wrong double spend failure: {error2}").into());
    }
    save_public(
        &out.join("PENDING-CONTROLS.json"),
        &json!({"childBeforeParent":error,"duplicatePendingSpend":error2}),
    )?;
    let batch = payment(&policy, &world, queued.clone())?;
    settle(
        program,
        &policy,
        &mut world,
        batch,
        &out.join("queued-batch"),
        host,
    )?;
    scheduler.accepted(&batch_jobs)?;
    let mut final_ops = vec![];
    let mut final_payouts = vec![];
    for who in 0..4 {
        let result = actors.call(who, json!({"method":"named"}), Some(&world.state))?;
        final_ops.extend(serde_json::from_value::<Vec<Operation>>(
            result["operations"].clone(),
        )?);
        for p in result["payouts"].as_array().ok_or("payouts")? {
            final_payouts.push(TransactionOutput::new(
                p["value"].as_u64().ok_or("value")?,
                native::spk(&serde_json::from_value::<Vec<u8>>(p["spk"].clone())?),
            ));
        }
    }
    if final_ops.len() != 5 || world.state.ledger.tree.leaves.len() != 15 {
        return Err("frozen workload shape".into());
    }
    let final_step = named(&policy, &world, final_ops.clone(), final_payouts.clone())?;
    settle(
        program,
        &policy,
        &mut world,
        final_step,
        &out.join("later-payouts"),
        host,
    )?;
    if world.state.ledger.reserve != 0
        || world.state.ledger.private_liability != 0
        || world.value != 0
    {
        return Err("terminal principal or liability".into());
    }
    // Each separate invocation reloads its wallet's own saved payout keys.
    actors.restart();
    let mut spends = vec![];
    if !host {
        for record in &world.records[1..] {
            let tx = read_transaction(&record["transaction"])?;
            for (index, o) in tx.outputs.iter().enumerate() {
                let encoded = native::encoded(&o.script_public_key);
                let owner = actors.calls.iter().find_map(|c| {
                    let who = c["actor"].as_u64()? as usize;
                    let result = &c["response"]["result"];
                    if result["groupSpk"] == json!(encoded)
                        || result["payouts"]
                            .as_array()
                            .is_some_and(|p| p.iter().any(|p| p["spk"] == json!(encoded)))
                    {
                        Some(who)
                    } else {
                        None
                    }
                });
                let Some(who) = owner else { continue };
                if encoded == refund {
                    continue;
                }
                let entry = UtxoEntry::new(o.value, o.script_public_key.clone(), 0, false, None);
                let mut spend = native::transaction(
                    TransactionOutpoint::new(tx.id(), index as u32),
                    vec![o.clone()],
                    vec![],
                    20,
                );
                spend.inputs[0].signature_script = vec![0; 66];
                let fee = native::quote(&spend, &entry)["minimumDefaultRelayFeeSompi"]
                    .as_u64()
                    .ok_or("spend fee")?;
                spend.outputs[0].value = spend.outputs[0]
                    .value
                    .checked_sub(fee)
                    .ok_or("spend value")?;
                spend.finalize();
                let signed=actors.call(who,json!({"method":"sign","funding":false,"transaction":hex::encode(bincode::serialize(&spend)?),"entry":hex::encode(bincode::serialize(&entry)?)}),None)?;
                spend = bincode::deserialize(&hex::decode(
                    signed["transaction"].as_str().ok_or("spend")?,
                )?)?;
                spends.push(json!({"owner":who,"transaction":spend,"entryBincodeHex":hex::encode(bincode::serialize(&entry)?),"report":native::validate(&spend,&entry)?}));
            }
        }
        if spends.len() != 8 {
            return Err(format!("expected eight restored payouts, got {}", spends.len()).into());
        }
    }
    save_public(
        &out.join("MAIN.json"),
        &json!({"records":world.records,"reserve":world.state.ledger.reserve,"liability":world.state.ledger.private_liability,"leaves":world.state.ledger.tree.leaves.len(),"restoredPayoutSpends":spends,"nativeFull":!host,"chainAccepted":false,"usefulPaymentSompi":4_700_000_000u64,"principalSompi":4_000_000_000u64}),
    )?;
    eprintln!("PHASE reference individual payments before withdrawal");
    let ref_start = Instant::now();
    for (n, op) in queued.iter().enumerate() {
        if !host {
            let arrived = arrival_events
                .iter()
                .find(|e| e["event"] == "payment queued" && e["index"] == json!(n))
                .ok_or("missing actual arrival")?["seconds"]
                .as_f64()
                .ok_or("arrival time")?;
            while first_seconds + ref_start.elapsed().as_secs_f64() < arrived {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        let step = payment(&policy, &reference, vec![op.clone()])?;
        settle(
            program,
            &policy,
            &mut reference,
            step,
            &out.join(format!("reference-payment-{n}")),
            host,
        )?;
    }
    let step = intent_step(&policy, &reference, &intent, &approvals, 0)?;
    settle(
        program,
        &policy,
        &mut reference,
        step,
        &out.join("reference-withdrawal"),
        host,
    )?;
    let reference_wait = first_seconds + ref_start.elapsed().as_secs_f64();
    let final_step = named(&policy, &reference, final_ops, final_payouts)?;
    settle(
        program,
        &policy,
        &mut reference,
        final_step,
        &out.join("reference-later-payouts"),
        host,
    )?;
    if reference.state.ledger.reserve != 0 || reference.state.ledger.private_liability != 0 {
        return Err("reference terminal accounting".into());
    }
    save_public(
        &out.join("REFERENCE.json"),
        &json!({"records":reference.records,"groupWaitSeconds":reference_wait,"branchWorkSeconds":ref_start.elapsed().as_secs_f64(),"commonPhaseCharged":true,"sequentialCounterfactual":true,"terminal":true,"remainingPrincipalSompi":reference.state.ledger.reserve,"nativeFull":!host}),
    )?;
    save_public(
        &out.join("ARRIVALS.json"),
        &json!({"events":arrival_events,"elapsedAfterCompetingProofSeconds":started.elapsed().as_secs_f64(),"boundedPayments":3,"externalUpdates":1,"unboundedLoadQualified":false}),
    )?;
    save_public(
        &out.join("SERVICE.json"),
        &json!({"calls":actors.calls,"identifiedLocalIpc":true,"anonymousRegistrationRetested":false,"payoutOwnerAssignments":1,"independentPeople":false,"backupFilesReadByCoordinator":false}),
    )?;
    if approval_hash != approval_digest(&approvals) {
        return Err("owner approval bytes changed".into());
    }
    eprintln!("PHASE complete: all principal drained, original approvals unchanged");
    Ok(())
}

pub fn replay_busy(program: &Path, run: &Path) -> Result<()> {
    use ark_serialize::CanonicalDeserialize;
    let program = fs::read(program)?;
    let image = risc0_zkvm::compute_image_id(&program)?;
    let policy = Policy {
        image: image.as_bytes().try_into()?,
    };
    let mut totals = vec![];
    let approved: Vec<Operation> =
        serde_json::from_value(read(&run.join("APPROVALS.json"))?["operations"].clone())?;
    for (file, names) in [
        (
            "MAIN.json",
            vec![
                "initial",
                "external",
                "priority-withdrawal",
                "queued-batch",
                "later-payouts",
            ],
        ),
        (
            "REFERENCE.json",
            vec![
                "initial",
                "external",
                "reference-payment-0",
                "reference-payment-1",
                "reference-payment-2",
                "reference-withdrawal",
                "reference-later-payouts",
            ],
        ),
    ] {
        let result = read(&run.join(file))?;
        if result["nativeFull"] != true {
            return Err("host preflight is not native acceptance".into());
        }
        let records = result["records"].as_array().ok_or("records")?;
        if records.len() != names.len() + 1 {
            return Err("replay record count".into());
        }
        let fund = read_transaction(&records[0]["transaction"])?;
        let source: UtxoEntry = from_hex(&records[0]["sourceEntryBincodeHex"])?;
        native::validate(&fund, &source)?;
        let mut prev = fund.clone();
        let mut state: app::State = bincode::deserialize(&fund.payload)?;
        if fund.outputs[0].script_public_key != policy.spk(state.root()) {
            return Err("initial binding".into());
        }
        let vk = ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(
            state.wallet_vk.as_slice(),
        )?;
        let mut fees = records[0]["report"]["feeSompi"].as_u64().ok_or("fee")?;
        for (record, name) in records[1..].iter().zip(names) {
            let tx = read_transaction(&record["transaction"])?;
            let input: app::Input = from_hex(&record["inputBincodeHex"])?;
            if tx.inputs[0].previous_outpoint != TransactionOutpoint::new(prev.id(), 0)
                || input.state.root() != state.root()
                || tx.payload != input.packet.bytes()
            {
                return Err("exact current parent/state/payload".into());
            }
            let entry = UtxoEntry::new(
                prev.outputs[0].value,
                prev.outputs[0].script_public_key.clone(),
                0,
                false,
                None,
            );
            if bincode::serialize(&input.effects)?
                != bincode::serialize(&native::effects(&tx, entry.amount))?
            {
                return Err("native effects".into());
            }
            for op in &input.packet.operations {
                if !proof::verify(&vk, op) {
                    return Err("wallet independent pairing".into());
                }
            }
            if input.packet.mode == app::JOINT
                && bincode::serialize(&input.packet.operations)? != bincode::serialize(&approved)?
            {
                return Err("original approvals changed".into());
            }
            let output = app::execute(&input)?;
            let dir = run.join(name);
            if fs::read(dir.join("input.bin"))? != bincode::serialize(&input)? {
                return Err("receipt exact input".into());
            }
            let receipt: risc0_zkvm::Receipt =
                bincode::deserialize(&fs::read(dir.join("candidate-compressed.bin"))?)?;
            prover::verify(&receipt, image, &output.journal)?;
            let mut expected = tx.clone();
            expected.inputs[0].signature_script = policy.witness(
                input.state.root(),
                output.journal[32..64].try_into()?,
                &prover::native_proof(&receipt)?,
            );
            expected.finalize();
            if bincode::serialize(&expected)? != bincode::serialize(&tx)? {
                return Err("native receipt witness mismatch".into());
            }
            let report = native::validate(&tx, &entry)?;
            fees = fees
                .checked_add(report["feeSompi"].as_u64().ok_or("fee")?)
                .ok_or("fees")?;
            state = output.state;
            prev = tx;
        }
        if state.ledger.reserve != 0 || state.ledger.private_liability != 0 {
            return Err("terminal reserve/liability".into());
        }
        totals.push(json!({"file":file,"nativeFeesSompi":fees,"remainingPrincipal":state.ledger.reserve,"remainingLiability":state.ledger.private_liability}));
    }
    let main = read(&run.join("MAIN.json"))?;
    let mut payout_outputs = HashMap::new();
    for record in main["records"].as_array().ok_or("records")? {
        let tx = read_transaction(&record["transaction"])?;
        for (i, o) in tx.outputs.iter().enumerate() {
            payout_outputs.insert(TransactionOutpoint::new(tx.id(), i as u32), o.clone());
        }
    }
    let mut spent = std::collections::HashSet::new();
    for spend in main["restoredPayoutSpends"].as_array().ok_or("spends")? {
        let tx = read_transaction(&spend["transaction"])?;
        let entry: UtxoEntry = from_hex(&spend["entryBincodeHex"])?;
        let point = tx.inputs[0].previous_outpoint;
        let actual = payout_outputs
            .get(&point)
            .ok_or("payout spend lacks actual ancestor")?;
        if !spent.insert(point)
            || entry.amount != actual.value
            || entry.script_public_key != actual.script_public_key
        {
            return Err("payout spend actual unspent entry".into());
        }
        native::validate(&tx, &entry)?;
    }
    if spent.len() != 8 {
        return Err("restored payout count".into());
    }
    println!(
        "{}",
        json!({"independentPublicReplay":true,"totals":totals,"restoredPayoutSpends":8,"privateBackupsRead":false,"chainAccepted":false})
    );
    Ok(())
}

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

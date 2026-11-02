use kpi_private_note_wallet::{
    circuit::WalletCircuit,
    ledger::Ledger,
    protocol::{hash, Delivery, Note, Operation, Statement, Tree, CREDIT, EXIT, TRANSFER},
    wallet::{Engine, Verifier, Wallet},
    Result,
};
use rand::{rngs::OsRng, seq::SliceRandom, Rng, RngCore};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

const SELECTION_V1: &str = "0165ce9cd097a74e7290b52469535aff0d30a9e82684a6296b2f0435a929bb4c";
const SELECTION_V2: &str = "87075c3df54302a2e3d97042938186ab3be49f4e4369a31a5377eef9ab361c5e";

#[derive(Clone, Copy)]
struct TrialPlan {
    id: &'static str,
    deposits: [u64; 2],
    payment: u64,
}

const PLANS: [TrialPlan; 3] = [
    TrialPlan {
        id: "trial-00",
        deposits: [900_000_000, 700_000_000],
        payment: 300_000_000,
    },
    TrialPlan {
        id: "trial-01",
        deposits: [850_000_000, 650_000_000],
        payment: 250_000_000,
    },
    TrialPlan {
        id: "trial-02",
        deposits: [1_000_000_000, 800_000_000],
        payment: 350_000_000,
    },
];

fn ensure(condition: bool, label: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(label.into())
    }
}

fn write_json(path: &Path, value: &impl Serialize, mode: u32) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    fs::write(path, bytes).map_err(|e| e.to_string())?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())
}

fn random_hash() -> [u8; 32] {
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    hash(&raw)
}

fn sample_circuit() -> Result<WalletCircuit> {
    let sender = Wallet::new();
    let recipient = Wallet::new();
    let input = sender.note(10);
    let mut tree = Tree::default();
    tree.append(input.commitment())?;
    let (siblings, directions) = tree.path(0)?;
    let outputs = [recipient.note(4), sender.note(6)];
    let deliveries = [outputs[0].deliver()?, outputs[1].deliver()?];
    let mut statement = Statement::new(TRANSFER, [0; 32], tree.root());
    statement.nullifier = sender.nf(&input);
    for index in 0..2 {
        statement.outputs[index] = deliveries[index].commitment;
        statement.delivery[index] = hash(&deliveries[index].ciphertext);
    }
    Ok(WalletCircuit {
        statement,
        witness: sender.witness(input, outputs, siblings, directions),
    })
}

fn capture_service(
    script: &Path,
    output: &Path,
    trial: &str,
    ordinal: usize,
    operation: &Operation,
) -> Result<()> {
    let mut token = [0u8; 16];
    OsRng.fill_bytes(&mut token);
    let request = json!({
        "schema": "wallet-local-public-operation-request-v1",
        "trial": trial,
        "ordinal": ordinal,
        "relayToken": hex::encode(token),
        "operation": operation,
    });
    let raw = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    let mut child = Command::new("python3")
        .arg(script)
        .arg(output)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .ok_or("capture stdin")?
        .write_all(&raw)
        .map_err(|e| e.to_string())?;
    let result = child.wait_with_output().map_err(|e| e.to_string())?;
    if !result.status.success() {
        return Err(format!(
            "service capture failed: {}",
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn accept_operation(
    public_trial: &Path,
    capture_script: &Path,
    started: &Instant,
    trial: &str,
    ordinal: usize,
    label: &str,
    proof_seconds: f64,
    ledger: &mut Ledger,
    verifier: &Verifier,
    operation: &Operation,
) -> Result<Value> {
    let capture_name = format!("capture-{ordinal:02}.json");
    capture_service(
        capture_script,
        &public_trial.join(&capture_name),
        trial,
        ordinal,
        operation,
    )?;
    let before = ledger.state_hash();
    let transition = ledger.apply(verifier, operation)?;
    let after = ledger.state_hash();
    let event = json!({
        "schema": "wallet-local-accepted-operation-v1",
        "trial": trial,
        "ordinal": ordinal,
        "label": label,
        "localMonotonicNs": started.elapsed().as_nanos().to_string(),
        "proofSeconds": proof_seconds,
        "capture": capture_name,
        "wireBytes": operation.wire_bytes()?.len(),
        "wireSha256": hex::encode(hash(&operation.wire_bytes()?)),
        "stateBefore": hex::encode(before),
        "stateAfter": hex::encode(after),
        "transition": hex::encode(transition),
        "operation": operation,
        "accepted": true,
    });
    write_json(
        &public_trial.join(format!("event-{ordinal:02}.json")),
        &event,
        0o644,
    )?;
    Ok(event)
}

fn relations() -> Vec<(usize, usize)> {
    let mut rng = OsRng;
    let first = if rng.gen_bool(0.5) { (0, 2) } else { (1, 2) };
    let mut remaining = vec![(0, 2), (0, 3), (1, 2), (1, 3)];
    remaining.retain(|pair| *pair != first);
    remaining.shuffle(&mut rng);
    vec![first, remaining[0], remaining[1]]
}

fn run_trial(
    plan: TrialPlan,
    relation: (usize, usize),
    engine: &Engine,
    verifier: &Verifier,
    public_root: &Path,
    private_root: &Path,
    capture_script: &Path,
    started: &Instant,
) -> Result<(Value, Value)> {
    let public_trial = public_root.join(plan.id);
    let private_trial = private_root.join(plan.id);
    fs::create_dir(&public_trial).map_err(|e| e.to_string())?;
    fs::create_dir(&private_trial).map_err(|e| e.to_string())?;
    fs::set_permissions(&private_trial, fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;

    let wallets = [Wallet::new(), Wallet::new(), Wallet::new(), Wallet::new()];
    for (index, wallet) in wallets.iter().enumerate() {
        fs::write(
            private_trial.join(format!("wallet-{index}.backup")),
            wallet.local_backup(),
        )
        .map_err(|e| e.to_string())?;
        fs::set_permissions(
            private_trial.join(format!("wallet-{index}.backup")),
            fs::Permissions::from_mode(0o600),
        )
        .map_err(|e| e.to_string())?;
    }

    let mut ledger = Ledger::new(engine.id());
    let deposit_ids = [random_hash(), random_hash()];
    let credit_notes = [wallets[0].note(plan.deposits[0]), wallets[1].note(plan.deposits[1])];
    let mut public_deposits = vec![];
    for index in 0..2 {
        ledger.register_authenticated_fixture_deposit(
            deposit_ids[index],
            plan.deposits[index],
            wallets[index].address.owner,
        )?;
        public_deposits.push(json!({
            "depositId": hex::encode(deposit_ids[index]),
            "owner": hex::encode(wallets[index].address.owner),
            "amountSompi": plan.deposits[index],
        }));
    }

    let mut events = vec![];
    for index in 0..2 {
        let mut statement = Statement::new(CREDIT, engine.id(), ledger.tree.root());
        statement.deposit = deposit_ids[index];
        statement.deposit_owner = wallets[index].address.owner;
        statement.deposit_value = plan.deposits[index];
        let delivery = credit_notes[index].deliver()?;
        let proof_start = Instant::now();
        let operation = engine.prove(
            statement,
            wallets[index].witness(
                wallets[index].authority_note(),
                [credit_notes[index].clone(), Note::dummy()],
                [[0; 32]; 2],
                [false; 2],
            ),
            [delivery, Delivery::absent()],
        )?;
        events.push(accept_operation(
            &public_trial,
            capture_script,
            started,
            plan.id,
            index,
            "credit",
            proof_start.elapsed().as_secs_f64(),
            &mut ledger,
            verifier,
            &operation,
        )?);
    }

    let sender = relation.0;
    let recipient = relation.1;
    let (siblings, directions) = ledger.tree.path(sender)?;
    let payment_note = wallets[recipient].note(plan.payment);
    let change_note = wallets[sender].note(plan.deposits[sender] - plan.payment);
    let payment_index = if OsRng.gen_bool(0.5) { 0 } else { 1 };
    let outputs = if payment_index == 0 {
        [payment_note.clone(), change_note.clone()]
    } else {
        [change_note.clone(), payment_note.clone()]
    };
    let deliveries = [outputs[0].deliver()?, outputs[1].deliver()?];
    let mut transfer_statement = Statement::new(TRANSFER, engine.id(), ledger.tree.root());
    transfer_statement.nullifier = wallets[sender].nf(&credit_notes[sender]);
    let proof_start = Instant::now();
    let transfer = engine.prove(
        transfer_statement,
        wallets[sender].witness(
            credit_notes[sender].clone(),
            outputs,
            siblings,
            directions,
        ),
        deliveries,
    )?;
    events.push(accept_operation(
        &public_trial,
        capture_script,
        started,
        plan.id,
        2,
        "transfer",
        proof_start.elapsed().as_secs_f64(),
        &mut ledger,
        verifier,
        &transfer,
    )?);
    let state_after_transfer = ledger.state_hash();
    ensure(
        ledger.apply(verifier, &transfer).is_err() && ledger.state_hash() == state_after_transfer,
        "accepted transfer replay rejection",
    )?;

    let found = wallets[recipient].discover(&ledger.deliveries, &ledger.tree, &ledger.nullifiers);
    ensure(
        found.len() == 1 && found[0].0.value == plan.payment,
        "recipient payment discovery",
    )?;
    let (exit_note, exit_index) = found[0].clone();
    let (exit_siblings, exit_directions) = ledger.tree.path(exit_index)?;
    let exit_destination = random_hash();
    let mut exit_statement = Statement::new(EXIT, engine.id(), ledger.tree.root());
    exit_statement.nullifier = wallets[recipient].nf(&exit_note);
    exit_statement.exit_destination = exit_destination;
    exit_statement.exit_value = plan.payment;
    let proof_start = Instant::now();
    let exit = engine.prove(
        exit_statement,
        wallets[recipient].witness(
            exit_note,
            [Note::dummy(), Note::dummy()],
            exit_siblings,
            exit_directions,
        ),
        [Delivery::absent(), Delivery::absent()],
    )?;
    events.push(accept_operation(
        &public_trial,
        capture_script,
        started,
        plan.id,
        3,
        "exit",
        proof_start.elapsed().as_secs_f64(),
        &mut ledger,
        verifier,
        &exit,
    )?);
    let before_wrong_payout = ledger.state_hash();
    ensure(
        ledger
            .confirm_authenticated_fixture_payout(
                exit.statement.id(),
                plan.payment,
                random_hash(),
                random_hash(),
            )
            .is_err()
            && ledger.state_hash() == before_wrong_payout,
        "diverted payout rejection",
    )?;
    let payout_output = random_hash();
    ledger.confirm_authenticated_fixture_payout(
        exit.statement.id(),
        plan.payment,
        exit_destination,
        payout_output,
    )?;
    ensure(
        ledger.reserve == plan.deposits[0] + plan.deposits[1] - plan.payment
            && ledger.private_liability == ledger.reserve,
        "post-payout value conservation",
    )?;
    let sender_notes = wallets[sender].discover(&ledger.deliveries, &ledger.tree, &ledger.nullifiers);
    ensure(
        sender_notes.len() == 1
            && sender_notes[0].0.value == plan.deposits[sender] - plan.payment,
        "sender change recovery",
    )?;
    let other_sender = 1 - sender;
    let other_notes = wallets[other_sender].discover(
        &ledger.deliveries,
        &ledger.tree,
        &ledger.nullifiers,
    );
    ensure(
        other_notes.len() == 1 && other_notes[0].0.value == plan.deposits[other_sender],
        "unspent depositor recovery",
    )?;
    ensure(
        wallets[recipient]
            .discover(&ledger.deliveries, &ledger.tree, &ledger.nullifiers)
            .is_empty(),
        "exited recipient note excluded",
    )?;

    let public_summary = json!({
        "schema": "wallet-local-public-trial-v1",
        "experiment": "wallet-local-practical-privacy-v2",
        "selectionSha256": [SELECTION_V1, SELECTION_V2],
        "trial": plan.id,
        "deposits": public_deposits,
        "events": events.iter().map(|event| event["ordinal"].clone()).collect::<Vec<_>>(),
        "payout": {
            "amountSompi": plan.payment,
            "destination": hex::encode(exit_destination),
            "nativeOutput": hex::encode(payout_output),
        },
        "final": {
            "stateHash": hex::encode(ledger.state_hash()),
            "reserveSompi": ledger.reserve,
            "privateLiabilitySompi": ledger.private_liability,
            "treeLeaves": ledger.tree.leaves.len(),
            "nullifiers": ledger.nullifiers.len(),
        },
        "controls": {
            "transferReplayRejectedAtomically": true,
            "divertedPayoutRejectedAtomically": true,
            "recipientRecoveredPayment": true,
            "senderRecoveredChange": true,
            "otherDepositorRecoveredUnspentNote": true,
            "valueConservation": true,
        },
    });
    write_json(&public_trial.join("trial.json"), &public_summary, 0o644)?;

    let labels = ["A", "B", "C", "D"];
    let truth = json!({
        "schema": "wallet-local-private-truth-v1",
        "trial": plan.id,
        "sender": labels[sender],
        "recipient": labels[recipient],
        "paymentSompi": plan.payment,
        "historicalNote": hex::encode(credit_notes[sender].commitment()),
        "paymentOutputIndex": payment_index,
        "changeOutputIndex": 1 - payment_index,
        "exitDestination": hex::encode(exit_destination),
        "transferNullifier": hex::encode(transfer.statement.nullifier),
        "exitNullifier": hex::encode(exit.statement.nullifier),
    });
    write_json(&private_trial.join("truth.json"), &truth, 0o600)?;

    let aux = json!({
        "trial": plan.id,
        "identityUniverse": labels,
        "depositOwnerIdentity": {
            hex::encode(wallets[0].address.owner): "A",
            hex::encode(wallets[1].address.owner): "B",
        },
        "contactEdges": [["A","C"],["A","D"],["B","C"],["B","D"]],
        "knownExitDestinationIdentity": if plan.id == "trial-00" {
            json!({hex::encode(exit_destination): "C"})
        } else {
            json!({})
        },
        "relayTokensMappedToIdentity": false,
    });
    Ok((aux, truth))
}

fn real_main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        return Err("usage: wallet-local-privacy-runner PUBLIC_DIR PRIVATE_DIR SERVICE_CAPTURE.py".into());
    }
    let public_root = PathBuf::from(&args[1]);
    let private_root = PathBuf::from(&args[2]);
    let capture_script = PathBuf::from(&args[3]);
    ensure(!public_root.exists(), "public output already exists")?;
    ensure(!private_root.exists(), "private output already exists")?;
    fs::create_dir_all(&public_root).map_err(|e| e.to_string())?;
    fs::create_dir_all(&private_root).map_err(|e| e.to_string())?;
    fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let started = Instant::now();
    let setup_started = Instant::now();
    let engine = Engine::setup(sample_circuit()?)?;
    let setup_seconds = setup_started.elapsed().as_secs_f64();
    let verifier = engine.verifier();
    let parameter_bytes = engine.public_parameters()?;
    let parameter_receipt = json!({
        "schema": "wallet-local-parameter-receipt-v1",
        "verifier": hex::encode(engine.id()),
        "verifyingKeyBytes": engine.vk_bytes().len(),
        "provingParameterBytes": parameter_bytes.len(),
        "provingParameterSha256": hex::encode(hash(&parameter_bytes)),
        "setupSeconds": setup_seconds,
    });
    drop(parameter_bytes);
    write_json(&public_root.join("parameters.json"), &parameter_receipt, 0o644)?;
    fs::write(public_root.join("verifying-key.bin"), engine.vk_bytes())
        .map_err(|e| e.to_string())?;

    let selected_relations = relations();
    let mut auxiliary = vec![];
    let mut truth_index = vec![];
    for (plan, relation) in PLANS.into_iter().zip(selected_relations) {
        let (aux, truth) = run_trial(
            plan,
            relation,
            &engine,
            &verifier,
            &public_root,
            &private_root,
            &capture_script,
            &started,
        )?;
        auxiliary.push(aux);
        truth_index.push(truth);
    }
    write_json(
        &public_root.join("auxiliary.json"),
        &json!({
            "schema": "wallet-local-simulated-auxiliary-v1",
            "classification": "simulated auxiliary knowledge, not observed network identity",
            "trials": auxiliary,
        }),
        0o644,
    )?;
    write_json(
        &private_root.join("truth-index.json"),
        &json!({
            "schema": "wallet-local-private-truth-index-v1",
            "trials": truth_index,
        }),
        0o600,
    )?;
    write_json(
        &public_root.join("run-receipt.json"),
        &json!({
            "schema": "wallet-local-run-receipt-v1",
            "experiment": "wallet-local-practical-privacy-v2",
            "selectionSha256": [SELECTION_V1, SELECTION_V2],
            "trialCount": 3,
            "acceptedOperationCount": 12,
            "serviceCaptureCount": 12,
            "elapsedSeconds": started.elapsed().as_secs_f64(),
            "proofSystem": "fresh one-party experimental Groth16 setup",
            "network": false,
            "funding": false,
            "sameHostOnly": true,
        }),
        0o644,
    )?;
    println!(
        "{}",
        json!({
            "public": public_root,
            "private": private_root,
            "elapsedSeconds": started.elapsed().as_secs_f64(),
            "trials": 3,
            "operations": 12,
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = real_main() {
        eprintln!("wallet-local-privacy-runner: {error}");
        std::process::exit(1);
    }
}

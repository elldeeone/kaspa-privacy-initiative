use kpi_private_note_wallet::{
    circuit::WalletCircuit,
    ledger::Ledger,
    protocol::{
        domain, hash, Delivery, Note, Operation, Statement, Tree, CREDIT, DEPTH, EXIT, TRANSFER,
    },
    wallet::{Engine, Verifier, Wallet},
    Result,
};
use rand::{rngs::OsRng, seq::SliceRandom, Rng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

const SELECTION_V1: &str = "27c148987324615e544380750ee0d80f11195eed34790d33f4ee776249df2e9c";
const SELECTION_V2: &str = "ca44444a19837a0f5abd7d65d0bbd375ae7888e34120e233d0d089f321a6d1b2";
const WORKLOAD_SHA: &str = "1259a46daf010dc8724cc6b390f0b0578faf34c6ccc073a0cabbd1027e501984";
const EXPECTED_DOMAIN_TEXT: &[u8] =
    b"KPI/LOCAL-NO-FUNDING/native-KAS/private-note-experiment-depth4-v1";
const LABELS: [&str; 6] = ["A", "B", "C", "D", "E", "F"];

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairWorkload {
    #[serde(rename = "depositsSompi")]
    deposits: [u64; 2],
    #[serde(rename = "p1Sompi")]
    p1: u64,
    #[serde(rename = "p2Sompi")]
    p2: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Workload {
    schema: String,
    experiment: String,
    pairs: BTreeMap<String, PairWorkload>,
}

#[derive(Clone, Copy)]
struct Relation {
    sender: usize,
    first_recipient: usize,
    second_recipient: usize,
}

#[derive(Clone, Copy, PartialEq)]
enum Arm {
    Continued,
    Control,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::Continued => "continued",
            Self::Control => "control",
        }
    }
}

#[derive(Clone)]
struct ExitRole {
    role: &'static str,
    owner: usize,
    value: u64,
}

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
    run: &str,
    ordinal: usize,
    operation: &Operation,
) -> Result<()> {
    let mut token = [0u8; 16];
    OsRng.fill_bytes(&mut token);
    let request = json!({
        "schema": "wallet-local-public-operation-request-v1",
        "trial": run,
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
    public_arm: &Path,
    capture_script: &Path,
    started: &Instant,
    run: &str,
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
        &public_arm.join(&capture_name),
        run,
        ordinal,
        operation,
    )?;
    let before = ledger.state_hash();
    let transition = ledger.apply(verifier, operation)?;
    let after = ledger.state_hash();
    let wire = operation.wire_bytes()?;
    let event = json!({
        "schema": "wallet-local-private-spend-accepted-operation-v1",
        "run": run,
        "ordinal": ordinal,
        "label": label,
        "localMonotonicNs": started.elapsed().as_nanos().to_string(),
        "proofSeconds": proof_seconds,
        "capture": capture_name,
        "wireBytes": wire.len(),
        "wireSha256": hex::encode(hash(&wire)),
        "stateBefore": hex::encode(before),
        "stateAfter": hex::encode(after),
        "transition": hex::encode(transition),
        "operation": operation,
        "accepted": true,
    });
    write_json(
        &public_arm.join(format!("event-{ordinal:02}.json")),
        &event,
        0o644,
    )?;
    Ok(event)
}

fn reject_mutated(
    ledger: &mut Ledger,
    verifier: &Verifier,
    operation: &Operation,
    mode: &str,
) -> Result<()> {
    let mut changed = operation.clone();
    match mode {
        "domain" => changed.statement.domain = hash(b"wrong depth-two profile domain"),
        "root" => changed.statement.anchor[0] ^= 1,
        _ => return Err("mutation mode".into()),
    }
    let before = ledger.state_hash();
    ensure(
        ledger.apply(verifier, &changed).is_err() && ledger.state_hash() == before,
        &format!("atomic wrong-{mode} rejection"),
    )
}

fn make_transfer(
    engine: &Engine,
    sender: &Wallet,
    input: Note,
    input_index: usize,
    payment: Note,
    change: Note,
    ledger: &Ledger,
) -> Result<(Operation, usize, [Note; 2])> {
    let payment_index = if OsRng.gen_bool(0.5) { 0 } else { 1 };
    let outputs = if payment_index == 0 {
        [payment, change]
    } else {
        [change, payment]
    };
    let deliveries = [outputs[0].deliver()?, outputs[1].deliver()?];
    let (siblings, directions) = ledger.tree.path(input_index)?;
    let mut statement = Statement::new(TRANSFER, engine.id(), ledger.tree.root());
    statement.nullifier = sender.nf(&input);
    let operation = engine.prove(
        statement,
        sender.witness(input, outputs.clone(), siblings, directions),
        deliveries,
    )?;
    Ok((operation, payment_index, outputs))
}

#[allow(clippy::too_many_arguments)]
fn exit_note(
    engine: &Engine,
    verifier: &Verifier,
    ledger: &mut Ledger,
    backup: &[u8; 64],
    expected_value: u64,
    public_arm: &Path,
    capture_script: &Path,
    started: &Instant,
    run: &str,
    ordinal: usize,
    label: &str,
) -> Result<(Value, Value)> {
    let wallet = Wallet::restore_local(backup);
    let found = wallet.discover(&ledger.deliveries, &ledger.tree, &ledger.nullifiers);
    let matching = found
        .into_iter()
        .filter(|(note, _)| note.value == expected_value)
        .collect::<Vec<_>>();
    ensure(matching.len() == 1, "restored wallet exit discovery")?;
    let (note, index) = matching[0].clone();
    let (siblings, directions) = ledger.tree.path(index)?;
    let destination = random_hash();
    let mut statement = Statement::new(EXIT, engine.id(), ledger.tree.root());
    statement.nullifier = wallet.nf(&note);
    statement.exit_destination = destination;
    statement.exit_value = note.value;
    let proof_start = Instant::now();
    let operation = engine.prove(
        statement,
        wallet.witness(
            note,
            [Note::dummy(), Note::dummy()],
            siblings,
            directions,
        ),
        [Delivery::absent(), Delivery::absent()],
    )?;
    let event = accept_operation(
        public_arm,
        capture_script,
        started,
        run,
        ordinal,
        label,
        proof_start.elapsed().as_secs_f64(),
        ledger,
        verifier,
        &operation,
    )?;
    let before_wrong = ledger.state_hash();
    ensure(
        ledger
            .confirm_authenticated_fixture_payout(
                operation.statement.id(),
                expected_value,
                random_hash(),
                random_hash(),
            )
            .is_err()
            && ledger.state_hash() == before_wrong,
        "diverted payout rejection",
    )?;
    let payout_output = random_hash();
    ledger.confirm_authenticated_fixture_payout(
        operation.statement.id(),
        expected_value,
        destination,
        payout_output,
    )?;
    Ok((
        event,
        json!({
            "ordinal": ordinal,
            "operationId": hex::encode(operation.statement.id()),
            "destination": hex::encode(destination),
            "amountSompi": expected_value,
            "nativeOutput": hex::encode(payout_output),
        }),
    ))
}

fn relation_pair() -> [Relation; 2] {
    let mut rng = OsRng;
    let first = Relation {
        sender: if rng.gen_bool(0.5) { 0 } else { 1 },
        first_recipient: if rng.gen_bool(0.5) { 2 } else { 3 },
        second_recipient: if rng.gen_bool(0.5) { 4 } else { 5 },
    };
    [
        first,
        Relation {
            sender: 1 - first.sender,
            first_recipient: 5 - first.first_recipient,
            second_recipient: 9 - first.second_recipient,
        },
    ]
}

#[allow(clippy::too_many_arguments)]
fn run_arm(
    pair: &str,
    arm: Arm,
    workload: &PairWorkload,
    relation: Relation,
    engine: &Engine,
    verifier: &Verifier,
    public_root: &Path,
    private_root: &Path,
    capture_script: &Path,
    started: &Instant,
) -> Result<(Value, Value)> {
    let run = format!("{pair}/{}", arm.name());
    let public_arm = public_root.join(pair).join(arm.name());
    let private_arm = private_root.join(pair).join(arm.name());
    fs::create_dir_all(&public_arm).map_err(|e| e.to_string())?;
    fs::create_dir_all(&private_arm).map_err(|e| e.to_string())?;
    fs::set_permissions(&private_arm, fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;

    let wallets = (0..6).map(|_| Wallet::new()).collect::<Vec<_>>();
    let backups = wallets.iter().map(Wallet::local_backup).collect::<Vec<_>>();
    for (index, backup) in backups.iter().enumerate() {
        let path = private_arm.join(format!("wallet-{index}.backup"));
        fs::write(&path, backup).map_err(|e| e.to_string())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }

    let mut ledger = Ledger::new(engine.id());
    let deposit_ids = [random_hash(), random_hash()];
    let credit_notes = [
        wallets[0].note(workload.deposits[0]),
        wallets[1].note(workload.deposits[1]),
    ];
    let mut public_deposits = vec![];
    for index in 0..2 {
        ledger.register_authenticated_fixture_deposit(
            deposit_ids[index],
            workload.deposits[index],
            wallets[index].address.owner,
        )?;
        public_deposits.push(json!({
            "depositId": hex::encode(deposit_ids[index]),
            "owner": hex::encode(wallets[index].address.owner),
            "amountSompi": workload.deposits[index],
        }));
    }

    let mut events = vec![];
    let mut ordinal = 0usize;
    for index in 0..2 {
        let mut statement = Statement::new(CREDIT, engine.id(), ledger.tree.root());
        statement.deposit = deposit_ids[index];
        statement.deposit_owner = wallets[index].address.owner;
        statement.deposit_value = workload.deposits[index];
        let delivery = credit_notes[index].deliver()?;
        let proof_start = Instant::now();
        let operation = engine.prove(
            statement,
            wallets[index].witness(
                wallets[index].authority_note(),
                [credit_notes[index].clone(), Note::dummy()],
                [[0; 32]; DEPTH],
                [false; DEPTH],
            ),
            [delivery, Delivery::absent()],
        )?;
        events.push(accept_operation(
            &public_arm,
            capture_script,
            started,
            &run,
            ordinal,
            "credit",
            proof_start.elapsed().as_secs_f64(),
            &mut ledger,
            verifier,
            &operation,
        )?);
        ordinal += 1;
    }

    let sender = relation.sender;
    let first_recipient = relation.first_recipient;
    let second_recipient = relation.second_recipient;
    let first_payment = wallets[first_recipient].note(workload.p1);
    let first_change = wallets[sender].note(workload.deposits[sender] - workload.p1);
    let proof_start = Instant::now();
    let (transfer1, first_payment_index, transfer1_outputs) = make_transfer(
        engine,
        &wallets[sender],
        credit_notes[sender].clone(),
        sender,
        first_payment,
        first_change,
        &ledger,
    )?;
    let transfer1_proof_seconds = proof_start.elapsed().as_secs_f64();
    reject_mutated(&mut ledger, verifier, &transfer1, "domain")?;
    reject_mutated(&mut ledger, verifier, &transfer1, "root")?;
    events.push(accept_operation(
        &public_arm,
        capture_script,
        started,
        &run,
        ordinal,
        "transfer-1",
        transfer1_proof_seconds,
        &mut ledger,
        verifier,
        &transfer1,
    )?);
    ordinal += 1;
    let after_transfer1 = ledger.state_hash();
    ensure(
        ledger.apply(verifier, &transfer1).is_err() && ledger.state_hash() == after_transfer1,
        "transfer-1 replay rejection",
    )?;

    let restored_first_recipient = Wallet::restore_local(&backups[first_recipient]);
    let received = restored_first_recipient.discover(
        &ledger.deliveries,
        &ledger.tree,
        &ledger.nullifiers,
    );
    ensure(
        received.len() == 1 && received[0].0.value == workload.p1,
        "backup-based first payment recovery",
    )?;
    let first_received_note = received[0].0.clone();
    let first_received_index = received[0].1;

    let mut transfer2_truth = Value::Null;
    let mut exit_truth = vec![];
    let mut payouts = vec![];
    let pre_checkpoint_event_count;
    let mut remaining;
    if arm == Arm::Continued {
        let second_payment = wallets[second_recipient].note(workload.p2);
        let second_change = wallets[first_recipient].note(workload.p1 - workload.p2);
        let proof_start = Instant::now();
        let (transfer2, second_payment_index, _transfer2_outputs) = make_transfer(
            engine,
            &restored_first_recipient,
            first_received_note,
            first_received_index,
            second_payment,
            second_change,
            &ledger,
        )?;
        let transfer2_proof_seconds = proof_start.elapsed().as_secs_f64();
        reject_mutated(&mut ledger, verifier, &transfer2, "root")?;
        events.push(accept_operation(
            &public_arm,
            capture_script,
            started,
            &run,
            ordinal,
            "transfer-2",
            transfer2_proof_seconds,
            &mut ledger,
            verifier,
            &transfer2,
        )?);
        ordinal += 1;
        let after_transfer2 = ledger.state_hash();
        ensure(
            ledger.apply(verifier, &transfer2).is_err()
                && ledger.state_hash() == after_transfer2,
            "transfer-2 replay rejection",
        )?;
        transfer2_truth = json!({
            "sender": LABELS[first_recipient],
            "recipient": LABELS[second_recipient],
            "amountSompi": workload.p2,
            "historicalOutput": hex::encode(transfer1_outputs[first_payment_index].commitment()),
            "paymentOutputIndex": second_payment_index,
            "changeOutputIndex": 1 - second_payment_index,
        });
        pre_checkpoint_event_count = ordinal;
        remaining = vec![
            ExitRole {
                role: "untouched-credit",
                owner: 1 - sender,
                value: workload.deposits[1 - sender],
            },
            ExitRole {
                role: "first-change",
                owner: sender,
                value: workload.deposits[sender] - workload.p1,
            },
            ExitRole {
                role: "second-change",
                owner: first_recipient,
                value: workload.p1 - workload.p2,
            },
            ExitRole {
                role: "second-payment",
                owner: second_recipient,
                value: workload.p2,
            },
        ];
    } else {
        let (event, payout) = exit_note(
            engine,
            verifier,
            &mut ledger,
            &backups[first_recipient],
            workload.p1,
            &public_arm,
            capture_script,
            started,
            &run,
            ordinal,
            "exit-immediate",
        )?;
        events.push(event);
        exit_truth.push(json!({
            "role": "first-payment",
            "owner": LABELS[first_recipient],
            "valueSompi": workload.p1,
            "payout": payout,
        }));
        payouts.push(exit_truth.last().unwrap()["payout"].clone());
        ordinal += 1;
        pre_checkpoint_event_count = ordinal;
        remaining = vec![
            ExitRole {
                role: "untouched-credit",
                owner: 1 - sender,
                value: workload.deposits[1 - sender],
            },
            ExitRole {
                role: "first-change",
                owner: sender,
                value: workload.deposits[sender] - workload.p1,
            },
        ];
    }

    write_json(
        &public_arm.join("checkpoint-pre-cashout.json"),
        &json!({
            "schema": "wallet-local-private-spend-checkpoint-v1",
            "run": run,
            "eventCount": pre_checkpoint_event_count,
            "stateHash": hex::encode(ledger.state_hash()),
            "reserveSompi": ledger.reserve,
            "privateLiabilitySompi": ledger.private_liability,
            "unpaidExitCount": ledger.exits.values().filter(|exit| !exit.paid).count(),
        }),
        0o644,
    )?;

    remaining.shuffle(&mut OsRng);
    for role in &remaining {
        let (event, payout) = exit_note(
            engine,
            verifier,
            &mut ledger,
            &backups[role.owner],
            role.value,
            &public_arm,
            capture_script,
            started,
            &run,
            ordinal,
            "exit-eventual",
        )?;
        events.push(event);
        exit_truth.push(json!({
            "role": role.role,
            "owner": LABELS[role.owner],
            "valueSompi": role.value,
            "payout": payout,
        }));
        payouts.push(exit_truth.last().unwrap()["payout"].clone());
        ordinal += 1;
    }

    ensure(
        ledger.reserve == 0 && ledger.private_liability == 0,
        "zero final reserve and liability",
    )?;
    for backup in &backups {
        let restored = Wallet::restore_local(backup);
        ensure(
            restored
                .discover(&ledger.deliveries, &ledger.tree, &ledger.nullifiers)
                .is_empty(),
            "all wallet claims exited",
        )?;
    }

    let summary = json!({
        "schema": "wallet-local-private-spend-public-arm-v1",
        "experiment": "wallet-local-private-spend-v2",
        "selectionSha256": [SELECTION_V1, SELECTION_V2],
        "privateWorkloadSha256": WORKLOAD_SHA,
        "pair": pair,
        "arm": arm.name(),
        "deposits": public_deposits,
        "preCashoutEventCount": pre_checkpoint_event_count,
        "eventOrdinals": events.iter().map(|event| event["ordinal"].clone()).collect::<Vec<_>>(),
        "payouts": payouts,
        "final": {
            "stateHash": hex::encode(ledger.state_hash()),
            "reserveSompi": ledger.reserve,
            "privateLiabilitySompi": ledger.private_liability,
            "treeLeaves": ledger.tree.leaves.len(),
            "nullifiers": ledger.nullifiers.len(),
            "paidExitCount": ledger.exits.values().filter(|exit| exit.paid).count(),
        },
        "controls": {
            "wrongDomainRejectedAtomically": true,
            "wrongRootRejectedAtomically": true,
            "acceptedTransfersReplayRejectedAtomically": true,
            "divertedPayoutsRejectedAtomically": true,
            "backupBasedReceivedNoteRecovery": true,
            "backupBasedExitAuthorityForEveryRemainingNote": true,
            "zeroFinalReserveAndLiability": true,
        },
    });
    write_json(&public_arm.join("arm.json"), &summary, 0o644)?;

    let truth = json!({
        "schema": "wallet-local-private-spend-truth-v1",
        "pair": pair,
        "arm": arm.name(),
        "firstPayment": {
            "sender": LABELS[sender],
            "recipient": LABELS[first_recipient],
            "amountSompi": workload.p1,
            "historicalCredit": hex::encode(credit_notes[sender].commitment()),
            "paymentOutputIndex": first_payment_index,
            "changeOutputIndex": 1 - first_payment_index,
        },
        "secondPayment": transfer2_truth,
        "exits": exit_truth,
    });
    write_json(&private_arm.join("truth.json"), &truth, 0o600)?;

    let mut known_exit = serde_json::Map::new();
    if pair == "pair-00" {
        for exit in truth["exits"].as_array().unwrap() {
            known_exit.insert(
                exit["payout"]["destination"].as_str().unwrap().to_owned(),
                exit["owner"].clone(),
            );
        }
    }
    let aux = json!({
        "run": run,
        "identityUniverse": LABELS,
        "depositOwnerIdentity": {
            hex::encode(wallets[0].address.owner): "A",
            hex::encode(wallets[1].address.owner): "B",
        },
        "contactEdges": [
            ["A","C"],["A","D"],["B","C"],["B","D"],
            ["C","E"],["C","F"],["D","E"],["D","F"]
        ],
        "knownExitDestinationIdentity": known_exit,
        "relayTokensMappedToIdentity": false,
    });
    Ok((aux, truth))
}

fn read_workload(path: &Path) -> Result<Workload> {
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    ensure(hex::encode(hash(&raw)) == WORKLOAD_SHA, "private workload SHA256")?;
    let workload: Workload = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    ensure(
        workload.schema == "wallet-local-private-spend-workload-v1"
            && workload.experiment == "wallet-local-private-spend-v2"
            && workload.pairs.len() == 2,
        "private workload identity",
    )?;
    for (pair, expected_deposits) in [
        ("pair-00", [900_000_000, 700_000_000]),
        ("pair-01", [850_000_000, 650_000_000]),
    ] {
        let item = workload.pairs.get(pair).ok_or("missing workload pair")?;
        ensure(item.deposits == expected_deposits, "workload deposits")?;
        ensure(
            item.p1 >= 200_000_000
                && item.p1 <= item.deposits[0].min(item.deposits[1]) - 100_000_000
                && item.p2 >= 50_000_000
                && item.p2 <= item.p1 - 50_000_000,
            "workload payment bounds",
        )?;
    }
    Ok(workload)
}

fn real_main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 5 {
        return Err("usage: wallet-local-private-spend-runner PUBLIC_DIR PRIVATE_DIR PRIVATE_WORKLOAD.json SERVICE_CAPTURE.py".into());
    }
    let public_root = PathBuf::from(&args[1]);
    let private_root = PathBuf::from(&args[2]);
    let workload_path = PathBuf::from(&args[3]);
    let capture_script = PathBuf::from(&args[4]);
    ensure(!public_root.exists(), "public output already exists")?;
    ensure(!private_root.exists(), "private output already exists")?;
    ensure(DEPTH == 4, "depth-four experiment profile")?;
    ensure(domain() == hash(EXPECTED_DOMAIN_TEXT), "depth-four domain")?;
    let workload = read_workload(&workload_path)?;
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
    write_json(
        &public_root.join("parameters.json"),
        &json!({
            "schema": "wallet-local-private-spend-parameter-receipt-v1",
            "depth": DEPTH,
            "capacity": 1usize << DEPTH,
            "domain": hex::encode(domain()),
            "verifier": hex::encode(engine.id()),
            "verifyingKeyBytes": engine.vk_bytes().len(),
            "provingParameterBytes": parameter_bytes.len(),
            "provingParameterSha256": hex::encode(hash(&parameter_bytes)),
            "setupSeconds": setup_seconds,
        }),
        0o644,
    )?;
    drop(parameter_bytes);
    fs::write(public_root.join("verifying-key.bin"), engine.vk_bytes())
        .map_err(|e| e.to_string())?;

    let relations = relation_pair();
    let mut auxiliary = vec![];
    let mut truth_index = vec![];
    for (pair_index, pair) in ["pair-00", "pair-01"].into_iter().enumerate() {
        let pair_workload = workload.pairs.get(pair).ok_or("workload pair")?;
        for arm in [Arm::Continued, Arm::Control] {
            let (aux, truth) = run_arm(
                pair,
                arm,
                pair_workload,
                relations[pair_index],
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
    }
    write_json(
        &public_root.join("auxiliary.json"),
        &json!({
            "schema": "wallet-local-private-spend-simulated-auxiliary-v1",
            "classification": "simulated legitimate contact and payout identity knowledge; no observed network identity",
            "runs": auxiliary,
        }),
        0o644,
    )?;
    write_json(
        &private_root.join("truth-index.json"),
        &json!({
            "schema": "wallet-local-private-spend-truth-index-v1",
            "privateWorkloadSha256": WORKLOAD_SHA,
            "runs": truth_index,
        }),
        0o600,
    )?;
    write_json(
        &public_root.join("run-receipt.json"),
        &json!({
            "schema": "wallet-local-private-spend-run-receipt-v1",
            "experiment": "wallet-local-private-spend-v2",
            "selectionSha256": [SELECTION_V1, SELECTION_V2],
            "privateWorkloadSha256": WORKLOAD_SHA,
            "pairCount": 2,
            "armCount": 4,
            "acceptedOperationCount": 28,
            "serviceCaptureCount": 28,
            "elapsedSeconds": started.elapsed().as_secs_f64(),
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
            "operations": 28,
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = real_main() {
        eprintln!("wallet-local-private-spend-runner: {error}");
        std::process::exit(1);
    }
}

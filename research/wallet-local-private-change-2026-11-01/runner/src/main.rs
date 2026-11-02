use kpi_private_note_wallet::{
    circuit::WalletCircuit,
    ledger::Ledger,
    protocol::{
        domain, hash, Delivery, Note, Operation, Statement, Tree, CREDIT, DEPTH, EXIT, TRANSFER,
    },
    wallet::{Engine, Verifier, Wallet},
    Result,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

const SELECTION_SHA: &str = "619a586a0f68ca7342834f59da0208a2f4a56331c4960f1bbc90aac422d79e7e";
const WORKLOAD_SHA: &str = "833ca8a1006ce5cf2a07282062a6fc092f28d2554bcbc3f3a7e4f11d6fb47536";
const DOMAIN_TEXT: &[u8] =
    b"KPI/LOCAL-NO-FUNDING/native-KAS/private-note-experiment-depth4-v1";
const LABELS: [&str; 8] = ["A", "B", "C", "D", "E", "F", "G", "H"];
const MIN_SPLIT: u64 = 10_000_000;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainWorkload {
    sender: String,
    #[serde(rename = "firstRecipient")]
    first_recipient: String,
    #[serde(rename = "secondRecipient")]
    second_recipient: String,
    #[serde(rename = "p1Sompi")]
    p1: u64,
    #[serde(rename = "p2Sompi")]
    p2: u64,
    #[serde(rename = "paymentOutputIndices")]
    payment_output_indices: [usize; 2],
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct ExitOrder {
    chain: usize,
    role: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArmWorkload {
    arm: String,
    chains: Vec<ChainWorkload>,
    #[serde(rename = "transferSchedule")]
    transfer_schedule: [usize; 4],
    #[serde(rename = "targetChain")]
    target_chain: usize,
    #[serde(rename = "finalExitOrder")]
    final_exit_order: Vec<ExitOrder>,
    #[serde(rename = "directExitOrder")]
    direct_exit_order: Option<Vec<String>>,
    #[serde(rename = "requestedWithdrawalSompi")]
    requested_withdrawal: Option<BTreeMap<String, u64>>,
    #[serde(rename = "splitOrder")]
    split_order: Option<Vec<String>>,
    #[serde(rename = "splitWithdrawalOutputIndex")]
    split_output_index: Option<BTreeMap<String, usize>>,
    #[serde(rename = "requestedExitOrder")]
    requested_exit_order: Option<Vec<String>>,
    #[serde(rename = "remainderExitOrder")]
    remainder_exit_order: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Workload {
    schema: String,
    experiment: String,
    #[serde(rename = "creditsSompi")]
    credits: BTreeMap<String, u64>,
    #[serde(rename = "minimumRequestedAndChangeSompi")]
    minimum_split: u64,
    arms: Vec<ArmWorkload>,
}

#[derive(Clone)]
struct RoleNote {
    chain: usize,
    role: &'static str,
    owner: usize,
    note: Note,
}

#[derive(Clone)]
struct SplitNotes {
    chain: usize,
    role: &'static str,
    owner: usize,
    withdrawal: Note,
    change: Note,
}

struct ChainRuntime {
    stage: usize,
    received: Option<(Note, usize)>,
    outputs: Vec<[Note; 2]>,
    transfer_truth: Vec<Value>,
}

fn ensure(condition: bool, label: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(label.into())
    }
}

fn label_index(label: &str) -> Result<usize> {
    LABELS
        .iter()
        .position(|candidate| *candidate == label)
        .ok_or_else(|| "identity label".into())
}

fn write_json(path: &Path, value: &impl Serialize, mode: u32) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
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
    arm: &str,
    ordinal: usize,
    operation: &Operation,
) -> Result<()> {
    let mut token = [0u8; 16];
    OsRng.fill_bytes(&mut token);
    let request = json!({
        "schema": "wallet-local-public-operation-request-v1",
        "trial": arm,
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
    public_root: &Path,
    arm: &str,
    capture_script: &Path,
    started: &Instant,
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
        &public_root.join(&capture_name),
        arm,
        ordinal,
        operation,
    )?;
    let before = ledger.state_hash();
    let transition = ledger.apply(verifier, operation)?;
    let wire = operation.wire_bytes()?;
    let event = json!({
        "schema": "wallet-local-private-change-accepted-operation-v1",
        "ordinal": ordinal,
        "label": label,
        "localMonotonicNs": started.elapsed().as_nanos().to_string(),
        "proofSeconds": proof_seconds,
        "capture": capture_name,
        "wireBytes": wire.len(),
        "wireSha256": hex::encode(hash(&wire)),
        "stateBefore": hex::encode(before),
        "stateAfter": hex::encode(ledger.state_hash()),
        "transition": hex::encode(transition),
        "operation": operation,
        "accepted": true,
    });
    write_json(
        &public_root.join(format!("event-{ordinal:02}.json")),
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
        "domain" => changed.statement.domain = hash(b"wrong profile domain"),
        "root" => changed.statement.anchor[0] ^= 1,
        _ => return Err("mutation mode".into()),
    }
    let before = ledger.state_hash();
    ensure(
        ledger.apply(verifier, &changed).is_err() && ledger.state_hash() == before,
        &format!("atomic wrong-{mode} rejection"),
    )
}

#[allow(clippy::too_many_arguments)]
fn make_transfer(
    engine: &Engine,
    sender: &Wallet,
    input: Note,
    input_index: usize,
    payment: Note,
    change: Note,
    payment_index: usize,
    ledger: &Ledger,
) -> Result<(Operation, [Note; 2])> {
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
    Ok((operation, outputs))
}

fn validate_split_parts(total: u64, requested: u64, change: u64) -> Result<()> {
    ensure(
        requested >= MIN_SPLIT
            && change >= MIN_SPLIT
            && requested.checked_add(change) == Some(total),
        "split bounds/conservation",
    )
}

fn discover_exact(wallet: &Wallet, ledger: &Ledger, note: &Note) -> Result<(Note, usize)> {
    let commitment = note.commitment();
    let matches = wallet
        .discover(&ledger.deliveries, &ledger.tree, &ledger.nullifiers)
        .into_iter()
        .filter(|(candidate, _)| candidate.commitment() == commitment)
        .collect::<Vec<_>>();
    ensure(matches.len() == 1, "exact backup discovery")?;
    Ok(matches[0].clone())
}

#[allow(clippy::too_many_arguments)]
fn exit_note(
    engine: &Engine,
    verifier: &Verifier,
    ledger: &mut Ledger,
    backups: &[[u8; 64]],
    role: &RoleNote,
    public_root: &Path,
    arm: &str,
    capture_script: &Path,
    started: &Instant,
    ordinal: usize,
    label: &str,
) -> Result<(Value, Value)> {
    let wallet = Wallet::restore_local(&backups[role.owner]);
    let (note, index) = discover_exact(&wallet, ledger, &role.note)?;
    let wrong_owner = Wallet::restore_local(&backups[(role.owner + 1) % backups.len()]);
    ensure(
        wrong_owner
            .discover(&ledger.deliveries, &ledger.tree, &ledger.nullifiers)
            .iter()
            .all(|(candidate, _)| candidate.commitment() != note.commitment()),
        "unauthorized wallet cannot discover exit note",
    )?;
    let (siblings, directions) = ledger.tree.path(index)?;
    let destination = random_hash();
    let mut statement = Statement::new(EXIT, engine.id(), ledger.tree.root());
    statement.nullifier = wallet.nf(&note);
    statement.exit_destination = destination;
    statement.exit_value = note.value;
    let proof_start = Instant::now();
    let operation = engine.prove(
        statement,
        wallet.witness(note.clone(), [Note::dummy(), Note::dummy()], siblings, directions),
        [Delivery::absent(), Delivery::absent()],
    )?;
    let event = accept_operation(
        public_root,
        arm,
        capture_script,
        started,
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
                note.value,
                random_hash(),
                random_hash(),
            )
            .is_err()
            && ledger.state_hash() == before_wrong,
        "diverted payout rejection",
    )?;
    let output = random_hash();
    ledger.confirm_authenticated_fixture_payout(
        operation.statement.id(),
        note.value,
        destination,
        output,
    )?;
    Ok((
        event,
        json!({
            "ordinal": ordinal,
            "destination": hex::encode(destination),
            "amountSompi": note.value,
            "nativeOutput": hex::encode(output),
        }),
    ))
}

fn validate_arm(arm: &ArmWorkload, candidate: bool) -> Result<()> {
    ensure(arm.chains.len() == 2 && arm.target_chain < 2, "arm chains/target")?;
    let chain0 = &arm.chains[0];
    let chain1 = &arm.chains[1];
    ensure(["A", "B"].contains(&chain0.sender.as_str()), "chain0 sender")?;
    ensure(["C", "D"].contains(&chain1.sender.as_str()), "chain1 sender")?;
    ensure(
        BTreeSet::from([chain0.first_recipient.as_str(), chain1.first_recipient.as_str()])
            == BTreeSet::from(["E", "F"]),
        "first recipient permutation",
    )?;
    ensure(
        BTreeSet::from([chain0.second_recipient.as_str(), chain1.second_recipient.as_str()])
            == BTreeSet::from(["G", "H"]),
        "second recipient permutation",
    )?;
    ensure(
        (220_000_000..=500_000_000).contains(&chain0.p1)
            && (80_000_000..=chain0.p1 - 80_000_000).contains(&chain0.p2),
        "chain0 amounts",
    )?;
    ensure(
        (180_000_000..=400_000_000).contains(&chain1.p1)
            && (60_000_000..=chain1.p1 - 60_000_000).contains(&chain1.p2),
        "chain1 amounts",
    )?;
    ensure(
        arm.chains
            .iter()
            .all(|chain| chain.payment_output_indices.iter().all(|index| *index < 2)),
        "payment output indices",
    )?;
    ensure(
        arm.transfer_schedule.iter().filter(|value| **value == 0).count() == 2
            && arm.transfer_schedule.iter().filter(|value| **value == 1).count() == 2,
        "transfer schedule",
    )?;
    let expected_final = BTreeSet::from([
        ExitOrder { chain: 0, role: "untouchedCredit".into() },
        ExitOrder { chain: 0, role: "firstChange".into() },
        ExitOrder { chain: 1, role: "untouchedCredit".into() },
        ExitOrder { chain: 1, role: "firstChange".into() },
        ExitOrder { chain: 1 - arm.target_chain, role: "secondChange".into() },
        ExitOrder { chain: 1 - arm.target_chain, role: "secondPayment".into() },
    ]);
    ensure(
        arm.final_exit_order.iter().cloned().collect::<BTreeSet<_>>() == expected_final
            && arm.final_exit_order.len() == 6,
        "final exit order",
    )?;
    let role_set = BTreeSet::from(["secondChange".to_owned(), "secondPayment".to_owned()]);
    if candidate {
        ensure(
            arm.direct_exit_order.is_none()
                && arm.split_order.as_ref().map(|items| items.iter().cloned().collect::<BTreeSet<_>>()) == Some(role_set.clone())
                && arm.requested_exit_order.as_ref().map(|items| items.iter().cloned().collect::<BTreeSet<_>>()) == Some(role_set.clone())
                && arm.remainder_exit_order.as_ref().map(|items| items.iter().cloned().collect::<BTreeSet<_>>()) == Some(role_set.clone()),
            "candidate orders",
        )?;
        let chain = &arm.chains[arm.target_chain];
        let values = BTreeMap::from([
            ("secondChange", chain.p1 - chain.p2),
            ("secondPayment", chain.p2),
        ]);
        let requested = arm.requested_withdrawal.as_ref().ok_or("requested values")?;
        let indices = arm.split_output_index.as_ref().ok_or("split indices")?;
        ensure(
            requested.keys().cloned().collect::<BTreeSet<_>>() == role_set
                && indices.keys().cloned().collect::<BTreeSet<_>>() == role_set
                && indices.values().all(|index| *index < 2),
            "candidate split maps",
        )?;
        for (role, value) in values {
            let request = requested[role];
            validate_split_parts(value, request, value - request)?;
        }
    } else {
        ensure(
            arm.direct_exit_order.as_ref().map(|items| items.iter().cloned().collect::<BTreeSet<_>>()) == Some(role_set)
                && arm.requested_withdrawal.is_none()
                && arm.split_order.is_none()
                && arm.split_output_index.is_none()
                && arm.requested_exit_order.is_none()
                && arm.remainder_exit_order.is_none(),
            "baseline shape",
        )?;
    }
    Ok(())
}

fn validate_workload(path: &Path) -> Result<Workload> {
    let raw = fs::read(path).map_err(|e| e.to_string())?;
    ensure(hex::encode(hash(&raw)) == WORKLOAD_SHA, "workload commitment")?;
    let workload: Workload = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    ensure(
        workload.schema == "wallet-local-private-change-workload-v1"
            && workload.experiment == "wallet-local-private-change-v1"
            && workload.minimum_split == MIN_SPLIT,
        "workload identity",
    )?;
    ensure(
        workload.credits
            == BTreeMap::from([
                ("A".into(), 900_000_000),
                ("B".into(), 800_000_000),
                ("C".into(), 700_000_000),
                ("D".into(), 600_000_000),
            ]),
        "credit policy",
    )?;
    ensure(
        workload.arms.len() == 2
            && workload.arms[0].arm == "direct-exit-baseline"
            && workload.arms[1].arm == "private-change-candidate",
        "arm order",
    )?;
    validate_arm(&workload.arms[0], false)?;
    validate_arm(&workload.arms[1], true)?;
    Ok(workload)
}

fn checkpoint(
    root: &Path,
    name: &str,
    ordinal: usize,
    unspent: usize,
    ledger: &Ledger,
) -> Result<()> {
    write_json(
        &root.join(format!("checkpoint-{name}.json")),
        &json!({
            "schema": "wallet-local-private-change-checkpoint-v1",
            "checkpoint": name,
            "eventCount": ordinal,
            "stateHash": hex::encode(ledger.state_hash()),
            "reserveSompi": ledger.reserve,
            "privateLiabilitySompi": ledger.private_liability,
            "unspentNoteCount": unspent,
        }),
        0o644,
    )
}

fn build_roles(
    arm: &ArmWorkload,
    credit_notes: &[Note],
    runtime: &[ChainRuntime; 2],
) -> Result<Vec<RoleNote>> {
    let mut roles = vec![];
    for chain_index in 0..2 {
        let chain = &arm.chains[chain_index];
        let sender = label_index(&chain.sender)?;
        let other = if chain_index == 0 {
            1 - sender
        } else if sender == 2 {
            3
        } else {
            2
        };
        let first_outputs = runtime[chain_index].outputs[0].clone();
        let second_outputs = runtime[chain_index].outputs[1].clone();
        roles.extend([
            RoleNote { chain: chain_index, role: "untouchedCredit", owner: other, note: credit_notes[other].clone() },
            RoleNote {
                chain: chain_index,
                role: "firstChange",
                owner: sender,
                note: first_outputs[1 - chain.payment_output_indices[0]].clone(),
            },
            RoleNote {
                chain: chain_index,
                role: "secondPayment",
                owner: label_index(&chain.second_recipient)?,
                note: second_outputs[chain.payment_output_indices[1]].clone(),
            },
            RoleNote {
                chain: chain_index,
                role: "secondChange",
                owner: label_index(&chain.first_recipient)?,
                note: second_outputs[1 - chain.payment_output_indices[1]].clone(),
            },
        ]);
    }
    Ok(roles)
}

#[allow(clippy::too_many_arguments)]
fn record_exit(
    events: &mut Vec<Value>,
    exit_truth: &mut Vec<Value>,
    payouts: &mut Vec<Value>,
    event: Value,
    payout: Value,
    role: &RoleNote,
    phase: &str,
    subrole: &str,
) {
    events.push(event);
    exit_truth.push(json!({
        "phase": phase,
        "subrole": subrole,
        "chain": role.chain,
        "role": role.role,
        "owner": LABELS[role.owner],
        "valueSompi": role.note.value,
        "commitment": hex::encode(role.note.commitment()),
        "payout": payout,
    }));
    payouts.push(exit_truth.last().unwrap()["payout"].clone());
}

#[allow(clippy::too_many_arguments)]
fn run_arm(
    arm: &ArmWorkload,
    candidate: bool,
    engine: &Engine,
    verifier: &Verifier,
    public_parent: &Path,
    private_parent: &Path,
    capture_script: &Path,
) -> Result<(Value, Value, Value)> {
    let public_root = public_parent.join(&arm.arm);
    let private_root = private_parent.join(&arm.arm);
    fs::create_dir(&public_root).map_err(|e| e.to_string())?;
    fs::create_dir(&private_root).map_err(|e| e.to_string())?;
    fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let started = Instant::now();
    let wallets = (0..8).map(|_| Wallet::new()).collect::<Vec<_>>();
    let backups = wallets.iter().map(Wallet::local_backup).collect::<Vec<_>>();
    for (index, backup) in backups.iter().enumerate() {
        let path = private_root.join(format!("wallet-{index}.backup"));
        fs::write(&path, backup).map_err(|e| e.to_string())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    let credit_values = [900_000_000, 800_000_000, 700_000_000, 600_000_000];
    let credit_notes = (0..4)
        .map(|index| wallets[index].note(credit_values[index]))
        .collect::<Vec<_>>();
    let deposit_ids = [random_hash(), random_hash(), random_hash(), random_hash()];
    let mut ledger = Ledger::new(engine.id());
    let mut public_deposits = vec![];
    for index in 0..4 {
        ledger.register_authenticated_fixture_deposit(
            deposit_ids[index],
            credit_values[index],
            wallets[index].address.owner,
        )?;
        public_deposits.push(json!({
            "depositId": hex::encode(deposit_ids[index]),
            "owner": hex::encode(wallets[index].address.owner),
            "amountSompi": credit_values[index],
        }));
    }

    let mut events = vec![];
    let mut ordinal = 0usize;
    for index in 0..4 {
        let mut statement = Statement::new(CREDIT, engine.id(), ledger.tree.root());
        statement.deposit = deposit_ids[index];
        statement.deposit_owner = wallets[index].address.owner;
        statement.deposit_value = credit_values[index];
        let proof_start = Instant::now();
        let operation = engine.prove(
            statement,
            wallets[index].witness(
                wallets[index].authority_note(),
                [credit_notes[index].clone(), Note::dummy()],
                [[0; 32]; DEPTH],
                [false; DEPTH],
            ),
            [credit_notes[index].deliver()?, Delivery::absent()],
        )?;
        events.push(accept_operation(
            &public_root,
            &arm.arm,
            capture_script,
            &started,
            ordinal,
            "credit",
            proof_start.elapsed().as_secs_f64(),
            &mut ledger,
            verifier,
            &operation,
        )?);
        ordinal += 1;
    }

    let mut runtime = [
        ChainRuntime { stage: 0, received: None, outputs: vec![], transfer_truth: vec![] },
        ChainRuntime { stage: 0, received: None, outputs: vec![], transfer_truth: vec![] },
    ];
    for chain_index in arm.transfer_schedule {
        let chain = &arm.chains[chain_index];
        let stage = runtime[chain_index].stage;
        let (sender_wallet, input, input_index, payment, change) = if stage == 0 {
            let sender = label_index(&chain.sender)?;
            (
                Wallet::restore_local(&backups[sender]),
                credit_notes[sender].clone(),
                sender,
                wallets[label_index(&chain.first_recipient)?].note(chain.p1),
                wallets[sender].note(credit_values[sender] - chain.p1),
            )
        } else {
            let first = label_index(&chain.first_recipient)?;
            let (input, index) = runtime[chain_index].received.clone().ok_or("second input")?;
            (
                Wallet::restore_local(&backups[first]),
                input,
                index,
                wallets[label_index(&chain.second_recipient)?].note(chain.p2),
                wallets[first].note(chain.p1 - chain.p2),
            )
        };
        let proof_start = Instant::now();
        let (operation, outputs) = make_transfer(
            engine,
            &sender_wallet,
            input,
            input_index,
            payment,
            change,
            chain.payment_output_indices[stage],
            &ledger,
        )?;
        let proof_seconds = proof_start.elapsed().as_secs_f64();
        reject_mutated(&mut ledger, verifier, &operation, "domain")?;
        reject_mutated(&mut ledger, verifier, &operation, "root")?;
        events.push(accept_operation(
            &public_root,
            &arm.arm,
            capture_script,
            &started,
            ordinal,
            "transfer",
            proof_seconds,
            &mut ledger,
            verifier,
            &operation,
        )?);
        let after = ledger.state_hash();
        ensure(
            ledger.apply(verifier, &operation).is_err() && ledger.state_hash() == after,
            "accepted transfer replay rejection",
        )?;
        runtime[chain_index].transfer_truth.push(json!({
            "eventOrdinal": ordinal,
            "stage": stage,
            "paymentOutputIndex": chain.payment_output_indices[stage],
            "changeOutputIndex": 1 - chain.payment_output_indices[stage],
            "inputCommitment": if stage == 0 {
                hex::encode(credit_notes[label_index(&chain.sender)?].commitment())
            } else {
                hex::encode(runtime[chain_index].received.as_ref().unwrap().0.commitment())
            },
        }));
        runtime[chain_index].outputs.push(outputs.clone());
        if stage == 0 {
            let first = label_index(&chain.first_recipient)?;
            let restored = Wallet::restore_local(&backups[first]);
            let expected = &outputs[chain.payment_output_indices[0]];
            runtime[chain_index].received = Some(discover_exact(&restored, &ledger, expected)?);
        }
        runtime[chain_index].stage += 1;
        ordinal += 1;
    }
    ensure(runtime.iter().all(|chain| chain.stage == 2), "complete original transfers")?;
    ensure(ledger.tree.leaves.len() == 12, "pre-withdrawal leaves")?;
    let roles = build_roles(arm, &credit_notes, &runtime)?;
    checkpoint(&public_root, "pre-withdrawal", ordinal, 8, &ledger)?;

    let mut exit_truth = vec![];
    let mut payouts = vec![];
    let mut split_truth = vec![];
    if candidate {
        let mut split_notes = vec![];
        for role_name in arm.split_order.as_ref().unwrap() {
            let original = roles
                .iter()
                .find(|role| role.chain == arm.target_chain && role.role == role_name)
                .ok_or("split role")?;
            let owner = Wallet::restore_local(&backups[original.owner]);
            let (input, index) = discover_exact(&owner, &ledger, &original.note)?;
            let requested = arm.requested_withdrawal.as_ref().unwrap()[role_name];
            let change_value = input.value - requested;
            validate_split_parts(input.value, MIN_SPLIT - 1, input.value - (MIN_SPLIT - 1))
                .expect_err("below-minimum request must reject");
            validate_split_parts(input.value, input.value - (MIN_SPLIT - 1), MIN_SPLIT - 1)
                .expect_err("below-minimum change must reject");
            validate_split_parts(input.value, requested, change_value - 1)
                .expect_err("split sum mismatch must reject");
            validate_split_parts(input.value, requested, change_value)?;
            let withdrawal_note = wallets[original.owner].note(requested);
            let change_note = wallets[original.owner].note(change_value);
            let output_index = arm.split_output_index.as_ref().unwrap()[role_name];
            let proof_start = Instant::now();
            let (operation, outputs) = make_transfer(
                engine,
                &owner,
                input,
                index,
                withdrawal_note,
                change_note,
                output_index,
                &ledger,
            )?;
            let proof_seconds = proof_start.elapsed().as_secs_f64();
            reject_mutated(&mut ledger, verifier, &operation, "domain")?;
            reject_mutated(&mut ledger, verifier, &operation, "root")?;
            events.push(accept_operation(
                &public_root,
                &arm.arm,
                capture_script,
                &started,
                ordinal,
                "transfer",
                proof_seconds,
                &mut ledger,
                verifier,
                &operation,
            )?);
            let after = ledger.state_hash();
            ensure(
                ledger.apply(verifier, &operation).is_err() && ledger.state_hash() == after,
                "self-split replay rejection",
            )?;
            let restored = Wallet::restore_local(&backups[original.owner]);
            let withdrawal = outputs[output_index].clone();
            let change = outputs[1 - output_index].clone();
            discover_exact(&restored, &ledger, &withdrawal)?;
            discover_exact(&restored, &ledger, &change)?;
            let wrong = Wallet::restore_local(&backups[(original.owner + 1) % backups.len()]);
            ensure(
                wrong
                    .discover(&ledger.deliveries, &ledger.tree, &ledger.nullifiers)
                    .iter()
                    .all(|(note, _)| {
                        note.commitment() != withdrawal.commitment()
                            && note.commitment() != change.commitment()
                    }),
                "wrong owner cannot discover split outputs",
            )?;
            split_truth.push(json!({
                "eventOrdinal": ordinal,
                "chain": original.chain,
                "role": original.role,
                "owner": LABELS[original.owner],
                "inputCommitment": hex::encode(original.note.commitment()),
                "inputValueSompi": original.note.value,
                "requestedSompi": withdrawal.value,
                "remainderSompi": change.value,
                "withdrawalOutputIndex": output_index,
                "changeOutputIndex": 1 - output_index,
            }));
            split_notes.push(SplitNotes {
                chain: original.chain,
                role: original.role,
                owner: original.owner,
                withdrawal,
                change,
            });
            ordinal += 1;
        }
        ensure(ledger.tree.leaves.len() == 16, "candidate capacity")?;
        for role_name in arm.requested_exit_order.as_ref().unwrap() {
            let split = split_notes.iter().find(|item| item.role == role_name).ok_or("requested split")?;
            let role = RoleNote { chain: split.chain, role: split.role, owner: split.owner, note: split.withdrawal.clone() };
            let (event, payout) = exit_note(
                engine, verifier, &mut ledger, &backups, &role, &public_root, &arm.arm,
                capture_script, &started, ordinal, "exit-requested",
            )?;
            record_exit(&mut events, &mut exit_truth, &mut payouts, event, payout, &role, "requested", "requestedWithdrawal");
            ordinal += 1;
        }
        checkpoint(&public_root, "requested-withdrawal", ordinal, 8, &ledger)?;
        for role_name in arm.remainder_exit_order.as_ref().unwrap() {
            let split = split_notes.iter().find(|item| item.role == role_name).ok_or("remainder split")?;
            let role = RoleNote { chain: split.chain, role: split.role, owner: split.owner, note: split.change.clone() };
            let (event, payout) = exit_note(
                engine, verifier, &mut ledger, &backups, &role, &public_root, &arm.arm,
                capture_script, &started, ordinal, "exit-remainder",
            )?;
            record_exit(&mut events, &mut exit_truth, &mut payouts, event, payout, &role, "remainder", "privateChange");
            ordinal += 1;
        }
        checkpoint(&public_root, "remainder-withdrawal", ordinal, 6, &ledger)?;
    } else {
        for role_name in arm.direct_exit_order.as_ref().unwrap() {
            let role = roles
                .iter()
                .find(|role| role.chain == arm.target_chain && role.role == role_name)
                .ok_or("direct exit role")?;
            let (event, payout) = exit_note(
                engine, verifier, &mut ledger, &backups, role, &public_root, &arm.arm,
                capture_script, &started, ordinal, "exit-requested",
            )?;
            record_exit(&mut events, &mut exit_truth, &mut payouts, event, payout, role, "requested", "fullRoleNote");
            ordinal += 1;
        }
        checkpoint(&public_root, "requested-withdrawal", ordinal, 6, &ledger)?;
        checkpoint(&public_root, "remainder-withdrawal", ordinal, 6, &ledger)?;
    }

    for order in &arm.final_exit_order {
        let role = roles
            .iter()
            .find(|role| role.chain == order.chain && role.role == order.role)
            .ok_or("final role")?;
        let (event, payout) = exit_note(
            engine, verifier, &mut ledger, &backups, role, &public_root, &arm.arm,
            capture_script, &started, ordinal, "exit-final",
        )?;
        record_exit(&mut events, &mut exit_truth, &mut payouts, event, payout, role, "final", "fullRoleNote");
        ordinal += 1;
    }
    let expected_operations = if candidate { 20 } else { 16 };
    ensure(
        ordinal == expected_operations && ledger.reserve == 0 && ledger.private_liability == 0,
        "complete zero-liability drainage",
    )?;
    for backup in &backups {
        let restored = Wallet::restore_local(backup);
        ensure(
            restored.discover(&ledger.deliveries, &ledger.tree, &ledger.nullifiers).is_empty(),
            "all owner notes exited",
        )?;
    }
    checkpoint(&public_root, "full-drainage", ordinal, 0, &ledger)?;

    let truth_chains = (0..2)
        .map(|chain_index| {
            let chain = &arm.chains[chain_index];
            let sender = label_index(&chain.sender).unwrap();
            json!({
                "chain": chain_index,
                "sender": chain.sender,
                "firstRecipient": chain.first_recipient,
                "secondRecipient": chain.second_recipient,
                "p1Sompi": chain.p1,
                "p2Sompi": chain.p2,
                "historicalCredit": hex::encode(credit_notes[sender].commitment()),
                "transfers": runtime[chain_index].transfer_truth,
            })
        })
        .collect::<Vec<_>>();
    let truth = json!({
        "schema": "wallet-local-private-change-arm-truth-v1",
        "arm": arm.arm,
        "chains": truth_chains,
        "targetChain": arm.target_chain,
        "splits": split_truth,
        "exits": exit_truth,
    });
    write_json(&private_root.join("truth.json"), &truth, 0o600)?;

    let known_exit = truth["exits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|exit| {
            (
                exit["payout"]["destination"].as_str().unwrap().to_owned(),
                exit["owner"].clone(),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    let auxiliary = json!({
        "schema": "wallet-local-private-change-auxiliary-v1",
        "arm": arm.arm,
        "identityUniverse": LABELS,
        "depositOwnerIdentity": {
            hex::encode(wallets[0].address.owner): "A",
            hex::encode(wallets[1].address.owner): "B",
            hex::encode(wallets[2].address.owner): "C",
            hex::encode(wallets[3].address.owner): "D",
        },
        "contactEdges": [
            ["A","E"],["A","F"],["B","E"],["B","F"],
            ["C","E"],["C","F"],["D","E"],["D","F"],
            ["E","G"],["E","H"],["F","G"],["F","H"]
        ],
        "knownExitDestinationIdentity": known_exit,
        "relayTokensMappedToIdentity": false,
    });
    write_json(&public_root.join("auxiliary.json"), &auxiliary, 0o644)?;

    let ledger_public = json!({
        "schema": "wallet-local-private-change-arm-ledger-v1",
        "experiment": "wallet-local-private-change-v1",
        "arm": arm.arm,
        "selectionSha256": SELECTION_SHA,
        "privateWorkloadSha256": WORKLOAD_SHA,
        "deposits": public_deposits,
        "checkpointEventCounts": if candidate {
            json!({"preWithdrawal":8,"requestedWithdrawal":12,"remainderWithdrawal":14,"fullDrainage":20})
        } else {
            json!({"preWithdrawal":8,"requestedWithdrawal":10,"remainderWithdrawal":10,"fullDrainage":16})
        },
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
            "unauthorizedWalletCannotDiscoverExitNote": true,
            "divertedPayoutsRejectedAtomically": true,
            "backupRecoveryAndExitForEveryNote": true,
            "zeroFinalReserveAndLiability": true,
            "splitBoundsAndConservationPreflight": candidate,
            "splitOutputsRecoveredExactlyOnce": candidate,
            "wrongOwnerCannotDiscoverSplitOutputs": candidate,
        },
        "applicationFeeSompi": 0,
        "nativeNetworkFee": "unmeasured-no-network",
        "elapsedSeconds": started.elapsed().as_secs_f64(),
    });
    write_json(&public_root.join("ledger.json"), &ledger_public, 0o644)?;
    Ok((
        json!({
            "arm": arm.arm,
            "acceptedOperationCount": expected_operations,
            "serviceCaptureCount": expected_operations,
            "elapsedSeconds": started.elapsed().as_secs_f64(),
            "treeLeaves": ledger.tree.leaves.len(),
            "paidExitCount": ledger.exits.values().filter(|exit| exit.paid).count(),
        }),
        auxiliary,
        truth,
    ))
}

fn real_main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 5 {
        return Err("usage: wallet-local-private-change-runner PUBLIC_DIR PRIVATE_DIR PRIVATE_WORKLOAD.json SERVICE_CAPTURE.py".into());
    }
    let public_root = PathBuf::from(&args[1]);
    let private_root = PathBuf::from(&args[2]);
    let workload_path = PathBuf::from(&args[3]);
    let capture_script = PathBuf::from(&args[4]);
    ensure(!public_root.exists(), "public output exists")?;
    ensure(!private_root.exists(), "private output exists")?;
    ensure(DEPTH == 4 && domain() == hash(DOMAIN_TEXT), "depth-four profile")?;
    let workload = validate_workload(&workload_path)?;
    fs::create_dir_all(&public_root).map_err(|e| e.to_string())?;
    fs::create_dir_all(&private_root).map_err(|e| e.to_string())?;
    fs::set_permissions(&private_root, fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;

    let started = Instant::now();
    let setup_started = Instant::now();
    let engine = Engine::setup(sample_circuit()?)?;
    let setup_seconds = setup_started.elapsed().as_secs_f64();
    let verifier = engine.verifier();
    let parameters = engine.public_parameters()?;
    write_json(
        &public_root.join("parameters.json"),
        &json!({
            "schema": "wallet-local-private-change-parameters-v1",
            "depth": DEPTH,
            "capacity": 1usize << DEPTH,
            "domain": hex::encode(domain()),
            "verifier": hex::encode(engine.id()),
            "verifyingKeyBytes": engine.vk_bytes().len(),
            "provingParameterBytes": parameters.len(),
            "provingParameterSha256": hex::encode(hash(&parameters)),
            "setupSeconds": setup_seconds,
        }),
        0o644,
    )?;
    drop(parameters);
    fs::write(public_root.join("verifying-key.bin"), engine.vk_bytes())
        .map_err(|e| e.to_string())?;

    let mut summaries = vec![];
    let mut aux = vec![];
    let mut truths = vec![];
    for (index, arm) in workload.arms.iter().enumerate() {
        let (summary, arm_aux, truth) = run_arm(
            arm,
            index == 1,
            &engine,
            &verifier,
            &public_root,
            &private_root,
            &capture_script,
        )?;
        summaries.push(summary);
        aux.push(arm_aux);
        truths.push(truth);
    }
    write_json(
        &private_root.join("truth-index.json"),
        &json!({
            "schema": "wallet-local-private-change-truth-index-v1",
            "privateWorkloadSha256": WORKLOAD_SHA,
            "arms": truths,
        }),
        0o600,
    )?;
    write_json(
        &public_root.join("auxiliary.json"),
        &json!({
            "schema": "wallet-local-private-change-auxiliary-index-v1",
            "arms": aux,
        }),
        0o644,
    )?;
    write_json(
        &public_root.join("run-receipt.json"),
        &json!({
            "schema": "wallet-local-private-change-run-receipt-v1",
            "experiment": "wallet-local-private-change-v1",
            "selectionSha256": SELECTION_SHA,
            "privateWorkloadSha256": WORKLOAD_SHA,
            "arms": summaries,
            "acceptedOperationCount": 36,
            "serviceCaptureCount": 36,
            "setupSeconds": setup_seconds,
            "elapsedSeconds": started.elapsed().as_secs_f64(),
            "network": false,
            "funding": false,
            "sameHostOnly": true,
            "applicationFeeSompi": 0,
            "nativeNetworkFee": "unmeasured-no-network",
        }),
        0o644,
    )?;
    println!(
        "{}",
        json!({
            "public": public_root,
            "private": private_root,
            "operations": 36,
            "elapsedSeconds": started.elapsed().as_secs_f64(),
        })
    );
    Ok(())
}

fn main() {
    if let Err(error) = real_main() {
        eprintln!("wallet-local-private-change-runner: {error}");
        std::process::exit(1);
    }
}

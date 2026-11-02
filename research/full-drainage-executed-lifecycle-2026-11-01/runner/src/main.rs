use kpi_private_note_wallet::{
    circuit::WalletCircuit,
    ledger::Ledger,
    protocol::{hash, Delivery, Note, Operation, Statement, Tree, CREDIT, DEPTH, EXIT, TRANSFER},
    wallet::{Address, Engine, Verifier, Wallet},
    Result,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs,
    io::{self, BufRead, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    time::Instant,
};

fn ensure(value: bool, message: &str) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn h(value: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(value).map_err(|e| e.to_string())?;
    raw.try_into().map_err(|_| "expected 32-byte hex".into())
}

fn read_json<T: for<'a> Deserialize<'a>>(path: &str) -> Result<T> {
    serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

fn read_ledger(path: &str) -> Result<Ledger> {
    bincode::deserialize(&fs::read(path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

fn write_ledger(path: &str, ledger: &Ledger) -> Result<()> {
    fs::write(path, bincode::serialize(ledger).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())
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

fn setup(parameters: &str, vk: &str, vk_uncompressed: &str) -> Result<()> {
    ensure(!Path::new(parameters).exists(), "parameters output exists")?;
    ensure(!Path::new(vk).exists(), "VK output exists")?;
    ensure(
        !Path::new(vk_uncompressed).exists(),
        "uncompressed VK output exists",
    )?;
    let started = Instant::now();
    let engine = Engine::setup(sample_circuit()?)?;
    let raw = engine.public_parameters()?;
    fs::write(parameters, &raw).map_err(|e| e.to_string())?;
    fs::write(vk, engine.vk_bytes()).map_err(|e| e.to_string())?;
    fs::write(vk_uncompressed, engine.vk_uncompressed_bytes()).map_err(|e| e.to_string())?;
    println!(
        "{}",
        json!({
            "schema": "full-drainage-setup-v1",
            "depth": DEPTH,
            "capacity": 1usize << DEPTH,
            "verifier": hex::encode(engine.id()),
            "provingParametersBytes": raw.len(),
            "verifyingKeyBytes": engine.vk_bytes().len(),
            "verifyingKeyUncompressedBytes": engine.vk_uncompressed_bytes().len(),
            "setupSeconds": started.elapsed().as_secs_f64()
        })
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WorkerCommand {
    action: String,
    ledger_path: String,
    deposit: Option<String>,
    value_sompi: Option<u64>,
    input_value_sompi: Option<u64>,
    payment_sompi: Option<u64>,
    payment_output_index: Option<usize>,
    recipient_owner: Option<String>,
    recipient_incoming: Option<String>,
    exit_destination: Option<String>,
}

fn matching_note(wallet: &Wallet, ledger: &Ledger, value: u64) -> Result<(Note, usize)> {
    let matches: Vec<_> = wallet
        .discover(&ledger.deliveries, &ledger.tree, &ledger.nullifiers)
        .into_iter()
        .filter(|(note, _)| note.value == value)
        .collect();
    ensure(
        matches.len() == 1,
        "expected exactly one spendable note value",
    )?;
    Ok(matches[0].clone())
}

fn prove_command(engine: &Engine, wallet: &Wallet, command: WorkerCommand) -> Result<Value> {
    let ledger = read_ledger(&command.ledger_path)?;
    let started = Instant::now();
    let operation = match command.action.as_str() {
        "credit" => {
            let value = command.value_sompi.ok_or("credit value")?;
            let note = wallet.note(value);
            let mut statement = Statement::new(CREDIT, engine.id(), ledger.tree.root());
            statement.deposit = h(command.deposit.as_deref().ok_or("deposit id")?)?;
            statement.deposit_owner = wallet.address.owner;
            statement.deposit_value = value;
            engine.prove(
                statement,
                wallet.witness(
                    wallet.authority_note(),
                    [note.clone(), Note::dummy()],
                    [[0; 32]; DEPTH],
                    [false; DEPTH],
                ),
                [note.deliver()?, Delivery::absent()],
            )?
        }
        "transfer" => {
            let input_value = command.input_value_sompi.ok_or("input value")?;
            let payment = command.payment_sompi.ok_or("payment")?;
            ensure(payment > 0 && payment < input_value, "payment range")?;
            let (input, input_index) = matching_note(wallet, &ledger, input_value)?;
            let recipient = Address {
                owner: h(command
                    .recipient_owner
                    .as_deref()
                    .ok_or("recipient owner")?)?,
                incoming: h(command
                    .recipient_incoming
                    .as_deref()
                    .ok_or("recipient incoming")?)?,
            };
            let payment_note = Note::for_address(&recipient, payment);
            let change_note = wallet.note(input_value - payment);
            let payment_index = command.payment_output_index.ok_or("payment output index")?;
            ensure(payment_index < 2, "payment output index")?;
            let outputs = if payment_index == 0 {
                [payment_note, change_note]
            } else {
                [change_note, payment_note]
            };
            let deliveries = [outputs[0].deliver()?, outputs[1].deliver()?];
            let (siblings, directions) = ledger.tree.path(input_index)?;
            let mut statement = Statement::new(TRANSFER, engine.id(), ledger.tree.root());
            statement.nullifier = wallet.nf(&input);
            engine.prove(
                statement,
                wallet.witness(input, outputs, siblings, directions),
                deliveries,
            )?
        }
        "exit" => {
            let input_value = command.input_value_sompi.ok_or("input value")?;
            let (input, input_index) = matching_note(wallet, &ledger, input_value)?;
            let (siblings, directions) = ledger.tree.path(input_index)?;
            let mut statement = Statement::new(EXIT, engine.id(), ledger.tree.root());
            statement.nullifier = wallet.nf(&input);
            statement.exit_destination = h(command
                .exit_destination
                .as_deref()
                .ok_or("exit destination")?)?;
            statement.exit_value = input_value;
            engine.prove(
                statement,
                wallet.witness(input, [Note::dummy(), Note::dummy()], siblings, directions),
                [Delivery::absent(), Delivery::absent()],
            )?
        }
        _ => return Err("unknown worker action".into()),
    };
    let wire = operation.wire_bytes()?;
    Ok(json!({
        "schema": "full-drainage-wallet-worker-result-v1",
        "action": command.action,
        "proofSeconds": started.elapsed().as_secs_f64(),
        "statementId": hex::encode(operation.statement.id()),
        "wireBytes": wire.len(),
        "wireSha256": hex::encode(hash(&wire)),
        "operation": operation
    }))
}

fn wallet_worker(store: &str, parameters: &str, expected: [u8; 32]) -> Result<()> {
    let store_path = Path::new(store);
    let restored = store_path.exists();
    let wallet = if restored {
        let raw = fs::read(store_path).map_err(|e| e.to_string())?;
        ensure(raw.len() == 64, "wallet store size")?;
        Wallet::restore_local(&raw.try_into().unwrap())
    } else {
        let wallet = Wallet::new();
        fs::write(store_path, wallet.local_backup()).map_err(|e| e.to_string())?;
        fs::set_permissions(store_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
        wallet
    };
    let load_started = Instant::now();
    let engine = Engine::from_public_parameters(
        &fs::read(parameters).map_err(|e| e.to_string())?,
        expected,
    )?;
    println!(
        "{}",
        json!({
            "schema": "full-drainage-wallet-worker-ready-v1",
            "restored": restored,
            "owner": hex::encode(wallet.address.owner),
            "incoming": hex::encode(wallet.address.incoming),
            "verifier": hex::encode(engine.id()),
            "parameterLoadSeconds": load_started.elapsed().as_secs_f64()
        })
    );
    io::stdout().flush().map_err(|e| e.to_string())?;
    for line in io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        if line.is_empty() {
            continue;
        }
        if line == "STOP" {
            return Ok(());
        }
        let result = serde_json::from_str::<WorkerCommand>(&line)
            .map_err(|e| e.to_string())
            .and_then(|command| prove_command(&engine, &wallet, command));
        match result {
            Ok(value) => println!("{}", value),
            Err(error) => println!("{}", json!({"error": error})),
        }
        io::stdout().flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DepositSpec {
    id: String,
    amount_sompi: u64,
    owner: String,
}

fn ledger_init(verifier: [u8; 32], deposits_path: &str, output: &str) -> Result<()> {
    ensure(!Path::new(output).exists(), "ledger output exists")?;
    let deposits: Vec<DepositSpec> = read_json(deposits_path)?;
    let mut ledger = Ledger::new(verifier);
    for deposit in deposits {
        ledger.register_authenticated_fixture_deposit(
            h(&deposit.id)?,
            deposit.amount_sompi,
            h(&deposit.owner)?,
        )?;
    }
    write_ledger(output, &ledger)
}

fn summary(ledger: &Ledger) -> Value {
    let pending_deposits: u64 = ledger
        .deposits
        .values()
        .filter(|deposit| deposit.status == 0)
        .map(|deposit| deposit.amount)
        .sum();
    let unpaid_exits: u64 = ledger
        .exits
        .values()
        .filter(|exit| !exit.paid)
        .map(|exit| exit.amount)
        .sum();
    json!({
        "state": hex::encode(ledger.state_hash()),
        "batch": ledger.batch,
        "treeLeaves": ledger.tree.leaves.len(),
        "nullifiers": ledger.nullifiers.len(),
        "deliveries": ledger.deliveries.len(),
        "reserveSompi": ledger.reserve,
        "privateLiabilitySompi": ledger.private_liability,
        "pendingDepositSompi": pending_deposits,
        "unpaidExitSompi": unpaid_exits,
        "paidNativeOutputs": ledger.paid_native_outputs.len()
    })
}

fn ledger_apply(
    vk: &str,
    expected: [u8; 32],
    input: &str,
    operation_path: &str,
    output: &str,
) -> Result<()> {
    ensure(!Path::new(output).exists(), "ledger output exists")?;
    let verifier = Verifier::from_bytes(&fs::read(vk).map_err(|e| e.to_string())?, expected)?;
    let mut ledger = read_ledger(input)?;
    let operation: Operation = read_json(operation_path)?;
    let before = summary(&ledger);
    let transition = ledger.apply(&verifier, &operation)?;
    ledger.next_batch()?;
    let after = summary(&ledger);
    write_ledger(output, &ledger)?;
    println!(
        "{}",
        json!({
            "schema": "full-drainage-ledger-apply-v1",
            "transition": hex::encode(transition),
            "before": before,
            "after": after
        })
    );
    Ok(())
}

fn ledger_payout(
    input: &str,
    exit_id: [u8; 32],
    amount: u64,
    destination: [u8; 32],
    native_output: [u8; 32],
    output: &str,
) -> Result<()> {
    ensure(!Path::new(output).exists(), "ledger output exists")?;
    let mut ledger = read_ledger(input)?;
    let before = summary(&ledger);
    ledger.confirm_authenticated_fixture_payout(exit_id, amount, destination, native_output)?;
    let after = summary(&ledger);
    write_ledger(output, &ledger)?;
    println!(
        "{}",
        json!({
            "schema": "full-drainage-ledger-payout-v1",
            "before": before,
            "after": after,
            "nativeOutput": hex::encode(native_output)
        })
    );
    Ok(())
}

fn real_main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("setup") if args.len() == 5 => setup(&args[2], &args[3], &args[4]),
        Some("wallet-worker") if args.len() == 5 => {
            wallet_worker(&args[2], &args[3], h(&args[4])?)
        }
        Some("ledger-init") if args.len() == 5 => {
            ledger_init(h(&args[2])?, &args[3], &args[4])?;
            let ledger = read_ledger(&args[4])?;
            println!("{}", summary(&ledger));
            Ok(())
        }
        Some("ledger-apply") if args.len() == 7 => {
            ledger_apply(&args[2], h(&args[3])?, &args[4], &args[5], &args[6])
        }
        Some("ledger-payout") if args.len() == 8 => ledger_payout(
            &args[2],
            h(&args[3])?,
            args[4].parse().map_err(|_| "amount")?,
            h(&args[5])?,
            h(&args[6])?,
            &args[7],
        ),
        Some("ledger-summary") if args.len() == 3 => {
            let ledger = read_ledger(&args[2])?;
            println!("{}", summary(&ledger));
            Ok(())
        }
        _ => Err("usage: setup PARAMS VK VK_UNCOMPRESSED | wallet-worker STORE PARAMS VK_ID | ledger-init VK_ID DEPOSITS OUT | ledger-apply VK VK_ID IN OP OUT | ledger-payout IN EXIT_ID AMOUNT DEST NATIVE_OUTPUT OUT | ledger-summary IN".into()),
    }
}

fn main() {
    if let Err(error) = real_main() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

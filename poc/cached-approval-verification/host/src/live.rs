// Small fresh TN10 rehearsal. Build and acceptance are separate one-shot steps.
use kaspa_rpc_core::{RpcTransaction, RpcUtxosByAddressesEntry};
#[derive(Clone, Copy)]
struct TrialValues {
    source: u64,
    bank: u64,
    principal: u64,
    denomination: u64,
}
fn trial_values(root: &Path) -> Result<TrialValues> {
    let trial = read(&root.join("trial.json"))?;
    Ok(if trial["fixture"] == "atomic-bundle-small" {
        TrialValues { source: 270_000_000, bank: 200_000_000, principal: 120_000_000,
                      denomination: 30_000_000 }
    } else {
        TrialValues { source: 700_000_000, bank: 600_000_000, principal: 400_000_000,
                      denomination: 100_000_000 }
    })
}
fn testnet_profile() -> Result<()> {
    if !cfg!(feature = "testnet") || DEPTH != 4 {
        return Err("dedicated TN10 profile required".into());
    }
    Ok(())
}
fn address(spk: &ScriptPublicKey) -> Result<String> {
    Ok(
        kaspa_txscript::extract_script_pub_key_address(spk, kaspa_addresses::Prefix::Testnet)?
            .to_string(),
    )
}
fn trial_actors(root: &Path) -> Result<Actors> {
    let t = read(&root.join("trial.json"))?;
    Ok(Actors {
        root: root.join("private"),
        params: t["parameters"].as_str().ok_or("parameters")?.into(),
        calls: vec![],
        processes: HashMap::new(),
    })
}
pub fn fresh_trial(program: &Path, params: &Path, root: &Path) -> Result<()> {
    fresh_trial_with_fixture(program, params, root, false)
}
pub fn fresh_board_trial(program: &Path, params: &Path, root: &Path) -> Result<()> {
    fresh_trial_with_fixture(program, params, root, true)
}
fn fresh_trial_with_fixture(program: &Path, params: &Path, root: &Path, board: bool) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    testnet_profile()?;
    fs::create_dir(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    fs::create_dir(root.join("private"))?;
    fs::set_permissions(root.join("private"), fs::Permissions::from_mode(0o700))?;
    fs::create_dir(root.join("cache"))?;
    fs::create_dir(root.join("programs"))?;
    for f in ["authorization.bin", "settlement.bin"] {
        let src = program.parent().ok_or("program parent")?.join(f);
        prover::write(&root.join("programs").join(f), &fs::read(src)?)?;
    }
    save(
        &root.join("trial.json"),
        &json!({"trial":hex::encode(fresh()),"network":"testnet-10","parameters":params.canonicalize()?,"walletDomain":hex::encode(domain()),"image":risc0_zkvm::compute_image_id(&fs::read(program)?)?.to_string(),"fixture":if board {"atomic-bundle-small"} else {"original"},"principalSompi":if board {120_000_000u64} else {400_000_000u64},"feeAllowanceSompi":if board {80_000_000u64} else {200_000_000u64},"fundingSourceSompi":if board {270_000_000u64} else {700_000_000u64},"scope":"fresh unfunded same-host experimental rehearsal; no production setup or privacy qualification"}),
    )?;
    let values = trial_values(root)?;
    let mut a = trial_actors(root)?;
    let mut wallets = vec![];
    for who in 0..4 {
        wallets.push(a.call(who, json!({"method":"public"}), None)?);
    }
    let raw: Vec<u8> = serde_json::from_value(wallets[0]["fundingSpk"].clone())?;
    save(
        &root.join("PUBLIC.json"),
        &json!({"wallets":wallets,"fundingAddress":address(&native::spk(&raw))?,"fundingSompi":values.source,"unfunded":true}),
    )?;
    println!("Fresh unfunded trial created at {}", root.display());
    Ok(())
}
fn rpc_entry(snapshot: &Value, point: TransactionOutpoint) -> Result<(Value, UtxoEntry)> {
    if snapshot["server"]["networkId"] != "testnet-10"
        || snapshot["witnessServer"]["networkId"] != "testnet-10"
        || snapshot["server"]["isSynced"] != true
        || snapshot["witnessServer"]["isSynced"] != true
    {
        return Err("two synchronized TN10 routes required".into());
    }
    for raw in snapshot["utxos"]["entries"]
        .as_array()
        .ok_or("UTXO entries")?
    {
        let e: RpcUtxosByAddressesEntry = serde_json::from_value(raw.clone())?;
        if TransactionOutpoint::from(e.outpoint) == point {
            return Ok((raw.clone(), e.utxo_entry.into()));
        }
    }
    Err("expected actual unspent source missing".into())
}
fn envelope(tx: &Transaction, entry: &UtxoEntry, raw: &Value, out: &Path) -> Result<()> {
    let mut report = native::validate(tx, entry)?;
    report["allInputScriptsExecuted"] = json!(true);
    report["transactionId"] = json!(tx.id().to_string());
    let rpc = RpcTransaction::from(tx);
    let encoded = serde_json::to_value(&rpc)?;
    let decoded: RpcTransaction = serde_json::from_value(encoded.clone())?;
    let roundtrip: Transaction = decoded.try_into()?;
    if &roundtrip != tx {
        return Err("exact SDK transaction roundtrip".into());
    }
    save(
        out,
        &json!({"record":{"transactionId":tx.id().to_string(),"transaction":encoded},"entries":[raw],"qualification":report,"outputAddresses":tx.outputs.iter().map(|o|address(&o.script_public_key)).collect::<Result<Vec<_>>>()?}),
    )?;
    Ok(())
}
pub fn ordinary_test_funding(
    trial: &Path,
    snapshot: &Path,
    keyfile: &Path,
    out: &Path,
) -> Result<()> {
    testnet_profile()?;
    let values = trial_values(trial)?;
    let public = read(&trial.join("PUBLIC.json"))?;
    let snapshot = read(snapshot)?;
    let secret = SecretKey::from_slice(&hex::decode(fs::read_to_string(keyfile)?.trim())?)?;
    let own = recipient(&secret);
    let raw = snapshot["utxos"]["entries"]
        .as_array()
        .ok_or("UTXO entries")?
        .iter()
        .find(|raw| {
            serde_json::from_value::<RpcUtxosByAddressesEntry>((*raw).clone()).is_ok_and(|e| {
                e.utxo_entry.script_public_key == own
                    && !e.utxo_entry.is_coinbase
                    && e.utxo_entry.covenant_id.is_none()
                    && e.utxo_entry.amount > values.source + 10_000_000
            })
        })
        .ok_or("owned ordinary test fee source unavailable")?;
    let e: RpcUtxosByAddressesEntry = serde_json::from_value(raw.clone())?;
    let point: TransactionOutpoint = e.outpoint.into();
    let (_, entry) = rpc_entry(&snapshot, point)?;
    let destination: kaspa_addresses::Address = public["fundingAddress"]
        .as_str()
        .ok_or("test address")?
        .try_into()?;
    if destination.prefix != kaspa_addresses::Prefix::Testnet {
        return Err("TN10 destination required".into());
    }
    let mut tx = native::transaction(
        point,
        vec![
            TransactionOutput::new(
                values.source,
                kaspa_txscript::pay_to_address_script(&destination),
            ),
            TransactionOutput::new(entry.amount - values.source, own),
        ],
        vec![],
        20,
    );
    tx.inputs[0].signature_script = vec![0; 66];
    let fee = native::quote(&tx, &entry)["minimumDefaultRelayFeeSompi"]
        .as_u64()
        .ok_or("funding fee")?;
    tx.outputs[1].value = tx.outputs[1]
        .value
        .checked_sub(fee)
        .ok_or("funding change")?;
    let pop = PopulatedTransaction::new(&tx, vec![entry.clone()]);
    tx.inputs[0].signature_script = kaspa_consensus_core::sign::sign_input(
        &pop,
        0,
        &secret.secret_bytes(),
        kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL,
    );
    tx.finalize();
    envelope(&tx, &entry, raw, out)
}
/// Publish the complete blind-reply board through an ordinary testnet transaction.
/// The key belongs to the separate ordinary test funding source, never the bank.
#[cfg(feature = "round-agreement")]
pub fn bundle_build(trial: &Path, snapshot: &Path, keyfile: &Path, out: &Path) -> Result<()> {
    testnet_profile()?;
    if trial_values(trial)?.denomination != 30_000_000 {
        return Err("small board fixture required".into());
    }
    let payload = fs::read(trial.join("registration/bundle.json"))?;
    if payload.len() > 25_000 || payload.len() < 1_000 {
        return Err("bundle payload size".into());
    }
    let config = read(&trial.join("registration/config.json"))?;
    crate::agreement::verify_board_public(&config, &trial.join("registration/bundle.json"))?;
    let snapshot = read(snapshot)?;
    let secret = SecretKey::from_slice(&hex::decode(fs::read_to_string(keyfile)?.trim())?)?;
    let own = recipient(&secret);
    let raw = snapshot["utxos"]["entries"].as_array().ok_or("UTXO entries")?.iter()
        .find(|raw| serde_json::from_value::<RpcUtxosByAddressesEntry>((*raw).clone())
            .is_ok_and(|e| e.utxo_entry.script_public_key == own && !e.utxo_entry.is_coinbase
                && e.utxo_entry.covenant_id.is_none() && e.utxo_entry.amount > 10_000_000))
        .ok_or("ordinary source change unavailable for bundle fee")?;
    let e: RpcUtxosByAddressesEntry = serde_json::from_value(raw.clone())?;
    let point: TransactionOutpoint = e.outpoint.into();
    let (_, entry) = rpc_entry(&snapshot, point)?;
    let mut tx = native::transaction(point, vec![TransactionOutput::new(entry.amount, own)], payload, 20);
    tx.inputs[0].signature_script = vec![0; 66];
    let fee = native::quote(&tx, &entry)["minimumDefaultRelayFeeSompi"].as_u64().ok_or("bundle fee")?;
    tx.outputs[0].value = tx.outputs[0].value.checked_sub(fee).ok_or("bundle change")?;
    let pop = PopulatedTransaction::new(&tx, vec![entry.clone()]);
    tx.inputs[0].signature_script = kaspa_consensus_core::sign::sign_input(
        &pop, 0, &secret.secret_bytes(),
        kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL,
    );
    tx.finalize();
    envelope(&tx, &entry, raw, out)
}
/// Refill the ordinary TN10 fee source from already paid, owner-held test
/// outputs of a *completed* earlier rehearsal. Never touches a bank reserve.
pub fn sweep_prior_test_payouts(prior: &Path, snapshot: &Path, destination: &Path, out: &Path) -> Result<()> {
    use std::collections::HashSet;
    testnet_profile()?;
    let complete = read(&prior.join("COMPLETE.json"))?;
    if complete["freshTN10RehearsalComplete"] != true
        || complete["terminalBankValueSompi"] != 0
        || complete["confirmedRestoredPayoutSpends"] != 5 {
        return Err("completed prior payouts required".into());
    }
    let destination: kaspa_addresses::Address = fs::read_to_string(destination)?.trim().try_into()?;
    if destination.prefix != kaspa_addresses::Prefix::Testnet { return Err("TN10 sweep destination required".into()); }
    let destination = kaspa_txscript::pay_to_address_script(&destination);
    let snapshot = read(snapshot)?;
    if snapshot["server"]["networkId"] != "testnet-10" || snapshot["witnessServer"]["networkId"] != "testnet-10"
        || snapshot["server"]["isSynced"] != true || snapshot["witnessServer"]["isSynced"] != true {
        return Err("two synchronized TN10 routes required".into());
    }
    let mut paid = HashSet::new();
    for i in 0..5 {
        let envelope = read(&prior.join(format!("recovery-{i}-envelope.json")))?;
        let accepted = read(&prior.join(format!("recovery-{i}-accepted.json")))?;
        check_accepted(&envelope, &accepted)?;
        paid.insert(envelope["record"]["transactionId"].as_str().ok_or("paid tx")?.to_string());
    }
    let mut keys = vec![];
    for who in 0..4 {
        let backup = read(&prior.join(format!("private/wallet-{who}/backup.json")))?;
        for value in backup["payouts"].as_object().ok_or("payout keys")?.values() {
            let bytes: Vec<u8> = serde_json::from_value(value.clone())?;
            keys.push(SecretKey::from_slice(&bytes)?);
        }
    }
    let mut inputs = vec![];
    for raw in snapshot["utxos"]["entries"].as_array().ok_or("UTXO entries")? {
        let rpc: RpcUtxosByAddressesEntry = serde_json::from_value(raw.clone())?;
        if !paid.contains(&rpc.outpoint.transaction_id.to_string()) { continue; }
        let matching = keys.iter().filter(|k| recipient(k) == rpc.utxo_entry.script_public_key).collect::<Vec<_>>();
        if matching.len() != 1 || rpc.utxo_entry.is_coinbase || rpc.utxo_entry.covenant_id.is_some() {
            return Err("prior paid output ownership mismatch".into());
        }
        let point: TransactionOutpoint = rpc.outpoint.into();
        let (_, entry) = rpc_entry(&snapshot, point)?;
        inputs.push(SweepInput { raw: raw.clone(), entry, key: *matching[0], point });
    }
    if inputs.len() != 5 { return Err("all five paid test outputs required".into()); }
    sign_test_sweep(inputs,destination,out,300_000_000)
}
struct SweepInput { raw: Value, entry: UtxoEntry, key: SecretKey, point: TransactionOutpoint }
fn sign_test_sweep(inputs: Vec<SweepInput>, destination: ScriptPublicKey, out: &Path, minimum: u64) -> Result<()> {
    use kaspa_consensus::processes::transaction_validator::{TransactionValidator, tx_validation_in_utxo_context::TxValidationFlags};
    use kaspa_consensus_core::{config::params::TESTNET_PARAMS, mass::MassCalculator};
    use std::sync::Arc;
    let total: u64 = inputs.iter().map(|i|i.entry.amount).sum();
    if total < minimum { return Err("insufficient owned test outputs".into()); }
    let entries = inputs.iter().map(|i|i.entry.clone()).collect::<Vec<_>>();
    let mut tx = Transaction::new(1,
        inputs.iter().map(|i| TransactionInput::new_with_compute_budget(i.point,vec![0;66],0,20)).collect(),
        vec![TransactionOutput::new(total,destination)],0,Default::default(),0,vec![]);
    let calc = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let estimate = calc.calc_non_contextual_masses(&tx);
    let required = estimate.compute_mass.max(estimate.normalized_transient(&TESTNET_PARAMS.block_mass_limits.cofactors()))*100;
    tx.outputs[0].value = total.checked_sub(required + 100_000).ok_or("sweep fee")?;
    let pop = PopulatedTransaction::new(&tx, entries.clone());
    let signatures = inputs.iter().enumerate().map(|(i,input)|
        kaspa_consensus_core::sign::sign_input(
            &pop,i,&input.key.secret_bytes(),kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL)
    ).collect::<Vec<_>>();
    for (input, signature) in tx.inputs.iter_mut().zip(signatures) {
        input.signature_script = signature;
    }
    tx.finalize();
    let calc = MassCalculator::new_with_consensus_params(&TESTNET_PARAMS);
    let context = calc.calc_contextual_masses(&PopulatedTransaction::new(&tx, entries.clone())).ok_or("sweep mass")?;
    tx.set_storage_mass(context.storage_mass);
    let validator = TransactionValidator::new(
        TESTNET_PARAMS.max_tx_inputs,TESTNET_PARAMS.max_tx_outputs,TESTNET_PARAMS.max_signature_script_len,
        TESTNET_PARAMS.max_script_public_key_len,TESTNET_PARAMS.coinbase_payload_script_public_key_max_len,
        TESTNET_PARAMS.coinbase_maturity(),TESTNET_PARAMS.ghostdag_k(),
        Arc::new(kaspa_txscript::caches::TxScriptCacheCounters::default()),
        MassCalculator::new_with_consensus_params(&TESTNET_PARAMS),TESTNET_PARAMS.mass_per_sig_op);
    validator.validate_tx_in_isolation(&tx)?;
    let actual_fee = validator.validate_populated_transaction_and_get_fee(
        &PopulatedTransaction::new(&tx, entries.clone()),1_000_000_000,1_000_000_000,
        TxValidationFlags::Full,None,None)?;
    if actual_fee < required { return Err("sweep below relay fee".into()); }
    let rpc = serde_json::to_value(RpcTransaction::from(&tx))?;
    let decoded: Transaction = serde_json::from_value::<RpcTransaction>(rpc.clone())?.try_into()?;
    if decoded != tx { return Err("sweep exact RPC roundtrip".into()); }
    save(out,&json!({"record":{"transactionId":tx.id().to_string(),"transaction":rpc},"entries":inputs.iter().map(|i|i.raw.clone()).collect::<Vec<_>>(),
        "qualification":{"transactionId":tx.id().to_string(),"allInputScriptsExecuted":true,"nativeFullValidation":true,"feeSompi":actual_fee},
        "outputAddresses":[address(&tx.outputs[0].script_public_key)?]}))?;
    Ok(())
}
const LIVE_PHASES: [&str; 5] = ["fund", "initial", "external", "withdrawal", "terminal"];
fn saved_world(root: &Path) -> Result<World> {
    let phase = LIVE_PHASES
        .iter()
        .rev()
        .find(|phase| root.join(format!("WORLD-{phase}.json")).is_file())
        .ok_or("no accepted bank history")?;
    let v = read(&root.join(format!("WORLD-{phase}.json")))?;
    let state: app::State = from_hex(&v["state"])?;
    let point: TransactionOutpoint = from_hex(&v["point"])?;
    let entry: UtxoEntry = from_hex(&v["entry"])?;
    Ok(World {
        state,
        point,
        value: v["value"].as_u64().ok_or("bank value")?,
        active: HashMap::from([(point, entry)]),
        records: serde_json::from_value(v["records"].clone())?,
    })
}
fn save_world(root: &Path, phase: &str, world: &World) -> Result<()> {
    let entry = if world.value == 0 {
        UtxoEntry::new(0, ScriptPublicKey::default(), 0, false, None)
    } else {
        world.entry()?
    };
    save(
        &root.join(format!("WORLD-{phase}.json")),
        &json!({"state":hex::encode(bincode::serialize(&world.state)?),"point":hex::encode(bincode::serialize(&world.point)?),"entry":hex::encode(bincode::serialize(&entry)?),"value":world.value,"records":world.records}),
    )
}
pub fn live_build(root: &Path, phase: &str, snapshot: &Path) -> Result<()> {
    testnet_profile()?;
    let values = trial_values(root)?;
    let n = LIVE_PHASES
        .iter()
        .position(|p| *p == phase)
        .ok_or("phase")?;
    if root.join(format!("WORLD-{phase}.json")).exists() {
        return Err("used phase; no rebuild or rebroadcast".into());
    }
    if n > 0
        && !root
            .join(format!("WORLD-{}.json", LIVE_PHASES[n - 1]))
            .is_file()
    {
        return Err("previous phase not accepted".into());
    }
    let program = root.join("programs/settlement.bin");
    let auth = root.join("programs/authorization.bin");
    let policy = Policy {
        image: risc0_zkvm::compute_image_id(&fs::read(&program)?)?
            .as_bytes()
            .try_into()?,
    };
    let snapshot = read(snapshot)?;
    let mut actors = trial_actors(root)?;
    let public = read(&root.join("PUBLIC.json"))?;
    let addresses = public["wallets"].as_array().ok_or("wallets")?;
    if phase == "fund" {
        let refund: Vec<u8> = serde_json::from_value(addresses[0]["fundingSpk"].clone())?;
        let own = native::spk(&refund);
        let raw = snapshot["utxos"]["entries"]
            .as_array()
            .ok_or("UTXO entries")?
            .iter()
            .find(|raw| {
                serde_json::from_value::<RpcUtxosByAddressesEntry>((*raw).clone()).is_ok_and(|e| {
                    e.utxo_entry.amount == values.source
                        && e.utxo_entry.script_public_key == own
                        && !e.utxo_entry.is_coinbase
                        && e.utxo_entry.covenant_id.is_none()
                })
            })
            .ok_or("fresh exact ordinary trial funding missing")?;
        let e: RpcUtxosByAddressesEntry = serde_json::from_value(raw.clone())?;
        let point: TransactionOutpoint = e.outpoint.into();
        let (_, entry) = rpc_entry(&snapshot, point)?;
        let vk = app::WALLET_VK.to_vec();
        let mut ledger = Ledger::new(hash(&vk));
        let pool = hash(
            &[
                b"KPI-fresh-TN10-inline-bank-v1\0".as_slice(),
                point.transaction_id.as_bytes().as_slice(),
                &point.index.to_le_bytes(),
            ]
            .concat(),
        );
        ledger.register_authenticated_fixture_deposit(
            pool,
            values.principal,
            serde_json::from_value(addresses[0]["owner"].clone())?,
        )?;
        let state = app::State {
            ledger,
            pool,
            wallet_vk: vk,
            fee_refund_spk: refund,
        };
        let mut tx = native::transaction(
            point,
            vec![
                TransactionOutput::new(values.bank, policy.spk(state.root())),
                TransactionOutput::new(values.source - values.bank, own),
            ],
            bincode::serialize(&state)?,
            20,
        );
        tx.inputs[0].signature_script = vec![0; 66];
        let fee = native::quote(&tx, &entry)["minimumDefaultRelayFeeSompi"]
            .as_u64()
            .ok_or("fee")?;
        tx.outputs[1].value -= fee;
        tx.finalize();
        let signed=actors.call(0,json!({"method":"sign","funding":true,"smallTrial":true,"tinyTrial":values.principal==120_000_000,"image":policy.image,"transaction":hex::encode(bincode::serialize(&tx)?),"entry":hex::encode(bincode::serialize(&entry)?)}),None)?;
        tx = bincode::deserialize(&hex::decode(
            signed["transaction"].as_str().ok_or("signed")?,
        )?)?;
        save(
            &root.join("fund-STATE.json"),
            &json!({"state":hex::encode(bincode::serialize(&state)?),"transaction":tx,"entry":hex::encode(bincode::serialize(&entry)?),"report":native::validate(&tx,&entry)?}),
        )?;
        envelope(&tx, &entry, raw, &root.join("fund-envelope.json"))?;
        return Ok(());
    }
    let mut world = saved_world(root)?;
    let (raw, entry) = rpc_entry(&snapshot, world.point)?;
    if entry.amount != world.value
        || entry.script_public_key != policy.spk(world.state.root())
        || entry.covenant_id.is_some()
    {
        return Err("actual bank UTXO does not match accepted state".into());
    }
    world.active.insert(world.point, entry.clone());
    let step = match phase {
        "initial" => {
            let mut projected = world.state.clone();
            let mut ops = actors.operations(0, json!({"method":"credit"}), &projected)?;
            for op in &ops {
                projected.ledger.apply(&public_verifier(&projected)?, op)?;
            }
            for (who, to, input, amount) in [
                (0, 1, values.principal, values.principal / 2),
                (1, 2, values.principal / 2, values.denomination),
                (0, 3, values.principal / 2, values.denomination),
            ] {
                ops.extend(transfers(
                    &mut actors,
                    who,
                    &mut projected,
                    &addresses[to],
                    input,
                    amount,
                )?);
            }
            payment(&policy, &world, ops)?
        }
        "external" => {
            let mut projected = world.state.clone();
            let ops = transfers(
                &mut actors,
                3,
                &mut projected,
                &addresses[0],
                values.denomination,
                values.denomination / 5,
            )?;
            payment(&policy, &world, ops)?
        }
        "withdrawal" => {
            let a = read(&root.join("APPROVALS.json"))?;
            let intent: app::WithdrawalIntent = serde_json::from_value(a["intent"].clone())?;
            let ops: Vec<Operation> = serde_json::from_value(a["operations"].clone())?;
            intent_step(&policy, &world, &intent, &ops, 0)?
        }
        "terminal" => {
            let mut ops = vec![];
            let mut payouts = vec![];
            for who in 0..4 {
                let r = actors.call(who, json!({"method":"named"}), Some(&world.state))?;
                ops.extend(serde_json::from_value::<Vec<Operation>>(
                    r["operations"].clone(),
                )?);
                for p in r["payouts"].as_array().ok_or("payouts")? {
                    payouts.push(TransactionOutput::new(
                        p["value"].as_u64().ok_or("value")?,
                        native::spk(&serde_json::from_value::<Vec<u8>>(p["spk"].clone())?),
                    ));
                }
            }
            if ops.len() != 2 {
                return Err("two final owned notes required".into());
            }
            named(&policy, &world, ops, payouts)?
        }
        _ => return Err("invalid stage".into()),
    };
    cached_settle(&auth, &program, &policy, &mut world, step, root, phase)?;
    let record = world.records.last().ok_or("record")?;
    let tx = read_transaction(&record["transaction"])?;
    envelope(
        &tx,
        &entry,
        &raw,
        &root.join(format!("{phase}-envelope.json")),
    )?;
    Ok(())
}
fn check_accepted(envelope: &Value, accepted: &Value) -> Result<Transaction> {
    if accepted["confirmed"].as_u64().unwrap_or(0) < 10
        || accepted["transactionId"] != envelope["record"]["transactionId"]
    {
        return Err("ten-confirmation exact acceptance required".into());
    }
    let expected: RpcTransaction =
        serde_json::from_value(envelope["record"]["transaction"].clone())?;
    let expected: Transaction = expected.try_into()?;
    let actual: RpcTransaction = serde_json::from_value(accepted["transaction"].clone())?;
    let actual: Transaction = actual.try_into()?;
    if expected != actual {
        return Err("accepted native body differs from exact locally validated transaction".into());
    }
    Ok(actual)
}
pub fn live_accept(root: &Path, phase: &str, accepted: &Path) -> Result<()> {
    testnet_profile()?;
    if !LIVE_PHASES.contains(&phase) {
        return Err("phase".into());
    }
    let envelope = read(&root.join(format!("{phase}-envelope.json")))?;
    let accepted = read(accepted)?;
    let tx = check_accepted(&envelope, &accepted)?;
    let world = if phase == "fund" {
        let record = read(&root.join("fund-STATE.json"))?;
        let state: app::State = from_hex(&record["state"])?;
        let point = TransactionOutpoint::new(tx.id(), 0);
        let entry = UtxoEntry::new(
            tx.outputs[0].value,
            tx.outputs[0].script_public_key.clone(),
            accepted["header"]["daaScore"].as_u64().ok_or("DAA")?,
            false,
            None,
        );
        World {
            state,
            point,
            value: entry.amount,
            active: HashMap::from([(point, entry)]),
            records: vec![
                json!({"kind":"deposit","transaction":tx,"sourceEntryBincodeHex":record["entry"],"report":record["report"],"confirmed":10}),
            ],
        }
    } else {
        let mut world = saved_world(root)?;
        let record = read(&root.join(phase).join("TRANSACTION.json"))?;
        let step = recorded_step(&record)?;
        if step.tx != tx {
            return Err("accepted receipt transaction mismatch".into());
        }
        world.accept(&step)?;
        world
    };
    save_world(root, phase, &world)?;
    save(&root.join(format!("{phase}-ACCEPTED.json")), &accepted)?;
    println!(
        "{}",
        json!({"phase":phase,"accepted":true,"reserve":world.state.ledger.reserve,"liability":world.state.ledger.private_liability})
    );
    Ok(())
}
/// Safe owner-authorized ordinary exits from a stopped research trial.
/// This is recovery of test KAS, never a retry of its failed privacy claim.
pub fn reclaim_build(root: &Path, snapshot: &Path) -> Result<()> {
    testnet_profile()?;
    if !root.join("FAILURE.json").is_file() || !root.join("WORLD-initial.json").is_file()
        || root.join("WORLD-external.json").exists() || root.join("reclaim-envelope.json").exists() {
        return Err("stopped initial-only trial required".into());
    }
    let mut world = saved_world(root)?;
    let snapshot = read(snapshot)?;
    let (raw, entry) = rpc_entry(&snapshot, world.point)?;
    let program = root.join("programs/settlement.bin");
    let auth = root.join("programs/authorization.bin");
    let policy = Policy { image: risc0_zkvm::compute_image_id(&fs::read(&program)?)?.as_bytes().try_into()? };
    if entry.amount != world.value || entry.script_public_key != policy.spk(world.state.root()) {
        return Err("accepted bank differs from stopped state".into());
    }
    world.active.insert(world.point, entry.clone());
    let mut actors = trial_actors(root)?;
    let mut ops = vec![];
    let mut payouts = vec![];
    for who in 0..4 {
        let reply = actors.call(who,json!({"method":"named"}),Some(&world.state))?;
        ops.extend(serde_json::from_value::<Vec<Operation>>(reply["operations"].clone())?);
        for p in reply["payouts"].as_array().ok_or("payouts")? {
            payouts.push(TransactionOutput::new(p["value"].as_u64().ok_or("value")?,
                native::spk(&serde_json::from_value::<Vec<u8>>(p["spk"].clone())?)));
        }
    }
    if ops.len() != 4 || payouts.len() != 4 || payouts.iter().map(|p|p.value).sum::<u64>() != trial_values(root)?.principal {
        return Err("four complete owner-authorized payouts required".into());
    }
    let step = named(&policy,&world,ops,payouts)?;
    cached_settle(&auth,&program,&policy,&mut world,step,root,"reclaim")?;
    let record = world.records.last().ok_or("reclaim record")?;
    envelope(&read_transaction(&record["transaction"])?,&entry,&raw,&root.join("reclaim-envelope.json"))?;
    Ok(())
}
pub fn reclaim_accept(root: &Path, accepted: &Path) -> Result<()> {
    testnet_profile()?;
    if root.join("WORLD-reclaim.json").exists() { return Err("reclaim already accepted".into()); }
    let tx = check_accepted(&read(&root.join("reclaim-envelope.json"))?,&read(accepted)?)?;
    let mut world = saved_world(root)?;
    let record = read(&root.join("reclaim/TRANSACTION.json"))?;
    let step = recorded_step(&record)?;
    if step.tx != tx { return Err("accepted reclaim differs from authorized step".into()); }
    world.accept(&step)?;
    if world.value != 0 || world.state.ledger.reserve != 0 || world.state.ledger.private_liability != 0 {
        return Err("reclaim did not fully drain reserve".into());
    }
    save_world(root,"reclaim",&world)?;
    save(&root.join("reclaim-ACCEPTED.json"),&read(accepted)?)?;
    Ok(())
}
pub fn sweep_reclaimed_test_kas(root: &Path, snapshot: &Path, source_key: &Path, out: &Path) -> Result<()> {
    testnet_profile()?;
    let world = read(&root.join("WORLD-reclaim.json"))?;
    if world["value"] != 0 { return Err("reclaim reserve remains".into()); }
    let envelope = read(&root.join("reclaim-envelope.json"))?;
    let accepted = read(&root.join("reclaim-ACCEPTED.json"))?;
    let tx = check_accepted(&envelope,&accepted)?;
    if tx.outputs.len() != 5 { return Err("four payouts and one refund required".into()); }
    let snapshot = read(snapshot)?;
    if snapshot["server"]["networkId"] != "testnet-10" || snapshot["witnessServer"]["networkId"] != "testnet-10"
        || snapshot["server"]["isSynced"] != true || snapshot["witnessServer"]["isSynced"] != true {
        return Err("two synchronized TN10 routes required".into());
    }
    let source = SecretKey::from_slice(&hex::decode(fs::read_to_string(source_key)?.trim())?)?;
    let destination = recipient(&source);
    let mut keys = vec![];
    for who in 0..4 {
        let backup = read(&root.join(format!("private/wallet-{who}/backup.json")))?;
        let funding: Vec<u8> = serde_json::from_value(backup["funding"].clone())?;
        keys.push(SecretKey::from_slice(&funding)?);
        for value in backup["payouts"].as_object().ok_or("payout keys")?.values() {
            let bytes: Vec<u8> = serde_json::from_value(value.clone())?;
            keys.push(SecretKey::from_slice(&bytes)?);
        }
    }
    let mut inputs = vec![];
    let mut source_count = 0;
    let mut reclaimed = std::collections::HashSet::new();
    for raw in snapshot["utxos"]["entries"].as_array().ok_or("UTXO entries")? {
        let rpc: RpcUtxosByAddressesEntry = serde_json::from_value(raw.clone())?;
        if rpc.utxo_entry.is_coinbase || rpc.utxo_entry.covenant_id.is_some() { continue; }
        let point: TransactionOutpoint = rpc.outpoint.into();
        let key = if point.transaction_id == tx.id() {
            let output = tx.outputs.get(point.index as usize).ok_or("reclaim output index")?;
            if output.value != rpc.utxo_entry.amount || output.script_public_key != rpc.utxo_entry.script_public_key {
                return Err("accepted reclaim output mismatch".into());
            }
            let matching = keys.iter().filter(|k| recipient(k) == rpc.utxo_entry.script_public_key).collect::<Vec<_>>();
            if matching.len() != 1 || !reclaimed.insert(point.index) { return Err("reclaim owner mismatch".into()); }
            *matching[0]
        } else if rpc.utxo_entry.script_public_key == destination && rpc.utxo_entry.amount > 100_000_000 {
            source_count += 1;
            source
        } else { continue; };
        let (_, entry) = rpc_entry(&snapshot,point)?;
        inputs.push(SweepInput { raw: raw.clone(), entry, key, point });
    }
    if reclaimed.len() != tx.outputs.len() || source_count != 1 {
        return Err("complete accepted reclaim plus one ordinary source change required".into());
    }
    sign_test_sweep(inputs,destination,out,280_000_000)
}
pub fn live_approvals(root: &Path, transport: &Path) -> Result<()> {
    testnet_profile()?;
    if !root.join("WORLD-initial.json").is_file() || root.join("WORLD-external.json").exists() {
        return Err("prepare approvals exactly after accepted initial payments".into());
    }
    let world = saved_world(root)?;
    let values = trial_values(root)?;
    let board = values.denomination == 30_000_000;
    let registration = root.join("registration");
    let config = crate::anonymous::new_round_for(&world.state, values.denomination, &registration)?;
    let transport = read(transport)?;
    let mut actors = trial_actors(root)?;
    let mut server = Command::new(std::env::current_exe()?)
        .args([
            if board { "serve-board" } else { "serve" },
            registration.join("config.json").to_str().unwrap(),
            registration.join("private/issuer.der").to_str().unwrap(),
            registration.join("operator.jsonl").to_str().unwrap(),
            &transport["servicePort"].as_u64().ok_or("port")?.to_string(),
        ])
        .args(if board { vec![registration.join("bundle.json")] } else { vec![] })
        .stderr(fs::File::create(registration.join("server.log"))?)
        .spawn()?;
    let result = (|| -> Result<()> {
        while !fs::read_to_string(registration.join("server.log"))?.contains("COORDINATOR_READY") {
            if server.try_wait()?.is_some() {
                return Err("registration server stopped".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let mut claims = vec![];
        if board {
            // The board server cannot reply until all three issue connections
            // arrive. Distinct wallet processes therefore issue concurrently.
            let handles = [2, 0, 1].into_iter().map(|who| {
                let trial = root.to_path_buf();
                let state = world.state.clone();
                let config = config.clone();
                let transport = transport.clone();
                std::thread::spawn(move || -> std::result::Result<H, String> {
                    let mut wallet = trial_actors(&trial).map_err(|e| e.to_string())?;
                    let reply = wallet.call(who, json!({"method":"registration-issue","config":config,
                        "onion":transport["onion"],"socks":transport["socks"]}), Some(&state))
                        .map_err(|e| e.to_string())?;
                    serde_json::from_value::<H>(reply["nullifier"].clone()).map_err(|e| e.to_string())
                })
            }).collect::<Vec<_>>();
            for handle in handles { claims.push(handle.join().map_err(|_| "claim thread panic")??); }
        } else {
            for who in [2, 0, 1] {
                let r=actors.call(who,json!({"method":"registration-issue","config":config,"onion":transport["onion"],"socks":transport["socks"]}),Some(&world.state))?;
                claims.push(serde_json::from_value::<H>(r["nullifier"].clone())?);
            }
        }
        if board {
            // The driver publishes the complete bundle and three independent
            // wallet readers write the accepted bytes into each private dir.
            for who in 0..3 {
                let accepted = root.join(format!("private/wallet-{who}/accepted-bundle.json"));
                while !accepted.is_file() {
                    if server.try_wait()?.is_some() { return Err("board server stopped".into()); }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                if fs::read(&accepted)? != fs::read(registration.join("bundle.json"))? {
                    return Err("wallet accepted bytes differ from published bundle".into());
                }
            }
        }
        for who in [1, 2, 0] {
            actors.call(who,json!({"method":if board {"registration-redeem-board"} else {"registration-redeem"},"config":config,"onion":transport["onion"],"socks":transport["socks"]}),None)?;
        }
        let mut payouts = vec![];
        for line in fs::read_to_string(registration.join("operator.jsonl"))?.lines() {
            let v: Value = serde_json::from_str(line)?;
            if v["request"]["kind"] == "redeem" && v["response"]["error"].is_null() {
                payouts.push(
                    [
                        vec![0, 0, 32],
                        hex::decode(v["response"]["recipientKey"].as_str().ok_or("key")?)?,
                        vec![0xac],
                    ]
                    .concat(),
                );
            }
        }
        if payouts.len() != 3 {
            return Err("three protected outputs required".into());
        }
        claims.sort();
        payouts.sort();
        let intent = app::WithdrawalIntent {
            protocol_domain: domain(),
            pool: world.state.pool,
            verifier: world.state.ledger.verifier,
            reference_anchor: world.state.ledger.tree.root(),
            nonce: fresh(),
            refund_key_hash: hash(&world.state.fee_refund_spk),
            denomination: values.denomination,
            fee_cap: 20_000_000,
            claims,
            payouts,
        };
        let mut operations = vec![];
        for who in 0..3 {
            operations.extend(actors.operations(
                who,
                json!({"method":"approve","intent":intent}),
                &world.state,
            )?);
        }
        operations.sort_by_key(|o| o.statement.nullifier);
        save(
            &root.join("APPROVALS.json"),
            &json!({"intent":intent,"hash":approval_digest(&operations),"operations":operations,"originalOwnerApprovals":3}),
        )?;
        let program = root.join("programs/settlement.bin");
        let policy = Policy {
            image: risc0_zkvm::compute_image_id(&fs::read(&program)?)?
                .as_bytes()
                .try_into()?,
        };
        let step = intent_step(&policy, &world, &intent, &operations, 0)?;
        let (cache, child) = cache_begin(&root.join("programs/authorization.bin"), &step, root)?;
        if let Some(mut child) = child {
            if !child.wait()?.success() {
                return Err("live approval cache failed".into());
            }
        }
        save(
            &root.join("APPROVAL-CACHE.json"),
            &json!({"path":cache,"journalHex":hex::encode(app::authorization_journal(&step.input)?)}),
        )?;
        Ok(())
    })();
    let _ = server.kill();
    let _ = server.wait();
    result
}
pub fn live_recovery(root: &Path, snapshot: &Path) -> Result<()> {
    testnet_profile()?;
    let world = saved_world(root)?;
    if world.state.ledger.reserve != 0
        || world.state.ledger.private_liability != 0
        || world.value != 0
    {
        return Err("bank not fully drained".into());
    }
    let snapshot = read(snapshot)?;
    let mut actors = trial_actors(root)?;
    let mut count = 0;
    for record in &world.records[1..] {
        let tx = read_transaction(&record["transaction"])?;
        for (index, o) in tx.outputs.iter().enumerate() {
            if native::encoded(&o.script_public_key).len() != 36
                || native::encoded(&o.script_public_key) == world.state.fee_refund_spk
            {
                continue;
            }
            let point = TransactionOutpoint::new(tx.id(), index as u32);
            let (raw, entry) = rpc_entry(&snapshot, point)?;
            if entry.amount != o.value || entry.script_public_key != o.script_public_key {
                return Err("actual payout differs from accepted principal".into());
            }
            let encoded = hex::encode(bincode::serialize(&entry)?);
            let mut owners = vec![];
            for who in 0..4 {
                if actors.call(who, json!({"method":"owns","entry":encoded}), None)?["owns"] == true
                {
                    owners.push(who);
                }
            }
            if owners.len() != 1 {
                return Err("restored payout owner".into());
            }
            let mut spend = native::transaction(point, vec![o.clone()], vec![], 20);
            spend.inputs[0].signature_script = vec![0; 66];
            let fee = native::quote(&spend, &entry)["minimumDefaultRelayFeeSompi"]
                .as_u64()
                .ok_or("fee")?;
            spend.outputs[0].value = spend.outputs[0]
                .value
                .checked_sub(fee)
                .ok_or("payout after fee")?;
            spend.finalize();
            let signed=actors.call(owners[0],json!({"method":"sign","funding":false,"transaction":hex::encode(bincode::serialize(&spend)?),"entry":encoded}),None)?;
            spend = bincode::deserialize(&hex::decode(
                signed["transaction"].as_str().ok_or("signed")?,
            )?)?;
            envelope(
                &spend,
                &entry,
                &raw,
                &root.join(format!("recovery-{count}-envelope.json")),
            )?;
            count += 1;
        }
    }
    if count != 5 {
        return Err("five terminal payout spends required".into());
    }
    save(
        &root.join("RECOVERY-PREPARED.json"),
        &json!({"restoredPayoutSpends":count,"independentPeople":false,"restoredFromOriginalOwnBackup":true,"servicesNotNeededForKeySigning":true}),
    )?;
    Ok(())
}

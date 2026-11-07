// Small fresh TN10 rehearsal. Build and acceptance are separate one-shot steps.
use kaspa_rpc_core::{RpcTransaction, RpcUtxosByAddressesEntry};
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
        &json!({"trial":hex::encode(fresh()),"network":"testnet-10","parameters":params.canonicalize()?,"walletDomain":hex::encode(domain()),"image":risc0_zkvm::compute_image_id(&fs::read(program)?)?.to_string(),"principalSompi":400_000_000u64,"feeAllowanceSompi":200_000_000u64,"fundingSourceSompi":700_000_000u64,"scope":"fresh unfunded same-host experimental rehearsal; no production setup or privacy qualification"}),
    )?;
    let mut a = trial_actors(root)?;
    let mut wallets = vec![];
    for who in 0..4 {
        wallets.push(a.call(who, json!({"method":"public"}), None)?);
    }
    let raw: Vec<u8> = serde_json::from_value(wallets[0]["fundingSpk"].clone())?;
    save(
        &root.join("PUBLIC.json"),
        &json!({"wallets":wallets,"fundingAddress":address(&native::spk(&raw))?,"fundingSompi":700_000_000u64,"unfunded":true}),
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
                    && e.utxo_entry.amount > 710_000_000
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
                700_000_000,
                kaspa_txscript::pay_to_address_script(&destination),
            ),
            TransactionOutput::new(entry.amount - 700_000_000, own),
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
                    e.utxo_entry.amount == 700_000_000
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
            400_000_000,
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
                TransactionOutput::new(600_000_000, policy.spk(state.root())),
                TransactionOutput::new(100_000_000, own),
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
        let signed=actors.call(0,json!({"method":"sign","funding":true,"smallTrial":true,"image":policy.image,"transaction":hex::encode(bincode::serialize(&tx)?),"entry":hex::encode(bincode::serialize(&entry)?)}),None)?;
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
                (0, 1, 400_000_000, 200_000_000),
                (1, 2, 200_000_000, 100_000_000),
                (0, 3, 200_000_000, 100_000_000),
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
                100_000_000,
                20_000_000,
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
pub fn live_approvals(root: &Path, transport: &Path) -> Result<()> {
    testnet_profile()?;
    if !root.join("WORLD-initial.json").is_file() || root.join("WORLD-external.json").exists() {
        return Err("prepare approvals exactly after accepted initial payments".into());
    }
    let world = saved_world(root)?;
    let registration = root.join("registration");
    let config = crate::anonymous::new_round_for(&world.state, 100_000_000, &registration)?;
    let transport = read(transport)?;
    let mut actors = trial_actors(root)?;
    let mut server = Command::new(std::env::current_exe()?)
        .args([
            "serve",
            registration.join("config.json").to_str().unwrap(),
            registration.join("private/issuer.der").to_str().unwrap(),
            registration.join("operator.jsonl").to_str().unwrap(),
            &transport["servicePort"].as_u64().ok_or("port")?.to_string(),
        ])
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
        for who in [2, 0, 1] {
            let r=actors.call(who,json!({"method":"registration-issue","config":config,"onion":transport["onion"],"socks":transport["socks"]}),Some(&world.state))?;
            claims.push(serde_json::from_value::<H>(r["nullifier"].clone())?);
        }
        for who in [1, 2, 0] {
            actors.call(who,json!({"method":"registration-redeem","config":config,"onion":transport["onion"],"socks":transport["socks"]}),None)?;
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
            denomination: 100_000_000,
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

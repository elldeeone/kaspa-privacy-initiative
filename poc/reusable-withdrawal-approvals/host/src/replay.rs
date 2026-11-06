fn record_view(record: &Value) -> Result<Value> {
    let mut v = record.clone();
    if record.get("inputBincodeHex").is_some() {
        let input: app::Input = from_hex(&record["inputBincodeHex"])?;
        v["publicState"] = state_view(&input.state);
        v["publicPacket"] = serde_json::to_value(&input.packet)?;
        v["publicEffects"] = serde_json::to_value(&input.effects)?;
    }
    Ok(v)
}
pub fn views_new(run: &Path, out: &Path) -> Result<()> {
    let main = read(&run.join("RESULT.json"))?;
    let records = main["records"].as_array().ok_or("records")?;
    let public = records
        .iter()
        .map(record_view)
        .collect::<Result<Vec<_>>>()?;

    save_public(
        out,
        &json!({"schema":"reusable-intent-full-public-view-v1","records":public,"approvals":read(&run.join("APPROVALS.json"))?,"scope":"one main accepted local history; separate counterfactual traces require explicit extra disclosure"}),
    )
}
fn replay_chain(program: &[u8], run: &Path, records: &[Value], names: &[&str]) -> Result<Value> {
    use ark_serialize::CanonicalDeserialize;
    if records.len() != names.len() + 1 {
        return Err("chain record count".into());
    }
    let policy = Policy {
        image: risc0_zkvm::compute_image_id(program)?
            .as_bytes()
            .try_into()?,
    };
    let fund = read_transaction(&records[0]["transaction"])?;
    let initial: app::State = bincode::deserialize(&fund.payload)?;
    initial.ledger.invariant()?;
    if fund.outputs[0].script_public_key != policy.spk(initial.root()) {
        return Err("initial bank image/root".into());
    }
    let fee = records[0]["report"]["feeSompi"]
        .as_u64()
        .ok_or("fund fee")?;
    let source = fund.outputs.iter().map(|o| o.value).sum::<u64>() + fee;
    native::validate(
        &fund,
        &UtxoEntry::new(
            source,
            fund.outputs[1].script_public_key.clone(),
            0,
            false,
            None,
        ),
    )?;
    let mut state = initial;
    let mut prev = fund.clone();
    let mut receipts = vec![];
    let mut spent = std::collections::HashSet::new();
    let vk = ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(
        state.wallet_vk.as_slice(),
    )?;
    for (record, name) in records[1..].iter().zip(names) {
        let tx = read_transaction(&record["transaction"])?;
        let input: app::Input = from_hex(&record["inputBincodeHex"])?;
        let point = TransactionOutpoint::new(prev.id(), 0);
        if tx.inputs[0].previous_outpoint != point || !spent.insert(point) {
            return Err("replay exact current unspent outpoint".into());
        }
        if input.state.root() != state.root() || tx.payload != input.packet.bytes() {
            return Err("replay exact state/payload".into());
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
            return Err("replay exact actual effects".into());
        }
        for op in &input.packet.operations {
            if !proof::verify(&vk, op) {
                return Err("independent wallet pairing".into());
            }
        }
        let output = app::execute(&input)?;
        let expected: app::State = from_hex(&record["postStateBincodeHex"])?;
        if output.state.root() != expected.root() {
            return Err("replay exact successor".into());
        }
        let dir = run.join(name);
        if fs::read(dir.join("input.bin"))? != bincode::serialize(&input)?
            || fs::read(dir.join("expected-journal.bin"))? != output.journal
        {
            return Err("replay recorded proof input/journal".into());
        }
        let receipt: risc0_zkvm::Receipt =
            bincode::deserialize(&fs::read(dir.join("candidate-compressed.bin"))?)?;
        prover::verify(
            &receipt,
            risc0_zkvm::compute_image_id(program)?,
            &output.journal,
        )?;
        if prover::native_proof(&receipt)? != fs::read(dir.join("native-proof.bin"))? {
            return Err("replay native proof bytes".into());
        }
        let validation = native::validate(&tx, &entry)?;
        if validation["feeSompi"] != output.fee {
            return Err("replay exact fee".into());
        }
        receipts.push(json!({"name":name,"nativeFull":true,"feeSompi":output.fee}));
        state = output.state;
        prev = tx;
    }
    state.ledger.invariant()?;
    Ok(
        json!({"receipts":receipts,"finalReserveSompi":state.ledger.reserve,"finalLiabilitySompi":state.ledger.private_liability,"sourceValueSompi":source}),
    )
}
pub fn replay_new(program_path: &Path, run: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    let program = fs::read(program_path)?;
    let main = read(&run.join("RESULT.json"))?;
    if main["hostOnlyPreflight"] != false {
        return Err("host preflight cannot qualify native execution".into());
    }
    let records = main["records"].as_array().ok_or("main records")?;
    let continued = read(&run.join("continuing-world.json"))?;
    let cr = continued["records"]
        .as_array()
        .ok_or("continuing records")?;
    let spent_record = read(&run.join("spent-world.json"))?;
    let sr = spent_record["records"].as_array().ok_or("spent records")?;
    if records.len() != 6 || cr.len() != 4 || sr.len() != 4 {
        return Err("expected branch lengths".into());
    }
    if records[..3] != cr[..3] || records[..3] != sr[..3] {
        return Err("counterfactual exact shared prefix".into());
    }
    let a = replay_chain(
        &program,
        run,
        records,
        &[
            "initial",
            "unrelated-payment",
            "alice-solo-first",
            "alice-solo-last",
            "terminal-intent",
        ],
    )?;
    let b = replay_chain(
        &program,
        run,
        cr,
        &["initial", "unrelated-payment", "continuing-intent"],
    )?;
    let c = replay_chain(
        &program,
        run,
        sr,
        &["initial", "unrelated-payment", "spent-note-control"],
    )?;
    if a["finalReserveSompi"] != 0
        || a["finalLiabilitySompi"] != 0
        || b["finalReserveSompi"] != 1_000_000_000u64
        || c["finalReserveSompi"] != 2_000_000_000u64
    {
        return Err("exact branch principal accounting".into());
    }
    let approval_record = read(&run.join("APPROVALS.json"))?;
    let original: Vec<Operation> = serde_json::from_value(approval_record["operations"].clone())?;
    let original_bytes = bincode::serialize(&original)?;
    for record in [&records[5], &cr[3]] {
        let input: app::Input = from_hex(&record["inputBincodeHex"])?;
        if bincode::serialize(&input.packet.operations)? != original_bytes {
            return Err("literal consent proof bytes changed".into());
        }
        if serde_json::to_value(input.packet.intent.as_ref().ok_or("missing intent")?)?
            != approval_record["intent"]
        {
            return Err("intent changed".into());
        }
    }
    let valid: app::Input = from_hex(&records[5]["inputBincodeHex"])?;
    let stx = read_transaction(&sr[3]["transaction"])?;
    let spent_state: app::State = from_hex(&sr[3]["postStateBincodeHex"])?;
    let point = TransactionOutpoint::new(stx.id(), 0);
    let value = stx.outputs[0].value;
    let spent = World {
        state: spent_state,
        point,
        value,
        active: HashMap::from([(
            point,
            UtxoEntry::new(
                value,
                stx.outputs[0].script_public_key.clone(),
                0,
                false,
                None,
            ),
        )]),
        records: sr.clone(),
    };
    let controls = host_controls(&valid, &spent)?;
    save_public(&out.join("HOST-CONTROLS.json"), &json!(controls))?;
    let policy = Policy {
        image: risc0_zkvm::compute_image_id(&program)?
            .as_bytes()
            .try_into()?,
    };
    let previous = read_transaction(&records[4]["transaction"])?;
    let entry = UtxoEntry::new(
        previous.outputs[0].value,
        previous.outputs[0].script_public_key.clone(),
        0,
        false,
        None,
    );
    let mut attack = read_transaction(&records[5]["transaction"])?;
    attack.inputs[0].signature_script = policy.witness(
        valid.state.root(),
        [0; 32],
        &fs::read(run.join("continuing-intent/native-proof.bin"))?,
    );
    attack.finalize();
    let stale = native::validate(&attack, &entry)
        .err()
        .ok_or("old receipt accepted at changed current state")?;
    if !stale.contains("ZkIntegrity") || !stale.contains("Groth16 verification failed") {
        return Err("stale receipt failed at wrong layer".into());
    }
    let mut reordered = valid.packet.clone();
    reordered.operations.reverse();
    let mut attack = read_transaction(&records[5]["transaction"])?;
    attack.payload = reordered.bytes();
    attack.finalize();
    let payload = native::validate(&attack, &entry)
        .err()
        .ok_or("receipt reused for different ordered payload")?;
    if !payload.contains("ZkIntegrity") || !payload.contains("Groth16 verification failed") {
        return Err("changed payload failed at wrong layer".into());
    }
    let ct = read_transaction(&cr[3]["transaction"])?;
    let parent = read_transaction(&cr[2]["transaction"])?;
    let centry = UtxoEntry::new(
        parent.outputs[0].value,
        parent.outputs[0].script_public_key.clone(),
        0,
        false,
        None,
    );
    let ci: app::Input = from_hex(&cr[3]["inputBincodeHex"])?;
    let next_root: H = app::execute(&ci)?.journal[32..64].try_into()?;
    let mut successor_controls = vec![];
    for (name, spk) in [
        (
            "changed successor program",
            Policy { image: [9; 32] }.spk(next_root),
        ),
        ("changed successor root", policy.spk([9; 32])),
    ] {
        let mut attack = ct.clone();
        attack.outputs[0].script_public_key = spk;
        attack.finalize();
        let error = native::validate(&attack, &centry)
            .err()
            .ok_or("changed successor accepted")?;
        if !error.contains("SignatureInvalid") || error.contains("ZkIntegrity") {
            return Err(format!("successor rejected at wrong layer: {error}").into());
        }
        successor_controls.push(json!({"case":name,"nativeGuardError":error}));
    }
    save_public(
        &out.join("SUCCESSOR-CONTROLS.json"),
        &json!(successor_controls),
    )?;
    save_public(
        &out.join("VERIFIED.json"),
        &json!({"newProcess":true,"main":a,"continuingCounterfactual":b,"spentNoteCounterfactual":c,"distinctCompleteReceipts":7,"distinctNativeFullTransactions":8,"literalWalletApprovalBytesUnchanged":true,"newCohortIntentApprovalsAfterUpdates":0,"staleReceiptNativeCryptoRejection":stale,"changedOrderedPayloadNativeCryptoRejection":payload,"privateWalletsIssuerOrProvingParametersRead":false,"scope":"supplied synthetic funding source; no accepted live chain or sustained-contention claim"}),
    )
}

pub fn prepare_cases(program: &Path, prior: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    let policy = Policy {
        image: risc0_zkvm::compute_image_id(&fs::read(program)?)?
            .as_bytes()
            .try_into()?,
    };
    let mut certificate = None;
    for (n, name) in ["stale", "priority-withdrawal", "reference-withdrawal"]
        .iter()
        .enumerate()
    {
        let original: app::Input =
            bincode::deserialize(&fs::read(prior.join(name).join("input.bin"))?)?;
        let journal = app::authorization_journal(&original)?;
        if let Some(ref expected) = certificate {
            if *expected != journal {
                return Err("retained packets differ".into());
            }
        } else {
            certificate = Some(journal);
        }
        let point = native::fake_point(hash(
            &[
                b"KPI/new-program/supplied-state/cache-diagnostic/".as_slice(),
                &[n as u8],
                &original.effects.previous,
            ]
            .concat(),
        ));
        let value = original.effects.input_value;
        let state = original.state;
        let entry = UtxoEntry::new(value, policy.spk(state.root()), 0, false, None);
        let world = World {
            state,
            point,
            value,
            active: HashMap::from([(point, entry.clone())]),
            records: vec![],
        };
        let intent = original.packet.intent.as_ref().ok_or("intent")?;
        let step = intent_step(&policy, &world, intent, &original.packet.operations, 0)?;
        let dir = out.join(n.to_string());
        fs::create_dir(&dir)?;
        prover::write(&dir.join("input.bin"), &bincode::serialize(&step.input)?)?;
        save(
            &dir.join("CASE.json"),
            &json!({"scope":"supplied new-program UTXO, not accepted ancestry or old-bank upgrade","transaction":step.tx,"inputBincodeHex":hex::encode(bincode::serialize(&step.input)?),"postStateBincodeHex":hex::encode(bincode::serialize(&step.output.state)?),"entryBincodeHex":hex::encode(bincode::serialize(&entry)?),"report":step.report}),
        )?;
    }
    Ok(())
}
pub fn check_case(program: &Path, case: &Path, proof: &Path) -> Result<()> {
    let record = read(&case.join("CASE.json"))?;
    let mut step = recorded_step(&record)?;
    let policy = Policy {
        image: risc0_zkvm::compute_image_id(&fs::read(program)?)?
            .as_bytes()
            .try_into()?,
    };
    let entry: UtxoEntry = from_hex(&record["entryBincodeHex"])?;
    let receipt: risc0_zkvm::Receipt =
        bincode::deserialize(&fs::read(proof.join("candidate-compressed.bin"))?)?;
    prover::verify(
        &receipt,
        risc0_zkvm::compute_image_id(&fs::read(program)?)?,
        &step.output.journal,
    )?;
    finish(&mut step, &policy, &prover::native_proof(&receipt)?, &entry)?;
    save(
        &proof.join("NATIVE.json"),
        &json!({"report":step.report,"transaction":step.tx,"suppliedStateOnly":true}),
    )?;
    println!("{}", step.report);
    Ok(())
}
pub fn native_controls(program: &Path, run: &Path, out: &Path) -> Result<()> {
    let policy = Policy {
        image: risc0_zkvm::compute_image_id(&fs::read(program)?)?
            .as_bytes()
            .try_into()?,
    };
    let original = read(&run.join("cases/0/CASE.json"))?;
    let mut step = recorded_step(&original)?;
    let entry: UtxoEntry = from_hex(&original["entryBincodeHex"])?;
    let receipt: risc0_zkvm::Receipt =
        bincode::deserialize(&fs::read(run.join("composed-0/candidate-compressed.bin"))?)?;
    let proof = prover::native_proof(&receipt)?;
    finish(&mut step, &policy, &proof, &entry)?;
    let mut cases = vec![];
    let other = read(&run.join("cases/1/CASE.json"))?;
    let mut changed = recorded_step(&other)?;
    let actual: UtxoEntry = from_hex(&other["entryBincodeHex"])?;
    changed.tx.inputs[0].signature_script = policy.witness(
        changed.input.state.root(),
        changed.output.journal[32..64].try_into()?,
        &proof,
    );
    changed.tx.finalize();
    let mut mutations = vec![("stale receipt on current native bank", changed.tx, actual)];
    let mut tx = step.tx.clone();
    tx.outputs[1].value += 1;
    tx.outputs[0].value -= 1;
    tx.finalize();
    mutations.push(("changed actual payout amount", tx, entry.clone()));
    let mut tx = step.tx.clone();
    let mut spk = native::encoded(&tx.outputs[1].script_public_key);
    spk[3] ^= 1;
    tx.outputs[1].script_public_key = native::spk(&spk);
    tx.finalize();
    mutations.push(("changed actual payout key", tx, entry.clone()));
    let mut tx = step.tx.clone();
    tx.outputs[0].value -= 1;
    tx.finalize();
    mutations.push(("changed actual fee", tx, entry.clone()));
    for (name, tx, entry) in mutations {
        let error = native::validate(&tx, &entry)
            .err()
            .ok_or_else(|| format!("native accepted {name}"))?;
        if !error.contains("ZkIntegrity") && !error.contains("Groth16") {
            return Err(format!("wrong native refusal: {error}").into());
        }
        cases.push(json!({"case":name,"error":error}));
    }
    fs::write(
        out,
        serde_json::to_vec_pretty(&json!({"actualNativeFull":true,"controls":cases}))?,
    )?;
    println!("{} native Full refusal controls passed", cases.len());
    Ok(())
}

pub fn conditional_native(program: &Path, case: &Path, conditional: &Path) -> Result<()> {
    let record = read(&case.join("CASE.json"))?;
    let mut step = recorded_step(&record)?;
    let entry: UtxoEntry = from_hex(&record["entryBincodeHex"])?;
    let policy = Policy {
        image: risc0_zkvm::compute_image_id(&fs::read(program)?)?
            .as_bytes()
            .try_into()?,
    };
    step.tx.inputs[0].signature_script = policy.witness(
        step.input.state.root(),
        step.output.journal[32..64].try_into()?,
        &fs::read(conditional.join("native-proof.bin"))?,
    );
    step.tx.finalize();
    let error = native::validate(&step.tx, &entry)
        .err()
        .ok_or("native accepted unresolved proof")?;
    if !error.contains("ZkIntegrity") && !error.contains("Groth16") {
        return Err(format!("wrong conditional native failure: {error}").into());
    }
    fs::write(
        conditional.join("NATIVE-REFUSAL.json"),
        serde_json::to_vec_pretty(
            &json!({"actualNativeFull":true,"error":error,"conditionallyProvenReceiptIsNotSpendAuthority":true}),
        )?,
    )?;
    println!("Native Full refused the real conditional Groth16 receipt");
    Ok(())
}

pub fn replay_diagnostic(program: &Path, run: &Path) -> Result<()> {
    let image = risc0_zkvm::compute_image_id(&fs::read(program)?)?;
    let policy = Policy {
        image: image.as_bytes().try_into()?,
    };
    prover::replay_cache(
        &program
            .parent()
            .ok_or("program parent")?
            .join("authorization.bin"),
        &run.join("authorization-cache"),
    )?;
    let mut journals = vec![];
    for (case, name) in [
        (0, "composed-0"),
        (1, "composed-1"),
        (2, "composed-2"),
        (2, "direct-2"),
    ] {
        let record = read(&run.join(format!("cases/{case}/CASE.json")))?;
        let mut step = recorded_step(&record)?;
        let entry: UtxoEntry = from_hex(&record["entryBincodeHex"])?;
        let receipt: risc0_zkvm::Receipt =
            bincode::deserialize(&fs::read(run.join(name).join("candidate-compressed.bin"))?)?;
        prover::verify(&receipt, image, &step.output.journal)?;
        finish(&mut step, &policy, &prover::native_proof(&receipt)?, &entry)?;
        if step.report["feeSompi"] != 16_555_100u64 {
            return Err("diagnostic native fee changed".into());
        }
        journals.push(step.output.journal);
    }
    if journals[2] != journals[3] {
        return Err("matched direct/composed economics differ".into());
    }
    println!(
        "{}",
        json!({"publicOnly":true,"completeNativeFullReceipts":4,"staticSuccinctCertificateVerified":true,"sameInputDirectComposedJournal":true,"privateParametersRead":false,"suppliedStateOnly":true})
    );
    Ok(())
}

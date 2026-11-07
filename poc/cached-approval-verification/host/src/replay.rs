// Independent public-only replay: full wallet pairing, SDK claims and native Full.
pub fn replay_combined(program: &Path, run: &Path) -> Result<()> {
    let image = risc0_zkvm::compute_image_id(&fs::read(program)?)?;
    let policy = Policy {
        image: image.as_bytes().try_into()?,
    };
    let cold = run.parent().ok_or("run parent")?.join("cold-reference");
    let corrected = cold.join("COMPLETE.json").is_file();
    let sources = if corrected {
        vec![run.to_path_buf(), cold.clone()]
    } else {
        vec![run.to_path_buf()]
    };
    let mut proofs = HashMap::new();
    for source in &sources {
        for item in fs::read_dir(source)? {
            let dir = item?.path();
            let record = dir.join("TRANSACTION.json");
            if record.is_file() {
                let r = read(&record)?;
                let tx = read_transaction(&r["transaction"])?;
                proofs.insert(tx.id(), dir);
            }
        }
    }
    let mut caches = 0;
    for source in &sources {
        for item in fs::read_dir(source.join("cache"))? {
            let dir = item?.path();
            if dir.join("REPORT.json").is_file() {
                prover::replay_cache(
                    &program
                        .parent()
                        .ok_or("program parent")?
                        .join("authorization.bin"),
                    &dir,
                )?;
                caches += 1;
            }
        }
    }
    let mut totals = vec![];
    let mut payout_entries = HashMap::new();
    let mut reference_entries = HashMap::new();
    for name in ["MAIN.json", "REFERENCE.json"] {
        let reference = if name == "REFERENCE.json" && corrected {
            cold.join(name)
        } else {
            run.join(name)
        };
        let result = read(&reference)?;
        let records = result["records"].as_array().ok_or("records")?;
        let first = &records[0];
        let funding = read_transaction(&first["transaction"])?;
        let source: UtxoEntry = from_hex(&first["sourceEntryBincodeHex"])?;
        native::validate(&funding, &source)?;
        let state: app::State = bincode::deserialize(&funding.payload)?;
        if funding.outputs[0].script_public_key != policy.spk(state.root())
            || funding.outputs[0].value < state.ledger.reserve
        {
            return Err("funded bank identity/backing".into());
        }
        let point = TransactionOutpoint::new(funding.id(), 0);
        let entry = UtxoEntry::new(
            funding.outputs[0].value,
            funding.outputs[0].script_public_key.clone(),
            0,
            false,
            None,
        );
        let mut world = World {
            state,
            point,
            value: entry.amount,
            active: HashMap::from([(point, entry)]),
            records: vec![first.clone()],
        };
        let mut payout = 0u64;
        for record in &records[1..] {
            let mut step = recorded_step(record)?;
            if step.input.state.root() != world.state.root()
                || step.tx.payload != step.input.packet.bytes()
                || bincode::serialize(&native::effects(&step.tx, world.value))?
                    != bincode::serialize(&step.input.effects)?
            {
                return Err("accepted predecessor/exact effects/payload".into());
            }
            let dir = proofs.get(&step.tx.id()).ok_or("public proof missing")?;
            let receipt: risc0_zkvm::Receipt =
                bincode::deserialize(&fs::read(dir.join("candidate-compressed.bin"))?)?;
            prover::verify(&receipt, image, &step.output.journal)?;
            let raw = prover::native_proof(&receipt)?;
            if step.tx.inputs[0].signature_script
                != policy.witness(
                    step.input.state.root(),
                    step.output.journal[32..64].try_into()?,
                    &raw,
                )
            {
                return Err("exact native witness from complete SDK receipt".into());
            }
            let unchanged = step.tx.clone();
            finish(&mut step, &policy, &raw, &world.entry()?)?;
            if step.tx != unchanged {
                return Err("native replay changed final body".into());
            }
            if step.input.packet.mode != app::PAYMENT {
                let offset = usize::from(step.output.state.ledger.reserve > 0);
                for index in offset..offset + step.input.packet.operations.len() {
                    let o = &step.tx.outputs[index];
                    let map = if name == "MAIN.json" {
                        &mut payout_entries
                    } else {
                        &mut reference_entries
                    };
                    map.insert(
                        TransactionOutpoint::new(step.tx.id(), index as u32),
                        UtxoEntry::new(o.value, o.script_public_key.clone(), 0, false, None),
                    );
                }
            }
            payout = payout
                .checked_add(step.output.payout_principal)
                .ok_or("payout sum")?;
            world.accept(&step)?;
        }
        if world.value != 0
            || world.state.ledger.reserve != 0
            || world.state.ledger.private_liability != 0
            || payout != 4_000_000_000
        {
            return Err("complete drainage/accounting".into());
        }
        totals.push(json!({"history":name,"completeReceipts":records.len()-1,"paidPrincipalSompi":payout,"remainingPrincipalSompi":0,"suppliedSourceOnly":true}));
    }
    let result = read(&run.join("MAIN.json"))?;
    let mut spends = 0;
    for record in result["restoredPayoutSpends"]
        .as_array()
        .ok_or("restored spends")?
    {
        let tx = read_transaction(&record["transaction"])?;
        let expected = payout_entries
            .remove(&tx.inputs[0].previous_outpoint)
            .ok_or("duplicate or unrelated restored spend")?;
        let entry: UtxoEntry = from_hex(&record["entryBincodeHex"])?;
        if expected != entry {
            return Err("restored spend exact accepted payout".into());
        }
        native::validate(&tx, &entry)?;
        spends += 1;
    }
    if spends != 8 || !payout_entries.is_empty() {
        return Err("all eight payouts spent exactly once".into());
    }
    let reference = read(&run.join("REFERENCE-RECOVERY.json"))?;
    let mut ref_spends = 0;
    for record in reference["restoredPayoutSpends"]
        .as_array()
        .ok_or("reference restored spends")?
    {
        let tx = read_transaction(&record["transaction"])?;
        let expected = reference_entries
            .remove(&tx.inputs[0].previous_outpoint)
            .ok_or("duplicate or unrelated reference payout")?;
        let entry: UtxoEntry = from_hex(&record["entryBincodeHex"])?;
        if expected != entry {
            return Err("reference payout exact accepted entry".into());
        }
        native::validate(&tx, &entry)?;
        ref_spends += 1;
    }
    if ref_spends != 8 || !reference_entries.is_empty() {
        return Err("all reference payouts spent exactly once".into());
    }
    println!(
        "{}",
        json!({"publicOnly":true,"cacheReceipts":caches,"histories":totals,"restoredPayoutSpends":spends,"referenceRestoredPayoutSpends":ref_spends,"coldReferenceSelected":corrected,"walletBackupsOrProvingParametersRead":false,"chainAcceptanceClaimed":false})
    );
    Ok(())
}

pub fn reference_recovery(run: &Path) -> Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let result = read(&run.join("REFERENCE.json"))?;
    let records: Vec<Value> = serde_json::from_value(result["records"].clone())?;
    let last = records.last().ok_or("records")?;
    let state: app::State = from_hex(&last["postStateBincodeHex"])?;
    let tx = read_transaction(&last["transaction"])?;
    let world = World {
        state,
        point: tx.inputs[0].previous_outpoint,
        value: 0,
        active: HashMap::new(),
        records,
    };
    let private = run.join("reference-recovery-private");
    fs::create_dir(&private)?;
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700))?;
    let root = private.join("actors");
    fs::create_dir(&root)?;
    for who in 0..4 {
        symlink(
            run.join(format!("private/wallet-{who}")).canonicalize()?,
            root.join(format!("wallet-{who}")),
        )?;
    }
    let mut actors = Actors {
        root,
        params: "/dev/null".into(),
        calls: vec![],
        processes: HashMap::new(),
    };
    let spends = restore_spends(&mut actors, &world, &world.state.fee_refund_spk)?;
    save(
        &run.join("REFERENCE-RECOVERY.json"),
        &json!({"additionalControlAfterOriginalComparison":true,"originalComparisonRecordsUnchanged":true,"restoredPayoutSpends":spends,"nativeFull":true,"chainAccepted":false}),
    )?;
    println!("Eight reference payouts independently spent with restored own keys");
    Ok(())
}

pub fn cold_reference(program: &Path, source: &Path, out: &Path) -> Result<()> {
    let main = read(&source.join("MAIN.json"))?;
    let records: Vec<Value> = serde_json::from_value(main["records"].clone())?;
    let joint = records
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(i, r)| {
            let input: app::Input = from_hex(&r["inputBincodeHex"]).ok()?;
            (input.packet.mode == app::JOINT).then_some(i)
        })
        .ok_or("joint prefix")?;
    let prefix = recorded_step(&records[joint])?;
    let state = prefix.output.state;
    let point = TransactionOutpoint::new(prefix.tx.id(), 0);
    let entry = UtxoEntry::new(
        prefix.tx.outputs[0].value,
        prefix.tx.outputs[0].script_public_key.clone(),
        0,
        false,
        None,
    );
    let mut world = World {
        state,
        point,
        value: entry.amount,
        active: HashMap::from([(point, entry)]),
        records: records[..=joint].to_vec(),
    };
    let mut payments = vec![];
    let mut final_record = None;
    for r in &records[joint + 1..] {
        let step = recorded_step(r)?;
        if step.input.packet.mode == app::PAYMENT {
            payments.extend(step.input.packet.operations);
        } else if step.input.packet.mode == app::NAMED {
            final_record = Some(r.clone());
        } else {
            return Err("unexpected post-prefix operation".into());
        }
    }
    if payments.len() != 3 {
        return Err("three actual queued payments required".into());
    }
    let final_step = recorded_step(&final_record.ok_or("final record")?)?;
    let final_payouts = final_step.tx.outputs[..final_step.input.packet.operations.len()].to_vec();
    fs::create_dir(out)?;
    fs::create_dir(out.join("cache"))?;
    save(
        &out.join("SELECTION.json"),
        &json!({"reason":"correct cross-arm cache reuse in original reference waiting times","source":source,"sameActualWalletOperations":true,"commonPrefixThroughWithdrawalSharedAndCharged":true,"postPrefixCachesInitiallyEmpty":true,"allFourPostPrefixCertificatesActuallyRecreated":true,"originalComparisonPreserved":true,"remainingPrivatePayments":3,"finalPayouts":5}),
    )?;
    let policy = Policy {
        image: risc0_zkvm::compute_image_id(&fs::read(program)?)?
            .as_bytes()
            .try_into()?,
    };
    let auth = program
        .parent()
        .ok_or("program parent")?
        .join("authorization.bin");
    let common = main["withdrawalWaitSeconds"]
        .as_f64()
        .ok_or("common wait")?;
    let arrivals = read(&source.join("ARRIVALS.json"))?;
    let start = Instant::now();
    let mut readiness = vec![];
    for (i, op) in payments.into_iter().enumerate() {
        let ready = arrivals["events"][i]["walletProofReadySeconds"]
            .as_f64()
            .ok_or("arrival")?;
        while common + start.elapsed().as_secs_f64() < ready {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let step = payment(&policy, &world, vec![op])?;
        cached_settle(
            &auth,
            program,
            &policy,
            &mut world,
            step,
            out,
            &format!("payment-{i}"),
        )?;
        let at = common + start.elapsed().as_secs_f64();
        readiness.push(json!({"index":i,"proofReadySeconds":at,"waitSeconds":at-ready}));
    }
    let step = named(
        &policy,
        &world,
        final_step.input.packet.operations,
        final_payouts,
    )?;
    cached_settle(
        &auth,
        program,
        &policy,
        &mut world,
        step,
        out,
        "later-payouts",
    )?;
    if world.value != 0
        || world.state.ledger.reserve != 0
        || world.state.ledger.private_liability != 0
    {
        return Err("cold reference terminal accounting".into());
    }
    save(
        &out.join("REFERENCE.json"),
        &json!({"records":world.records,"reserve":0,"liability":0,"nativeFull":true,"chainAccepted":false,"withdrawalWaitSeconds":common,"paymentReadiness":readiness,"commonPrefixCharged":true,"sequentialCounterfactual":true,"postPrefixCachesCold":true,"postPrefixActualWorkSeconds":start.elapsed().as_secs_f64()}),
    )?;
    let original = read(&source.join("REFERENCE.json"))?;
    let before = original["records"]
        .as_array()
        .ok_or("original reference records")?;
    if before.len() != world.records.len() {
        return Err("cold reference history count changed".into());
    }
    for (a, b) in before.iter().zip(&world.records) {
        if read_transaction(&a["transaction"])?.id() != read_transaction(&b["transaction"])?.id() {
            return Err("cold reference native body IDs changed".into());
        }
    }
    save(
        &out.join("COMPLETE.json"),
        &json!({"complete":true,"postPrefixCacheHits":0,"nativeTransactionIdsMatchOriginalReference":true,"terminalPrincipalSompi":0,"terminalLiabilitySompi":0,"sameActualWalletProofsAndArrivalSchedule":true}),
    )?;
    println!("Complete cold-cache reference verified; native IDs unchanged");
    Ok(())
}

pub fn replay_live(program:&Path,root:&Path)->Result<()> {
 testnet_profile()?;let image=risc0_zkvm::compute_image_id(&fs::read(program)?)?;let policy=Policy{image:image.as_bytes().try_into()?};
 let fund_envelope=read(&root.join("fund-envelope.json"))?;let fund=check_accepted(&fund_envelope,&read(&root.join("fund-ACCEPTED.json"))?)?;
 let raw:RpcUtxosByAddressesEntry=serde_json::from_value(fund_envelope["entries"][0].clone())?;let source:UtxoEntry=raw.utxo_entry.into();native::validate(&fund,&source)?;
 let first=read(&root.join("WORLD-fund.json"))?;let state:app::State=from_hex(&first["state"])?;
 if fund.payload!=bincode::serialize(&state)? || fund.outputs[0].script_public_key!=policy.spk(state.root()){return Err("actual funded bank/pinned image".into());}
 let point=TransactionOutpoint::new(fund.id(),0);let entry=UtxoEntry::new(fund.outputs[0].value,fund.outputs[0].script_public_key.clone(),0,false,None);
 let mut world=World{state,point,value:entry.amount,active:HashMap::from([(point,entry)]),records:vec![]};let mut payouts=HashMap::new();let mut principal=0;
 for phase in ["initial","external","withdrawal","terminal"]{
  let envelope=read(&root.join(format!("{phase}-envelope.json")))?;let accepted=read(&root.join(format!("{phase}-ACCEPTED.json")))?;let tx=check_accepted(&envelope,&accepted)?;
  let record=read(&root.join(phase).join("TRANSACTION.json"))?;let step=recorded_step(&record)?;
  if step.tx!=tx || step.input.state.root()!=world.state.root() || tx.payload!=step.input.packet.bytes() || bincode::serialize(&native::effects(&tx,world.value))?!=bincode::serialize(&step.input.effects)?{return Err("live accepted ancestry/effects/payload".into());}
  let actual:RpcUtxosByAddressesEntry=serde_json::from_value(envelope["entries"][0].clone())?;let actual_point:TransactionOutpoint=actual.outpoint.into();let actual_entry:UtxoEntry=actual.utxo_entry.into();
  if actual_point!=world.point || actual_entry.amount!=world.value || actual_entry.script_public_key!=policy.spk(world.state.root()){return Err("actual accepted predecessor UTXO".into());}world.active.insert(world.point,actual_entry);
  let receipt:risc0_zkvm::Receipt=bincode::deserialize(&fs::read(root.join(phase).join("candidate-compressed.bin"))?)?;prover::verify(&receipt,image,&step.output.journal)?;
  if tx.inputs[0].signature_script!=policy.witness(step.input.state.root(),step.output.journal[32..64].try_into()?,&prover::native_proof(&receipt)?){return Err("accepted native witness exact complete receipt".into());}
  if step.input.packet.mode!=app::PAYMENT{let offset=usize::from(step.output.state.ledger.reserve>0);for i in offset..offset+step.input.packet.operations.len(){let output=&tx.outputs[i];payouts.insert(TransactionOutpoint::new(tx.id(),i as u32),(output.value,output.script_public_key.clone()));}}
  principal+=step.output.payout_principal;world.accept(&step)?;
 }
 if world.value!=0 || world.state.ledger.reserve!=0 || world.state.ledger.private_liability!=0 || principal!=400_000_000 || payouts.len()!=5{return Err("live terminal principal/liability".into());}
 for i in 0..5{let envelope=read(&root.join(format!("recovery-{i}-envelope.json")))?;let tx=check_accepted(&envelope,&read(&root.join(format!("recovery-{i}-accepted.json")))?)?;
  let raw:RpcUtxosByAddressesEntry=serde_json::from_value(envelope["entries"][0].clone())?;let entry:UtxoEntry=raw.utxo_entry.into();let expected=payouts.remove(&tx.inputs[0].previous_outpoint).ok_or("unrelated/replayed payout spend")?;
  if (entry.amount,entry.script_public_key.clone())!=expected{return Err("actual payout exact value/script".into());}native::validate(&tx,&entry)?;
 }
 if !payouts.is_empty(){return Err("unspent rehearsal payout".into());}
 let mut cache_count=0;for item in fs::read_dir(root.join("cache"))?{let dir=item?.path();if dir.join("REPORT.json").is_file(){prover::replay_cache(&program.parent().ok_or("program parent")?.join("authorization.bin"),&dir)?;cache_count+=1;}}
 println!("{}",json!({"publicOnly":true,"acceptedBankFunding":true,"exactAcceptedCompleteReceiptSettlements":4,"cacheReceipts":cache_count,"paidPrincipalSompi":principal,"remainingBankValueSompi":0,"remainingLiabilitySompi":0,"acceptedRestoredPayoutSpends":5,"minimumObservedConfirmations":10,"walletBackupsOrProvingParametersRead":false,"scope":"independent SDK/native recheck of retained exact chain observations, not a trustless light-client proof or independent-user qualification"}));Ok(())
}

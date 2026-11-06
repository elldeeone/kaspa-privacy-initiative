include!("../../../batched-payment-costs/host/src/bench.rs");

/// Host-only checked generator, before building the new image.
pub fn pin(state_path: &Path, pins: &Path) -> Result<()> {
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    let state: app::State = from_hex(&read(state_path)?["bincodeHex"])?;
    let raw = &state.wallet_vk;
    let mut r = raw.as_slice();
    let vk = ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(&mut r)?;
    if !r.is_empty() || proof::serialize(&vk) != *raw || vk.gamma_abc_g1.len() != 3 {
        return Err("checked canonical wallet key/arity".into());
    }
    if hash(raw) != state.ledger.verifier { return Err("state key identity".into()); }
    let mut full = vec![]; vk.serialize_uncompressed(&mut full)?;
    prover::write(&pins.join("vk-compressed.bin"),raw)?;
    prover::write(&pins.join("vk-uncompressed.bin"),&full)?;
    save(&pins.join("CHECKED.json"),&json!({"compressedSha256":hex::encode(hash(raw)),"uncompressedSha256":hex::encode(hash(&full)),"publicInputs":2,"checkedCanonicalSubgroups":true}))
}

fn settle(program: &[u8], policy: &Policy, world: &mut World, mut step: Step, out: &Path) -> Result<Value> {
    let (p,stats)=prover::prove(program,&step.input,out)?;
    finish(&mut step,policy,&p,&world.entry()?)?;
    world.accept(&step)?;
    save(&out.with_extension("native.json"), &world.records.last().unwrap())?;
    Ok(stats)
}
fn rediscover(w: &mut Work, state: &app::State) -> Result<()> {
    for i in 0..3 {
        let wallet=Wallet::restore_local(&w.wallets[i].local_backup());
        let notes=wallet.discover(&state.ledger.deliveries,&state.ledger.tree,&state.ledger.nullifiers);
        if notes.len()!=1 {return Err("one unspent note per restored wallet".into());}
        let (p,q)=state.ledger.tree.path(notes[0].1)?;
        w.witnesses[i]=wallet.witness(notes[0].0.clone(),[Note::dummy(),Note::dummy()],p,q);
    }
    Ok(())
}

pub fn busy(program_path: &Path, dynamic_path: &Path, core: &Path, out: &Path) -> Result<()> {
    fs::create_dir(out)?;
    let program=fs::read(program_path)?;
    let dynamic=fs::read(dynamic_path)?;
    let (mut w,_,_,_)=restored_work(core)?;
    let policy=Policy{image:risc0_zkvm::compute_image_id(&program)?.as_bytes().try_into()?};
    let (fund,entry,report)=funding(&w,&policy)?;
    let mut world=World::start(&w,&fund,&entry,&report);
    let ops=w.operations.clone();
    let initial=prepare_step(&mut w,&policy,&world.state,world.point,world.value,app::PAYMENT,&ops,&[])?;
    // Both real programs prove the EXACT same public input and journal. Only the
    // pinned image is accepted by this fresh bank's immutable native verifier.
    let (dp,dynamic_stats)=prover::prove(&dynamic,&initial.input,&out.join("dynamic-control"))?;
    let mut wrong_image_tx=initial.tx.clone();
    wrong_image_tx.inputs[0].signature_script=policy.witness(initial.input.state.root(),initial.output.journal[32..64].try_into()?,&dp);
    wrong_image_tx.finalize();
    let wrong_image=native::validate(&wrong_image_tx,&world.entry()?).err().ok_or("wrong guest image accepted")?.to_string();
    let pinned_stats=settle(&program,&policy,&mut world,initial,&out.join("pinned-initial"))?;
    let stale_started=Instant::now();
    let stale=prepare_step(&mut w,&policy,&world.state,world.point,world.value,app::JOINT,&[],&[1,2])?;
    let stale_seconds=stale_started.elapsed().as_secs_f64();
    let cohort_nfs=[stale.input.packet.operations[0].statement.nullifier,stale.input.packet.operations[1].statement.nullifier];
    save(&out.join("stale-prepared.json"),&json!({"inputBincodeHex":hex::encode(bincode::serialize(&stale.input)?),"transaction":stale.tx,"walletPreparationSeconds":stale_seconds,"actualWalletProofs":2}))?;
    // Alice pays herself. Neither Bob's nor Carol's note is touched.
    let alice=&w.wallets[0];
    let new_note=alice.note(w.d);
    let mut s=Statement::new(TRANSFER,w.engine.id(),world.state.ledger.tree.root());
    s.nullifier=nullifier(&w.witnesses[0].secret,&w.witnesses[0].input);
    let mut witness=w.witnesses[0].clone(); witness.outputs=[new_note.clone(),Note::dummy()];
    let op=w.engine.prove(s,witness,[new_note.deliver()?,Delivery::absent()]);
    let busy=prepare_step(&mut w,&policy,&world.state,world.point,world.value,app::PAYMENT,&[op],&[])?;
    let busy_stats=settle(&program,&policy,&mut world,busy,&out.join("unrelated-payment"))?;
    assert!(cohort_nfs.iter().all(|n|!world.state.ledger.nullifiers.contains(n)));
    let stale_point=world.accept(&stale).err().ok_or("stale point accepted")?.to_string();
    let mut stale_at_current=stale.input.clone();
    stale_at_current.state=world.state.clone();
    stale_at_current.effects.previous=world.point.transaction_id.as_bytes().try_into()?;
    stale_at_current.effects.index=world.point.index;
    stale_at_current.effects.input_value=world.value;
    let stale_context=app::execute(&stale_at_current).err().ok_or("stale context accepted")?;
    if stale_context!="complete native effects authorization" {return Err(format!("wrong stale rejection: {stale_context}").into());}
    let actual_guest=prover::reject_guest(&program,&stale_at_current)?;
    rediscover(&mut w,&world.state)?;
    let retry=prepare_step(&mut w,&policy,&world.state,world.point,world.value,app::JOINT,&[],&[1,2])?;
    let retry_stats=settle(&program,&policy,&mut world,retry,&out.join("fresh-joint"))?;
    // Restored Alice still exits without the departed cohort or issuer.
    let solo=prepare_step(&mut w,&policy,&world.state,world.point,world.value,app::SOLO,&[],&[0])?;
    let solo_stats=settle(&program,&policy,&mut world,solo,&out.join("restored-solo"))?;
    assert_eq!(world.state.ledger.reserve,0); assert_eq!(world.state.ledger.private_liability,0);
    assert!(world.active.is_empty()); assert!(world.state.canonical());
    let fee: u64=world.records.iter().map(|r|r["report"]["feeSompi"].as_u64().unwrap()).sum();
    let result=json!({"schema":"busy-bank-followup-v1","scope":"offline genuine complete receipts and native Full; supplied synthetic source","exactInputDynamicControl":dynamic_stats,"exactInputPinned":pinned_stats,"wrongImageNativeRejection":wrong_image,"busyPayment":busy_stats,"freshJoint":retry_stats,"restoredSolo":solo_stats,"staleOutpointRejection":stale_point,"staleEffectsRejection":stale_context,"actualGuestStaleRejection":actual_guest,"cohortNotesStillUnspentAfterUnrelatedPayment":true,"wastedApprovalProofs":2,"wastedApprovalSeconds":stale_seconds,"wastedApprovalNativeFeeSompi":0,"totalNativeFeeSompi":fee,"principalPayoutSompi":3*w.d,"finalReserveSompi":0,"finalPrivateLiabilitySompi":0,"finalActiveBankOutputs":0,"records":world.records});
    save(&out.join("RESULT.json"),&result)?;
    eprintln!("BUSY_COMPLETE native_fee_sompi={fee}");
    Ok(())
}

pub fn privacy(core: &Path,out: &Path) -> Result<()> {
    let (mut w,_,_,_)=restored_work(core)?;
    fs::create_dir(out)?;
    crate::anonymous::prepare(&mut w.engine,&w.witnesses,&w.post,out)
}

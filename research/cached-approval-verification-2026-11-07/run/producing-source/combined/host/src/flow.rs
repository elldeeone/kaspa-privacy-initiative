// Combined finite workload. Fresh banks only; no immutable-bank upgrade.
fn child_cli(args:&[String],dir:&Path)->Result<Child>{
 let work=dir.with_extension("work");fs::create_dir(&work)?;
 Ok(Command::new("setsid").arg("--wait").arg(std::env::current_exe()?).args(args)
 .env("RISC0_WORK_DIR",work).stdout(Stdio::null()).stderr(fs::OpenOptions::new().create_new(true).write(true).open(dir.with_extension("stderr.log"))?).spawn()?)
}
fn input_file(step:&Step,dir:&Path)->Result<std::path::PathBuf>{let file=dir.with_extension("input.bin");prover::write(&file,&bincode::serialize(&step.input)?)?;Ok(file)}
fn cache_path(step:&Step,out:&Path)->Result<std::path::PathBuf>{Ok(out.join("cache").join(hex::encode(hash(&app::authorization_journal(&step.input)?))))}
fn cache_begin(auth:&Path,step:&Step,out:&Path)->Result<(std::path::PathBuf,Option<Child>)>{
 let cache=cache_path(step,out)?;
 if cache.join("REPORT.json").exists(){return Ok((cache,None));}
 let input=input_file(step,&cache)?;
 let child=child_cli(&["authorize".into(),auth.display().to_string(),input.display().to_string(),cache.display().to_string()],&cache)?;Ok((cache,Some(child)))
}
fn cached_begin(auth:&Path,program:&Path,step:&Step,cache:&Path,dir:&Path)->Result<Child>{
 let input=input_file(step,dir)?;
 child_cli(&["settle".into(),auth.display().to_string(),program.display().to_string(),input.display().to_string(),cache.join("receipt.bin").display().to_string(),dir.display().to_string()],dir)
}
fn cached_collect(policy:&Policy,world:&mut World,step:&mut Step,dir:&Path)->Result<Value>{
 let receipt:risc0_zkvm::Receipt=bincode::deserialize(&fs::read(dir.join("candidate-compressed.bin"))?)?;
 prover::verify(&receipt,risc0_zkvm::sha::Digest::from_bytes(policy.image),&step.output.journal)?;
 let raw=prover::native_proof(&receipt)?;if raw!=fs::read(dir.join("native-proof.bin"))?{return Err("native receipt mismatch".into());}
 finish(step,policy,&raw,&world.entry()?)?;world.accept(step)?;
 save(&dir.join("TRANSACTION.json"),&json!({"transaction":step.tx,"inputBincodeHex":hex::encode(bincode::serialize(&step.input)?),"postStateBincodeHex":hex::encode(bincode::serialize(&step.output.state)?),"report":step.report}))?;
 Ok(read(&dir.join("REPORT.json"))?)
}
fn cached_settle(auth:&Path,program:&Path,policy:&Policy,world:&mut World,mut step:Step,out:&Path,name:&str)->Result<Value>{
 let (cache,child)=cache_begin(auth,&step,out)?;
 if let Some(mut child)=child{if !child.wait()?.success(){return Err(format!("cache failed: {}",cache.display()).into());}}
 let dir=out.join(name);let mut child=cached_begin(auth,program,&step,&cache,&dir)?;
 if !child.wait()?.success(){return Err(format!("settlement failed: {}",dir.display()).into());}
 cached_collect(policy,world,&mut step,&dir)
}
fn arrived(actors:&mut Actors,projected:&mut app::State,addresses:&[Value],queued:&mut Vec<Operation>,events:&mut Vec<Value>,clock:Instant)->Result<()> {
 let i=queued.len();if i<3 && clock.elapsed().as_secs_f64()>=[90.,330.,570.][i]{
  let start=clock.elapsed().as_secs_f64();queued.extend(prepare_arrival(actors,projected,addresses,i)?);
  events.push(json!({"index":i,"arrivedSeconds":start,"walletProofReadySeconds":clock.elapsed().as_secs_f64()}));
 }
 Ok(())
}
fn restore_spends(actors:&mut Actors,world:&World,refund:&[u8])->Result<Vec<Value>>{
 actors.restart();let mut spends=vec![];
 for record in &world.records[1..]{let tx=read_transaction(&record["transaction"])?;
  for (index,o) in tx.outputs.iter().enumerate(){
   let encoded=native::encoded(&o.script_public_key);if encoded.len()!=36 || encoded==refund{continue;}
   let entry=UtxoEntry::new(o.value,o.script_public_key.clone(),0,false,None);let raw=hex::encode(bincode::serialize(&entry)?);
   let mut owners=vec![];for who in 0..4{if actors.call(who,json!({"method":"owns","entry":raw}),None)?["owns"]==true{owners.push(who);}}
   if owners.len()!=1{return Err("restored payout unique ownership".into());}let who=owners[0];
   let mut spend=native::transaction(TransactionOutpoint::new(tx.id(),index as u32),vec![o.clone()],vec![],20);
   spend.inputs[0].signature_script=vec![0;66];let fee=native::quote(&spend,&entry)["minimumDefaultRelayFeeSompi"].as_u64().ok_or("recovery fee")?;
   spend.outputs[0].value=spend.outputs[0].value.checked_sub(fee).ok_or("recovery value")?;spend.finalize();
   let signed=actors.call(who,json!({"method":"sign","funding":false,"transaction":hex::encode(bincode::serialize(&spend)?),"entry":raw}),None)?;
   spend=bincode::deserialize(&hex::decode(signed["transaction"].as_str().ok_or("signed spend")?)?)?;
   spends.push(json!({"ownerDisclosureControl":who,"transaction":spend,"entryBincodeHex":raw,"report":native::validate(&spend,&entry)?}));
  }
 }if spends.len()!=8{return Err("eight recovered payouts required".into());}Ok(spends)
}
pub fn run_combined(program:&Path,params:&Path,out:&Path,transport:&Path)->Result<()> {
 use std::os::unix::fs::PermissionsExt;
 let auth=program.parent().ok_or("program parent")?.join("authorization.bin");
 fs::create_dir(out)?;fs::create_dir(out.join("cache"))?;fs::create_dir(out.join("private"))?;fs::set_permissions(out.join("private"),fs::Permissions::from_mode(0o700))?;
 let mut actors=Actors{root:out.join("private"),params:params.into(),calls:vec![],processes:HashMap::new()};
 let mut addresses=vec![];for who in 0..4{addresses.push(actors.call(who,json!({"method":"public"}),None)?);}
 let policy=Policy{image:risc0_zkvm::compute_image_id(&fs::read(program)?)?.as_bytes().try_into()?};
 let source=native::fake_point(fresh());let pool=hash(&[b"KPI-combined-fresh-bank-v1\0".as_slice(),source.transaction_id.as_bytes().as_slice()].concat());
 let vk=app::WALLET_VK.to_vec();let mut ledger=Ledger::new(hash(&vk));ledger.register_authenticated_fixture_deposit(pool,4_000_000_000,serde_json::from_value(addresses[0]["owner"].clone())?)?;
 let refund:Vec<u8>=serde_json::from_value(addresses[0]["fundingSpk"].clone())?;let initial=app::State{ledger,pool,wallet_vk:vk,fee_refund_spk:refund.clone()};
 let (fund,entry,report)=funding_public(&mut actors,&policy,&initial,source,&native::spk(&refund))?;
 let point=TransactionOutpoint::new(fund.id(),0);let bank=UtxoEntry::new(fund.outputs[0].value,fund.outputs[0].script_public_key.clone(),0,false,None);
 let mut world=World{state:initial.clone(),point,value:bank.amount,active:HashMap::from([(point,bank)]),records:vec![json!({"kind":"deposit","transaction":fund,"sourceEntryBincodeHex":hex::encode(bincode::serialize(&entry)?),"report":report})]};
 let mut projected=initial;let mut ops=actors.operations(0,json!({"method":"credit"}),&projected)?;for op in &ops{projected.ledger.apply(&public_verifier(&projected)?,op)?;}
 for (who,to,input,amount) in [(0,1,4_000_000_000,2_000_000_000),(1,2,2_000_000_000,1_000_000_000),(0,3,2_000_000_000,1_000_000_000)]{ops.extend(transfers(&mut actors,who,&mut projected,&addresses[to],input,amount)?);}
 eprintln!("PHASE combined genuine initial payments");let step=payment(&policy,&world,ops)?;cached_settle(&auth,program,&policy,&mut world,step,out,"initial")?;
 eprintln!("PHASE wallet-owned blind registration over onion transport");
 let registration=out.join("registration");let config=crate::anonymous::new_round(&world.state,&registration)?;let transport=read(transport)?;
 let mut server=Command::new(std::env::current_exe()?).args(["serve",registration.join("config.json").to_str().unwrap(),registration.join("private/issuer.der").to_str().unwrap(),registration.join("operator.jsonl").to_str().unwrap(),&transport["servicePort"].as_u64().ok_or("service port")?.to_string()]).stderr(fs::File::create(registration.join("server.log"))?).spawn()?;
 let result=(||->Result<()>{
  while !fs::read_to_string(registration.join("server.log"))?.contains("COORDINATOR_READY"){if server.try_wait()?.is_some(){return Err("registration server stopped".into());}std::thread::sleep(std::time::Duration::from_millis(50));}
  let mut claims=vec![];for who in [2,0,1]{let r=actors.call(who,json!({"method":"registration-issue","config":config,"onion":transport["onion"],"socks":transport["socks"]}),Some(&world.state))?;claims.push(serde_json::from_value::<H>(r["nullifier"].clone())?);}
  for who in [1,2,0]{actors.call(who,json!({"method":"registration-redeem","config":config,"onion":transport["onion"],"socks":transport["socks"]}),None)?;}
  let mut payouts=vec![];for line in fs::read_to_string(registration.join("operator.jsonl"))?.lines(){let v:Value=serde_json::from_str(line)?;if v["request"]["kind"]=="redeem" && v["response"]["error"].is_null(){let key=hex::decode(v["response"]["recipientKey"].as_str().ok_or("recipient key")?)?;payouts.push([vec![0,0,32],key,vec![0xac]].concat());}}
  if payouts.len()!=3{return Err("three anonymous outputs required".into());}claims.sort();payouts.sort();
  let intent=app::WithdrawalIntent{protocol_domain:domain(),pool,verifier:world.state.ledger.verifier,reference_anchor:world.state.ledger.tree.root(),nonce:fresh(),refund_key_hash:hash(&refund),denomination:1_000_000_000,fee_cap:20_000_000,claims,payouts};
  let mut approvals=vec![];for who in 0..3{approvals.extend(actors.operations(who,json!({"method":"approve","intent":intent}),&world.state)?);}approvals.sort_by_key(|o|o.statement.nullifier);let digest=approval_digest(&approvals);
  save(&out.join("APPROVALS.json"),&json!({"intent":intent,"operations":approvals,"hash":digest,"registeredOutputOwnershipExported":false}))?;
  let stale=intent_step(&policy,&world,&intent,&approvals,0)?;save(&out.join("HOST-CONTROLS.json"),&json!(queue_controls(&stale.input)?))?;
  projected=world.state.clone();let external_ops=transfers(&mut actors,3,&mut projected,&addresses[0],1_000_000_000,200_000_000)?;let mut external=payment(&policy,&world,external_ops)?;
  // Prepare the actual competing receipt before the race; charge its whole cost.
  let (external_cache,child)=cache_begin(&auth,&external,out)?;if let Some(mut c)=child{if !c.wait()?.success(){return Err("external certificate failed".into());}}
  let mut c=cached_begin(&auth,program,&external,&external_cache,&out.join("external"))?;if !c.wait()?.success(){return Err("external settlement failed".into());}
  let clock=Instant::now();let mut events=vec![];let mut queued=vec![];
  let (cache,child)=cache_begin(&auth,&stale,out)?;let mut c=child.ok_or("fresh withdrawal certificate unexpectedly exists")?;
  eprintln!("PHASE retained approval verification with timed payment arrivals");
  loop{arrived(&mut actors,&mut projected,&addresses,&mut queued,&mut events,clock)?;if let Some(status)=c.try_wait()?{if !status.success(){return Err("withdrawal certificate failed".into());}break;}std::thread::sleep(std::time::Duration::from_millis(100));}
  let obsolete=out.join("cancelled-stale-settlement");let mut child=cached_begin(&auth,program,&stale,&cache,&obsolete)?;
  let cancellation_started=Instant::now();
  while !fs::read_to_string(obsolete.with_extension("stderr.log"))?.contains("SETTLE_START"){if child.try_wait()?.is_some(){return Err("stale job stopped before proving".into());}std::thread::sleep(std::time::Duration::from_millis(10));}
  std::thread::sleep(std::time::Duration::from_millis(500));if child.try_wait()?.is_some(){return Err("stale job finished before injection".into());}
  cached_collect(&policy,&mut world,&mut external,&out.join("external"))?;
  let cancelled=Command::new("kill").args(["-TERM","--",&format!("-{}",child.id())]).status()?;if !cancelled.success(){return Err("owned prover group cancellation failed".into());}let status=child.wait()?;
  save(&out.join("CANCELLATION.json"),&json!({"ownedGroupPid":child.id(),"status":status.to_string(),"seconds":cancellation_started.elapsed().as_secs_f64(),"cacheRetained":true,"nativeFeeSompi":0,"reason":"actual accepted competing bank transaction"}))?;
  let retry=intent_step(&policy,&world,&intent,&approvals,0)?;if app::authorization_journal(&retry.input)?!=app::authorization_journal(&stale.input)?{return Err("static receipt changed with current bank".into());}
  let mut retry=retry;let mut child=cached_begin(&auth,program,&retry,&cache,&out.join("withdrawal"))?;
  loop{arrived(&mut actors,&mut projected,&addresses,&mut queued,&mut events,clock)?;if let Some(status)=child.try_wait()?{if !status.success(){return Err("fresh withdrawal failed".into());}break;}std::thread::sleep(std::time::Duration::from_millis(100));}
  cached_collect(&policy,&mut world,&mut retry,&out.join("withdrawal"))?;let withdrawal_wait=clock.elapsed().as_secs_f64();let mut reference=world.clone();
  eprintln!("PHASE withdrawal accepted; work-conserving optional payment batches");
  let mut accepted=0;let mut batches=vec![];let mut payment_ready=vec![];
  while accepted<3{
   arrived(&mut actors,&mut projected,&addresses,&mut queued,&mut events,clock)?;
   if accepted==queued.len(){std::thread::sleep(std::time::Duration::from_millis(100));continue;}
   let end=queued.len();let step=payment(&policy,&world,queued[accepted..end].to_vec())?;let name=format!("payments-{accepted}-{end}");
   let (cache,child)=cache_begin(&auth,&step,out)?;if let Some(mut c)=child{loop{arrived(&mut actors,&mut projected,&addresses,&mut queued,&mut events,clock)?;if let Some(status)=c.try_wait()?{if !status.success(){return Err("payment cache failed".into());}break;}std::thread::sleep(std::time::Duration::from_millis(100));}}
   let mut step=step;let mut child=cached_begin(&auth,program,&step,&cache,&out.join(&name))?;
   loop{arrived(&mut actors,&mut projected,&addresses,&mut queued,&mut events,clock)?;if let Some(status)=child.try_wait()?{if !status.success(){return Err("payment settlement failed".into());}break;}std::thread::sleep(std::time::Duration::from_millis(100));}
   cached_collect(&policy,&mut world,&mut step,&out.join(&name))?;let at=clock.elapsed().as_secs_f64();for i in accepted..end{payment_ready.push(json!({"index":i,"proofReadySeconds":at,"waitSeconds":at-events[i]["walletProofReadySeconds"].as_f64().unwrap()}));}batches.push(json!({"first":accepted,"end":end,"readySeconds":at}));accepted=end;
  }
  let mut final_ops=vec![];let mut final_payouts=vec![];for who in 0..4{let r=actors.call(who,json!({"method":"named"}),Some(&world.state))?;final_ops.extend(serde_json::from_value::<Vec<Operation>>(r["operations"].clone())?);for p in r["payouts"].as_array().ok_or("payouts")?{final_payouts.push(TransactionOutput::new(p["value"].as_u64().ok_or("value")?,native::spk(&serde_json::from_value::<Vec<u8>>(p["spk"].clone())?)));}}
  if final_ops.len()!=5 || world.state.ledger.tree.leaves.len()!=15{return Err("frozen full workload shape".into());}
  let step=named(&policy,&world,final_ops.clone(),final_payouts.clone())?;cached_settle(&auth,program,&policy,&mut world,step,out,"later-payouts")?;
  if world.state.ledger.reserve!=0 || world.state.ledger.private_liability!=0 || world.value!=0{return Err("terminal principal/liability".into());}
  let spends=restore_spends(&mut actors,&world,&refund)?;
  save(&out.join("MAIN.json"),&json!({"records":world.records,"reserve":0,"liability":0,"restoredPayoutSpends":spends,"nativeFull":true,"chainAccepted":false,"principalSompi":4_000_000_000u64,"usefulPaymentSompi":4_700_000_000u64,"withdrawalWaitSeconds":withdrawal_wait,"paymentBatches":batches,"paymentReadiness":payment_ready}))?;
  eprintln!("PHASE matched unbatched payment counterfactual");let start=Instant::now();let mut ref_ready=vec![];
  for (i,op) in queued.iter().enumerate(){while withdrawal_wait+start.elapsed().as_secs_f64()<events[i]["walletProofReadySeconds"].as_f64().ok_or("arrival")?{std::thread::sleep(std::time::Duration::from_millis(100));}let step=payment(&policy,&reference,vec![op.clone()])?;cached_settle(&auth,program,&policy,&mut reference,step,out,&format!("reference-payment-{i}"))?;let ready=withdrawal_wait+start.elapsed().as_secs_f64();ref_ready.push(json!({"index":i,"proofReadySeconds":ready,"waitSeconds":ready-events[i]["walletProofReadySeconds"].as_f64().unwrap()}));}
  let step=named(&policy,&reference,final_ops,final_payouts)?;cached_settle(&auth,program,&policy,&mut reference,step,out,"reference-later-payouts")?;
  if reference.state.ledger.reserve!=0 || reference.state.ledger.private_liability!=0{return Err("reference terminal principal/liability".into());}
  save(&out.join("REFERENCE.json"),&json!({"records":reference.records,"reserve":0,"liability":0,"nativeFull":true,"chainAccepted":false,"commonPrefixCharged":true,"sequentialCounterfactual":true,"withdrawalWaitSeconds":withdrawal_wait,"paymentReadiness":ref_ready}))?;
  save(&out.join("ARRIVALS.json"),&json!({"events":events,"fixedScheduleSeconds":[90,330,570],"boundedPayments":3,"actualCompetingAcceptedUpdates":1}))?;
  if approval_digest(&approvals)!=digest{return Err("repeat wallet approvals".into());}
  save(&out.join("COMPLETE.json"),&json!({"complete":true,"protectedWalletOwnedOutputRegistration":true,"originalApprovals":3,"repeatedApprovals":0,"currentStateAlwaysFresh":true,"consensusChanges":false,"sameHostOnly":true,"serviceOnlyPayoutAssignments":6,"ownerDisclosureAssignments":1,"independentPeople":false,"privacyQualification":false}))?;Ok(())
 })();let _=server.kill();let _=server.wait();result
}

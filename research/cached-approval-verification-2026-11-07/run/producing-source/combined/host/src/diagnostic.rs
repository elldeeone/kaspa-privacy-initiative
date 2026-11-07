pub fn prepare_cases(program:&Path,prior:&Path,out:&Path)->Result<()>{
 fs::create_dir(out)?;
 let policy=Policy{image:risc0_zkvm::compute_image_id(&fs::read(program)?)?.as_bytes().try_into()?};
 let mut certificate=None;
 for (n,name) in ["stale","priority-withdrawal","reference-withdrawal"].iter().enumerate(){
  let original:app::Input=bincode::deserialize(&fs::read(prior.join(name).join("input.bin"))?)?;
  let journal=app::authorization_journal(&original)?;
  if let Some(ref expected)=certificate{if *expected!=journal{return Err("retained packets differ".into());}}else{certificate=Some(journal);}
  let point=native::fake_point(hash(&[b"KPI/new-program/supplied-state/cache-diagnostic/".as_slice(),&[n as u8],&original.effects.previous].concat()));
  let value=original.effects.input_value;let state=original.state;
  let entry=UtxoEntry::new(value,policy.spk(state.root()),0,false,None);
  let world=World{state,point,value,active:HashMap::from([(point,entry.clone())]),records:vec![]};
  let intent=original.packet.intent.as_ref().ok_or("intent")?;
  let step=intent_step(&policy,&world,intent,&original.packet.operations,0)?;
  let dir=out.join(n.to_string());fs::create_dir(&dir)?;
  prover::write(&dir.join("input.bin"),&bincode::serialize(&step.input)?)?;
  save(&dir.join("CASE.json"),&json!({"scope":"supplied new-program UTXO, not accepted ancestry or old-bank upgrade","transaction":step.tx,"inputBincodeHex":hex::encode(bincode::serialize(&step.input)?),"postStateBincodeHex":hex::encode(bincode::serialize(&step.output.state)?),"entryBincodeHex":hex::encode(bincode::serialize(&entry)?),"report":step.report}))?;
 }
 Ok(())
}
pub fn check_case(program:&Path,case:&Path,proof:&Path)->Result<()>{
 let record=read(&case.join("CASE.json"))?;let mut step=recorded_step(&record)?;
 let policy=Policy{image:risc0_zkvm::compute_image_id(&fs::read(program)?)?.as_bytes().try_into()?};
 let entry:UtxoEntry=from_hex(&record["entryBincodeHex"])?;
 let receipt:risc0_zkvm::Receipt=bincode::deserialize(&fs::read(proof.join("candidate-compressed.bin"))?)?;
 prover::verify(&receipt,risc0_zkvm::compute_image_id(&fs::read(program)?)?,&step.output.journal)?;
 finish(&mut step,&policy,&prover::native_proof(&receipt)?,&entry)?;
 save(&proof.join("NATIVE.json"),&json!({"report":step.report,"transaction":step.tx,"suppliedStateOnly":true}))?;
 println!("{}",step.report);Ok(())
}

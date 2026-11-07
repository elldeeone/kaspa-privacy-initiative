use kpi_batched_payment_core as app;
use risc0_zkvm::{Receipt,ExecutorEnv,ProverOpts,VerifierContext,compute_image_id,default_prover,sha::{Digest,Digestible}};
use serde_json::{Value,json};
use std::{fs,path::Path,time::Instant};
pub use crate::original_prover::{Result,write,native_proof,verify};
fn input(path:&Path)->Result<app::Input>{
 use bincode::Options;
 Ok(bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes().deserialize(&fs::read(path)?)?)
}
fn check_auth(receipt:&Receipt,image:Digest,journal:&[u8])->Result<()>{
 receipt.inner.succinct()?;
 receipt.verify_with_context(&VerifierContext::default().with_dev_mode(false),image)?;
 if receipt.journal.bytes!=journal || receipt.claim()?.digest()!=risc0_zkvm::ReceiptClaim::ok(image,journal.to_vec()).digest(){return Err("certificate exact successful unconditional claim".into());}
 if !receipt.claim()?.value()?.output.value()?.ok_or("certificate missing output")?.assumptions.is_empty(){return Err("certificate unresolved assumptions".into());}Ok(())
}
fn environment(raw:&[u8],receipt:Option<Receipt>,method:Option<u32>)->Result<ExecutorEnv<'static>>{
 if std::env::var_os("RISC0_DEV_MODE").is_some(){return Err("development mode forbidden".into());}
 let mut env=ExecutorEnv::builder();
 if let Some(method)=method{env.write_slice(&[method]);}
 env.write_slice(&[u32::try_from(raw.len())?]).write_slice(raw).segment_limit_po2(19).session_limit(Some(1_000_000_000));
 if let Some(receipt)=receipt{env.add_assumption(receipt);}
 Ok(env.build()?)
}
pub fn authorize(program:&Path,path:&Path,out:&Path)->Result<Value>{
 let input=input(path)?;let expected=app::authorize_packet(&input)?;let raw=bincode::serialize(&input)?;
 let program=fs::read(program)?;let image=compute_image_id(&program)?;
 fs::create_dir(out)?;write(&out.join("input.bin"),&raw)?;write(&out.join("journal.bin"),&expected)?;
 let started=Instant::now();eprintln!("AUTHORIZE_START {}",out.display());
 let info=default_prover().prove_with_opts(environment(&raw,None,None)?,&program,&ProverOpts::succinct())?;
 check_auth(&info.receipt,image,&expected)?;
 write(&out.join("receipt.bin"),&bincode::serialize(&info.receipt)?)?;
 let report=json!({"image":image.to_string(),"seconds":started.elapsed().as_secs_f64(),"stats":info.stats,"operations":input.packet.operations.len(),"journalHex":hex::encode(&expected),"unconditionalSuccinct":true,"developmentMode":false});
 write(&out.join("REPORT.json"),&serde_json::to_vec_pretty(&report)?)?;eprintln!("AUTHORIZE_DONE {report}");Ok(report)
}
pub fn settle(auth_program:&Path,program:&Path,path:&Path,cache:&Path,out:&Path)->Result<Value>{
 settle_inner(Some((auth_program,cache)),program,path,out)
}
pub fn direct(program:&Path,path:&Path,out:&Path)->Result<Value>{settle_inner(None,program,path,out)}
fn settle_inner(cached:Option<(&Path,&Path)>,program:&Path,path:&Path,out:&Path)->Result<Value>{
 let input=input(path)?;let expected=app::execute(&input)?;let raw=bincode::serialize(&input)?;
 let mut auth_image=None;
 use bincode::Options;
 let receipt=if let Some((auth_program,cache))=cached{
 let image=compute_image_id(&fs::read(auth_program)?)?;auth_image=Some(image);
 let receipt:Receipt=bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes().deserialize(&fs::read(cache).map_err(|e|format!("missing cached proof receipt: {e}"))?)?;
 check_auth(&receipt,image,&app::authorization_journal(&input)?)?;Some(receipt)
 }else{None};
 let program=fs::read(program)?;let image=compute_image_id(&program)?;
 fs::create_dir(out)?;write(&out.join("input.bin"),&raw)?;write(&out.join("expected-journal.bin"),&expected.journal)?;
 let started=Instant::now();eprintln!("SETTLE_START {}",out.display());
 let info=default_prover().prove_with_opts(environment(&raw,receipt,Some(u32::from(cached.is_some())))?,&program,&ProverOpts::succinct())?;
 info.receipt.verify_with_context(&VerifierContext::default().with_dev_mode(false),image)?;
 if info.receipt.journal.bytes!=expected.journal{return Err("composed exact journal".into());}
 write(&out.join("candidate-succinct.bin"),&bincode::serialize(&info.receipt)?)?;
 let compose_seconds=started.elapsed().as_secs_f64();
 let receipt=default_prover().compress(&ProverOpts::groth16(),&info.receipt)?;
 verify(&receipt,image,&expected.journal)?;
 write(&out.join("candidate-compressed.bin"),&bincode::serialize(&receipt)?)?;
 write(&out.join("native-proof.bin"),&native_proof(&receipt)?)?;
 let report=json!({"image":image.to_string(),"authorizationImage":auth_image.map(|i|i.to_string()),"seconds":started.elapsed().as_secs_f64(),"compositionSeconds":compose_seconds,"stats":info.stats,"unresolvedAssumptions":0,"nativeGroth16":true,"currentStateChecksFresh":true,"cachedVerification":cached.is_some()});
 write(&out.join("REPORT.json"),&serde_json::to_vec_pretty(&report)?)?;eprintln!("SETTLE_DONE {report}");Ok(report)
}
/// Legacy helper required by reused benchmark source; the original full-check
/// path remains available for explicit direct controls, never a cached shortcut.
pub fn prove(program:&[u8],input:&app::Input,out:&Path)->Result<(Vec<u8>,Value)>{crate::original_prover::prove(program,input,out)}
pub use crate::original_prover::reject_guest;

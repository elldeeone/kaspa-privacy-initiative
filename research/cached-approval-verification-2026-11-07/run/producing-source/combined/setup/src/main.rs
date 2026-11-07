//! One-party experimental parameters. No production setup or funds qualification.
#[path="../../../batched-payment-costs/host/src/circuit.rs"] mod circuit;
#[path="../../../batched-payment-costs/host/src/proof.rs"] mod proof;
use kpi_private_note_wallet::{protocol::*,wallet::Wallet};
use ark_serialize::{CanonicalSerialize,CanonicalDeserialize};
use std::{fs,path::Path,time::Instant,os::unix::fs::{PermissionsExt,OpenOptionsExt},io::Write};
fn main()->Result<(),Box<dyn std::error::Error>>{
 let args=std::env::args().collect::<Vec<_>>();let out=Path::new(&args[1]);fs::create_dir(out)?;fs::set_permissions(out,fs::Permissions::from_mode(0o700))?;
 let started=Instant::now();let w=Wallet::new();let n=w.note(4_000_000_000);let d=n.deliver()?;
 let mut s=Statement::new(CREDIT,[0;32],Tree::default().root());s.deposit=hash(b"KPI-testnet-parameter-sample");s.deposit_owner=w.address.owner;s.deposit_value=n.value;s.outputs[0]=d.commitment;s.delivery[0]=hash(&d.ciphertext);
 let witness=w.witness(w.authority_note(),[n,Note::dummy()],[[0;32];DEPTH],[false;DEPTH]);
 let mut engine=proof::Engine::setup(circuit::WalletCircuit{statement:s.clone(),witness:witness.clone()});
 let op=engine.prove(s,witness,[d,Delivery::absent()]);assert!(engine.verify(&op));
 let compressed=proof::serialize(&engine.vk);let checked=ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(compressed.as_slice())?;assert_eq!(checked.gamma_abc_g1.len(),3);assert_eq!(proof::serialize(&checked),compressed);
 let mut full=vec![];checked.serialize_uncompressed(&mut full)?;
 let mut f=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(out.join("proving-parameters.bin"))?;engine.pk.serialize_compressed(&mut f)?;f.sync_all()?;
 fs::write(out.join("vk-compressed.bin"),&compressed)?;fs::write(out.join("vk-uncompressed.bin"),&full)?;
 fs::write(out.join("REPORT.json"),serde_json::to_vec_pretty(&serde_json::json!({"experimentalOnePartySetup":true,"domain":hex::encode(domain()),"depth":DEPTH,"constraints":engine.constraints,"verifier":hex::encode(engine.id()),"seconds":started.elapsed().as_secs_f64(),"verifiedRealSample":true}))?)?;
 println!("{}",out.display());Ok(())
}

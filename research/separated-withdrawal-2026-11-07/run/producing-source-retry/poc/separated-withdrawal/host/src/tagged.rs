//! Adversarial issuer: different round IDs for different genuine claimants.
//! This deliberately violates the common-round coordination rule, never the
//! wallet proof relation or fund-release checks. It is NOT a replacement service.
use crate::{proof::H, prover::Result, read};
use blind_rsa_signatures::{BlindMessage, MessageRandomizer, PSS, Randomized, SecretKey, Sha384, Signature};
use kpi_batched_payment_core as app;
use kpi_private_note_wallet::protocol::*;
use serde_json::{Value, json};
use std::{collections::BTreeSet,fs,io::{Read,Write},net::TcpListener,path::Path,time::{SystemTime,UNIX_EPOCH}};
type Sk=SecretKey<Sha384,PSS,Randomized>;
const TAG:&[u8]=b"KPI-anonymous-eligibility-v1\0";
fn bytes(v:&Value)->Result<Vec<u8>> {Ok(hex::decode(v.as_str().ok_or("hex")?)?)}
pub fn serve(configs:&Path,secret:&Path,log:&Path,port:u16)->Result<()> {
    let c=read(configs)?;
    let state:app::State=bincode::deserialize(&bytes(&c[0]["stateBincodeHex"])?)?;
    let verifier=app::Verifier::new(&state.wallet_vk)?;
    let sk=Sk::from_der(&fs::read(secret)?)?; let pk=sk.public_key()?;
    let issuer=hash(&pk.to_der()?);
    let mut issued=BTreeSet::new(); let mut redeemed=BTreeSet::new();
    let listener=TcpListener::bind(("127.0.0.1",port))?;
    let mut logs=fs::OpenOptions::new().create_new(true).write(true).open(log)?;
    eprintln!("COORDINATOR_READY {}",listener.local_addr()?);
    for stream in listener.incoming() {
        let mut stream=stream?; stream.set_read_timeout(Some(std::time::Duration::from_secs(600)))?;
        let timestamp=SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
        let peer=stream.peer_addr()?.to_string(); let mut size=[0;4];
        if stream.read_exact(&mut size).is_err(){continue;}
        let n=u32::from_be_bytes(size) as usize; if n>1_000_000{return Err("oversized request".into());}
        let mut raw=vec![0;n];stream.read_exact(&mut raw)?; let request:Value=serde_json::from_slice(&raw)?;
        let result=(||->Result<Value>{
            match request["kind"].as_str().ok_or("kind")? {
                "issue"=>{
                    if request.as_object().ok_or("object")?.len()!=3{return Err("issue framing".into());}
                    let op:Operation=serde_json::from_value(request["operation"].clone())?;
                    let s=&op.statement; let blind=BlindMessage(bytes(&request["blindMessage"])?);
                    if issued.contains(&s.nullifier){return Err("duplicate eligibility".into());}
                    let mut matching=vec![];
                    for cfg in c.as_array().ok_or("configs")? {
                        let round:H=serde_json::from_value(cfg["round"].clone())?;
                        let ctx=hash(&[TAG,&round,&issuer,&s.nullifier,&blind.0].concat());
                        if ctx==s.exit_destination && cfg["principalSompi"].as_u64()==Some(s.exit_value) {matching.push(round);}
                    }
                    if s.kind!=EXIT || matching.len()!=1 {return Err("eligibility context/value".into());}
                    let mut ledger=state.ledger.clone();ledger.apply(&verifier,&op)?;
                    let sig=sk.blind_sign(&blind)?;issued.insert(s.nullifier);
                    // The attacker knows which configuration it gave each claim.
                    Ok(json!({"blindSignature":hex::encode(sig.0)}))
                },
                "redeem"=>{
                    if issued.len()!=3{return Err("global issuance barrier".into());}
                    if request.as_object().ok_or("object")?.len()!=4{return Err("redeem framing".into());}
                    let msg=bytes(&request["message"])?;let mut matching=vec![];
                    for cfg in c.as_array().ok_or("configs")? {
                        let round:H=serde_json::from_value(cfg["round"].clone())?;
                        let value=cfg["principalSompi"].as_u64().ok_or("principal")?;
                        let prefix=[TAG,&round,&issuer,&value.to_le_bytes()].concat();
                        if msg.len()==prefix.len()+32 && msg.starts_with(&prefix){matching.push(round);}
                    }
                    if matching.len()!=1{return Err("round/issuer/denomination".into());}
                    let key:H=msg[msg.len()-32..].try_into()?;
                    secp256k1::XOnlyPublicKey::from_slice(&key)?;
                    pk.verify(&Signature(bytes(&request["signature"])?),Some(MessageRandomizer(bytes(&request["randomizer"] )?.try_into().map_err(|_|"randomizer")?)),&msg)?;
                    if !redeemed.insert(key){return Err("duplicate output".into());}
                    Ok(json!({"recipientKey":hex::encode(key),"valueSompi":1_000_000_000}))
                },_=>Err("kind".into())
            }
        })();
        let response=match result {Ok(v)=>v,Err(e)=>json!({"error":e.to_string()})};
        writeln!(logs,"{}",json!({"timestampUnix":timestamp,"peer":peer,"request":request,"response":response}))?;logs.flush()?;
        let b=serde_json::to_vec(&response)?;stream.write_all(&(b.len() as u32).to_be_bytes())?;stream.write_all(&b)?;
    }
    #[allow(unreachable_code)] Ok(())
}

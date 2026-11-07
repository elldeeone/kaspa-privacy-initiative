//! A real issuer which may hold completed issue requests and release replies
//! one at a time. This tests service-controlled ordering, not clock guessing.
use crate::{proof::H, prover::Result, read};
use blind_rsa_signatures::{BlindMessage, MessageRandomizer, Randomized, SecretKey, Sha384, Signature, PSS};
use kpi_batched_payment_core as app;
use kpi_private_note_wallet::protocol::{hash, Operation, EXIT};
use serde_json::{json, Value};
use std::{collections::BTreeSet, fs, io::{Read, Write}, net::{TcpListener, TcpStream}, path::Path, time::{SystemTime, UNIX_EPOCH}};

type Sk = SecretKey<Sha384, PSS, Randomized>;
const TAG: &[u8] = b"KPI-anonymous-eligibility-v1\0";
fn bytes(v: &Value) -> Result<Vec<u8>> { Ok(hex::decode(v.as_str().ok_or("hex")?)?) }
fn recv(stream: &mut TcpStream) -> Result<Value> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(600)))?;
    let mut size = [0; 4]; stream.read_exact(&mut size)?;
    let n = u32::from_be_bytes(size) as usize;
    if n > 1_000_000 { return Err("oversized request".into()); }
    let mut raw = vec![0; n]; stream.read_exact(&mut raw)?;
    Ok(serde_json::from_slice(&raw)?)
}
fn respond(stream: &mut TcpStream, v: &Value) -> Result<()> {
    let b = serde_json::to_vec(v)?;
    stream.write_all(&(b.len() as u32).to_be_bytes())?;
    stream.write_all(&b)?;
    Ok(())
}
fn log(logs: &mut fs::File, peer: &str, request: &Value, response: &Value) -> Result<()> {
    let at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
    writeln!(logs,"{}",json!({"timestampUnix":at,"peer":peer,"request":request,"response":response}))?;
    logs.flush()?;
    Ok(())
}
pub fn serve(configs: &Path, secret: &Path, log_path: &Path, port: u16, mode: &str) -> Result<()> {
    if !["honest", "tagged", "staggered"].contains(&mode) { return Err("mode".into()); }
    let supplied = read(configs)?;
    let configs = if supplied.is_array() { supplied.as_array().ok_or("configs")?.clone() } else { vec![supplied] };
    let state: app::State = bincode::deserialize(&bytes(&configs[0]["stateBincodeHex"])?)?;
    let verifier = app::Verifier::new(&state.wallet_vk)?;
    let sk = Sk::from_der(&fs::read(secret)?)?;
    let pk = sk.public_key()?;
    let issuer = hash(&pk.to_der()?);
    if configs.iter().any(|c| c["issuer"] != json!(issuer) || c["stateBincodeHex"] != configs[0]["stateBincodeHex"]) {
        return Err("issuer/state mismatch".into());
    }
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let mut logs = fs::OpenOptions::new().create_new(true).write(true).open(log_path)?;
    eprintln!("COORDINATOR_READY {}", listener.local_addr()?);
    let mut pending = Vec::new();
    let mut claims = BTreeSet::new();
    for _ in 0..3 {
        let (mut stream, _) = listener.accept()?;
        let peer = stream.peer_addr()?.to_string();
        let request = recv(&mut stream)?;
        if request["kind"] != "issue" || request.as_object().ok_or("issue")?.len() != 3 { return Err("issue framing".into()); }
        let op: Operation = serde_json::from_value(request["operation"].clone())?;
        let s = &op.statement;
        let blind = BlindMessage(bytes(&request["blindMessage"])?);
        let matching = configs.iter().filter(|c| {
            let round: H = match serde_json::from_value(c["round"].clone()) { Ok(v) => v, Err(_) => return false };
            s.exit_destination == hash(&[TAG, &round, &issuer, &s.nullifier, &blind.0].concat())
                && c["principalSompi"].as_u64() == Some(s.exit_value)
        }).count();
        if s.kind != EXIT || matching != 1 || !claims.insert(s.nullifier) { return Err("eligibility context or duplicate".into()); }
        state.ledger.clone().apply(&verifier, &op)?;
        let signature = sk.blind_sign(&blind)?;
        pending.push((stream, peer, request, hex::encode(signature.0)));
    }
    let cohort = pending.iter().map(|p| p.2.clone()).collect::<Vec<_>>();
    let mut keys = BTreeSet::new();
    let mut redeem_one = |logs: &mut fs::File| -> Result<()> {
        let (mut stream, _) = listener.accept()?;
        let peer = stream.peer_addr()?.to_string();
        let request = recv(&mut stream)?;
        if request["kind"] != "redeem" || request.as_object().ok_or("redeem")?.len() != 4 { return Err("redeem framing".into()); }
        let msg = bytes(&request["message"])?;
        let matched = configs.iter().filter_map(|c| {
            let round: H = serde_json::from_value(c["round"].clone()).ok()?;
            let value = c["principalSompi"].as_u64()?;
            let prefix = [TAG, &round, &issuer, &value.to_le_bytes()].concat();
            if msg.len() == prefix.len()+32 && msg.starts_with(&prefix) { Some((value,prefix.len())) } else { None }
        }).collect::<Vec<_>>();
        if matched.len() != 1 { return Err("redeem config".into()); }
        let (value,start) = matched[0];
        let key: H = msg[start..].try_into()?;
        secp256k1::XOnlyPublicKey::from_slice(&key)?;
        let randomizer = MessageRandomizer(bytes(&request["randomizer"])?.try_into().map_err(|_| "randomizer")?);
        pk.verify(&Signature(bytes(&request["signature"])?), Some(randomizer), &msg)?;
        if !keys.insert(key) { return Err("duplicate payout".into()); }
        let response = json!({"recipientKey":hex::encode(key),"valueSompi":value});
        log(logs, &peer, &request, &response)?;
        respond(&mut stream, &response)?;
        Ok(())
    };
    for (mut stream,peer,request,signature) in pending {
        let response = json!({"blindSignature":signature,"cohortIssues":cohort});
        log(&mut logs, &peer, &request, &response)?;
        respond(&mut stream, &response)?;
        if mode == "staggered" { redeem_one(&mut logs)?; }
    }
    if mode == "honest" { for _ in 0..3 { redeem_one(&mut logs)?; } }
    // Tagged wallets refuse redemption, so no redeem requests are expected.
    Ok(())
}

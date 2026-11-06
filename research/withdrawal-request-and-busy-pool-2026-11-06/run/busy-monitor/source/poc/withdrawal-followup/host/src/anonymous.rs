//! Experimental identity-free coordinator. Proofs authorize; no human roster.
use crate::{
    proof::{self, Engine, H},
    prover::{self, Result},
};
use blind_rsa_signatures::{
    BlindMessage, BlindSignature, BlindingResult, DefaultRng, KeyPair, MessageRandomizer, PSS,
    PublicKey, Randomized, Secret, SecretKey, Sha384, Signature,
};
use kpi_batched_payment_core as app;
use kpi_private_note_wallet::{circuit::Witness, protocol::*};
use rand::{RngCore, rngs::OsRng};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
type Pk = PublicKey<Sha384, PSS, Randomized>;
type Sk = SecretKey<Sha384, PSS, Randomized>;
const TAG: &[u8] = b"KPI-anonymous-eligibility-v1\0";
fn save(p: &Path, v: &Value) -> Result<()> {
    prover::write(p, &serde_json::to_vec_pretty(v)?)
}
fn read(p: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}
fn bytes(v: &Value) -> Result<Vec<u8>> {
    Ok(hex::decode(v.as_str().ok_or("hex")?)?)
}
fn context(round: H, issuer: H, nf: H, blind: &[u8]) -> H {
    hash(&[TAG, &round, &issuer, &nf, blind].concat())
}
fn message(round: H, issuer: H, value: u64, key: H) -> Vec<u8> {
    [TAG, &round, &issuer, &value.to_le_bytes(), &key].concat()
}

pub fn prepare(
    engine: &mut Engine,
    witnesses: &[Witness; 3],
    state: &app::State,
    out: &Path,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir(out.join("private"))?;
    fs::set_permissions(out.join("private"), fs::Permissions::from_mode(0o700))?;
    let keys = KeyPair::<Sha384, PSS, Randomized>::generate(&mut DefaultRng, 2048)?;
    let der = keys.pk.to_der()?;
    let issuer = hash(&der);
    let mut round = [0; 32];
    OsRng.fill_bytes(&mut round);
    let config = json!({"round":round,"issuer":issuer,"issuerDer":hex::encode(der),"principalSompi":witnesses[0].input.value,"stateBincodeHex":hex::encode(bincode::serialize(state)?)});
    save(&out.join("config.json"), &config)?;
    prover::write(&out.join("private/issuer.der"), &keys.sk.to_der()?)?;
    let mut truth = vec![];
    for (i, w) in witnesses.iter().enumerate() {
        let sk = secp256k1::SecretKey::new(&mut OsRng);
        let key = secp256k1::Keypair::from_secret_key(&secp256k1::Secp256k1::new(), &sk)
            .x_only_public_key()
            .0
            .serialize();
        let msg = message(round, issuer, w.input.value, key);
        let blind = keys.pk.blind(&mut DefaultRng, &msg)?;
        let nf = nullifier(&w.secret, &w.input);
        let auth = engine.authorize(
            w,
            context(round, issuer, nf, &blind.blind_message.0),
            state.ledger.tree.root(),
        );
        let issue = json!({"kind":"issue","blindMessage":hex::encode(&blind.blind_message.0),"operation":auth});
        save(
            &out.join(format!("private/client-{i}.json")),
            &json!({"issue":issue,"message":hex::encode(msg),"blindSecret":hex::encode(blind.secret.0),"randomizer":hex::encode(blind.msg_randomizer.unwrap().0)}),
        )?;
        truth.push(json!({"owner":format!("owner-{}",i+1),"sourceAddress":format!("127.0.0.{}",i+2),"nullifier":hex::encode(nf),"recipientKey":hex::encode(key),"valueSompi":w.input.value}));
    }
    save(&out.join("private/truth.json"), &json!(truth))?;
    Ok(())
}
pub fn finalize(config: &Path, client: &Path, response: &Path, out: &Path) -> Result<()> {
    let c = read(config)?;
    let v = read(client)?;
    let r = read(response)?;
    let pk = Pk::from_der(&bytes(&c["issuerDer"])?)?;
    let msg = bytes(&v["message"])?;
    let randomizer = MessageRandomizer(
        bytes(&v["randomizer"])?
            .try_into()
            .map_err(|_| "randomizer width")?,
    );
    let state = BlindingResult {
        blind_message: BlindMessage(bytes(&v["issue"]["blindMessage"])?),
        secret: Secret(bytes(&v["blindSecret"])?),
        msg_randomizer: Some(randomizer),
    };
    let signature = pk.finalize(&BlindSignature(bytes(&r["blindSignature"])?), &state, &msg)?;
    save(
        out,
        &json!({"kind":"redeem","message":hex::encode(msg),"signature":hex::encode(signature.0),"randomizer":hex::encode(randomizer.0)}),
    )
}
pub fn serve(config: &Path, secret: &Path, log: &Path, port: u16) -> Result<()> {
    let c = read(config)?;
    let state: app::State = bincode::deserialize(&bytes(&c["stateBincodeHex"])?)?;
    let verifier = app::Verifier::new(&state.wallet_vk)?;
    let round: H = serde_json::from_value(c["round"].clone())?;
    let issuer: H = serde_json::from_value(c["issuer"].clone())?;
    let principal = c["principalSompi"].as_u64().ok_or("principal")?;
    let sk = Sk::from_der(&fs::read(secret)?)?;
    let pk = sk.public_key()?;
    if hash(&pk.to_der()?) != issuer {
        return Err("issuer identity".into());
    }
    let mut issued = BTreeSet::new();
    let mut redeemed = BTreeSet::new();
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let mut logs = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(log)?;
    eprintln!("COORDINATOR_READY {}", listener.local_addr()?);
    for stream in listener.incoming() {
        let mut stream = stream?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(60)))?;
        let peer = stream.peer_addr()?.to_string();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64();
        let mut size = [0; 4];
        if stream.read_exact(&mut size).is_err() {
            continue;
        }
        let n = u32::from_be_bytes(size) as usize;
        if n > 1_000_000 {
            continue;
        }
        let mut raw = vec![0; n];
        stream.read_exact(&mut raw)?;
        let request: Value = serde_json::from_slice(&raw)?;
        let result = (|| -> Result<Value> {
            // Strict framing prevents extra identity fields silently reaching logs.
            let fields = request.as_object().ok_or("object")?;
            match request["kind"].as_str().ok_or("kind")? {
                "issue" => {
                    if fields.len() != 3 {
                        return Err("unexpected issue field".into());
                    }
                    let op: Operation = serde_json::from_value(request["operation"].clone())?;
                    let blind = BlindMessage(bytes(&request["blindMessage"])?);
                    let s = &op.statement;
                    if issued.contains(&s.nullifier) {
                        return Err("duplicate eligibility".into());
                    }
                    if s.kind != EXIT
                        || s.exit_value != principal
                        || s.exit_destination != context(round, issuer, s.nullifier, &blind.0)
                    {
                        return Err("eligibility context/value".into());
                    }
                    let mut trial = state.ledger.clone();
                    trial.apply(&verifier, &op)?;
                    let signature = sk.blind_sign(&blind)?;
                    issued.insert(s.nullifier);
                    Ok(json!({"blindSignature":hex::encode(signature.0)}))
                }
                "redeem" => {
                    if fields.len() != 4 {
                        return Err("unexpected redemption field".into());
                    }
                    if issued.len() != 3 {
                        return Err("issuance barrier".into());
                    }
                    let msg = bytes(&request["message"])?;
                    let prefix = message(round, issuer, principal, [0; 32]);
                    let start = prefix.len() - 32;
                    if msg.len() != prefix.len() || msg[..start] != prefix[..start] {
                        return Err("round/issuer/denomination framing".into());
                    }
                    let key: H = msg[start..].try_into()?;
                    secp256k1::XOnlyPublicKey::from_slice(&key)?;
                    let sig = Signature(bytes(&request["signature"])?);
                    let randomizer = MessageRandomizer(
                        bytes(&request["randomizer"])?
                            .try_into()
                            .map_err(|_| "randomizer width")?,
                    );
                    pk.verify(&sig, Some(randomizer), &msg)?;
                    if !redeemed.insert(key) {
                        return Err("duplicate output".into());
                    }
                    Ok(json!({"recipientKey":hex::encode(key),"valueSompi":principal}))
                }
                _ => Err("request kind".into()),
            }
        })();
        let response = match result {
            Ok(v) => v,
            Err(e) => json!({"error":e.to_string()}),
        };
        writeln!(
            logs,
            "{}",
            json!({"timestampUnix":timestamp,"peer":peer,"request":request,"response":response})
        )?;
        logs.flush()?;
        let b = serde_json::to_vec(&response)?;
        stream.write_all(&(b.len() as u32).to_be_bytes())?;
        stream.write_all(&b)?;
    }
    Ok(())
}

/// Independent public replay: no issuer key, wallet backup or prover parameters.
pub fn verify_logs(config: &Path, log: &Path, out: &Path) -> Result<()> {
    use ark_serialize::CanonicalDeserialize;
    let c = read(config)?;
    let state: app::State = bincode::deserialize(&bytes(&c["stateBincodeHex"])?)?;
    let round: H = serde_json::from_value(c["round"].clone())?;
    let issuer: H = serde_json::from_value(c["issuer"].clone())?;
    let pk = Pk::from_der(&bytes(&c["issuerDer"])?)?;
    let vk = ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(
        state.wallet_vk.as_slice(),
    )?;
    let verifier = app::Verifier::new(&state.wallet_vk)?;
    let mut claims = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut negative = 0;
    for line in fs::read_to_string(log)?.lines() {
        let v: Value = serde_json::from_str(line)?;
        let r = &v["request"];
        if v["response"].get("error").is_some() {
            negative += 1;
            continue;
        }
        match r["kind"].as_str().ok_or("kind")? {
            "issue" => {
                let op: Operation = serde_json::from_value(r["operation"].clone())?;
                if !claims.insert(op.statement.nullifier) || !proof::verify(&vk, &op) {
                    return Err("independent eligibility proof/replay".into());
                }
                if op.statement.exit_destination
                    != context(
                        round,
                        issuer,
                        op.statement.nullifier,
                        &bytes(&r["blindMessage"])?,
                    )
                    || op.statement.exit_value != c["principalSompi"].as_u64().ok_or("principal")?
                {
                    return Err("eligibility context/value".into());
                }
                let mut ledger = state.ledger.clone();
                ledger.apply(&verifier, &op)?;
            }
            "redeem" => {
                if claims.len() != 3 {
                    return Err("public issuance barrier".into());
                }
                let msg = bytes(&r["message"])?;
                let key: H = msg[msg.len() - 32..].try_into()?;
                if !keys.insert(key) {
                    return Err("duplicate payout".into());
                }
                if msg
                    != message(
                        round,
                        issuer,
                        c["principalSompi"].as_u64().ok_or("principal")?,
                        key,
                    )
                {
                    return Err("public message framing".into());
                }
                pk.verify(
                    &Signature(bytes(&r["signature"])?),
                    Some(MessageRandomizer(
                        bytes(&r["randomizer"])?
                            .try_into()
                            .map_err(|_| "randomizer")?,
                    )),
                    &msg,
                )?;
                if v["response"]["recipientKey"] != hex::encode(key) {
                    return Err("response payout key".into());
                }
            }
            _ => return Err("public request kind".into()),
        }
    }
    if claims.len() != 3 || keys.len() != 3 || negative < 8 {
        return Err("incomplete public logs".into());
    }
    save(
        out,
        &json!({"newProcess":true,"genuineEligibilityProofs":3,"independentArkworksVerification":true,"finalRfc9474Signatures":3,"negativeResponses":negative,"privateMaterialUsed":false}),
    )
}

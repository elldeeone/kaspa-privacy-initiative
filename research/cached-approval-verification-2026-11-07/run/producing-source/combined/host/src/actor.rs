//! A wallet process. Opens only its own backup plus cached public parameters.
//! Same-host process separation is experimental, not a security sandbox.
use crate::{
    native,
    proof::{Engine, H},
    prover::Result,
};
use ark_serialize::CanonicalDeserialize;
use kaspa_consensus_core::tx::*;
use kpi_batched_payment_core as app;
use kpi_private_note_wallet::{
    protocol::*,
    wallet::{Address, Wallet},
};
use rand::rngs::OsRng;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, Write},
    path::Path,
    time::Instant,
};

#[derive(Serialize, Deserialize)]
struct Backup {
    wallet: Vec<u8>,
    funding: H,
    payouts: BTreeMap<String, H>,
}
fn fresh_key() -> H {
    SecretKey::new(&mut OsRng).secret_bytes()
}
fn public(k: &H) -> H {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(k).unwrap())
        .x_only_public_key()
        .0
        .serialize()
}
fn p2pk(k: &H) -> ScriptPublicKey {
    native::spk(&[vec![0, 0, 32], public(k).to_vec(), vec![0xac]].concat())
}
fn store(dir: &Path, b: &Backup) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let p = dir.join("backup.new");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&p)?;
    f.write_all(&serde_json::to_vec(b)?)?;
    f.sync_all()?;
    fs::rename(p, dir.join("backup.json"))?;
    Ok(())
}
fn field<T: serde::de::DeserializeOwned>(r: &Value, k: &str) -> Result<T> {
    Ok(serde_json::from_value(r[k].clone())?)
}
fn handle(dir: &Path, params: &Path, r: &Value, cache: &mut Option<Engine>) -> Result<Value> {
    use std::os::unix::fs::PermissionsExt;
    let started = Instant::now();
    if !dir.exists() {
        fs::create_dir(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        let w = Wallet::new();
        store(
            dir,
            &Backup {
                wallet: w.local_backup().to_vec(),
                funding: fresh_key(),
                payouts: BTreeMap::from([("group".into(), fresh_key())]),
            },
        )?;
    }
    let mut backup: Backup = serde_json::from_slice(&fs::read(dir.join("backup.json"))?)?;
    let wallet = Wallet::restore_local(
        &backup
            .wallet
            .clone()
            .try_into()
            .map_err(|_| "wallet width")?,
    );
    let method = r["method"].as_str().ok_or("method")?;
    let result = if method == "registration-redeem" {
        crate::anonymous::redeem_local(dir,r)?
    } else if method == "public" {
        json!({"owner":wallet.address.owner,"incoming":wallet.address.incoming,"fundingSpk":native::encoded(&p2pk(&backup.funding))})
    } else if method == "owns" {
        let entry:UtxoEntry=bincode::deserialize(&hex::decode(r["entry"].as_str().ok_or("entry")?)?)?;
        json!({"owns":backup.payouts.values().any(|k|p2pk(k)==entry.script_public_key)})
    } else if method == "sign" {
        let mut tx: Transaction = bincode::deserialize(&hex::decode(
            r["transaction"].as_str().ok_or("transaction")?,
        )?)?;
        let entry: UtxoEntry =
            bincode::deserialize(&hex::decode(r["entry"].as_str().ok_or("entry")?)?)?;
        let k = if entry.script_public_key == p2pk(&backup.funding) {
            backup.funding
        } else {
            *backup
                .payouts
                .values()
                .find(|k| p2pk(k) == entry.script_public_key)
                .ok_or("wallet does not own payout")?
        };
        if tx.inputs.len() != 1 || tx.outputs.is_empty() || tx.outputs.iter().any(|o| o.value == 0)
        {
            return Err("wallet signing shape".into());
        }
        if r["funding"].as_bool() == Some(true) {
            let initial: app::State = bincode::deserialize(&tx.payload)?;
            let image: H = field(&r, "image")?;
            if entry.amount != 4_300_000_000
                || entry.script_public_key != p2pk(&backup.funding)
                || tx.outputs.len() != 2
                || initial.ledger.reserve != 4_000_000_000
                || initial.fee_refund_spk != native::encoded(&entry.script_public_key)
                || tx.outputs[0].value != 4_200_000_000
                || tx.outputs[0].script_public_key != (native::Policy { image }).spk(initial.root())
                || tx.outputs[1].script_public_key != entry.script_public_key
            {
                return Err("wallet funding entitlement".into());
            }
        } else if tx.outputs.len() != 1
            || tx.outputs[0].script_public_key != entry.script_public_key
            || tx.outputs[0].value >= entry.amount
        {
            return Err("wallet recovery self-spend entitlement".into());
        }
        let pop = PopulatedTransaction::new(&tx, vec![entry]);
        tx.inputs[0].signature_script = kaspa_consensus_core::sign::sign_input(
            &pop,
            0,
            &k,
            kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL,
        );
        tx.finalize();
        json!({"transaction":hex::encode(bincode::serialize(&tx)?),"restoredOwnKey":true})
    } else {
        let state: app::State =
            bincode::deserialize(&hex::decode(r["state"].as_str().ok_or("state")?)?)?;
        let notes = wallet.discover(
            &state.ledger.deliveries,
            &state.ledger.tree,
            &state.ledger.nullifiers,
        );
        if method == "entitlement" {
            let value = r["value"].as_u64().ok_or("value")?;
            let n = notes
                .iter()
                .find(|n| n.0.value == value)
                .ok_or("owned entitlement")?;
            json!({"nullifier":wallet.nf(&n.0)})
        } else {
            if cache.is_none() {
                let pk = ark_groth16::ProvingKey::<ark_bn254::Bn254>::deserialize_compressed(
                    fs::read(params)?.as_slice(),
                )?;
                *cache = Some(Engine {
                    vk: pk.vk.clone(),
                    pk,
                    proofs: 0,
                    constraints: if cfg!(feature="testnet"){1_209_140}else{1_209_100},
                });
            }
            let engine = cache.as_mut().unwrap();
            let before = engine.proofs;
            if engine.id() != state.ledger.verifier {
                return Err("public parameter identity".into());
            }
            let mut operations = vec![];
            let mut payouts = vec![];
            match method {
                "registration-issue" => {
                    let value=r["config"]["principalSompi"].as_u64().ok_or("principal")?;
                    let n=notes.iter().find(|n|n.0.value==value).ok_or("registration note")?;
                    let (p,q)=state.ledger.tree.path(n.1)?;
                    let witness=wallet.witness(n.0.clone(),[Note::dummy(),Note::dummy()],p,q);
                    let result=crate::anonymous::issue_local(dir,r,&state,&witness,public(&backup.payouts["group"]),engine)?;
                    return Ok(json!({"result":result,"processId":std::process::id(),"seconds":started.elapsed().as_secs_f64(),"onlyOwnBackupRead":true}));
                }
                "credit" => {
                    let n = wallet.note(4_000_000_000);
                    let mut s = Statement::new(CREDIT, engine.id(), state.ledger.tree.root());
                    s.deposit = state.pool;
                    s.deposit_owner = wallet.address.owner;
                    s.deposit_value = n.value;
                    operations.push(engine.prove(
                        s,
                        wallet.witness(
                            wallet.authority_note(),
                            [n.clone(), Note::dummy()],
                            [[0; 32]; DEPTH],
                            [false; DEPTH],
                        ),
                        [n.deliver()?, Delivery::absent()],
                    ));
                }
                "transfer" => {
                    let input_value = r["inputValue"].as_u64().ok_or("input value")?;
                    let amount = r["amount"].as_u64().ok_or("amount")?;
                    let n = notes
                        .iter()
                        .find(|n| n.0.value == input_value)
                        .ok_or("owned unspent input")?;
                    if amount == 0 || amount >= input_value {
                        return Err("two positive outputs required".into());
                    }
                    let addr = Address {
                        owner: field(&r["recipient"], "owner")?,
                        incoming: field(&r["recipient"], "incoming")?,
                    };
                    let output = Note::for_address(&addr, amount);
                    let change = wallet.note(input_value - amount);
                    let (p, q) = state.ledger.tree.path(n.1)?;
                    let mut s = Statement::new(TRANSFER, engine.id(), state.ledger.tree.root());
                    s.nullifier = wallet.nf(&n.0);
                    operations.push(engine.prove(
                        s,
                        wallet.witness(n.0.clone(), [output.clone(), change.clone()], p, q),
                        [output.deliver()?, change.deliver()?],
                    ));
                }
                "approve" => {
                    let intent: app::WithdrawalIntent = field(&r, "intent")?;
                    let n = notes
                        .iter()
                        .find(|n| n.0.value == intent.denomination)
                        .ok_or("owned cohort note")?;
                    if intent.pool != state.pool
                        || intent.protocol_domain != domain()
                        || intent.verifier != engine.id()
                        || intent.reference_anchor != state.ledger.tree.root()
                        || intent.refund_key_hash != hash(&state.fee_refund_spk)
                        || intent.denomination != 1_000_000_000
                        || intent.fee_cap > 20_000_000
                        || intent.fee_cap == 0
                        || !intent.claims.contains(&wallet.nf(&n.0))
                        || !intent
                            .payouts
                            .contains(&native::encoded(&p2pk(&backup.payouts["group"])))
                    {
                        return Err("wallet full intent entitlement".into());
                    }
                    let (p, q) = state.ledger.tree.path(n.1)?;
                    operations.push(engine.authorize(
                        &wallet.witness(n.0.clone(), [Note::dummy(), Note::dummy()], p, q),
                        intent.commitment(),
                        intent.reference_anchor,
                    ));
                }
                "named" => {
                    for (n, pos) in notes {
                        let nf = wallet.nf(&n);
                        let label = hex::encode(nf);
                        let k = *backup.payouts.entry(label).or_insert_with(fresh_key);
                        let spk = p2pk(&k);
                        let (p, q) = state.ledger.tree.path(pos)?;
                        let dest = hash(&[vec![0], public(&k).to_vec()].concat());
                        operations.push(engine.authorize(
                            &wallet.witness(n.clone(), [Note::dummy(), Note::dummy()], p, q),
                            dest,
                            state.ledger.tree.root(),
                        ));
                        payouts.push(json!({"value":n.value,"spk":native::encoded(&spk)}));
                    }
                    store(dir, &backup)?;
                }
                _ => return Err("unknown actor method".into()),
            }
            json!({"operations":operations,"payouts":payouts,"proofs":engine.proofs-before})
        }
    };
    Ok(
        json!({"result":result,"processId":std::process::id(),"seconds":started.elapsed().as_secs_f64(),"onlyOwnBackupRead":true}),
    )
}
pub fn run(dir: &Path, params: &Path) -> Result<()> {
    let mut cache = None;
    for line in std::io::stdin().lock().lines() {
        let request: Value = serde_json::from_str(&line?)?;
        let response = handle(dir, params, &request, &mut cache)?;
        println!("{response}");
        std::io::stdout().flush()?;
    }
    Ok(())
}

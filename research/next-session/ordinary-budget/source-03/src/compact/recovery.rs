//! H7 recovery. The backup selects an authenticated public pool descriptor.
//! Mirrors supply bytes, never authority. Current-chain acceptance is established
//! separately by the transport; native replay alone cannot establish freshness.
use super::{experiment as ex, *};
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fs, path::{Path, PathBuf}, time::Instant};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub format: String,
    pub network: String,
    pub genesis: String,
    pub domain: H,
    pub initial_commitment: H,
    // Decimal integer sompi at the JSON boundary, matching native::Utxo.
    pub reserve_sompi: String,
    pub source: native::Utxo,
    pub funding: native::Utxo,
    pub funding_full_hash: String,
    pub start_hash: String,
    pub pk_sha256: String,
    pub vk_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    pub format: String,
    pub descriptor_sha256: String,
    pub wallet: Wallet,
    pub initial_note: Option<Note>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub through: u32,
    pub reserve: Option<native::Utxo>,
    pub last_transaction_id: String,
}

fn hex32(s: &str) -> Result<()> {
    if s.len() != 64 || s.bytes().any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b)) {
        return Err("expected canonical 32-byte hex identity".into());
    }
    Ok(())
}

impl Descriptor {
    fn manifest(&self, vk: &[u8]) -> Result<ex::Manifest> {
        if self.format != "kpi-compact-recovery-descriptor-v1"
            || self.network != "testnet-10" || self.genesis != GENESIS_HEX
            || vk.len() != 328 || self.vk_sha256 != hex::encode(hash(vk)) {
            return Err("descriptor network/version/VK".into());
        }
        for s in [&self.pk_sha256, &self.vk_sha256, &self.funding.txid,
            &self.funding_full_hash, &self.start_hash] { hex32(s)?; }
        let reserve: u64 = self.reserve_sompi.parse()?;
        if reserve.to_string() != self.reserve_sompi || reserve > MAX_SOMPI
            || reserve < NOTE_FLOOR || self.funding.amount != reserve
            || self.funding.index != 0 || self.funding.is_coinbase {
            return Err("descriptor reserve/funding".into());
        }
        let state = PublicState::initial(self.initial_commitment)?;
        let spk = pay_to_script_hash_script(&covenant::redeem(&self.domain, &state.compact()?, vk)?);
        if self.funding.spk != hex::encode(native::encode_spk(&spk)) {
            return Err("descriptor funding covenant".into());
        }
        Ok(ex::Manifest {network:self.network.clone(), genesis:self.genesis.clone(),
            reserve, domain:self.domain, initial_state:state, receivers:Vec::new(),
            parameters:json!({"pk_sha256":self.pk_sha256,"vk_sha256":self.vk_sha256})})
    }
}

/// Called before any private payment, after constructing the funding transaction.
fn seal(root: &Path, start_hash: String) -> Result<Value> {
    hex32(&start_hash)?;
    let public = root.join("public");
    let (m, vk) = ex::manifest(&public)?;
    let tx = native::parse_tx(&ex::read(&public.join("0000.json"))?)?;
    let d = Descriptor {format:"kpi-compact-recovery-descriptor-v1".into(),
        network:m.network.clone(), genesis:m.genesis.clone(), domain:m.domain,
        initial_commitment:m.initial_state.commitments[0], reserve_sompi:m.reserve.to_string(),
        source:ex::read(&public.join("source-utxo.json"))?, funding:native::Utxo::output(&tx,0,0),
        funding_full_hash:kaspa_consensus_core::hashing::tx::hash(&tx).to_string(), start_hash,
        pk_sha256:m.parameters["pk_sha256"].as_str().ok_or("PK pin")?.into(),
        vk_sha256:hex::encode(hash(&vk))};
    d.manifest(&vk)?;
    ex::history(&public,0,&m,&vk)?;
    ex::save(&public.join("descriptor.json"),&d)?;
    let pin = ex::file_hash(&public.join("descriptor.json"))?;
    fs::create_dir(root.join("backups"))?;
    for i in 0..3 {
        let w: ex::PrivateWallet = ex::read(&root.join(format!("wallet{i}/wallet.json")))?;
        ex::save(&root.join(format!("backups/wallet{i}.json")),&Backup {
            format:"kpi-compact-wallet-backup-v1".into(),descriptor_sha256:pin.clone(),
            wallet:w.wallet,initial_note:w.initial_note})?;
    }
    Ok(json!({"backup_count":3,"descriptor_sha256":pin,"funding_txid":tx.id().to_string(),
        "before_private_payments":true,"recipient_note_openings_in_backups":0}))
}

fn context(public: &Path, backup: &Path) -> Result<(Descriptor, ex::Manifest, Vec<u8>, ex::PrivateWallet)> {
    let b: Backup = ex::read(backup)?;
    if b.format != "kpi-compact-wallet-backup-v1" || b.descriptor_sha256 != ex::file_hash(&public.join("descriptor.json"))? {
        return Err("backup descriptor identity".into());
    }
    let d: Descriptor = ex::read(&public.join("descriptor.json"))?;
    let vk = fs::read(public.join("vk.bin"))?;
    let m = d.manifest(&vk)?;
    if let Some(n) = &b.initial_note {
        let receive = b.wallet.receive(&d.domain);
        if n.owner != receive.owner || n.incoming != receive.incoming
            || n.value != m.reserve || n.commitment(&d.domain) != d.initial_commitment {
            return Err("backup initial note ownership/commitment".into());
        }
    }
    Ok((d,m,vk,ex::PrivateWallet {wallet:b.wallet,initial_note:b.initial_note}))
}

fn checked_history(public: &Path, d: &Descriptor, m: &ex::Manifest, vk: &[u8]) -> Result<(Head,ex::History)> {
    let head: Head = ex::read(&public.join("head.json"))?;
    let source: native::Utxo = ex::read(&public.join("source-utxo.json"))?;
    if serde_json::to_value(&source)? != serde_json::to_value(&d.source)? {
        return Err("funding input context substitution".into());
    }
    let h = ex::history(public,head.through,m,vk)?;
    if h.transactions[0].id().to_string() != d.funding.txid
        || kaspa_consensus_core::hashing::tx::hash(&h.transactions[0]).to_string() != d.funding_full_hash
        || h.transactions.last().ok_or("empty history")?.id().to_string() != head.last_transaction_id {
        return Err("history endpoint identity".into());
    }
    match (&h.reserve,&head.reserve) {
        (Some(a),Some(b)) if a.txid==b.txid && a.index==b.index && a.amount==b.amount && a.spk==b.spk && !b.is_coinbase => {},
        (None,None) => {},
        _ => return Err("history does not reach the independently checked head".into()),
    }
    Ok((head,h))
}

fn inspect(public: &Path, backup: &Path, parameters: bool) -> Result<Value> {
    let t = Instant::now();
    let (d,m,vk,w) = context(public,backup)?;
    if parameters && ex::file_hash(&public.join("pk.bin"))? != d.pk_sha256 {
        return Err("proving parameter checksum".into());
    }
    let (head,h) = checked_history(public,&d,&m,&vk)?;
    let notes = ex::scan(&h,&m,&w)?;
    Ok(json!({"verified":true,"unspent_notes":notes.len(),"through":head.through,
        "reserve_remains":h.reserve.is_some(),"scan_and_validation_ms":t.elapsed().as_millis(),
        "no_manifest":!public.join("manifest.json").exists(),"parameters_hash_checked":parameters,
        "scope":"native replay; chain acceptance/freshness must be checked by transport"}))
}

fn exit(public: &Path, backup: &Path, out: &Path) -> Result<Value> {
    let began = Instant::now();
    let (d,m,vk,w) = context(public,backup)?;
    let (head,h) = checked_history(public,&d,&m,&vk)?;
    let notes = ex::scan(&h,&m,&w)?;
    let selected = notes.first().ok_or("no spendable recovered note")?;
    let fee = ex::fees()?.exit;
    let payout = selected.note.value.checked_sub(fee).filter(|v| *v>=PAYOUT_FLOOR).ok_or("recovered exit payout floor")?;
    let payout_spk = native::encode_spk(&native::p2pk(&w.wallet.payout_key(&m.domain,head.through))?);
    let (c,b) = ex::authorization(&w.wallet,&selected.note,&h.state,selected.position,
        [Note::dummy(),Note::dummy()],m.domain,fee,payout,payout_spk.clone().try_into().map_err(|_|"payout SPK width")?,
        if head.through==0 {m.reserve}else{0})?;
    let load_start = Instant::now();
    if ex::file_hash(&public.join("pk.bin"))? != d.pk_sha256 {return Err("proving parameter checksum".into());}
    let pk: ProvingKey<Bn254> = ex::decode(&public.join("pk.bin"))?;
    if ex::compressed(&pk.vk)? != vk {return Err("proving/verifying key mismatch".into());}
    let load_ms = load_start.elapsed().as_millis();
    let (bundle,proof_ms) = ex::prove(&pk,c,b)?;
    let (tx,entries) = settle(&m.domain,&h.state,h.reserve.as_ref().ok_or("closed pool")?,&vk,&bundle)?;
    let result = ex::save_tx(out,head.through+1,&tx,&entries,json!({"recovered_wallet":true,"new_private_proof":true}))?;
    let payout_index = tx.outputs.len()-1;
    if tx.outputs[payout_index].value != payout || native::encode_spk(&tx.outputs[payout_index].script_public_key) != payout_spk {
        return Err("recovery payout binding".into());
    }
    ex::save(&out.join("exit.bundle.json"),&bundle)?;
    let v = json!({"created":true,"through":head.through,"transaction_file":format!("{:04}.json",head.through+1),
        "payout_owned_by_backup":true,"payout":native::Utxo::output(&tx,payout_index,0),
        "fee_sompi":fee.to_string(),"input_value_sompi":selected.note.value.to_string(),
        "parameter_load_ms":load_ms,"proving_ms":proof_ms,"total_local_ms":began.elapsed().as_millis(),
        "native":result,"new_private_proofs":1,"unspent_notes_before":notes.len()});
    ex::save(&out.join("exit-report.json"),&v)?;
    Ok(v)
}

pub fn run() -> Result<()> {
    let args:Vec<String> = std::env::args().skip(1).collect();
    let p=|i:usize|->Result<PathBuf>{Ok(args.get(i).ok_or("missing argument")?.into())};
    let v=match args.first().map(String::as_str) {
        Some("seal")=>seal(&p(1)?,args.get(2).ok_or("start block hash")?.clone())?,
        Some("inspect")=>inspect(&p(1)?,&p(2)?,false)?,
        Some("check-parameters")=>inspect(&p(1)?,&p(2)?,true)?,
        Some("exit")=>exit(&p(1)?,&p(2)?,&p(3)?)?,
        _=>return Err("seal ROOT START_HASH | inspect PUBLIC BACKUP | check-parameters PUBLIC BACKUP | exit PUBLIC BACKUP OUT".into()),
    };
    println!("{}",serde_json::to_string(&v)?);
    Ok(())
}

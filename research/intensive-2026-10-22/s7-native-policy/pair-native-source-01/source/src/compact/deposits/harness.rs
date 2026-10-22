//! Bounded four-wallet harness. Accepted-chain selection is a transport concern;
//! this module verifies the pinned genesis and every native/public transition.
use super::{super::experiment as ex, *};
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Instant,
};
pub mod controls;

pub fn dir(p: &Path) -> Result<()> {
    fs::create_dir(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn emit(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string(v)?);
    std::io::stdout().flush()?;
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub format: String,
    pub network: String,
    pub genesis: String,
    pub domain: H,
    pub initial_commitment: H,
    pub pk_sha256: String,
    pub vk_sha256: String,
    pub funding_scripts: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub identity: Identity,
    pub sources: Vec<native::Utxo>,
    pub funding_txid: String,
    pub start_hash: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Private {
    pub wallet: Wallet,
    pub funding_key: H,
    pub initial_note: Option<Note>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saved {
    pub format: String,
    pub descriptor_sha256: String,
    pub count: u32,
    pub bundles: Vec<Bundle>,
}
pub struct History {
    pub state: PublicState,
    pub reserve: Option<native::Utxo>,
    pub transactions: Vec<Transaction>,
    pub fees: u64,
}

pub fn context(public: &Path) -> Result<(Descriptor, Vec<u8>)> {
    let d: Descriptor = ex::read(&public.join("descriptor.json"))?;
    let vk = fs::read(public.join("vk.bin"))?;
    let id = &d.identity;
    if id.format != "kpi-compact-deposits-v5"
        || id.network != "testnet-10"
        || id.genesis != GENESIS_HEX
        || vk.len() != 328
        || id.vk_sha256 != hex::encode(hash(&vk))
        || d.sources.len() != 4
        || id.funding_scripts.len() != 4
        || d.start_hash.len() != 64
        || hex::decode(&d.start_hash)?.len() != 32
    {
        return Err("v5 descriptor identity".into());
    }
    let mut seen = std::collections::HashSet::new();
    for (i, u) in d.sources.iter().enumerate() {
        if !seen.insert((u.txid.clone(), u.index))
            || u.spk != id.funding_scripts[i]
            || u.is_coinbase
            || (i > 0 && u.amount != CONTRIBUTION)
            || (i == 0 && u.amount <= CONTRIBUTION)
        {
            return Err("v5 funding source identity".into());
        }
    }
    Ok((d, vk))
}
pub fn replay(public: &Path, d: &Descriptor, vk: &[u8]) -> Result<History> {
    let raw: Vec<Value> = ex::read(&public.join("history.json"))?;
    if raw.is_empty() {
        return Err("missing public history".into());
    }
    let mut state = PublicState::initial(d.identity.initial_commitment)?;
    let initial = native::parse_tx(&raw[0])?;
    if initial.id().to_string() != d.funding_txid
        || initial.inputs.len() != 1
        || initial.inputs[0].previous_outpoint != d.sources[0].outpoint()?
        || initial.outputs.len() != 2
        || initial.outputs[0].value != CONTRIBUTION
        || initial.outputs[0].script_public_key != reserve_spk(&d.identity.domain, &state, vk)?
    {
        return Err("canonical singleton genesis/lineage".into());
    }
    let mut total = native::validate(&initial, &[d.sources[0].entry()?])?;
    let mut reserve = Some(native::Utxo::output(&initial, 0, 0));
    let mut transactions = vec![initial];
    let mut external = d.sources[1..].to_vec();
    for v in raw.iter().skip(1) {
        let tx = native::parse_tx(v)?;
        let prior = reserve.as_ref().ok_or("history after terminal")?;
        if tx.inputs.is_empty() || tx.inputs[0].previous_outpoint != prior.outpoint()? {
            return Err("reserve lineage discontinuity".into());
        }
        let (deposit, a, s) = parse(&tx.payload)?;
        let mut entries = vec![prior.entry()?];
        if deposit {
            if tx.inputs.len() != 2 {
                return Err("deposit input count".into());
            }
            let i = external
                .iter()
                .position(|u| u.outpoint().ok() == Some(tx.inputs[1].previous_outpoint))
                .ok_or("funding input absent/already consumed")?;
            entries.push(external.remove(i).entry()?);
        } else if tx.inputs.len() != 1 {
            return Err("spend input count".into());
        }
        total = total
            .checked_add(native::validate(&tx, &entries)?)
            .ok_or("fee sum")?;
        native::policy(&tx, &entries)?;
        let (next, w) = update(&state, &a, deposit)?;
        if a.domain != d.identity.domain || next.compact()? != s || tx.payload[P_WITNESS..] != w {
            return Err("v5 public state reconstruction".into());
        }
        state = next;
        reserve = if s.cm_count == s.nf_count {
            None
        } else {
            Some(native::Utxo::output(&tx, 0, 0))
        };
        transactions.push(tx);
    }
    Ok(History {
        state,
        reserve,
        transactions,
        fees: total,
    })
}
pub fn load_pk(params: &Path, id: &Identity, vk: &[u8]) -> Result<ProvingKey<Bn254>> {
    if ex::file_hash(&params.join("pk.bin"))? != id.pk_sha256 {
        return Err("PK hash mismatch".into());
    }
    let pk: ProvingKey<Bn254> = ex::decode(&params.join("pk.bin"))?;
    if ex::compressed(&pk.vk)? != vk {
        return Err("PK/VK mismatch".into());
    }
    Ok(pk)
}
pub fn scan(h: &History, w: &Wallet, d: &H) -> Result<Vec<(u32, Note)>> {
    let mut notes = Vec::new();
    let mut position = 1;
    for tx in h.transactions.iter().skip(1) {
        let (_, a, _) = parse(&tx.payload)?;
        if a.mode == 1 {
            for i in 0..2 {
                if let Ok(n) = w.decrypt(
                    d,
                    &tx.payload[P_CIPHER + i * 185..P_CIPHER + (i + 1) * 185],
                    &a.outputs[i],
                ) {
                    if !(NOTE_FLOOR..=MAX_SOMPI).contains(&n.value) {
                        return Err("delivered value outside spendable range".into());
                    }
                    if !h.state.spent(&nullifier(
                        d,
                        &w.spending,
                        &n.commitment(d),
                        position + i as u32,
                    )) {
                        notes.push((position + i as u32, n));
                    }
                }
            }
            position += 2;
        }
    }
    Ok(notes)
}
fn check_own_delivery(w: &Wallet, domain: &H, bundle: &Bundle, expected: &[Note; 2]) -> Result<()> {
    let a = bundle.auth()?;
    let ciphertexts = bundle.ciphertext_bytes()?;
    for (i, note) in expected.iter().enumerate() {
        let received = w.decrypt(domain, &ciphertexts[i * 185..(i + 1) * 185], &a.outputs[i])?;
        if received.value != note.value || received.commitment(domain) != note.commitment(domain) {
            return Err("deposit delivery differs from signing intent".into());
        }
    }
    Ok(())
}
fn init(params: &Path, root: &Path) -> Result<Value> {
    dir(root)?;
    dir(&root.join("public"))?;
    let d = hash(&[b"KPI/compact/deposits/v5\0".as_slice(), &random()].concat());
    let wallets: Vec<Private> = (0..4)
        .map(|_| Private {
            wallet: Wallet::fresh(),
            funding_key: random(),
            initial_note: None,
        })
        .collect();
    let vk = fs::read(params.join("vk.bin"))?;
    let params_meta: Value = ex::read(&params.join("parameters.json"))?;
    let initial = wallets[0].wallet.receive(&d).note(CONTRIBUTION)?;
    let scripts = wallets
        .iter()
        .map(|w| {
            Ok(hex::encode(native::encode_spk(&native::p2pk(
                &w.funding_key,
            )?)))
        })
        .collect::<Result<Vec<_>>>()?;
    let id = Identity {
        format: "kpi-compact-deposits-v5".into(),
        network: "testnet-10".into(),
        genesis: GENESIS_HEX.into(),
        domain: d,
        initial_commitment: initial.commitment(&d),
        pk_sha256: params_meta["pk_sha256"]
            .as_str()
            .ok_or("parameter pin")?
            .into(),
        vk_sha256: hex::encode(hash(&vk)),
        funding_scripts: scripts,
    };
    if params_meta["vk_sha256"] != id.vk_sha256 {
        return Err("existing parameter VK mismatch".into());
    }
    ex::save(&root.join("public/identity.json"), &id)?;
    ex::write(&root.join("public/vk.bin"), &vk)?;
    for (i, mut w) in wallets.into_iter().enumerate() {
        if i == 0 {
            w.initial_note = Some(initial.clone());
        }
        ex::save(&root.join(format!("wallet{i}.json")), &w)?;
    }
    Ok(json!({"fresh_unfunded_identity":true,"domain":hex::encode(d),"fees":fees()?}))
}
fn genesis(root: &Path, inputs: &Path, start_hash: String) -> Result<Value> {
    let public = root.join("public");
    let id: Identity = ex::read(&public.join("identity.json"))?;
    let vk = fs::read(public.join("vk.bin"))?;
    let sources: Vec<native::Utxo> = ex::read(inputs)?;
    if sources.len() != 4 {
        return Err("four source UTXOs required".into());
    }
    let w: Private = ex::read(&root.join("wallet0.json"))?;
    let state = PublicState::initial(id.initial_commitment)?;
    let (tx, e) = native::ordinary(
        &sources[0],
        &w.funding_key,
        vec![TransactionOutput::new(
            CONTRIBUTION,
            reserve_spk(&id.domain, &state, &vk)?,
        )],
    )?;
    let d = Descriptor {
        identity: id,
        sources,
        funding_txid: tx.id().to_string(),
        start_hash,
    };
    ex::save(&public.join("descriptor.json"), &d)?;
    let report = ex::save_tx(&public, 0, &tx, &e, json!({"kind":"genesis"}))?;
    ex::save(&public.join("history.json"), &vec![native::tx_json(&tx)])?;
    context(&public)?;
    replay(&public, &d, &vk)?;
    Ok(report)
}
fn allocate(root: &Path, source: &Path, funding: &Path, out: &Path) -> Result<Value> {
    let config: Value = ex::read(&funding.join("funding.json"))?;
    if config["network"] != "testnet-10" {
        return Err("allocation is testnet-10 only".into());
    }
    let key: H = hex::decode(fs::read_to_string(funding.join("funding.key"))?.trim())?
        .try_into()
        .map_err(|_| "funding key width")?;
    if config["address"] != native::address(&native::p2pk(&key)?)? {
        return Err("funding address mismatch".into());
    }
    let id: Identity = ex::read(&root.join("public/identity.json"))?;
    if id.format != "kpi-compact-deposits-v5"
        || id.network != "testnet-10"
        || id.funding_scripts.len() != 4
    {
        return Err("allocation identity".into());
    }
    let source: native::Utxo = ex::read(source)?;
    let outputs = id
        .funding_scripts
        .iter()
        .enumerate()
        .map(|(i, s)| {
            Ok(TransactionOutput::new(
                CONTRIBUTION + if i == 0 { 100_000_000 } else { 0 },
                native::decode_spk(s)?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let (tx, e) = native::ordinary(&source, &key, outputs)?;
    let r = ex::save_tx(
        out,
        0,
        &tx,
        &e,
        json!({"kind":"ordinary-input-preparation","shared-test-coin-ancestry":true}),
    )?;
    ex::save(
        &out.join("sources.json"),
        &(0..4)
            .map(|i| native::Utxo::output(&tx, i, 0))
            .collect::<Vec<_>>(),
    )?;
    Ok(r)
}
pub fn exit_proof(
    pk: &ProvingKey<Bn254>,
    wallet: &Wallet,
    note: &Note,
    position: u32,
    d: &H,
    state: &PublicState,
) -> Result<(Bundle, u128)> {
    let f = fees()?.exit;
    let payout = note
        .value
        .checked_sub(f)
        .filter(|v| *v >= PAYOUT_FLOOR)
        .ok_or("exit floor")?;
    let spk = native::encode_spk(&native::p2pk(&wallet.payout_key(d, position))?)
        .try_into()
        .map_err(|_| "payout shape")?;
    let (c, b) = ex::authorization(
        wallet,
        note,
        state,
        position,
        [Note::dummy(), Note::dummy()],
        *d,
        f,
        payout,
        spk,
        0,
    )?;
    ex::prove(pk, c, b)
}
fn join(public: &Path, private: &Path, params: &Path, index: usize, out: &Path) -> Result<()> {
    if index >= 4 {
        return Err("wallet index".into());
    }
    let (d, vk) = context(public)?;
    let h = replay(public, &d, &vk)?;
    let w: Private = ex::read(private)?;
    if native::encode_spk(&native::p2pk(&w.funding_key)?)
        != hex::decode(&d.identity.funding_scripts[index])?
    {
        return Err("wallet funding identity".into());
    }
    if h.transactions.len() != index + 1 {
        return Err("join schedule/accepted prefix".into());
    }
    let t = Instant::now();
    let pk = load_pk(params, &d.identity, &vk)?;
    let load = t.elapsed().as_millis();
    let domain = d.identity.domain;
    let f = fees()?;
    let fee = if index == 0 { f.transfer } else { f.deposit };
    let output = [
        w.wallet.receive(&domain).note(PAYMENT)?,
        w.wallet
            .receive(&domain)
            .note(CONTRIBUTION - PAYMENT - fee)?,
    ];
    let input = if index == 0 {
        w.initial_note.clone().ok_or("initial note backup")?
    } else {
        w.wallet.receive(&domain).note(CONTRIBUTION)?
    };
    let virtual_state = PublicState::initial(input.commitment(&domain))?;
    let before = if index == 0 { &h.state } else { &virtual_state };
    let (c, b) = ex::authorization(
        &w.wallet,
        &input,
        before,
        0,
        output.clone(),
        domain,
        fee,
        0,
        [0; 36],
        CONTRIBUTION,
    )?;
    // A hash of ciphertext is not proof of correct encryption. The self-deposit
    // wallet checks both deliveries before authorizing its native funding input.
    check_own_delivery(&w.wallet, &domain, &b, &output)?;
    let (b, admission_ms) = ex::prove(&pk, c, b)?;
    let external = if index == 0 {
        None
    } else {
        Some(&d.sources[index])
    };
    let (mut tx, e) = settle(
        &domain,
        &h.state,
        h.reserve.as_ref().ok_or("closed reserve")?,
        &vk,
        &b,
        external,
    )?;
    if index > 0 {
        native::sign(&mut tx, &e, 1, &w.funding_key)?;
    }
    ex::save(out.join("admission.bundle.json").as_path(), &b)?;
    let metrics = ex::save_tx(
        out,
        0,
        &tx,
        &e,
        json!({"kind":if index==0 {"bootstrap"}else{"deposit"}}),
    )?;
    ex::save(
        &out.join("admission.inputs.json"),
        &if index == 0 {
            vec![h.reserve.as_ref().unwrap().clone()]
        } else {
            vec![
                h.reserve.as_ref().unwrap().clone(),
                d.sources[index].clone(),
            ]
        },
    )?;
    emit(
        &json!({"admission_ready":true,"transaction_file":"0000.json","parameter_load_ms":load,"proof_ms":admission_ms,"native":metrics}),
    )?;
    let ack = std::io::stdin()
        .lock()
        .lines()
        .next()
        .ok_or("missing acceptance acknowledgement")??;
    if ack != "accepted" {
        return Err("unexpected acceptance acknowledgement".into());
    }
    let accepted = replay(public, &d, &vk)?;
    if accepted.transactions.last().map(|t| t.id()) != Some(tx.id()) {
        return Err("own admission not in accepted prefix".into());
    }
    let notes = scan(&accepted, &w.wallet, &domain)?;
    if notes.len() != 2
        || notes.iter().zip(&output).any(|((_, n), expected)| {
            n.commitment(&domain) != expected.commitment(&domain) || n.value != expected.value
        })
    {
        return Err("own delivery/commitment/value mismatch".into());
    }
    let mut bundles = Vec::new();
    let mut times = Vec::new();
    for (position, n) in &notes {
        let (b, ms) = exit_proof(&pk, &w.wallet, n, *position, &domain, &accepted.state)?;
        bundles.push(b);
        times.push(ms);
    }
    let saved = Saved {
        format: "kpi-v5-saved-exits-v1".into(),
        descriptor_sha256: ex::file_hash(&public.join("descriptor.json"))?,
        count: accepted.state.compact()?.cm_count,
        bundles,
    };
    ex::save(&out.join("saved.json"), &saved)?;
    let result = json!({"prepared":true,"count":saved.count,"notes_scanned":notes.len(),"exit_proof_ms":times,
        "parameter_load_ms":load,"admission_proof_ms":admission_ms,"new_private_proofs":3});
    ex::save(&out.join("prepared.json"), &result)?;
    emit(&result)
}
fn public_exit(public: &Path, saved: &Path, index: usize, out: &Path) -> Result<Value> {
    let start = Instant::now();
    let (d, vk) = context(public)?;
    let saved: Saved = ex::read(saved)?;
    if saved.format != "kpi-v5-saved-exits-v1"
        || saved.descriptor_sha256 != ex::file_hash(&public.join("descriptor.json"))?
        || saved.bundles.len() != 2
    {
        return Err("saved proof/descriptor identity".into());
    }
    let h = replay(public, &d, &vk)?;
    let b = saved.bundles.get(index).ok_or("saved proof index")?;
    let a = b.auth()?;
    if a.mode != 2 || a.count != saved.count {
        return Err("saved exit shape".into());
    }
    let (tx, e) = settle(
        &d.identity.domain,
        &h.state,
        h.reserve.as_ref().ok_or("closed pool")?,
        &vk,
        b,
        None,
    )?;
    if tx.payload[P_AUTH..P_CIPHER] != hex::decode(&b.authorization)?
        || tx.inputs[0].signature_script[2..130] != hex::decode(&b.proof)?
    {
        return Err("saved authorization/proof changed".into());
    }
    let report = ex::save_tx(out, 0, &tx, &e, json!({"saved_proof":true}))?;
    let v = json!({"unchanged_proof_and_authorization":true,"no_wallet_or_proving_key_input":true,"rebuild_us":start.elapsed().as_micros(),
        "prepared_count":saved.count,"current_count":h.state.compact()?.cm_count,"native":report,
        "payout":native::Utxo::output(&tx,tx.outputs.len()-1,0),"terminal":tx.outputs.len()==1});
    ex::save(&out.join("result.json"), &v)?;
    Ok(v)
}
pub fn run() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let p = |i: usize| -> Result<PathBuf> { Ok(a.get(i).ok_or("missing argument")?.into()) };
    let n = |i: usize| -> Result<usize> { Ok(a.get(i).ok_or("missing index")?.parse()?) };
    let v=match a.first().map(String::as_str) {
        Some("fees")=>json!({"fees":fees()?,"redeem_bytes":covenant::REDEEM_LEN,"payload_bytes":PAYLOAD_SIZE,"note_floor":NOTE_FLOOR}),
        Some("init")=>init(&p(1)?,&p(2)?)?,
        Some("genesis")=>genesis(&p(1)?,&p(2)?,a.get(3).ok_or("start hash")?.clone())?,
        Some("allocate")=>allocate(&p(1)?,&p(2)?,&p(3)?,&p(4)?)?,
        Some("join")=>{join(&p(1)?,&p(2)?,&p(3)?,n(4)?,&p(5)?)?;return Ok(());},
        Some("exit")=>public_exit(&p(1)?,&p(2)?,n(3)?,&p(4)?)?,
        Some("check")=>{let (d,vk)=context(&p(1)?)?;let h=replay(&p(1)?,&d,&vk)?;json!({"valid":true,"transactions":h.transactions.len(),"state":h.state.compact()?,"drained":h.reserve.is_none(),"fees_sompi":h.fees.to_string()})},
        Some("controls")=>controls::run(&p(1)?,&p(2)?,&p(3)?)?,
        _=>return Err("fees | init PARAMS ROOT | genesis ROOT SOURCES START_HASH | join PUBLIC WALLET PARAMS INDEX OUT | exit PUBLIC SAVED INDEX OUT | check PUBLIC | controls ROOT PARAMS OUT".into())
    };
    emit(&v)
}

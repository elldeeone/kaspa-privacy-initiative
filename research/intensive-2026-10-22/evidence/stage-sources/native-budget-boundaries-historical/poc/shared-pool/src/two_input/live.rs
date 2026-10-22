//! TN10 transport adapter for the unchanged v6 relation. No broadcast in Rust.
//! Replay is restricted to this four-depositor fixture; accepted chain discovery
//! is performed by isolated clients, not trusted controller state exports.
use super::*;
use crate::compact::experiment::{read, save, write};
use crate::protocol::GENESIS_HEX;
use serde_json::{Value, json};
use std::{fs, path::Path};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Private {
    domain: H,
    wallets: Vec<Wallet>,
    initial: Note,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    format: String,
    network: String,
    genesis: String,
    domain: H,
    initial_commitment: H,
    initial_value: u64,
    vk_sha256: String,
    sources: Vec<native::Utxo>,
    funding_txid: String,
    start_hash: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    format: String,
    descriptor_sha256: String,
    bundles: Vec<Bundle>,
}
pub struct History {
    state: tree::PublicState,
    reserve: Option<native::Utxo>,
    fees: u64,
    transactions: usize,
}
fn digest(p: &Path) -> Result<String> {
    Ok(hex::encode(hash(&fs::read(p)?)))
}
fn save_tx(
    out: &Path,
    step: u32,
    tx: &Transaction,
    entries: &[UtxoEntry],
    extra: Value,
) -> Result<Value> {
    native::validate(tx, entries)?;
    let metrics = native::policy(tx, entries)?;
    let units = native::meter(tx, entries)?;
    let raw = native::tx_json(tx);
    native::validate(&native::parse_tx(&raw)?, entries)?;
    save(&out.join(format!("{step:04}.json")), &raw)?;
    let result = json!({"txid":tx.id().to_string(),"full_hash":kaspa_consensus_core::hashing::tx::hash(tx).to_string(),"metrics":metrics,"script_units":units,"native_full":true,"policy":true,"extra":extra});
    save(&out.join(format!("{step:04}.metrics.json")), &result)?;
    Ok(result)
}
fn dir(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn new(params: &Path, root: &Path) -> Result<Value> {
    let vk = fs::read(params.join("vk.bin"))?;
    let setup: Value = read(&params.join("setup.json"))?;
    if vk.len() != 328 || setup["vk_sha256"] != hex::encode(hash(&vk)) {
        return Err("parameter identity".into());
    }
    let d = hash(
        &[
            b"KPI/COMPACT/TN10/v6\0".as_slice(),
            &hex::decode(GENESIS_HEX)?,
            &random(),
            &hash(&vk),
            &NOTE_FLOOR.to_le_bytes(),
            &FEE.to_le_bytes(),
        ]
        .concat(),
    );
    let wallets: Vec<_> = (0..4).map(|_| Wallet::fresh()).collect();
    let initial = wallets[0].receive(&d).note(2_000_000_000)?;
    save(
        &root.join("wallets.json"),
        &Private {
            domain: d,
            wallets,
            initial,
        },
    )?;
    write(&root.join("vk.bin"), &vk)?;
    Ok(
        json!({"unfunded":true,"network":"testnet-10","fresh_wallets":4,"vk_sha256":hex::encode(hash(&vk))}),
    )
}
fn allocate(root: &Path, source: &Path, funding: &Path, out: &Path) -> Result<Value> {
    let config: Value = read(&funding.join("funding.json"))?;
    if config["network"] != "testnet-10" {
        return Err("TN10 only".into());
    }
    let key: H = hex::decode(fs::read_to_string(funding.join("funding.key"))?.trim())?
        .try_into()
        .map_err(|_| "funding key")?;
    if config["address"] != native::address(&native::p2pk(&key)?)? {
        return Err("funding identity".into());
    }
    let p: Private = read(&root.join("wallets.json"))?;
    if p.wallets.len() != 4 {
        return Err("wallet count".into());
    }
    let outputs = [2_100_000_000, 1_100_000_000, 1_200_000_000, 1_300_000_000]
        .into_iter()
        .zip(&p.wallets)
        .map(|(v, w)| Ok(TransactionOutput::new(v, native::p2pk(&w.native)?)))
        .collect::<Result<Vec<_>>>()?;
    let (tx, e) = native::ordinary(&read(source)?, &key, outputs)?;
    let r = save_tx(out, 0, &tx, &e, json!({"ordinary_test_funding":true}))?;
    save(
        &out.join("sources.json"),
        &(0..4)
            .map(|i| native::Utxo::output(&tx, i, 0))
            .collect::<Vec<_>>(),
    )?;
    Ok(r)
}
fn prepare(params: &Path, root: &Path, sources: &Path, start_hash: String) -> Result<Value> {
    let p: Private = read(&root.join("wallets.json"))?;
    let vk = fs::read(root.join("vk.bin"))?;
    if vk != fs::read(params.join("vk.bin"))? || p.wallets.len() != 4 {
        return Err("preparation identity".into());
    }
    let sources: Vec<native::Utxo> = read(sources)?;
    if sources.len() != 4 || hex::decode(&start_hash)?.len() != 32 {
        return Err("funding shape".into());
    }
    for (i, u) in sources.iter().enumerate() {
        if u.spk != hex::encode(native::encode_spk(&native::p2pk(&p.wallets[i].native)?))
            || u.is_coinbase
            || u.amount != [2_100_000_000, 1_100_000_000, 1_200_000_000, 1_300_000_000][i]
        {
            return Err("funding ownership/value".into());
        }
    }
    let state = tree::PublicState::initial(p.initial.commitment(&p.domain))?;
    let (genesis, ge) = native::ordinary(
        &sources[0],
        &p.wallets[0].native,
        vec![TransactionOutput::new(
            p.initial.value,
            reserve_spk(&p.domain, &state, &vk)?,
        )],
    )?;
    let public = root.join("public");
    dir(&public)?;
    let d = Descriptor {
        format: "kpi-two-input-live-v1".into(),
        network: "testnet-10".into(),
        genesis: GENESIS_HEX.into(),
        domain: p.domain,
        initial_commitment: p.initial.commitment(&p.domain),
        initial_value: p.initial.value,
        vk_sha256: hex::encode(hash(&vk)),
        sources: sources.clone(),
        funding_txid: genesis.id().to_string(),
        start_hash,
    };
    save(&public.join("descriptor.json"), &d)?;
    write(&public.join("vk.bin"), &vk)?;
    save_tx(&public, 0, &genesis, &ge, json!({"singleton_genesis":true}))?;
    let proof_run = root.join("proof-run");
    harness::demo(
        params,
        &proof_run,
        Some(harness::Preparation {
            domain: p.domain,
            wallets: p.wallets.clone(),
            initial: p.initial,
            sources,
            reserve: native::Utxo::output(&genesis, 0, 0),
        }),
    )?;
    let r: Value = read(&proof_run.join("result-private.json"))?;
    if r["operations"] != 13 || r["saved_proofs_unchanged"] != 6 || r["reserve_remaining"] != 0 {
        return Err("prepared workload did not drain".into());
    }
    let mut history = vec![native::tx_json(&genesis)];
    for row in r["rows"].as_array().ok_or("rows")?.iter().take(7) {
        history.push(row["tx"].clone());
    }
    save(&public.join("history.json"), &history)?;
    let caps = root.join("capabilities");
    dir(&caps)?;
    let mut bundles: Vec<Vec<Bundle>> = vec![vec![]; 4];
    for (owner, pos) in [(1, 3), (2, 5), (3, 7), (0, 10), (2, 13), (1, 14)] {
        let req: Value = read(&proof_run.join(format!("exit-{pos}.json")))?;
        let b: Bundle = serde_json::from_value(req["bundle"].clone())?;
        if b.auth()?.spk.as_slice()
            != native::encode_spk(&native::p2pk(&p.wallets[owner].payout_key(&p.domain, pos))?)
        {
            return Err("saved payout is not owner's script".into());
        }
        bundles[owner].push(b);
    }
    for (i, bundles) in bundles.into_iter().enumerate() {
        save(
            &caps.join(format!("wallet-{i}.json")),
            &Saved {
                format: "kpi-two-input-saved-v1".into(),
                descriptor_sha256: digest(&public.join("descriptor.json"))?,
                bundles,
            },
        )?;
    }
    let (_, h) = replay(&public)?;
    Ok(
        json!({"prepared":true,"prefix_transactions":h.transactions,"saved_proofs":6,"private_change_decrypted":true,
        "partial_change_respent":true,"actual_broadcast":false,"prover_process_exits_before_live_execution":true}),
    )
}
fn context(public: &Path) -> Result<(Descriptor, Vec<u8>)> {
    let d: Descriptor = read(&public.join("descriptor.json"))?;
    let vk = fs::read(public.join("vk.bin"))?;
    if d.format != "kpi-two-input-live-v1"
        || d.network != "testnet-10"
        || d.genesis != GENESIS_HEX
        || vk.len() != 328
        || d.vk_sha256 != hex::encode(hash(&vk))
        || d.initial_value != 2_000_000_000
        || d.sources.len() != 4
        || hex::decode(&d.start_hash)?.len() != 32
    {
        return Err("v6 descriptor identity".into());
    }
    let mut seen = std::collections::HashSet::new();
    for u in &d.sources {
        if !seen.insert((u.txid.clone(), u.index))
            || u.is_coinbase
            || u.amount == 0
            || u.amount > MAX_SOMPI
        {
            return Err("descriptor source identity".into());
        }
    }
    Ok((d, vk))
}
fn extract(tx: &Transaction) -> Result<Bundle> {
    let script = &tx.inputs.first().ok_or("reserve input")?.signature_script;
    if tx.payload.len() != PAYLOAD_SIZE
        || &tx.payload[..8] != b"KPICR06\0"
        || script.len() != covenant::WITNESS_LEN
        || script[..2] != [0x4c, 128]
    {
        return Err("v6 transaction framing".into());
    }
    Ok(Bundle {
        authorization: hex::encode(&tx.payload[P_AUTH..P_CIPHER]),
        proof: hex::encode(&script[2..130]),
        ciphertexts: [
            hex::encode(&tx.payload[P_CIPHER..P_CIPHER + 185]),
            hex::encode(&tx.payload[P_CIPHER + 185..P_STATE]),
        ],
    })
}
fn replay(public: &Path) -> Result<(Descriptor, History)> {
    let (d, vk) = context(public)?;
    let raw: Vec<Value> = read(&public.join("history.json"))?;
    let genesis = native::parse_tx(raw.first().ok_or("missing public history")?)?;
    let mut state = tree::PublicState::initial(d.initial_commitment)?;
    if genesis.id().to_string() != d.funding_txid
        || genesis.inputs.len() != 1
        || genesis.inputs[0].previous_outpoint != d.sources[0].outpoint()?
        || genesis.outputs.len() != 2
        || genesis.outputs[0].value != d.initial_value
        || genesis.outputs[0].script_public_key != reserve_spk(&d.domain, &state, &vk)?
    {
        return Err("pinned genesis/lineage".into());
    }
    let mut fees = native::validate(&genesis, &[d.sources[0].entry()?])?;
    native::policy(&genesis, &[d.sources[0].entry()?])?;
    let mut reserve = Some(native::Utxo::output(&genesis, 0, 0));
    let mut external = d.sources[1..].to_vec();
    for v in raw.iter().skip(1) {
        let tx = native::parse_tx(v)?;
        let prior = reserve.as_ref().ok_or("history after drain")?;
        if tx
            .inputs
            .first()
            .ok_or("missing reserve input")?
            .previous_outpoint
            != prior.outpoint()?
        {
            return Err("reserve lineage discontinuity".into());
        }
        let b = extract(&tx)?;
        let a = b.auth()?;
        let ext = if a.mode == 0 {
            let point = tx
                .inputs
                .get(1)
                .ok_or("missing funding input")?
                .previous_outpoint;
            let index = external
                .iter()
                .position(|u| u.outpoint().ok() == Some(point))
                .ok_or("unbacked/reused admission")?;
            Some(external.remove(index))
        } else {
            None
        };
        let (mut expected, entries, next) =
            settle(&d.domain, &state, prior, &vk, &b, ext.as_ref())?;
        if ext.is_some() {
            expected.inputs[1].signature_script = tx.inputs[1].signature_script.clone();
            expected.finalize();
        }
        if native::tx_json(&expected) != native::tx_json(&tx) {
            return Err("public state/transaction reconstruction".into());
        }
        fees = fees
            .checked_add(native::validate(&tx, &entries)?)
            .ok_or("fee overflow")?;
        native::policy(&tx, &entries)?;
        // Padding makes counts unrelated to the number of outstanding claims.
        let remaining = prior
            .amount
            .checked_add(ext.as_ref().map_or(0, |e| e.amount))
            .and_then(|v| v.checked_sub(a.payout))
            .and_then(|v| v.checked_sub(a.fee))
            .ok_or("backing arithmetic")?;
        reserve = if remaining == 0 {
            None
        } else {
            Some(native::Utxo::output(&tx, 0, 0))
        };
        state = next;
    }
    Ok((
        d,
        History {
            state,
            reserve,
            fees,
            transactions: raw.len(),
        },
    ))
}
fn exit(public: &Path, saved: &Path, index: usize, out: &Path) -> Result<Value> {
    let saved: Saved = read(saved)?;
    if saved.format != "kpi-two-input-saved-v1"
        || saved.descriptor_sha256 != digest(&public.join("descriptor.json"))?
    {
        return Err("saved descriptor identity".into());
    }
    let (d, h) = replay(public)?;
    let vk = fs::read(public.join("vk.bin"))?;
    let b = saved.bundles.get(index).ok_or("saved index")?;
    let a = b.auth()?;
    if a.mode != 2 {
        return Err("saved proof is not a drain".into());
    }
    let (tx, e, _) = settle(
        &d.domain,
        &h.state,
        h.reserve.as_ref().ok_or("drained pool")?,
        &vk,
        b,
        None,
    )?;
    if tx.payload[P_AUTH..P_CIPHER] != hex::decode(&b.authorization)?
        || tx.inputs[0].signature_script[2..130] != hex::decode(&b.proof)?
    {
        return Err("saved bytes changed".into());
    }
    let native = save_tx(out, 0, &tx, &e, json!({"saved_capability":true}))?;
    Ok(
        json!({"unchanged_proof_and_authorization":true,"no_wallet_or_proving_key_input":true,"history_transactions":h.transactions,
        "native":native,"payout":native::Utxo::output(&tx,tx.outputs.len()-1,0),"terminal":tx.outputs.len()==1}),
    )
}
pub fn run() -> Result<()> {
    let a = std::env::args().skip(1).collect::<Vec<_>>();
    let p = |i: usize| -> Result<&Path> { Ok(Path::new(a.get(i).ok_or("missing argument")?)) };
    let r=match a.first().map(String::as_str){
        Some("exit") if a.len()==2=>return harness::run(),
        Some("new") if a.len()==3=>new(p(1)?,p(2)?)?,
        Some("allocate") if a.len()==5=>allocate(p(1)?,p(2)?,p(3)?,p(4)?)?,
        Some("prepare") if a.len()==5=>prepare(p(1)?,p(2)?,p(3)?,a[4].clone())?,
        Some("exit") if a.len()==5=>exit(p(1)?,p(2)?,a[3].parse()?,p(4)?)?,
        Some("check") if a.len()==2=>{let(_,h)=replay(p(1)?)?;json!({"valid":true,"drained":h.reserve.is_none(),"transactions":h.transactions,"state":h.state.compact()?,"fees_sompi":h.fees})},
        Some("hashes") if a.len()==2=>{let v:Vec<Value>=read(p(1)?)?;json!(v.iter().map(|r|{let tx=native::parse_tx(r)?;Ok(json!({"txid":tx.id().to_string(),"full_hash":kaspa_consensus_core::hashing::tx::hash(&tx).to_string()}))}).collect::<Result<Vec<_>>>()?)},
        _=>return Err("new PARAMS ROOT | allocate ROOT SOURCE FUNDING OUT | prepare PARAMS ROOT SOURCES START | exit PUBLIC SAVED INDEX OUT | check PUBLIC | hashes TRANSACTIONS".into())
    };
    println!("{}", r);
    Ok(())
}

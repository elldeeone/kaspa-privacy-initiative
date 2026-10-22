//! H12 experiment adapter. Reuses the immutable v5 covenant and private proofs.
//! Funding policy is not enforced as a new consensus rule. No privileged exit.
use super::{deposits as dep, experiment as ex, study::{self, Ledger, Request}, *};
use serde_json::{Value, json};
use std::{fs, path::Path};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Private {
    wallets: Vec<Wallet>,
    funding_keys: Vec<H>,
    notes: Vec<(usize, Note)>,
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
    bundle: Bundle,
}

fn amounts(root: &Path) -> Result<Vec<u64>> {
    let plan: Value = ex::read(&root.join("plan.json"))?;
    let mut values = vec![plan["initial_value"].as_u64().ok_or("initial value")?];
    for e in plan["events"].as_array().ok_or("events")? {
        if e["kind"] == "deposit" {values.push(e["deposit"].as_u64().ok_or("deposit value")?);}
    }
    if values.len() != 4 || values.iter().any(|v| *v > MAX_SOMPI) {return Err("four contributions/range".into());}
    let f = dep::fees()?;
    let net = values[0].checked_sub(f.transfer).ok_or("bootstrap credit")?;
    if net < 2*NOTE_FLOOR || values[1..].iter().any(|v| v.checked_sub(f.deposit) != Some(net)) {
        return Err("unequal net credits".into());
    }
    Ok(values)
}

fn allocate(root: &Path, source: &Path, funding: &Path, out: &Path) -> Result<Value> {
    let config: Value = ex::read(&funding.join("funding.json"))?;
    if config["network"] != "testnet-10" {return Err("TN10 only".into());}
    let key: H = hex::decode(fs::read_to_string(funding.join("funding.key"))?.trim())?
        .try_into().map_err(|_| "funding key width")?;
    if config["address"] != native::address(&native::p2pk(&key)?)? {return Err("funding identity".into());}
    let private: Private = ex::read(&root.join("prepared/wallets.json"))?;
    if private.funding_keys.len() != 4 {return Err("funding keys".into());}
    let mut values = amounts(root)?;
    values[0] = values[0].checked_add(100_000_000).ok_or("genesis fee/change allowance")?;
    let outputs = values.iter().zip(&private.funding_keys).map(|(v,k)|
        Ok(TransactionOutput::new(*v, native::p2pk(k)?))).collect::<Result<Vec<_>>>()?;
    let (tx, entries) = native::ordinary(&ex::read(source)?, &key, outputs)?;
    let report = ex::save_tx(out, 0, &tx, &entries, json!({"ordinary_test_funding":true}))?;
    ex::save(&out.join("sources.json"), &(0..4).map(|i| native::Utxo::output(&tx, i, 0)).collect::<Vec<_>>())?;
    Ok(report)
}

fn extract(tx: &Transaction) -> Result<Bundle> {
    dep::parse(&tx.payload)?;
    let script = &tx.inputs.first().ok_or("reserve input")?.signature_script;
    if script.len() != dep::covenant::REDEEM_LEN+133 || script[..2] != [0x4c, 0x80] {
        return Err("v5 proof framing".into());
    }
    Ok(Bundle {authorization:hex::encode(&tx.payload[P_AUTH..P_CIPHER]),
        proof:hex::encode(&script[2..130]),
        ciphertexts:[hex::encode(&tx.payload[P_CIPHER..P_CIPHER+185]), hex::encode(&tx.payload[P_CIPHER+185..P_STATE])]})
}

/// Bind freshly prepared proofs to real independently signed ordinary sources.
/// Only public settlement paths and funding signatures change. Every proof is
/// natively revalidated, and old fallback bytes are retained privately.
fn bind(root: &Path, sources: &Path, start_hash: String) -> Result<Value> {
    let private: Private = ex::read(&root.join("prepared/wallets.json"))?;
    let request: Request = ex::read(&root.join("prepared/fresh-request.json"))?;
    let plan: Value = ex::read(&root.join("plan.json"))?;
    let exits = plan["events"].as_array().ok_or("plan events")?.iter()
        .filter(|e| e["kind"] == "exit").collect::<Vec<_>>();
    if exits.len() != request.bundles.len() {return Err("exit plan/capability count".into());}
    let mut paid_owners = std::collections::HashSet::new();
    for (event,bundle) in exits.iter().zip(&request.bundles) {
        let position:usize = event["position"].as_u64().ok_or("exit position")?.try_into()?;
        let (owner,note) = private.notes.get(position).ok_or("exit opening")?;
        if event["owner"].as_u64()!=Some(*owner as u64) {return Err("exit owner differs".into());}
        let wallet = private.wallets.get(*owner).ok_or("exit wallet")?;
        let a = bundle.auth()?;
        if a.mode!=2 || a.payout.checked_add(a.fee)!=Some(note.value)
            || a.spk.as_slice()!=native::encode_spk(&native::p2pk(&wallet.payout_key(&request.domain,position.try_into()?))?) {
            return Err("exit recipient/value differs from owning wallet".into());
        }
        paid_owners.insert(*owner);
    }
    if paid_owners.len()!=4 {return Err("not all four wallets have exits".into());}
    let sources: Vec<native::Utxo> = ex::read(sources)?;
    let values = amounts(root)?;
    if sources.len()!=4 || private.funding_keys.len()!=4 || private.wallets.len()!=4
        || start_hash.len()!=64 || hex::decode(&start_hash)?.len()!=32 {return Err("funded shape".into());}
    let mut seen = std::collections::HashSet::new();
    for (i,u) in sources.iter().enumerate() {
        if !seen.insert((u.txid.clone(),u.index)) || u.is_coinbase
            || u.spk != hex::encode(native::encode_spk(&native::p2pk(&private.funding_keys[i])?))
            || (i==0 && u.amount <= values[0]) || (i>0 && u.amount != values[i]) {
            return Err("funded source ownership/value".into());
        }
    }
    let vk = hex::decode(&request.vk)?;
    let initial = &private.notes.first().ok_or("initial opening")?.1;
    if initial.value != values[0] {return Err("initial amount mismatch".into());}
    let state = PublicState::initial(initial.commitment(&request.domain))?;
    let (genesis, entries) = native::ordinary(&sources[0], &private.funding_keys[0],
        vec![TransactionOutput::new(values[0], dep::reserve_spk(&request.domain, &state, &vk)?)])?;
    let mut prefix = Ledger {state, reserve:Some(native::Utxo::output(&genesis,0,0)),
        transactions:vec![native::tx_json(&genesis)], contexts:vec![vec![sources[0].clone()]],
        metrics:vec![native::policy(&genesis,&entries)?], fees:native::validate(&genesis,&entries)?};
    let mut next_source = 1;
    for raw in request.prefix.transactions.iter().skip(1) {
        let tx = native::parse_tx(raw)?;
        let (deposit, _, _) = dep::parse(&tx.payload)?;
        let b = extract(&tx)?;
        let external = if deposit {
            let index = next_source; next_source += 1;
            Some((sources.get(index).ok_or("extra admission")?, &private.funding_keys[index]))
        } else {None};
        prefix.apply(&request.domain, &vk, &b, external)?;
    }
    if next_source != 4 || prefix.state.compact()? != request.prefix.state.compact()? {
        return Err("rebinding changed shielded state".into());
    }
    let public = root.join("public"); dep::harness::dir(&public)?;
    let d = Descriptor {format:"kpi-normalized-v5-v1".into(), network:"testnet-10".into(),
        genesis:GENESIS_HEX.into(), domain:request.domain, initial_commitment:initial.commitment(&request.domain),
        initial_value:values[0], vk_sha256:hex::encode(hash(&vk)), sources,
        funding_txid:genesis.id().to_string(), start_hash};
    ex::save(&public.join("descriptor.json"), &d)?;
    fs::write(public.join("vk.bin"), &vk)?;
    ex::save(&public.join("history.json"), &prefix.transactions)?;
    ex::save(&public.join("contexts.json"), &prefix.contexts)?;
    ex::save(&public.join("metrics.json"), &prefix.metrics)?;
    let capabilities = root.join("capabilities"); dep::harness::dir(&capabilities)?;
    for arm in ["saved","fresh"] {
        let mut r: Request = ex::read(&root.join(format!("prepared/{arm}-request.json")))?;
        for (index, bundle) in r.bundles.iter().enumerate() {
            ex::save(&capabilities.join(format!("{arm}-{index:04}.json")), &Saved {
                format:"kpi-normalized-exit-v1".into(), descriptor_sha256:ex::file_hash(&public.join("descriptor.json"))?,
                bundle:bundle.clone()})?;
        }
        r.prefix = prefix.clone(); ex::save(&root.join(format!("{arm}-bound.json")), &r)?;
    }
    let (_, checked) = replay(&public)?;
    if checked.state.compact()? != prefix.state.compact()? {return Err("replay differs".into());}
    Ok(json!({"bound":true,"prefix_transactions":prefix.transactions.len(),
        "unchanged_private_proofs":true,"equal_net_credit_sompi":values[0]-dep::fees()?.transfer}))
}

fn context(public: &Path) -> Result<(Descriptor, Vec<u8>)> {
    let d: Descriptor = ex::read(&public.join("descriptor.json"))?;
    let vk = fs::read(public.join("vk.bin"))?;
    if d.format!="kpi-normalized-v5-v1" || d.network!="testnet-10" || d.genesis!=GENESIS_HEX
        || vk.len()!=328 || d.vk_sha256!=hex::encode(hash(&vk)) || d.sources.len()!=4
        || d.initial_value>MAX_SOMPI || d.start_hash.len()!=64 || hex::decode(&d.start_hash)?.len()!=32 {
        return Err("normalized descriptor identity".into());
    }
    let mut seen=std::collections::HashSet::new();
    for u in &d.sources {
        if !seen.insert((u.txid.clone(),u.index)) || u.is_coinbase || u.amount>MAX_SOMPI {
            return Err("descriptor source identity".into());
        }
    }
    Ok((d,vk))
}

fn replay(public: &Path) -> Result<(Descriptor, Ledger)> {
    let (d,vk) = context(public)?;
    let raw: Vec<Value> = ex::read(&public.join("history.json"))?;
    let initial = native::parse_tx(raw.first().ok_or("missing history")?)?;
    let mut state = PublicState::initial(d.initial_commitment)?;
    if initial.id().to_string()!=d.funding_txid || initial.inputs.len()!=1
        || initial.inputs[0].previous_outpoint!=d.sources[0].outpoint()? || initial.outputs.len()!=2
        || initial.outputs[0].value!=d.initial_value
        || initial.outputs[0].script_public_key!=dep::reserve_spk(&d.domain,&state,&vk)? {
        return Err("pinned genesis/lineage".into());
    }
    let mut fee = native::validate(&initial,&[d.sources[0].entry()?])?;
    let mut reserve = Some(native::Utxo::output(&initial,0,0));
    let mut external=d.sources[1..].to_vec();
    let mut contexts=vec![vec![d.sources[0].clone()]];
    let mut metrics=vec![native::policy(&initial,&[d.sources[0].entry()?])?];
    for v in raw.iter().skip(1) {
        let tx=native::parse_tx(v)?;
        let prior=reserve.as_ref().ok_or("history after drain")?;
        if tx.inputs.is_empty() || tx.inputs[0].previous_outpoint!=prior.outpoint()? {
            return Err("reserve lineage discontinuity".into());
        }
        let (deposit,a,s)=dep::parse(&tx.payload)?;
        let mut ctx=vec![prior.clone()];
        if deposit {
            if tx.inputs.len()!=2 {return Err("admission inputs".into());}
            let i=external.iter().position(|u|u.outpoint().ok()==Some(tx.inputs[1].previous_outpoint))
                .ok_or("unbacked/reused admission")?;
            ctx.push(external.remove(i));
        } else if tx.inputs.len()!=1 {return Err("spend inputs".into());}
        let entries=ctx.iter().map(native::Utxo::entry).collect::<Result<Vec<_>>>()?;
        fee=fee.checked_add(native::validate(&tx,&entries)?).ok_or("fee overflow")?;
        metrics.push(native::policy(&tx,&entries)?);
        let (next,w)=dep::update(&state,&a,deposit)?;
        if a.domain!=d.domain || next.compact()?!=s || tx.payload[P_WITNESS..]!=w {
            return Err("public state reconstruction".into());
        }
        state=next;
        reserve=if s.cm_count==s.nf_count {None} else {Some(native::Utxo::output(&tx,0,0))};
        contexts.push(ctx);
    }
    Ok((d,Ledger{state,reserve,transactions:raw,contexts,metrics,fees:fee}))
}

fn exit(public: &Path, saved: &Path, out: &Path) -> Result<Value> {
    let saved: Saved=ex::read(saved)?;
    if saved.format!="kpi-normalized-exit-v1" || saved.descriptor_sha256!=ex::file_hash(&public.join("descriptor.json"))? {
        return Err("saved capability/descriptor identity".into());
    }
    let (d,mut ledger)=replay(public)?;
    let vk=fs::read(public.join("vk.bin"))?;
    if saved.bundle.auth()?.mode!=2 {return Err("not a full exit".into());}
    let old=ledger.reserve.as_ref().ok_or("drained pool")?.clone();
    ledger.apply(&d.domain,&vk,&saved.bundle,None)?;
    let tx=native::parse_tx(ledger.transactions.last().ok_or("exit absent")?)?;
    let report=ex::save_tx(out,0,&tx,&[old.entry()?],json!({"saved_capability":true}))?;
    let result=json!({"unchanged_proof_and_authorization":true,"no_wallet_or_proving_key_input":true,
        "native":report,"payout":native::Utxo::output(&tx,tx.outputs.len()-1,0),"terminal":ledger.reserve.is_none()});
    ex::save(&out.join("result.json"),&result)?; Ok(result)
}

pub fn run() -> Result<()> {
    let a=std::env::args().skip(1).collect::<Vec<_>>();
    let p=|i:usize|->Result<&Path>{Ok(Path::new(a.get(i).ok_or("missing argument")?))};
    let r=match a.first().map(String::as_str) {
        Some("prepare") if a.len()==4=>study::prepare_one(p(1)?,p(2)?,p(3)?)?,
        Some("allocate") if a.len()==5=>allocate(p(1)?,p(2)?,p(3)?,p(4)?)?,
        Some("bind") if a.len()==4=>bind(p(1)?,p(2)?,a[3].clone())?,
        Some("exit") if a.len()==4=>exit(p(1)?,p(2)?,p(3)?)?,
        Some("check") if a.len()==2=>{let (_,h)=replay(p(1)?)?;json!({"valid":true,"drained":h.reserve.is_none(),
            "transactions":h.transactions.len(),"state":h.state.compact()?,"fees_sompi":h.fees})},
        Some("hashes") if a.len()==2=>{
            let raw:Vec<Value>=ex::read(p(1)?)?;
            let rows=raw.iter().map(|v|{let tx=native::parse_tx(v)?;
                Ok(json!({"txid":tx.id().to_string(),"full_hash":kaspa_consensus_core::hashing::tx::hash(&tx).to_string()}))})
                .collect::<Result<Vec<_>>>()?;
            json!(rows)
        },
        _=>return Err("prepare PARAMS PLAN OUT | allocate ROOT INPUT FUNDING OUT | bind ROOT SOURCES START | exit PUBLIC SAVED OUT | check PUBLIC".into())
    };
    println!("{}",serde_json::to_string(&r)?); Ok(())
}

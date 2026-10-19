//! Local TN10-only reuse of ordinary outputs from our previous experiments.
//! This is not a reserve withdrawal path and is never part of the covenant.
use kpi_shared_pool::{Result,native,protocol::{H,Wallet,MAX_SOMPI}};
use kpi_shared_pool::compact::experiment::{read,save};
use kaspa_consensus_core::tx::{Transaction,TransactionInput,TransactionOutput};
use serde_json::{Value,json};
use std::{fs,path::Path};
fn key_for(row:&Value,source:&native::Utxo,funding:&Path)->Result<H>{
    let funding_key:H=hex::decode(fs::read_to_string(funding.join("funding.key"))?.trim())?.try_into().map_err(|_|"funding key length")?;
    let matches=|k:&H|native::p2pk(k).map(|s|hex::encode(native::encode_spk(&s))==source.spk).unwrap_or(false);
    if matches(&funding_key){return Ok(funding_key);}
    let root=Path::new(row["origin"]["root"].as_str().ok_or("missing origin")?);
    let legacy=root.join("public/manifest.json");
    let m:Value=read(&if legacy.is_file(){legacy}else{root.join("public/descriptor.json")})?;
    let domain:H=serde_json::from_value(if m["domain"].is_array(){m["domain"].clone()}else{m["identity"]["domain"].clone()})?;
    let step:u32=row["origin"]["step"].as_u64().ok_or("origin step")?.try_into()?;
    // v5 exits derive keys from note position, which can exceed transaction
    // position (each admission creates two notes). Bound the search by the
    // public commitment count, still requiring exact script/key ownership.
    let mut key_limit=step;
    if m["identity"]["format"]=="kpi-compact-deposits-v5" || m["format"]=="kpi-normalized-v5-v1" {
        let history:Vec<Value>=read(&root.join("public/history.json"))?;
        let payload=hex::decode(history.get(step as usize).ok_or("origin history")?["payload"].as_str().ok_or("origin payload")?)?;
        if payload.len()==3892 {key_limit=key_limit.max(u32::from_le_bytes(payload[644..648].try_into()?));}
        if key_limit>65535 {return Err("origin commitment count range".into());}
    }
    if m["format"]=="kpi-normalized-v5-v1" {
        let private:Value=read(&root.join("prepared/wallets.json"))?;
        for v in private["funding_keys"].as_array().ok_or("funding keys")? {
            let key:H=serde_json::from_value(v.clone())?;if matches(&key){return Ok(key);}
        }
        for v in private["wallets"].as_array().ok_or("wallets")? {
            let w:Wallet=serde_json::from_value(v.clone())?;
            for key in std::iter::once(w.native).chain((0..=key_limit).map(|n|w.payout_key(&domain,n))) {
                if matches(&key){return Ok(key);}
            }
        }
        return Err("no owned normalized-pool ordinary payout key".into());
    }
    for i in 0..4 {
        let old=root.join(format!("wallet{i}/wallet.json"));
        let file=if old.is_file(){old}else{root.join(format!("wallet{i}.json"))};if !file.is_file(){continue;}
        let v:Value=read(&file)?;let w:Wallet=serde_json::from_value(v["wallet"].clone())?;
        if v["funding_key"].is_array(){let key:H=serde_json::from_value(v["funding_key"].clone())?;if matches(&key){return Ok(key);}}
        // A saved authorization can settle many transactions after its payout
        // key was chosen. Search its possible earlier creation indices and
        // still require an exact match to the ordinary UTXO's public script.
        for k in std::iter::once(w.native).chain((0..=key_limit).map(|n|w.payout_key(&domain,n))) {
            if matches(&k){return Ok(k);}
        }
    }
    Err("no owned key matches prior experimental payout".into())
}
fn run()->Result<()> {
    let args=std::env::args().skip(1).collect::<Vec<_>>();
    if args.len()!=3 {return Err("INPUTS FUNDING_DIRECTORY OUTPUT_DIRECTORY".into());}
    let rows:Vec<Value>=read(Path::new(&args[0]))?;if rows.len()!=2{return Err("exactly two ordinary inputs".into());}
    let funding=Path::new(&args[1]);let out=Path::new(&args[2]);
    let config:Value=read(&funding.join("funding.json"))?;
    if config["network"]!="testnet-10" {return Err("testnet-10 only".into());}
    let k:H=hex::decode(fs::read_to_string(funding.join("funding.key"))?.trim())?.try_into().map_err(|_|"funding key length")?;
    let destination=native::p2pk(&k)?;
    if config["address"]!=native::address(&destination)? {return Err("funding address mismatch".into());}
    let mut inputs=Vec::new();let mut entries=Vec::new();let mut keys=Vec::new();let mut total=0u64;
    for row in &rows {
        let mut clean=row.clone();clean.as_object_mut().ok_or("input object")?.remove("origin");
        let u:native::Utxo=serde_json::from_value(clean)?;
        if u.is_coinbase {return Err("coinbase input".into());}
        keys.push(key_for(row,&u,funding)?);entries.push(u.entry()?);
        inputs.push(TransactionInput::new_with_compute_budget(u.outpoint()?,vec![0;66],u64::MAX,10));
        total=total.checked_add(u.amount).filter(|v|*v<=MAX_SOMPI).ok_or("input total")?;
    }
    if inputs[0].previous_outpoint==inputs[1].previous_outpoint{return Err("duplicate ordinary input".into());}
    let mut fee=1;
    let mut tx=loop {
        let value=total.checked_sub(fee).filter(|v|*v>0).ok_or("funding fee")?;
        let t=Transaction::new(1,inputs.clone(),vec![TransactionOutput::new(value,destination.clone())],0,Default::default(),0,vec![]);
        native::set_mass(&t,&entries)?;let required=native::metrics(&t,&entries)?["mining_mass"].as_u64().ok_or("mass")?.checked_mul(100).ok_or("fee overflow")?;
        if fee<required {fee=required;continue;}break t;
    };
    for (i,key) in keys.iter().enumerate(){native::sign(&mut tx,&entries,i,key)?;}
    native::validate(&tx,&entries)?;let metrics=native::policy(&tx,&entries)?;
    save(&out.join("transaction.json"),&native::tx_json(&tx))?;
    save(&out.join("validation.json"),&json!({"network":"testnet-10","native_full":true,"policy":metrics,"ordinary_inputs":2,"destination":config["address"]}))?;
    println!("{}",json!({"transactionId":tx.id().to_string(),"feeSompi":fee,"outputSompi":tx.outputs[0].value}));Ok(())
}
fn main(){if let Err(e)=run(){eprintln!("experimental funding: {e}");std::process::exit(1);}}

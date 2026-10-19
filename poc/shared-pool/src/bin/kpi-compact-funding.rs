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
    let m:Value=read(&root.join("public/manifest.json"))?;
    let domain:H=serde_json::from_value(m["domain"].clone())?;
    let step:u32=row["origin"]["step"].as_u64().ok_or("origin step")?.try_into()?;
    for i in 0..4 {
        let file=root.join(format!("wallet{i}/wallet.json"));if !file.is_file(){continue;}
        let v:Value=read(&file)?;let w:Wallet=serde_json::from_value(v["wallet"].clone())?;
        // A saved authorization can settle many transactions after its payout
        // key was chosen. Search its possible earlier creation indices and
        // still require an exact match to the ordinary UTXO's public script.
        for k in std::iter::once(w.native).chain((0..=step).map(|n|w.payout_key(&domain,n))) {
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

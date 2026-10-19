//! Mutations bypass friendly builders and execute real native consensus.
use super::*;
use serde_json::{Value,json};
use std::{fs,path::Path};
fn replace_state(tx:&mut Transaction,d:&H,s:&State,vk:&[u8])->Result<()> {
    tx.payload[P_STATE..P_WITNESS].copy_from_slice(&s.bytes());
    if s.cm_count!=s.nf_count {
        let good=PublicState::initial([1;32])?.compact()?;
        let mut r=covenant::redeem(d,&good,vk)?;
        r[36..36+STATE_LEN].copy_from_slice(&s.bytes());
        tx.outputs[0].script_public_key=pay_to_script_hash_script(&r);
    }
    Ok(())
}
fn reject(out:&mut Vec<Value>,name:&str,step:u32,mut tx:Transaction,entries:&[UtxoEntry])->Result<()> {
    tx.finalize(); native::set_mass(&tx,entries)?;
    let error=native::validate(&tx,entries).err().ok_or_else(||format!("NATIVE ACCEPTED hostile {name}, step {step}"))?;
    out.push(json!({"control":name,"step":step,"rejected":true,"native_error":error.to_string()}));Ok(())
}
pub fn run(public:&Path)->Result<Value> {
    let (m,vk)=experiment::manifest(public)?;
    let mut steps=fs::read_dir(public)?.filter_map(|e|e.ok()).filter_map(|e|{
        let n=e.file_name().to_string_lossy().into_owned();
        if n.len()==9 && n.ends_with(".json") {n[..4].parse::<u32>().ok()}else{None}
    }).collect::<Vec<_>>();steps.sort();
    let end=*steps.last().ok_or("no control transactions")?;
    let h=experiment::history(public,end,&m,&vk)?;
    if h.reserve.is_some(){return Err("controls require full drain".into());}
    let payments=(end-3)/2; let bob=payments+2;
    let mut out=Vec::new();
    for step in [1,2,bob,end] {
        let tx=&h.transactions[step as usize];let previous=&h.transactions[step as usize-1];
        let input=native::Utxo::output(previous,0,0);let entries=vec![input.entry()?];
        let (a,next)=parse_payload(&tx.payload)?;
        native::validate(tx,&entries)?;
        for (name,off) in [("wrong domain",P_AUTH+8),("wrong historical root",P_AUTH+A_ANCHOR),
            ("wrong nullifier",P_AUTH+A_NF),("unauthorized recipient",P_AUTH+A_SPK+3),
            ("unauthorized fee",P_AUTH+A_FEE),("unauthorized amount",P_AUTH+A_PAYOUT),
            ("modified ciphertext",P_CIPHER),("false anchor path",P_WITNESS+W_ANCHOR),
            ("false predecessor index",P_WITNESS+W_PRED_INDEX),("false predecessor value",P_WITNESS+W_PRED),
            ("false predecessor next index",P_WITNESS+W_PRED+32),("false predecessor successor",P_WITNESS+W_PRED+36),
            ("false predecessor membership",P_WITNESS+W_PRED_PATH),
            ("false empty nullifier path",P_WITNESS+W_NF_APPEND),
            ("false first append path",P_WITNESS+W_CM_APPEND),("false second append path",P_WITNESS+W_CM_APPEND+PATH_LEN),
            ("false history append path",P_WITNESS+W_HISTORY_APPEND)] {
            let mut bad=tx.clone();bad.payload[off]^=1;reject(&mut out,name,step,bad,&entries)?;
        }
        for (name,offset,value) in [("future anchor",A_COUNT,65535u32),("even anchor",A_COUNT,2),("zero anchor",A_COUNT,0)] {
            let mut bad=tx.clone();bad.payload[P_AUTH+offset..P_AUTH+offset+4].copy_from_slice(&value.to_le_bytes());reject(&mut out,name,step,bad,&entries)?;
        }
        let mut bad=tx.clone();bad.inputs[0].signature_script[2]^=1;reject(&mut out,"malformed proof",step,bad,&entries)?;
        for which in 0..5 {
            let mut s=next.clone();let name=match which {
                0=>{s.cm_root[0]^=1;"forged commitment root with matching successor"},
                1=>{s.nf_root[0]^=1;"lost spentness with matching successor"},
                2=>{s.history_root[0]^=1;"forged history with matching successor"},
                3=>{s.cm_count+=2;"invented commitment count with matching successor"},
                _=>{s.nf_count-=1;"rewound spent count with matching successor"},
            };
            if next.cm_count!=next.nf_count {let mut bad=tx.clone();replace_state(&mut bad,&m.domain,&s,&vk)?;reject(&mut out,name,step,bad,&entries)?;}
        }
        let mut bad=tx.clone();bad.outputs[0].value+=1;reject(&mut out,"one sompi underbacking or wrong payout",step,bad,&entries)?;
        let mut bad=tx.clone();bad.inputs[0]=TransactionInput::new_with_compute_budget(tx.inputs[0].previous_outpoint,tx.inputs[0].signature_script.clone(),u64::MAX,1);
        reject(&mut out,"insufficient execution budget",step,bad,&entries)?;
        if a.mode==1 {
            let mut bad=tx.clone();bad.payload[P_AUTH+A_BOOT]^=1;reject(&mut out,"bootstrap backing or replay",step,bad,&entries)?;
        }
        if step>1 {
            let mut bad=tx.clone();bad.payload[P_WITNESS+W_PRED_PATH..P_WITNESS+W_NF_APPEND+PATH_LEN]
                .copy_from_slice(&h.transactions[1].payload[P_WITNESS+W_PRED_PATH..P_WITNESS+W_NF_APPEND+PATH_LEN]);
            reject(&mut out,"stale current spentness witnesses",step,bad,&entries)?;
        }
    }
    // Replay Bob's actual proof after payout. Compute consistent duplicate roots
    // below host checks so the strict gap check must reject, not a stale path.
    let before=experiment::history(public,bob,&m,&vk)?;
    let original=&h.transactions[bob as usize];let (a,_)=parse_payload(&original.payload)?;
    let old=before.state;let compact=old.compact()?;let mut next=old.clone();
    let pred=old.nullifiers.iter().position(|l|l.value==a.nullifier).ok_or("missing Bob spent marker")?;
    let prior=old.nullifiers[pred].clone();let mut witness=original.payload[P_WITNESS..].to_vec();
    witness[W_PRED_INDEX..W_PRED_INDEX+4].copy_from_slice(&(pred as u32).to_le_bytes());
    witness[W_PRED..W_PRED+68].copy_from_slice(&prior.bytes());
    for (i,v) in old.nf_tree()?.path(pred as u32)?.iter().enumerate(){witness[W_PRED_PATH+i*32..W_PRED_PATH+(i+1)*32].copy_from_slice(v);}
    let idx=next.nullifiers.len() as u32;
    next.nullifiers[pred].next_index=idx;next.nullifiers[pred].next_value=a.nullifier;
    for (i,v) in next.nf_tree()?.path(idx)?.iter().enumerate(){witness[W_NF_APPEND+i*32..W_NF_APPEND+(i+1)*32].copy_from_slice(v);}
    next.nullifiers.push(tree::NfLeaf{value:a.nullifier,next_index:prior.next_index,next_value:prior.next_value});
    let input=before.reserve.ok_or("Bob prematurely terminal")?;
    let mut bad=original.clone();
    bad.inputs[0]=TransactionInput::new_with_compute_budget(input.outpoint()?,covenant::signature(&original.inputs[0].signature_script[2..130],&covenant::redeem(&m.domain,&compact,&vk)?)?,u64::MAX,covenant::BUDGET);
    bad.payload[P_WITNESS..].copy_from_slice(&witness);replace_state(&mut bad,&m.domain,&next.compact()?,&vk)?;
    bad.outputs[0].value=input.amount-a.payout-a.fee;
    reject(&mut out,"duplicate withdrawal with original valid proof and consistent fresh roots",bob+1,bad,&[input.entry()?])?;
    // Synthetic current-UTXO boundary fixture, not a 65,535-note accepted history.
    // Its archive includes Bob's genuine old anchor; all current tree witnesses
    // are recomputed, and his unchanged proof exits at the last usable NF index.
    let mut boundary=PublicState::initial([1;32])?;
    boundary.commitments=vec![[1;32];tree::LIMIT-1];
    boundary.roots=vec![[8;32];tree::LIMIT/2];
    boundary.roots[(a.count as usize-1)/2]=a.anchor;
    *boundary.roots.last_mut().unwrap()=boundary.cm_tree()?.root();
    let key=|n:u32|{let mut h=[0;32];h[..4].copy_from_slice(&n.to_le_bytes());h};
    boundary.nullifiers=(0..tree::LIMIT-1).map(|i|tree::NfLeaf{
        value:key(i as u32),next_index:if i==tree::LIMIT-2{0}else{i as u32+1},
        next_value:if i==tree::LIMIT-2{[0;32]}else{key(i as u32+1)},
    }).collect();
    let r=covenant::redeem(&m.domain,&boundary.compact()?,&vk)?;
    let u=native::Utxo{txid:hex::encode([9;32]),index:0,amount:a.payout+a.fee,spk:hex::encode(native::encode_spk(&pay_to_script_hash_script(&r))),daa:0,is_coinbase:false};
    let bundle=Bundle{authorization:hex::encode(a.bytes()),proof:hex::encode(&original.inputs[0].signature_script[2..130]),ciphertexts:[hex::encode([0;185]),hex::encode([0;185])]};
    let (terminal,es)=settle(&m.domain,&boundary,&u,&vk,&bundle)?;
    native::validate(&terminal,&es)?;let metrics=native::policy(&terminal,&es)?;
    if terminal.outputs.len()!=1 || terminal.outputs[0].value!=a.payout {return Err("capacity terminal output".into());}
    Ok(json!({"native_rejections":out.len(),"controls":out,"all_positive_transactions":end+1,
        "capacity_terminal_fixture":{"commitments":65535,"nullifiers_before":65534,"native_full":true,"original_bob_proof":true,"metrics":metrics,"scope":"synthetic current state, not full historical execution"}}))
}

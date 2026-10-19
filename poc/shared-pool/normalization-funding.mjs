#!/usr/bin/env node
// Ordinary payouts only. All ownership/signatures and relay fees are checked
// by the existing two-input builder. No reserve or proof is spent here.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {read,save,fileHash,connect,utxos,fundingDir,transaction} from './runtime.mjs';
import {exactUtxo,outputUtxo,confirm,outpoint} from './chain.mjs';
import {mkdir} from './deposits-common.mjs';

const [mode,baseArg,inputArg,gateArg]=process.argv.slice(2),base=path.resolve(baseArg);
const builder='/home/luke/projects/kaspa-privacy-self-funded/poc/self-funded/target/release/kpi-compact-funding';
if(mode==='inventory'){
  const legacy=read(inputArg),candidates=new Map(legacy.utxos.map(u=>[outpoint(u),u]));
  const parents=['/home/luke/.local/share/kpi-deposit-tests/live',path.join(path.dirname(base),'runs')];
  for(const parent of parents)for(const name of fs.existsSync(parent)?fs.readdirSync(parent):[]){
    const root=path.join(parent,name),history=path.join(root,'public/history.json');
    if(!fs.existsSync(path.join(root,'result.json'))||!fs.existsSync(history))continue;
    const h=read(history);for(let step=0;step<h.length;step++)h[step].outputs.forEach((_,i)=>{
      const u=outputUtxo(h[step],i);if(/^000020[0-9a-f]{64}ac$/.test(u.spk))candidates.set(outpoint(u),{...u,origin:{root,step}});
    });
  }
  const {rpc}=await connect();try{
    const funding=(await utxos(rpc,read(path.join(fundingDir,'funding.json')).address)).filter(u=>!u.is_coinbase);
    const live=[];for(const u of candidates.values())if(await exactUtxo(rpc,u))live.push(u);
    const all=new Map([...live,...funding].map(u=>[outpoint(u),u]));mkdir(base);
    const file=path.join(base,'inventory-'+crypto.randomUUID()+'.json');
    save(file,{network:'testnet-10',funding,utxos:[...all.values()],observedAt:new Date().toISOString()});
    console.log(JSON.stringify({file,ordinaryOutputs:all.size,totalSompi:[...all.values()].reduce((s,u)=>s+BigInt(u.amount),0n).toString(),broadcast:false}));
  }finally{await rpc.disconnect();}
}else if(mode==='prepare'){
  const inventory=read(inputArg);assert.equal(inventory.network,'testnet-10');assert.equal(inventory.funding.length,1);
  const root=path.join(base,'consolidation-'+crypto.randomUUID());mkdir(root);
  let current=inventory.funding[0],steps=0,fees=0n;
  const candidates=inventory.utxos.filter(u=>outpoint(u)!==outpoint(current));
  candidates.sort((a,b)=>BigInt(a.amount)>BigInt(b.amount)?-1:1);
  while(BigInt(current.amount)<9_160_000_000n){
    const next=candidates.shift();assert.ok(next,'insufficient recovered ordinary test coins');
    const dir=path.join(root,String(steps).padStart(4,'0'));mkdir(dir);save(path.join(dir,'inputs.json'),[current,next]);
    const r=spawnSync(builder,[path.join(dir,'inputs.json'),fundingDir,dir],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);
    const report=JSON.parse(r.stdout);save(path.join(dir,'build.json'),report);
    const raw=read(path.join(dir,'transaction.json'));transaction(raw).free();current=outputUtxo(raw,0);fees+=BigInt(report.feeSompi);steps++;
  }
  save(path.join(root,'plan.json'),{network:'testnet-10',steps,feesSompi:fees.toString(),final:current,builderSha256:fileHash(builder)});
  console.log(JSON.stringify({root,steps,feesSompi:fees.toString(),finalSompi:current.amount,broadcast:false}));
}else if(mode==='broadcast'){
  const root=path.resolve(inputArg),plan=read(path.join(root,'plan.json'));
  assert.equal(read(path.join(gateArg,'offline-result.json')).offline_pass,true);
  assert.equal(plan.network,'testnet-10');assert.equal(plan.builderSha256,fileHash(builder));
  const {rpc}=await connect();try{
    for(let i=0;i<plan.steps;i++){
      const dir=path.join(root,String(i).padStart(4,'0'));
      for(const u of read(path.join(dir,'inputs.json')))assert.ok(await exactUtxo(rpc,u));
      const raw=read(path.join(dir,'transaction.json')),tx=transaction(raw);
      save(path.join(dir,'submission.json'),{transactionId:raw.id,at:new Date().toISOString(),noRebroadcast:true});
      try{const response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});assert.equal(response.transactionId,raw.id);save(path.join(dir,'response.json'),response);}
      finally{tx.free();}
      save(path.join(dir,'confirmed.json'),{outputs:await confirm(rpc,raw),at:new Date().toISOString()});
    }
    assert.ok(await exactUtxo(rpc,plan.final));save(path.join(root,'result.json'),{...plan,complete:true});
    console.log(JSON.stringify({complete:true,steps:plan.steps,feesSompi:plan.feesSompi}));
  }finally{await rpc.disconnect();}
}else throw Error('inventory BASE LEGACY_INVENTORY | prepare BASE INVENTORY | broadcast BASE PLAN OFFLINE_GATE');

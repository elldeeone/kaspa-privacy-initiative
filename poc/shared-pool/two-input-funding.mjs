#!/usr/bin/env node
// Reuse our ordinary testnet payouts only; never spends a covenant reserve.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {read,save,fileHash,connect,utxos,fundingDir,transaction} from './runtime.mjs';
import {exactUtxo,outputUtxo,confirm,outpoint} from './chain.mjs';
import {mkdir} from './deposits-common.mjs';
const [mode,baseArg,inputArg,gateArg]=process.argv.slice(2),base=path.resolve(baseArg);
const builder=process.env.KPI_ORDINARY_FUNDING_BINARY??'/home/luke/projects/kaspa-privacy-self-funded/poc/self-funded/target/release/kpi-compact-funding';
if(mode==='inventory'){
  const prior=read(inputArg),candidates=new Map(prior.utxos.map(u=>[outpoint(u),u]));
  const liveRoot=path.join(path.dirname(base),'runs');
  for(const name of fs.existsSync(liveRoot)?fs.readdirSync(liveRoot):[]){
    const root=path.join(liveRoot,name);if(!fs.existsSync(path.join(root,'result.json')))continue;
    const r=read(path.join(root,'result.json'));if(!r.complete||r.network!=='testnet-10')continue;
    read(path.join(root,'public/history.json')).forEach((tx,step)=>tx.outputs.forEach((_,i)=>{
      const u=outputUtxo(tx,i);if(/^000020[0-9a-f]{64}ac$/.test(u.spk))candidates.set(outpoint(u),{...u,origin:{root,step}});
    }));
  }
  const {rpc}=await connect();try{
    const funding=(await utxos(rpc,read(path.join(fundingDir,'funding.json')).address)).filter(u=>!u.is_coinbase);
    const live=[];for(const u of candidates.values())if(await exactUtxo(rpc,u))live.push(u);
    const all=new Map([...live,...funding].map(u=>[outpoint(u),u]));mkdir(base);
    const file=path.join(base,'inventory-'+crypto.randomUUID()+'.json');
    save(file,{network:'testnet-10',funding,utxos:[...all.values()]});
    console.log(JSON.stringify({file,ordinaryOutputs:all.size,totalSompi:[...all.values()].reduce((s,u)=>s+BigInt(u.amount),0n).toString(),broadcast:false}));
  }finally{await rpc.disconnect();}
}else if(mode==='plan'){
  const inventory=read(inputArg);assert.equal(inventory.network,'testnet-10');assert.equal(inventory.funding.length,1);
  mkdir(base);const root=path.join(base,'consolidation-'+crypto.randomUUID());mkdir(root);
  let current=inventory.funding[0],fees=0n,steps=0;
  const candidates=inventory.utxos.filter(u=>outpoint(u)!==outpoint(current)).sort((a,b)=>BigInt(a.amount)>BigInt(b.amount)?-1:1);
  while(BigInt(current.amount)<5_800_000_000n){
    const next=candidates.shift();assert.ok(next,'insufficient owned ordinary test KAS');
    const dir=path.join(root,String(steps).padStart(4,'0'));mkdir(dir);save(path.join(dir,'inputs.json'),[current,next]);
    const p=spawnSync(builder,[path.join(dir,'inputs.json'),fundingDir,dir],{encoding:'utf8'});assert.equal(p.status,0,p.stderr);
    const report=JSON.parse(p.stdout);save(path.join(dir,'build.json'),report);
    const raw=read(path.join(dir,'transaction.json'));transaction(raw).free();current=outputUtxo(raw,0);fees+=BigInt(report.feeSompi);steps++;
  }
  save(path.join(root,'plan.json'),{network:'testnet-10',steps,feesSompi:fees.toString(),final:current,builderSha256:fileHash(builder)});
  console.log(JSON.stringify({root,steps,feeSompi:fees.toString(),finalSompi:current.amount,broadcast:false}));
}else if(mode==='broadcast'){
  const root=path.resolve(inputArg),plan=read(path.join(root,'plan.json'));
  assert.equal(read(path.join(gateArg,'offline-result.json')).offline_pass,true);
  assert.equal(plan.network,'testnet-10');assert.equal(plan.builderSha256,fileHash(builder));
  const {rpc}=await connect();try{
    for(let i=0;i<plan.steps;i++){
      const dir=path.join(root,String(i).padStart(4,'0'));for(const u of read(path.join(dir,'inputs.json')))assert.ok(await exactUtxo(rpc,u));
      const raw=read(path.join(dir,'transaction.json')),tx=transaction(raw);
      save(path.join(dir,'submission.json'),{transactionId:raw.id,at:new Date().toISOString(),noRebroadcast:true});
      try{const response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});assert.equal(response.transactionId,raw.id);save(path.join(dir,'response.json'),response);}
      finally{tx.free();}
      save(path.join(dir,'confirmed.json'),{outputs:await confirm(rpc,raw),at:new Date().toISOString()});
    }
    assert.ok(await exactUtxo(rpc,plan.final));save(path.join(root,'result.json'),{...plan,complete:true});
    console.log(JSON.stringify({complete:true,steps:plan.steps,feeSompi:plan.feesSompi}));
  }finally{await rpc.disconnect();}
}else throw Error('inventory BASE PRIOR | plan BASE INVENTORY | broadcast BASE PLAN OFFLINE_GATE');

#!/usr/bin/env node
// Reuse ordinary, already withdrawn test coins. This never spends a pool UTXO
// and uses the existing ownership-checking two-input consolidation builder.
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
  const candidates=new Map();
  const parents=['kpi-shared-pool-trials','kpi-shared-pool-contention-trials','kpi-compact-tests/live','kpi-recovery-tests/live','kpi-anchored-tests/live'];
  for(const relative of parents){const parent=path.join('/home/luke/.local/share',relative);if(!fs.existsSync(parent))continue;
    for(const name of fs.readdirSync(parent)){const root=path.join(parent,name),pub=path.join(root,'public');
      if(!fs.existsSync(path.join(pub,'manifest.json')))continue;
      for(const file of fs.readdirSync(pub).filter(f=>/^\d{4}\.json$/.test(f))){
        const raw=read(path.join(pub,file));if(!raw.id||!raw.outputs)continue;
        for(let i=0;i<raw.outputs.length;i++){const u=outputUtxo(raw,i);
          if(/^000020[0-9a-f]{64}ac$/.test(u.spk))candidates.set(outpoint(u),{...u,origin:{root,step:Number(file.slice(0,4))}});
        }
      }
    }
  }
  const {rpc}=await connect();try{
    const funding=(await utxos(rpc,read(path.join(fundingDir,'funding.json')).address)).filter(u=>!u.is_coinbase);
    const live=[];for(const u of candidates.values())if(await exactUtxo(rpc,u))live.push(u);
    const ownedFunding=new Set(funding.map(outpoint));const rows=[...funding,...live.filter(u=>!ownedFunding.has(outpoint(u)))];
    mkdir(base);const output=path.join(base,'ordinary-inventory-'+crypto.randomUUID()+'.json');
    save(output,{network:'testnet-10',funding,utxos:rows,observedAt:new Date().toISOString()});
    console.log(JSON.stringify({output,ordinaryOutputs:rows.length,totalSompi:rows.reduce((s,u)=>s+BigInt(u.amount),0n).toString(),broadcast:false}));
  }finally{await rpc.disconnect();}
}else if(mode==='prepare'){
  const inventory=read(inputArg);assert.equal(inventory.network,'testnet-10');assert.equal(inventory.funding.length,1);
  const root=path.join(base,'funding-'+crypto.randomUUID());mkdir(root);
  let current=inventory.funding[0],steps=0;const candidates=inventory.utxos.filter(u=>outpoint(u)!==outpoint(current));
  candidates.sort((a,b)=>BigInt(a.amount)>BigInt(b.amount)?-1:1);
  const rejected=[];let fees=0n;
  while(BigInt(current.amount)<8_300_000_000n){
    const next=candidates.shift();assert.ok(next,'insufficient owned ordinary test coins for both runs');
    const dir=path.join(root,String(steps).padStart(4,'0'));mkdir(dir);
    save(path.join(dir,'inputs.json'),[current,next]);
    const r=spawnSync(builder,[path.join(dir,'inputs.json'),fundingDir,dir],{encoding:'utf8'});
    assert.equal(r.status,0,r.stderr);const report=JSON.parse(r.stdout);save(path.join(dir,'build.json'),report);
    const raw=read(path.join(dir,'transaction.json'));transaction(raw).free();current=outputUtxo(raw,0);fees+=BigInt(report.feeSompi);steps++;
  }
  save(path.join(root,'plan.json'),{network:'testnet-10',steps,feesSompi:fees.toString(),final:current,rejected,builderSha256:fileHash(builder)});
  console.log(JSON.stringify({root,steps,feesSompi:fees.toString(),finalSompi:current.amount,broadcast:false}));
}else if(mode==='broadcast'){
  const root=path.resolve(inputArg),plan=read(path.join(root,'plan.json')),gate=read(path.join(gateArg,'offline-result.json'));
  assert.equal(gate.offline_pass,true);assert.equal(plan.builderSha256,fileHash(builder));
  const {rpc}=await connect();try{
    for(let i=0;i<plan.steps;i++){
      const dir=path.join(root,String(i).padStart(4,'0'));for(const u of read(path.join(dir,'inputs.json')))assert.ok(await exactUtxo(rpc,u));
      const raw=read(path.join(dir,'transaction.json')),tx=transaction(raw);
      save(path.join(dir,'submission.json'),{transactionId:raw.id,at:new Date().toISOString()});
      try{const response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});assert.equal(response.transactionId,raw.id);save(path.join(dir,'response.json'),response);}
      finally{tx.free();}
      save(path.join(dir,'confirmed.json'),{outputs:await confirm(rpc,raw),at:new Date().toISOString()});
    }
    assert.ok(await exactUtxo(rpc,plan.final));save(path.join(root,'result.json'),{...plan,complete:true});
    console.log(JSON.stringify({complete:true,steps:plan.steps,feesSompi:plan.feesSompi,finalSompi:plan.final.amount}));
  }finally{await rpc.disconnect();}
}else throw Error('inventory BASE | prepare BASE INVENTORY | broadcast BASE PLAN GATE');

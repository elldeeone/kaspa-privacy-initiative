#!/usr/bin/env node
// Reuse only inventoried ordinary outputs from the owner's preceding TN10 tests.
// `prepare` is offline; `broadcast` requires this candidate's 100-payment gate.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {read,save,binary,fundingDir,fileHash,connect,transaction} from './runtime.mjs';
import {exactUtxo,confirm,outputUtxo,outpoint} from './chain.mjs';
const [command,input,destination,offline]=process.argv.slice(2);
const builder=path.join(path.dirname(binary),'kpi-compact-funding');
if(command==='prepare'){
  const inventory=read(input);assert.equal(inventory.network,'testnet-10');
  fs.mkdirSync(destination,{mode:0o700});
  const rows=inventory.utxos.filter(u=>!u.is_coinbase).sort((a,b)=>BigInt(a.amount)>BigInt(b.amount)?-1:1);
  const original=new Set(rows.map(outpoint));assert.equal(original.size,rows.length);
  let current=rows.shift(),step=0,totalFees=0n;
  const target=11_200_000_000n;
  while(BigInt(current.amount)<target){
    const next=rows.shift();assert.ok(next,'insufficient inventoried test coins');
    const dir=path.join(destination,String(step).padStart(4,'0'));fs.mkdirSync(dir,{mode:0o700});
    save(path.join(dir,'inputs.json'),[current,next]);
    const p=spawnSync(builder,[path.join(dir,'inputs.json'),fundingDir,dir],{encoding:'utf8'});
    assert.equal(p.status,0,p.stderr);const report=JSON.parse(p.stdout);totalFees+=BigInt(report.feeSompi);
    const raw=read(path.join(dir,'transaction.json'));transaction(raw).free();
    current={...outputUtxo(raw,0),origin:{funding:true}};step++;
  }
  save(path.join(destination,'plan.json'),{network:'testnet-10',transactions:step,feeSompi:totalFees,final:current,ordinaryOnly:true,builderSha256:fileHash(builder)});
  console.log(JSON.stringify({prepared:step,feeSompi:totalFees.toString(),finalSompi:current.amount,broadcast:false}));
}else if(command==='broadcast'){
  const plan=read(path.join(input,'plan.json')),gate=read(path.join(offline,'offline-result.json'));
  assert.equal(gate.offline_pass,true);assert.equal(gate.payments_after_bob_authorization,100);
  assert.equal(gate.binary_sha256,fileHash(binary));assert.equal(plan.builderSha256,fileHash(builder));
  const {rpc}=await connect();try{
    for(let step=0;step<plan.transactions;step++){
      const dir=path.join(input,String(step).padStart(4,'0')),rows=read(path.join(dir,'inputs.json'));
      for(const u of rows)assert.ok(await exactUtxo(rpc,u),'ordinary funding input already spent');
      const raw=read(path.join(dir,'transaction.json')),tx=transaction(raw);
      save(path.join(dir,'submission.json'),{txid:raw.id,submittedAt:new Date().toISOString(),bodySha256:fileHash(path.join(dir,'transaction.json'))});
      let response;try{response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});}
      catch(error){save(path.join(dir,'response.json'),{accepted:false,error:String(error)});throw error;}finally{tx.free();}
      assert.equal(response.transactionId,raw.id);save(path.join(dir,'response.json'),{accepted:true,response});
      save(path.join(dir,'confirmed.json'),{outputs:await confirm(rpc,raw),observedAt:new Date().toISOString()});
    }
    save(path.join(input,'result.json'),{complete:true,ordinaryOnly:true,transactions:plan.transactions,feeSompi:plan.feeSompi,final:plan.final});
    console.log(JSON.stringify({complete:true,transactions:plan.transactions,feeSompi:plan.feeSompi}));
  }finally{await rpc.disconnect();}
}else throw Error('prepare INVENTORY OUTPUT | broadcast PLAN_DIR unused OFFLINE');

#!/usr/bin/env node
// Read-only chain evidence. Capture an anchor immediately before broadcasting,
// then retrieve Full accepted transaction data and compare every native byte.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
const k=createRequire(import.meta.url)(process.env.KPI_SDK_PATH??'/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa/kaspa.js');
const [command,root]=process.argv.slice(2);assert.ok(root);
const read=p=>JSON.parse(fs.readFileSync(p,'utf8'));
const encode=v=>JSON.stringify(v,(_,x)=>typeof x==='bigint'?x.toString():x,2)+'\n';
const save=(p,v)=>fs.writeFileSync(p,encode(v),{flag:'wx',mode:0o600});
const digest=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const rpc=new k.RpcClient({url:process.env.KPI_TN10_RPC??'ws://10.0.3.26:17210',networkId:'testnet-10'});
await rpc.connect({timeoutDuration:15000});
try{
  const info=await rpc.getServerInfo();assert.equal(info.networkId,'testnet-10');assert.equal(info.isSynced,true);
  if(command==='anchor'){
    const dag=await rpc.getBlockDagInfo();save(path.join(root,'chain-anchor.json'),{capturedAt:new Date().toISOString(),info,dag});
    console.log(JSON.stringify({anchor:dag.sink}));
  }else if(command==='fetch'){
    const start=read(path.join(root,'chain-anchor.json')).dag.sink;
    const expected=read(path.join(root,'chain-only.json'));
    const wanted=new Map(expected.transactions.map(r=>[r.tx.id,r]));const found=new Map();
    let cursor=start;const pages=[];
    while(found.size<wanted.size){
      const page=await rpc.getVirtualChainFromBlockV2({startHash:cursor,dataVerbosityLevel:'Full'});
      if(found.size)assert.equal(page.removedChainBlockHashes.length,0,'chain changed during paginated retrieval; refresh read-only evidence');
      for(const group of page.chainBlockAcceptedTransactions){
        for(const t of group.acceptedTransactions){
          const id=t.verboseData?.transactionId;if(!wanted.has(id))continue;
          const raw={version:t.version,id,inputs:t.inputs.map(i=>({previousOutpoint:i.previousOutpoint,signatureScript:i.signatureScript??'',sequence:i.sequence.toString(),sigOpCount:i.sigOpCount,computeBudget:i.computeBudget})),outputs:t.outputs.map(o=>({value:o.value.toString(),scriptPublicKey:typeof o.scriptPublicKey==='string'?o.scriptPublicKey:o.scriptPublicKey.version.toString(16).padStart(4,'0')+o.scriptPublicKey.script,covenant:o.covenant??null})),lockTime:t.lockTime.toString(),subnetworkId:t.subnetworkId,gas:t.gas.toString(),payload:t.payload,storageMass:t.storageMass.toString()};
          assert.deepEqual(raw,wanted.get(id).tx,'retrieved chain body differs from submission');
          const metrics=read(path.join(root,'public',String(wanted.get(id).step).padStart(4,'0')+'.metrics.json'));
          assert.equal(t.verboseData.hash,metrics.full_hash,'full transaction hash differs');
          found.set(id,{row:{...wanted.get(id),tx:raw},acceptedHeader:group.chainBlockHeader,verboseData:t.verboseData,raw:t});
        }
      }
      pages.push({start:cursor,removedBlocks:page.removedChainBlockHashes,addedBlocks:page.addedChainBlockHashes.length,matched:found.size});
      if(found.size===wanted.size)break;
      const next=page.addedChainBlockHashes.at(-1);
      if(next&&next!==cursor){cursor=next;}else{await new Promise(r=>setTimeout(r,2000));}
    }
    const transactions=expected.transactions.map(r=>found.get(r.tx.id).row);
    save(path.join(root,'chain-confirmed.json'),{schema:expected.schema,network:expected.network,transactions});
    save(path.join(root,'chain-retrieval.json'),{retrievedAt:new Date().toISOString(),source:'getVirtualChainFromBlockV2 Full accepted transaction data',info,start,pages,exactBodyAndFullHashMatches:found.size,chainSha256:digest(path.join(root,'chain-confirmed.json')),accepted:expected.transactions.map(r=>{const f=found.get(r.tx.id);return {step:r.step,header:f.acceptedHeader,transaction:f.raw};})});
    console.log(JSON.stringify({retrieved:found.size,exactBodyAndFullHashMatches:found.size,output:path.join(root,'chain-confirmed.json')}));
  }else throw Error('usage: node fetch-chain.mjs anchor|fetch TRIAL');
}finally{await rpc.disconnect();}

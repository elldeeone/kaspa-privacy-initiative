// One wallet's saved capabilities and pinned descriptor/VK only. No private
// prover, sender, other wallet, or operator state is available to this process.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {read,save,fileHash,transaction,connect} from './runtime.mjs';
import {confirm,exactUtxo} from './chain.mjs';
import {mkdir,command,replace} from './deposits-common.mjs';
import {acceptedHistory,reserveAfter} from './two-input-chain.mjs';

const run=process.argv[2],mode=read(path.join(run,'config.json')).mode,saved=read('/saved.json');
assert.ok(['offline','tn10'].includes(mode));
assert.equal(saved.format,'kpi-two-input-saved-v1');
assert.equal(saved.descriptor_sha256,fileHash('/source/descriptor.json'));
const d=read('/source/descriptor.json');
assert.equal(d.network,'testnet-10');assert.equal(d.vk_sha256,fileHash('/source/vk.bin'));
for(const name of ['/home','/params','/wallets.json','/other-wallets'])assert.ok(!fs.existsSync(name));
const pub=path.join(run,'public');mkdir(pub);
for(const f of ['descriptor.json','vk.bin'])fs.copyFileSync('/source/'+f,path.join(pub,f),fs.constants.COPYFILE_EXCL);
const receipts=[];let rpc,history=mode==='offline'?read('/accepted/history.json'):null;
try{
  if(mode==='tn10')rpc=(await connect()).rpc;
  for(let index=0;index<saved.bundles.length;index++){
    let discovered;
    if(rpc){discovered=await acceptedHistory(rpc,d);history=discovered.history;}
    replace(path.join(pub,'history.json'),history);
    const out=path.join(run,`exit-${index}`);mkdir(out);
    const result=command('/program',['exit',pub,'/saved.json',String(index),out],out,'settlement');
    assert.equal(result.unchanged_proof_and_authorization,true);
    const raw=read(path.join(out,'0000.json'));
    const a=saved.bundles[index];
    assert.equal(Buffer.from(raw.payload,'hex').subarray(8,385).toString('hex'),a.authorization);
    assert.equal(Buffer.from(raw.inputs[0].signatureScript,'hex').subarray(2,130).toString('hex'),a.proof);
    if(rpc){
      assert.ok(await exactUtxo(rpc,reserveAfter(history.at(-1))),'reserve changed before submission');
      const tx=transaction(raw);save(path.join(out,'submission.json'),{transactionId:raw.id,at:new Date().toISOString(),noRebroadcast:true});
      try{const response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});assert.equal(response.transactionId,raw.id);save(path.join(out,'response.json'),response);}
      finally{tx.free();}
      save(path.join(out,'confirmed.json'),{outputs:await confirm(rpc,raw),at:new Date().toISOString()});
      assert.ok(await exactUtxo(rpc,result.payout));
    }
    receipts.push({...result,confirmed:!!rpc,transaction:raw,discovery:discovered?{pages:discovered.pages,observedAt:discovered.observedAt}:null});
    if(!rpc)history.push(raw);
  }
  save(path.join(run,'result.json'),{complete:true,mode,noWalletOrProvingKey:true,ownCapabilitiesOnly:true,
    currentStateFromAcceptedRPC:!!rpc,savedSha256:fileHash('/saved.json'),receipts});
}finally{if(rpc)await rpc.disconnect();}

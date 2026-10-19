// Runs in an isolated wallet namespace: two saved proofs, public descriptor/VK,
// and either an explicit offline chain snapshot or the wallet's own TN10 RPC.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {read,save,fileHash,transaction,connect} from './runtime.mjs';
import {confirm,exactUtxo,outputUtxo} from './chain.mjs';
import {mkdir,command,replace,acceptedHistory} from './deposits-common.mjs';

export async function client(root){
  const config=read(path.join(root,'config.json')),saved=read('/saved.json');
  assert.ok(['offline','tn10'].includes(config.mode));
  const publicDir=path.join(root,'public');mkdir(publicDir);const attempts=[];
  for(const source of config.sources){
    try{
      const descriptor=fs.readFileSync(new URL('descriptor.json',source));
      const vk=fs.readFileSync(new URL('vk.bin',source));
      const crypto=await import('node:crypto');const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
      assert.equal(hash(descriptor),saved.descriptor_sha256);assert.equal(hash(vk),JSON.parse(descriptor).identity.vk_sha256);
      fs.writeFileSync(path.join(publicDir,'descriptor.json'),descriptor,{flag:'wx',mode:0o600});
      fs.writeFileSync(path.join(publicDir,'vk.bin'),vk,{flag:'wx',mode:0o600});attempts.push({source,accepted:true});break;
    }catch(error){attempts.push({source,accepted:false,error:String(error)});}
  }
  assert.ok(attempts.at(-1)?.accepted,'no authenticated public descriptor/VK source');
  assert.ok(!fs.existsSync('/params'));assert.ok(!fs.existsSync('/wallet.json'));assert.ok(!fs.existsSync('/home/luke'));
  const d=read(path.join(publicDir,'descriptor.json'));let rpc;let history;
  if(config.mode==='tn10')rpc=(await connect()).rpc;else history=read('/accepted/history.json');
  const results=[];
  try{
    for(let index=0;index<2;index++){
      if(rpc)history=(await acceptedHistory(rpc,d)).history;
      const hp=path.join(publicDir,'history.json');if(fs.existsSync(hp))replace(hp,history);else save(hp,history);
      const out=path.join(root,`exit-${index}`);mkdir(out);
      const result=command('/program',['exit',publicDir,'/saved.json',String(index),out],out,'settlement');
      assert.equal(result.unchanged_proof_and_authorization,true);const raw=read(path.join(out,'0000.json'));const tx=transaction(raw);
      try{
        if(rpc){
          const expected=result.payout;const input=outputUtxo(history.at(-1),0);assert.ok(await exactUtxo(rpc,input),'reserve changed before submit');
          save(path.join(out,'submission.json'),{transactionId:raw.id,at:new Date().toISOString()});
          const response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});assert.equal(response.transactionId,raw.id);
          save(path.join(out,'response.json'),response);const outputs=await confirm(rpc,raw);
          assert.ok(await exactUtxo(rpc,expected));save(path.join(out,'confirmed.json'),{outputs,at:new Date().toISOString()});
        }
      }finally{tx.free();}
      history.push(raw);results.push({...result,transaction:raw,confirmed:!!rpc});
    }
    const v={complete:true,mode:config.mode,noWalletOrProvingKey:true,sources:attempts,exits:results,
      savedProofFileSha256:fileHash('/saved.json'),at:new Date().toISOString()};
    save(path.join(root,'result.json'),v);return v;
  }finally{if(rpc)await rpc.disconnect();}
}
if(process.argv[1]===fileURLToPath(import.meta.url))await client(process.argv[2]);

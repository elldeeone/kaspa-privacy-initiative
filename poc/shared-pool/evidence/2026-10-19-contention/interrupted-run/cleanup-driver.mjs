// Operational cleanup only: fresh identity, no seed transaction rebroadcast.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {startAgent} from '../../../contention.mjs';
import {read,save,connect,transaction,rust} from '../../../runtime.mjs';
import {acceptedSnapshot,canonicalRpcTx,outputUtxo,exactUtxo,successor} from '../../../chain.mjs';
const old=process.argv[2],base=process.argv[3];
assert.ok(!fs.existsSync(path.join(old,'barrier/go.json')),'cleanup only supports failure before any exit release');
const root=path.join(base,new Date().toISOString().replaceAll(':','-')+'-cleanup-'+crypto.randomUUID());
fs.mkdirSync(root,{mode:0o700});fs.cpSync(path.join(old,'public'),path.join(root,'public'),{recursive:true});
for(const i of [0,1])fs.cpSync(path.join(old,`wallet${i}`),path.join(root,`wallet${i}`),{recursive:true});
fs.copyFileSync(path.join(old,'anchor.json'),path.join(root,'anchor.json'));
fs.mkdirSync(path.join(root,'barrier'),{mode:0o700});fs.mkdirSync(path.join(root,'logs'),{mode:0o700});
save(path.join(root,'origin.json'),{sourceTrial:path.basename(old),scope:'separate cleanup identity; original rehearsal remains failed; no seed transaction rebroadcast'});
console.log(JSON.stringify({stage:'cleanup-created',root}));
const {rpc}=await connect(),agents=[];
try{
 const seed=read(path.join(root,'public/0002.json')),initial=outputUtxo(seed,0);
 assert.ok(await exactUtxo(rpc,initial));
 for(const i of [0,1])agents.push(startAgent(root,i));
 const ready=await Promise.all(agents.map(a=>a.ready()));assert.deepEqual(ready[0].predecessor,ready[1].predecessor);assert.equal(ready[0].predecessor.transactionId,seed.id);
 save(path.join(root,'barrier/go.json'),{releasedAt:new Date().toISOString()});console.log(JSON.stringify({stage:'cleanup-released'}));
 await Promise.all(agents.map(a=>a.done));
 const results=agents.map(a=>read(path.join(a.dir,'result.json')));assert.deepEqual(results.map(r=>r.rebuilds).sort(),[0,1]);
 const snapshot=await acceptedSnapshot(rpc,read(path.join(root,'anchor.json')).sink);
 let reserve=initial,fee=0n;const chain=[];
 while(reserve){
  const row=successor(snapshot,reserve);assert.ok(row);const raw=canonicalRpcTx(row.transaction);transaction(raw).free();
  const stem=path.join(root,'logs',String(chain.length));save(stem+'.json',raw);save(stem+'.inputs.json',[reserve]);
  const val=rust(path.join(root,'logs'),String(chain.length)+'-validate',['validate',stem+'.json',stem+'.inputs.json']);assert.equal(val.full_hash,row.transaction.verboseData.hash);
  chain.push({transaction:row.transaction,validation:val,inputs:[reserve]});fee+=BigInt(val.metrics.fee_sompi);
  reserve=Buffer.from(raw.payload,'hex')[8]===3?null:outputUtxo(raw,0);
 }
 assert.equal(chain.length,2);let payouts=0n;
 for(const r of results){assert.ok(await exactUtxo(rpc,r.payout));payouts+=BigInt(r.payout.amount);assert.equal(r.ownNotesRemaining,0);}
 assert.equal(payouts+fee,BigInt(initial.amount));
 save(path.join(root,'result.json'),{success:true,scope:'cleanup only; does not qualify a rehearsal',initialReserve:initial,acceptedFeeSompi:fee.toString(),payoutSompi:payouts.toString(),terminalReserveSpent:true,wallets:results,accepted:chain});
 console.log(JSON.stringify({stage:'cleanup-complete',root,feeSompi:fee.toString(),bothExited:true}));
}finally{await Promise.allSettled(agents.map(a=>a.stop()));await rpc.disconnect();}

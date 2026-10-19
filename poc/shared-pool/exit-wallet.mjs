#!/usr/bin/env node
// Autonomous bounded wallet: own secrets + public artifacts + ordinary RPC.
// No controller messages after the common release, and no winner ID input.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {binary,read,save,number,fileHash,transaction,rust,connect,startWallet} from './runtime.mjs';
import {sleep,outputUtxo,exactUtxo,canonicalRpcTx,acceptedSnapshot,successor,submissionFailure} from './chain.mjs';

const root=path.resolve(process.argv[2]??'/trial');
const publicDir=path.join(root,'public'),logs=path.join(root,'logs');
fs.mkdirSync(logs,{mode:0o700});
const seed=read(path.join(root,'seed.json'));
assert.deepEqual(Object.keys(seed).sort(),['anchor','network','through']);
assert.equal(seed.network,'testnet-10');assert.equal(seed.through,2);
assert.equal(fs.existsSync('/home/luke'),false,'wallet agent can see host home');
save(path.join(root,'agent-isolation.json'),{privateWalletFiles:1,otherWalletsMounted:false,hostHomeAccessible:false,publicSeedOnly:true,networkAccess:'ordinary TN10 RPC; network privacy not tested',mounts:fs.readFileSync('/proc/mounts','utf8')});
const {rpc,info}=await connect();save(path.join(root,'node.json'),info);
const prover=startWallet(root,0);
let through=seed.through,reserve=outputUtxo(read(path.join(publicDir,number(through)+'.json')),0);
let adopted=[],attempts=[];
function txPath(step){return path.join(publicDir,number(step)+'.json');}
function lastNullifier(raw){
  const p=Buffer.from(raw.payload,'hex'),count=p[11];
  assert.ok(count>0);const start=9+3+32*24+32*(count-1);
  return p.subarray(start,start+32).toString('hex');
}
async function candidate(){
  const scan=await prover.request({through,kind:'scan'});
  assert.equal(scan.rejected_notes.length,0);assert.equal(scan.notes.length,1,'bounded agent expects its single claim');
  const startedAt=new Date().toISOString();
  const v=await prover.request({through,kind:'full',spend_cm:scan.notes[0].cm});
  const step=through+1,p=path.join(prover.out,number(step)+'.json'),raw=read(p);
  transaction(raw).free();
  const input=await exactUtxo(rpc,reserve);assert.ok(input,'reserve changed during proof; fresh recovery cycle required');
  const index=attempts.length;
  const inputs=path.join(logs,`attempt-${index}.inputs.json`);save(inputs,[input]);
  const checked=rust(logs,`attempt-${index}-validate`,['validate',p,inputs]);
  assert.equal(checked.full_hash,v.report.full_hash);
  const result={index,step,raw,startedAt,proofCompletedAt:new Date().toISOString(),report:v.report,inputs:[input]};
  save(path.join(root,`attempt-${index}.transaction.json`),raw);
  save(path.join(root,`attempt-${index}.proof.json`),{startedAt,completedAt:result.proofCompletedAt,report:v.report});
  if(index){
    const old=attempts[0];assert.notEqual(raw.inputs[0].previousOutpoint.transactionId,old.raw.inputs[0].previousOutpoint.transactionId);
    assert.equal(lastNullifier(raw),lastNullifier(old.raw),'retry must spend the same owned claim');
    assert.notEqual(raw.inputs[0].signatureScript.slice(0,260),old.raw.inputs[0].signatureScript.slice(0,260),'proof was not regenerated');
    // Actual new state/body with the old proof must fail native verification.
    const stale=structuredClone(raw);
    stale.inputs[0].signatureScript=old.raw.inputs[0].signatureScript.slice(0,260)+raw.inputs[0].signatureScript.slice(260);
    transaction(stale).free();
    const cp=path.join(logs,'reused-proof.json');save(cp,stale);
    const control=spawnSync(binary,['validate',cp,inputs],{encoding:'utf8'});
    assert.notEqual(control.status,0);assert.match(control.stderr,/Groth16 verification failed/);
    save(path.join(root,'stale-proof-control.json'),{rejected:true,error:control.stderr.trim(),sameEconomicNullifier:true,freshPredecessor:true,freshProof:true});
  }
  attempts.push(result);return result;
}
async function submitOnce(c){
  const tx=transaction(c.raw);
  save(path.join(root,`attempt-${c.index}.submission.json`),{txid:c.raw.id,submittedAt:new Date().toISOString(),predecessor:c.raw.inputs[0].previousOutpoint});
  try{
    const response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});
    assert.equal(response.transactionId,c.raw.id);
    save(path.join(root,`attempt-${c.index}.response.json`),{accepted:true,response});
  }catch(error){
    const outcome=submissionFailure(error,c.index);
    save(path.join(root,`attempt-${c.index}.response.json`),outcome);
    if(outcome.classification.startsWith('unexpected'))throw error;
  }
  finally{tx.free();}
}
async function adopt(row,snapshot){
  const raw=canonicalRpcTx(row.transaction);transaction(raw).free();
  assert.equal(raw.inputs.length,1,'this bounded exit race has no external inputs');
  assert.equal(raw.inputs[0].previousOutpoint.transactionId,reserve.txid);
  assert.equal(raw.inputs[0].previousOutpoint.index,reserve.index);
  const step=through+1,p=txPath(step),context=path.join(logs,`adopt-${step}.inputs.json`);
  save(p,raw);save(context,[reserve]);
  const checked=rust(logs,`adopt-${step}-validate`,['validate',p,context]);
  assert.equal(checked.full_hash,row.transaction.verboseData.hash);
  const mode=Buffer.from(raw.payload,'hex')[8];assert.ok([2,3].includes(mode));
  save(path.join(root,`adopt-${step}.json`),{discoveredAt:snapshot.observedAt,source:'getVirtualChainFromBlockV2 Full; selected by previous reserve outpoint',pages:snapshot.pages,transaction:row.transaction,header:row.header,validation:checked});
  adopted.push(raw.id);through=step;reserve=mode===3?null:outputUtxo(raw,0);
  // The prover verifies the entire append-only history and propagated rules.
  const scan=await prover.request({through,kind:'scan'});
  return {raw,scan};
}
try{
  await prover.ready;
  const initial=await acceptedSnapshot(rpc,seed.anchor);
  for(let step=0;step<=seed.through;step++){
    const raw=read(txPath(step));const row=initial.transactions.find(r=>r.transaction.verboseData?.transactionId===raw.id);
    assert.ok(row,'public seed is not in node accepted history');
    assert.deepEqual(canonicalRpcTx(row.transaction),raw);
    assert.equal(row.transaction.verboseData.hash,read(path.join(publicDir,number(step)+'.metrics.json')).full_hash);
  }
  save(path.join(root,'seed-confirmed.json'),{source:'independent Full accepted-chain query',observedAt:initial.observedAt,transactions:3,pages:initial.pages});
  const first=await candidate();
  save(path.join(root,'ready.json'),{txid:first.raw.id,predecessor:first.raw.inputs[0].previousOutpoint,proofCompletedAt:first.proofCompletedAt});
  while(!fs.existsSync('/barrier/go.json'))await sleep(20);
  await submitOnce(first);
  let pending=first;
  for(;;){
    const snapshot=await acceptedSnapshot(rpc,seed.anchor);
    // Adopted history must still be represented in this accepted-chain view.
    for(const id of adopted)assert.ok(snapshot.transactions.some(r=>r.transaction.verboseData?.transactionId===id),'adopted history reorg: rollback is outside this bounded test');
    const row=successor(snapshot,reserve);
    if(!row){await sleep(1000);continue;}
    const {raw,scan}=await adopt(row,snapshot);
    if(raw.id===pending.raw.id){
      assert.deepEqual(scan.notes,[]);assert.deepEqual(scan.rejected_notes,[]);
      const index=Buffer.from(raw.payload,'hex')[8]===3?0:1;
      const expected=outputUtxo(raw,index);let payout;
      while(!(payout=await exactUtxo(rpc,expected)))await sleep(1000);
      const payoutConfirmedAt=new Date().toISOString();
      await prover.close();
      save(path.join(root,'result.json'),{completedAt:new Date().toISOString(),payoutConfirmedAt,acceptedTxid:raw.id,payout,attempts:attempts.length,rebuilds:attempts.length-1,terminal:reserve===null,ownNotesRemaining:0,adopted,proverClosed:true,scope:'own keys and public artifacts; one correct TN10 node; no general reorg or contention-fairness claim'});
      break;
    }
    assert.ok(reserve,'another exit drained our outstanding claim');
    assert.equal(attempts.length,1,'unexpected further contention outside two-wallet test');
    assert.equal(scan.notes.length,1);
    // No coordinator communication. Public accepted successor drives a new
    // full proof; neither a winner ID nor an alternate transaction is supplied.
    pending=await candidate();await submitOnce(pending);
  }
}catch(error){prover.kill();throw error;}
finally{await rpc.disconnect();}

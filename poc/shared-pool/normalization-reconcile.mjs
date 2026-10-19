// Read-only chain reconciliation. This module has no signing or broadcast call.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {read,save,fileHash,transaction,connect} from './runtime.mjs';
import {acceptedSnapshot,canonicalRpcTx,exactUtxo,outputUtxo,outpoint,sleep} from './chain.mjs';
import {command} from './deposits-common.mjs';

export function hashes(program,transactions,file){
  save(file,transactions);
  const rows=command(program,['hashes',file],path.dirname(file),path.basename(file)+'.hashes');
  assert.equal(rows.length,transactions.length);
  const result=new Map();for(let i=0;i<rows.length;i++){
    assert.equal(rows[i].txid,transactions[i].id);assert.match(rows[i].full_hash,/^[0-9a-f]{64}$/);
    result.set(rows[i].txid,rows[i].full_hash);
  }
  assert.equal(result.size,transactions.length);return result;
}

export async function reconcile(root,hashProgram,recorderFailure=false){
  const identity=read(path.join(root,'identity.json'));
  assert.equal(identity.binarySha256,fileHash(path.join(root,'program')));
  const d=read(path.join(root,'public/descriptor.json')),history=read(path.join(root,'public/history.json'));
  const plan=read(path.join(root,'plan.json')),exits=plan.events.filter(e=>e.kind==='exit');
  const receipts=exits.map((_,i)=>read(path.join(root,`tn10-fresh-${String(i).padStart(4,'0')}/result.json`)));
  for(let i=0;i<receipts.length;i++){
    const r=receipts[i];assert.equal(r.complete,true);assert.equal(r.confirmed,true);assert.equal(r.unchanged_proof_and_authorization,true);
    assert.deepEqual(history[history.length-receipts.length+i],r.transaction);
  }
  const allocation=read(path.join(root,'allocation/0000.json')),all=[allocation,...history];
  for(const raw of all)transaction(raw).free();
  const expected=hashes(hashProgram,all,path.join(root,'reconciliation-transactions.json'));
  for(const r of receipts)assert.equal(expected.get(r.transaction.id),r.native.full_hash);
  assert.equal(expected.get(allocation.id),read(path.join(root,'allocation/0000.metrics.json')).full_hash);
  const checked=command(path.join(root,'program'),['check',path.join(root,'public')],path.join(root,'logs'),'reconciliation-drain');
  assert.equal(checked.drained,true);assert.equal(checked.state.cm_count,checked.state.nf_count);
  const {rpc}=await connect();
  try{
    const wanted=new Map(all.map(t=>[t.id,t]));let accepted;
    for(;;){
      accepted=[];const snapshot=await acceptedSnapshot(rpc,d.start_hash);
      for(const row of snapshot.transactions){const id=row.transaction.verboseData.transactionId;if(wanted.has(id)){
        const raw=canonicalRpcTx(row.transaction);assert.deepEqual(raw,wanted.get(id));
        assert.equal(row.transaction.verboseData.hash,expected.get(id));accepted.push({transaction:raw,fullHash:row.transaction.verboseData.hash,header:row.header});}}
      if(new Set(accepted.map(r=>r.transaction.id)).size===wanted.size)break;await sleep(1000);
    }
    const source=read(path.join(root,'allocation-input.json')),remaining=new Map([[outpoint(source),source]]);let fees=0n;
    for(const raw of all){let ins=0n;
      for(const i of raw.inputs){const key=`${i.previousOutpoint.transactionId}:${i.previousOutpoint.index}`;assert.ok(remaining.has(key));ins+=BigInt(remaining.get(key).amount);remaining.delete(key);}
      let outs=0n;raw.outputs.forEach((_,i)=>{const u=outputUtxo(raw,i);remaining.set(outpoint(u),u);outs+=BigInt(u.amount);});
      assert.ok(ins>outs);fees+=ins-outs;
    }
    for(const r of receipts)assert.ok(await exactUtxo(rpc,r.payout));
    for(const u of remaining.values())assert.ok(await exactUtxo(rpc,u));
    assert.equal([...remaining.values()].reduce((s,u)=>s+BigInt(u.amount),0n)+fees,BigInt(source.amount));
    const contexts=read(path.join(root,'public/contexts.json'));
    for(let i=contexts.length;i<history.length;i++)contexts.push([outputUtxo(history[i-1],0)]);
    save(path.join(root,'chain.json'),{schema:'kpi-h11-native-chain-v1',transactions:history,contexts,minutes:history.map((_,i)=>i-1)});
    save(path.join(root,'chain-confirmed.json'),{exactBodies:all.length,transactions:accepted,
      observerClock:'dependency-order ordinal; actual chain timestamps in headers'});
    const result={complete:true,role:identity.role,network:'testnet-10',binarySha256:identity.binarySha256,sources:identity.sources,
      planSha256:identity.planSha256,checked,confirmedTransactions:all.length,claims:receipts.length,
      allFourWalletsPaid:new Set(exits.map(e=>e.owner)).size===4,proverStoppedBeforeBroadcast:true,
      exitsIndependentOfWalletPKOperator:true,unchangedSelectedProofs:true,sharedFundingAncestry:true,
      postBroadcastRecorderFailure:recorderFailure,reconciliationReadOnly:true,
      hashToolSha256:fileHash(hashProgram),recorderSha256:fileHash(fileURLToPath(import.meta.url)),
      totalFeeSompi:fees.toString(),exitReceipts:receipts,finalOrdinaryOutputs:[...remaining.values()],
      scope:'Four synthetic wallets on one host; mechanism validation, not anonymity or network privacy'};
    save(path.join(root,'result.json'),result);return result;
  }finally{await rpc.disconnect();}
}

if(process.argv[1]===fileURLToPath(import.meta.url)){
  const [root,program]=process.argv.slice(2);const r=await reconcile(path.resolve(root),path.resolve(program),true);
  console.log(JSON.stringify({reconciled:true,broadcast:false,confirmedTransactions:r.confirmedTransactions,totalFeeSompi:r.totalFeeSompi}));
}

#!/usr/bin/env node
// Native TN10 rehearsal/trial after the offline gate. Every invocation creates
// a fresh identity; write-ahead submission records forbid silent rebroadcast.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {read,save,fileHash,transaction,connect,utxos,fundingDir,rpcUrl} from './runtime.mjs';
import {confirm,exactUtxo,outputUtxo,acceptedSnapshot,canonicalRpcTx,sleep} from './chain.mjs';
import {mkdir,command,depositBinary,pinSources,replace} from './deposits-common.mjs';
import {create,join,exitClient} from './deposits.mjs';

const [role,paramsArg,baseArg,gateArg,rehearsalArg]=process.argv.slice(2);
assert.ok(['rehearsal','trial'].includes(role));
const params=path.resolve(paramsArg),base=path.resolve(baseArg),gate=read(path.join(path.resolve(gateArg),'offline-result.json'));
assert.equal(gate.offline_pass,true);assert.equal(gate.binarySha256,fileHash(depositBinary));assert.deepEqual(gate.sources,pinSources());
if(role==='trial'){
  const rehearsal=read(path.join(path.resolve(rehearsalArg),'result.json'));
  assert.equal(rehearsal.complete,true);assert.equal(rehearsal.role,'rehearsal');
  assert.equal(rehearsal.binarySha256,fileHash(depositBinary));assert.deepEqual(rehearsal.sources,pinSources());
}
const root=create(params,base,role),pub=path.join(root,'public'),logs=path.join(root,'logs');
console.log(JSON.stringify({stage:'fresh-live-identity',role,root}));
const {rpc,info}=await connect();
const submitted=[];
async function submit(raw,out,inputs){
  for(const input of inputs)assert.ok(await exactUtxo(rpc,input),'input unavailable before first submission');
  const tx=transaction(raw);save(path.join(out,'submission.json'),{transactionId:raw.id,at:new Date().toISOString()});
  try{
    const response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});assert.equal(response.transactionId,raw.id);
    save(path.join(out,'response.json'),response);
  }catch(error){save(path.join(out,'failure.json'),{error:String(error),noRebroadcast:true});throw error;}
  finally{tx.free();}
  const outputs=await confirm(rpc,raw);save(path.join(out,'confirmed.json'),{outputs,at:new Date().toISOString()});
  submitted.push(raw);return outputs;
}
try{
  save(path.join(root,'node.json'),{rpcUrl,info});
  const anchor=(await rpc.getBlockDagInfo()).sink;
  const available=(await utxos(rpc,read(path.join(fundingDir,'funding.json')).address)).filter(u=>!u.is_coinbase&&BigInt(u.amount)>4_102_000_000n);
  available.sort((a,b)=>BigInt(a.amount)>BigInt(b.amount)?-1:1);assert.ok(available.length,'no owned ordinary input large enough for four contributions');
  const source=available[0];save(path.join(root,'allocation-input.json'),source);
  const allocation=path.join(root,'allocation');mkdir(allocation);
  command(depositBinary,['allocate',root,path.join(root,'allocation-input.json'),fundingDir,allocation],logs,'allocation');
  await submit(read(path.join(allocation,'0000.json')),allocation,[source]);
  const sourcesFile=path.join(allocation,'sources.json');
  command(depositBinary,['genesis',root,sourcesFile,anchor],logs,'genesis');
  const genesisOut=path.join(root,'genesis-live');mkdir(genesisOut);
  await submit(read(path.join(pub,'0000.json')),genesisOut,[read(sourcesFile)[0]]);
  for(let index=0;index<4;index++)await join(root,params,index,async(raw,out)=>{
    await submit(raw,out,read(path.join(out,'admission.inputs.json')));
  });
  save(path.join(root,'prepared.json'),{complete:true,allFourProversExited:true,preparedProofs:8,at:new Date().toISOString()});
  const wallets=[];
  for(const index of [3,2,1,0]){
    const run=path.join(root,`exit-wallet-${index}`);
    const result=await exitClient(root,pub,path.join(root,`prover-${index}/saved.json`),run,'tn10');
    assert.equal(result.complete,true);for(const e of result.exits){assert.equal(e.confirmed,true);assert.ok(await exactUtxo(rpc,e.payout));}
    const h=read(path.join(pub,'history.json'));h.push(...result.exits.map(e=>e.transaction));replace(path.join(pub,'history.json'),h);
    wallets.push({wallet:index,...result});console.log(JSON.stringify({stage:'independent-wallet-paid',role,wallet:index,notes:2}));
  }
  const checked=command(depositBinary,['check',pub],logs,'final-check');assert.equal(checked.drained,true);assert.equal(checked.transactions,13);
  const history=read(path.join(pub,'history.json'));const all=[read(path.join(allocation,'0000.json')),...history];
  const wanted=new Map(all.map(t=>[t.id,t]));let matches;
  const hashes=new Map();
  for(const dir of [allocation,pub,...[0,1,2,3].map(i=>path.join(root,`prover-${i}`))]){
    const m=read(path.join(dir,'0000.metrics.json'));hashes.set(m.txid,m.full_hash);
  }
  for(const w of wallets)for(const e of w.exits)hashes.set(e.transaction.id,e.native.full_hash);
  assert.equal(hashes.size,14);
  for(;;){
    const snapshot=await acceptedSnapshot(rpc,anchor);matches=[];
    for(const row of snapshot.transactions){const id=row.transaction.verboseData.transactionId;if(wanted.has(id)){
      const actual=canonicalRpcTx(row.transaction);assert.deepEqual(actual,wanted.get(id));
      assert.equal(row.transaction.verboseData.hash,hashes.get(id),'accepted full transaction hash differs');
      matches.push({transaction:actual,fullHash:row.transaction.verboseData.hash,header:row.header});}}
    if(new Set(matches.map(x=>x.transaction.id)).size===14)break;await sleep(1000);
  }
  // Independently reconcile all ordinary inputs/outputs, including preparation
  // and unused ordinary change. No owner labels are used in this accounting.
  const remaining=new Map([[`${source.txid}:${source.index}`,source]]);let totalFees=0n;
  for(const tx of all){let ins=0n;for(const i of tx.inputs){const p=`${i.previousOutpoint.transactionId}:${i.previousOutpoint.index}`;
    assert.ok(remaining.has(p),'duplicate/missing funded input');ins+=BigInt(remaining.get(p).amount);remaining.delete(p);}
    let outs=0n;tx.outputs.forEach((_,j)=>{const u=outputUtxo(tx,j);remaining.set(`${u.txid}:${u.index}`,u);outs+=BigInt(u.amount);});
    assert.ok(ins>outs);totalFees+=ins-outs;}
  for(const u of remaining.values())assert.ok(await exactUtxo(rpc,u));
  assert.equal([...remaining.values()].reduce((s,u)=>s+BigInt(u.amount),0n)+totalFees,BigInt(source.amount));
  save(path.join(root,'chain-confirmed.json'),{exactBodies:14,transactions:matches});
  const result={complete:true,role,network:'testnet-10',binarySha256:fileHash(depositBinary),sources:pinSources(),
    checked,wallets,confirmedTransactions:14,poolSequenceTransactions:13,ordinaryPreparationTransactions:1,
    allFourProversStopped:true,operatorHelp:false,totalFeeSompi:totalFees.toString(),finalOrdinaryOutputs:[...remaining.values()],
    sharedTestFundingAncestry:true,completedAt:new Date().toISOString(),scope:'Four isolated synthetic wallets; not anonymity, mainnet safety or general contention liveness'};
  save(path.join(root,'result.json'),result);console.log(JSON.stringify({stage:'live-complete',role,root,totalFeeSompi:result.totalFeeSompi}));
}finally{await rpc.disconnect();}

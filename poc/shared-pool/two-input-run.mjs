#!/usr/bin/env node
// Fresh identities; all proving completes before reserve funding. Each live
// identity broadcasts once. Read-only reconciliation can be repeated separately.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {read,save,fileHash,transaction,connect,utxos,fundingDir,sdkPath} from './runtime.mjs';
import {confirm,exactUtxo,outputUtxo,acceptedSnapshot,canonicalRpcTx,sleep,outpoint} from './chain.mjs';
import {mkdir,command,sandbox,audit,replace} from './deposits-common.mjs';
import {hashes} from './normalization-reconcile.mjs';

const here=path.dirname(fileURLToPath(import.meta.url));
const binary=process.env.KPI_TWO_INPUT_BINARY??'/home/luke/projects/kaspa-privacy-self-funded/poc/self-funded/target/release/kpi-two-input-live';
const files=['two-input-run.mjs','two-input-chain.mjs','two-input-client.mjs','src/two_input/live.rs','src/two_input/harness.rs',
  'src/two_input/mod.rs','src/two_input/circuit.rs','src/two_input/covenant.rs','src/two_input/tree.rs',
  'runtime.mjs','chain.mjs','deposits-common.mjs','normalization-reconcile.mjs','src/native.rs','src/protocol.rs','Cargo.toml','Cargo.lock'];
const pins=()=>Object.fromEntries(files.map(f=>[f,fileHash(path.join(here,f))]));
function create(role,params,base){
  mkdir(base);const root=path.join(base,role+'-'+crypto.randomUUID());mkdir(root);mkdir(path.join(root,'logs'));
  fs.copyFileSync(binary,path.join(root,'program'),fs.constants.COPYFILE_EXCL);
  const started=Date.now();const init=command(path.join(root,'program'),['new',params,root],path.join(root,'logs'),'init');
  save(path.join(root,'identity.json'),{role,createdAt:new Date().toISOString(),freshUnfundedMs:Date.now()-started,
    binarySha256:fileHash(binary),sources:pins(),...init});
  console.log(JSON.stringify({stage:'fresh-unfunded-identity',root,role,elapsedMs:Date.now()-started}));return root;
}
function client(root,wallet,mode,history,label){
  const run=path.join(root,`${label}-wallet-${wallet}`);mkdir(run);save(path.join(run,'config.json'),{mode});
  const args=[...sandbox(),...(mode==='tn10'?['--share-net']:[]),
    '--ro-bind',path.join(root,'program'),'/program','--ro-bind',process.execPath,'/node',
    '--ro-bind',path.dirname(sdkPath),'/sdk','--setenv','KPI_SDK_PATH','/sdk/kaspa.js',
    '--ro-bind',path.join(root,`capabilities/wallet-${wallet}.json`),'/saved.json',
    '--ro-bind',path.join(root,'public/descriptor.json'),'/source/descriptor.json',
    '--ro-bind',path.join(root,'public/vk.bin'),'/source/vk.bin','--bind',run,'/run','--dir','/software'];
  for(const f of ['two-input-client.mjs','two-input-chain.mjs','runtime.mjs','chain.mjs','deposits-common.mjs'])args.push('--ro-bind',path.join(here,f),'/software/'+f);
  if(mode==='offline'){save(path.join(run,'accepted.json'),history);args.push('--ro-bind',path.join(run,'accepted.json'),'/accepted/history.json');}
  else args.push('--setenv','KPI_TN10_RPC',process.env.KPI_TN10_RPC??'ws://10.0.3.26:17210');
  audit(args,path.join(run,'isolation.json'),mode==='tn10');
  const stdout=fs.openSync(path.join(run,'stdout.log'),'wx',0o600),stderr=fs.openSync(path.join(run,'stderr.log'),'wx',0o600);
  let p;try{p=spawnSync('bwrap',[...args,'--','/node','/software/two-input-client.mjs','/run'],{stdio:['ignore',stdout,stderr]});}
  finally{fs.closeSync(stdout);fs.closeSync(stderr);}
  save(path.join(run,'process-exit.json'),{code:p.status,at:new Date().toISOString()});
  assert.equal(p.status,0,fs.readFileSync(path.join(run,'stderr.log'),'utf8'));return read(path.join(run,'result.json'));
}
function check(root,history,label){
  replace(path.join(root,'public/history.json'),history);
  const r=command(path.join(root,'program'),['check',path.join(root,'public')],path.join(root,'logs'),label);
  assert.equal(r.drained,true);assert.equal(r.transactions,14);return r;
}
function qualify(root){
  const evaluation='qualification-'+crypto.randomUUID(),evaluationDir=path.join(root,evaluation);mkdir(evaluationDir);
  const prefix=read(path.join(root,'public/history.json'));assert.equal(prefix.length,8);
  const wallets=[];let history=[...prefix];
  for(const wallet of [1,2,3,0]){const r=client(root,wallet,'offline',history,evaluation);wallets.push(r);history.push(...r.receipts.map(e=>e.transaction));}
  const checked=check(root,history,evaluation+'-final');
  const controls=[];
  const reject=(name,h,d,savedChange)=>{
    const pub=path.join(evaluationDir,'negative-'+name);mkdir(pub);mkdir(path.join(pub,'out'));
    // Descriptor pins cover exact bytes. Preserve them unless substitution is
    // the control, or hash mismatch would mask every history/proof rejection.
    if(d)save(path.join(pub,'descriptor.json'),d);
    else fs.copyFileSync(path.join(root,'public/descriptor.json'),path.join(pub,'descriptor.json'),fs.constants.COPYFILE_EXCL);
    fs.copyFileSync(path.join(root,'public/vk.bin'),path.join(pub,'vk.bin'));
    save(path.join(pub,'history.json'),h);
    const saved=read(path.join(root,'capabilities/wallet-0.json'));if(savedChange)savedChange(saved);
    save(path.join(pub,'saved.json'),saved);
    const p=spawnSync(path.join(root,'program'),['exit',pub,path.join(pub,'saved.json'),'0',path.join(pub,'out')],{encoding:'utf8'});
    assert.notEqual(p.status,0,name);
    const causes={'missing-history':/missing public history/,'missing-middle':/reserve lineage discontinuity/,
      'wrong-descriptor':/saved descriptor identity/,'inflated-reserve':/canonical\/ID mismatch/,
      'corrupt-saved-proof':/script|proof|Groth16|compressed|serialization/i,'second-spend':/drained pool/};
    assert.match(p.stderr,causes[name],name+' must reach its intended check');controls.push({name,rejected:true,error:p.stderr.trim()});
  };
  reject('missing-history',[],null);
  reject('missing-middle',[prefix[0],...prefix.slice(2)],null);
  const wrong=structuredClone(read(path.join(root,'public/descriptor.json')));wrong.network='mainnet';reject('wrong-descriptor',prefix,wrong);
  const inflated=structuredClone(prefix);inflated.at(-1).outputs[0].value=String(BigInt(inflated.at(-1).outputs[0].value)+1n);reject('inflated-reserve',inflated,null);
  reject('corrupt-saved-proof',prefix,null,s=>{const b=Buffer.from(s.bundles[0].proof,'hex');b[0]^=1;s.bundles[0].proof=b.toString('hex');});
  reject('second-spend',history,null);
  replace(path.join(root,'public/history.json'),prefix);
  const result={offline_pass:true,binarySha256:fileHash(path.join(root,'program')),sources:pins(),wallets,checked,controls,
    fourWalletsPaid:true,sixSavedProofsUnchanged:true,noWalletOrPKInExitProcesses:true};
  save(path.join(evaluationDir,'result.json'),result);replace(path.join(root,'offline-result.json'),result);
  console.log(JSON.stringify({stage:'offline-adapter-passed',root,wallets:4,proofs:6}));return result;
}
async function reconcile(root){
  const id=read(path.join(root,'identity.json')),program=path.join(root,'program');assert.equal(id.binarySha256,fileHash(program));
  // A recorder failure must be recoverable without replaying any broadcast.
  // Keep each read-only attempt, including incomplete ones, in its own folder.
  const recording=path.join(root,'reconciliation-'+crypto.randomUUID());mkdir(recording);
  const d=read(path.join(root,'public/descriptor.json')),history=read(path.join(root,'public/history.json'));
  const wallets=[1,2,3,0].map(w=>({wallet:w,...read(path.join(root,`tn10-wallet-${w}/result.json`))}));
  const receipts=wallets.flatMap(w=>w.receipts);assert.equal(receipts.length,6);
  for(const r of receipts){assert.equal(r.confirmed,true);assert.equal(r.unchanged_proof_and_authorization,true);}
  const checked=command(program,['check',path.join(root,'public')],recording,'live-final');assert.equal(checked.drained,true);assert.equal(checked.transactions,14);
  const all=[read(path.join(root,'allocation/0000.json')),...history];assert.equal(all.length,15);
  const expected=hashes(program,all,path.join(recording,'transactions.json'));
  const {rpc}=await connect();try{
    const wanted=new Map(all.map(t=>[t.id,t]));let matches;
    for(;;){matches=[];const snap=await acceptedSnapshot(rpc,d.start_hash);
      for(const row of snap.transactions){const txid=row.transaction.verboseData.transactionId;if(wanted.has(txid)){
        const raw=canonicalRpcTx(row.transaction);assert.deepEqual(raw,wanted.get(txid));assert.equal(row.transaction.verboseData.hash,expected.get(txid));
        matches.push({transaction:raw,fullHash:row.transaction.verboseData.hash,header:row.header});}}
      if(new Set(matches.map(m=>m.transaction.id)).size===15)break;await sleep(1000);
    }
    const source=read(path.join(root,'allocation-input.json')),remaining=new Map([[outpoint(source),source]]);let fees=0n;
    for(const tx of all){let ins=0n,outs=0n;for(const i of tx.inputs){const k=`${i.previousOutpoint.transactionId}:${i.previousOutpoint.index}`;assert.ok(remaining.has(k));ins+=BigInt(remaining.get(k).amount);remaining.delete(k);}
      tx.outputs.forEach((_,i)=>{const u=outputUtxo(tx,i);remaining.set(outpoint(u),u);outs+=BigInt(u.amount);});assert.ok(ins>outs);fees+=ins-outs;}
    for(const u of remaining.values())assert.ok(await exactUtxo(rpc,u));
    assert.equal([...remaining.values()].reduce((s,u)=>s+BigInt(u.amount),0n)+fees,BigInt(source.amount));
    const partial=outputUtxo(history[6],1);assert.equal(partial.amount,'211000000');assert.ok(await exactUtxo(rpc,partial));
    const chain={exactBodies:15,transactions:matches};save(path.join(recording,'chain-confirmed.json'),chain);
    const result={complete:true,role:id.role,network:'testnet-10',binarySha256:id.binarySha256,sources:id.sources,checked,
      wallets,confirmedTransactions:15,poolOperations:13,savedExits:6,allFourWalletsPaid:true,privateChangeSpendable:true,
      partialWithdrawalSompi:partial.amount,partialChangeRespent:true,allProofAuthBytesUnchanged:true,
      originalProverStoppedBeforeBroadcast:true,currentStateFromAcceptedRPC:true,operatorHelpForExits:false,
      totalFeeSompi:fees.toString(),poolFeeSompi:'520000000',remainingReserveSompi:'0',finalOrdinaryOutputs:[...remaining.values()],
      sharedFundingAncestry:true,completedAt:new Date().toISOString(),scope:'Four isolated wallets on one host and one RPC. Precomputed proofs. No anonymity or general recovery guarantee.'};
    save(path.join(recording,'result.json'),result);replace(path.join(root,'chain-confirmed.json'),chain);replace(path.join(root,'result.json'),result);
    console.log(JSON.stringify({stage:'live-complete',root,role:id.role,totalFeeSompi:result.totalFeeSompi}));return result;
  }finally{await rpc.disconnect();}
}
async function main(){
  const [role,paramsArg,baseArg,gateArg,rehearsalArg]=process.argv.slice(2);
  if(role==='reconcile'){await reconcile(path.resolve(paramsArg));return;}
  if(role==='qualify'){qualify(path.resolve(paramsArg));return;}
  assert.ok(['new','offline','rehearsal','trial'].includes(role));
  const params=path.resolve(paramsArg),base=path.resolve(baseArg);
  if(['rehearsal','trial'].includes(role)){
    const gate=read(path.join(path.resolve(gateArg),'offline-result.json'));assert.equal(gate.offline_pass,true);assert.equal(gate.binarySha256,fileHash(binary));assert.deepEqual(gate.sources,pins());
    if(role==='trial'){const r=read(path.join(path.resolve(rehearsalArg),'result.json'));assert.equal(r.complete,true);assert.equal(r.role,'rehearsal');assert.equal(r.binarySha256,fileHash(binary));assert.deepEqual(r.sources,pins());}
  }
  const root=create(role,params,base);if(role==='new')return;
  const {rpc,info}=await connect();try{
    save(path.join(root,'node.json'),{network:info.networkId,synced:info.isSynced,version:info.serverVersion});
    const anchor=(await rpc.getBlockDagInfo()).sink;
    const available=(await utxos(rpc,read(path.join(fundingDir,'funding.json')).address)).filter(u=>!u.is_coinbase);
    available.sort((a,b)=>BigInt(a.amount)>BigInt(b.amount)?-1:1);
    assert.ok(available.length,'ordinary test funding source absent');
    const source=structuredClone(available[0]);
    if(role==='offline'){source.txid=crypto.randomBytes(32).toString('hex');source.amount='10000000000';}
    else assert.ok(BigInt(source.amount)>5_701_000_000n,'consolidate owned ordinary outputs first');
    save(path.join(root,'allocation-input.json'),source);const allocation=path.join(root,'allocation');mkdir(allocation);
    command(path.join(root,'program'),['allocate',root,path.join(root,'allocation-input.json'),fundingDir,allocation],path.join(root,'logs'),'allocation');
    console.log(JSON.stringify({stage:'preparing-genuine-proofs',root}));
    command(path.join(root,'program'),['prepare',params,root,path.join(allocation,'sources.json'),anchor],path.join(root,'logs'),'prepare');
    save(path.join(root,'prover-stopped.json'),{stopped:true,at:new Date().toISOString()});
    console.log(JSON.stringify({stage:'proofs-ready-prover-stopped',root}));
    if(role==='offline'){qualify(root);return;}
    async function submit(raw,inputs,label){
      const dir=path.join(root,label);mkdir(dir);for(const u of inputs)assert.ok(await exactUtxo(rpc,u));
      const tx=transaction(raw);save(path.join(dir,'submission.json'),{transactionId:raw.id,at:new Date().toISOString(),noRebroadcast:true});
      try{const response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});assert.equal(response.transactionId,raw.id);save(path.join(dir,'response.json'),response);}
      finally{tx.free();}
      save(path.join(dir,'confirmed.json'),{outputs:await confirm(rpc,raw),at:new Date().toISOString()});
    }
    await submit(read(path.join(allocation,'0000.json')),[source],'allocation-live');
    const history=read(path.join(root,'public/history.json')),sources=read(path.join(allocation,'sources.json'));
    for(let i=0;i<history.length;i++){
      const raw=history[i],ctx=i===0?[sources[0]]:[outputUtxo(history[i-1],0)];
      if(raw.inputs.length===2)ctx.push(sources.find(u=>u.txid===raw.inputs[1].previousOutpoint.transactionId&&u.index===raw.inputs[1].previousOutpoint.index));
      assert.ok(ctx.every(Boolean));await submit(raw,ctx,'prefix-'+i);
    }
    console.log(JSON.stringify({stage:'payment-and-partial-withdrawal-confirmed',root}));
    for(const wallet of [1,2,3,0]){
      const r=client(root,wallet,'tn10',null,'tn10');history.push(...r.receipts.map(e=>e.transaction));replace(path.join(root,'public/history.json'),history);
      console.log(JSON.stringify({stage:'independent-wallet-paid',root,wallet,claims:r.receipts.length}));
    }
    await reconcile(root);
  }finally{await rpc.disconnect();}
}
await main();

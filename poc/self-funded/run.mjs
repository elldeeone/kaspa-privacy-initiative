#!/usr/bin/env node
// TN10 only. Preparation and broadcasting are separate commands. Each intended
// submission is recorded durably before the RPC call and is never retried here.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';

const here=path.dirname(fileURLToPath(import.meta.url));
const binary=path.join(here,'target/release/kpi-self-funded');
const sdkPath=process.env.KPI_SDK_PATH ?? '/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa/kaspa.js';
const k=createRequire(import.meta.url)(sdkPath);
const rpcUrl=process.env.KPI_TN10_RPC ?? 'ws://10.0.3.26:17210';
const fundingDir=process.env.KPI_FUNDING_DIR ?? '/home/luke/.local/share/kpi-test-wallets/20261019-self-funded-fc9f7ff0-1860-4c81-977b-3448e06079ae';
const stringify=v=>JSON.stringify(v,(_,x)=>typeof x==='bigint'?x.toString():x,2);
const read=p=>JSON.parse(fs.readFileSync(p,'utf8'));
function syncDirectory(p){const fd=fs.openSync(p,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function save(p,v){const fd=fs.openSync(p,'wx',0o600);try{fs.writeFileSync(fd,stringify(v)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}syncDirectory(path.dirname(p));}
const labels=['funding','payment','bob-exit','alice-exit','low-fee','alternative'];
const fileHash=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
function spk(s){return s.version.toString(16).padStart(4,'0')+s.script;}
function canonical(tx){
  tx.finalize();
  return {version:tx.version,id:tx.id,
    inputs:tx.inputs.map(i=>({previousOutpoint:{transactionId:i.previousOutpoint.transactionId,index:i.previousOutpoint.index},signatureScript:i.signatureScript??'',sequence:i.sequence.toString(),sigOpCount:i.sigOpCount,computeBudget:i.computeBudget})),
    outputs:tx.outputs.map(o=>({value:o.value.toString(),scriptPublicKey:spk(o.scriptPublicKey),covenant:o.covenant?{authorizingInput:o.covenant.authorizingInput,covenantId:o.covenant.covenantId.toString()}:null})),
    lockTime:tx.lockTime.toString(),subnetworkId:tx.subnetworkId,gas:tx.gas.toString(),payload:tx.payload,storageMass:tx.storageMass.toString()};
}
function transaction(raw){
  const outputs=raw.outputs.map(o=>{assert.equal(o.covenant,null);const out={...o,value:BigInt(o.value)};delete out.covenant;return out;});
  const tx=new k.Transaction({...raw,inputs:raw.inputs.map(i=>({...i,sequence:BigInt(i.sequence)})),outputs,lockTime:BigInt(raw.lockTime),gas:BigInt(raw.gas),storageMass:BigInt(raw.storageMass)});
  assert.deepEqual(canonical(tx),raw,'SDK changed exact native transaction');return tx;
}
function entry(row){const u=row.entry??row;assert.equal(u.covenantId??null,null,'unexpected covenant metadata');return {txid:u.outpoint.transactionId,index:u.outpoint.index,amount:u.amount.toString(),spk:spk(u.scriptPublicKey),daa:u.blockDaaScore.toString(),is_coinbase:u.isCoinbase};}
function address(script){const a=k.addressFromScriptPublicKey(script,'testnet-10');assert.ok(a,'unsupported script address');try{return a.toString();}finally{a.free();}}
function rust(logdir,label,args){
  const out=fs.openSync(path.join(logdir,label+'.stdout.json'),'wx',0o600),err=fs.openSync(path.join(logdir,label+'.stderr.log'),'wx',0o600);
  console.log(stringify({stage:label,started:new Date().toISOString()}));
  let result;try{result=spawnSync('/usr/bin/time',['-v','-o',path.join(logdir,label+'.resources.txt'),binary,...args],{stdio:['ignore',out,err],env:{...process.env,RAYON_NUM_THREADS:'4'}});}finally{fs.closeSync(out);fs.closeSync(err);}
  assert.equal(result.status,0,`${label} failed; inspect ${logdir}/${label}.stderr.log`);
  const report=read(path.join(logdir,label+'.stdout.json'));console.log(stringify(report));return report;
}
async function connect(){const rpc=new k.RpcClient({url:rpcUrl,networkId:'testnet-10'});await rpc.connect({timeoutDuration:15000});const info=await rpc.getServerInfo();assert.equal(info.networkId,'testnet-10');assert.equal(info.isSynced,true);return {rpc,info};}
async function utxos(rpc,addr){return (await rpc.getUtxosByAddresses({addresses:[addr]})).entries.map(entry);}
function isolated(root,who,prior,label){
  const output=path.join(root,who+'-isolated');
  const result=spawnSync('python3',[path.join(here,'isolate-exit.py'),binary,path.join(root,'public'),path.join(root,who,'wallet.json'),prior,label,output],{stdio:'inherit'});
  assert.equal(result.status,0,`${who} isolated exit failed`);
  for(const suffix of ['.json','.metrics.json']) fs.copyFileSync(path.join(output,label+suffix),path.join(root,'public',label+suffix),fs.constants.COPYFILE_EXCL);
  return read(path.join(output,label+'.metrics.json'));
}
async function prepare(params,base){
  fs.mkdirSync(base,{recursive:true,mode:0o700});const root=path.join(base,new Date().toISOString().replaceAll(':','-')+'-'+crypto.randomUUID());
  // Fresh identity creation itself is a single native command; no funding or RPC.
  const initialized=spawnSync(binary,['init',params,root],{encoding:'utf8'});assert.equal(initialized.status,0,initialized.stderr);console.log(initialized.stdout);
  const logs=path.join(root,'logs');fs.mkdirSync(logs,{mode:0o700});
  const {rpc,info}=await connect();
  try{
    const wallet=read(path.join(fundingDir,'funding.json'));assert.equal(wallet.network,'testnet-10');
    const candidates=(await utxos(rpc,wallet.address)).filter(u=>!u.is_coinbase&&BigInt(u.amount)>1_100_000_000n).sort((a,b)=>BigInt(a.amount)>BigInt(b.amount)?-1:1);
    assert.ok(candidates.length,'no sufficient ordinary TN10 funding UTXO');
    save(path.join(root,'funding-input.json'),candidates[0]);save(path.join(root,'node-before.json'),{endpoint:rpcUrl,info,feeEstimate:await rpc.getFeeEstimate()});
    rust(logs,'fund',['fund',root,path.join(root,'funding-input.json'),path.join(fundingDir,'funding.key')]);
  }finally{await rpc.disconnect();}
  rust(logs,'payment',['pay',root]);
  console.log(stringify({stage:'bob-exit-isolated'}));isolated(root,'bob','payment','bob-exit');
  console.log(stringify({stage:'alice-terminal-exit-isolated'}));isolated(root,'alice','bob-exit','alice-exit');
  rust(logs,'low-fee',['pay-low-fee',root]);rust(logs,'alternative',['pay-alternative',root]);
  rust(logs,'native-controls',['controls',path.join(root,'public')]);
  const transactions={};for(const label of labels){const p=path.join(root,'public',label+'.json');transaction(read(p)).free();transactions[label]=fileHash(p);}
  const sources=Object.fromEntries(['Cargo.toml','Cargo.lock','src/protocol.rs','src/circuit.rs','src/covenant.rs','src/native.rs','src/main.rs','src/lib.rs','run.mjs','isolate-exit.py'].map(name=>[name,crypto.createHash('sha256').update(fs.readFileSync(path.join(here,name))).digest('hex')]));
  save(path.join(root,'prepared.json'),{root,created:new Date().toISOString(),sdkRoundTrips:6,completeSequenceLocallyValidated:true,broadcast:false,binarySha256:fileHash(binary),sources,transactions});
  console.log(stringify({prepared:root,broadcast:false}));
}
async function exactUtxo(rpc,expected){
  const rows=await utxos(rpc,address(expected.spk));const found=rows.find(u=>u.txid===expected.txid&&u.index===expected.index);
  if(found){assert.equal(found.amount,expected.amount);assert.equal(found.spk,expected.spk);assert.equal(found.is_coinbase,false);}return found;
}
function expectedOutput(raw,index){const o=raw.outputs[index];return {txid:raw.id,index,amount:o.value,spk:o.scriptPublicKey,daa:'0',is_coinbase:false};}
async function confirm(rpc,raw){
  for(;;){const outputs=await Promise.all(raw.outputs.map((_,i)=>exactUtxo(rpc,expectedOutput(raw,i))));if(outputs.every(Boolean))return outputs;await new Promise(resolve=>setTimeout(resolve,2000));}
}
async function submitOnce(rpc,root,label,negative=false){
  const raw=read(path.join(root,'public',label+'.json'));const tx=transaction(raw);
  save(path.join(root,'live',label+'.submission.json'),{txid:raw.id,negative,submittedAt:new Date().toISOString(),rawSha256:crypto.createHash('sha256').update(stringify(raw)).digest('hex')});
  let response;try{response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});}catch(error){
    const message=String(error);save(path.join(root,'live',label+'.response.json'),{accepted:false,error:message});
    if(!negative)throw error;
    if(label==='low-fee') assert.match(message,/fee/i,'low-fee control rejected for a different reason');
    if(label==='alternative') assert.match(message,/spent|missing|orphan|outpoint|double/i,'spent-input control rejected for a different reason');
    console.log(stringify({stage:label,rejected:true,reason:message}));return;
  }finally{tx.free();}
  save(path.join(root,'live',label+'.response.json'),{accepted:true,response});
  assert.equal(negative,false,'negative transaction unexpectedly accepted: stop this trial');
  assert.equal(response.transactionId,raw.id);
  const outputs=await confirm(rpc,raw);save(path.join(root,'live',label+'.confirmed.json'),{txid:raw.id,observedAt:new Date().toISOString(),outputs});
  console.log(stringify({stage:label,confirmed:true,txid:raw.id}));
}
async function live(root){
  const prepared=read(path.join(root,'prepared.json'));assert.equal(prepared.broadcast,false);
  assert.equal(fileHash(binary),prepared.binarySha256,'binary changed after preparation');
  for(const label of labels){const p=path.join(root,'public',label+'.json');assert.equal(fileHash(p),prepared.transactions[label],'prepared transaction changed: '+label);transaction(read(p)).free();}
  fs.mkdirSync(path.join(root,'live'),{mode:0o700}); // existing directory rejects reruns
  syncDirectory(root);
  const {rpc,info}=await connect();
  try{
    save(path.join(root,'live','node.json'),{endpoint:rpcUrl,info,feeEstimate:await rpc.getFeeEstimate()});
    for(const label of ['funding','payment','bob-exit','alice-exit']){
      const raw=read(path.join(root,'public',label+'.json'));
      const prior=label==='funding'?read(path.join(root,'funding-input.json')):expectedOutput(read(path.join(root,'public',({'payment':'funding','bob-exit':'payment','alice-exit':'bob-exit'})[label]+'.json')),0);
      const actual=await exactUtxo(rpc,prior);assert.ok(actual,'canonical predecessor is not currently unspent');
      const context=path.join(root,'live',label+'.input.json');save(context,actual);
      rust(path.join(root,'live'),label+'-validation',['validate',path.join(root,'public',label+'.json'),context]);
      if(label==='payment') await submitOnce(rpc,root,'low-fee',true);
      await submitOnce(rpc,root,label);
      if(label==='payment') await submitOnce(rpc,root,'alternative',true);
    }
    const previous=expectedOutput(read(path.join(root,'public','bob-exit.json')),0);
    assert.equal(await exactUtxo(rpc,previous),undefined,'terminal reserve remains unspent');
    const fees=['funding','payment','bob-exit','alice-exit'].map(label=>BigInt(read(path.join(root,'public',label+'.metrics.json')).metrics.fee_sompi));
    const summary={completedAt:new Date().toISOString(),network:'testnet-10',confirmed:['funding','payment','bob-exit','alice-exit'],feeSompi:fees.reduce((a,b)=>a+b,0n),terminalReserveSpent:true,bobPrivateInputs:1,bobNetworkIsolatedDuringProving:true,scope:'funded TN10 mechanical trial; not anonymity, cryptographic audit or mainnet evidence'};
    save(path.join(root,'live','result.json'),summary);console.log(stringify(summary));
  }finally{await rpc.disconnect();}
}
const [command,a,b]=process.argv.slice(2);
try{if(command==='prepare'&&a&&b)await prepare(path.resolve(a),path.resolve(b));else if(command==='live'&&a)await live(path.resolve(a));else throw Error('usage: node run.mjs prepare PARAMS TRIAL_BASE | live TRIAL');}
catch(error){console.error(String(error));process.exitCode=1;}

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {Readable} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {fileURLToPath} from 'node:url';
import {read,save,binary,number,transaction} from './runtime.mjs';
import {acceptedSnapshot,canonicalRpcTx,outputUtxo,successor,exactUtxo,sleep} from './chain.mjs';

export const recoveryBinary=process.env.KPI_RECOVERY_BINARY??path.join(path.dirname(binary),'kpi-recovery');
export const mkdir=p=>fs.mkdirSync(p,{recursive:true,mode:0o700});
export const copy=(a,b)=>fs.copyFileSync(a,b,fs.constants.COPYFILE_EXCL);
export async function digest(file){
  const h=crypto.createHash('sha256');
  for await(const chunk of fs.createReadStream(file))h.update(chunk);
  return h.digest('hex');
}
export function recovery(logdir,label,args){
  const out=fs.openSync(path.join(logdir,label+'.stdout.json'),'wx',0o600);
  const err=fs.openSync(path.join(logdir,label+'.stderr.log'),'wx',0o600);
  let r;try{r=spawnSync('/usr/bin/time',['-v','-o',path.join(logdir,label+'.resources.txt'),recoveryBinary,...args],
    {stdio:['ignore',out,err],env:{...process.env,RAYON_NUM_THREADS:'4'}});}finally{fs.closeSync(out);fs.closeSync(err);}
  assert.equal(r.status,0,`${label}: ${r.error??fs.readFileSync(path.join(logdir,label+'.stderr.log'),'utf8')}`);
  return read(path.join(logdir,label+'.stdout.json'));
}
export function reserveAfter(tx){
  if(!tx.payload)return outputUtxo(tx,0);
  const payload=Buffer.from(tx.payload,'hex');
  assert.equal(payload.subarray(0,8).toString(),'KPICR01\0');
  const stateOffset=8+265+370;
  assert.ok(payload.length>=stateOffset+105);
  const cm=payload.readUInt32LE(stateOffset+1),nf=payload.readUInt32LE(stateOffset+5);
  return cm===nf?null:outputUtxo(tx,0);
}
export function headFor(txs){
  assert.ok(txs.length);
  return {through:txs.length-1,reserve:reserveAfter(txs.at(-1)),last_transaction_id:txs.at(-1).id};
}
export function followAccepted(rows,descriptor){
  const first=rows.find(t=>t.id===descriptor.funding.txid);
  assert.ok(first,'accepted funding transaction unavailable');
  const txs=[first];let current=reserveAfter(first);
  const seen=new Set([first.id]);
  while(current){
    const next=rows.filter(t=>t.inputs[0]?.previousOutpoint.transactionId===current.txid&&t.inputs[0]?.previousOutpoint.index===current.index);
    const unique=new Map(next.map(t=>[t.id,t]));assert.ok(unique.size<=1,'competing accepted reserve spends');
    if(!unique.size)break;
    const t=unique.values().next().value;assert.ok(!seen.has(t.id),'cyclic history');seen.add(t.id);
    txs.push(t);current=reserveAfter(t);
  }
  return txs;
}
export async function liveHistory(rpc,descriptor){
  for(;;){
    const snap=await acceptedSnapshot(rpc,descriptor.start_hash);
    const rows=snap.transactions.map(x=>canonicalRpcTx(x.transaction));
    const txs=followAccepted(rows,descriptor),head=headFor(txs);
    if(head.reserve&&!await exactUtxo(rpc,head.reserve)){await sleep(1000);continue;}
    return {txs,head,snapshot:snap};
  }
}
export function writeHistory(publicDir,descriptor,txs){
  save(path.join(publicDir,'source-utxo.json'),descriptor.source);
  txs.forEach((tx,i)=>{transaction(tx).free();save(path.join(publicDir,number(i)+'.json'),tx);});
  save(path.join(publicDir,'head.json'),headFor(txs));
}
async function fetchFile(source,name,destination){
  const url=new URL(name,source.endsWith('/')?source:source+'/');
  if(url.protocol==='file:')copy(fileURLToPath(url),destination);
  else{
    assert.ok(['http:','https:'].includes(url.protocol),'unsupported public source');
    const response=await fetch(url);assert.ok(response.ok,`public source HTTP ${response.status}`);
    await pipeline(Readable.fromWeb(response.body),fs.createWriteStream(destination,{flags:'wx',mode:0o600}));
  }
  return fs.statSync(destination).size;
}
export async function publicSource(source,dir,backup){
  mkdir(dir);let bytes=0;
  bytes+=await fetchFile(source,'descriptor.json',path.join(dir,'descriptor.json'));
  assert.equal(await digest(path.join(dir,'descriptor.json')),read(backup).descriptor_sha256,'descriptor substitution');
  const d=read(path.join(dir,'descriptor.json'));assert.equal(d.network,'testnet-10');
  for(const name of ['vk.bin','pk.bin']){
    bytes+=await fetchFile(source,name,path.join(dir,name));
    assert.equal(await digest(path.join(dir,name)),d[name.slice(0,-4)+'_sha256'],'parameter substitution');
  }
  bytes+=await fetchFile(source,'history.json',path.join(dir,'history.json'));
  return {descriptor:d,packet:read(path.join(dir,'history.json')),bytes};
}
export function checkArchive(packet,txs){
  assert.ok(Array.isArray(packet.transactions)&&packet.transactions.length>0,'missing archive');
  assert.ok(packet.transactions.length<=txs.length,'archive ahead of accepted chain');
  packet.transactions.forEach((tx,i)=>assert.deepEqual(tx,txs[i],'archive differs from accepted prefix'));
  return {archivedTransactions:packet.transactions.length,fetchedSuccessors:txs.length-packet.transactions.length};
}

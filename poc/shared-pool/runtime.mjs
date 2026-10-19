#!/usr/bin/env node
// Shared TN10 transport, exact native encoding and isolated local prover.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import readline from 'node:readline';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';
import {spawn, spawnSync} from 'node:child_process';
const here=path.dirname(fileURLToPath(import.meta.url));
const binary=process.env.KPI_BINARY ?? path.join(here,'target/release/kpi-shared-pool');
const sdkPath=process.env.KPI_SDK_PATH ?? '/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa/kaspa.js';
const k=createRequire(import.meta.url)(sdkPath);
const rpcUrl=process.env.KPI_TN10_RPC ?? 'ws://10.0.3.26:17210';
const fundingDir=process.env.KPI_FUNDING_DIR ?? '/home/luke/.local/share/kpi-test-wallets/20261019-self-funded-fc9f7ff0-1860-4c81-977b-3448e06079ae';
const stringify=v=>JSON.stringify(v,(_,x)=>typeof x==='bigint'?x.toString():x,2);
const read=p=>JSON.parse(fs.readFileSync(p,'utf8'));
const number=n=>String(n).padStart(4,'0');
const fileHash=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
function syncDirectory(p){const fd=fs.openSync(p,'r');try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function save(p,v){const fd=fs.openSync(p,'wx',0o600);try{fs.writeFileSync(fd,stringify(v)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}syncDirectory(path.dirname(p));}
function spk(s){return s.version.toString(16).padStart(4,'0')+s.script;}
function canonical(tx){
  tx.finalize();return {version:tx.version,id:tx.id,
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
  let result;try{result=spawnSync('/usr/bin/time',['-v','-o',path.join(logdir,label+'.resources.txt'),binary,...args],{stdio:['ignore',out,err],env:{...process.env,RAYON_NUM_THREADS:'4'}});}finally{fs.closeSync(out);fs.closeSync(err);}
  assert.equal(result.status,0,`${label} failed; inspect ${logdir}/${label}.stderr.log`);
  return read(path.join(logdir,label+'.stdout.json'));
}
async function connect(){const rpc=new k.RpcClient({url:rpcUrl,networkId:'testnet-10'});await rpc.connect({timeoutDuration:15000});const info=await rpc.getServerInfo();assert.equal(info.networkId,'testnet-10');assert.equal(info.isSynced,true);return {rpc,info};}
async function utxos(rpc,addr){return (await rpc.getUtxosByAddresses({addresses:[addr]})).entries.map(entry);}
function walletSandbox(root,index,out,key=path.join(root,`wallet${index}/wallet.json`)){
  fs.mkdirSync(out,{mode:0o700});
  const args=['--unshare-all','--die-with-parent','--new-session','--clearenv','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--setenv','PATH','/usr/bin:/bin','--setenv','RAYON_NUM_THREADS','4','--dir','/software','--ro-bind',path.resolve(binary),'/software/kpi-shared-pool','--ro-bind',path.join(root,'public'),'/public','--ro-bind',key,'/wallet.json','--bind',out,'/output','--chdir','/output'];
  const audit=`import json,pathlib
assert not pathlib.Path('/home/luke').exists()
assert [p.name for p in pathlib.Path('/sys/class/net').glob('*')] == []
net=pathlib.Path('/proc/net/dev').read_text()
assert all(line.split(':')[0].strip() == 'lo' for line in net.splitlines() if ':' in line)
print(json.dumps({'hostHomeAccessible':False,'networkDevices':net,'mounts':pathlib.Path('/proc/mounts').read_text(),'privateInputCount':1,'otherWalletsMounted':False,'networkUnshared':True,'pidNamespaceUnshared':True,'sourceCheckoutMounted':False}))`;
  const checked=spawnSync('bwrap',[...args,'--','python3','-c',audit],{encoding:'utf8'});assert.equal(checked.status,0,checked.stderr);save(path.join(out,'namespace.json'),JSON.parse(checked.stdout));
  return args;
}
function walletChannel(index,out,input,output,done,kill){
  const lines=[],waiters=[];let closed=false,failure;
  const fail=e=>{failure=e;for(const w of waiters.splice(0))w.reject(e);};
  input.on('error',fail);output.on('error',fail);
  done.then(()=>{closed=true;if(waiters.length)fail(Error('wallet closed before response'));},e=>{closed=true;fail(e);});
  readline.createInterface({input:output}).on('line',line=>{try{const v=JSON.parse(line);const w=waiters.shift();if(w)w.resolve(v);else lines.push(v);}catch(e){fail(e);}});
  const receive=()=>{if(failure)return Promise.reject(failure);if(lines.length)return Promise.resolve(lines.shift());if(closed)return Promise.reject(Error('wallet closed'));return new Promise((resolve,reject)=>waiters.push({resolve,reject}));};
  const ready=receive().then(v=>{assert.equal(v.ready,true);save(path.join(out,'ready.json'),v);console.log(JSON.stringify({stage:'wallet-ready',wallet:index,parameterLoadMs:v.parameter_load_ms}));return v;});
  ready.catch(()=>{});
  return {out,ready,async request(v){await ready;if(failure)throw failure;input.write(JSON.stringify(v)+'\n');return receive();},async close(){input.end();await done;},kill};
}
function startWallet(root,index){
  const out=path.join(root,`wallet${index}-isolated`);
  if(process.env.KPI_PROVER_CHANNEL){
    const channel=process.env.KPI_PROVER_CHANNEL;
    const audit=read(path.join(out,'namespace.json'));assert.ok(audit.networkUnshared&&!audit.otherWalletsMounted);
    const input=fs.createWriteStream(path.join(channel,'request')),output=fs.createReadStream(path.join(channel,'response'));
    const done=new Promise((resolve,reject)=>{output.on('error',reject);input.on('error',reject);output.on('end',async()=>{
      try{const exit=path.join(out,'prover-exit.json');while(!fs.existsSync(exit))await new Promise(r=>setTimeout(r,20));assert.equal(read(exit).code,0);resolve();}catch(e){reject(e);}
    });});done.catch(()=>{});
    return walletChannel(index,out,input,output,done,()=>input.end());
  }
  const args=walletSandbox(root,index,out);
  const err=fs.openSync(path.join(out,'stderr.log'),'wx',0o600);
  const child=spawn('/usr/bin/time',['-v','-o',path.join(out,'resources.txt'),'bwrap',...args,'--','/software/kpi-shared-pool','wallet-session','/public','/wallet.json','/output'],{stdio:['pipe','pipe',err]});fs.closeSync(err);
  const done=new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',code=>code===0?resolve():reject(Error(`wallet ${index} exited ${code}; ${out}/stderr.log`)));});done.catch(()=>{});
  return walletChannel(index,out,child.stdin,child.stdout,done,()=>child.kill('SIGTERM'));
}
function startWalletSidecar(root,key){
  const out=path.join(root,'wallet0-isolated'),channel=path.join(root,'channel');
  fs.mkdirSync(channel,{mode:0o700});
  const pipes=spawnSync('mkfifo',['-m','600',path.join(channel,'request'),path.join(channel,'response')],{encoding:'utf8'});assert.equal(pipes.status,0,pipes.stderr);
  const args=walletSandbox(root,0,out,key);
  const err=fs.openSync(path.join(out,'stderr.log'),'wx',0o600);
  // The host launcher never reads protocol messages. The wallet and prover open
  // the two FIFOs directly; closing the request pipe delivers real stdin EOF.
  const script=String.raw`/software/kpi-shared-pool wallet-session /public /wallet.json /output < /channel/request > /channel/response; code=$?; printf '{"code":%s}\n' "$code" > /output/prover-exit.tmp; mv /output/prover-exit.tmp /output/prover-exit.json; exit "$code"`;
  const child=spawn('bwrap',[...args,'--bind',channel,'/channel','--','/bin/sh','-c',script],{stdio:['ignore','ignore',err]});fs.closeSync(err);
  const done=new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',code=>code===0?resolve():reject(Error(`wallet prover exited ${code}; ${out}/stderr.log`)));});done.catch(()=>{});
  return {done,kill(){child.kill('SIGTERM');}};

}

export {here,binary,sdkPath,k,rpcUrl,fundingDir,stringify,read,number,fileHash,syncDirectory,save,spk,canonical,transaction,entry,address,rust,connect,utxos,startWallet,startWalletSidecar};

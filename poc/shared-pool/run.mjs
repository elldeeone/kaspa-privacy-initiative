#!/usr/bin/env node
// Bounded TN10 experiment. Each submission is durably recorded and attempted once.
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
function startWallet(root,index){
  const out=path.join(root,`wallet${index}-isolated`);fs.mkdirSync(out,{mode:0o700});
  const args=['--unshare-all','--die-with-parent','--new-session','--clearenv','--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--setenv','PATH','/usr/bin:/bin','--setenv','RAYON_NUM_THREADS','4','--dir','/software','--ro-bind',path.resolve(binary),'/software/kpi-shared-pool','--ro-bind',path.join(root,'public'),'/public','--ro-bind',path.join(root,`wallet${index}/wallet.json`),'/wallet.json','--bind',out,'/output','--chdir','/output'];
  const audit=`import json,pathlib
assert not pathlib.Path('/home/luke').exists()
assert [p.name for p in pathlib.Path('/sys/class/net').glob('*')] == []
net=pathlib.Path('/proc/net/dev').read_text()
assert all(line.split(':')[0].strip() == 'lo' for line in net.splitlines() if ':' in line)
print(json.dumps({'hostHomeAccessible':False,'networkDevices':net,'mounts':pathlib.Path('/proc/mounts').read_text(),'privateInputCount':1,'otherWalletsMounted':False,'networkUnshared':True,'pidNamespaceUnshared':True,'sourceCheckoutMounted':False}))`;
  const checked=spawnSync('bwrap',[...args,'--','python3','-c',audit],{encoding:'utf8'});assert.equal(checked.status,0,checked.stderr);save(path.join(out,'namespace.json'),JSON.parse(checked.stdout));
  const err=fs.openSync(path.join(out,'stderr.log'),'wx',0o600);
  const child=spawn('/usr/bin/time',['-v','-o',path.join(out,'resources.txt'),'bwrap',...args,'--','/software/kpi-shared-pool','wallet-session','/public','/wallet.json','/output'],{stdio:['pipe','pipe',err]});fs.closeSync(err);
  const lines=[],waiters=[];let closed=false,failure;
  const fail=e=>{failure=e;for(const w of waiters.splice(0))w.reject(e);};
  child.on('error',fail);
  const done=new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',(code)=>{closed=true;if(code!==0){const e=Error(`wallet ${index} exited ${code}; ${out}/stderr.log`);fail(e);reject(e);}else{if(waiters.length)fail(Error('wallet closed before response'));resolve();}});});
  // Attach a rejection handler now; operations still observe the failure.
  done.catch(()=>{});
  readline.createInterface({input:child.stdout}).on('line',line=>{try{const v=JSON.parse(line);const w=waiters.shift();if(w)w.resolve(v);else lines.push(v);}catch(e){fail(e);}});
  const receive=()=>{if(failure)return Promise.reject(failure);if(lines.length)return Promise.resolve(lines.shift());if(closed)return Promise.reject(Error('wallet closed'));return new Promise((resolve,reject)=>waiters.push({resolve,reject}));};
  const ready=receive().then(v=>{assert.equal(v.ready,true);save(path.join(out,'ready.json'),v);console.log(JSON.stringify({stage:'wallet-ready',wallet:index,parameterLoadMs:v.parameter_load_ms}));return v;});
  ready.catch(()=>{});
  return {out,ready,async request(v){await ready;if(failure)throw failure;child.stdin.write(JSON.stringify(v)+'\n');return receive();},async close(){child.stdin.end();await done;},kill(){child.kill('SIGTERM');}};
}
const sourceFiles=['Cargo.toml','Cargo.lock','src/protocol.rs','src/circuit.rs','src/covenant.rs','src/native.rs','src/main.rs','src/lib.rs','src/app.rs','src/fixtures.rs','src/tests.rs','run.mjs'];
async function prepare(params,base,arm){
  assert.ok(['full','partial'].includes(arm));fs.mkdirSync(base,{recursive:true,mode:0o700});
  const root=path.join(base,new Date().toISOString().replaceAll(':','-')+'-'+arm+'-'+crypto.randomUUID());
  const initialized=spawnSync(binary,['init',params,root],{encoding:'utf8'});assert.equal(initialized.status,0,initialized.stderr);console.log(JSON.stringify({stage:'identity-created',root,arm}));
  const publicDir=path.join(root,'public'),logs=path.join(root,'logs');fs.mkdirSync(logs,{mode:0o700});
  const {rpc,info}=await connect();
  try{
    const wallet=read(path.join(fundingDir,'funding.json'));assert.equal(wallet.network,'testnet-10');
    const candidates=(await utxos(rpc,wallet.address)).filter(u=>!u.is_coinbase&&BigInt(u.amount)>4_900_000_000n).sort((a,b)=>BigInt(a.amount)>BigInt(b.amount)?-1:1);
    assert.ok(candidates.length,'no sufficient ordinary TN10 funding UTXO');save(path.join(root,'funding-input.json'),candidates[0]);
    save(path.join(root,'node-before.json'),{endpoint:rpcUrl,info,feeEstimate:await rpc.getFeeEstimate()});
    rust(logs,'fund',['fund',root,path.join(root,'funding-input.json'),path.join(fundingDir,'funding.key')]);
  }finally{await rpc.disconnect();}
  const m=read(path.join(publicDir,'manifest.json'));
  const wallets=[0,1,2,3].map(i=>startWallet(root,i));
  const truth={arm,initial:{cm:Buffer.from(m.initial_state.commitments[0]).toString('hex'),value:'1000000000',wallet:0},events:[]};
  let through=1,firstWithdrawalHorizon;
  async function act(wallet,request){
    const result=await wallets[wallet].request({through,...request});const step=through+1;
    assert.equal(result.report.step,step);assert.equal(result.report.full_validation,true);assert.equal(result.report.relay_policy,true);
    for(const suffix of ['.json','.metrics.json'])fs.copyFileSync(path.join(wallets[wallet].out,number(step)+suffix),path.join(publicDir,number(step)+suffix),fs.constants.COPYFILE_EXCL);
    truth.events.push({...result.truth,wallet,kind:request.kind});through=step;
    console.log(JSON.stringify({stage:'proof-prepared',step,kind:request.kind,wallet,provingMs:result.report.extra.proving_ms}));return result.truth;
  }
  try{
    await Promise.all(wallets.map(w=>w.ready));
    const p1=await act(0,{kind:'transfer',spend_cm:truth.initial.cm,recipient:m.receivers[1],amount:'400000000'});
    const deposits={};for(const w of [1,2,3])deposits[w]=await act(w,{kind:'deposit',deposit_index:w});
    const p2=await act(1,{kind:'transfer',spend_cm:p1.outputs[0].cm,recipient:m.receivers[2],amount:'300000000'});
    const p3=await act(2,{kind:'transfer',spend_cm:deposits[2].outputs[0].cm,recipient:m.receivers[3],amount:'500000000'});
    const p4=await act(3,{kind:'transfer',spend_cm:p3.outputs[0].cm,recipient:m.receivers[0],amount:'200000000'});
    const p5=await act(0,{kind:'transfer',spend_cm:p4.outputs[0].cm,recipient:m.receivers[1],amount:'100000000'});
    const selected=[p5.outputs[1].cm,p5.outputs[0].cm,p2.outputs[0].cm,p4.outputs[1].cm];
    for(const w of [0,1,2,3])await act(w,{kind:arm==='full'?'full':'partial',spend_cm:selected[w],...(arm==='partial'?{amount:'25000000'}:{})});
    firstWithdrawalHorizon=through;
    for(const w of [0,1,2,3]){
      const scanned=await wallets[w].request({through,kind:'scan'});
      for(const note of scanned.notes)await act(w,{kind:'full',spend_cm:note.cm});
      assert.deepEqual((await wallets[w].request({through,kind:'scan'})).notes,[]);
    }
    // Everyone rescans the terminal history using only their own wallet file.
    for(const w of wallets)assert.deepEqual((await w.request({through,kind:'scan'})).notes,[]);
    await Promise.all(wallets.map(w=>w.close()));
  }catch(e){for(const w of wallets)w.kill();throw e;}
  assert.equal(Buffer.from(read(path.join(publicDir,number(through)+'.json')).payload,'hex')[8],3,'no terminal exit');
  truth.firstWithdrawalHorizon=firstWithdrawalHorizon;save(path.join(root,'private-truth.json'),truth);
  const controls=rust(logs,'native-controls',['controls',publicDir,String(through)]);
  const transactions={};for(let step=0;step<=through;step++){const p=path.join(publicDir,number(step)+'.json');transaction(read(p)).free();transactions[number(step)]=fileHash(p);}
  const sources=Object.fromEntries(sourceFiles.map(name=>[name,fileHash(path.join(here,name))]));
  save(path.join(root,'prepared.json'),{root,arm,created:new Date().toISOString(),sdkRoundTrips:through+1,completeSequenceLocallyValidated:true,broadcast:false,lastStep:through,firstWithdrawalHorizon,binarySha256:fileHash(binary),sources,transactions,groundTruthSha256:fileHash(path.join(root,'private-truth.json')),nativeControls:controls.native_rejections});
  console.log(JSON.stringify({prepared:root,transactions:through+1,broadcast:false}));
}
async function exactUtxo(rpc,expected){const rows=await utxos(rpc,address(expected.spk));const found=rows.find(u=>u.txid===expected.txid&&u.index===expected.index);if(found){assert.equal(found.amount,expected.amount);assert.equal(found.spk,expected.spk);assert.equal(found.is_coinbase,false);}return found;}
function expectedOutput(raw,index){const o=raw.outputs[index];return {txid:raw.id,index,amount:o.value,spk:o.scriptPublicKey,daa:'0',is_coinbase:false};}
const outpoint=u=>`${u.txid}:${u.index}`;
async function confirm(rpc,raw){for(;;){const outputs=await Promise.all(raw.outputs.map((_,i)=>exactUtxo(rpc,expectedOutput(raw,i))));if(outputs.every(Boolean))return outputs;await new Promise(resolve=>setTimeout(resolve,2000));}}
async function submitOnce(rpc,root,step){
  const label=number(step),raw=read(path.join(root,'public',label+'.json')),tx=transaction(raw);
  save(path.join(root,'live',label+'.submission.json'),{txid:raw.id,submittedAt:new Date().toISOString(),rawSha256:fileHash(path.join(root,'public',label+'.json'))});
  let response;try{response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});}catch(error){save(path.join(root,'live',label+'.response.json'),{accepted:false,error:String(error)});throw error;}finally{tx.free();}
  save(path.join(root,'live',label+'.response.json'),{accepted:true,response});assert.equal(response.transactionId,raw.id);
  const outputs=await confirm(rpc,raw);save(path.join(root,'live',label+'.confirmed.json'),{txid:raw.id,observedAt:new Date().toISOString(),outputs});
  console.log(JSON.stringify({stage:'confirmed',step,txid:raw.id}));return outputs;
}
async function live(root){
  const prepared=read(path.join(root,'prepared.json'));assert.equal(prepared.broadcast,false);assert.equal(fileHash(binary),prepared.binarySha256,'binary changed after preparation');
  for(let step=0;step<=prepared.lastStep;step++){const label=number(step),p=path.join(root,'public',label+'.json');assert.equal(fileHash(p),prepared.transactions[label]);transaction(read(p)).free();}
  fs.mkdirSync(path.join(root,'live'),{mode:0o700});syncDirectory(root); // existing directory rejects any rerun
  const {rpc,info}=await connect();const source=read(path.join(root,'funding-input.json'));const ledger=new Map([[outpoint(source),source]]);let totalFee=0n;
  try{
    save(path.join(root,'live','node.json'),{endpoint:rpcUrl,info,feeEstimate:await rpc.getFeeEstimate()});
    for(let step=0;step<=prepared.lastStep;step++){
      const label=number(step),p=path.join(root,'public',label+'.json'),raw=read(p),actual=[];
      for(const i of raw.inputs){const key=`${i.previousOutpoint.transactionId}:${i.previousOutpoint.index}`;const prior=ledger.get(key);assert.ok(prior,'missing locally tracked input');const u=await exactUtxo(rpc,prior);assert.ok(u,'canonical input no longer unspent');actual.push(u);ledger.delete(key);}
      const context=path.join(root,'live',label+'.inputs.json');save(context,actual);const validation=rust(path.join(root,'live'),label+'-validation',['validate',p,context]);
      totalFee+=BigInt(validation.metrics.fee_sompi);for(const u of await submitOnce(rpc,root,step))ledger.set(outpoint(u),u);
    }
    const terminal=read(path.join(root,'public',number(prepared.lastStep)+'.json'));assert.equal(Buffer.from(terminal.payload,'hex')[8],3);assert.equal(terminal.outputs.length,1);
    for(const u of ledger.values())assert.ok(await exactUtxo(rpc,u),'final payout/change is not confirmed');
    const previous=expectedOutput(read(path.join(root,'public',number(prepared.lastStep-1)+'.json')),0);assert.equal(await exactUtxo(rpc,previous),undefined,'terminal reserve remains');
    const remaining=[...ledger.values()].reduce((n,u)=>n+BigInt(u.amount),0n);assert.equal(remaining+totalFee,BigInt(source.amount),'native accounting does not balance');
    const result={completedAt:new Date().toISOString(),network:'testnet-10',arm:prepared.arm,confirmedTransactions:prepared.lastStep+1,feeSompi:totalFee,terminalReserveSpent:true,finalUnspentOutputs:[...ledger.values()],fourWalletsIndependentlyProvedAndDrained:true,scope:'synthetic TN10 trial; not real-world anonymity, cryptographic audit or mainnet proof'};
    save(path.join(root,'live','result.json'),result);console.log(stringify(result));
    // Strict chain-only observer export. Deliberately omit descriptor, metrics,
    // account labels, private note selections, schedules and process output.
    const chain={schema:'kpi-shared-pool-chain-v2',network:'testnet-10',transactions:[]};
    for(let step=0;step<=prepared.lastStep;step++){const label=number(step);chain.transactions.push({step,tx:read(path.join(root,'public',label+'.json')),inputs:read(path.join(root,'live',label+'.inputs.json'))});}
    save(path.join(root,'chain-only.json'),chain);
  }finally{await rpc.disconnect();}
}
const [command,a,b,c]=process.argv.slice(2);
try{if(command==='prepare'&&a&&b&&c)await prepare(path.resolve(a),path.resolve(b),c);else if(command==='live'&&a)await live(path.resolve(a));else throw Error('usage: node run.mjs prepare PARAMS TRIAL_BASE full|partial | live TRIAL');}catch(error){console.error(String(error));process.exitCode=1;}

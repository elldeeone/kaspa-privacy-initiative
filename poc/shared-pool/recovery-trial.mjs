#!/usr/bin/env node
// H7 trial preparation and offline gate. Private roots are always outside Git.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {k,read,save,rust,binary,fileHash,number,startWallet,spk,transaction} from './runtime.mjs';
import {outputUtxo,outpoint} from './chain.mjs';
import {mkdir,copy,recovery,recoveryBinary,headFor,writeHistory} from './recovery-common.mjs';
import {launchLocal} from './recovery-sandbox.mjs';
import {controls} from './recovery-controls.mjs';
const here=path.dirname(fileURLToPath(import.meta.url));

export function sources(){
  const paths=['Cargo.toml','Cargo.lock','src/lib.rs','src/native.rs','src/protocol.rs','src/compact/mod.rs',
    'src/compact/tree.rs','src/compact/circuit.rs','src/compact/covenant.rs','src/compact/experiment.rs','src/compact/recovery.rs',
    'src/bin/kpi-recovery.rs','recovery-client.mjs','recovery-common.mjs','recovery-sandbox.mjs','recovery-trial.mjs',
    'recovery-controls.mjs','recovery-live.mjs','recovery-remote.mjs','runtime.mjs','chain.mjs'];
  return Object.fromEntries(paths.map(n=>[n,fileHash(path.join(here,n))]));
}
export function createIdentity(params,base,role){
  mkdir(base);const root=path.join(base,`${role}-${crypto.randomUUID()}`);
  const init=spawnSync(binary,['init',params,root,'1000000000'],{encoding:'utf8'});
  assert.equal(init.status,0,init.stderr);mkdir(path.join(root,'logs'));
  save(path.join(root,'identity.json'),{role,network:'testnet-10',createdAt:new Date().toISOString(),sources:sources(),
    compactBinarySha256:fileHash(binary),recoveryBinarySha256:fileHash(recoveryBinary),fresh:true});
  return root;
}
export function restoreIdentity(prior,base,role){
  // Fresh recovery attempt for an existing pool, never a rebroadcast/resume of
  // an old broadcaster. Only the three pre-exit transactions are adopted.
  assert.ok(['offline','cleanup'].includes(role));
  const stopped=read(path.join(prior,'originals-stopped.json'));assert.equal(stopped.aliceProverExited,true);
  mkdir(base);const root=path.join(base,`${role}-${crypto.randomUUID()}`);
  for(const dir of ['public','logs','backups'])mkdir(path.join(root,dir));
  for(const name of ['manifest.json','descriptor.json','vk.bin','pk.bin','source-utxo.json'])copy(path.join(prior,'public',name),path.join(root,'public',name));
  for(let i=0;i<3;i++){
    copy(path.join(prior,`backups/wallet${i}.json`),path.join(root,`backups/wallet${i}.json`));
    for(const suffix of ['.json','.metrics.json'])copy(path.join(prior,'public',number(i)+suffix),path.join(root,'public',number(i)+suffix));
    if(role==='cleanup')for(const suffix of ['.inputs.json','.submission.json','.response.json','.confirmed.json'])
      copy(path.join(prior,'logs',number(i)+suffix),path.join(root,'logs',number(i)+suffix));
  }
  copy(path.join(prior,'originals-stopped.json'),path.join(root,'originals-stopped.json'));
  save(path.join(root,'identity.json'),{role,network:'testnet-10',createdAt:new Date().toISOString(),sources:sources(),
    compactBinarySha256:fileHash(binary),recoveryBinarySha256:fileHash(recoveryBinary),fresh:true,
    freshRecoveryAttempt:true,existingPool:read(path.join(root,'public/descriptor.json')).funding.txid});
  return root;
}
export async function preparePayments(root,afterTransaction=async()=>{}){
  const pub=path.join(root,'public');const alice=startWallet(root,0);
  try{
    await alice.ready;
    for(const [through,amount,recipient] of [[0,'400000000',1],[1,'200000000',2]]){
      const label=`payment-${through+1}`;
      const report=await alice.request({through,kind:'transfer',label,amount,recipient});
      save(path.join(root,'logs',label+'.proof.json'),report);
      copy(path.join(alice.out,label+'.bundle.json'),path.join(pub,label+'.bundle.json'));
      rust(path.join(root,'logs'),label+'-settle',['rebase',pub,String(through),path.join(pub,label+'.bundle.json'),pub]);
      await afterTransaction(through+1);
      console.log(JSON.stringify({stage:'private-payment-prepared',step:through+1}));
    }
    await alice.close();
    save(path.join(root,'originals-stopped.json'),{aliceProverExited:true,bobProverEverStarted:false,carolProverEverStarted:false,
      stoppedAt:new Date().toISOString(),recoveryStarted:false});
  }catch(error){alice.kill();throw error;}
}
export function makeArchive(root,target){
  mkdir(target);const pub=path.join(root,'public');
  for(const name of ['descriptor.json','vk.bin','pk.bin'])copy(path.join(pub,name),path.join(target,name));
  save(path.join(target,'history.json'),{transactions:[0,1,2].map(i=>read(path.join(pub,number(i)+'.json')))});
}
export function finishAccounting(root){
  const pub=path.join(root,'public'),txs=Array.from({length:6},(_,i)=>read(path.join(pub,number(i)+'.json')));
  const source=read(path.join(pub,'source-utxo.json'));const ledger=new Map([[outpoint(source),source]]);let fees=0n;
  for(const [i,tx] of txs.entries()){
    transaction(tx).free();let input=0n;
    for(const x of tx.inputs){const p=`${x.previousOutpoint.transactionId}:${x.previousOutpoint.index}`;assert.ok(ledger.has(p));input+=BigInt(ledger.get(p).amount);ledger.delete(p);}
    let output=0n;tx.outputs.forEach((_,j)=>{const u=outputUtxo(tx,j);ledger.set(outpoint(u),u);output+=BigInt(u.amount);});
    const fee=input-output;assert.ok(fee>0n);assert.equal(fee,BigInt(read(path.join(pub,number(i)+'.metrics.json')).metrics.fee_sompi));fees+=fee;
  }
  assert.equal(headFor(txs).reserve,null);assert.equal([...ledger.values()].reduce((s,u)=>s+BigInt(u.amount),0n)+fees,BigInt(source.amount));
  const checked=spawnSync('python3',[path.join(here,'check-compact-state.py'),pub],{encoding:'utf8'});assert.equal(checked.status,0,checked.stderr);
  const independent=JSON.parse(checked.stdout);assert.equal(independent.all_claims_drained,true);assert.equal(independent.spends,5);
  save(path.join(root,'independent-state.json'),independent);
  const v={transactions:6,claims:5,allClaimsDrained:true,remainingReserve:null,totalFeeSompi:fees.toString(),finalOrdinaryOutputs:[...ledger.values()]};
  save(path.join(root,'accounting.json'),v);return v;
}

async function offline(params,base,prior){
  const root=prior?restoreIdentity(prior,base,'offline'):createIdentity(params,base,'offline'),pub=path.join(root,'public'),logs=path.join(root,'logs');
  console.log(JSON.stringify({stage:'identity-created',root}));
  if(!prior){
  const secret=crypto.randomBytes(32).toString('hex'),key=new k.PrivateKey(secret),pk=key.toPublicKey(),address=pk.toAddress('testnet-10');
  const source={txid:crypto.randomBytes(32).toString('hex'),index:0,amount:'2000000000',spk:spk(k.payToAddressScript(address)),daa:'0',is_coinbase:false};
  key.free();pk.free();address.free();
  save(path.join(root,'synthetic-source.json'),source);fs.writeFileSync(path.join(root,'synthetic-funding.key'),secret,{flag:'wx',mode:0o600});
  rust(logs,'fund',['fund',root,path.join(root,'synthetic-source.json'),path.join(root,'synthetic-funding.key')]);
  recovery(logs,'seal',['seal',root,'0'.repeat(64)]);
  await preparePayments(root);
  }
  const mirror=path.join(root,'mirror-secondary');makeArchive(root,mirror);
  const txs=[0,1,2].map(i=>read(path.join(pub,number(i)+'.json'))),results=[];
  for(const index of [1,2,0]){
    const run=path.join(root,`recovered-${index}`);mkdir(run);
    const chain=path.join(root,`accepted-before-${index}.json`);save(chain,{transactions:txs});
    save(path.join(run,'config.json'),{mode:'offline',sources:['file:///sources/primary/','file:///sources/secondary/'],chainFile:'/chain/accepted.json'});
    await launchLocal({backup:path.join(root,`backups/wallet${index}.json`),run,source:mirror,chain});
    const r=read(path.join(run,'output/result.json'));assert.equal(r.sources[0].accepted,false);assert.equal(r.sources[1].accepted,true);
    const step=txs.length,prior=outputUtxo(txs.at(-1),0);save(path.join(logs,`exit-${index}.input.json`),[prior]);
    rust(logs,`exit-${index}-validate`,['validate',path.join(run,'output',r.proof.transaction_file),path.join(logs,`exit-${index}.input.json`)]);
    for(const suffix of ['.json','.metrics.json'])copy(path.join(run,'output',number(step)+suffix),path.join(pub,number(step)+suffix));
    txs.push(r.transaction);results.push({wallet:index,payout:r.payout,newPrivateProofs:r.newPrivateProofs,proof:r.proof,totalMs:r.totalMs});
    console.log(JSON.stringify({stage:'offline-wallet-recovered',wallet:index,payoutSompi:r.payout.amount}));
  }
  const accounting=finishAccounting(root);
  const rejects=await controls(root);
  const native=rust(logs,'native-controls',['controls',pub]);save(path.join(root,'native-controls.json'),native);
  const result={complete:true,offline_pass:true,broadcast:false,...read(path.join(root,'identity.json')),accounting,wallets:results,
    recoveryControls:rejects,nativeRejections:native.native_rejections,originalsStopped:true,
    scope:'Synthetic explicit UTXOs and isolated local recovery; no live chain or independent-host claim'};
  save(path.join(root,'offline-result.json'),result);console.log(JSON.stringify({stage:'offline-passed',root,transactions:6,nativeRejections:native.native_rejections}));
}

if(process.argv[1]===fileURLToPath(import.meta.url)){
  const [command,params,base]=process.argv.slice(2);
  if(command==='offline')await offline(path.resolve(params),path.resolve(base));
  else if(command==='restore-offline')await offline(undefined,path.resolve(base),path.resolve(params));
  else if(command==='new')console.log(JSON.stringify({root:createIdentity(path.resolve(params),path.resolve(base),'unfunded'),funded:false}));
  else throw Error('offline PARAMS BASE | restore-offline PRIOR BASE | new PARAMS BASE');
}

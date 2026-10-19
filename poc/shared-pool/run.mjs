#!/usr/bin/env node
// Bounded TN10 experiment. Each submission is durably recorded and attempted once.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {here,binary,k,rpcUrl,fundingDir,stringify,read,number,fileHash,syncDirectory,save,transaction,address,rust,connect,utxos,startWallet} from './runtime.mjs';
const sourceFiles=['Cargo.toml','Cargo.lock','src/protocol.rs','src/circuit.rs','src/covenant.rs','src/native.rs','src/main.rs','src/lib.rs','src/app.rs','src/fixtures.rs','src/tests.rs','run.mjs','runtime.mjs'];
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

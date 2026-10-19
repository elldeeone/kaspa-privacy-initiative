#!/usr/bin/env node
// Bounded offline/TN10 lifecycle. Every broadcast is durably recorded once.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import readline from 'node:readline';
import {spawn,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {performance} from 'node:perf_hooks';
import {read,save,fileHash,transaction,connect,utxos,fundingDir,number,rust,binary,sdkPath,rpcUrl,stringify} from './runtime.mjs';
import {confirm,exactUtxo,outputUtxo,outpoint,acceptedSnapshot,canonicalRpcTx,sleep} from './chain.mjs';
const here=path.dirname(fileURLToPath(import.meta.url));
const sourceFiles=['Cargo.toml','Cargo.lock','src/lib.rs','src/native.rs','src/protocol.rs',
  'src/bin/kpi-compact.rs',...['mod','tree','circuit','covenant','experiment','controls','tests'].map(x=>`src/compact/${x}.rs`),
  'compact.mjs','compact-rebase.mjs','runtime.mjs','chain.mjs'];
const sources=()=>Object.fromEntries(sourceFiles.map(f=>[f,fileHash(path.join(here,f))]));
const copy=(a,b)=>fs.copyFileSync(a,b,fs.constants.COPYFILE_EXCL);
function baseSandbox(network=false){return ['--unshare-all',...(network?['--share-net']:[]),'--die-with-parent','--new-session','--clearenv',
  '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64',
  '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--setenv','PATH','/usr/bin:/bin','--setenv','RAYON_NUM_THREADS','4',
  '--dir','/software','--ro-bind',binary,'/software/kpi-compact','--chdir','/tmp'];}
function wallet(root,index,label){
  const out=path.join(root,label);fs.mkdirSync(out,{mode:0o700});
  const args=[...baseSandbox(),'--ro-bind',path.join(root,'public'),'/public','--ro-bind',path.join(root,`wallet${index}`,'wallet.json'),'/wallet.json','--bind',out,'/output'];
  const audit=spawnSync('bwrap',[...args,'--','python3','-c',"import pathlib; assert not pathlib.Path('/home/luke').exists(); assert not any(':' in s and s.split(':')[0].strip() != 'lo' for s in pathlib.Path('/proc/net/dev').read_text().splitlines()); print('isolated')"],{encoding:'utf8'});
  assert.equal(audit.status,0,audit.stderr);
  save(path.join(out,'isolation.json'),{networkUnshared:true,otherWalletsAccessible:false,hostHomeAccessible:false,privateInputCount:1});
  const err=fs.openSync(path.join(out,'stderr.log'),'wx',0o600);
  const child=spawn('bwrap',[...args,'--','/software/kpi-compact','wallet-session','/public','/wallet.json','/output'],{stdio:['pipe','pipe',err]});fs.closeSync(err);
  const queued=[],waiting=[];let error,closed=false;
  const fail=e=>{error=e;for(const w of waiting.splice(0))w.reject(e);};
  child.stdin.on('error',fail);
  const done=new Promise((resolve,reject)=>{child.on('error',e=>{fail(e);reject(e);});child.on('close',code=>{
    closed=true;save(path.join(out,'process-exit.json'),{code,exitedAt:new Date().toISOString()});
    if(code===0){if(waiting.length)fail(Error('wallet closed with pending response'));resolve();}else{const e=Error(`${label} failed: ${out}/stderr.log`);fail(e);reject(e);}
  });});done.catch(()=>{});
  readline.createInterface({input:child.stdout}).on('line',line=>{try{const v=JSON.parse(line);const w=waiting.shift();if(w)w.resolve(v);else queued.push(v);}catch(e){fail(e);}});
  const receive=()=>error?Promise.reject(error):queued.length?Promise.resolve(queued.shift()):closed?Promise.reject(Error('wallet closed')):new Promise((resolve,reject)=>waiting.push({resolve,reject}));
  const ready=receive().then(v=>{assert.equal(v.ready,true);save(path.join(out,'ready.json'),v);return v;});ready.catch(()=>{});
  return {out,ready,done,async request(v){await ready;child.stdin.write(JSON.stringify(v)+'\n');return receive();},async close(){child.stdin.end();await done;},kill(){child.kill('SIGTERM');}};
}
function publicRebase(root,through,label){
  const view=path.join(root,`${label}-public-view`),out=path.join(root,`${label}-rebuild`);fs.mkdirSync(view,{mode:0o700});fs.mkdirSync(out,{mode:0o700});
  for(const name of ['manifest.json','vk.bin','source-utxo.json',`${label}.bundle.json`,...Array.from({length:through+1},(_,i)=>`${number(i)}.json`)])copy(path.join(root,'public',name),path.join(view,name));
  const args=[...baseSandbox(),'--ro-bind',view,'/public','--bind',out,'/output','--','/software/kpi-compact','rebase','/public',String(through),`/public/${label}.bundle.json`,'/output'];
  const t=performance.now();const result=spawnSync('bwrap',args,{encoding:'utf8'});assert.equal(result.status,0,result.stderr);
  save(path.join(out,'process.json'),{publicOnly:true,noWalletMounted:true,noProvingKeyMounted:true,wallMs:performance.now()-t});
  for(const suffix of ['.json','.metrics.json'])copy(path.join(out,number(through+1)+suffix),path.join(root,'public',number(through+1)+suffix));
  return JSON.parse(result.stdout);
}
async function publicBob(root,anchor,payments){
  const dir=path.join(root,'bob-public-rebuilder'),pub=path.join(dir,'public'),out=path.join(dir,'output');
  fs.mkdirSync(dir,{mode:0o700});fs.mkdirSync(pub,{mode:0o700});fs.mkdirSync(out,{mode:0o700});
  for(const n of ['manifest.json','vk.bin','source-utxo.json','0000.json','0001.json','bob.bundle.json'])copy(path.join(root,'public',n),path.join(pub,n));
  save(path.join(pub,'start.json'),{anchor,payments});
  const args=[...baseSandbox(true),'--ro-bind',process.execPath,'/software/node','--ro-bind',path.dirname(sdkPath),'/sdk',
    '--setenv','KPI_SDK_PATH','/sdk/kaspa.js','--setenv','KPI_BINARY','/software/kpi-compact','--setenv','KPI_TN10_RPC',rpcUrl,'--bind',dir,'/run'];
  for(const f of ['compact-rebase.mjs','runtime.mjs','chain.mjs'])args.push('--ro-bind',path.join(here,f),`/software/${f}`);
  const err=fs.openSync(path.join(out,'stderr.log'),'wx',0o600);
  const child=spawn('bwrap',[...args,'--','/software/node','/software/compact-rebase.mjs','/run'],{stdio:['ignore','inherit',err]});fs.closeSync(err);
  await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',code=>code===0?resolve():reject(Error(`public Bob failed: ${out}/stderr.log`)));});
  for(let i=2;i<=payments+1;i++)assert.deepEqual(read(path.join(pub,number(i)+'.json')),read(path.join(root,'public',number(i)+'.json')));
  for(const suffix of ['.json','.metrics.json'])copy(path.join(out,number(payments+2)+suffix),path.join(root,'public',number(payments+2)+suffix));
  return read(path.join(out,'result.json'));
}
function checkOffline(root){
  const v=read(path.join(root,'offline-result.json'));assert.equal(v.offline_pass,true);assert.equal(v.binary_sha256,fileHash(binary));
  assert.equal(v.payments_after_bob_authorization,100);
  for(let i=0;i<v.transactions;i++)transaction(read(path.join(root,'public',number(i)+'.json'))).free();
  return v;
}
async function smoke(offline){
  const v=checkOffline(offline);
  const root=path.join(offline,`isolation-${crypto.randomUUID()}`);fs.mkdirSync(root,{mode:0o700});
  fs.mkdirSync(path.join(root,'public'),{mode:0o700});
  for(const n of ['manifest.json','vk.bin','source-utxo.json','bob.bundle.json',...Array.from({length:102},(_,i)=>number(i)+'.json')])copy(path.join(offline,'public',n),path.join(root,'public',n));
  const rebuilt=publicRebase(root,101,'bob');
  const tx=read(path.join(root,'public','0102.json')),b=read(path.join(root,'public','bob.bundle.json'));
  assert.equal(tx.inputs[0].signatureScript.slice(4,260),b.proof);assert.equal(tx.payload.slice(16,16+265*2),b.authorization);
  save(path.join(root,'result.json'),{publicOnly:true,originalProofReused:true,rebuilt,broadcast:false});
  console.log(JSON.stringify({sandboxSmoke:true,broadcast:false,root}));
}
async function live(params,base,role,offline,rehearsal){
  assert.ok(['rehearsal','trial'].includes(role));const checked=checkOffline(offline);
  const code=sources(),binHash=fileHash(binary);
  if(role==='trial'){
    const r=read(path.join(rehearsal,'result.json'));assert.equal(r.complete,true);assert.equal(r.role,'rehearsal');
    assert.equal(r.binarySha256,binHash);assert.deepEqual(r.sources,code);
  }
  fs.mkdirSync(base,{recursive:true,mode:0o700});const root=path.join(base,`${new Date().toISOString().replaceAll(':','-')}-${role}-${crypto.randomUUID()}`);
  const reserve=role==='rehearsal'?'1000000000':'10000000000';
  const initialized=spawnSync(binary,['init',params,root,reserve],{encoding:'utf8'});assert.equal(initialized.status,0,initialized.stderr);
  const payments=role==='rehearsal'?2:100;
  const pub=path.join(root,'public'),logs=path.join(root,'live');fs.mkdirSync(logs,{mode:0o700});
  save(path.join(root,'identity.json'),{root,role,network:'testnet-10',binarySha256:binHash,sources:code,offlineRoot:offline,vkSha256:checked.vk_sha256});
  console.log(JSON.stringify({stage:'identity-created',root,role}));
  const {rpc,info}=await connect();let alice,bob,cleanup,aliceCleanup;
  let source;
  async function submit(step){
    const label=number(step),raw=read(path.join(pub,label+'.json'));
    const prior=step===0?source:outputUtxo(read(path.join(pub,number(step-1)+'.json')),0);
    const actual=await exactUtxo(rpc,prior);assert.ok(actual,'input no longer unspent');
    const ctx=path.join(logs,label+'.inputs.json');save(ctx,[actual]);rust(logs,label+'-validate',['validate',path.join(pub,label+'.json'),ctx]);
    const tx=transaction(raw);save(path.join(logs,label+'.submission.json'),{txid:raw.id,submittedAt:new Date().toISOString(),bodySha256:fileHash(path.join(pub,label+'.json'))});
    let response;try{response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});}
    catch(error){save(path.join(logs,label+'.response.json'),{accepted:false,error:String(error)});throw error;}finally{tx.free();}
    assert.equal(response.transactionId,raw.id);save(path.join(logs,label+'.response.json'),{accepted:true,response});
    const outputs=await confirm(rpc,raw);save(path.join(logs,label+'.confirmed.json'),{outputs,observedAt:new Date().toISOString()});
    console.log(JSON.stringify({stage:'confirmed',step,txid:raw.id}));
  }
  async function authorize(w,request){
    const r=await w.request(request);save(path.join(w.out,request.label+'.report.json'),r);
    copy(path.join(w.out,request.label+'.bundle.json'),path.join(pub,request.label+'.bundle.json'));
    console.log(JSON.stringify({stage:'authorized',label:request.label,provingMs:r.proving_ms}));return r;
  }
  try{
    save(path.join(root,'node-before.json'),{endpoint:rpcUrl,info,feeEstimate:await rpc.getFeeEstimate()});
    const funding=read(path.join(fundingDir,'funding.json'));assert.equal(funding.network,'testnet-10');
    const rows=(await utxos(rpc,funding.address)).filter(u=>!u.is_coinbase&&BigInt(u.amount)>BigInt(reserve)+1_000_000n).sort((a,b)=>BigInt(a.amount)>BigInt(b.amount)?-1:1);
    assert.ok(rows.length,'no sufficient testnet funding UTXO');source=rows[0];save(path.join(root,'funding-input.json'),source);
    rust(logs,'fund',['fund',root,path.join(root,'funding-input.json'),path.join(fundingDir,'funding.key')]);
    alice=wallet(root,0,'alice-prover');bob=wallet(root,1,'bob-prover');await Promise.all([alice.ready,bob.ready]);
    await authorize(alice,{through:0,kind:'transfer',label:'bootstrap',amount:'400000000',recipient:1});publicRebase(root,0,'bootstrap');
    const anchor=(await rpc.getBlockDagInfo()).sink;save(path.join(root,'chain-anchor.json'),{anchor});
    await submit(0);await submit(1);
    const bobReport=await authorize(bob,{through:1,kind:'exit',label:'bob'});await bob.close();
    save(path.join(root,'bob-prover-stopped.json'),{stoppedBeforeAlicePayment:true,stoppedAt:new Date().toISOString(),report:bobReport});
    const rebaseAnchor=(await rpc.getBlockDagInfo()).sink;
    for(let i=1;i<=payments;i++){
      const label=`payment-${i}`;
      await authorize(alice,{through:i,kind:'transfer',label,amount:'60000000',recipient:2});
      publicRebase(root,i,label);await submit(i+1);
    }
    await alice.close();
    save(path.join(root,'all-payment-provers-stopped.json'),{aliceStopped:true,bobStopped:true,stoppedAt:new Date().toISOString()});
    const rebased=await publicBob(root,rebaseAnchor,payments);
    assert.equal(rebased.proofUnchanged,true);assert.equal(rebased.additionalProofs,0);
    // Carol holds the 100 payments. Bob never restarts his prover.
    cleanup=wallet(root,2,'carol-cleanup-prover');aliceCleanup=wallet(root,0,'alice-cleanup-prover');await Promise.all([cleanup.ready,aliceCleanup.ready]);
    let through=payments+2;
    for(const w of [cleanup,aliceCleanup]){
      for(;;){const s=await w.request({through,kind:'scan',label:'scan'});if(s.unspent_notes===0)break;
        const label=`cleanup-${through}`;await authorize(w,{through,kind:'exit',label});publicRebase(root,through,label);through++;await submit(through);
      }
    }
    const scans=await Promise.all([aliceCleanup.request({through,kind:'scan',label:'final'}),cleanup.request({through,kind:'scan',label:'final'})]);
    for(const s of scans){assert.equal(s.unspent_notes,0);assert.equal(s.reserve_remains,false);}
    await Promise.all([aliceCleanup.close(),cleanup.close()]);
    const count=through+1;assert.equal(count,2*payments+4);
    const ledger=new Map([[outpoint(source),source]]);let fees=0n;
    for(let i=0;i<count;i++){
      const tx=read(path.join(pub,number(i)+'.json'));for(const input of tx.inputs)assert.ok(ledger.delete(`${input.previousOutpoint.transactionId}:${input.previousOutpoint.index}`));
      tx.outputs.forEach((_,j)=>{const u=outputUtxo(tx,j);ledger.set(outpoint(u),u);});
      fees+=BigInt(read(path.join(pub,number(i)+'.metrics.json')).metrics.fee_sompi);
    }
    for(const u of ledger.values())assert.ok(await exactUtxo(rpc,u));
    assert.equal(await exactUtxo(rpc,outputUtxo(read(path.join(pub,number(through-1)+'.json')),0)),undefined);
    assert.equal([...ledger.values()].reduce((n,u)=>n+BigInt(u.amount),0n)+fees,BigInt(source.amount));
    // Retrieve accepted bodies, not just UTXO and mempool responses.
    const expectedBodies=new Map(Array.from({length:count},(_,step)=>{
      const transaction=read(path.join(pub,number(step)+'.json'));
      return [transaction.id,{step,transaction,fullHash:read(path.join(pub,number(step)+'.metrics.json')).full_hash}];
    }));
    let matched=new Map();
    while(matched.size<count){
      const snapshot=await acceptedSnapshot(rpc,anchor);matched=new Map();
      for(const row of snapshot.transactions){const expected=expectedBodies.get(row.transaction.verboseData.transactionId);
        if(expected){
          assert.deepEqual(canonicalRpcTx(row.transaction),expected.transaction);assert.equal(row.transaction.verboseData.hash,expected.fullHash);
          matched.set(expected.step,{step:expected.step,transaction:expected.transaction,acceptedHeader:row.header});
        }
      }if(matched.size<count)await sleep(1000);
    }
    save(path.join(root,'chain-confirmed.json'),{network:'testnet-10',exactBodyAndFullHashMatches:count,transactions:[...matched.values()].sort((a,b)=>a.step-b.step)});
    const result={complete:true,role,network:'testnet-10',binarySha256:binHash,sources:code,confirmedTransactions:count,paymentsAfterBobAuthorization:payments,
      bob:rebased,bobProverStoppedBeforeAlicePayment:true,allClaimsDrained:true,terminalReserveSpent:true,finalWalletScans:scans,
      totalFeeSompi:fees,finalOrdinaryOutputs:[...ledger.values()],completedAt:new Date().toISOString(),
      scope:'synthetic bounded TN10 experiment; not real-world anonymity, general liveness or cryptographic review'};
    save(path.join(root,'result.json'),result);console.log(stringify({root,...result}));
  }catch(error){for(const w of [alice,bob,cleanup,aliceCleanup])w?.kill();throw error;}finally{await rpc.disconnect();}
}
const [command,a,b,c,d,e]=process.argv.slice(2);
try{
  if(command==='sdk'){const r=checkOffline(path.resolve(a));console.log(JSON.stringify({sdkRoundTrips:r.transactions,offlinePass:r.offline_pass}));}
  else if(command==='smoke')await smoke(path.resolve(a));
  else if(command==='live')await live(path.resolve(a),path.resolve(b),c,path.resolve(d),e?path.resolve(e):undefined);
  else throw Error('usage: KPI_BINARY=... node compact.mjs sdk OFFLINE | live PARAMS BASE rehearsal|trial OFFLINE [REHEARSAL]');
}catch(error){console.error(String(error));process.exitCode=1;}

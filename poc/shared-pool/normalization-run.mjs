#!/usr/bin/env node
// H12 native adapter. Fresh trial identity per invocation; no rebroadcast.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {read,save,fileHash,transaction,connect,utxos,fundingDir,sdkPath} from './runtime.mjs';
import {confirm,exactUtxo,outputUtxo} from './chain.mjs';
import {mkdir,command,sandbox,audit,replace} from './deposits-common.mjs';
import {hashes,reconcile} from './normalization-reconcile.mjs';

const here=path.dirname(fileURLToPath(import.meta.url));
const binary=process.env.KPI_NORMALIZATION_BINARY??'/home/luke/projects/kaspa-privacy-self-funded/poc/self-funded/target/release/kpi-normalized-deposits';
const files=['normalization-run.mjs','normalization-client.mjs','normalization-reconcile.mjs','src/compact/normalization.rs',
  'src/compact/study.rs','src/compact/deposits/mod.rs','src/compact/deposits/covenant.rs',
  'src/compact/circuit.rs','src/compact/tree.rs','src/native.rs','src/protocol.rs',
  'runtime.mjs','chain.mjs','deposits-common.mjs'];
const pins=()=>Object.fromEntries(files.map(f=>[f,fileHash(path.join(here,f))]));

function create(base,plan,role){
  mkdir(base);const root=path.join(base,role+'-'+crypto.randomUUID());mkdir(root);mkdir(path.join(root,'logs'));
  fs.copyFileSync(plan,path.join(root,'plan.json'),fs.constants.COPYFILE_EXCL);
  fs.copyFileSync(binary,path.join(root,'program'),fs.constants.COPYFILE_EXCL);
  save(path.join(root,'identity.json'),{role,unfunded:true,createdAt:new Date().toISOString(),
    binarySha256:fileHash(binary),sources:pins(),planSha256:fileHash(plan)});
  console.log(JSON.stringify({stage:'fresh-unfunded-identity',root,role}));return root;
}

function client(root,arm,index,mode,history){
  const run=path.join(root,`${mode}-${arm}-${String(index).padStart(4,'0')}`);mkdir(run);
  save(path.join(run,'config.json'),{mode});
  const args=[...sandbox(),...(mode==='tn10'?['--share-net']:[]),
    '--ro-bind',path.join(root,'program'),'/program','--ro-bind',process.execPath,'/node',
    '--ro-bind',path.dirname(sdkPath),'/sdk','--setenv','KPI_SDK_PATH','/sdk/kaspa.js',
    '--ro-bind',path.join(root,`capabilities/${arm}-${String(index).padStart(4,'0')}.json`),'/saved.json',
    '--ro-bind',path.join(root,'public/descriptor.json'),'/source/descriptor.json',
    '--ro-bind',path.join(root,'public/vk.bin'),'/source/vk.bin','--bind',run,'/run','--dir','/software'];
  for(const f of ['normalization-client.mjs','runtime.mjs','chain.mjs','deposits-common.mjs'])args.push('--ro-bind',path.join(here,f),'/software/'+f);
  if(mode==='offline'){
    save(path.join(run,'accepted.json'),history);
    args.push('--ro-bind',path.join(run,'accepted.json'),'/accepted/history.json');
  }else args.push('--setenv','KPI_TN10_RPC',process.env.KPI_TN10_RPC??'ws://10.0.3.26:17210');
  audit(args,path.join(run,'isolation.json'),mode==='tn10');
  const stdout=fs.openSync(path.join(run,'stdout.log'),'wx',0o600),stderr=fs.openSync(path.join(run,'stderr.log'),'wx',0o600);
  let r;try{r=spawnSync('bwrap',[...args,'--','/node','/software/normalization-client.mjs','/run'],{stdio:['ignore',stdout,stderr]});}
  finally{fs.closeSync(stdout);fs.closeSync(stderr);}
  save(path.join(run,'process-exit.json'),{code:r.status,stoppedAt:new Date().toISOString()});
  assert.equal(r.status,0,fs.readFileSync(path.join(run,'stderr.log'),'utf8'));
  return read(path.join(run,'result.json'));
}

function finalCheck(root,history,label){
  const pub=path.join(root,'public');replace(path.join(pub,'history.json'),history);
  const got=command(path.join(root,'program'),['check',pub],path.join(root,'logs'),label);
  assert.equal(got.drained,true);assert.equal(got.state.cm_count,got.state.nf_count);return got;
}

function modelGate(study){
  assert.equal(read(path.join(study,'summary.json')).both_inference_screens_pass,true);
  assert.equal(read(path.join(study,'native/native-summary.json')).complete,true);
}

async function offline(study,params,base){
  modelGate(study);
  const plan=path.join(study,'native/native-plans/sparse-00.json');
  const root=create(base,plan,'offline'),log=path.join(root,'logs');
  // Reuse already generated genuine calibration capabilities only for this
  // adapter check. Both live identities independently generate fresh wallets.
  fs.cpSync(path.join(study,'native/native-runtime/prepared/sparse-00'),path.join(root,'prepared'),{recursive:true,errorOnExist:true,force:false});
  const old=read(path.join(root,'prepared/fresh-request.json'));
  const sources=[old.prefix.contexts[0][0],...old.prefix.contexts.slice(1).filter(x=>x.length===2).map(x=>x[1])];
  save(path.join(root,'sources.json'),sources);
  command(path.join(root,'program'),['bind',root,path.join(root,'sources.json'),'0'.repeat(64)],log,'bind');
  const prefix=read(path.join(root,'public/history.json')),exits=read(plan).events.filter(e=>e.kind==='exit');
  const arms={};
  for(const arm of ['saved','fresh']){
    let history=[...prefix];const receipts=[];
    for(let i=0;i<exits.length;i++){
      const r=client(root,arm,i,'offline',history);history.push(r.transaction);receipts.push(r);
    }
    const checked=finalCheck(root,history,arm+'-check');
    const fullHashes=hashes(path.join(root,'program'),history,path.join(root,arm+'-transactions.json'));
    for(const r of receipts)assert.equal(fullHashes.get(r.transaction.id),r.native.full_hash);
    assert.equal(new Set(exits.map(e=>e.owner)).size,4);
    arms[arm]={allFourWalletsPaid:true,claims:receipts.length,checked,unchangedProofs:true,
      exitProcessesHaveNoWalletOrPK:true,receipts};
  }
  // Hostile public inputs must fail in the new replay/exit adapter, independently
  // of H10's native covenant controls (which remain unchanged).
  const controls=[];
  function reject(name,history,descriptor,capability=0){
    const pub=path.join(root,'negative-'+name);mkdir(pub);
    if(name==='changed-descriptor')save(path.join(pub,'descriptor.json'),descriptor);
    else fs.copyFileSync(path.join(root,'public/descriptor.json'),path.join(pub,'descriptor.json'));
    fs.copyFileSync(path.join(root,'public/vk.bin'),path.join(pub,'vk.bin'));
    save(path.join(pub,'history.json'),history);const out=path.join(pub,'out');mkdir(out);
    const r=spawnSync(path.join(root,'program'),['exit',pub,path.join(root,`capabilities/fresh-${String(capability).padStart(4,'0')}.json`),out],{encoding:'utf8'});
    assert.notEqual(r.status,0,name);
    const expected={'missing-history':/missing history/,'missing-middle':/lineage discontinuity/,
      'changed-descriptor':/descriptor identity/,'inflated-reserve':/transaction id|transaction ID|mismatch|signature script|balance|output|conservation/i};
    assert.match(r.stderr,expected[name],name+' must reach its intended check');
    if(name!=='changed-descriptor')assert.doesNotMatch(r.stderr,/descriptor identity/);
    controls.push({name,rejected:true,reason:r.stderr.trim()});
  }
  const d=read(path.join(root,'public/descriptor.json'));
  reject('missing-history',[],d);reject('missing-middle',[prefix[0],...prefix.slice(2)],d);
  const altered=structuredClone(d);altered.initial_value=(BigInt(altered.initial_value)+1n).toString();reject('changed-descriptor',prefix,altered);
  const alteredHistory=structuredClone(prefix);alteredHistory[1].outputs[0].value=(BigInt(alteredHistory[1].outputs[0].value)+1n).toString();
  reject('inflated-reserve',alteredHistory,d);
  // Mutate the actual capability, preserving the descriptor pin. This reaches
  // the authorization/native checks instead of stopping at a changed hash.
  for(const name of ['wrong-domain','wrong-payout','malformed-proof']){
    const pub=path.join(root,'negative-'+name);mkdir(pub);
    for(const f of ['descriptor.json','vk.bin'])fs.copyFileSync(path.join(root,'public',f),path.join(pub,f));
    save(path.join(pub,'history.json'),prefix);
    const capability=read(path.join(root,'capabilities/fresh-0000.json'));
    const field=name==='malformed-proof'?'proof':'authorization';
    const bytes=Buffer.from(capability.bundle[field],'hex');bytes[name==='wrong-domain'?8:name==='wrong-payout'?189:0]^=1;
    capability.bundle[field]=bytes.toString('hex');save(path.join(pub,'capability.json'),capability);
    const out=path.join(pub,'out');mkdir(out);
    const r=spawnSync(path.join(root,'program'),['exit',pub,path.join(pub,'capability.json'),out],{encoding:'utf8'});
    assert.notEqual(r.status,0);controls.push({name,rejected:true,reason:r.stderr.trim()});
  }
  for(const [winner,loser] of [['saved','fresh'],['fresh','saved']]){
    const after=[...prefix,arms[winner].receipts[0].transaction];
    const pub=path.join(root,`duplicate-${winner}`);mkdir(pub);
    for(const f of ['descriptor.json','vk.bin'])fs.copyFileSync(path.join(root,'public',f),path.join(pub,f));
    save(path.join(pub,'history.json'),after);const out=path.join(pub,'out');mkdir(out);
    const r=spawnSync(path.join(root,'program'),['exit',pub,path.join(root,`capabilities/${loser}-0000.json`),out],{encoding:'utf8'});
    assert.notEqual(r.status,0);assert.match(r.stderr,/already spent/);controls.push({name:`${winner}-then-${loser}`,rejected:true,reason:r.stderr.trim()});
  }
  save(path.join(root,'offline-result.json'),{offline_pass:true,arms,controls,binarySha256:fileHash(binary),sources:pins(),planSha256:fileHash(plan)});
  console.log(JSON.stringify({stage:'offline-adapter-passed',root,claimsPerArm:exits.length}));
}

async function live(role,study,params,base,gatePath,rehearsalPath){
  modelGate(study);const gate=read(path.join(gatePath,'offline-result.json'));
  assert.equal(gate.offline_pass,true);assert.equal(gate.binarySha256,fileHash(binary));assert.deepEqual(gate.sources,pins());
  const planPath=path.join(study,'native/native-plans/sparse-00.json');assert.equal(gate.planSha256,fileHash(planPath));
  if(role==='trial'){
    const rehearsal=read(path.join(rehearsalPath,'result.json'));
    assert.equal(rehearsal.complete,true);assert.equal(rehearsal.role,'rehearsal');
    assert.equal(rehearsal.postBroadcastRecorderFailure,false);
    assert.equal(rehearsal.binarySha256,fileHash(binary));assert.deepEqual(rehearsal.sources,pins());
  }
  const root=create(base,planPath,role),log=path.join(root,'logs'),program=path.join(root,'program');
  command(program,['prepare',params,path.join(root,'plan.json'),path.join(root,'prepared')],log,'prover');
  save(path.join(root,'prover-stopped.json'),{stopped:true,at:new Date().toISOString()});
  console.log(JSON.stringify({stage:'genuine-proofs-ready-prover-stopped',root}));
  const plan=read(planPath),events=plan.events,exitEvents=events.filter(e=>e.kind==='exit');
  const needed=BigInt(plan.initial_value)+events.filter(e=>e.kind==='deposit').reduce((s,e)=>s+BigInt(e.deposit),0n)+102_000_000n;
  const {rpc,info}=await connect();const submitted=[];
  async function submit(raw,ctx,dir){
    mkdir(dir);for(const u of ctx)assert.ok(await exactUtxo(rpc,u),'missing input before first submission');
    const tx=transaction(raw);save(path.join(dir,'submission.json'),{transactionId:raw.id,at:new Date().toISOString(),noRebroadcast:true});
    try{const response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});assert.equal(response.transactionId,raw.id);save(path.join(dir,'response.json'),response);}
    finally{tx.free();}
    save(path.join(dir,'confirmed.json'),{outputs:await confirm(rpc,raw),at:new Date().toISOString()});submitted.push(raw);
  }
  try{
    save(path.join(root,'node.json'),{info});const anchor=(await rpc.getBlockDagInfo()).sink;
    const available=(await utxos(rpc,read(path.join(fundingDir,'funding.json')).address)).filter(u=>!u.is_coinbase&&BigInt(u.amount)>needed);
    available.sort((a,b)=>BigInt(a.amount)>BigInt(b.amount)?-1:1);assert.ok(available.length,'insufficient ordinary test funding');
    const source=available[0];save(path.join(root,'allocation-input.json'),source);
    const allocation=path.join(root,'allocation');mkdir(allocation);
    command(program,['allocate',root,path.join(root,'allocation-input.json'),fundingDir,allocation],log,'allocation');
    const allocationRaw=read(path.join(allocation,'0000.json'));
    await submit(allocationRaw,[source],allocation);
    command(program,['bind',root,path.join(allocation,'sources.json'),anchor],log,'bind');
    const pub=path.join(root,'public'),prefix=read(path.join(pub,'history.json')),contexts=read(path.join(pub,'contexts.json'));
    for(let i=0;i<prefix.length;i++)await submit(prefix[i],contexts[i],path.join(root,`growth-${i}`));
    console.log(JSON.stringify({stage:'four-deposits-two-payments-confirmed',role,root}));
    let history=[...prefix];
    for(let index=0;index<exitEvents.length;index++){
      const r=client(root,'fresh',index,'tn10');assert.equal(r.confirmed,true);assert.ok(await exactUtxo(rpc,r.payout));
      history.push(r.transaction);
      console.log(JSON.stringify({stage:'independent-claim-paid',role,claim:index+1,of:exitEvents.length}));
    }
    finalCheck(root,history,'complete-drain');
    const result=await reconcile(root,program);
    console.log(JSON.stringify({stage:'tn10-complete',role,root,totalFeeSompi:result.totalFeeSompi}));
  }finally{await rpc.disconnect();}
}

const [mode,studyArg,paramsArg,baseArg,gateArg,rehearsalArg]=process.argv.slice(2);
const study=path.resolve(studyArg),params=path.resolve(paramsArg),base=path.resolve(baseArg);
if(mode==='new')create(base,path.join(study,'native/native-plans/sparse-00.json'),'unfunded');
else if(mode==='offline')await offline(study,params,base);
else if(['rehearsal','trial'].includes(mode))await live(mode,study,params,base,path.resolve(gateArg),rehearsalArg&&path.resolve(rehearsalArg));
else throw Error('new|offline STUDY PARAMS BASE | rehearsal|trial STUDY PARAMS BASE GATE [REHEARSAL]');

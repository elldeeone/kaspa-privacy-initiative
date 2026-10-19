#!/usr/bin/env node
// Private trials stay outside Git. All live actions are restricted to TN10.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import readline from 'node:readline';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {read,save,fileHash,transaction,sdkPath} from './runtime.mjs';
import {mkdir,command,depositBinary,sandbox,audit,replace,pinSources} from './deposits-common.mjs';

export function create(params,base,role){
  mkdir(base);const root=path.join(base,role+'-'+crypto.randomUUID());
  const r=command(depositBinary,['init',params,root],base,role+'-init-'+crypto.randomUUID());
  mkdir(path.join(root,'logs'));mkdir(path.join(root,'software'));
  fs.copyFileSync(depositBinary,path.join(root,'software/program'),fs.constants.COPYFILE_EXCL);
  save(path.join(root,'identity.json'),{role,createdAt:new Date().toISOString(),unfunded:true,binarySha256:fileHash(depositBinary),sources:pinSources(),...r});
  return root;
}
export async function join(root,params,index,accepted=async()=>{}){
  const out=path.join(root,`prover-${index}`);mkdir(out);
  const args=[...sandbox(),'--ro-bind',path.join(root,'software/program'),'/program',
    '--ro-bind',path.join(root,'public'),'/public','--ro-bind',path.join(root,`wallet${index}.json`),'/wallet.json',
    '--ro-bind',params,'/params','--bind',out,'/output'];
  audit(args,path.join(out,'isolation.json'));
  const err=fs.openSync(path.join(out,'stderr.log'),'wx',0o600);
  const p=spawn('bwrap',[...args,'--','/usr/bin/time','-v','-o','/output/resources.txt','/program','join','/public','/wallet.json','/params',String(index),'/output'],
    {stdio:['pipe','pipe',err]});fs.closeSync(err);
  const exited=new Promise((resolve,reject)=>{p.on('error',reject);p.on('close',resolve);});
  const responses=[];
  for await(const line of readline.createInterface({input:p.stdout})){
    const r=JSON.parse(line);responses.push(r);
    if(r.admission_ready){
      const raw=read(path.join(out,'0000.json'));transaction(raw).free();
      await accepted(raw,out);
      const h=read(path.join(root,'public/history.json'));h.push(raw);replace(path.join(root,'public/history.json'),h);
      p.stdin.end('accepted\n');
      console.log(JSON.stringify({stage:'admission-accepted',wallet:index,proofMs:r.proof_ms}));
    }
  }
  const code=await exited;save(path.join(out,'process-exit.json'),{code,stoppedAt:new Date().toISOString()});
  assert.equal(code,0,fs.readFileSync(path.join(out,'stderr.log'),'utf8'));assert.equal(responses.at(-1).prepared,true);
  console.log(JSON.stringify({stage:'saved-proofs-ready-prover-stopped',wallet:index,count:responses.at(-1).count}));
}
export async function prepareOffline(params,base){
  const root=create(params,base,'offline');const id=read(path.join(root,'public/identity.json'));
  const sources=id.funding_scripts.map((spk,i)=>({txid:crypto.randomBytes(32).toString('hex'),index:0,
    amount:i===0?'1100000000':'1000000000',spk,daa:'0',is_coinbase:false}));
  save(path.join(root,'sources.json'),sources);
  command(path.join(root,'software/program'),['genesis',root,path.join(root,'sources.json'),'0'.repeat(64)],path.join(root,'logs'),'genesis');
  console.log(JSON.stringify({stage:'offline-identity',root}));
  for(let i=0;i<4;i++)await join(root,params,i);
  save(path.join(root,'prepared.json'),{complete:true,allFourProversExited:true,preparedProofs:8,broadcast:false});
  return root;
}
export async function exitClient(root,publicDir,saved,run,mode,historyFile,binary=depositBinary){
  mkdir(run);save(path.join(run,'config.json'),{mode,sources:['file:///missing/','file:///source/']});
  const software=path.dirname(fileURLToPath(import.meta.url));
  const args=[...sandbox(),...(mode==='tn10'?['--share-net']:[]),
    '--ro-bind',binary,'/program','--ro-bind',process.execPath,'/node',
    '--ro-bind',path.dirname(sdkPath),'/sdk','--setenv','KPI_SDK_PATH','/sdk/kaspa.js',
    '--ro-bind',saved,'/saved.json','--bind',run,'/run','--dir','/source',
    '--ro-bind',path.join(publicDir,'descriptor.json'),'/source/descriptor.json',
    '--ro-bind',path.join(publicDir,'vk.bin'),'/source/vk.bin','--dir','/software'];
  for(const file of ['deposits-client.mjs','deposits-common.mjs','runtime.mjs','chain.mjs'])args.push('--ro-bind',path.join(software,file),'/software/'+file);
  if(mode==='offline')args.push('--dir','/accepted','--ro-bind',historyFile,'/accepted/history.json');
  else args.push('--setenv','KPI_TN10_RPC',process.env.KPI_TN10_RPC??'ws://10.0.3.26:17210');
  audit(args,path.join(run,'isolation.json'),mode==='tn10');
  const out=fs.openSync(path.join(run,'stdout.log'),'wx',0o600),err=fs.openSync(path.join(run,'stderr.log'),'wx',0o600);
  const p=spawn('bwrap',[...args,'--','/node','/software/deposits-client.mjs','/run'],{stdio:['ignore',out,err]});fs.closeSync(out);fs.closeSync(err);
  const code=await new Promise((resolve,reject)=>{p.on('error',reject);p.on('close',resolve);});
  save(path.join(run,'process-exit.json'),{code,at:new Date().toISOString()});
  assert.equal(code,0,fs.readFileSync(path.join(run,'stderr.log'),'utf8'));return read(path.join(run,'result.json'));
}
export async function evaluate(root,params){
  const output=path.join(root,'evaluation-'+crypto.randomUUID());mkdir(output);
  assert.equal(read(path.join(root,'prepared.json')).allFourProversExited,true);
  const controlDir=path.join(output,'controls');mkdir(controlDir);
  const controls=command(depositBinary,['controls',root,params,controlDir],output,'controls');
  assert.equal(controls.complete,true);
  transaction(read(path.join(controlDir,'allocation/0000.json'))).free();
  const dataControls=[];
  for(const variant of ['missing-history','corrupt-genesis','missing-middle','wrong-vk']){
    const dir=path.join(output,variant);mkdir(dir);
    for(const f of ['descriptor.json','vk.bin'])fs.copyFileSync(path.join(root,'public',f),path.join(dir,f));
    const h=read(path.join(root,'public/history.json'));
    if(variant==='corrupt-genesis'){const d=read(path.join(dir,'descriptor.json'));d.identity.initial_commitment[0]^=1;replace(path.join(dir,'descriptor.json'),d);}
    if(variant==='missing-middle')h.splice(2,1);
    if(variant==='wrong-vk'){const p=path.join(dir,'vk.bin'),v=fs.readFileSync(p);v[0]^=1;fs.writeFileSync(p,v);}
    if(variant!=='missing-history')save(path.join(dir,'history.json'),h);
    const r=spawnSync(depositBinary,['check',dir],{encoding:'utf8'});assert.notEqual(r.status,0,variant);
    dataControls.push({control:variant,rejected:true});
  }
  // A valid prefix can replay locally. Freshness belongs to the separately
  // checked chain head/UTXO, not to the mirror or private proof.
  const stale=path.join(output,'stale-prefix');mkdir(stale);
  for(const f of ['descriptor.json','vk.bin'])fs.copyFileSync(path.join(root,'public',f),path.join(stale,f));
  const full=read(path.join(root,'public/history.json'));save(path.join(stale,'history.json'),full.slice(0,2));
  const staleOut=path.join(stale,'output');mkdir(staleOut);
  command(depositBinary,['exit',stale,path.join(root,'prover-0/saved.json'),'0',staleOut],stale,'local-validity');
  const attempted=read(path.join(staleOut,'0000.json'));
  assert.notEqual(attempted.inputs[0].previousOutpoint.transactionId,full.at(-1).id);
  dataControls.push({control:'valid-stale-prefix',locallyValid:true,rejectedByCurrentOutpointCheck:true});
  const orders=[[3,2,1,0],[0,1,2,3],[0,2,3,1],[0,1,3,2]],reports=[];
  for(const order of orders){
    const orderDir=path.join(output,'order-'+order.join(''));mkdir(orderDir);
    let history=read(path.join(root,'public/history.json'));assert.equal(history.length,5);
    const pub=path.join(orderDir,'public');mkdir(pub);
    for(const f of ['descriptor.json','vk.bin'])fs.copyFileSync(path.join(root,'public',f),path.join(pub,f));
    const wallets=[];
    for(const i of order){
      const snapshot=path.join(orderDir,`before-${i}.json`);save(snapshot,history);
      const r=await exitClient(root,pub,path.join(root,`prover-${i}/saved.json`),path.join(orderDir,`wallet-${i}`),'offline',snapshot);
      history.push(...r.exits.map(x=>x.transaction));wallets.push({wallet:i,...r});
    }
    save(path.join(pub,'history.json'),history);
    const checked=command(depositBinary,['check',pub],orderDir,'final-replay');assert.equal(checked.drained,true);
    assert.equal(checked.transactions,13);assert.equal(checked.state.cm_count,9);assert.equal(checked.state.nf_count,9);
    assert.equal(wallets.at(-1).exits.at(-1).terminal,true);reports.push({order,wallets,checked});
    console.log(JSON.stringify({stage:'offline-order-drained',order,transactions:13}));
  }
  const result={complete:true,offline_pass:true,controls,dataControls,orders:reports,binarySha256:fileHash(depositBinary),sources:pinSources(),broadcast:false};
  save(path.join(output,'offline-result.json'),result);console.log(JSON.stringify({stage:'offline-passed',output}));return output;
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
  const [mode,params,base]=process.argv.slice(2);
  if(mode==='new')console.log(JSON.stringify({root:create(path.resolve(params),path.resolve(base),'unfunded')}));
  else if(mode==='prepare-offline')console.log(JSON.stringify({prepared:await prepareOffline(path.resolve(params),path.resolve(base))}));
  else if(mode==='evaluate')await evaluate(path.resolve(params),path.resolve(base));
  else if(mode==='offline')await evaluate(await prepareOffline(path.resolve(params),path.resolve(base)),path.resolve(params));
  else throw Error('new PARAMS BASE | prepare-offline PARAMS BASE');
}

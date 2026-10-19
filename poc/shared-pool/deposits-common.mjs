import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {read,save,fileHash} from './runtime.mjs';
import {outputUtxo,canonicalRpcTx,acceptedSnapshot,exactUtxo,sleep} from './chain.mjs';

export const here=path.dirname(fileURLToPath(import.meta.url));
export const depositBinary=process.env.KPI_DEPOSIT_BINARY??'/home/luke/projects/kaspa-privacy-self-funded/poc/self-funded/target/release/kpi-deposits';
export const mkdir=p=>fs.mkdirSync(p,{recursive:true,mode:0o700});
export function replace(p,v){const tmp=p+'.next';save(tmp,v);fs.renameSync(tmp,p);}
export function command(binary,args,logdir,label){
  const out=fs.openSync(path.join(logdir,label+'.stdout.json'),'wx',0o600),err=fs.openSync(path.join(logdir,label+'.stderr.log'),'wx',0o600);
  let r;try{r=spawnSync('/usr/bin/time',['-v','-o',path.join(logdir,label+'.resources.txt'),binary,...args],
    {stdio:['ignore',out,err],env:{...process.env,RAYON_NUM_THREADS:'4'}});}finally{fs.closeSync(out);fs.closeSync(err);}
  assert.equal(r.status,0,`${label} failed: ${fs.readFileSync(path.join(logdir,label+'.stderr.log'),'utf8')}`);
  return read(path.join(logdir,label+'.stdout.json'));
}
export function sandbox(){return ['--unshare-all','--die-with-parent','--new-session','--clearenv',
  '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64',
  '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--setenv','PATH','/usr/bin:/bin','--setenv','RAYON_NUM_THREADS','4'];}
export function audit(args,out,network=false){
  const probe=`import pathlib,json
assert not pathlib.Path('/home/luke').exists()
assert not pathlib.Path('/params').exists() if ${network?'True':'False'} else True
print(json.dumps({'host_home_accessible':False,'mounts':pathlib.Path('/proc/mounts').read_text(),'interfaces':pathlib.Path('/proc/net/dev').read_text()}))`;
  const r=spawnSync('bwrap',[...args,'--','python3','-c',probe],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);
  save(out,JSON.parse(r.stdout));
}
export function reserveAfter(raw){
  if(!raw.payload)return outputUtxo(raw,0);
  const b=Buffer.from(raw.payload,'hex');assert.equal(b.length,3892);assert.equal(b[643],5);
  assert.ok(['KPICR01\0','KPICD01\0'].includes(b.subarray(0,8).toString()));
  return b.readUInt32LE(644)===b.readUInt32LE(648)?null:outputUtxo(raw,0);
}
export async function acceptedHistory(rpc,d){
  for(;;){
    const snapshot=await acceptedSnapshot(rpc,d.start_hash),rows=snapshot.transactions.map(r=>canonicalRpcTx(r.transaction));
    const byId=new Map(rows.map(t=>[t.id,t]));
    // The trial's ordinary source amounts/scripts come from accepted parent
    // transactions, not untrusted UTXO-context JSON supplied by the controller.
    for(const u of d.sources){const parent=byId.get(u.txid);assert.ok(parent,'accepted funding parent unavailable');
      const actual=outputUtxo(parent,u.index);assert.equal(actual.amount,u.amount);assert.equal(actual.spk,u.spk);}
    const first=byId.get(d.funding_txid);if(!first){await sleep(1000);continue;}
    const history=[first];let current=reserveAfter(first);const seen=new Set([first.id]);
    while(current){
      const next=[...byId.values()].filter(t=>t.inputs[0]?.previousOutpoint.transactionId===current.txid&&t.inputs[0]?.previousOutpoint.index===current.index);
      assert.ok(next.length<=1,'competing accepted reserve spends');if(!next.length)break;
      assert.ok(!seen.has(next[0].id));seen.add(next[0].id);history.push(next[0]);current=reserveAfter(next[0]);
    }
    if(current&&!await exactUtxo(rpc,current)){await sleep(1000);continue;}
    return {history,current,snapshot};
  }
}
export const pinSources=()=>Object.fromEntries(['Cargo.toml','Cargo.lock','src/lib.rs','src/bin/kpi-deposits.rs','src/compact/mod.rs','src/compact/experiment.rs','src/compact/deposits/mod.rs','src/compact/deposits/covenant.rs',
  'src/compact/deposits/harness.rs','src/compact/deposits/harness/controls.rs','src/compact/circuit.rs','src/compact/tree.rs',
  'src/native.rs','src/protocol.rs','deposits.mjs','deposits-common.mjs','deposits-client.mjs','deposits-live.mjs'].filter(f=>fs.existsSync(path.join(here,f))).map(f=>[f,fileHash(path.join(here,f))]));

// Synthetic public metadata only. No network, wallets or original registry data.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawn} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {initialize,reserve} from './relay_registry.mjs';

const H=c=>c.repeat(64),clone=value=>JSON.parse(JSON.stringify(value));
const hash=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const stages=['consolidate-0','consolidate-1','consolidate-2','genesis','round-01','round-02'];
const value={schema:'kpx8-replacement-relay-handover/v1',
  domain_hex32:'be2c62d1ca8714bcce51659dfe12c190acc42234c6b1c2ff3c0fa60cf653e480',
  financial_profile_sha256:'69a7adc46fc96b6a0368c48d4252290140ee500a5558749af7908624be9b923f',
  trial_id:'cfec7af9-5614-4af0-bf30-de1d24de7595',selection_sha256:H('a'),descriptor_sha256:H('b'),
  history_sha256:H('c'),checkpoint_sha256:H('d'),accepted_pool_prefix_txids:[H('4'),H('5'),H('6')],
  used_submissions:stages.map((stage,i)=>({stage,transaction_id:H(String(i+1)),status:'CONFIRMED'})),
  all_prior_pool_submissions_resolved:true,original_coordinator_prover_and_writers_stopped:true};
const bytes=value=>Buffer.from(JSON.stringify(value)+'\n');
const handover=bytes(value),sha=hash(handover);
const record={trial_id:value.trial_id,transaction_id:H('7'),previous_outpoint_hex36:H('6')+'00000000',
  case_sha256:H('8'),candidate_sha256:H('9'),last_checked_virtual_daa:'18446744073709551615'};

function fixture(t,ready=true){
 const parent=fs.mkdtempSync(path.join(os.tmpdir(),'kpx8-registry-public-test-'));
 t.after(()=>fs.rmSync(parent,{recursive:true,force:true}));
 const root=path.join(parent,'registry');if(ready)initialize(root,handover,sha);
 return {parent,root};
}

test('sealed same-byte reinitialization is durable and rejects a changed handover',t=>{
 const {root}=fixture(t);assert.deepEqual(initialize(root,handover,sha),value);
 for(const name of ['INITIALIZING','HANDOVER.json','SEALED']){
  const stat=fs.lstatSync(path.join(root,name));assert.equal(stat.mode&0o7777,0o400);assert.equal(stat.nlink,1);
 }
 const changed=clone(value);changed.history_sha256=H('e');const raw=bytes(changed);
 assert.throws(()=>initialize(root,raw,hash(raw)));
});

test('strict complete handover rejects ambiguous or unconfirmed input before creating a root',t=>{
 const {parent}=fixture(t,false);
 const changes=[v=>{v.extra=true;},v=>{v.all_prior_pool_submissions_resolved=false;},
  v=>{v.original_coordinator_prover_and_writers_stopped=1;},v=>{v.financial_profile_sha256=H('a');},
  v=>{v.trial_id=v.trial_id.toUpperCase();},v=>{v.used_submissions.pop();},
  v=>{v.used_submissions[0].status='ACKNOWLEDGED';},
  v=>{v.used_submissions[0].stage='genesis';},
  v=>{v.used_submissions[0].transaction_id=v.used_submissions[1].transaction_id;},
  v=>{v.accepted_pool_prefix_txids.reverse();},v=>{v.selection_sha256=1;}];
 changes.forEach((change,i)=>{
  const v=clone(value);change(v);const raw=bytes(v),root=path.join(parent,'bad-'+i);
  assert.throws(()=>initialize(root,raw,hash(raw)));assert.equal(fs.existsSync(root),false);
 });
 const duplicate=Buffer.from(handover.toString().replace('"schema":','"schema":"ignored","schema":'));
 assert.throws(()=>initialize(path.join(parent,'duplicate'),duplicate,hash(duplicate)));
 assert.throws(()=>initialize(path.join(parent,'wrong-sha'),handover,H('0')));
});

test('interrupted initialization and extra seal files never become a fresh registry',t=>{
 const {root}=fixture(t,false);fs.mkdirSync(root,{mode:0o700});
 fs.writeFileSync(path.join(root,'INITIALIZING'),sha+'\n',{mode:0o400,flag:'wx'});
 assert.throws(()=>initialize(root,handover,sha));assert.throws(()=>reserve(root,sha,'exit-01',record));
 const other=path.join(path.dirname(root),'complete');initialize(other,handover,sha);
 fs.writeFileSync(path.join(other,'unexpected'),'known synthetic metadata',{mode:0o400});
 assert.throws(()=>initialize(other,handover,sha));
});

test('stage, transaction and predecessor remain consumed across restarts and new labels',t=>{
 const {root}=fixture(t);const targets=reserve(root,sha,'exit-01',record);assert.equal(targets.length,3);
 for(const file of targets){assert.equal(fs.lstatSync(file).mode&0o7777,0o400);
  assert.equal(JSON.parse(fs.readFileSync(file)).record.last_checked_virtual_daa,'18446744073709551615');}
 initialize(root,handover,sha);
 assert.throws(()=>reserve(root,sha,'exit-01',{...record,transaction_id:H('a'),previous_outpoint_hex36:H('b')+'00000000'}));
 assert.throws(()=>reserve(root,sha,'exit-02',{...record,previous_outpoint_hex36:H('b')+'00000000'}));
 assert.throws(()=>reserve(root,sha,'exit-02',{...record,transaction_id:H('a')}));
 assert.equal(reserve(root,sha,'exit-02',{...record,transaction_id:H('a'),previous_outpoint_hex36:H('b')+'00000000'}).length,3);
});

test('every prior stage or transaction ID is refused, including a changed predecessor',t=>{
 const {root}=fixture(t);
 for(const prior of value.used_submissions){
  assert.throws(()=>reserve(root,sha,prior.stage,record));
  assert.throws(()=>reserve(root,sha,'exit-01',{...record,transaction_id:prior.transaction_id}));
 }
 assert.equal(fs.readdirSync(path.join(root,'predecessors')).length,0);
});

test('one surviving marker consumes all identities after a partial reservation',t=>{
 for(const survivor of ['predecessors','transactions','stages']){
  const {root}=fixture(t),targets=reserve(root,sha,'exit-01',record);
  for(const file of targets)if(path.basename(path.dirname(file))!==survivor)fs.unlinkSync(file);
  initialize(root,handover,sha);
  assert.throws(()=>reserve(root,sha,'exit-01',{...record,transaction_id:H('a'),previous_outpoint_hex36:H('b')+'00000000'}));
  assert.throws(()=>reserve(root,sha,'exit-02',{...record,previous_outpoint_hex36:H('b')+'00000000'}));
  assert.throws(()=>reserve(root,sha,'exit-02',{...record,transaction_id:H('a')}));
 }
});

test('record types, exact fields, u64 DAA and canonical stage/point encodings are mandatory',t=>{
 const {root}=fixture(t);
 const changes=[{trial_id:'00000000-0000-4000-8000-000000000000'},
  {transaction_id:H('0')},{previous_outpoint_hex36:H('0')+'00000000'},
  {previous_outpoint_hex36:H('6')+'0000000A'},{case_sha256:H('A')},{extra:true},
  ...['18446744073709551616','-1','01','+1','1.0','１',1,true].map(x=>({last_checked_virtual_daa:x}))];
 for(const change of changes)assert.throws(()=>reserve(root,sha,'exit-01',{...record,...change}));
 for(const stage of ['../exit','Exit-01','exit_01','',false])assert.throws(()=>reserve(root,sha,stage,record));
 assert.equal(reserve(root,sha,'exit-01',{...record,last_checked_virtual_daa:'0'}).length,3);
});

test('symlink roots, altered modes and hardlinked seals or reservation markers reject',t=>{
 const {root,parent}=fixture(t);
 const alias=path.join(parent,'alias');fs.symlinkSync(root,alias);
 assert.throws(()=>initialize(alias,handover,sha));
 const seal=path.join(root,'HANDOVER.json');fs.linkSync(seal,path.join(parent,'seal-link'));
 assert.throws(()=>initialize(root,handover,sha));fs.unlinkSync(path.join(parent,'seal-link'));
 const files=reserve(root,sha,'exit-01',record);fs.linkSync(files[0],path.join(parent,'intent-link'));
 assert.throws(()=>reserve(root,sha,'exit-02',{...record,transaction_id:H('a'),previous_outpoint_hex36:H('b')+'00000000'}));
 fs.unlinkSync(path.join(parent,'intent-link'));fs.chmodSync(path.join(root,'SEALED'),0o600);
 assert.throws(()=>initialize(root,handover,sha));
});

function race(root,parent,mode,index){
 const module=pathToFileURL(fileURLToPath(new URL('./relay_registry.mjs',import.meta.url))).href;
 const code=`import fs from 'node:fs';import {initialize,reserve} from ${JSON.stringify(module)};
 const [root,file,pin,mode,index]=process.argv.slice(1);const raw=fs.readFileSync(file);
 try{initialize(root,raw,pin);if(mode!=='init'){
 const r=JSON.parse(process.env.KPX_PUBLIC_TEST_RECORD);
 r.transaction_id=Number(index).toString(16).padStart(64,'0');reserve(root,pin,'exit-'+index,r);}
 process.stdout.write('GRANTED');}catch{process.stdout.write('REFUSED');}`;
 return new Promise((resolve,reject)=>{
  const child=spawn(process.execPath,['--input-type=module','-e',code,root,path.join(parent,'HANDOVER-PUBLIC.json'),sha,mode,String(index)],
    {env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',TZ:'UTC',KPX_PUBLIC_TEST_RECORD:JSON.stringify(record)},
      stdio:['ignore','pipe','pipe']});
  let out='',err='';child.stdout.on('data',b=>{out+=b;});child.stderr.on('data',b=>{err+=b;});
  child.on('error',reject);child.on('close',status=>status===0?resolve(out):reject(Error(err)));
 });
}

test('simultaneous initializers and competing sends cannot produce two grants',async t=>{
 const {root,parent}=fixture(t,false);fs.writeFileSync(path.join(parent,'HANDOVER-PUBLIC.json'),handover,{mode:0o400});
 const init=await Promise.all(Array.from({length:8},(_,i)=>race(root,parent,'init',i+20)));
 assert(init.includes('GRANTED'));assert.deepEqual(initialize(root,handover,sha),value);
 const attempts=await Promise.all(Array.from({length:8},(_,i)=>race(root,parent,'reserve',i+20)));
 assert.equal(attempts.filter(x=>x==='GRANTED').length,1);
 assert.equal(fs.readdirSync(path.join(root,'predecessors')).length,1);
});

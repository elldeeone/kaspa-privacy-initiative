import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {read,save,fileHash,number} from './runtime.mjs';
import {mkdir,copy,recoveryBinary,headFor,checkArchive,followAccepted} from './recovery-common.mjs';
import {launchLocal} from './recovery-sandbox.mjs';

export async function controls(root){
  const base=path.join(root,'controls');mkdir(base);
  const pub=path.join(root,'public'),rows=[];
  const txs=Array.from({length:6},(_,i)=>read(path.join(pub,number(i)+'.json')));
  const rewrite=(file,value)=>fs.writeFileSync(file,JSON.stringify(value));
  function fixture(name,owner=1,through=2){
    const dir=path.join(base,name),view=path.join(dir,'public');mkdir(view);
    for(const n of ['descriptor.json','vk.bin','source-utxo.json'])copy(path.join(pub,n),path.join(view,n));
    for(let i=0;i<=through;i++)copy(path.join(pub,number(i)+'.json'),path.join(view,number(i)+'.json'));
    save(path.join(view,'head.json'),headFor(txs.slice(0,through+1)));
    const backup=path.join(dir,'backup.json');copy(path.join(root,`backups/wallet${owner}.json`),backup);
    return {dir,view,backup};
  }
  function call(f,command='inspect'){
    const args=[command,f.view,f.backup];if(command==='exit'){mkdir(path.join(f.dir,'out'));args.push(path.join(f.dir,'out'));}
    return spawnSync(recoveryBinary,args,{encoding:'utf8',env:{...process.env,RAYON_NUM_THREADS:'4'}});
  }
  function reject(name,mutate,{owner=1,through=2,command='inspect'}={}){
    const f=fixture(name,owner,through);mutate(f);const r=call(f,command);
    assert.notEqual(r.status,0,`${name} accepted`);assert.equal(r.signal,null,`${name} crashed`);
    rows.push({control:name,rejected:true,error:r.stderr.trim()});
  }
  for(const owner of [0,1,2]){
    const f=fixture(`valid-wallet-${owner}`,owner);const r=call(f);assert.equal(r.status,0,r.stderr);assert.equal(JSON.parse(r.stdout).unspent_notes,1);
    const b=read(f.backup);assert.deepEqual(Object.keys(b.wallet).sort(),['native','spending','viewing']);
    if(owner!==0)assert.equal(b.initial_note,null);
  }
  reject('backup-pin',f=>{const b=read(f.backup);b.descriptor_sha256='0'.repeat(64);rewrite(f.backup,b);});
  reject('unknown-backup-field',f=>{const b=read(f.backup);b.future_note={};rewrite(f.backup,b);});
  reject('malformed-key',f=>{const b=read(f.backup);b.wallet.spending=[1];rewrite(f.backup,b);});
  for(const [name,change] of [
    ['wrong-network',d=>d.network='mainnet'],['wrong-genesis',d=>d.genesis='0'.repeat(64)],
    ['wrong-domain',d=>d.domain[0]^=1],['wrong-reserve',d=>d.reserve_sompi='1000000001'],
    ['noncanonical-amount',d=>d.reserve_sompi='01000000000'],['receiver-list-in-descriptor',d=>d.receivers=[]],
  ])reject(name,f=>{const p=path.join(f.view,'descriptor.json'),d=read(p);change(d);rewrite(p,d);const b=read(f.backup);b.descriptor_sha256=fileHash(p);rewrite(f.backup,b);});
  reject('corrupt-vk',f=>{const p=path.join(f.view,'vk.bin'),b=fs.readFileSync(p);b[0]^=1;fs.writeFileSync(p,b);});
  reject('corrupt-pk',f=>fs.writeFileSync(path.join(f.view,'pk.bin'),Buffer.from([1])),{command:'check-parameters'});
  reject('funding-context-substitution',f=>{const p=path.join(f.view,'source-utxo.json'),u=read(p);u.amount=(BigInt(u.amount)+1n).toString();rewrite(p,u);});
  reject('missing-middle',f=>fs.unlinkSync(path.join(f.view,'0001.json')));
  reject('missing-tail',f=>fs.unlinkSync(path.join(f.view,'0002.json')));
  reject('reordered-history',f=>{rewrite(path.join(f.view,'0001.json'),txs[2]);rewrite(path.join(f.view,'0002.json'),txs[1]);});
  reject('stale-endpoint',f=>{const p=path.join(f.view,'head.json'),h=read(p);h.through=1;rewrite(p,h);});
  reject('forged-current-reserve',f=>{const p=path.join(f.view,'head.json'),h=read(p);h.reserve.amount='1';rewrite(p,h);});
  reject('ciphertext-tampering',f=>{const p=path.join(f.view,'0002.json'),t=read(p),b=Buffer.from(t.payload,'hex');b[273]^=1;t.payload=b.toString('hex');rewrite(p,t);});
  reject('proof-tampering',f=>{const p=path.join(f.view,'0002.json'),t=read(p),b=Buffer.from(t.inputs[0].signatureScript,'hex');b[2]^=1;t.inputs[0].signatureScript=b.toString('hex');rewrite(p,t);});
  reject('wrong-initial-note',f=>{const b=read(f.backup);b.initial_note.rho[0]^=1;rewrite(f.backup,b);},{owner:0,through:0});
  for(const key of ['spending','viewing'])reject(`wrong-${key}-cannot-exit`,f=>{const b=read(f.backup);b.wallet[key][0]^=1;rewrite(f.backup,b);},{command:'exit'});
  reject('spent-note-cannot-exit',()=>{},{through:3,command:'exit'});
  const initial=fixture('initial-depositor-backup',0,0);let r=call(initial);assert.equal(r.status,0,r.stderr);assert.equal(JSON.parse(r.stdout).unspent_notes,1);
  const b=read(initial.backup);b.initial_note=null;rewrite(initial.backup,b);r=call(initial);assert.equal(r.status,0,r.stderr);assert.equal(JSON.parse(r.stdout).unspent_notes,0);
  rows.push({control:'initial-opening-needed-before-first-transfer',withOpening:1,keysOnly:0});
  for(const owner of [0,1,2]){
    const f=fixture(`terminal-wallet-${owner}`,owner,5),r=call(f);assert.equal(r.status,0,r.stderr);assert.equal(JSON.parse(r.stdout).unspent_notes,0);assert.equal(JSON.parse(r.stdout).reserve_remains,false);
  }
  assert.throws(()=>checkArchive({transactions:[txs[0],txs[2]]},txs));
  assert.equal(checkArchive({transactions:[txs[0]]},txs).fetchedSuccessors,5);
  const d=read(path.join(pub,'descriptor.json'));
  assert.deepEqual(followAccepted([...txs].reverse(),d),txs);
  assert.throws(()=>followAccepted(txs.slice(1),d));
  rows.push({control:'archive-omission-rejected-stale-prefix-extended',rejected:true});
  const run=path.join(base,'all-sources-missing');mkdir(run);save(path.join(run,'config.json'),{
    mode:'offline',sources:['file:///missing-one/','file:///missing-two/'],chainFile:'/chain/accepted.json'});
  const chain=path.join(base,'chain.json');save(chain,{transactions:txs.slice(0,3)});
  await assert.rejects(launchLocal({run,backup:path.join(root,'backups/wallet1.json'),source:path.join(root,'mirror-secondary'),chain}));
  assert.ok(!fs.existsSync(path.join(run,'output/exit-report.json')));assert.ok(read(path.join(run,'output/sources.json')).attempts.every(x=>!x.accepted));
  rows.push({control:'all-public-sources-unavailable',safeHalt:true,recoverySucceeded:false});
  const result={passed:true,cases:rows.length,controls:rows,validWalletScans:3,terminalWalletScans:3};save(path.join(root,'recovery-controls.json'),result);return result;
}

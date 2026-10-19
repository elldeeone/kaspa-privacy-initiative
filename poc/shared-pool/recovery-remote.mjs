#!/usr/bin/env node
// Host launcher on the recovery machine. Each wallet sees only its own backup.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const software=path.dirname(fileURLToPath(import.meta.url));
process.env.KPI_SDK_PATH=software+'/sdk/kaspa.js';
process.env.KPI_BINARY=software+'/kpi-compact';
process.env.KPI_RECOVERY_BINARY=software+'/kpi-recovery';
const {sandboxArgs}=await import('./recovery-sandbox.mjs');
const {read,save}=await import('./runtime.mjs');
const {digest}=await import('./recovery-common.mjs');
const [command,root,index]=process.argv.slice(2);
assert.ok(/^\/home\/ubuntu\/kpi-recovery-stage1(?:-[a-z0-9-]+)?\/trials\/(?:rehearsal|trial|cleanup)-[a-f0-9-]+$/.test(root),'unexpected remote trial path');
if(command==='hashes'){
  const result={};for(const f of ['descriptor.json','vk.bin','pk.bin','history.json'])result[f]=await digest(path.join(root,'public',f));
  console.log(JSON.stringify(result));
}else if(command==='run'){
  assert.ok(['0','1','2'].includes(index));const run=path.join(root,`recovered-${index}`),config=read(path.join(run,'config.json'));
  const args=sandboxArgs({backup:path.join(root,`backups/wallet${index}.json`),run,source:path.join(root,'public'),network:true,
    node:software+'/node',sdk:software+'/sdk',software,compact:software+'/kpi-compact',recover:software+'/kpi-recovery',rpc:config.rpcUrl});
  // This host denies unprivileged user namespaces. Root creates the mount/PID
  // isolation, then setpriv returns the client to ubuntu with no capabilities.
  // A nested root user namespace
  // cannot traverse ubuntu's private host directories; do not make them public.
  assert.deepEqual(args.slice(0,2),['--unshare-all','--share-net']);
  args.splice(0,2,'--unshare-pid','--unshare-ipc','--unshare-uts','--unshare-cgroup-try',
    '--cap-drop','ALL','--cap-add','CAP_SETUID','--cap-add','CAP_SETGID');
  const out=fs.openSync(path.join(run,'client.stdout.log'),'wx',0o600),err=fs.openSync(path.join(run,'client.stderr.log'),'wx',0o600);
  const child=spawn('sudo',['-n',software+'/bwrap',...args,'--','/usr/bin/setpriv',
    '--reuid',String(process.getuid()),'--regid',String(process.getgid()),'--clear-groups','--no-new-privs',
    '--inh-caps=-all','--ambient-caps=-all',
    '/software/node','/software/recovery-client.mjs','/run'],{stdio:['ignore',out,err]});
  fs.closeSync(out);fs.closeSync(err);
  const code=await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',resolve);});
  const ownership=spawnSync('sudo',['-n','chown','-R',`${process.getuid()}:${process.getgid()}`,run],{encoding:'utf8'});assert.equal(ownership.status,0,ownership.stderr);
  save(path.join(run,'process-exit.json'),{code,exitedAt:new Date().toISOString(),separateHost:true});
  assert.equal(code,0,fs.readFileSync(path.join(run,'client.stderr.log'),'utf8'));
  console.log(fs.readFileSync(path.join(run,'client.stdout.log'),'utf8'));
}else throw Error('hashes TRIAL_ROOT | run TRIAL_ROOT WALLET_INDEX');

import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {binary,sdkPath,save} from './runtime.mjs';
import {recoveryBinary} from './recovery-common.mjs';

const here=path.dirname(fileURLToPath(import.meta.url));
export function sandboxArgs({backup,run,source,chain,network=false,node=process.execPath,sdk=path.dirname(sdkPath),software=here,compact=binary,recover=recoveryBinary,rpc}){
  const args=['--unshare-all',...(network?['--share-net']:[]),'--die-with-parent','--new-session','--clearenv',
    '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64',
    '--proc','/proc','--dev','/dev','--tmpfs','/tmp','--setenv','PATH','/usr/bin:/bin','--setenv','RAYON_NUM_THREADS','4',
    '--dir','/software','--ro-bind',node,'/software/node','--ro-bind',compact,'/software/kpi-compact',
    '--ro-bind',recover,'/software/kpi-recovery','--ro-bind',sdk,'/sdk',
    '--setenv','KPI_SDK_PATH','/sdk/kaspa.js','--setenv','KPI_BINARY','/software/kpi-compact',
    '--setenv','KPI_RECOVERY_BINARY','/software/kpi-recovery','--ro-bind',backup,'/backup.json','--bind',run,'/run','--chdir','/run'];
  for(const name of ['recovery-client.mjs','recovery-common.mjs','runtime.mjs','chain.mjs'])args.push('--ro-bind',path.join(software,name),'/software/'+name);
  if(source)args.push('--dir','/sources','--ro-bind',source,'/sources/secondary');
  if(chain)args.push('--dir','/chain','--ro-bind',chain,'/chain/accepted.json');
  if(network)args.push('--dir','/etc','--ro-bind','/etc/resolv.conf','/etc/resolv.conf',
    '--ro-bind','/etc/hosts','/etc/hosts','--ro-bind','/etc/nsswitch.conf','/etc/nsswitch.conf');
  if(rpc)args.push('--setenv','KPI_TN10_RPC',rpc);
  return args;
}
export async function launchLocal(options){
  const args=sandboxArgs(options);
  const stdout=fs.openSync(path.join(options.run,'client.stdout.log'),'wx',0o600),stderr=fs.openSync(path.join(options.run,'client.stderr.log'),'wx',0o600);
  const child=spawn('bwrap',[...args,'--','/software/node','/software/recovery-client.mjs','/run'],{stdio:['ignore',stdout,stderr]});
  fs.closeSync(stdout);fs.closeSync(stderr);
  const code=await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',resolve);});
  save(path.join(options.run,'process-exit.json'),{code,exitedAt:new Date().toISOString()});
  assert.equal(code,0,fs.readFileSync(path.join(options.run,'client.stderr.log'),'utf8'));
}

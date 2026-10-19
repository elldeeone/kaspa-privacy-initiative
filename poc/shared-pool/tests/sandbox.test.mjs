// Exercise actual sibling-sandbox/FIFO startup, isolation and EOF shutdown.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';

test('wallet controls a network-isolated sibling prover through private FIFOs',async()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'kpi-sandbox-'));
  fs.mkdirSync(path.join(root,'public'));const key=path.join(root,'fixture-key');fs.writeFileSync(key,'public test fixture');
  const stub=path.join(root,'fixture-prover');
  fs.writeFileSync(stub,`#!/usr/bin/python3
import sys,json,pathlib
assert not pathlib.Path('/home/luke').exists()
assert pathlib.Path('/wallet.json').read_text() == 'public test fixture'
net=pathlib.Path('/proc/net/dev').read_text()
assert all(line.split(':')[0].strip() == 'lo' for line in net.splitlines() if ':' in line)
print(json.dumps({'ready':True,'parameter_load_ms':0}),flush=True)
for line in sys.stdin:
 print(json.dumps({'echo':json.loads(line),'networkUnshared':True}),flush=True)
`,{mode:0o700});
  process.env.KPI_BINARY=stub;
  const runtime=await import('../runtime.mjs');
  const prover=runtime.startWalletSidecar(root,key);let child;
  try{
    const source=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
    const script=`import assert from 'node:assert/strict';import fs from 'node:fs';import {startWallet} from '/software/src/runtime.mjs';assert.equal(fs.existsSync('/home/luke'),false);const p=startWallet('/trial',0);await p.ready;assert.deepEqual(await p.request({operation:'round-trip'}),{echo:{operation:'round-trip'},networkUnshared:true});await p.close();console.log('isolated round trip and prover EOF shutdown passed');`;
    child=spawn('bwrap',['--unshare-user','--unshare-pid','--unshare-ipc','--unshare-uts','--die-with-parent','--clearenv','--ro-bind','/usr','/usr','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--dir','/software','--ro-bind',process.execPath,'/software/node','--ro-bind',source,'/software/src','--ro-bind',path.dirname(runtime.sdkPath),'/sdk','--bind',root,'/trial','--setenv','KPI_SDK_PATH','/sdk/kaspa.js','--setenv','KPI_PROVER_CHANNEL','/trial/channel','--','/software/node','--input-type=module','-e',script],{stdio:['ignore','pipe','pipe']});
    let output='',error='';child.stdout.on('data',x=>output+=x);child.stderr.on('data',x=>error+=x);
    const code=await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',resolve);});
    assert.equal(code,0,error);assert.match(output,/EOF shutdown passed/);await prover.done;
    const record=JSON.parse(fs.readFileSync(path.join(root,'wallet0-isolated/prover-exit.json')));assert.equal(record.code,0);
  }finally{child?.kill('SIGTERM');prover.kill();await prover.done.catch(()=>{});fs.rmSync(root,{recursive:true,force:true});}
});

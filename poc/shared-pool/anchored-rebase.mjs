#!/usr/bin/env node
// Public-only wallet continuation: no note, spending/viewing key or proving key.
// Discover the accepted successor by reserve lineage, not a supplied winner ID.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {performance} from 'node:perf_hooks';
import {read,save,rust,connect,transaction,fileHash} from './runtime.mjs';
import {acceptedSnapshot,successor,canonicalRpcTx,outputUtxo,exactUtxo,confirm,sleep} from './chain.mjs';

const root=path.resolve(process.argv[2]);
const pub=path.join(root,'public'),out=path.join(root,'output');
assert.ok(!fs.existsSync('/home/luke'),'rebuilder sees host home');
assert.ok(!fs.existsSync(path.join(pub,'pk.bin')),'rebuilder has a proving key');
assert.ok(!fs.existsSync('/wallet.json'),'rebuilder has a wallet');
save(path.join(out,'isolation.json'),{hostHomeAccessible:false,provingKeyAccessible:false,walletAccessible:false,publicOnly:true,mounts:fs.readFileSync('/proc/mounts','utf8')});
const start=read(path.join(pub,'start.json'));
const original=read(path.join(pub,'bob.bundle.json'));
const prior=outputUtxo(read(path.join(pub,'0001.json')),0);
const {rpc,info}=await connect();
try {
  save(path.join(out,'node.json'),info);
  let found,snapshot;
  const discoveryStart=performance.now();
  while(!found){snapshot=await acceptedSnapshot(rpc,start.anchor);found=successor(snapshot,prior);if(!found)await sleep(1000);}
  const raw=canonicalRpcTx(found.transaction);
  transaction(raw).free();
  save(path.join(pub,'0002.json'),raw);
  save(path.join(out,'0002.inputs.json'),[prior]);
  const valid=rust(out,'validate-discovered',['validate',path.join(pub,'0002.json'),path.join(out,'0002.inputs.json')]);
  const current=outputUtxo(raw,0);assert.ok(await exactUtxo(rpc,current),'discovered successor is not unspent');
  save(path.join(out,'discovery.json'),{source:'getVirtualChainFromBlockV2 Full',selection:'spent reserve outpoint',acceptedHeader:found.header,pages:snapshot.pages,observedAt:snapshot.observedAt,discoveryMs:performance.now()-discoveryStart,transactionId:raw.id,nativeValidation:valid});
  const began=performance.now();
  const report=rust(out,'rebuild',['rebase',pub,'2',path.join(pub,'bob.bundle.json'),out]);
  const rebuildingMs=performance.now()-began;
  const exit=read(path.join(out,'0003.json'));
  assert.equal(exit.inputs[0].signatureScript.slice(4,260),original.proof,'private proof changed');
  assert.equal(exit.payload.slice(16,16+262*2),original.authorization,'authorization changed');
  assert.equal(read(path.join(pub,'bob.bundle.json')).proof,original.proof);
  const actual=await exactUtxo(rpc,current);assert.ok(actual);
  save(path.join(out,'0003.inputs.json'),[actual]);
  rust(out,'validate-current',['validate',path.join(out,'0003.json'),path.join(out,'0003.inputs.json')]);
  const tx=transaction(exit);
  save(path.join(out,'0003.submission.json'),{txid:exit.id,submittedAt:new Date().toISOString(),bodySha256:fileHash(path.join(out,'0003.json'))});
  let response;
  try {response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});}
  catch(error){save(path.join(out,'0003.response.json'),{accepted:false,error:String(error)});throw error;}
  finally{tx.free();}
  assert.equal(response.transactionId,exit.id);
  save(path.join(out,'0003.response.json'),{accepted:true,response});
  const outputs=await confirm(rpc,exit);
  save(path.join(out,'0003.confirmed.json'),{observedAt:new Date().toISOString(),outputs});
  save(path.join(out,'result.json'),{confirmed:true,transactionId:exit.id,proofUnchanged:true,authorizationUnchanged:true,additionalProofs:0,publicOnly:true,rebuildingMs,feeSompi:report.metrics.fee_sompi.toString(),payout:outputs[1],report});
  console.log(JSON.stringify({stage:'bob-payout-confirmed',transactionId:exit.id,rebuildingMs,additionalProofs:0}));
} finally {await rpc.disconnect();}

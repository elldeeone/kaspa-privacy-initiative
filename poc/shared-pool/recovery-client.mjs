#!/usr/bin/env node
// One fresh wallet: one backup, public mirrors, and an independent chain view.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {performance} from 'node:perf_hooks';
import {read,save,connect,transaction,rust,fileHash,rpcUrl} from './runtime.mjs';
import {confirm,exactUtxo,canonicalRpcTx,sleep} from './chain.mjs';
import {mkdir,copy,publicSource,followAccepted,liveHistory,writeHistory,checkArchive,recovery} from './recovery-common.mjs';

const root=path.resolve(process.argv[2]),config=read(path.join(root,'config.json'));
const backup='/backup.json',out=path.join(root,'output');mkdir(out);
assert.ok(!fs.existsSync('/home/luke')&&!fs.existsSync('/home/ubuntu'),'original home exposed');
assert.ok(!fs.existsSync('/wallet.json')&&!fs.existsSync('/manifest.json'),'experiment inputs exposed');
assert.ok(['offline','tn10'].includes(config.mode));
const status=Object.fromEntries(fs.readFileSync('/proc/self/status','utf8').split('\n')
  .filter(line=>/^(Uid|Gid|CapEff|CapPrm|NoNewPrivs):/.test(line)).map(line=>{const i=line.indexOf(':');return [line.slice(0,i),line.slice(i+1).trim()];}));
assert.equal(status.CapEff,'0000000000000000','wallet retains host capabilities');
save(path.join(out,'isolation.json'),{privateInputCount:1,onlyBackupMounted:true,originalHomeAccessible:false,
  originalManifestAccessible:false,mounts:fs.readFileSync('/proc/mounts','utf8'),pidNamespace:fs.readlinkSync('/proc/self/ns/pid'),
  networkDevices:fs.readFileSync('/proc/net/dev','utf8'),processStatus:status});
const began=performance.now();let rpc,info;
try{
  if(config.mode==='tn10'){assert.equal(config.rpcUrl,rpcUrl);({rpc,info}=await connect());save(path.join(out,'node.json'),{endpoint:rpcUrl,info});}
  let adopted;const attempts=[];
  for(let i=0;i<config.sources.length;i++){
    const view=path.join(root,`source-${i}`);
    try{
      const s=await publicSource(config.sources[i],view,backup);
      const history=rpc?await liveHistory(rpc,s.descriptor):{txs:followAccepted(read(config.chainFile).transactions,s.descriptor)};
      const archive=checkArchive(s.packet,history.txs);writeHistory(view,s.descriptor,history.txs);
      const checked=recovery(out,`source-${i}-check`,['check-parameters',view,backup]);
      assert.equal(checked.no_manifest,true);assert.equal(checked.unspent_notes,1,'bounded workload expects one recovered note');
      attempts.push({source:config.sources[i],accepted:true,bytes:s.bytes,...archive});
      adopted={view,...s,txs:history.txs,checked};break;
    }catch(error){attempts.push({source:config.sources[i],accepted:false,error:String(error)});}
  }
  save(path.join(out,'sources.json'),{attempts});assert.ok(adopted,'no authenticated complete public source');
  const discoveryMs=performance.now()-began;
  // Cold parameter decoding/proving blocks this JS thread. Do not leave a
  // WebSocket needing heartbeat processing open during that local operation.
  if(rpc){await rpc.disconnect();rpc=undefined;}
  const proof=recovery(out,'create-exit',['exit',adopted.view,backup,out]);
  const raw=read(path.join(out,proof.transaction_file));transaction(raw).free();
  assert.equal(proof.new_private_proofs,1);assert.equal(proof.payout_owned_by_backup,true);
  assert.equal(raw.outputs.at(-1).value,proof.payout.amount);assert.equal(raw.outputs.at(-1).scriptPublicKey,proof.payout.spk);
  let outputs=null;
  if(config.mode==='tn10'){
    ({rpc,info}=await connect());
    save(path.join(out,'node-after-proof.json'),{endpoint:rpcUrl,info,reconnectedBeforeCurrentStateCheck:true});
  }
  if(rpc){
    const prior=headForAdopted();const actual=await exactUtxo(rpc,prior);assert.ok(actual,'reserve changed during proving');
    save(path.join(out,'current-input.json'),[actual]);rust(out,'native-current',['validate',path.join(out,proof.transaction_file),path.join(out,'current-input.json')]);
    save(path.join(out,'submission.json'),{txid:raw.id,submittedAt:new Date().toISOString(),bodySha256:fileHash(path.join(out,proof.transaction_file))});
    const tx=transaction(raw);let response;
    try{response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});}
    catch(error){save(path.join(out,'response.json'),{accepted:null,error:String(error)});throw error;}
    finally{tx.free();}
    assert.equal(response.transactionId,raw.id);save(path.join(out,'response.json'),{accepted:true,response});
    outputs=await confirm(rpc,raw);save(path.join(out,'confirmed.json'),{outputs,observedAt:new Date().toISOString()});
    let accepted;
    for(;;){
      const h=await liveHistory(rpc,adopted.descriptor);
      const found=h.snapshot.transactions.find(x=>x.transaction.verboseData.transactionId===raw.id);
      if(found){
        assert.deepEqual(canonicalRpcTx(found.transaction),raw);assert.equal(found.transaction.verboseData.hash,proof.native.full_hash);
        accepted={transaction:raw,acceptedHeader:found.header,fullHash:found.transaction.verboseData.hash};
        const final=path.join(root,'final-public');mkdir(final);
        for(const n of ['descriptor.json','vk.bin'])copy(path.join(adopted.view,n),path.join(final,n));
        writeHistory(final,adopted.descriptor,h.txs);
        const scanned=recovery(out,'after-exit',['inspect',final,backup]);assert.equal(scanned.unspent_notes,0);
        break;
      }await sleep(1000);
    }
    save(path.join(out,'accepted.json'),accepted);
  }
  save(path.join(out,'result.json'),{complete:true,mode:config.mode,broadcast:!!rpc,confirmed:!!rpc,
    transaction:raw,proof,payout:proof.payout,outputs,publicDiscoveryMs:discoveryMs,totalMs:performance.now()-began,
    newPrivateProofs:1,privateBackupOnly:true,originalManifestUsed:false,sources:attempts});
  console.log(JSON.stringify({stage:'recovered-exit',mode:config.mode,transactionId:raw.id,payoutSompi:proof.payout.amount}));
  function headForAdopted(){return read(path.join(adopted.view,'head.json')).reserve;}
}finally{if(rpc)await rpc.disconnect();}

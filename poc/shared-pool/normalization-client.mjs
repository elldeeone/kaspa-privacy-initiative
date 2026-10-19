// One isolated exit: its own previously prepared capability and pinned public
// descriptor/VK, plus independently fetched accepted history. No wallet or PK.
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {read,save,fileHash,transaction,connect} from './runtime.mjs';
import {confirm,exactUtxo,outputUtxo} from './chain.mjs';
import {mkdir,command,acceptedHistory} from './deposits-common.mjs';

const run=process.argv[2],config=read(path.join(run,'config.json')),saved=read('/saved.json');
assert.ok(['offline','tn10'].includes(config.mode));
assert.equal(saved.descriptor_sha256,fileHash('/source/descriptor.json'));
const descriptor=read('/source/descriptor.json');
assert.equal(descriptor.vk_sha256,fileHash('/source/vk.bin'));
assert.equal(descriptor.network,'testnet-10');
for(const name of ['/params','/wallet.json','/home','/other-wallets'])assert.ok(!fs.existsSync(name));
const pub=path.join(run,'public');mkdir(pub);
for(const name of ['descriptor.json','vk.bin'])fs.copyFileSync('/source/'+name,path.join(pub,name),fs.constants.COPYFILE_EXCL);
let rpc;
try{
  let history;
  if(config.mode==='tn10'){
    rpc=(await connect()).rpc;
    history=(await acceptedHistory(rpc,descriptor)).history;
  }else history=read('/accepted/history.json');
  save(path.join(pub,'history.json'),history);
  const out=path.join(run,'exit');mkdir(out);
  const result=command('/program',['exit',pub,'/saved.json',out],out,'settlement');
  assert.equal(result.unchanged_proof_and_authorization,true);
  const raw=read(path.join(out,'0000.json')),tx=transaction(raw);
  try{
    if(rpc){
      assert.ok(await exactUtxo(rpc,outputUtxo(history.at(-1),0)),'reserve changed before submission');
      save(path.join(out,'submission.json'),{transactionId:raw.id,at:new Date().toISOString(),noRebroadcast:true});
      const response=await rpc.submitTransaction({transaction:tx,allowOrphan:false});
      assert.equal(response.transactionId,raw.id);save(path.join(out,'response.json'),response);
      save(path.join(out,'confirmed.json'),{outputs:await confirm(rpc,raw),at:new Date().toISOString()});
      assert.ok(await exactUtxo(rpc,result.payout));
    }
  }finally{tx.free();}
  save(path.join(run,'result.json'),{complete:true,mode:config.mode,noWalletOrProvingKey:true,
    ownCapabilityOnly:true,savedSha256:fileHash('/saved.json'),confirmed:!!rpc,...result,transaction:raw});
}finally{if(rpc)await rpc.disconnect();}

#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {read,save,rust,binary,fileHash,number,connect,utxos,fundingDir,transaction,rpcUrl} from './runtime.mjs';
import {confirm,exactUtxo,outputUtxo,acceptedSnapshot,canonicalRpcTx,sleep} from './chain.mjs';
import {mkdir,copy,recovery,recoveryBinary} from './recovery-common.mjs';
import {createIdentity,restoreIdentity,preparePayments,makeArchive,finishAccounting,sources} from './recovery-trial.mjs';
const quote=s=>"'"+String(s).replaceAll("'","'\\''")+"'";
const host=process.env.KPI_RECOVERY_HOST??'ubuntu@10.0.3.26';
const remoteBase=process.env.KPI_RECOVERY_REMOTE??'/home/ubuntu/kpi-recovery-stage1';
const recoveryRpc=process.env.KPI_RECOVERY_RPC??'wss://vector-10.kaspa.green/kaspa/testnet-10/wrpc/borsh';
const archiveHost=process.env.KPI_ARCHIVE_HOST;
function shell(command){const r=spawnSync('ssh',['-o','BatchMode=yes',host,command],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);return r.stdout;}
function scp(from,to){const r=spawnSync('scp',['-q','-r',from,to],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);}
async function remote(command){
  const child=spawn('ssh',['-o','BatchMode=yes',host,command],{stdio:['ignore','inherit','inherit']});
  await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',c=>c===0?resolve():reject(Error(`remote recovery exited ${c}`)));});
}
async function remoteRead(command){
  const child=spawn('ssh',['-o','BatchMode=yes',host,command],{stdio:['ignore','pipe','pipe']});
  let out='',err='';child.stdout.on('data',b=>out+=b);child.stderr.on('data',b=>err+=b);
  await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',c=>c===0?resolve():reject(Error(err)));});
  return out;
}
async function archiveServer(dir){
  const allowed=new Set(['descriptor.json','vk.bin','pk.bin','history.json']);
  const server=http.createServer((req,res)=>{
    const name=req.url.slice(1);if(!allowed.has(name)){res.writeHead(404);res.end();return;}
    res.writeHead(200,{'content-length':fs.statSync(path.join(dir,name)).size});fs.createReadStream(path.join(dir,name)).pipe(res);
  });
  await new Promise(resolve=>server.listen(0,'0.0.0.0',resolve));return server;
}
async function live(role,params,base,offline,rehearsal){
  assert.ok(['rehearsal','trial','cleanup'].includes(role));assert.ok(archiveHost,'KPI_ARCHIVE_HOST must identify the original host on the LAN');
  const gate=read(path.join(offline,'offline-result.json'));assert.equal(gate.offline_pass,true);
  assert.deepEqual(gate.sources,sources());assert.equal(gate.recoveryBinarySha256,fileHash(recoveryBinary));assert.equal(gate.compactBinarySha256,fileHash(binary));
  if(role==='trial'){const r=read(path.join(rehearsal,'result.json'));assert.equal(r.complete,true);assert.equal(r.role,'rehearsal');assert.deepEqual(r.sources,sources());}
  const root=role==='cleanup'?restoreIdentity(rehearsal,base,role):createIdentity(params,base,role),pub=path.join(root,'public'),logs=path.join(root,'logs');
  const remoteRoot=remoteBase+'/trials/'+path.basename(root);
  console.log(JSON.stringify({stage:'identity-created',root,role}));
  const {rpc,info}=await connect();let server;
  try{
    save(path.join(root,'node-before.json'),{endpoint:rpcUrl,info,feeEstimate:await rpc.getFeeEstimate()});
    let anchor;
    if(role==='cleanup'){
      anchor=read(path.join(pub,'descriptor.json')).start_hash;
      assert.ok(await exactUtxo(rpc,outputUtxo(read(path.join(pub,'0002.json')),0)),
        'cleanup requires the interrupted pool to remain at its pre-exit state');
    }else{
    const funding=read(path.join(fundingDir,'funding.json'));assert.equal(funding.network,'testnet-10');
    const rows=(await utxos(rpc,funding.address)).filter(u=>!u.is_coinbase&&BigInt(u.amount)>1_001_000_000n).sort((a,b)=>BigInt(a.amount)>BigInt(b.amount)?-1:1);
    assert.ok(rows.length,'insufficient ordinary testnet funding');const source=rows[0];save(path.join(root,'funding-input.json'),source);
    rust(logs,'fund',['fund',root,path.join(root,'funding-input.json'),path.join(fundingDir,'funding.key')]);
    anchor=(await rpc.getBlockDagInfo()).sink;
    recovery(logs,'seal',['seal',root,anchor]);
    async function submit(step){
      const tx=read(path.join(pub,number(step)+'.json')),prior=step===0?source:outputUtxo(read(path.join(pub,number(step-1)+'.json')),0);
      const actual=await exactUtxo(rpc,prior);assert.ok(actual);save(path.join(logs,number(step)+'.inputs.json'),[actual]);
      rust(logs,number(step)+'-validate',['validate',path.join(pub,number(step)+'.json'),path.join(logs,number(step)+'.inputs.json')]);
      save(path.join(logs,number(step)+'.submission.json'),{txid:tx.id,submittedAt:new Date().toISOString(),bodySha256:fileHash(path.join(pub,number(step)+'.json'))});
      const encoded=transaction(tx);let response;
      try{response=await rpc.submitTransaction({transaction:encoded,allowOrphan:false});}
      catch(error){save(path.join(logs,number(step)+'.response.json'),{accepted:null,error:String(error)});throw error;}
      finally{encoded.free();}
      assert.equal(response.transactionId,tx.id);save(path.join(logs,number(step)+'.response.json'),{accepted:true,response});
      save(path.join(logs,number(step)+'.confirmed.json'),{outputs:await confirm(rpc,tx),observedAt:new Date().toISOString()});
      console.log(JSON.stringify({stage:'confirmed',step,txid:tx.id}));
    }
    await submit(0);await preparePayments(root,submit);
    }
    const mirror=path.join(root,'mirror-secondary');makeArchive(root,mirror);
    server=await archiveServer(mirror);const primary=`http://${archiveHost}:${server.address().port}/`;
    shell('mkdir -p '+quote(remoteRoot+'/backups')+' '+quote(remoteRoot+'/public'));
    for(const f of ['descriptor.json','vk.bin','pk.bin','history.json'])scp(path.join(mirror,f),host+':'+remoteRoot+'/public/'+f);
    for(let i=0;i<3;i++)scp(path.join(root,`backups/wallet${i}.json`),host+':'+remoteRoot+`/backups/wallet${i}.json`);
    const remoteHashes=JSON.parse(shell(quote(remoteBase+'/software/node')+' '+quote(remoteBase+'/software/recovery-remote.mjs')+' hashes '+quote(remoteRoot)));
    for(const f of ['descriptor.json','vk.bin','pk.bin','history.json'])assert.equal(remoteHashes[f],fileHash(path.join(mirror,f)));
    const originalReachable=await remoteRead('curl --fail --silent '+quote(primary+'descriptor.json'));assert.equal(JSON.parse(originalReachable).funding.txid,read(path.join(pub,'descriptor.json')).funding.txid);
    await new Promise(resolve=>server.close(resolve));server=null;
    save(path.join(root,'original-source-stopped.json'),{primary,stopped:true,remoteArchiveVerified:true,at:new Date().toISOString()});
    const wallets=[];
    for(const index of [1,2,0]){
      const local=path.join(root,`recovered-${index}`);mkdir(local);
      save(path.join(local,'config.json'),{mode:'tn10',rpcUrl:recoveryRpc,sources:[primary,'file:///sources/secondary/']});
      shell('mkdir -p '+quote(remoteRoot+`/recovered-${index}`));scp(path.join(local,'config.json'),host+':'+remoteRoot+`/recovered-${index}/config.json`);
      await remote(quote(remoteBase+'/software/node')+' '+quote(remoteBase+'/software/recovery-remote.mjs')+' run '+quote(remoteRoot)+' '+quote(String(index)));
      scp(host+':'+remoteRoot+`/recovered-${index}/output`,local+'/output');
      scp(host+':'+remoteRoot+`/recovered-${index}/process-exit.json`,local+'/process-exit.json');
      const r=read(path.join(local,'output/result.json'));assert.equal(r.confirmed,true);assert.equal(r.newPrivateProofs,1);
      assert.equal(r.sources[0].accepted,false);assert.equal(r.sources[1].accepted,true);
      const step=wallets.length+3;
      for(const suffix of ['.json','.metrics.json'])copy(path.join(local,'output',number(step)+suffix),path.join(pub,number(step)+suffix));
      assert.ok(await exactUtxo(rpc,r.payout),'original node does not confirm recovered payout');
      wallets.push({wallet:index,...r});console.log(JSON.stringify({stage:'independent-wallet-payout',wallet:index,payoutSompi:r.payout.amount,txid:r.transaction.id}));
    }
    const accounting=finishAccounting(root);
    for(const u of accounting.finalOrdinaryOutputs)assert.ok(await exactUtxo(rpc,u));
    const expected=new Map(Array.from({length:6},(_,i)=>{const tx=read(path.join(pub,number(i)+'.json'));return [tx.id,{tx,hash:read(path.join(pub,number(i)+'.metrics.json')).full_hash}];}));
    let matches;
    for(;;){const snap=await acceptedSnapshot(rpc,anchor);matches=[];
      for(const row of snap.transactions){const e=expected.get(row.transaction.verboseData.transactionId);if(e){assert.deepEqual(canonicalRpcTx(row.transaction),e.tx);assert.equal(row.transaction.verboseData.hash,e.hash);matches.push({transaction:e.tx,fullHash:e.hash,header:row.header});}}
      if(new Set(matches.map(x=>x.transaction.id)).size===6)break;await sleep(1000);
    }
    save(path.join(root,'chain-confirmed.json'),{transactions:matches,exactBodiesAndFullHashes:6});
    const result={complete:true,role,...read(path.join(root,'identity.json')),accounting,wallets,originalsStopped:true,
      recoveryHost:'separate TN10 server',originalRpc:rpcUrl,recoveryRpc,publicArchiveFailover:true,
      confirmedTransactions:6,completedAt:new Date().toISOString(),scope:'Three synthetic independent wallet processes; not three humans, cryptographic audit or network anonymity'};
    save(path.join(root,'result.json'),result);console.log(JSON.stringify({stage:'live-complete',role,root,feeSompi:accounting.totalFeeSompi}));
  }finally{if(server)await new Promise(resolve=>server.close(resolve));await rpc.disconnect();}
}
const [role,params,base,offline,rehearsal]=process.argv.slice(2);
await live(role,path.resolve(params),path.resolve(base),path.resolve(offline),rehearsal?path.resolve(rehearsal):undefined);

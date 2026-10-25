// Synthetic connection-lifecycle controls. No network or financial acceptance.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import {spawnSync} from 'node:child_process';
import test from 'node:test';
import {execute} from './delta.mjs';
import {CHILD_DOMAIN} from './selection.mjs';
import {GENESIS,canonicalTransaction,loadSdk,script,sha,stringify} from './wire.mjs';

const sdk=loadSdk();
function header(score,parent='00'.repeat(32)) {
  const raw={hash:'00'.repeat(32),version:2,parentsByLevel:[[parent]],hashMerkleRoot:'00'.repeat(32),
    acceptedIdMerkleRoot:'00'.repeat(32),utxoCommitment:'00'.repeat(32),timestamp:String(score),
    bits:1,nonce:'0',daaScore:String(score),blueScore:String(score),
    blueWork:BigInt(score).toString(16).padStart(48,'0'),pruningPoint:'00'.repeat(32)};
  const value=new sdk.Header({...raw,timestamp:BigInt(score),nonce:0n,daaScore:BigInt(score),
    blueScore:BigInt(score),blueWork:BigInt(score)});
  try {raw.hash=value.finalize();}finally {value.free();}return raw;
}
function write(root,name,value) {
  const raw=Buffer.isBuffer(value)?value:Buffer.from(stringify(value)+'\n'),file=path.join(root,name);
  fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,raw,{flag:'wx'});
  return {path:file,sha256:sha(raw),bytes:raw.length};
}
function fixture(complete=false) {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'kpi-delta-transport-')),anchor=header(0),end=header(1,anchor.hash);
  const selected={schema:'kpx8-GN3-selection/v1',network_id:'testnet-10',genesis_hash_hex:GENESIS,
    domain_hex32:CHILD_DOMAIN,state_magic_hex8:Buffer.from('KPX8ST01').toString('hex'),
    financial_profile_sha256:'11'.repeat(32),native_tail_hex:'aa',native_tail_sha256:sha(Buffer.from('aa','hex'))};
  const selection=write(root,'selection.json',selected),redeem=Buffer.alloc(115);
  Buffer.from('4c704b50583853543031','hex').copy(redeem);Buffer.from(CHILD_DOMAIN,'hex').copy(redeem,10);
  redeem.writeUInt32LE(3,74);redeem.writeUInt32LE(1,110);redeem[114]=0xaa;
  const d={schema:'kpx8-gn3-network-descriptor/v1',network_id:'testnet-10',genesis_hash_hex:GENESIS,
    financial_profile_sha256:selected.financial_profile_sha256,trial_id:'11111111-1111-4111-8111-111111111111',
    founding_outpoint:{transactionId:sha('synthetic-funding'),index:0},birth_start_hash:anchor.hash,
    initial_redeem_hex:redeem.toString('hex'),initial_redeem_sha256:sha(redeem)};
  let funding={verboseData:{transactionId:d.founding_outpoint.transactionId},inputs:[]},reserveScript;
  if(complete) {
    const spk=sdk.payToScriptHashScript(redeem);
    try {reserveScript=script(spk);}finally {spk.free();}
    const payload=Buffer.alloc(1576);Buffer.from('KPX8GN01').copy(payload);
    Buffer.from(selected.financial_profile_sha256,'hex').copy(payload,8);
    Buffer.from(CHILD_DOMAIN,'hex').copy(payload,40);
    Buffer.from(d.trial_id.replaceAll('-',''),'hex').copy(payload,72);
    const inputScript='000020'+'11'.repeat(32)+'ac';
    const entries=Array.from({length:3},(_,i)=>({outpoint:{transactionId:sha(`synthetic-input-${i}`),index:0},
      amount:'100000000',scriptPublicKey:inputScript,blockDaaScore:'0',isCoinbase:false,covenantId:null}));
    const tx=new sdk.Transaction({version:1,inputs:entries.map(entry=>({previousOutpoint:entry.outpoint,
      signatureScript:'',sequence:0n,computeBudget:0,sigOpCount:0,utxo:{...entry,amount:100000000n,blockDaaScore:0n}})),
      outputs:[{value:299999999n,scriptPublicKey:reserveScript}],lockTime:0n,subnetworkId:'00'.repeat(20),
      gas:0n,payload:payload.toString('hex'),storageMass:0n});
    try {tx.finalize();funding=canonicalTransaction(tx);}finally {tx.free();}
    funding.verboseData={transactionId:funding.id};
    funding.inputs=funding.inputs.map((input,i)=>({...input,verboseData:{utxoEntry:entries[i]}}));
    d.founding_outpoint.transactionId=funding.id;
  }
  const descriptor=write(root,'descriptor.json',d);
  const pageRaw=Buffer.from(stringify({removedChainBlockHashes:[],addedChainBlockHashes:[end.hash],
    chainBlockAcceptedTransactions:[{chainBlockHeader:end,acceptedTransactions:[funding]}]})+'\n');
  const gz=zlib.gzipSync(pageRaw),page=write(root,'old/pages/00000.json.gz',gz);
  const record={path:'pages/00000.json.gz',request:{startHash:anchor.hash,dataVerbosityLevel:'Full',minConfirmationCount:20},
    gzip_sha256:page.sha256,gzip_bytes:gz.length,decoded_sha256:sha(pageRaw),decoded_bytes:pageRaw.length,encoding:'synthetic Full fixture'};
  const fetched=write(root,'old/fetch.json',{schema:'kpx8-gn3-network-fetch/v1',status:'FETCHED_PENDING_REPLAY',
    network_id:'testnet-10',genesis_hash_hex:GENESIS,selection_file_sha256:selection.sha256,
    descriptor_file_sha256:descriptor.sha256,descriptor:d,pages:[record],coverage:{complete:true,frontier_seen:true,
      pruned:false,start_hash:anchor.hash,end_cursor:end.hash,frontier:end,anchor_header:anchor,
      initial_sink:header(100),removed_chain_block_hashes:[],missing:[],min_confirmation_count:20,accepted_transaction_rows_scanned:1}});
  const handoff=write(root,'handoff.json',{schema:'kpx8-confirmed-transition-handoff/v1',
    status:'RECORDED_VALIDATING_NODE_PREFIX_FINANCIAL_AND_NATIVE_PASS',submission_performed:false,
    selectors:{selection,descriptor,'fetch.json':fetched},full_prefix_pages:[page]});
  return {root,selection,descriptor,handoff,output:path.join(root,'new'),d,funding,reserveScript,anchor,end};
}
async function disconnectedControl() {
  const f=fixture(),events=[];let next=0;
  class RpcClient {
    constructor(){this.id=++next;this.connected=false;events.push({event:'create',id:this.id});}
    async connect(){this.connected=true;events.push({event:'connect',id:this.id,
      cachePrepared:fs.existsSync(path.join(f.output,'attempt-001/cache/pages/00000.json.gz'))});}
    async getServerInfo(){
      if(!this.connected)throw new Error('WebSocket is not connected');
      this.connected=false;
      throw new Error(this.id===1?'WebSocket disconnected':'CONTROL_FRESH_FULL_FALLBACK_REACHED');
    }
    async disconnect(){this.connected=false;events.push({event:'disconnect',id:this.id});}
  }
  try {
    const result=await execute(f.selection.path,f.selection.sha256,f.descriptor.path,f.descriptor.sha256,
      f.handoff.path,f.handoff.sha256,f.output,['ws://127.0.0.1:1'],{...sdk,RpcClient});
    return {events,result};
  }finally {fs.rmSync(f.root,{recursive:true});}
}

test('authenticate and copy the complete local cache before opening its socket',async()=>{
  const {events}=await disconnectedControl(),first=events.find(row=>row.event==='connect');
  assert.equal(first.cachePrepared,true,'cache preparation must precede the first live RPC connection');
});

test('replace a disconnected incremental socket before the unchanged full fallback',async()=>{
  const {events,result}=await disconnectedControl(),connected=events.filter(row=>row.event==='connect');
  assert.equal(connected.length,2,'full fallback needs a genuinely fresh client/connection');
  assert.notEqual(connected[0].id,connected[1].id);
  assert.match(result.attempts[0].error,/CONTROL_FRESH_FULL_FALLBACK_REACHED/);
});

test('entire successful execute output passes the exact frozen integer-only replay parser',async()=>{
  const f=fixture(true),headers=[f.anchor,f.end];
  for(let i=2;i<=100;i++)headers.push(header(i,headers.at(-1).hash));
  const byHash=new Map(headers.map((h,i)=>[h.hash,i]));
  class RpcClient {
    async connect(){} async disconnect(){}
    async getServerInfo(){return {networkId:'testnet-10',serverVersion:'2.1.0',isSynced:true,hasUtxoIndex:true};}
    async getBlockDagInfo(){return {network:'testnet-10',sink:headers[100].hash};}
    async getBlock({hash}){const h=headers[byHash.get(hash)];return {block:{header:h,
      verboseData:{isChainBlock:true,selectedParentHash:h.parentsByLevel[0][0]}}};}
    async getVirtualChainFromBlockV2({startHash}) {
      const added=headers.slice(byHash.get(startHash)+1,80);
      return {removedChainBlockHashes:[],addedChainBlockHashes:added.map(h=>h.hash),
        chainBlockAcceptedTransactions:added.map(h=>({chainBlockHeader:h,
          acceptedTransactions:h.hash===f.end.hash?[f.funding]:[]}))};
    }
    async getUtxosByAddresses(){return {entries:[{outpoint:f.d.founding_outpoint,amount:'299999999',
      scriptPublicKey:f.reserveScript,blockDaaScore:'1',isCoinbase:false,covenantId:null}]};}
  }
  const originalNow=Date.now;let ticks=0;
  Date.now=()=>ticks++===0?0:65038;
  try {
    const result=await execute(f.selection.path,f.selection.sha256,f.descriptor.path,f.descriptor.sha256,
      f.handoff.path,f.handoff.sha256,f.output,['ws://127.0.0.1:1'],{...sdk,RpcClient});
    assert.equal(result.status,'FETCHED_PENDING_REPLAY');
    assert.equal(result.source.acquisition_mode,'INCREMENTAL');
    const parser=`import ast,json,runpy,sys
h=runpy.run_path('/var/tmp/kpi-root-guard-helper-09.py')
p='/var/tmp/kpi-owner-private-lifecycle-01/assets/recovery-full-runtime-01/software/poc/owner-private-lifecycle/recovery/replay_closed.py'
b=h['read'](p,'eaf2fd951211faecefee7019f2fe1d7caaf908b18f71f6a4e00958b6cef8f863')
nodes=[n for n in ast.parse(b).body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in {'Refused','need','parse'}]
ns={'json':json};exec(compile(ast.Module(body=nodes,type_ignores=[]),p,'exec'),ns)
ns['parse'](sys.stdin.buffer.read())
`;
    const parsed=spawnSync('/usr/bin/python3',['-c',parser],{input:stringify(result),encoding:'utf8'});
    assert.equal(parsed.status,0,parsed.stderr);
    assert.equal(result.source.transport.cache_preparation_milliseconds,65038);
    assert.equal('cache_preparation_seconds' in result.source.transport,false);
    assert.equal(result.source.collector.name,'whole-main-page-delta/v3');
  }finally {Date.now=originalNow;fs.rmSync(f.root,{recursive:true});}
});

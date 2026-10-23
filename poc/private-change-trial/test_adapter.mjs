// Transport-only controls. Mocked acceptance is not consensus validation.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createRequire} from 'node:module';
import {bodyDomain, canonical, execute, observe, roundtrip, spk} from './adapter.mjs';
const k = createRequire(import.meta.url)('/home/luke/.cache/kpi-sdk/v2.1.0/kaspa-wasm32-sdk/nodejs/kaspa/kaspa.js');
const script = '000020'+'11'.repeat(32)+'ac';
const point = {transactionId:'22'.repeat(32),index:3};
const utxo={outpoint:point,amount:100100000n,scriptPublicKey:script,blockDaaScore:700n,isCoinbase:false};
const contexts=[{outpoint:point,amount_sompi:'100100000',script_public_key:script,block_daa_score:'700',is_coinbase:false,covenant_id:null}];
const tx = new k.Transaction({version:1,inputs:[{previousOutpoint:point,signatureScript:'00',sequence:0xffffffffffffffffn,sigOpCount:0,computeBudget:200,utxo}],outputs:[{value:100000000n,scriptPublicKey:script}],lockTime:0n,subnetworkId:'00'.repeat(20),gas:0n,payload:'',storageMass:0n});
tx.finalize(); const raw=canonical(tx); tx.free();
let count=0;
const pass = async (name, action) => { await action(); count++; console.log(`PASS ${name}`); };
const fail = async (name, action, pattern) => pass(name, () => assert.rejects(action, pattern));
await pass('u64MAX SDK roundtrip', () => { const tx=roundtrip(k,raw,contexts);tx.free();assert.equal(raw.inputs[0].sequence,'18446744073709551615'); });
await pass('native JSON numeric u64MAX remains exact', async () => {
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'kpx3-transport-'));
  try { const native={version:raw.version,inputs:raw.inputs,outputs:raw.outputs,lockTime:raw.lockTime,subnetworkId:raw.subnetworkId,gas:raw.gas,payload:raw.payload,mass:raw.storageMass,id:raw.id};
    const body=JSON.stringify(native).replace(/"(sequence|value|lockTime|gas|mass)":"([0-9]+)"/g,'"$1":$2');
    const file=path.join(directory,'transaction.json');fs.writeFileSync(file,body);
    fs.writeFileSync(path.join(directory,'supplied-context.json'),JSON.stringify([{amount_sompi:100100000,script_public_key:script,block_daa_score:700,is_coinbase:false,covenant_id:null}]));
    const report=await execute({op:'roundtrip',body_path:file});assert.deepEqual(report.transaction,raw);
  }finally{fs.rmSync(directory,{recursive:true});}
});
await pass('unknown script public key version rejected',()=>assert.throws(()=>spk('0001'+script.slice(4)),/version/));
await pass('conflicting RPC mass aliases rejected',()=>assert.throws(()=>canonical({...raw,mass:1n}),/aliases/));
await pass('nonzero deprecated v1 sigops rejected',()=>assert.throws(()=>canonical({...raw,inputs:raw.inputs.map(i=>({...i,sigOpCount:1}))})));
await pass('RPC v1 sigOpCount zero normalized',()=>assert.deepEqual(canonical({...raw,inputs:raw.inputs.map(i=>({...i,sigOpCount:0})),mass:0n}),raw));
const anchor='44'.repeat(32), sink='55'.repeat(32), start='66'.repeat(32);
const expected={outpoint:point,amount_sompi:'100100000',script_public_key:script,block_daa_score:'700',is_coinbase:false,covenant_id:null};
const checked={inputs:[expected]};
function context(){return{amount:100100000n,scriptPublicKey:script,isCoinbase:false,blockDaaScore:700n,covenantId:null};}
function mock(options={}){
  let pages=0;
  const accepted=structuredClone(raw);
  accepted.inputs[0].verboseData={utxoEntry:context()};
  if(options.wrongWitness)accepted.inputs[0].signatureScript='01';
  if(options.wrongAmount)accepted.inputs[0].verboseData.utxoEntry.amount=100100001n;
  if(options.wrongDaa)accepted.inputs[0].verboseData.utxoEntry.blockDaaScore=701n;
  if(options.missingContext)delete accepted.inputs[0].verboseData;
  if(options.badContextVersion)accepted.inputs[0].verboseData.utxoEntry.scriptPublicKey='0001'+script.slice(4);
  return {
    async getVirtualChainFromBlockV2(){pages++;if(options.removed&&pages===3)return{removedChainBlockHashes:[anchor],addedChainBlockHashes:[],chainBlockAcceptedTransactions:[]};
      if((options.relatedAfter||options.unrelatedAfter)&&pages===3){const later='77'.repeat(32);return{removedChainBlockHashes:[],addedChainBlockHashes:[later],chainBlockAcceptedTransactions:[{chainBlockHeader:{hash:later,blueScore:101n},acceptedTransactions:[{inputs:[{previousOutpoint:{transactionId:options.relatedAfter?raw.id:'88'.repeat(32),index:0}}]}]}]};}
      return{removedChainBlockHashes:[],addedChainBlockHashes:pages===1?[anchor]:[],chainBlockAcceptedTransactions:pages===1?[{chainBlockHeader:{hash:anchor,blueScore:100n},acceptedTransactions:[accepted]}]:[]};},
    async getUtxosByAddresses(){const entries=options.absent?[]:[{outpoint:{transactionId:raw.id,index:0},amount:100000000n,scriptPublicKey:script,blockDaaScore:720n,isCoinbase:false,covenantId:null}];
      if(options.sourceUnspent)entries.push({outpoint:point,amount:100100000n,scriptPublicKey:script,blockDaaScore:700n,isCoinbase:false,covenantId:null});return{entries};},
    async getServerInfo(){return{networkId:'testnet-10',isSynced:true,hasUtxoIndex:true,virtualDaaScore:800n};},
    async getBlockDagInfo(){return{network:'testnet-10',sink};},
    async getBlock({hash}){return{block:{header:{hash,blueScore:hash===sink?(options.shallow?120n:121n):100n},verboseData:{isChainBlock:!options.notChain}}};}
  };
}
const request={start_hash:start,min_confirmations:20,expected_unspent_output_indices:[0]};
await pass('mock exact accepted body/current payout/spent input/depth21',async()=>{const result=await observe(k,mock(),request,raw,checked);assert.equal(result.confirmation_policy.actual_blue_score_distance,'21');assert.equal(result.spent_inputs[0].queried,true);assert.equal(result.current_outputs[0].utxo.covenant_id,null);});
await fail('mock changed accepted witness rejected',()=>observe(k,mock({wrongWitness:true}),request,raw,checked),/substitution/);
await fail('mock changed Full input value rejected',()=>observe(k,mock({wrongAmount:true}),request,raw,checked),/100100001/);
await fail('mock changed Full input DAA rejected',()=>observe(k,mock({wrongDaa:true}),request,raw,checked),/DAA/);
await fail('mock Full missing input context rejected',()=>observe(k,mock({missingContext:true}),request,raw,checked),/missing/);
await fail('mock Full unknown input SPK version rejected',()=>observe(k,mock({badContextVersion:true}),request,raw,checked),/version/);
await fail('mock payout absent rejected',()=>observe(k,mock({absent:true}),request,raw,checked),/UTXO absent/);
await fail('mock consumed input still unspent rejected',()=>observe(k,mock({sourceUnspent:true}),request,raw,checked),/still present/);
await fail('mock depth20 fails strict greater-than policy',()=>observe(k,mock({shallow:true}),request,raw,checked),/depth/);
await fail('mock removed accepting anchor rejected',()=>observe(k,mock({removed:true}),request,raw,checked),/removed/);
await fail('mock non-chain accepting anchor rejected',()=>observe(k,mock({notChain:true}),request,raw,checked),/removed/);
await fail('mock queried payout spent after current query rejected',()=>observe(k,mock({relatedAfter:true}),request,raw,checked),/post-query related spend/);
await pass('mock unrelated post-query activity allowed',async()=>{const result=await observe(k,mock({unrelatedAfter:true}),request,raw,checked);assert.equal(result.post_query_related_spend_check,true);});

const repo = path.resolve(path.dirname(new URL(import.meta.url).pathname), '../..');
const bodies = [
  ['initial-payment','research/next-session/private-service-loss/trial/local-public-01/case-0001'],
  ['partial-cashout','research/next-session/privacy-recovery/lifecycle/main-execution-01/bob-partial'],
  ['change-payment','research/next-session/private-service-loss/trial/local-public-01/case-0001'],
  ['full-cashout','research/next-session/private-service-loss/trial/local-public-01/case-0002'],
  ['terminal-cashout','research/next-session/private-service-loss/trial/local-public-01/case-0003']
];
for (const [stage, relative] of bodies) {
  const directory=path.join(repo,relative);
  const tx=JSON.parse(fs.readFileSync(path.join(directory,'transaction.json'),'utf8'));
  const entries=JSON.parse(fs.readFileSync(path.join(directory,'supplied-context.json'),'utf8'));
  const profile={domain_hex32:Buffer.from(tx.payload,'hex').subarray(8,40).toString('hex')};
  const local={inputs:entries};
  await pass(`Auth528 six-stage dispatch ${stage}`,()=>bodyDomain(k,tx,profile,stage,local));
  await pass(`changed immutable program rejected for ${stage}`,()=>{
    const bad=structuredClone(tx), frame=Buffer.from(bad.inputs[0].signatureScript,'hex');frame[frame.length-1]^=1;
    bad.inputs[0].signatureScript=frame.toString('hex');
    const script=k.payToScriptHashScript(frame.subarray(199));
    try {const altered={inputs:[{...entries[0],script_public_key:spk(script)}]};
      assert.throws(()=>bodyDomain(k,bad,profile,stage,altered),/unapproved immutable program/);
    }finally{script.free();}
  });
  await pass(`old magic rejected for ${stage}`,()=>assert.throws(()=>bodyDomain(k,{...tx,payload:Buffer.from('KPX2AU01').toString('hex')+tx.payload.slice(16)},profile,stage,local),/stage\/payload/));
  const wrong=stage==='terminal-cashout'?'full-cashout':'terminal-cashout';
  await pass(`wrong payout mode rejected for ${stage}`,()=>assert.throws(()=>bodyDomain(k,tx,profile,wrong,local),/private payout|continuing private exit|terminal private exit/));
  for (const oldStage of ['private-payment','bob-private-exit','charlie-private-exit']) {
    await pass(`old stage ${oldStage} rejected for ${stage}`,()=>assert.throws(()=>bodyDomain(k,tx,profile,oldStage,local),/unknown finite stage/));
  }
}
const initial=path.join(repo,'research/next-session/private-service-loss/trial/local-public-01');
const found=JSON.parse(fs.readFileSync(path.join(initial,'case-0000/transaction.json'),'utf8'));
const payment=JSON.parse(fs.readFileSync(path.join(initial,'case-0001/transaction.json'),'utf8'));
const initialRedeem=Buffer.from(payment.inputs[0].signatureScript,'hex').subarray(199).toString('hex');
await pass('founding whole program and domain',()=>bodyDomain(k,found,
  {domain_hex32:Buffer.from(found.payload,'hex').subarray(8,40).toString('hex')},'founding',
  {output0_redeem_hex:initialRedeem}));
console.log(JSON.stringify({passed:count,consensus_engine_executed:false,broadcasts:0,prior_public_bodies_used_for_dispatch_controls_only:true}));
